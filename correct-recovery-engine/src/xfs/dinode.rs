use crate::error::{Error, Result};
use crate::io::ImageRead;
use crate::util::be::{be_u16_at, be_u32_at, be_u64_at};
use crate::util::crc32c::crc32c_with_zeroed_range;
use crate::xfs::inode_addr::InodeLocation;
use crate::xfs::superblock::{CrcStatus, Superblock};

pub const INODE_MAGIC: u16 = 0x494E; // 'IN'

pub const DINODE_V1_V2_CORE_SIZE: usize = 96;
pub const DINODE_V1_V2_FULL_SIZE: usize = 100;
pub const DINODE_V3_CORE_SIZE: usize = 176;

pub const NULLAGINO: u32 = u32::MAX;

const OFF_MAGIC: usize = 0;
const OFF_MODE: usize = 2;
const OFF_VERSION: usize = 4;
const OFF_FORMAT: usize = 5;
const OFF_ONLINK_OR_METATYPE: usize = 6;
const OFF_UID: usize = 8;
const OFF_GID: usize = 12;
const OFF_NLINK: usize = 16;
const OFF_PROJID_LO: usize = 20;
const OFF_PROJID_HI: usize = 22;
const OFF_PAD_OR_EXTENTS: usize = 24;
const OFF_FLUSHITER: usize = 30;
const OFF_ATIME: usize = 32;
const OFF_MTIME: usize = 40;
const OFF_CTIME: usize = 48;
const OFF_SIZE: usize = 56;
const OFF_NBLOCKS: usize = 64;
const OFF_EXTSIZE: usize = 72;
const OFF_NEXTENTS_OR_ANEXTENTS: usize = 76;
const OFF_ANEXTENTS_OR_PAD: usize = 80;
const OFF_FORKOFF: usize = 82;
const OFF_AFORMAT: usize = 83;
const OFF_DMEVMASK: usize = 84;
const OFF_DMSTATE: usize = 88;
const OFF_FLAGS: usize = 90;
const OFF_GEN: usize = 92;
const OFF_NEXT_UNLINKED: usize = 96;

const OFF_V3_CRC: usize = 100;
const OFF_V3_CHANGECOUNT: usize = 104;
const OFF_V3_LSN: usize = 112;
const OFF_V3_FLAGS2: usize = 120;
const OFF_V3_COWEXTSIZE: usize = 128;
const OFF_V3_CRTIME: usize = 144;
const OFF_V3_INO: usize = 152;
const OFF_V3_UUID: usize = 160;

// DIFLAG bits (di_flags)
pub const XFS_DIFLAG_REALTIME: u16 = 1 << 0;
pub const XFS_DIFLAG_PREALLOC: u16 = 1 << 1;
pub const XFS_DIFLAG_NEWRTBM: u16 = 1 << 2;
pub const XFS_DIFLAG_IMMUTABLE: u16 = 1 << 3;
pub const XFS_DIFLAG_APPEND: u16 = 1 << 4;
pub const XFS_DIFLAG_SYNC: u16 = 1 << 5;
pub const XFS_DIFLAG_NOATIME: u16 = 1 << 6;
pub const XFS_DIFLAG_NODUMP: u16 = 1 << 7;
pub const XFS_DIFLAG_RTINHERIT: u16 = 1 << 8;
pub const XFS_DIFLAG_PROJINHERIT: u16 = 1 << 9;
pub const XFS_DIFLAG_NOSYMLINKS: u16 = 1 << 10;
pub const XFS_DIFLAG_EXTSZINHERIT: u16 = 1 << 11;
pub const XFS_DIFLAG_NODEFRAG: u16 = 1 << 12;
pub const XFS_DIFLAG_FILESTREAM: u16 = 1 << 13;

// DIFLAG2 bits (di_flags2)
pub const XFS_DIFLAG2_DAX: u64 = 1 << 0;
pub const XFS_DIFLAG2_REFLINK: u64 = 1 << 1;
pub const XFS_DIFLAG2_COWEXTSIZE: u64 = 1 << 2;
pub const XFS_DIFLAG2_BIGTIME: u64 = 1 << 3;
pub const XFS_DIFLAG2_NREXT64: u64 = 1 << 4;
pub const XFS_DIFLAG2_METADATA: u64 = 1 << 5;

// Bigtime epoch offset: 2^31 seconds (corresponds to Dec 13 1901)
const XFS_BIGTIME_EPOCH_OFFSET: i64 = 2_147_483_648;
const NSEC_PER_SEC: u64 = 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Fifo,
    CharacterDevice,
    Directory,
    BlockDevice,
    RegularFile,
    Symlink,
    Socket,
    Unallocated,
    Unknown(u16),
}

impl FileType {
    pub fn from_mode(mode: u16) -> Self {
        match mode & 0xF000 {
            0x1000 => FileType::Fifo,
            0x2000 => FileType::CharacterDevice,
            0x4000 => FileType::Directory,
            0x6000 => FileType::BlockDevice,
            0x8000 => FileType::RegularFile,
            0xA000 => FileType::Symlink,
            0xC000 => FileType::Socket,
            0x0000 => FileType::Unallocated,
            other => FileType::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataForkFormat {
    Dev,
    Local,
    Extents,
    Btree,
    Uuid,
    MetaBtree,
    Unknown(u8),
}

impl DataForkFormat {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => DataForkFormat::Dev,
            1 => DataForkFormat::Local,
            2 => DataForkFormat::Extents,
            3 => DataForkFormat::Btree,
            4 => DataForkFormat::Uuid,
            5 => DataForkFormat::MetaBtree,
            other => DataForkFormat::Unknown(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            DataForkFormat::Dev => 0,
            DataForkFormat::Local => 1,
            DataForkFormat::Extents => 2,
            DataForkFormat::Btree => 3,
            DataForkFormat::Uuid => 4,
            DataForkFormat::MetaBtree => 5,
            DataForkFormat::Unknown(other) => other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrForkFormat {
    None,
    Local,
    Extents,
    Btree,
    Unknown(u8),
}

impl AttrForkFormat {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => AttrForkFormat::None,
            1 => AttrForkFormat::Local,
            2 => AttrForkFormat::Extents,
            3 => AttrForkFormat::Btree,
            other => AttrForkFormat::Unknown(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            AttrForkFormat::None => 0,
            AttrForkFormat::Local => 1,
            AttrForkFormat::Extents => 2,
            AttrForkFormat::Btree => 3,
            AttrForkFormat::Unknown(other) => other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    pub sec: i64,
    pub nsec: u32,
}

impl Timestamp {
    pub fn decode(raw_bytes: &[u8; 8], is_bigtime: bool) -> Self {
        if is_bigtime {
            let raw = u64::from_be_bytes(*raw_bytes);
            let sec_part = raw / NSEC_PER_SEC;
            let nsec = (raw % NSEC_PER_SEC) as u32;
            let sec = (sec_part as i64).wrapping_sub(XFS_BIGTIME_EPOCH_OFFSET);
            Timestamp { sec, nsec }
        } else {
            let sec =
                i32::from_be_bytes([raw_bytes[0], raw_bytes[1], raw_bytes[2], raw_bytes[3]]) as i64;
            let nsec = u32::from_be_bytes([raw_bytes[4], raw_bytes[5], raw_bytes[6], raw_bytes[7]]);
            Timestamp { sec, nsec }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DinodeIssue {
    CrcMismatch { stored: u32, computed: u32 },
    UuidMismatch { expected: [u8; 16], found: [u8; 16] },
    InoMismatch { expected: u64, found: u64 },
    InvalidFileType { mode: u16 },
    InvalidDataForkFormat { format: u8, mode: u16 },
    InvalidAttrForkFormat { format: u8 },
    InvalidForkOffset { forkoff: u8, max_forkoff: usize },
    SizeMismatchForLocal { size: u64, max_local_bytes: usize },
    ExtentsExceedBlocks { total_extents: u64, nblocks: u64 },
    NegativeSize { size: u64 },
    NonZeroPadding { field: &'static str, value: u64 },
    V2NonZeroOnlink { onlink: u16 },
    SymlinkOrDirZeroSizeNonZeroNlink { mode: u16, nlink: u32 },
    DirLocalFormatExpected { size: u64, format: u8 },
}

#[derive(Debug, Clone)]
pub struct DinodeCore {
    pub magic: u16,
    pub mode: u16,
    pub version: u8,
    pub format: DataForkFormat,
    pub file_type: FileType,
    pub permissions: u16,
    pub onlink: Option<u16>,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub projid: u32,
    pub projid_lo: u16,
    pub projid_hi: u16,
    pub flushiter: Option<u16>,
    pub atime: Timestamp,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
    pub crtime: Option<Timestamp>,
    pub size: u64,
    pub nblocks: u64,
    pub extsize: u32,
    pub nextents: u64,
    pub anextents: u32,
    pub forkoff: u8,
    pub aformat: AttrForkFormat,
    pub dmevmask: u32,
    pub dmstate: u16,
    pub flags: u16,
    pub flags2: Option<u64>,
    pub generation: u32,
    pub next_unlinked: Option<u32>,
    pub next_unlinked_raw: u32,
    pub crc: Option<u32>,
    pub changecount: Option<u64>,
    pub lsn: Option<u64>,
    pub cowextsize: Option<u32>,
    pub ino: Option<u64>,
    pub uuid: Option<[u8; 16]>,
    pub crc_status: CrcStatus,
    pub issues: Vec<DinodeIssue>,
}

impl DinodeCore {
    #[inline]
    pub fn is_dir(&self) -> bool {
        self.file_type == FileType::Directory
    }

    #[inline]
    pub fn is_file(&self) -> bool {
        self.file_type == FileType::RegularFile
    }

    #[inline]
    pub fn is_symlink(&self) -> bool {
        self.file_type == FileType::Symlink
    }

    #[inline]
    pub fn is_fifo(&self) -> bool {
        self.file_type == FileType::Fifo
    }

    #[inline]
    pub fn is_socket(&self) -> bool {
        self.file_type == FileType::Socket
    }

    #[inline]
    pub fn is_char_dev(&self) -> bool {
        self.file_type == FileType::CharacterDevice
    }

    #[inline]
    pub fn is_block_dev(&self) -> bool {
        self.file_type == FileType::BlockDevice
    }

    #[inline]
    pub fn is_unallocated(&self) -> bool {
        self.file_type == FileType::Unallocated
    }

    #[inline]
    pub fn has_attr_fork(&self) -> bool {
        self.forkoff > 0
    }

    #[inline]
    pub fn literal_area_offset(&self) -> usize {
        if self.version >= 3 {
            DINODE_V3_CORE_SIZE
        } else {
            DINODE_V1_V2_FULL_SIZE
        }
    }

    pub fn data_fork_size(&self, inode_size: usize) -> usize {
        let lit_offset = self.literal_area_offset();
        if inode_size <= lit_offset {
            return 0;
        }
        let lit_size = inode_size - lit_offset;
        if self.forkoff == 0 {
            lit_size
        } else {
            let boff = (self.forkoff as usize) << 3;
            lit_size.min(boff)
        }
    }

    pub fn attr_fork_size(&self, inode_size: usize) -> usize {
        let lit_offset = self.literal_area_offset();
        if inode_size <= lit_offset || self.forkoff == 0 {
            return 0;
        }
        let lit_size = inode_size - lit_offset;
        let boff = (self.forkoff as usize) << 3;
        lit_size.saturating_sub(boff)
    }

    pub fn data_fork_bytes<'a>(&self, inode_buf: &'a [u8]) -> Result<&'a [u8]> {
        let lit_offset = self.literal_area_offset();
        let len = self.data_fork_size(inode_buf.len());
        if inode_buf.len() < lit_offset + len {
            return Err(Error::Truncated {
                needed: lit_offset + len,
                available: inode_buf.len(),
            });
        }
        Ok(&inode_buf[lit_offset..lit_offset + len])
    }

    pub fn attr_fork_bytes<'a>(&self, inode_buf: &'a [u8]) -> Result<&'a [u8]> {
        if self.forkoff == 0 {
            return Ok(&[]);
        }
        let lit_offset = self.literal_area_offset();
        let boff = (self.forkoff as usize) << 3;
        let attr_start = lit_offset + boff;
        let len = self.attr_fork_size(inode_buf.len());
        if inode_buf.len() < attr_start + len {
            return Err(Error::Truncated {
                needed: attr_start + len,
                available: inode_buf.len(),
            });
        }
        Ok(&inode_buf[attr_start..attr_start + len])
    }
}

#[derive(Debug, Clone)]
pub struct Dinode {
    pub location: InodeLocation,
    pub core: DinodeCore,
    pub raw: Vec<u8>,
}

fn malformed(reason: &'static str) -> Error {
    Error::Malformed {
        structure: "dinode",
        reason,
    }
}

pub fn parse_dinode_core(buf: &[u8], inode_size: usize) -> Result<DinodeCore> {
    parse_dinode_core_internal(buf, inode_size, None, None)
}

pub fn parse_dinode_from_bytes(
    buf: &[u8],
    sb: &Superblock,
    location: Option<&InodeLocation>,
) -> Result<DinodeCore> {
    parse_dinode_core_internal(buf, sb.inode_size as usize, Some(sb), location)
}

pub fn parse_dinode(
    reader: &mut dyn ImageRead,
    fs_base_offset: u64,
    sb: &Superblock,
    location: &InodeLocation,
) -> Result<Dinode> {
    let inode_size = sb.inode_size as usize;
    let mut buf = vec![0u8; inode_size];
    reader.read_at(fs_base_offset + location.byte_offset, &mut buf)?;
    let core = parse_dinode_from_bytes(&buf, sb, Some(location))?;
    Ok(Dinode {
        location: *location,
        core,
        raw: buf,
    })
}

fn parse_dinode_core_internal(
    buf: &[u8],
    inode_size: usize,
    sb: Option<&Superblock>,
    location: Option<&InodeLocation>,
) -> Result<DinodeCore> {
    if buf.len() < DINODE_V1_V2_FULL_SIZE {
        return Err(Error::Truncated {
            needed: DINODE_V1_V2_FULL_SIZE,
            available: buf.len(),
        });
    }

    let magic = be_u16_at(buf, OFF_MAGIC)?;
    if magic != INODE_MAGIC {
        return Err(malformed("invalid inode magic number"));
    }

    let version = buf[OFF_VERSION];
    if !(1..=3).contains(&version) {
        return Err(malformed("unsupported inode version"));
    }

    if version == 3 && buf.len() < DINODE_V3_CORE_SIZE {
        return Err(Error::Truncated {
            needed: DINODE_V3_CORE_SIZE,
            available: buf.len(),
        });
    }

    let mut issues = Vec::new();
    let mode = be_u16_at(buf, OFF_MODE)?;
    let file_type = FileType::from_mode(mode);
    let permissions = mode & 0o7777;

    if let FileType::Unknown(_) = file_type {
        issues.push(DinodeIssue::InvalidFileType { mode });
    }

    let raw_format = buf[OFF_FORMAT];
    let format = DataForkFormat::from_u8(raw_format);
    let uid = be_u32_at(buf, OFF_UID)?;
    let gid = be_u32_at(buf, OFF_GID)?;

    let (onlink, nlink) = match version {
        1 => {
            let onl = be_u16_at(buf, OFF_ONLINK_OR_METATYPE)?;
            (Some(onl), onl as u32)
        }
        2 => {
            let onl = be_u16_at(buf, OFF_ONLINK_OR_METATYPE)?;
            if onl != 0 {
                issues.push(DinodeIssue::V2NonZeroOnlink { onlink: onl });
            }
            let nl = be_u32_at(buf, OFF_NLINK)?;
            (Some(onl), nl)
        }
        _ => {
            let nl = be_u32_at(buf, OFF_NLINK)?;
            (None, nl)
        }
    };

    let (projid, projid_lo, projid_hi) = if version == 1 {
        (0, 0, 0)
    } else {
        let lo = be_u16_at(buf, OFF_PROJID_LO)?;
        let hi = be_u16_at(buf, OFF_PROJID_HI)?;
        (((hi as u32) << 16) | (lo as u32), lo, hi)
    };

    let (flags2, is_bigtime, is_nrext64) = if version == 3 {
        let f2 = be_u64_at(buf, OFF_V3_FLAGS2)?;
        let bigtime = (f2 & XFS_DIFLAG2_BIGTIME) != 0;
        let nrext64 = (f2 & XFS_DIFLAG2_NREXT64) != 0;
        (Some(f2), bigtime, nrext64)
    } else {
        (None, false, false)
    };

    let flushiter = if version <= 2 {
        Some(be_u16_at(buf, OFF_FLUSHITER)?)
    } else {
        None
    };

    let mut atime_bytes = [0u8; 8];
    atime_bytes.copy_from_slice(&buf[OFF_ATIME..OFF_ATIME + 8]);
    let atime = Timestamp::decode(&atime_bytes, is_bigtime);

    let mut mtime_bytes = [0u8; 8];
    mtime_bytes.copy_from_slice(&buf[OFF_MTIME..OFF_MTIME + 8]);
    let mtime = Timestamp::decode(&mtime_bytes, is_bigtime);

    let mut ctime_bytes = [0u8; 8];
    ctime_bytes.copy_from_slice(&buf[OFF_CTIME..OFF_CTIME + 8]);
    let ctime = Timestamp::decode(&ctime_bytes, is_bigtime);

    let size = be_u64_at(buf, OFF_SIZE)?;
    if (size & (1u64 << 63)) != 0 {
        issues.push(DinodeIssue::NegativeSize { size });
    }

    let nblocks = be_u64_at(buf, OFF_NBLOCKS)?;
    let extsize = be_u32_at(buf, OFF_EXTSIZE)?;

    let (nextents, anextents) = if is_nrext64 {
        let ne = be_u64_at(buf, OFF_PAD_OR_EXTENTS)?;
        let ane = be_u32_at(buf, OFF_NEXTENTS_OR_ANEXTENTS)?;
        let pad = be_u16_at(buf, OFF_ANEXTENTS_OR_PAD)?;
        if pad != 0 {
            issues.push(DinodeIssue::NonZeroPadding {
                field: "di_nrext64_pad",
                value: pad as u64,
            });
        }
        (ne, ane)
    } else {
        let ne = be_u32_at(buf, OFF_NEXTENTS_OR_ANEXTENTS)? as u64;
        let ane = be_u16_at(buf, OFF_ANEXTENTS_OR_PAD)? as u32;
        if version == 3 {
            let pad = be_u64_at(buf, OFF_PAD_OR_EXTENTS)?;
            if pad != 0 {
                issues.push(DinodeIssue::NonZeroPadding {
                    field: "di_v3_pad",
                    value: pad,
                });
            }
        }
        (ne, ane)
    };

    let forkoff = buf[OFF_FORKOFF];
    let raw_aformat = buf[OFF_AFORMAT];
    let aformat = AttrForkFormat::from_u8(raw_aformat);

    let dmevmask = be_u32_at(buf, OFF_DMEVMASK)?;
    let dmstate = be_u16_at(buf, OFF_DMSTATE)?;
    let flags = be_u16_at(buf, OFF_FLAGS)?;
    let generation = be_u32_at(buf, OFF_GEN)?;

    let next_unlinked_raw = be_u32_at(buf, OFF_NEXT_UNLINKED)?;
    let next_unlinked = if next_unlinked_raw == NULLAGINO || next_unlinked_raw == 0 {
        None
    } else {
        Some(next_unlinked_raw)
    };

    let (crc, changecount, lsn, cowextsize, crtime, ino, uuid, crc_status) = if version == 3 {
        let stored_crc = u32::from_le_bytes([
            buf[OFF_V3_CRC],
            buf[OFF_V3_CRC + 1],
            buf[OFF_V3_CRC + 2],
            buf[OFF_V3_CRC + 3],
        ]);
        let cc = be_u64_at(buf, OFF_V3_CHANGECOUNT)?;
        let l = be_u64_at(buf, OFF_V3_LSN)?;
        let cow = be_u32_at(buf, OFF_V3_COWEXTSIZE)?;

        let mut cr_bytes = [0u8; 8];
        cr_bytes.copy_from_slice(&buf[OFF_V3_CRTIME..OFF_V3_CRTIME + 8]);
        let cr = Timestamp::decode(&cr_bytes, is_bigtime);

        let i = be_u64_at(buf, OFF_V3_INO)?;
        let mut u = [0u8; 16];
        u.copy_from_slice(&buf[OFF_V3_UUID..OFF_V3_UUID + 16]);

        let effective_crc_len = if buf.len() >= inode_size {
            inode_size
        } else {
            buf.len()
        };
        let computed = crc32c_with_zeroed_range(&buf[..effective_crc_len], OFF_V3_CRC, 4);

        let c_status = if computed == stored_crc {
            CrcStatus::Verified
        } else {
            let status = CrcStatus::Mismatch {
                stored: stored_crc,
                computed,
            };
            issues.push(DinodeIssue::CrcMismatch {
                stored: stored_crc,
                computed,
            });
            status
        };

        (
            Some(stored_crc),
            Some(cc),
            Some(l),
            Some(cow),
            Some(cr),
            Some(i),
            Some(u),
            c_status,
        )
    } else {
        (
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            CrcStatus::NotApplicable,
        )
    };

    let mut core = DinodeCore {
        magic,
        mode,
        version,
        format,
        file_type,
        permissions,
        onlink,
        uid,
        gid,
        nlink,
        projid,
        projid_lo,
        projid_hi,
        flushiter,
        atime,
        mtime,
        ctime,
        crtime,
        size,
        nblocks,
        extsize,
        nextents,
        anextents,
        forkoff,
        aformat,
        dmevmask,
        dmstate,
        flags,
        flags2,
        generation,
        next_unlinked,
        next_unlinked_raw,
        crc,
        changecount,
        lsn,
        cowextsize,
        ino,
        uuid,
        crc_status,
        issues: Vec::new(),
    };

    validate_core_semantics(&core, &mut issues, inode_size, sb, location)?;
    core.issues = issues;

    Ok(core)
}

fn validate_core_semantics(
    core: &DinodeCore,
    issues: &mut Vec<DinodeIssue>,
    inode_size: usize,
    sb: Option<&Superblock>,
    location: Option<&InodeLocation>,
) -> Result<()> {
    let lit_offset = core.literal_area_offset();
    if inode_size > lit_offset {
        let lit_size = inode_size - lit_offset;
        let max_forkoff = lit_size >> 3;
        if (core.forkoff as usize) > max_forkoff {
            issues.push(DinodeIssue::InvalidForkOffset {
                forkoff: core.forkoff,
                max_forkoff,
            });
        }
    }

    let data_fork_size = core.data_fork_size(inode_size);

    if core.format == DataForkFormat::Local {
        if core.file_type == FileType::RegularFile {
            issues.push(DinodeIssue::InvalidDataForkFormat {
                format: core.format.to_u8(),
                mode: core.mode,
            });
        }
        if core.size > data_fork_size as u64 {
            issues.push(DinodeIssue::SizeMismatchForLocal {
                size: core.size,
                max_local_bytes: data_fork_size,
            });
        }
        if core.nextents != 0 {
            issues.push(DinodeIssue::ExtentsExceedBlocks {
                total_extents: core.nextents,
                nblocks: core.nblocks,
            });
        }
    }

    if core.mode != 0 && (core.is_dir() || core.is_symlink()) && core.size == 0 && core.nlink != 0 {
        issues.push(DinodeIssue::SymlinkOrDirZeroSizeNonZeroNlink {
            mode: core.mode,
            nlink: core.nlink,
        });
    }

    if core.mode != 0
        && core.format == DataForkFormat::Extents
        && core.nextents + core.anextents as u64 > core.nblocks
    {
        issues.push(DinodeIssue::ExtentsExceedBlocks {
            total_extents: core.nextents + core.anextents as u64,
            nblocks: core.nblocks,
        });
    }

    if let (Some(sb), Some(uuid)) = (sb, core.uuid)
        && uuid != sb.uuid
    {
        issues.push(DinodeIssue::UuidMismatch {
            expected: sb.uuid,
            found: uuid,
        });
    }

    if let (Some(loc), Some(ino)) = (location, core.ino)
        && ino != loc.ino
    {
        issues.push(DinodeIssue::InoMismatch {
            expected: loc.ino,
            found: ino,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_v3_dinode_buf(isize: usize) -> Vec<u8> {
        let mut buf = vec![0u8; isize];
        buf[OFF_MAGIC..OFF_MAGIC + 2].copy_from_slice(&INODE_MAGIC.to_be_bytes());
        buf[OFF_MODE..OFF_MODE + 2].copy_from_slice(&0o100644u16.to_be_bytes());
        buf[OFF_VERSION] = 3;
        buf[OFF_FORMAT] = DataForkFormat::Extents.to_u8();
        buf[OFF_UID..OFF_UID + 4].copy_from_slice(&1000u32.to_be_bytes());
        buf[OFF_GID..OFF_GID + 4].copy_from_slice(&1000u32.to_be_bytes());
        buf[OFF_NLINK..OFF_NLINK + 4].copy_from_slice(&1u32.to_be_bytes());
        buf[OFF_PROJID_LO..OFF_PROJID_LO + 2].copy_from_slice(&0u16.to_be_bytes());
        buf[OFF_PROJID_HI..OFF_PROJID_HI + 2].copy_from_slice(&0u16.to_be_bytes());
        buf[OFF_SIZE..OFF_SIZE + 8].copy_from_slice(&4096u64.to_be_bytes());
        buf[OFF_NBLOCKS..OFF_NBLOCKS + 8].copy_from_slice(&1u64.to_be_bytes());
        buf[OFF_NEXTENTS_OR_ANEXTENTS..OFF_NEXTENTS_OR_ANEXTENTS + 4]
            .copy_from_slice(&0u32.to_be_bytes());
        buf[OFF_FORKOFF] = 0;
        buf[OFF_AFORMAT] = AttrForkFormat::None.to_u8();
        buf[OFF_NEXT_UNLINKED..OFF_NEXT_UNLINKED + 4].copy_from_slice(&NULLAGINO.to_be_bytes());
        buf[OFF_V3_FLAGS2..OFF_V3_FLAGS2 + 8]
            .copy_from_slice(&(XFS_DIFLAG2_BIGTIME | XFS_DIFLAG2_NREXT64).to_be_bytes());
        buf[OFF_PAD_OR_EXTENTS..OFF_PAD_OR_EXTENTS + 8].copy_from_slice(&1u64.to_be_bytes());
        buf[OFF_V3_INO..OFF_V3_INO + 8].copy_from_slice(&128u64.to_be_bytes());
        let uuid = [0xAA; 16];
        buf[OFF_V3_UUID..OFF_V3_UUID + 16].copy_from_slice(&uuid);

        let crc = crc32c_with_zeroed_range(&buf, OFF_V3_CRC, 4);
        buf[OFF_V3_CRC..OFF_V3_CRC + 4].copy_from_slice(&crc.to_le_bytes());
        buf
    }

    #[test]
    fn parses_golden_v3_inode_with_crc_and_nrext64() {
        let buf = build_v3_dinode_buf(512);
        let core = parse_dinode_core(&buf, 512).expect("parse valid v3 dinode");

        assert_eq!(core.magic, INODE_MAGIC);
        assert_eq!(core.version, 3);
        assert_eq!(core.file_type, FileType::RegularFile);
        assert_eq!(core.permissions, 0o644);
        assert_eq!(core.uid, 1000);
        assert_eq!(core.gid, 1000);
        assert_eq!(core.nlink, 1);
        assert_eq!(core.size, 4096);
        assert_eq!(core.nblocks, 1);
        assert_eq!(core.nextents, 1);
        assert_eq!(core.anextents, 0);
        assert_eq!(core.format, DataForkFormat::Extents);
        assert_eq!(core.aformat, AttrForkFormat::None);
        assert_eq!(core.next_unlinked, None);
        assert_eq!(core.crc_status, CrcStatus::Verified);
        assert_eq!(core.ino, Some(128));
        assert_eq!(core.uuid, Some([0xAA; 16]));
        assert!(core.issues.is_empty());
    }

    #[test]
    fn parses_v1_and_v2_golden_inodes() {
        // v1 inode
        let mut buf_v1 = vec![0u8; 256];
        buf_v1[OFF_MAGIC..OFF_MAGIC + 2].copy_from_slice(&INODE_MAGIC.to_be_bytes());
        buf_v1[OFF_MODE..OFF_MODE + 2].copy_from_slice(&0o40755u16.to_be_bytes());
        buf_v1[OFF_VERSION] = 1;
        buf_v1[OFF_FORMAT] = DataForkFormat::Local.to_u8();
        buf_v1[OFF_ONLINK_OR_METATYPE..OFF_ONLINK_OR_METATYPE + 2]
            .copy_from_slice(&3u16.to_be_bytes());
        buf_v1[OFF_UID..OFF_UID + 4].copy_from_slice(&0u32.to_be_bytes());
        buf_v1[OFF_GID..OFF_GID + 4].copy_from_slice(&0u32.to_be_bytes());
        buf_v1[OFF_SIZE..OFF_SIZE + 8].copy_from_slice(&6u64.to_be_bytes());
        buf_v1[OFF_FLUSHITER..OFF_FLUSHITER + 2].copy_from_slice(&12u16.to_be_bytes());
        buf_v1[OFF_NEXT_UNLINKED..OFF_NEXT_UNLINKED + 4].copy_from_slice(&NULLAGINO.to_be_bytes());

        let core_v1 = parse_dinode_core(&buf_v1, 256).expect("parse v1 dinode");
        assert_eq!(core_v1.version, 1);
        assert_eq!(core_v1.file_type, FileType::Directory);
        assert_eq!(core_v1.nlink, 3);
        assert_eq!(core_v1.onlink, Some(3));
        assert_eq!(core_v1.projid, 0);
        assert_eq!(core_v1.flushiter, Some(12));
        assert_eq!(core_v1.crc_status, CrcStatus::NotApplicable);

        // v2 inode
        let mut buf_v2 = vec![0u8; 256];
        buf_v2[OFF_MAGIC..OFF_MAGIC + 2].copy_from_slice(&INODE_MAGIC.to_be_bytes());
        buf_v2[OFF_MODE..OFF_MODE + 2].copy_from_slice(&0o120777u16.to_be_bytes());
        buf_v2[OFF_VERSION] = 2;
        buf_v2[OFF_FORMAT] = DataForkFormat::Local.to_u8();
        buf_v2[OFF_ONLINK_OR_METATYPE..OFF_ONLINK_OR_METATYPE + 2]
            .copy_from_slice(&0u16.to_be_bytes());
        buf_v2[OFF_NLINK..OFF_NLINK + 4].copy_from_slice(&1u32.to_be_bytes());
        buf_v2[OFF_PROJID_LO..OFF_PROJID_LO + 2].copy_from_slice(&42u16.to_be_bytes());
        buf_v2[OFF_PROJID_HI..OFF_PROJID_HI + 2].copy_from_slice(&1u16.to_be_bytes());
        buf_v2[OFF_SIZE..OFF_SIZE + 8].copy_from_slice(&11u64.to_be_bytes());
        buf_v2[OFF_FLUSHITER..OFF_FLUSHITER + 2].copy_from_slice(&5u16.to_be_bytes());
        buf_v2[OFF_NEXT_UNLINKED..OFF_NEXT_UNLINKED + 4].copy_from_slice(&NULLAGINO.to_be_bytes());

        let core_v2 = parse_dinode_core(&buf_v2, 256).expect("parse v2 dinode");
        assert_eq!(core_v2.version, 2);
        assert_eq!(core_v2.file_type, FileType::Symlink);
        assert_eq!(core_v2.nlink, 1);
        assert_eq!(core_v2.projid, (1 << 16) | 42);
        assert_eq!(core_v2.flushiter, Some(5));
        assert_eq!(core_v2.crc_status, CrcStatus::NotApplicable);
    }

    #[test]
    fn validates_multiple_file_types() {
        let types = [
            (0o010644, FileType::Fifo),
            (0o020660, FileType::CharacterDevice),
            (0o040755, FileType::Directory),
            (0o060660, FileType::BlockDevice),
            (0o100644, FileType::RegularFile),
            (0o120777, FileType::Symlink),
            (0o140777, FileType::Socket),
            (0o000000, FileType::Unallocated),
        ];

        for (mode, expected_ft) in types {
            let mut buf = build_v3_dinode_buf(512);
            buf[OFF_MODE..OFF_MODE + 2].copy_from_slice(&(mode as u16).to_be_bytes());
            if matches!(
                expected_ft,
                FileType::Fifo
                    | FileType::CharacterDevice
                    | FileType::BlockDevice
                    | FileType::Socket
            ) {
                buf[OFF_FORMAT] = DataForkFormat::Dev.to_u8();
            }
            let crc = crc32c_with_zeroed_range(&buf, OFF_V3_CRC, 4);
            buf[OFF_V3_CRC..OFF_V3_CRC + 4].copy_from_slice(&crc.to_le_bytes());

            let core = parse_dinode_core(&buf, 512).expect("parse file type");
            assert_eq!(core.file_type, expected_ft);
        }
    }

    #[test]
    fn decodes_bigtime_and_classic_timestamps() {
        // Classic timestamp (positive and negative seconds)
        let classic_bytes = [0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0xE8]; // sec=256, nsec=1000
        let ts = Timestamp::decode(&classic_bytes, false);
        assert_eq!(ts.sec, 256);
        assert_eq!(ts.nsec, 1000);

        let classic_neg_bytes = [0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x01]; // sec=-256, nsec=1
        let ts_neg = Timestamp::decode(&classic_neg_bytes, false);
        assert_eq!(ts_neg.sec, -256);
        assert_eq!(ts_neg.nsec, 1);

        // Bigtime timestamp at epoch (sec=0, nsec=0) -> raw = 2_147_483_648 * 1_000_000_000
        let epoch_raw = 2_147_483_648u64 * 1_000_000_000u64;
        let ts_epoch = Timestamp::decode(&epoch_raw.to_be_bytes(), true);
        assert_eq!(ts_epoch.sec, 0);
        assert_eq!(ts_epoch.nsec, 0);

        // Bigtime minimum time (raw = 0) -> sec = -2_147_483_648
        let ts_min = Timestamp::decode(&0u64.to_be_bytes(), true);
        assert_eq!(ts_min.sec, -2_147_483_648);
        assert_eq!(ts_min.nsec, 0);

        // Bigtime 2026 timestamp
        let raw_2026 =
            (1_787_738_382i64 + XFS_BIGTIME_EPOCH_OFFSET) as u64 * 1_000_000_000 + 123_456_789;
        let ts_2026 = Timestamp::decode(&raw_2026.to_be_bytes(), true);
        assert_eq!(ts_2026.sec, 1_787_738_382);
        assert_eq!(ts_2026.nsec, 123_456_789);
    }

    #[test]
    fn reports_crc_mismatch_as_forensic_issue_not_panic() {
        let mut buf = build_v3_dinode_buf(512);
        buf[OFF_V3_CRC..OFF_V3_CRC + 4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());

        let core = parse_dinode_core(&buf, 512).expect("must parse without panic on bad CRC");
        assert!(matches!(core.crc_status, CrcStatus::Mismatch { .. }));
        assert!(
            core.issues
                .iter()
                .any(|i| matches!(i, DinodeIssue::CrcMismatch { .. }))
        );
    }

    #[test]
    fn rejects_bad_magic_and_version() {
        let mut buf = build_v3_dinode_buf(512);
        buf[OFF_MAGIC..OFF_MAGIC + 2].copy_from_slice(&0x5846u16.to_be_bytes()); // 'XF' instead of 'IN'
        assert!(matches!(
            parse_dinode_core(&buf, 512),
            Err(Error::Malformed { .. })
        ));

        let mut buf2 = build_v3_dinode_buf(512);
        buf2[OFF_VERSION] = 4; // version 4 invalid
        assert!(matches!(
            parse_dinode_core(&buf2, 512),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn rejects_truncated_buffers() {
        let buf = vec![0u8; 50];
        assert!(matches!(
            parse_dinode_core(&buf, 512),
            Err(Error::Truncated { .. })
        ));

        let mut buf_v3_short = vec![0u8; 120];
        buf_v3_short[OFF_MAGIC..OFF_MAGIC + 2].copy_from_slice(&INODE_MAGIC.to_be_bytes());
        buf_v3_short[OFF_VERSION] = 3;
        assert!(matches!(
            parse_dinode_core(&buf_v3_short, 512),
            Err(Error::Truncated { .. })
        ));
    }

    #[test]
    fn fork_slices_and_offsets() {
        let mut buf = build_v3_dinode_buf(512);
        buf[OFF_FORKOFF] = 10; // 80 bytes for data fork
        let crc = crc32c_with_zeroed_range(&buf, OFF_V3_CRC, 4);
        buf[OFF_V3_CRC..OFF_V3_CRC + 4].copy_from_slice(&crc.to_le_bytes());

        let core = parse_dinode_core(&buf, 512).unwrap();
        assert_eq!(core.data_fork_size(512), 80);
        assert_eq!(core.attr_fork_size(512), 512 - 176 - 80);

        let df_slice = core.data_fork_bytes(&buf).unwrap();
        assert_eq!(df_slice.len(), 80);
        let af_slice = core.attr_fork_bytes(&buf).unwrap();
        assert_eq!(af_slice.len(), 512 - 176 - 80);
    }

    #[test]
    fn validates_plausibility_and_forensic_issues() {
        // Negative size
        let mut buf = build_v3_dinode_buf(512);
        buf[OFF_SIZE..OFF_SIZE + 8].copy_from_slice(&(0x8000_0000_0000_0001u64).to_be_bytes());
        let crc = crc32c_with_zeroed_range(&buf, OFF_V3_CRC, 4);
        buf[OFF_V3_CRC..OFF_V3_CRC + 4].copy_from_slice(&crc.to_le_bytes());
        let core = parse_dinode_core(&buf, 512).unwrap();
        assert!(
            core.issues
                .iter()
                .any(|i| matches!(i, DinodeIssue::NegativeSize { .. }))
        );

        // Invalid forkoff
        let mut buf_fork = build_v3_dinode_buf(512);
        buf_fork[OFF_FORKOFF] = 200; // 1600 bytes exceeds 512-byte inode literal area
        let crc = crc32c_with_zeroed_range(&buf_fork, OFF_V3_CRC, 4);
        buf_fork[OFF_V3_CRC..OFF_V3_CRC + 4].copy_from_slice(&crc.to_le_bytes());
        let core_fork = parse_dinode_core(&buf_fork, 512).unwrap();
        assert!(
            core_fork
                .issues
                .iter()
                .any(|i| matches!(i, DinodeIssue::InvalidForkOffset { .. }))
        );

        // Local format size mismatch
        let mut buf_local = build_v3_dinode_buf(512);
        buf_local[OFF_MODE..OFF_MODE + 2].copy_from_slice(&0o40755u16.to_be_bytes()); // directory
        buf_local[OFF_FORMAT] = DataForkFormat::Local.to_u8();
        buf_local[OFF_SIZE..OFF_SIZE + 8].copy_from_slice(&2000u64.to_be_bytes()); // exceeds literal area
        let crc = crc32c_with_zeroed_range(&buf_local, OFF_V3_CRC, 4);
        buf_local[OFF_V3_CRC..OFF_V3_CRC + 4].copy_from_slice(&crc.to_le_bytes());
        let core_local = parse_dinode_core(&buf_local, 512).unwrap();
        assert!(
            core_local
                .issues
                .iter()
                .any(|i| matches!(i, DinodeIssue::SizeMismatchForLocal { .. }))
        );

        // Extents exceed blocks
        let mut buf_ext = build_v3_dinode_buf(512);
        buf_ext[OFF_NBLOCKS..OFF_NBLOCKS + 8].copy_from_slice(&2u64.to_be_bytes());
        buf_ext[OFF_PAD_OR_EXTENTS..OFF_PAD_OR_EXTENTS + 8].copy_from_slice(&10u64.to_be_bytes()); // 10 extents > 2 blocks
        let crc = crc32c_with_zeroed_range(&buf_ext, OFF_V3_CRC, 4);
        buf_ext[OFF_V3_CRC..OFF_V3_CRC + 4].copy_from_slice(&crc.to_le_bytes());
        let core_ext = parse_dinode_core(&buf_ext, 512).unwrap();
        assert!(
            core_ext
                .issues
                .iter()
                .any(|i| matches!(i, DinodeIssue::ExtentsExceedBlocks { .. }))
        );
    }

    #[test]
    fn deterministic_fuzzing_never_panics() {
        let mut state = 0x8543_2117_AABB_CCDDu64;
        let mut buf = vec![0u8; 512];

        for _ in 0..2000 {
            for byte in buf.iter_mut() {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *byte = (state >> 33) as u8;
            }
            for len in [0, 10, 50, 96, 100, 175, 176, 256, 512] {
                let _ = parse_dinode_core(&buf[..len], 512);
            }
        }
    }
}
