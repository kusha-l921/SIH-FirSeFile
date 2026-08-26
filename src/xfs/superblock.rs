use crate::error::{Error, Result};
use crate::io::ImageRead;
use crate::util::be::{be_u16_at, be_u32_at, be_u64_at};
use crate::util::crc32c::crc32c;

pub const SUPERBLOCK_SECTOR_BYTES: usize = 512;

const OFF_MAGIC: usize = 0;
const OFF_BLOCKSIZE: usize = 4;
const OFF_DBLOCKS: usize = 8;
const OFF_RBLOCKS: usize = 16;
const OFF_REXTENTS: usize = 24;
const OFF_UUID: usize = 32;
const OFF_LOGSTART: usize = 48;
const OFF_ROOTINO: usize = 56;
const OFF_RBMINO: usize = 64;
const OFF_RSUMINO: usize = 72;
const OFF_REXTSIZE: usize = 80;
const OFF_AGBLOCKS: usize = 84;
const OFF_AGCOUNT: usize = 88;
const OFF_RBMBLOCKS: usize = 92;
const OFF_LOGBLOCKS: usize = 96;
const OFF_VERSIONNUM: usize = 100;
const OFF_SECTSIZE: usize = 102;
const OFF_INODESIZE: usize = 104;
const OFF_INOPBLOCK: usize = 106;
const OFF_BLOCKLOG: usize = 120;
const OFF_SECTLOG: usize = 121;
const OFF_INODELOG: usize = 122;
const OFF_INOPBLOG: usize = 123;
const OFF_AGBLKLOG: usize = 124;
const OFF_REXTSLOG: usize = 125;
const OFF_INPROGRESS: usize = 126;
const OFF_IMAXPCT: usize = 127;
const OFF_ICOUNT: usize = 128;
const OFF_IFREE: usize = 136;
const OFF_FDBLOCKS: usize = 144;
const OFF_FREXTENTS: usize = 152;
const OFF_UQUOTINO: usize = 160;
const OFF_GQUOTINO: usize = 168;
const OFF_QFLAGS: usize = 176;
const OFF_FLAGS: usize = 178;
const OFF_SHAREDVN: usize = 179;
const OFF_INOALIGNMT: usize = 180;
const OFF_UNIT: usize = 184;
const OFF_WIDTH: usize = 188;
const OFF_DIRBLKLOG: usize = 192;
const OFF_LOGSECTLOG: usize = 193;
const OFF_LOGSECTSIZE: usize = 194;
const OFF_LOGSUNIT: usize = 196;
const OFF_FEATURES2: usize = 200;
const OFF_BAD_FEATURES2: usize = 204;
const OFF_FEATURES_COMPAT: usize = 208;
const OFF_FEATURES_RO_COMPAT: usize = 212;
const OFF_FEATURES_INCOMPAT: usize = 216;
const OFF_FEATURES_LOG_INCOMPAT: usize = 220;
const OFF_CRC: usize = 224;
const OFF_SPINO_ALIGN: usize = 228;
const OFF_PQUOTINO: usize = 232;

const MAGIC: u32 = 0x5846_5342;

const VERSION_NUM_MASK: u16 = 0x000F;
const VERSION_4: u16 = 4;
const VERSION_5: u16 = 5;
const VERSION_MOREBITSBIT: u16 = 0x8000;

const FEAT2_LAZYSBCOUNT: u32 = 1 << 1;
const FEAT2_ATTR2: u32 = 1 << 3;
const FEAT2_PROJID32: u32 = 1 << 7;
const FEAT2_CRC: u32 = 1 << 8;
const FEAT2_FTYPE: u32 = 1 << 9;
const KNOWN_FEATURES2: u32 =
    FEAT2_LAZYSBCOUNT | FEAT2_ATTR2 | FEAT2_PROJID32 | FEAT2_CRC | FEAT2_FTYPE;

const FEAT_RO_FINOBT: u32 = 1 << 0;
const FEAT_RO_RMAPBT: u32 = 1 << 1;
const FEAT_RO_REFLINK: u32 = 1 << 2;
const FEAT_RO_INOBTCNT: u32 = 1 << 3;
const KNOWN_RO_SUPPORTED: u32 = FEAT_RO_FINOBT;
const KNOWN_RO_UNHANDLED: u32 = FEAT_RO_RMAPBT | FEAT_RO_REFLINK | FEAT_RO_INOBTCNT;

const FEAT_INC_FTYPE: u32 = 1 << 0;
const FEAT_INC_SPINODES: u32 = 1 << 1;
const FEAT_INC_META_UUID: u32 = 1 << 2;
const FEAT_INC_BIGTIME: u32 = 1 << 3;
const FEAT_INC_NEEDSREPAIR: u32 = 1 << 4;
const FEAT_INC_NREXT64: u32 = 1 << 5;
const FEAT_INC_EXCHRANGE: u32 = 1 << 6;
const FEAT_INC_PARENT: u32 = 1 << 7;
const FEAT_INC_METADIR: u32 = 1 << 8;
const FEAT_INC_ZONED: u32 = 1 << 9;
const FEAT_INC_ZONE_GAPS: u32 = 1 << 10;
const KNOWN_INC_SUPPORTED: u32 =
    FEAT_INC_FTYPE | FEAT_INC_SPINODES | FEAT_INC_META_UUID | FEAT_INC_BIGTIME | FEAT_INC_NREXT64;
const KNOWN_INC_UNHANDLED: u32 =
    FEAT_INC_EXCHRANGE | FEAT_INC_PARENT | FEAT_INC_METADIR | FEAT_INC_ZONED | FEAT_INC_ZONE_GAPS;

const MIN_BLOCK_BYTES: u64 = 512;
const MAX_BLOCK_BYTES: u64 = 65_536;
const MIN_CRC_BLOCK_BYTES: u64 = 1024;
const MIN_SECTOR_BYTES: u64 = 512;
const MAX_SECTOR_BYTES: u64 = 32_768;
const MIN_AG_BYTES: u64 = 1 << 24;
const MAX_AG_BYTES: u64 = 1 << 40;
const MIN_INODE_BYTES: u64 = 256;
const MAX_INODE_BYTES: u64 = 2048;
const INODES_PER_CHUNK: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrcStatus {
    NotApplicable,
    Verified,
    Mismatch { stored: u32, computed: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuperblockIssue {
    RealtimeSubvolumeNotSupported,
    NeedsRepairFlagSet,
    UnsupportedIncompatBits { bits: u32 },
    UnknownFeatures2Bits { bits: u32 },
    UnknownCompatBits { bits: u32 },
    UnknownRoCompatBits { bits: u32 },
    UnknownIncompatBits { bits: u32 },
    UnknownLogIncompatBits { bits: u32 },
    Features2PaddingDivergence,
}

#[derive(Debug, Clone)]
pub struct Superblock {
    pub magic: u32,
    pub block_size: u32,
    pub dblocks: u64,
    pub rblocks: u64,
    pub rextents: u64,
    pub uuid: [u8; 16],
    pub log_start: u64,
    pub root_inode: u64,
    pub rbmi_inode: u64,
    pub rsumi_inode: u64,
    pub rext_size: u32,
    pub ag_blocks: u32,
    pub ag_count: u32,
    pub rt_bitmap_blocks: u32,
    pub log_blocks: u32,
    pub version_num_raw: u16,
    pub sector_size: u32,
    pub inode_size: u32,
    pub inodes_per_block: u32,
    pub block_log: u8,
    pub sector_log: u8,
    pub inode_log: u8,
    pub inopb_log: u8,
    pub agblk_log: u8,
    pub rexts_log: u8,
    pub mkfs_in_progress: u8,
    pub imax_pct: u8,
    pub inode_count: u64,
    pub inode_free: u64,
    pub free_dblocks: u64,
    pub free_rextents: u64,
    pub user_quota_inode: u64,
    pub group_quota_inode: u64,
    pub quota_flags: u16,
    pub sb_flags: u8,
    pub shared_vn: u8,
    pub inode_align_blocks: u32,
    pub stripe_unit: u32,
    pub stripe_width: u32,
    pub dirblk_log: u8,
    pub log_sector_log: u8,
    pub log_sector_size: u16,
    pub log_sunit: u32,
    pub features2_raw: u32,
    pub bad_features2: u32,
    pub features_compat: Option<u32>,
    pub features_ro_compat: Option<u32>,
    pub features_incompat: Option<u32>,
    pub features_log_incompat: Option<u32>,
    pub spino_align: Option<u32>,
    pub project_quota_inode: Option<u64>,
    pub crc_stored: Option<u32>,
    pub crc_status: CrcStatus,
    pub issues: Vec<SuperblockIssue>,
}

impl Superblock {
    pub fn parse(
        reader: &mut dyn ImageRead,
        fs_base_offset: u64,
    ) -> Result<(Superblock, Geometry)> {
        let mut sector = [0u8; SUPERBLOCK_SECTOR_BYTES];
        reader.read_at(fs_base_offset, &mut sector)?;
        Self::parse_bytes(&sector)
    }

    pub fn parse_bytes(sector: &[u8]) -> Result<(Superblock, Geometry)> {
        if sector.len() < SUPERBLOCK_SECTOR_BYTES {
            return Err(Error::Truncated {
                needed: SUPERBLOCK_SECTOR_BYTES,
                available: sector.len(),
            });
        }
        let s = Sector { b: sector };

        let magic = s.be32(OFF_MAGIC)?;
        if magic != MAGIC {
            return Err(malformed("magic is not XFSB"));
        }

        let version_num_raw = s.be16(OFF_VERSIONNUM)?;
        let version_num = version_num_raw & VERSION_NUM_MASK;
        if version_num != VERSION_4 && version_num != VERSION_5 {
            return Err(Error::Unsupported {
                structure: "superblock format version other than 4 or 5",
            });
        }
        let is_v5 = version_num == VERSION_5;
        let morebits = version_num_raw & VERSION_MOREBITSBIT != 0;

        let block_size = s.be32(OFF_BLOCKSIZE)?;
        let block_log = s.byte(OFF_BLOCKLOG)?;
        require_pow2_with_log(
            "block size",
            block_size as u64,
            block_log,
            MIN_BLOCK_BYTES,
            MAX_BLOCK_BYTES,
        )?;
        if is_v5 && (block_size as u64) < MIN_CRC_BLOCK_BYTES {
            return Err(malformed("block size below v5 CRC minimum"));
        }

        let sector_size = s.be16(OFF_SECTSIZE)? as u32;
        let sector_log = s.byte(OFF_SECTLOG)?;
        require_pow2_with_log(
            "sector size",
            sector_size as u64,
            sector_log,
            MIN_SECTOR_BYTES,
            MAX_SECTOR_BYTES,
        )?;

        let dblocks = s.be64(OFF_DBLOCKS)?;
        let rblocks = s.be64(OFF_RBLOCKS)?;
        let rextents = s.be64(OFF_REXTENTS)?;
        let log_start = s.be64(OFF_LOGSTART)?;
        let root_inode = s.be64(OFF_ROOTINO)?;
        let rbmi_inode = s.be64(OFF_RBMINO)?;
        let rsumi_inode = s.be64(OFF_RSUMINO)?;
        let rext_size = s.be32(OFF_REXTSIZE)?;
        let ag_blocks = s.be32(OFF_AGBLOCKS)?;
        let ag_count = s.be32(OFF_AGCOUNT)?;
        let rt_bitmap_blocks = s.be32(OFF_RBMBLOCKS)?;
        let log_blocks = s.be32(OFF_LOGBLOCKS)?;
        let inode_size = s.be16(OFF_INODESIZE)? as u32;
        let inodes_per_block = s.be16(OFF_INOPBLOCK)? as u32;
        let inode_log = s.byte(OFF_INODELOG)?;
        let inopb_log = s.byte(OFF_INOPBLOG)?;
        let agblk_log = s.byte(OFF_AGBLKLOG)?;
        let rexts_log = s.byte(OFF_REXTSLOG)?;
        let mkfs_in_progress = s.byte(OFF_INPROGRESS)?;
        let imax_pct = s.byte(OFF_IMAXPCT)?;
        let inode_count = s.be64(OFF_ICOUNT)?;
        let inode_free = s.be64(OFF_IFREE)?;
        let free_dblocks = s.be64(OFF_FDBLOCKS)?;
        let free_rextents = s.be64(OFF_FREXTENTS)?;
        let user_quota_inode = s.be64(OFF_UQUOTINO)?;
        let group_quota_inode = s.be64(OFF_GQUOTINO)?;
        let quota_flags = s.be16(OFF_QFLAGS)?;
        let sb_flags = s.byte(OFF_FLAGS)?;
        let shared_vn = s.byte(OFF_SHAREDVN)?;
        let inode_align_blocks = s.be32(OFF_INOALIGNMT)?;
        let stripe_unit = s.be32(OFF_UNIT)?;
        let stripe_width = s.be32(OFF_WIDTH)?;
        let dirblk_log = s.byte(OFF_DIRBLKLOG)?;
        let log_sector_log = s.byte(OFF_LOGSECTLOG)?;
        let log_sector_size = s.be16(OFF_LOGSECTSIZE)?;
        let log_sunit = s.be32(OFF_LOGSUNIT)?;

        validate_ag_geometry(
            ag_count as u64,
            ag_blocks as u64,
            agblk_log,
            dblocks,
            block_size,
        )?;

        require_pow2_with_log(
            "inode size",
            inode_size as u64,
            inode_log,
            MIN_INODE_BYTES,
            MAX_INODE_BYTES,
        )?;
        if block_log < inode_log || block_log - inode_log != inopb_log {
            return Err(malformed("inopblog inconsistent with block and inode logs"));
        }
        let expected_inopb = block_size / inode_size;
        if inodes_per_block != expected_inopb || !log_matches(inodes_per_block as u64, inopb_log) {
            return Err(malformed(
                "inodes-per-block inconsistent with block and inode sizes",
            ));
        }
        if dirblk_log as u32 + block_log as u32 > 16 {
            return Err(malformed("directory block size exceeds maximum block size"));
        }
        if imax_pct > 100 {
            return Err(malformed("imax_pct exceeds 100 percent"));
        }
        if shared_vn != 0 {
            return Err(malformed("shared-version field nonzero"));
        }
        if dblocks == 0 {
            return Err(malformed("dblocks is zero"));
        }

        let ino_shift = agblk_log as u32 + inopb_log as u32;
        if ino_shift >= 64 {
            return Err(malformed("inode addressing shift exceeds 64 bits"));
        }

        let total_inode_capacity = dblocks
            .checked_mul(inodes_per_block as u64)
            .ok_or_else(|| malformed("inode capacity overflows 64-bit arithmetic"))?;
        if root_inode == 0 || root_inode >= total_inode_capacity {
            return Err(malformed("root inode number outside filesystem bounds"));
        }
        if root_inode >> ino_shift >= ag_count as u64 {
            return Err(malformed(
                "root inode allocation group beyond superblock ag_count",
            ));
        }
        if mkfs_in_progress != 0 {
            return Err(Error::Unsupported {
                structure: "filesystem marked mkfs-in-progress",
            });
        }

        let mut issues = Vec::new();

        let features2_raw = s.be32(OFF_FEATURES2)?;
        let bad_features2 = s.be32(OFF_BAD_FEATURES2)?;
        let features2_effective = if morebits {
            features2_raw | bad_features2
        } else {
            0
        };
        if morebits && features2_raw != bad_features2 {
            issues.push(SuperblockIssue::Features2PaddingDivergence);
        }
        let crc_bit_set = features2_effective & FEAT2_CRC != 0;
        if is_v5 && !crc_bit_set {
            return Err(malformed(
                "v5 superblock without the metadata-CRC feature bit",
            ));
        }
        if !is_v5 && crc_bit_set {
            return Err(malformed("v4 superblock with the metadata-CRC feature bit"));
        }
        let unknown_f2 = features2_effective & !KNOWN_FEATURES2;
        if unknown_f2 != 0 {
            issues.push(SuperblockIssue::UnknownFeatures2Bits { bits: unknown_f2 });
        }

        if rblocks != 0 || rextents != 0 || rt_bitmap_blocks != 0 {
            issues.push(SuperblockIssue::RealtimeSubvolumeNotSupported);
        }

        let (
            features_compat,
            features_ro_compat,
            features_incompat,
            features_log_incompat,
            spino_align,
            project_quota_inode,
            crc_stored,
            crc_status,
        ) = if is_v5 || s.be32(OFF_CRC)? != 0 {
            let compat = s.be32(OFF_FEATURES_COMPAT)?;
            let ro = s.be32(OFF_FEATURES_RO_COMPAT)?;
            let inc = s.be32(OFF_FEATURES_INCOMPAT)?;
            let login = s.be32(OFF_FEATURES_LOG_INCOMPAT)?;
            let spino = s.be32(OFF_SPINO_ALIGN)?;
            let pquot = s.be64(OFF_PQUOTINO)?;

            if inc & FEAT_INC_NEEDSREPAIR != 0 {
                issues.push(SuperblockIssue::NeedsRepairFlagSet);
            }
            let unknown_ro = ro & !(KNOWN_RO_SUPPORTED | KNOWN_RO_UNHANDLED);
            if unknown_ro != 0 {
                issues.push(SuperblockIssue::UnknownRoCompatBits { bits: unknown_ro });
            }
            let unhandled_inc = inc & KNOWN_INC_UNHANDLED;
            if unhandled_inc != 0 {
                issues.push(SuperblockIssue::UnsupportedIncompatBits {
                    bits: unhandled_inc,
                });
            }
            let unknown_inc = inc & !(KNOWN_INC_SUPPORTED | KNOWN_INC_UNHANDLED);
            if unknown_inc != 0 {
                issues.push(SuperblockIssue::UnknownIncompatBits { bits: unknown_inc });
            }
            if compat != 0 {
                issues.push(SuperblockIssue::UnknownCompatBits { bits: compat });
            }
            if login != 0 {
                issues.push(SuperblockIssue::UnknownLogIncompatBits { bits: login });
            }
            if inc & FEAT_INC_SPINODES != 0 {
                let expected_align = (INODES_PER_CHUNK * inode_size as u64) >> block_log;
                if inode_align_blocks as u64 != expected_align {
                    return Err(malformed(
                        "sparse-inode alignment inconsistent with inode geometry",
                    ));
                }
            }

            let stored = u32::from_le_bytes([
                sector[OFF_CRC],
                sector[OFF_CRC + 1],
                sector[OFF_CRC + 2],
                sector[OFF_CRC + 3],
            ]);
            let computed = compute_sb_crc(sector, sector_size as usize);
            let status = if stored == computed {
                CrcStatus::Verified
            } else {
                CrcStatus::Mismatch { stored, computed }
            };
            (
                Some(compat),
                Some(ro),
                Some(inc),
                Some(login),
                Some(spino),
                Some(pquot),
                Some(stored),
                status,
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

        let sb = Superblock {
            magic,
            block_size,
            dblocks,
            rblocks,
            rextents,
            uuid: {
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(s.slice(OFF_UUID, 16)?);
                uuid
            },
            log_start,
            root_inode,
            rbmi_inode,
            rsumi_inode,
            rext_size,
            ag_blocks,
            ag_count,
            rt_bitmap_blocks,
            log_blocks,
            version_num_raw,
            sector_size,
            inode_size,
            inodes_per_block,
            block_log,
            sector_log,
            inode_log,
            inopb_log,
            agblk_log,
            rexts_log,
            mkfs_in_progress,
            imax_pct,
            inode_count,
            inode_free,
            free_dblocks,
            free_rextents,
            user_quota_inode,
            group_quota_inode,
            quota_flags,
            sb_flags,
            shared_vn,
            inode_align_blocks,
            stripe_unit,
            stripe_width,
            dirblk_log,
            log_sector_log,
            log_sector_size,
            log_sunit,
            features2_raw,
            bad_features2,
            features_compat,
            features_ro_compat,
            features_incompat,
            features_log_incompat,
            spino_align,
            project_quota_inode,
            crc_stored,
            crc_status,
            issues,
        };

        let total_bytes = dblocks
            .checked_mul(block_size as u64)
            .ok_or_else(|| malformed("filesystem size overflows 64-bit arithmetic"))?;

        let geometry = Geometry {
            block_bytes: block_size as u64,
            ag_blocks: ag_blocks as u64,
            ag_count,
            inode_bytes: inode_size as u64,
            inodes_per_block: inodes_per_block as u64,
            agblk_log,
            inopb_log,
            ino_shift,
            dblocks,
            total_bytes,
        };

        Ok((sb, geometry))
    }

    pub fn version_num(&self) -> u16 {
        self.version_num_raw & VERSION_NUM_MASK
    }

    pub fn version5(&self) -> bool {
        self.version_num() == VERSION_5
    }

    pub fn features2_effective(&self) -> u32 {
        if self.version_num_raw & VERSION_MOREBITSBIT != 0 {
            self.features2_raw | self.bad_features2
        } else {
            0
        }
    }

    pub fn crc_enabled(&self) -> bool {
        self.version5() || self.features2_effective() & FEAT2_CRC != 0
    }

    fn feature_ro(&self, bit: u32) -> bool {
        self.features_ro_compat.is_some_and(|v| v & bit != 0)
    }

    fn feature_inc(&self, bit: u32) -> bool {
        self.features_incompat.is_some_and(|v| v & bit != 0)
    }

    pub fn finobt_enabled(&self) -> bool {
        self.version5() && self.feature_ro(FEAT_RO_FINOBT)
    }

    pub fn sparse_inodes_enabled(&self) -> bool {
        self.version5() && self.feature_inc(FEAT_INC_SPINODES)
    }

    pub fn nrext64_enabled(&self) -> bool {
        self.version5() && self.feature_inc(FEAT_INC_NREXT64)
    }

    pub fn meta_uuid_enabled(&self) -> bool {
        self.version5() && self.feature_inc(FEAT_INC_META_UUID)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Geometry {
    block_bytes: u64,
    ag_blocks: u64,
    ag_count: u32,
    inode_bytes: u64,
    inodes_per_block: u64,
    agblk_log: u8,
    inopb_log: u8,
    ino_shift: u32,
    dblocks: u64,
    total_bytes: u64,
}

impl Geometry {
    pub fn fs_block_bytes(&self) -> u32 {
        self.block_bytes as u32
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn dblocks(&self) -> u64 {
        self.dblocks
    }

    pub fn ag_count(&self) -> u32 {
        self.ag_count
    }

    pub fn ag_blocks(&self) -> u32 {
        self.ag_blocks as u32
    }

    pub fn inodes_per_block(&self) -> u32 {
        self.inodes_per_block as u32
    }

    pub fn agblk_log(&self) -> u8 {
        self.agblk_log
    }

    pub fn ag_start_byte(&self, ag_number: u32) -> Result<u64> {
        if ag_number >= self.ag_count {
            return Err(Error::Malformed {
                structure: "allocation group index",
                reason: "ag_number beyond superblock ag_count",
            });
        }
        (ag_number as u64)
            .checked_mul(self.ag_blocks)
            .and_then(|blocks| blocks.checked_mul(self.block_bytes))
            .ok_or(Error::Malformed {
                structure: "allocation group index",
                reason: "byte offset computation overflows 64-bit arithmetic",
            })
    }

    pub fn ag_no_of_ino(&self, inode_number: u64) -> Result<u32> {
        let ag = (inode_number >> self.ino_shift) as u32;
        if ag >= self.ag_count {
            return Err(Error::Malformed {
                structure: "inode number",
                reason: "references allocation group beyond superblock ag_count",
            });
        }
        Ok(ag)
    }

    pub fn inode_locate(&self, inode_number: u64) -> Result<(u32, u64, u64)> {
        let ag = self.ag_no_of_ino(inode_number)?;
        let rel = inode_number & ((1u64 << self.ino_shift) - 1);
        let ag_block = rel >> self.inopb_log;
        if ag_block >= self.ag_blocks {
            return Err(Error::Malformed {
                structure: "inode number",
                reason: "block offset beyond superblock ag_blocks",
            });
        }
        let offset_in_block = (rel & ((1u64 << self.inopb_log) - 1)) * self.inode_bytes;
        Ok((ag, ag_block, offset_in_block))
    }

    pub fn inode_fs_byte(&self, inode_number: u64) -> Result<u64> {
        let (ag, ag_block, offset_in_block) = self.inode_locate(inode_number)?;
        let base = self.ag_start_byte(ag)?;
        let block_off = ag_block
            .checked_mul(self.block_bytes)
            .ok_or(Error::Malformed {
                structure: "inode number",
                reason: "byte offset computation overflows 64-bit arithmetic",
            })?;
        base.checked_add(block_off)
            .and_then(|v| v.checked_add(offset_in_block))
            .ok_or(Error::Malformed {
                structure: "inode number",
                reason: "byte offset computation overflows 64-bit arithmetic",
            })
    }
}

struct Sector<'a> {
    b: &'a [u8],
}

impl Sector<'_> {
    fn slice(&self, off: usize, len: usize) -> Result<&[u8]> {
        self.b.get(off..off + len).ok_or(Error::Truncated {
            needed: off + len,
            available: self.b.len(),
        })
    }

    fn byte(&self, off: usize) -> Result<u8> {
        self.b.get(off).copied().ok_or(Error::Truncated {
            needed: off + 1,
            available: self.b.len(),
        })
    }

    fn be16(&self, off: usize) -> Result<u16> {
        be_u16_at(self.b, off)
    }

    fn be32(&self, off: usize) -> Result<u32> {
        be_u32_at(self.b, off)
    }

    fn be64(&self, off: usize) -> Result<u64> {
        be_u64_at(self.b, off)
    }
}

fn malformed(reason: &'static str) -> Error {
    Error::Malformed {
        structure: "superblock",
        reason,
    }
}

fn compute_sb_crc(sector: &[u8], sector_size: usize) -> u32 {
    let coverage = sector_size.min(sector.len());
    let mut scratch = vec![0u8; coverage];
    scratch.copy_from_slice(&sector[..coverage]);
    scratch[OFF_CRC..OFF_CRC + 4].fill(0);
    crc32c(&scratch)
}

fn log_matches(value: u64, log: u8) -> bool {
    log < 64 && value.is_power_of_two() && (value.trailing_zeros() as u8) == log
}

fn require_pow2_with_log(
    name: &'static str,
    value: u64,
    log: u8,
    min: u64,
    max: u64,
) -> Result<()> {
    if value < min || value > max {
        return Err(Error::Malformed {
            structure: name,
            reason: "outside supported range",
        });
    }
    if !log_matches(value, log) {
        return Err(Error::Malformed {
            structure: name,
            reason: "size-log field inconsistent with size",
        });
    }
    Ok(())
}

fn validate_ag_geometry(
    ag_count: u64,
    ag_blocks: u64,
    agblk_log: u8,
    dblocks: u64,
    block_size: u32,
) -> Result<()> {
    if ag_count == 0 {
        return Err(malformed("ag_count is zero"));
    }
    if ag_blocks == 0 {
        return Err(malformed("ag_blocks is zero"));
    }
    let ag_bytes = ag_blocks
        .checked_mul(block_size as u64)
        .ok_or_else(|| malformed("AG size overflows 64-bit arithmetic"))?;
    if ag_bytes < MIN_AG_BYTES {
        return Err(malformed("AG size below supported minimum of 16 MiB"));
    }
    if ag_bytes > MAX_AG_BYTES {
        return Err(malformed("AG size above supported maximum of 1 TiB"));
    }
    let expected_agblk_log = (ag_blocks - 1).checked_ilog2().unwrap_or(0) + 1;
    if agblk_log as u32 != expected_agblk_log {
        return Err(malformed("agblk_log inconsistent with ag_blocks"));
    }
    let before_last = (ag_count - 1)
        .checked_mul(ag_blocks)
        .ok_or_else(|| malformed("AG geometry overflows 64-bit arithmetic"))?;
    let all = ag_count
        .checked_mul(ag_blocks)
        .ok_or_else(|| malformed("AG geometry overflows 64-bit arithmetic"))?;
    if dblocks <= before_last || dblocks > all {
        return Err(malformed(
            "dblocks inconsistent with ag_count and ag_blocks geometry",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemImage;

    const BS: u32 = 4096;
    const INODE_SIZE: u16 = 512;
    const AGB: u32 = 16384;
    const AGC: u32 = 4;
    const DBLOCKS: u64 = 65_536;
    const V4_FLAGS: u16 = 0xBD74;
    const F2_CLEAN: u32 = FEAT2_LAZYSBCOUNT | FEAT2_ATTR2 | FEAT2_FTYPE;

    fn put16(dst: &mut [u8], off: usize, v: u16) {
        dst[off..off + 2].copy_from_slice(&v.to_be_bytes());
    }

    fn put32(dst: &mut [u8], off: usize, v: u32) {
        dst[off..off + 4].copy_from_slice(&v.to_be_bytes());
    }

    fn put32le(dst: &mut [u8], off: usize, v: u32) {
        dst[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn put64(dst: &mut [u8], off: usize, v: u64) {
        dst[off..off + 8].copy_from_slice(&v.to_be_bytes());
    }

    fn golden_v4() -> [u8; SUPERBLOCK_SECTOR_BYTES] {
        let mut b = [0u8; SUPERBLOCK_SECTOR_BYTES];
        put32(&mut b, OFF_MAGIC, MAGIC);
        put32(&mut b, OFF_BLOCKSIZE, BS);
        put64(&mut b, OFF_DBLOCKS, DBLOCKS);
        put64(&mut b, OFF_ROOTINO, 128);
        put32(&mut b, OFF_AGBLOCKS, AGB);
        put32(&mut b, OFF_AGCOUNT, AGC);
        put16(&mut b, OFF_VERSIONNUM, V4_FLAGS);
        put16(&mut b, OFF_SECTSIZE, 512);
        put16(&mut b, OFF_INODESIZE, INODE_SIZE);
        put16(&mut b, OFF_INOPBLOCK, (BS as u16) / INODE_SIZE);
        b[OFF_BLOCKLOG] = 12;
        b[OFF_SECTLOG] = 9;
        b[OFF_INODELOG] = 9;
        b[OFF_INOPBLOG] = 3;
        b[OFF_AGBLKLOG] = 14;
        put32(&mut b, OFF_INOALIGNMT, 8);
        put32(&mut b, OFF_FEATURES2, F2_CLEAN);
        put32(&mut b, OFF_BAD_FEATURES2, F2_CLEAN);
        b
    }

    fn seal_crc(b: &mut [u8], sector_size: usize) {
        b[OFF_CRC..OFF_CRC + 4].copy_from_slice(&0u32.to_le_bytes());
        let coverage = sector_size.min(b.len());
        let crc = crc32c(&b[..coverage]);
        put32le(b, OFF_CRC, crc);
    }

    fn golden_v5() -> [u8; SUPERBLOCK_SECTOR_BYTES] {
        let mut b = golden_v4();
        put16(&mut b, OFF_VERSIONNUM, V4_FLAGS | 1);
        put32(&mut b, OFF_FEATURES2, F2_CLEAN | FEAT2_CRC);
        put32(&mut b, OFF_BAD_FEATURES2, F2_CLEAN | FEAT2_CRC);
        put32(&mut b, OFF_FEATURES_COMPAT, 0);
        put32(
            &mut b,
            OFF_FEATURES_RO_COMPAT,
            FEAT_RO_FINOBT | FEAT_RO_REFLINK,
        );
        put32(&mut b, OFF_FEATURES_INCOMPAT, KNOWN_INC_SUPPORTED);
        put32(&mut b, OFF_FEATURES_LOG_INCOMPAT, 0);
        put32(&mut b, OFF_SPINO_ALIGN, 8);
        put64(&mut b, OFF_PQUOTINO, 0);
        seal_crc(&mut b, SUPERBLOCK_SECTOR_BYTES);
        b
    }

    fn parse_ok(sector: &[u8]) -> (Superblock, Geometry) {
        Superblock::parse_bytes(sector).expect("golden superblock must parse")
    }

    #[test]
    fn golden_v4_parses_with_expected_capabilities() {
        let (sb, geo) = parse_ok(&golden_v4());
        assert!(!sb.version5());
        assert_eq!(sb.version_num(), 4);
        assert!(!sb.crc_enabled());
        assert_eq!(sb.crc_status, CrcStatus::NotApplicable);
        assert!(sb.crc_stored.is_none());
        assert!(!sb.finobt_enabled());
        assert!(!sb.sparse_inodes_enabled());
        assert!(!sb.nrext64_enabled());
        assert!(sb.issues.is_empty());
        assert_eq!(sb.root_inode, 128);
        assert_eq!(geo.fs_block_bytes(), BS);
        assert_eq!(geo.total_bytes(), DBLOCKS * BS as u64);
    }

    #[test]
    fn golden_v5_parses_with_expected_capabilities_and_crc_verified() {
        let (sb, geo) = parse_ok(&golden_v5());
        assert!(sb.version5());
        assert!(sb.crc_enabled());
        assert_eq!(sb.crc_status, CrcStatus::Verified);
        assert!(sb.finobt_enabled());
        assert!(sb.sparse_inodes_enabled());
        assert!(sb.nrext64_enabled());
        assert!(sb.meta_uuid_enabled());
        assert!(sb.issues.is_empty());
        assert_eq!(geo.fs_block_bytes(), BS);
        assert_eq!(geo.total_bytes(), DBLOCKS * BS as u64);
        assert_eq!(
            sb.features_ro_compat,
            Some(FEAT_RO_FINOBT | FEAT_RO_REFLINK)
        );
        assert_eq!(sb.features_incompat, Some(KNOWN_INC_SUPPORTED));
        assert_eq!(sb.spino_align, Some(8));
    }

    #[test]
    fn geometry_helpers_match_golden_values() {
        let (_, geo) = parse_ok(&golden_v5());
        assert_eq!(geo.ag_start_byte(0).unwrap(), 0);
        assert_eq!(geo.ag_start_byte(1).unwrap(), 67_108_864);
        assert_eq!(geo.ag_start_byte(3).unwrap(), 201_326_592);
        assert_eq!(geo.dblocks(), DBLOCKS);
        assert!(geo.ag_start_byte(4).is_err());
    }

    #[test]
    fn inode_location_math_is_exact() {
        let (_, geo) = parse_ok(&golden_v5());
        assert_eq!(geo.ag_no_of_ino(0x40150).unwrap(), 2);
        assert_eq!(geo.inode_locate(0x40150).unwrap(), (2, 42, 0));
        assert_eq!(geo.inode_locate(0x40153).unwrap(), (2, 42, 1536));
        assert_eq!(geo.inode_locate(0x7FFFF).unwrap(), (3, 16_383, 3_584));
        assert_eq!(geo.inode_fs_byte(0x40150).unwrap(), 134_217_728 + 42 * 4096);
    }

    #[test]
    fn inode_outside_filesystem_bounds_errors() {
        let (_, geo) = parse_ok(&golden_v5());
        assert!(geo.inode_locate(4 << 17).is_err());
        assert!(geo.ag_no_of_ino(4 << 17).is_err());
        assert!(geo.inode_fs_byte(4 << 17).is_err());
    }

    #[test]
    fn inode_blocks_beyond_non_pow2_ag_are_rejected() {
        let mut b = golden_v5();
        put32(&mut b, OFF_AGBLOCKS, 12_288);
        b[OFF_AGBLKLOG] = 14;
        put32(&mut b, OFF_AGCOUNT, 3);
        put64(&mut b, OFF_DBLOCKS, 36_864);
        seal_crc(&mut b, SUPERBLOCK_SECTOR_BYTES);
        let (_, geo) = parse_ok(&b);
        assert_eq!(geo.inode_locate(12_287 << 3).unwrap(), (0, 12_287, 0));
        assert!(geo.inode_locate(13_000 << 3).is_err());
        assert_eq!(geo.ag_start_byte(2).unwrap(), 100_663_296);
    }

    #[test]
    fn invalid_magic_is_rejected() {
        let mut b = golden_v5();
        b[OFF_MAGIC] ^= 0xFF;
        assert!(matches!(
            Superblock::parse_bytes(&b),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn invalid_block_sizes_are_rejected() {
        let mut b = golden_v5();
        put32(&mut b, OFF_BLOCKSIZE, 3000);
        assert!(Superblock::parse_bytes(&b).is_err());

        let mut b = golden_v5();
        b[OFF_BLOCKLOG] = 13;
        assert!(Superblock::parse_bytes(&b).is_err());

        let mut b = golden_v5();
        put32(&mut b, OFF_BLOCKSIZE, 512);
        put32(&mut b, OFF_FEATURES_COMPAT, 0);
        assert!(matches!(
            Superblock::parse_bytes(&b),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn invalid_sector_size_is_rejected() {
        let mut b = golden_v5();
        put16(&mut b, OFF_SECTSIZE, 40_000);
        assert!(Superblock::parse_bytes(&b).is_err());
    }

    #[test]
    fn invalid_ag_geometry_is_rejected() {
        let mut b = golden_v5();
        put32(&mut b, OFF_AGCOUNT, 0);
        assert!(Superblock::parse_bytes(&b).is_err());

        let mut b = golden_v5();
        put32(&mut b, OFF_AGBLOCKS, 1024);
        b[OFF_AGBLKLOG] = 10;
        put64(&mut b, OFF_DBLOCKS, 4096);
        assert!(matches!(
            Superblock::parse_bytes(&b),
            Err(Error::Malformed { .. })
        ));

        let mut b = golden_v5();
        b[OFF_AGBLKLOG] = 15;
        assert!(Superblock::parse_bytes(&b).is_err());

        let mut b = golden_v5();
        put64(&mut b, OFF_DBLOCKS, 49_152);
        assert!(Superblock::parse_bytes(&b).is_err());

        let mut b = golden_v5();
        put64(&mut b, OFF_DBLOCKS, 0);
        assert!(Superblock::parse_bytes(&b).is_err());
    }

    #[test]
    fn invalid_inode_geometry_is_rejected() {
        let mut b = golden_v5();
        put16(&mut b, OFF_INODESIZE, 128);
        b[OFF_INODELOG] = 7;
        assert!(Superblock::parse_bytes(&b).is_err());

        let mut b = golden_v5();
        put16(&mut b, OFF_INOPBLOCK, 4);
        assert!(Superblock::parse_bytes(&b).is_err());
    }

    #[test]
    fn other_field_sanity_checks_are_enforced() {
        let mut b = golden_v5();
        b[OFF_DIRBLKLOG] = 5;
        assert!(Superblock::parse_bytes(&b).is_err());

        let mut b = golden_v5();
        b[OFF_IMAXPCT] = 101;
        assert!(Superblock::parse_bytes(&b).is_err());

        let mut b = golden_v5();
        b[OFF_SHAREDVN] = 1;
        assert!(Superblock::parse_bytes(&b).is_err());

        let mut b = golden_v5();
        b[OFF_INPROGRESS] = 1;
        assert!(matches!(
            Superblock::parse_bytes(&b),
            Err(Error::Unsupported { .. })
        ));
    }

    #[test]
    fn root_inode_bounds_are_enforced() {
        let mut b = golden_v5();
        put64(&mut b, OFF_ROOTINO, 0);
        assert!(Superblock::parse_bytes(&b).is_err());

        let mut b = golden_v5();
        put64(&mut b, OFF_ROOTINO, DBLOCKS * 8);
        assert!(Superblock::parse_bytes(&b).is_err());
    }

    #[test]
    fn truncated_input_never_panics() {
        let b = golden_v5();
        assert!(matches!(
            Superblock::parse_bytes(&b[..100]),
            Err(Error::Truncated {
                needed: 512,
                available: 100
            })
        ));

        let mut img = MemImage::new(&b[..100]);
        assert!(matches!(
            Superblock::parse(&mut img, 0),
            Err(Error::OutOfBounds { .. })
        ));
    }

    #[test]
    fn unsupported_versions_are_rejected_cleanly() {
        for raw in [0xBD73u16, 0xBD76] {
            let mut b = golden_v5();
            put16(&mut b, OFF_VERSIONNUM, raw);
            assert!(matches!(
                Superblock::parse_bytes(&b),
                Err(Error::Unsupported { .. })
            ));
        }
    }

    #[test]
    fn crc_feature_bit_must_match_version() {
        let mut b = golden_v4();
        put32(&mut b, OFF_FEATURES2, F2_CLEAN | FEAT2_CRC);
        put32(&mut b, OFF_BAD_FEATURES2, F2_CLEAN | FEAT2_CRC);
        assert!(Superblock::parse_bytes(&b).is_err());

        let mut b = golden_v5();
        let f2 = F2_CLEAN;
        put32(&mut b, OFF_FEATURES2, f2);
        put32(&mut b, OFF_BAD_FEATURES2, f2);
        assert!(Superblock::parse_bytes(&b).is_err());
    }

    #[test]
    fn v5_crc_mismatch_is_reported_without_aborting_parse() {
        let mut b = golden_v5();
        b[OFF_FDBLOCKS] ^= 0x55;
        let (sb, _) = Superblock::parse_bytes(&b).expect("crc mismatch must not abort parse");
        match sb.crc_status {
            CrcStatus::Mismatch { stored, computed } => {
                assert_ne!(stored, computed);
            }
            other => panic!("expected mismatch, got {other:?}"),
        }
        assert!(sb.issues.is_empty());
    }

    #[test]
    fn corruption_after_crc_field_is_detected() {
        let mut b = golden_v5();
        b[OFF_SPINO_ALIGN] ^= 0xFF;
        let (sb, _) = Superblock::parse_bytes(&b).expect("parse still succeeds");
        assert!(matches!(sb.crc_status, CrcStatus::Mismatch { .. }));
    }

    #[test]
    fn larger_sector_superblocks_cover_full_sector_crc() {
        let mut b = [0u8; 1024];
        b[..SUPERBLOCK_SECTOR_BYTES].copy_from_slice(&golden_v5());
        put16(&mut b, OFF_SECTSIZE, 1024);
        b[OFF_SECTLOG] = 10;
        seal_crc(&mut b, 1024);

        let (sb, _) = parse_ok(&b);
        assert_eq!(sb.sector_size, 1024);
        assert_eq!(sb.crc_status, CrcStatus::Verified);

        let mut truncated_input = [0u8; SUPERBLOCK_SECTOR_BYTES];
        truncated_input.copy_from_slice(&b[..SUPERBLOCK_SECTOR_BYTES]);
        let (sb_short, _) = parse_ok(&truncated_input);
        assert!(matches!(sb_short.crc_status, CrcStatus::Mismatch { .. }));

        let mut corrupted = b;
        corrupted[700] ^= 0xFF;
        let (sb_bad, _) = Superblock::parse_bytes(&corrupted).unwrap();
        assert!(matches!(sb_bad.crc_status, CrcStatus::Mismatch { .. }));
    }

    #[test]
    fn v4_with_nonzero_crc_field_gets_checked_like_kernel() {
        let mut b = golden_v4();
        put32le(&mut b, OFF_CRC, 0xDEAD_BEEF);
        let (sb, _) = Superblock::parse_bytes(&b).expect("v4 with junk crc parses");
        assert!(matches!(sb.crc_status, CrcStatus::Mismatch { .. }));
    }

    #[test]
    fn realtime_subvolume_reported_as_issue_not_error() {
        let mut b = golden_v4();
        put64(&mut b, OFF_RBLOCKS, 100);
        let (sb, _) = parse_ok(&b);
        assert!(
            sb.issues
                .contains(&SuperblockIssue::RealtimeSubvolumeNotSupported)
        );
    }

    #[test]
    fn reserved_rt_inodes_alone_do_not_imply_realtime() {
        let mut b = golden_v5();
        put64(&mut b, OFF_RBMINO, 129);
        put64(&mut b, OFF_RSUMINO, 130);
        put32(&mut b, OFF_REXTSIZE, 1);
        let (sb, _) = parse_ok(&b);
        assert!(sb.issues.is_empty());
    }

    #[test]
    fn needsrepair_flag_reported_as_issue() {
        let mut b = golden_v5();
        let inc = KNOWN_INC_SUPPORTED | FEAT_INC_NEEDSREPAIR;
        put32(&mut b, OFF_FEATURES_INCOMPAT, inc);
        seal_crc(&mut b, SUPERBLOCK_SECTOR_BYTES);
        let (sb, _) = parse_ok(&b);
        assert!(sb.issues.contains(&SuperblockIssue::NeedsRepairFlagSet));
    }

    #[test]
    fn feature_bit_classification_issues() {
        let mut b = golden_v5();
        let inc = KNOWN_INC_SUPPORTED | KNOWN_INC_UNHANDLED | (1 << 11);
        put32(&mut b, OFF_FEATURES_INCOMPAT, inc);
        put32(&mut b, OFF_FEATURES_RO_COMPAT, FEAT_RO_FINOBT | (1 << 20));
        put32(&mut b, OFF_FEATURES_COMPAT, 1);
        put32(&mut b, OFF_FEATURES_LOG_INCOMPAT, 1);
        seal_crc(&mut b, SUPERBLOCK_SECTOR_BYTES);
        let (sb, _) = parse_ok(&b);
        assert!(
            sb.issues
                .contains(&SuperblockIssue::UnsupportedIncompatBits {
                    bits: KNOWN_INC_UNHANDLED
                })
        );
        assert!(
            sb.issues
                .contains(&SuperblockIssue::UnknownIncompatBits { bits: 1 << 11 })
        );
        assert!(
            sb.issues
                .contains(&SuperblockIssue::UnknownRoCompatBits { bits: 1 << 20 })
        );
        assert!(
            sb.issues
                .contains(&SuperblockIssue::UnknownCompatBits { bits: 1 })
        );
        assert!(
            sb.issues
                .contains(&SuperblockIssue::UnknownLogIncompatBits { bits: 1 })
        );
    }

    #[test]
    fn features2_padding_divergence_reported_but_union_applied() {
        let mut b = golden_v4();
        put32(&mut b, OFF_FEATURES2, F2_CLEAN);
        put32(&mut b, OFF_BAD_FEATURES2, F2_CLEAN | FEAT2_PROJID32);
        let (sb, _) = parse_ok(&b);
        assert!(
            sb.issues
                .contains(&SuperblockIssue::Features2PaddingDivergence)
        );
        assert_eq!(sb.features2_effective(), F2_CLEAN | FEAT2_PROJID32);
    }

    #[test]
    fn sparse_alignment_mismatch_rejected() {
        let mut b = golden_v5();
        put32(&mut b, OFF_INOALIGNMT, 9);
        assert!(Superblock::parse_bytes(&b).is_err());
    }
}
