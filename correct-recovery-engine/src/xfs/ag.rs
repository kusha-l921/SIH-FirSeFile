use crate::error::{Error, Result};
use crate::io::ImageRead;
use crate::util::be::{be_u32_at, be_u64_at};
use crate::util::crc32c::crc32c_with_zeroed_range;
use crate::xfs::superblock::{CrcStatus, Geometry, Superblock};

pub const AGF_SECTOR_INDEX: u64 = 1;
pub const AGI_SECTOR_INDEX: u64 = 2;
pub const AGFL_SECTOR_INDEX: u64 = 3;

const AGF_MAGIC: u32 = 0x5841_4746;
const AGI_MAGIC: u32 = 0x5841_4749;
const AGFL_MAGIC: u32 = 0x5841_464C;

const AGF_HEADER_VERSION: u32 = 1;
const AGI_HEADER_VERSION: u32 = 1;

const NULLAGINO: u32 = u32::MAX;

const OFF_AGF_MAGIC: usize = 0;
const OFF_AGF_VERSION: usize = 4;
const OFF_AGF_SEQNO: usize = 8;
const OFF_AGF_LENGTH: usize = 12;
const OFF_AGF_BNO_ROOT: usize = 16;
const OFF_AGF_CNT_ROOT: usize = 20;
const OFF_AGF_RMAP_ROOT: usize = 24;
const OFF_AGF_BNO_LEVEL: usize = 28;
const OFF_AGF_CNT_LEVEL: usize = 32;
const OFF_AGF_RMAP_LEVEL: usize = 36;
const OFF_AGF_FLFIRST: usize = 40;
const OFF_AGF_FLLAST: usize = 44;
const OFF_AGF_FLCOUNT: usize = 48;
const OFF_AGF_FREEBLKS: usize = 52;
const OFF_AGF_LONGEST: usize = 56;
const OFF_AGF_BTREEBLKS: usize = 60;
const OFF_AGF_UUID: usize = 64;
const OFF_AGF_RMAP_BLOCKS: usize = 80;
const OFF_AGF_REFCOUNT_BLOCKS: usize = 84;
const OFF_AGF_REFCOUNT_ROOT: usize = 88;
const OFF_AGF_REFCOUNT_LEVEL: usize = 92;
const OFF_AGF_LSN: usize = 208;
const OFF_AGF_CRC: usize = 216;

const OFF_AGI_MAGIC: usize = 0;
const OFF_AGI_VERSION: usize = 4;
const OFF_AGI_SEQNO: usize = 8;
const OFF_AGI_LENGTH: usize = 12;
const OFF_AGI_COUNT: usize = 16;
const OFF_AGI_ROOT: usize = 20;
const OFF_AGI_LEVEL: usize = 24;
const OFF_AGI_FREECOUNT: usize = 28;
const OFF_AGI_NEWINO: usize = 32;
const OFF_AGI_DIRINO: usize = 36;
const OFF_AGI_UNLINKED: usize = 40;
const AGI_UNLINKED_BUCKETS: usize = 64;
const OFF_AGI_UUID: usize = 296;
const OFF_AGI_CRC: usize = 312;
const OFF_AGI_LSN: usize = 320;
const OFF_AGI_FINO_ROOT: usize = 328;
const OFF_AGI_FINO_LEVEL: usize = 332;
const OFF_AGI_IBLOCKS: usize = 336;
const OFF_AGI_FBLOCKS: usize = 340;

const OFF_AGFL_MAGIC: usize = 0;
const OFF_AGFL_SEQNO: usize = 4;
const OFF_AGFL_UUID: usize = 8;
const OFF_AGFL_LSN: usize = 24;
const OFF_AGFL_CRC: usize = 32;
const OFF_AGFL_ENTRIES: usize = 36;
const AGFL_HEADER_BYTES_V5: usize = 36;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgHeaderOffsets {
    pub agf_byte_offset: u64,
    pub agi_byte_offset: u64,
    pub agfl_byte_offset: u64,
}

pub fn ag_header_offsets(
    geometry: &Geometry,
    sector_bytes: u32,
    ag_number: u32,
) -> Result<AgHeaderOffsets> {
    let base = geometry.ag_start_byte(ag_number)?;
    let sector = sector_bytes as u64;
    Ok(AgHeaderOffsets {
        agf_byte_offset: base + AGF_SECTOR_INDEX * sector,
        agi_byte_offset: base + AGI_SECTOR_INDEX * sector,
        agfl_byte_offset: base + AGFL_SECTOR_INDEX * sector,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgIssue {
    UuidMismatch,
    InvalidUnlinkedBucket {
        index: usize,
        value: u32,
    },
    ImplausibleInodeCounts {
        count: u32,
        freecount: u32,
        capacity: u32,
    },
    AgflEntryOutOfRange {
        slot: u32,
        value: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RmapBtInfo {
    pub root: u32,
    pub level: u32,
    pub blocks: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefcountBtInfo {
    pub root: u32,
    pub level: u32,
    pub blocks: u32,
}

#[derive(Debug, Clone)]
pub struct Agf {
    pub seqno: u32,
    pub length_blocks: u32,
    pub free_blocks: u32,
    pub longest_free: u32,
    pub btree_blocks: u32,
    pub bnobt_root: u32,
    pub bnobt_level: u32,
    pub cntbt_root: u32,
    pub cntbt_level: u32,
    pub rmapbt: Option<RmapBtInfo>,
    pub refcountbt: Option<RefcountBtInfo>,
    pub flfirst: u32,
    pub fllast: u32,
    pub flcount: u32,
    pub uuid: Option<[u8; 16]>,
    pub lsn: Option<u64>,
    pub crc_status: CrcStatus,
    pub issues: Vec<AgIssue>,
}

#[derive(Debug, Clone)]
pub struct Agfl {
    pub seqno: Option<u32>,
    pub capacity: usize,
    pub entries: Vec<u32>,
    pub uuid: Option<[u8; 16]>,
    pub lsn: Option<u64>,
    pub crc_status: CrcStatus,
    pub issues: Vec<AgIssue>,
}

#[derive(Debug, Clone)]
pub struct Agi {
    pub version: u32,
    pub seqno: u32,
    pub length_blocks: u32,
    pub inode_capacity: u32,
    pub inode_count: u32,
    pub free_inode_count: u32,
    pub inobt_root: u32,
    pub inobt_level: u32,
    pub finobt: Option<(u32, u32)>,
    pub inobt_blocks: Option<u32>,
    pub finobt_blocks: Option<u32>,
    pub newino: u32,
    pub dirino: u32,
    pub unlinked_buckets: [u32; AGI_UNLINKED_BUCKETS],
    pub uuid: Option<[u8; 16]>,
    pub lsn: Option<u64>,
    pub crc_status: CrcStatus,
    pub issues: Vec<AgIssue>,
}

impl Agi {
    pub fn unlinked_heads(&self) -> impl Iterator<Item = (usize, u32)> + '_ {
        self.unlinked_buckets
            .iter()
            .enumerate()
            .filter(|(_index, value)| {
                **value != 0
                    && **value != NULLAGINO
                    && (**value as u64) < self.inode_capacity as u64
            })
            .map(|(index, value)| (index, *value))
    }
}

#[derive(Debug, Clone)]
pub struct AllocationGroup {
    pub number: u32,
    pub agf: Agf,
    pub agi: Agi,
    pub agfl: Agfl,
}

fn read_header_sector(
    reader: &mut dyn ImageRead,
    fs_base_offset: u64,
    geometry: &Geometry,
    sb: &Superblock,
    ag_number: u32,
    sector_index: u64,
) -> Result<Vec<u8>> {
    let header_byte = geometry.ag_start_byte(ag_number)? + sector_index * sb.sector_size as u64;
    let mut buf = vec![0u8; sb.sector_size as usize];
    reader.read_at(fs_base_offset + header_byte, &mut buf)?;
    Ok(buf)
}

fn require(cond: bool, structure: &'static str, reason: &'static str) -> Result<()> {
    if cond {
        Ok(())
    } else {
        Err(Error::Malformed { structure, reason })
    }
}

fn expected_ag_length(geometry: &Geometry, ag_number: u32) -> Result<u32> {
    let ag_blocks = geometry.ag_blocks() as u64;
    if ag_number + 1 == geometry.ag_count() {
        let last = geometry.dblocks() - (geometry.ag_count() as u64 - 1) * ag_blocks;
        u32::try_from(last).map_err(|_| Error::Malformed {
            structure: "AG header",
            reason: "last allocation group length exceeds 32-bit block range",
        })
    } else {
        Ok(ag_blocks as u32)
    }
}

fn validate_tree_root(root: u32, level: u32, limit: u32, structure: &'static str) -> Result<()> {
    if level == 0 {
        require(root == 0, structure, "level-zero tree must have null root")
    } else {
        require(root != 0, structure, "non-empty tree has null root")?;
        require(
            (root as u64) < limit as u64,
            structure,
            "btree root block beyond allocation group bounds",
        )
    }
}

fn check_uuid(field: Option<[u8; 16]>, sb_uuid: &[u8; 16], issues: &mut Vec<AgIssue>) {
    if let Some(uuid) = field
        && &uuid != sb_uuid
    {
        issues.push(AgIssue::UuidMismatch);
    }
}

fn crc_status_for(buf: &[u8], crc_offset: usize, v5_required: bool) -> CrcStatus {
    let stored = u32::from_le_bytes([
        buf[crc_offset],
        buf[crc_offset + 1],
        buf[crc_offset + 2],
        buf[crc_offset + 3],
    ]);
    if !v5_required && stored == 0 {
        return CrcStatus::NotApplicable;
    }
    let computed = crc32c_with_zeroed_range(buf, crc_offset, 4);
    if stored == computed {
        CrcStatus::Verified
    } else {
        CrcStatus::Mismatch { stored, computed }
    }
}

pub fn parse_agf(
    reader: &mut dyn ImageRead,
    fs_base_offset: u64,
    sb: &Superblock,
    geometry: &Geometry,
    ag_number: u32,
) -> Result<Agf> {
    let buf = read_header_sector(
        reader,
        fs_base_offset,
        geometry,
        sb,
        ag_number,
        AGF_SECTOR_INDEX,
    )?;
    let is_v5 = sb.version5();

    require(
        be_u32_at(&buf, OFF_AGF_MAGIC)? == AGF_MAGIC,
        "AGF",
        "magic is not XAGF",
    )?;
    require(
        be_u32_at(&buf, OFF_AGF_VERSION)? == AGF_HEADER_VERSION,
        "AGF",
        "unsupported header version",
    )?;
    let seqno = be_u32_at(&buf, OFF_AGF_SEQNO)?;
    require(seqno == ag_number, "AGF", "sequence number mismatch")?;

    let length_blocks = be_u32_at(&buf, OFF_AGF_LENGTH)?;
    let expected_length = expected_ag_length(geometry, ag_number)?;
    require(
        length_blocks == expected_length,
        "AGF",
        "length disagrees with filesystem geometry",
    )?;

    let free_blocks = be_u32_at(&buf, OFF_AGF_FREEBLKS)?;
    require(
        free_blocks <= length_blocks,
        "AGF",
        "free block count exceeds allocation group length",
    )?;
    let longest_free = be_u32_at(&buf, OFF_AGF_LONGEST)?;
    require(
        longest_free <= length_blocks,
        "AGF",
        "longest free extent exceeds allocation group length",
    )?;

    let bnobt_root = be_u32_at(&buf, OFF_AGF_BNO_ROOT)?;
    let bnobt_level = be_u32_at(&buf, OFF_AGF_BNO_LEVEL)?;
    validate_tree_root(bnobt_root, bnobt_level, length_blocks, "AGF")?;
    let cntbt_root = be_u32_at(&buf, OFF_AGF_CNT_ROOT)?;
    let cntbt_level = be_u32_at(&buf, OFF_AGF_CNT_LEVEL)?;
    validate_tree_root(cntbt_root, cntbt_level, length_blocks, "AGF")?;

    let rmap_root = be_u32_at(&buf, OFF_AGF_RMAP_ROOT)?;
    let rmap_level = be_u32_at(&buf, OFF_AGF_RMAP_LEVEL)?;
    let rmap_blocks = be_u32_at(&buf, OFF_AGF_RMAP_BLOCKS)?;
    let rmapbt = if rmap_root != 0 || rmap_level != 0 || rmap_blocks != 0 {
        validate_tree_root(rmap_root, rmap_level, length_blocks, "AGF")?;
        Some(RmapBtInfo {
            root: rmap_root,
            level: rmap_level,
            blocks: rmap_blocks,
        })
    } else {
        None
    };

    let refcount_root = be_u32_at(&buf, OFF_AGF_REFCOUNT_ROOT)?;
    let refcount_level = be_u32_at(&buf, OFF_AGF_REFCOUNT_LEVEL)?;
    let refcount_blocks = be_u32_at(&buf, OFF_AGF_REFCOUNT_BLOCKS)?;
    let refcountbt = if refcount_root != 0 || refcount_level != 0 || refcount_blocks != 0 {
        validate_tree_root(refcount_root, refcount_level, length_blocks, "AGF")?;
        Some(RefcountBtInfo {
            root: refcount_root,
            level: refcount_level,
            blocks: refcount_blocks,
        })
    } else {
        None
    };

    let mut issues = Vec::new();
    let (uuid, lsn, crc_status) = if is_v5 {
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[OFF_AGF_UUID..OFF_AGF_UUID + 16]);
        check_uuid(Some(uuid), &sb.uuid, &mut issues);
        let lsn = be_u64_at(&buf, OFF_AGF_LSN)?;
        let status = crc_status_for(&buf, OFF_AGF_CRC, true);
        (Some(uuid), Some(lsn), status)
    } else {
        (None, None, CrcStatus::NotApplicable)
    };

    Ok(Agf {
        seqno,
        length_blocks,
        free_blocks,
        longest_free,
        btree_blocks: be_u32_at(&buf, OFF_AGF_BTREEBLKS)?,
        bnobt_root,
        bnobt_level,
        cntbt_root,
        cntbt_level,
        rmapbt,
        refcountbt,
        flfirst: be_u32_at(&buf, OFF_AGF_FLFIRST)?,
        fllast: be_u32_at(&buf, OFF_AGF_FLLAST)?,
        flcount: be_u32_at(&buf, OFF_AGF_FLCOUNT)?,
        uuid,
        lsn,
        crc_status,
        issues,
    })
}

pub fn parse_agi(
    reader: &mut dyn ImageRead,
    fs_base_offset: u64,
    sb: &Superblock,
    geometry: &Geometry,
    ag_number: u32,
) -> Result<Agi> {
    let buf = read_header_sector(
        reader,
        fs_base_offset,
        geometry,
        sb,
        ag_number,
        AGI_SECTOR_INDEX,
    )?;
    let is_v5 = sb.version5();

    require(
        be_u32_at(&buf, OFF_AGI_MAGIC)? == AGI_MAGIC,
        "AGI",
        "magic is not XAGI",
    )?;
    require(
        be_u32_at(&buf, OFF_AGI_VERSION)? == AGI_HEADER_VERSION,
        "AGI",
        "unsupported header version",
    )?;
    let seqno = be_u32_at(&buf, OFF_AGI_SEQNO)?;
    require(seqno == ag_number, "AGI", "sequence number mismatch")?;

    let length_blocks = be_u32_at(&buf, OFF_AGI_LENGTH)?;
    let expected_length = expected_ag_length(geometry, ag_number)?;
    require(
        length_blocks == expected_length,
        "AGI",
        "length disagrees with filesystem geometry",
    )?;

    let inode_count = be_u32_at(&buf, OFF_AGI_COUNT)?;
    let free_inode_count = be_u32_at(&buf, OFF_AGI_FREECOUNT)?;
    let inobt_root = be_u32_at(&buf, OFF_AGI_ROOT)?;
    let inobt_level = be_u32_at(&buf, OFF_AGI_LEVEL)?;
    validate_tree_root(inobt_root, inobt_level, length_blocks, "AGI")?;

    let inode_capacity =
        u32::try_from((length_blocks as u64) * (geometry.inodes_per_block() as u64))
            .unwrap_or(u32::MAX);

    let mut issues = Vec::new();
    if inode_count > inode_capacity || free_inode_count > inode_count || inode_capacity == 0 {
        issues.push(AgIssue::ImplausibleInodeCounts {
            count: inode_count,
            freecount: free_inode_count,
            capacity: inode_capacity,
        });
    }

    let mut unlinked_buckets = [0u32; AGI_UNLINKED_BUCKETS];
    for (index, slot) in unlinked_buckets.iter_mut().enumerate() {
        *slot = be_u32_at(&buf, OFF_AGI_UNLINKED + index * 4)?;
    }
    for (index, &value) in unlinked_buckets.iter().enumerate() {
        let is_null = value == 0 || value == NULLAGINO;
        if !is_null && (value as u64) >= inode_capacity as u64 {
            issues.push(AgIssue::InvalidUnlinkedBucket { index, value });
        }
    }

    let (finobt, inobt_blocks, finobt_blocks, uuid, lsn, crc_status) = if is_v5 {
        let fino_root = be_u32_at(&buf, OFF_AGI_FINO_ROOT)?;
        let fino_level = be_u32_at(&buf, OFF_AGI_FINO_LEVEL)?;
        let finobt = if sb.finobt_enabled() && !(fino_root == 0 && fino_level == 0) {
            validate_tree_root(fino_root, fino_level, length_blocks, "AGI")?;
            Some((fino_root, fino_level))
        } else {
            None
        };
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[OFF_AGI_UUID..OFF_AGI_UUID + 16]);
        check_uuid(Some(uuid), &sb.uuid, &mut issues);
        let lsn = be_u64_at(&buf, OFF_AGI_LSN)?;
        let status = crc_status_for(&buf, OFF_AGI_CRC, true);
        (
            finobt,
            Some(be_u32_at(&buf, OFF_AGI_IBLOCKS)?),
            Some(be_u32_at(&buf, OFF_AGI_FBLOCKS)?),
            Some(uuid),
            Some(lsn),
            status,
        )
    } else {
        (None, None, None, None, None, CrcStatus::NotApplicable)
    };

    Ok(Agi {
        version: be_u32_at(&buf, OFF_AGI_VERSION)?,
        seqno,
        length_blocks,
        inode_capacity,
        inode_count,
        free_inode_count,
        inobt_root,
        inobt_level,
        finobt,
        inobt_blocks,
        finobt_blocks,
        newino: be_u32_at(&buf, OFF_AGI_NEWINO)?,
        dirino: be_u32_at(&buf, OFF_AGI_DIRINO)?,
        unlinked_buckets,
        uuid,
        lsn,
        crc_status,
        issues,
    })
}

pub fn parse_agfl(
    reader: &mut dyn ImageRead,
    fs_base_offset: u64,
    sb: &Superblock,
    geometry: &Geometry,
    ag_number: u32,
    agf: &Agf,
) -> Result<Agfl> {
    let buf = read_header_sector(
        reader,
        fs_base_offset,
        geometry,
        sb,
        ag_number,
        AGFL_SECTOR_INDEX,
    )?;
    let is_v5 = sb.version5();
    let sector_bytes = buf.len();
    let capacity = if is_v5 {
        sector_bytes.saturating_sub(AGFL_HEADER_BYTES_V5) / 4
    } else {
        sector_bytes / 4
    };

    let entries_start = if is_v5 {
        require(
            be_u32_at(&buf, OFF_AGFL_MAGIC)? == AGFL_MAGIC,
            "AGFL",
            "magic is not XAFL",
        )?;
        require(
            be_u32_at(&buf, OFF_AGFL_SEQNO)? == ag_number,
            "AGFL",
            "sequence number mismatch",
        )?;
        OFF_AGFL_ENTRIES
    } else {
        0
    };

    require(
        (agf.flcount as usize) <= capacity,
        "AGFL",
        "freelist count exceeds table capacity",
    )?;
    if agf.flcount > 0 {
        require(
            (agf.flfirst as usize) < capacity,
            "AGFL",
            "freelist first index beyond table capacity",
        )?;
        let expected_last =
            ((agf.flfirst as u64 + agf.flcount as u64 - 1) % capacity as u64) as u32;
        require(
            agf.fllast == expected_last,
            "AGFL",
            "freelist last index inconsistent with first and count",
        )?;
    }

    let mut issues = Vec::new();
    let mut entries = Vec::with_capacity(agf.flcount as usize);
    for i in 0..agf.flcount {
        let raw_index = ((agf.flfirst as u64 + i as u64) % capacity as u64) as usize;
        let value = be_u32_at(&buf, entries_start + raw_index * 4)?;
        if value == 0 || value >= agf.length_blocks {
            issues.push(AgIssue::AgflEntryOutOfRange { slot: i, value });
        } else {
            entries.push(value);
        }
    }

    let (seqno, uuid, lsn, crc_status) = if is_v5 {
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[OFF_AGFL_UUID..OFF_AGFL_UUID + 16]);
        check_uuid(Some(uuid), &sb.uuid, &mut issues);
        let lsn = be_u64_at(&buf, OFF_AGFL_LSN)?;
        let status = crc_status_for(&buf, OFF_AGFL_CRC, true);
        (Some(ag_number), Some(uuid), Some(lsn), status)
    } else {
        (None, None, None, CrcStatus::NotApplicable)
    };

    Ok(Agfl {
        seqno,
        capacity,
        entries,
        uuid,
        lsn,
        crc_status,
        issues,
    })
}

pub fn parse_allocation_group(
    reader: &mut dyn ImageRead,
    fs_base_offset: u64,
    sb: &Superblock,
    geometry: &Geometry,
    ag_number: u32,
) -> Result<AllocationGroup> {
    let agf = parse_agf(reader, fs_base_offset, sb, geometry, ag_number)?;
    let agi = parse_agi(reader, fs_base_offset, sb, geometry, ag_number)?;
    let agfl = parse_agfl(reader, fs_base_offset, sb, geometry, ag_number, &agf)?;
    Ok(AllocationGroup {
        number: ag_number,
        agf,
        agi,
        agfl,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xfs::superblock::testing::{golden_v4, golden_v5, put32, put64};

    struct Ctx {
        sb: Superblock,
        geometry: Geometry,
    }

    fn ag_length(ctx: &Ctx, seqno: u32) -> u32 {
        if seqno + 1 == ctx.sb.ag_count {
            (ctx.sb.dblocks - (ctx.sb.ag_count as u64 - 1) * ctx.sb.ag_blocks as u64) as u32
        } else {
            ctx.sb.ag_blocks
        }
    }

    fn ctx_from(golden: &[u8]) -> Ctx {
        let (sb, geometry) = Superblock::parse_bytes(golden).expect("golden sb");
        Ctx { sb, geometry }
    }

    fn ctx_v5() -> Ctx {
        ctx_from(&golden_v5())
    }

    fn ctx_v4() -> Ctx {
        ctx_from(&golden_v4())
    }

    struct Src {
        data: Vec<u8>,
    }

    impl Src {
        fn place(mut self, ctx: &Ctx, ag: u32, index: u64, sector: &[u8]) -> Self {
            let offset = (ctx.geometry.ag_start_byte(ag).unwrap()
                + index * ctx.sb.sector_size as u64) as usize;
            self.data[offset..offset + sector.len()].copy_from_slice(sector);
            self
        }
    }

    struct Reader<'a>(&'a [u8]);

    impl ImageRead for Reader<'_> {
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
            crate::MemImage::new(self.0).read_at(offset, buf)
        }
    }

    fn seal(buf: &mut [u8], crc_offset: usize) {
        buf[crc_offset..crc_offset + 4].copy_from_slice(&0u32.to_le_bytes());
        let crc = crate::util::crc32c::crc32c(buf);
        buf[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());
    }

    fn span_bytes(ctx: &Ctx, ag: u32) -> usize {
        (ctx.geometry.ag_start_byte(ag).unwrap() + 4 * ctx.sb.sector_size as u64) as usize
    }

    fn run_agf(ctx: &Ctx, sector: &[u8], ag: u32) -> Result<Agf> {
        let src = Src {
            data: vec![0u8; span_bytes(ctx, ag)],
        }
        .place(ctx, ag, AGF_SECTOR_INDEX, sector);
        parse_agf(&mut Reader(&src.data), 0, &ctx.sb, &ctx.geometry, ag)
    }

    fn run_agi(ctx: &Ctx, sector: &[u8], ag: u32) -> Result<Agi> {
        let src = Src {
            data: vec![0u8; span_bytes(ctx, ag)],
        }
        .place(ctx, ag, AGI_SECTOR_INDEX, sector);
        parse_agi(&mut Reader(&src.data), 0, &ctx.sb, &ctx.geometry, ag)
    }

    fn run_agfl(ctx: &Ctx, sector: &[u8], agf: &Agf, ag: u32) -> Result<Agfl> {
        let src = Src {
            data: vec![0u8; span_bytes(ctx, ag)],
        }
        .place(ctx, ag, AGFL_SECTOR_INDEX, sector);
        parse_agfl(&mut Reader(&src.data), 0, &ctx.sb, &ctx.geometry, ag, agf)
    }

    fn agf_sector(ctx: &Ctx, seqno: u32) -> Vec<u8> {
        let length = ag_length(ctx, seqno);
        let mut b = vec![0u8; ctx.sb.sector_size as usize];
        put32(&mut b, OFF_AGF_MAGIC, AGF_MAGIC);
        put32(&mut b, OFF_AGF_VERSION, 1);
        put32(&mut b, OFF_AGF_SEQNO, seqno);
        put32(&mut b, OFF_AGF_LENGTH, length);
        put32(&mut b, OFF_AGF_BNO_ROOT, 1);
        put32(&mut b, OFF_AGF_CNT_ROOT, 2);
        put32(&mut b, OFF_AGF_RMAP_ROOT, 5);
        put32(&mut b, OFF_AGF_BNO_LEVEL, 1);
        put32(&mut b, OFF_AGF_CNT_LEVEL, 1);
        put32(&mut b, OFF_AGF_RMAP_LEVEL, 1);
        put32(&mut b, OFF_AGF_FLFIRST, 1);
        put32(&mut b, OFF_AGF_FLLAST, 6);
        put32(&mut b, OFF_AGF_FLCOUNT, 6);
        put32(&mut b, OFF_AGF_FREEBLKS, length - 21);
        put32(&mut b, OFF_AGF_LONGEST, length - 24);
        put32(&mut b, OFF_AGF_RMAP_BLOCKS, 1);
        put32(&mut b, OFF_AGF_REFCOUNT_BLOCKS, 1);
        put32(&mut b, OFF_AGF_REFCOUNT_ROOT, 6);
        put32(&mut b, OFF_AGF_REFCOUNT_LEVEL, 1);
        if ctx.sb.version5() {
            b[OFF_AGF_UUID..OFF_AGF_UUID + 16].copy_from_slice(&ctx.sb.uuid);
            put64(&mut b, OFF_AGF_LSN, 7);
            seal(&mut b, OFF_AGF_CRC);
        }
        b
    }

    fn agf_with_fl_bookkeeping(ctx: &Ctx, first: u32, last: u32, count: u32) -> Vec<u8> {
        let mut b = agf_sector(ctx, 0);
        put32(&mut b, OFF_AGF_FLFIRST, first);
        put32(&mut b, OFF_AGF_FLLAST, last);
        put32(&mut b, OFF_AGF_FLCOUNT, count);
        if ctx.sb.version5() {
            seal(&mut b, OFF_AGF_CRC);
        }
        b
    }

    fn agi_sector(ctx: &Ctx, seqno: u32) -> Vec<u8> {
        let mut b = vec![0u8; ctx.sb.sector_size as usize];
        put32(&mut b, OFF_AGI_MAGIC, AGI_MAGIC);
        put32(&mut b, OFF_AGI_VERSION, 1);
        put32(&mut b, OFF_AGI_SEQNO, seqno);
        put32(&mut b, OFF_AGI_LENGTH, ag_length(ctx, seqno));
        put32(&mut b, OFF_AGI_COUNT, 128);
        put32(&mut b, OFF_AGI_ROOT, 3);
        put32(&mut b, OFF_AGI_LEVEL, 1);
        put32(&mut b, OFF_AGI_FREECOUNT, 61);
        put32(&mut b, OFF_AGI_NEWINO, 128);
        put32(&mut b, OFF_AGI_UNLINKED, 5);
        put32(&mut b, OFF_AGI_UNLINKED + 4, NULLAGINO);
        put32(&mut b, OFF_AGI_FINO_ROOT, 4);
        put32(&mut b, OFF_AGI_FINO_LEVEL, 1);
        put32(&mut b, OFF_AGI_IBLOCKS, 2);
        put32(&mut b, OFF_AGI_FBLOCKS, 1);
        if ctx.sb.version5() {
            b[OFF_AGI_UUID..OFF_AGI_UUID + 16].copy_from_slice(&ctx.sb.uuid);
            put64(&mut b, OFF_AGI_LSN, 9);
            seal(&mut b, OFF_AGI_CRC);
        }
        b
    }

    fn agfl_sector_v5(ctx: &Ctx, raw_slots: &[(usize, u32)]) -> Vec<u8> {
        let mut b = vec![0u8; ctx.sb.sector_size as usize];
        put32(&mut b, OFF_AGFL_MAGIC, AGFL_MAGIC);
        put32(&mut b, OFF_AGFL_SEQNO, 0);
        b[OFF_AGFL_UUID..OFF_AGFL_UUID + 16].copy_from_slice(&ctx.sb.uuid);
        for (slot, value) in raw_slots {
            let off = OFF_AGFL_ENTRIES + slot * 4;
            put32(&mut b, off, *value);
        }
        seal(&mut b, OFF_AGFL_CRC);
        b
    }

    #[test]
    fn header_offsets_follow_geometry_and_reject_bad_ag() {
        let ctx = ctx_v5();
        let offs = ag_header_offsets(&ctx.geometry, ctx.sb.sector_size, 2).unwrap();
        assert_eq!(offs.agf_byte_offset, 2 * 16384 * 4096 + 512);
        assert_eq!(offs.agi_byte_offset, 2 * 16384 * 4096 + 1024);
        assert_eq!(offs.agfl_byte_offset, 2 * 16384 * 4096 + 1536);
        assert!(ag_header_offsets(&ctx.geometry, ctx.sb.sector_size, 4).is_err());
    }

    #[test]
    fn golden_agf_v5_parses_with_all_fields() {
        let ctx = ctx_v5();
        let agf = run_agf(&ctx, &agf_sector(&ctx, 0), 0).expect("agf");
        assert_eq!(agf.seqno, 0);
        assert_eq!(agf.length_blocks, 16384);
        assert_eq!(agf.free_blocks, 16363);
        assert_eq!(agf.longest_free, 16360);
        assert_eq!((agf.bnobt_root, agf.bnobt_level), (1, 1));
        assert_eq!((agf.cntbt_root, agf.cntbt_level), (2, 1));
        assert_eq!(
            agf.rmapbt,
            Some(RmapBtInfo {
                root: 5,
                level: 1,
                blocks: 1
            })
        );
        assert_eq!(
            agf.refcountbt,
            Some(RefcountBtInfo {
                root: 6,
                level: 1,
                blocks: 1
            })
        );
        assert_eq!((agf.flfirst, agf.fllast, agf.flcount), (1, 6, 6));
        assert_eq!(agf.lsn, Some(7));
        assert_eq!(agf.uuid, Some(ctx.sb.uuid));
        assert_eq!(agf.crc_status, CrcStatus::Verified);
        assert!(agf.issues.is_empty());
    }

    #[test]
    fn golden_agf_v4_has_no_v5_fields() {
        let ctx = ctx_v4();
        let agf = run_agf(&ctx, &agf_sector(&ctx, 0), 0).expect("agf");
        assert!(agf.uuid.is_none());
        assert!(agf.lsn.is_none());
        assert_eq!(agf.crc_status, CrcStatus::NotApplicable);
        assert!(agf.issues.is_empty());
    }

    #[test]
    fn last_ag_shorter_length_is_accepted_when_geometry_matches() {
        let mut sb_bytes = golden_v5();
        put64(&mut sb_bytes, 8, 60_000);
        sb_bytes[224..228].copy_from_slice(&0u32.to_le_bytes());
        seal(&mut sb_bytes, 224);
        let (sb, geometry) = Superblock::parse_bytes(&sb_bytes).expect("short-tail sb");
        let ctx = Ctx { sb, geometry };
        let agf = run_agf(&ctx, &agf_sector(&ctx, 3), 3).expect("last ag");
        assert_eq!(agf.length_blocks, 10_848);
    }

    #[test]
    fn agf_structural_violations_are_hard_errors() {
        let ctx = ctx_v5();

        let mut bad = agf_sector(&ctx, 0);
        put32(&mut bad, OFF_AGF_MAGIC, 0x12345678);
        assert!(run_agf(&ctx, &bad, 0).is_err());

        let mut bad = agf_sector(&ctx, 0);
        bad[OFF_AGF_VERSION] = 2;
        assert!(run_agf(&ctx, &bad, 0).is_err());

        let wrong_seq = agf_sector(&ctx, 1);
        assert!(run_agf(&ctx, &wrong_seq, 0).is_err());

        let mut bad = agf_sector(&ctx, 0);
        put32(&mut bad, OFF_AGF_LENGTH, 16383);
        assert!(run_agf(&ctx, &bad, 0).is_err());

        let mut bad = agf_sector(&ctx, 0);
        put32(&mut bad, OFF_AGF_FREEBLKS, 20_000);
        assert!(run_agf(&ctx, &bad, 0).is_err());

        let mut bad = agf_sector(&ctx, 0);
        put32(&mut bad, OFF_AGF_LONGEST, 20_000);
        assert!(run_agf(&ctx, &bad, 0).is_err());

        let mut bad = agf_sector(&ctx, 0);
        put32(&mut bad, OFF_AGF_BNO_ROOT, 99_999);
        assert!(run_agf(&ctx, &bad, 0).is_err());

        let mut bad = agf_sector(&ctx, 0);
        put32(&mut bad, OFF_AGF_BNO_LEVEL, 0);
        put32(&mut bad, OFF_AGF_BNO_ROOT, 7);
        assert!(run_agf(&ctx, &bad, 0).is_err());

        let short = &agf_sector(&ctx, 0)[..100];
        assert!(matches!(
            parse_agf(&mut Reader(short), 0, &ctx.sb, &ctx.geometry, 0),
            Err(Error::OutOfBounds { .. })
        ));
    }

    #[test]
    fn agf_crc_mismatch_is_soft_with_details() {
        let ctx = ctx_v5();
        let mut bad = agf_sector(&ctx, 0);
        bad[OFF_AGF_FREEBLKS + 3] ^= 0x40;
        let agf = run_agf(&ctx, &bad, 0).expect("soft crc");
        match agf.crc_status {
            CrcStatus::Mismatch { stored, computed } => assert_ne!(stored, computed),
            other => panic!("expected mismatch, got {other:?}"),
        }
    }

    #[test]
    fn agf_uuid_mismatch_is_recorded_as_issue() {
        let ctx = ctx_v5();
        let mut bad = agf_sector(&ctx, 0);
        bad[OFF_AGF_UUID] ^= 0xFF;
        seal(&mut bad, OFF_AGF_CRC);
        let agf = run_agf(&ctx, &bad, 0).expect("uuid issue");
        assert_eq!(agf.crc_status, CrcStatus::Verified);
        assert!(agf.issues.contains(&AgIssue::UuidMismatch));
    }

    #[test]
    fn golden_agi_v5_parses_and_extracts_unlinked_heads() {
        let ctx = ctx_v5();
        let agi = run_agi(&ctx, &agi_sector(&ctx, 0), 0).expect("agi");
        assert_eq!(agi.seqno, 0);
        assert_eq!(agi.length_blocks, 16384);
        assert_eq!(agi.inode_count, 128);
        assert_eq!(agi.free_inode_count, 61);
        assert_eq!((agi.inobt_root, agi.inobt_level), (3, 1));
        assert_eq!(agi.finobt, Some((4, 1)));
        assert_eq!(agi.inobt_blocks, Some(2));
        assert_eq!(agi.finobt_blocks, Some(1));
        assert_eq!(agi.newino, 128);
        let heads: Vec<(usize, u32)> = agi.unlinked_heads().collect();
        assert_eq!(heads, vec![(0, 5)]);
        assert_eq!(agi.crc_status, CrcStatus::Verified);
        assert!(agi.issues.is_empty());
    }

    #[test]
    fn agi_invalid_unlinked_bucket_is_soft_issue() {
        let ctx = ctx_v5();
        let mut bad = agi_sector(&ctx, 0);
        put32(&mut bad, OFF_AGI_UNLINKED + 9 * 4, 500_000);
        seal(&mut bad, OFF_AGI_CRC);
        let agi = run_agi(&ctx, &bad, 0).expect("agi soft");
        assert!(agi.issues.contains(&AgIssue::InvalidUnlinkedBucket {
            index: 9,
            value: 500_000
        }));
        assert!(agi.unlinked_heads().all(|(_, v)| v < 500_000));
    }

    #[test]
    fn agi_implausible_counts_are_soft_issues() {
        let ctx = ctx_v5();
        let mut bad = agi_sector(&ctx, 0);
        put32(&mut bad, OFF_AGI_COUNT, 999_999);
        put32(&mut bad, OFF_AGI_FREECOUNT, 999_999);
        seal(&mut bad, OFF_AGI_CRC);
        let agi = run_agi(&ctx, &bad, 0).expect("agi soft");
        assert!(
            agi.issues
                .iter()
                .any(|issue| matches!(issue, AgIssue::ImplausibleInodeCounts { .. }))
        );
    }

    #[test]
    fn agi_structural_violations_are_hard_errors() {
        let ctx = ctx_v5();

        let mut bad = agi_sector(&ctx, 0);
        put32(&mut bad, OFF_AGI_MAGIC, 0xDEAD);
        assert!(run_agi(&ctx, &bad, 0).is_err());

        let mut bad = agi_sector(&ctx, 0);
        put32(&mut bad, OFF_AGI_VERSION, 7);
        assert!(run_agi(&ctx, &bad, 0).is_err());

        let wrong_seq = agi_sector(&ctx, 1);
        assert!(run_agi(&ctx, &wrong_seq, 0).is_err());

        let mut bad = agi_sector(&ctx, 0);
        put32(&mut bad, OFF_AGI_LENGTH, 16_000);
        assert!(run_agi(&ctx, &bad, 0).is_err());

        let mut bad = agi_sector(&ctx, 0);
        put32(&mut bad, OFF_AGI_ROOT, 77_777);
        assert!(run_agi(&ctx, &bad, 0).is_err());

        let short = &agi_sector(&ctx, 0)[..64];
        assert!(matches!(
            parse_agi(&mut Reader(short), 0, &ctx.sb, &ctx.geometry, 0),
            Err(Error::OutOfBounds { .. })
        ));
    }

    #[test]
    fn agfl_v5_empty_and_wraparound_entries_parse_in_logical_order() {
        let ctx = ctx_v5();

        let empty_fl = agfl_sector_v5(&ctx, &[]);
        let empty_bookkeeping = agf_with_fl_bookkeeping(&ctx, 0, 0, 0);
        let agf = run_agf(&ctx, &empty_bookkeeping, 0).unwrap();
        let agfl = run_agfl(&ctx, &empty_fl, &agf, 0).expect("empty agfl");
        assert!(agfl.entries.is_empty());
        assert_eq!(agfl.capacity, 119);
        assert_eq!(agfl.crc_status, CrcStatus::Verified);
        assert!(agfl.issues.is_empty());

        let wrapped_sectors = agfl_sector_v5(
            &ctx,
            &[(117, 900), (118, 901), (0, 100), (1, 101), (2, 102)],
        );
        let wrap_bookkeeping = agf_with_fl_bookkeeping(&ctx, 117, 2, 5);
        let agf = run_agf(&ctx, &wrap_bookkeeping, 0).unwrap();
        let agfl = run_agfl(&ctx, &wrapped_sectors, &agf, 0).expect("wrapped agfl");
        assert_eq!(agfl.entries, vec![900, 901, 100, 101, 102]);
        assert!(agfl.issues.is_empty());
    }

    #[test]
    fn agfl_v4_raw_table_without_header() {
        let ctx = ctx_v4();
        let mut b = vec![0u8; ctx.sb.sector_size as usize];
        put32(&mut b, 0, 50);
        put32(&mut b, 4, 51);
        put32(&mut b, 8, 52);
        let bookkeeping = agf_with_fl_bookkeeping(&ctx, 0, 2, 3);
        let agf = run_agf(&ctx, &bookkeeping, 0).unwrap();
        let agfl = run_agfl(&ctx, &b, &agf, 0).expect("v4 agfl");
        assert_eq!(agfl.capacity, 128);
        assert_eq!(agfl.entries, vec![50, 51, 52]);
        assert_eq!(agfl.seqno, None);
        assert_eq!(agfl.crc_status, CrcStatus::NotApplicable);
    }

    #[test]
    fn agfl_bookkeeping_and_entry_range_enforced() {
        let ctx = ctx_v5();
        let entries = agfl_sector_v5(&ctx, &[(0, 100), (1, 200_000), (2, 0)]);

        let bookkeeping = agf_with_fl_bookkeeping(&ctx, 0, 2, 3);
        let agf = run_agf(&ctx, &bookkeeping, 0).unwrap();
        let agfl = run_agfl(&ctx, &entries, &agf, 0).expect("entry issues are soft");
        assert_eq!(agfl.entries, vec![100]);
        assert_eq!(agfl.issues.len(), 2);
        assert!(agfl.issues.contains(&AgIssue::AgflEntryOutOfRange {
            slot: 1,
            value: 200_000
        }));

        let over_count = agf_with_fl_bookkeeping(&ctx, 0, 118, 120);
        let over_agf = run_agf(&ctx, &over_count, 0).unwrap();
        assert!(run_agfl(&ctx, &entries, &over_agf, 0).is_err());

        let bad_first = agf_with_fl_bookkeeping(&ctx, 500, 0, 1);
        let bad_first_agf = run_agf(&ctx, &bad_first, 0).unwrap();
        assert!(run_agfl(&ctx, &entries, &bad_first_agf, 0).is_err());

        let bad_last = agf_with_fl_bookkeeping(&ctx, 0, 117, 3);
        let bad_last_agf = run_agf(&ctx, &bad_last, 0).unwrap();
        assert!(run_agfl(&ctx, &entries, &bad_last_agf, 0).is_err());

        let mut bad_magic = agfl_sector_v5(&ctx, &[]);
        put32(&mut bad_magic, OFF_AGFL_MAGIC, 0);
        let plain_agf = run_agf(&ctx, &agf_with_fl_bookkeeping(&ctx, 0, 0, 0), 0).unwrap();
        assert!(run_agfl(&ctx, &bad_magic, &plain_agf, 0).is_err());
    }

    #[test]
    fn allocation_group_aggregate_wires_all_three_headers() {
        let ctx = ctx_v5();
        let agf_bytes = agf_with_fl_bookkeeping(&ctx, 0, 0, 1);
        let mut agfl_bytes = agfl_sector_v5(&ctx, &[(0, 30)]);
        agfl_bytes.truncate(512);
        let _ = &mut agfl_bytes;
        let src = Src {
            data: vec![0u8; 8192],
        }
        .place(&ctx, 0, AGF_SECTOR_INDEX, &agf_bytes)
        .place(&ctx, 0, AGI_SECTOR_INDEX, &agi_sector(&ctx, 0))
        .place(&ctx, 0, AGFL_SECTOR_INDEX, &agfl_bytes);
        let group = parse_allocation_group(&mut Reader(&src.data), 0, &ctx.sb, &ctx.geometry, 0)
            .expect("aggregate");
        assert_eq!(group.number, 0);
        assert_eq!(group.agf.seqno, 0);
        assert_eq!(group.agi.seqno, 0);
        assert_eq!(group.agfl.entries, vec![30]);
        assert_eq!(group.agfl.crc_status, CrcStatus::Verified);
    }

    #[test]
    fn never_panics_on_deterministic_garbage_sectors() {
        let ctx = ctx_v5();
        let mut state = 0x853C_49E6_748F_EA9Bu64;
        for _ in 0..96 {
            let mut sector = vec![0u8; ctx.sb.sector_size as usize];
            for byte in sector.iter_mut() {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *byte = (state >> 33) as u8;
            }
            let _ = parse_agf(&mut Reader(&sector), 0, &ctx.sb, &ctx.geometry, 0);
            let _ = parse_agi(&mut Reader(&sector), 0, &ctx.sb, &ctx.geometry, 0);
        }
    }
}
