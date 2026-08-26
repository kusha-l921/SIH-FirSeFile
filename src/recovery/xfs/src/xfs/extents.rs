use crate::error::{Error, Result};
use crate::io::ImageRead;
use crate::util::be::{be_u16_at, be_u32_at, be_u64_at};
use crate::util::crc32c::crc32c_with_zeroed_range;
use crate::xfs::dinode::{DataForkFormat, Dinode, FileType};
use crate::xfs::fork::{data_fork_region, local_data_bytes};
use crate::xfs::superblock::{Geometry, Superblock};

pub const XFS_BMAP_MAGIC: u32 = 0x424D_4150; // 'BMAP'
pub const XFS_BMAP_CRC_MAGIC: u32 = 0x424D_4133; // 'BMA3'

const HDR_BYTES_V4: usize = 24;
const HDR_BYTES_V5: usize = 72;

const OFF_BMDR_LEVEL: usize = 0;
const OFF_BMDR_NUMRECS: usize = 2;
const BMDR_HEADER_BYTES: usize = 4;

const OFF_BMBT_MAGIC: usize = 0;
const OFF_BMBT_LEVEL: usize = 4;
const OFF_BMBT_NUMRECS: usize = 6;
const OFF_BMBT_LEFTSIB: usize = 8;
const OFF_BMBT_RIGHTSIB: usize = 16;
const OFF_BMBT_BLKNO: usize = 24;
const OFF_BMBT_UUID: usize = 40;
const OFF_BMBT_OWNER: usize = 56;
const OFF_BMBT_CRC: usize = 64;

const MAX_BMBT_LEVELS: u16 = 64;
pub const NULLFSBLOCK: u64 = 0xFFFF_FFFF_FFFF_FFFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentState {
    Normal,
    Unwritten,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileExtent {
    pub logical_start: u64,
    pub physical_start: u64,
    pub block_count: u64,
    pub state: ExtentState,
}

impl FileExtent {
    #[inline]
    pub fn logical_end(&self) -> u64 {
        self.logical_start.saturating_add(self.block_count)
    }

    #[inline]
    pub fn physical_end(&self) -> u64 {
        self.physical_start.saturating_add(self.block_count)
    }

    #[inline]
    pub fn contains_logical_block(&self, block: u64) -> bool {
        block >= self.logical_start && block < self.logical_end()
    }
}

pub fn decode_bmbt_record(raw: &[u8; 16]) -> FileExtent {
    let l0 = u64::from_be_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]);
    let l1 = u64::from_be_bytes([
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
    ]);

    let state = if (l0 >> 63) != 0 {
        ExtentState::Unwritten
    } else {
        ExtentState::Normal
    };

    let logical_start = (l0 & 0x7FFF_FFFF_FFFF_FFFF) >> 9;
    let physical_start = ((l0 & 0x1FF) << 43) | (l1 >> 21);
    let block_count = l1 & 0x1F_FFFF;

    FileExtent {
        logical_start,
        physical_start,
        block_count,
        state,
    }
}

pub fn encode_bmbt_record(extent: &FileExtent) -> [u8; 16] {
    let flag_bit: u64 = if extent.state == ExtentState::Unwritten {
        1 << 63
    } else {
        0
    };
    let startoff_bits = (extent.logical_start & 0x003F_FFFF_FFFF_FFFF) << 9;
    let startblock_hi = (extent.physical_start >> 43) & 0x1FF;
    let l0 = flag_bit | startoff_bits | startblock_hi;

    let startblock_lo = (extent.physical_start & 0x07FF_FFFF_FFFF) << 21;
    let blockcount_bits = extent.block_count & 0x1F_FFFF;
    let l1 = startblock_lo | blockcount_bits;

    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&l0.to_be_bytes());
    out[8..16].copy_from_slice(&l1.to_be_bytes());
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtentIssue {
    ZeroBlockCount {
        index: usize,
        logical_start: u64,
    },
    LogicalOverlap {
        prev_end: u64,
        next_start: u64,
    },
    DecreasingLogicalOffset {
        prev_start: u64,
        next_start: u64,
    },
    LogicalStartOverflow {
        logical_start: u64,
        block_count: u64,
    },
    PhysicalStartOverflow {
        physical_start: u64,
        block_count: u64,
    },
    PhysicalBlockOutOfBounds {
        physical_start: u64,
        block_count: u64,
        dblocks: u64,
    },
    BtreeCycleDetected {
        block: u64,
    },
    BtreeBadMagic {
        block: u64,
        magic: u32,
    },
    BtreeCrcMismatch {
        block: u64,
        stored: u32,
        computed: u32,
    },
    BtreeUuidMismatch {
        block: u64,
    },
    BtreeBlknoMismatch {
        block: u64,
        expected: u64,
        found: u64,
    },
    BtreeLevelMismatch {
        block: u64,
        expected: u16,
        found: u16,
    },
    BtreeOwnerMismatch {
        block: u64,
        expected: u64,
        found: u64,
    },
    BtreeExcessiveDepth {
        level: u16,
    },
    BtreeInvalidPointer {
        fsblock: u64,
        dblocks: u64,
    },
    TruncatedRecord {
        needed: usize,
        available: usize,
    },
    ExtentCountMismatch {
        declared: u64,
        found: u64,
    },
}

#[derive(Debug, Clone)]
pub struct ExtentMap {
    pub extents: Vec<FileExtent>,
    pub issues: Vec<ExtentIssue>,
}

impl ExtentMap {
    pub fn is_empty(&self) -> bool {
        self.extents.is_empty()
    }

    pub fn total_blocks(&self) -> u64 {
        self.extents.iter().map(|e| e.block_count).sum()
    }

    pub fn find_extent_for_block(&self, block: u64) -> Option<&FileExtent> {
        self.extents
            .iter()
            .find(|e| e.contains_logical_block(block))
    }
}

pub fn parse_data_fork(
    reader: &mut dyn ImageRead,
    fs_base_offset: u64,
    sb: &Superblock,
    geometry: &Geometry,
    inode: &Dinode,
) -> Result<ExtentMap> {
    match inode.core.format {
        DataForkFormat::Local => {
            let _ = local_data_bytes(inode, sb.inode_size as usize)?;
            Ok(ExtentMap {
                extents: Vec::new(),
                issues: Vec::new(),
            })
        }
        DataForkFormat::Extents => parse_extents_data_fork(inode, sb, geometry),
        DataForkFormat::Btree => parse_btree_data_fork(reader, fs_base_offset, sb, geometry, inode),
        DataForkFormat::Dev => Ok(ExtentMap {
            extents: Vec::new(),
            issues: Vec::new(),
        }),
        DataForkFormat::Uuid | DataForkFormat::MetaBtree | DataForkFormat::Unknown(_) => {
            Err(Error::Unsupported {
                structure: "unsupported data fork format",
            })
        }
    }
}

fn parse_extents_data_fork(
    inode: &Dinode,
    sb: &Superblock,
    geometry: &Geometry,
) -> Result<ExtentMap> {
    let region = data_fork_region(inode, sb.inode_size as usize)?;
    let mut extents = Vec::new();
    let mut issues = Vec::new();

    let num_recs = inode.core.nextents as usize;
    let expected_bytes = num_recs.saturating_mul(16);

    if region.raw.len() < expected_bytes {
        issues.push(ExtentIssue::TruncatedRecord {
            needed: expected_bytes,
            available: region.raw.len(),
        });
    }

    let actual_recs = (region.raw.len() / 16).min(num_recs);
    for i in 0..actual_recs {
        let offset = i * 16;
        let mut raw = [0u8; 16];
        raw.copy_from_slice(&region.raw[offset..offset + 16]);
        let extent = decode_bmbt_record(&raw);
        validate_single_extent(&extent, i, geometry.dblocks(), &mut issues);
        extents.push(extent);
    }

    if (extents.len() as u64) != inode.core.nextents {
        issues.push(ExtentIssue::ExtentCountMismatch {
            declared: inode.core.nextents,
            found: extents.len() as u64,
        });
    }

    validate_extent_sequence(&extents, &mut issues);

    Ok(ExtentMap { extents, issues })
}

fn parse_btree_data_fork(
    reader: &mut dyn ImageRead,
    fs_base_offset: u64,
    sb: &Superblock,
    geometry: &Geometry,
    inode: &Dinode,
) -> Result<ExtentMap> {
    let region = data_fork_region(inode, sb.inode_size as usize)?;
    if region.raw.len() < BMDR_HEADER_BYTES {
        return Err(Error::Truncated {
            needed: BMDR_HEADER_BYTES,
            available: region.raw.len(),
        });
    }

    let root_level = be_u16_at(region.raw, OFF_BMDR_LEVEL)?;
    let root_numrecs = be_u16_at(region.raw, OFF_BMDR_NUMRECS)?;

    let mut extents = Vec::new();
    let mut issues = Vec::new();
    let mut visited = Vec::new();

    if root_level == 0 {
        let avail_recs = (region.raw.len() - BMDR_HEADER_BYTES) / 16;
        let recs_to_read = (root_numrecs as usize).min(avail_recs);
        for i in 0..recs_to_read {
            let offset = BMDR_HEADER_BYTES + i * 16;
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&region.raw[offset..offset + 16]);
            let extent = decode_bmbt_record(&raw);
            validate_single_extent(&extent, i, geometry.dblocks(), &mut issues);
            extents.push(extent);
        }
    } else {
        if root_level > MAX_BMBT_LEVELS {
            issues.push(ExtentIssue::BtreeExcessiveDepth { level: root_level });
            return Ok(ExtentMap { extents, issues });
        }

        let dblocklen = region.raw.len();
        let dmxr = (dblocklen.saturating_sub(BMDR_HEADER_BYTES)) / 16;
        let mut ctx = BmbtContext {
            reader,
            fs_base_offset,
            sb,
            geometry,
            owner_ino: inode.location.ino,
        };
        let num_ptrs = (root_numrecs as usize).min(dmxr);
        let ptr_start = BMDR_HEADER_BYTES + dmxr * 8;

        for i in 0..num_ptrs {
            let ptr_offset = ptr_start + i * 8;
            if ptr_offset + 8 > region.raw.len() {
                issues.push(ExtentIssue::TruncatedRecord {
                    needed: ptr_offset + 8,
                    available: region.raw.len(),
                });
                break;
            }
            let child_fsb = be_u64_at(region.raw, ptr_offset)?;
            traverse_bmbt_node(
                &mut ctx,
                child_fsb,
                root_level - 1,
                &mut visited,
                &mut extents,
                &mut issues,
            )?;
        }
    }

    validate_extent_sequence(&extents, &mut issues);

    Ok(ExtentMap { extents, issues })
}

struct BmbtContext<'a> {
    reader: &'a mut dyn ImageRead,
    fs_base_offset: u64,
    sb: &'a Superblock,
    geometry: &'a Geometry,
    owner_ino: u64,
}

pub fn fsblock_to_byte(geometry: &Geometry, fsblock: u64) -> Result<u64> {
    let ag = (fsblock >> geometry.agblk_log()) as u32;
    if ag >= geometry.ag_count() {
        return Err(Error::Malformed {
            structure: "fsblock",
            reason: "references allocation group beyond superblock ag_count",
        });
    }
    let agbno = fsblock & ((1u64 << geometry.agblk_log()) - 1);
    if agbno >= geometry.ag_blocks() as u64 {
        return Err(Error::Malformed {
            structure: "fsblock",
            reason: "block offset beyond superblock ag_blocks",
        });
    }
    let base = geometry.ag_start_byte(ag)?;
    let block_bytes = geometry.fs_block_bytes() as u64;
    base.checked_add(agbno * block_bytes)
        .ok_or(Error::Malformed {
            structure: "fsblock",
            reason: "byte offset computation overflows 64-bit arithmetic",
        })
}

fn traverse_bmbt_node(
    ctx: &mut BmbtContext<'_>,
    fsblock: u64,
    expected_level: u16,
    visited: &mut Vec<u64>,
    extents: &mut Vec<FileExtent>,
    issues: &mut Vec<ExtentIssue>,
) -> Result<()> {
    let byte_offset = match fsblock_to_byte(ctx.geometry, fsblock) {
        Ok(off) => off,
        Err(_) => {
            issues.push(ExtentIssue::BtreeInvalidPointer {
                fsblock,
                dblocks: ctx.geometry.dblocks(),
            });
            return Ok(());
        }
    };

    if visited.contains(&fsblock) {
        issues.push(ExtentIssue::BtreeCycleDetected { block: fsblock });
        return Ok(());
    }
    visited.push(fsblock);

    let block_size = ctx.sb.block_size as usize;
    let mut block_buf = vec![0u8; block_size];
    ctx.reader
        .read_at(ctx.fs_base_offset + byte_offset, &mut block_buf)?;

    let is_v5 = ctx.sb.version5();
    let expected_magic = if is_v5 {
        XFS_BMAP_CRC_MAGIC
    } else {
        XFS_BMAP_MAGIC
    };
    let hdr_len = if is_v5 { HDR_BYTES_V5 } else { HDR_BYTES_V4 };

    let magic = be_u32_at(&block_buf, OFF_BMBT_MAGIC)?;
    if magic != expected_magic {
        issues.push(ExtentIssue::BtreeBadMagic {
            block: fsblock,
            magic,
        });
        return Ok(());
    }

    let _leftsib = be_u64_at(&block_buf, OFF_BMBT_LEFTSIB)?;
    let _rightsib = be_u64_at(&block_buf, OFF_BMBT_RIGHTSIB)?;

    if is_v5 {
        let stored_crc = u32::from_le_bytes([
            block_buf[OFF_BMBT_CRC],
            block_buf[OFF_BMBT_CRC + 1],
            block_buf[OFF_BMBT_CRC + 2],
            block_buf[OFF_BMBT_CRC + 3],
        ]);
        let computed = crc32c_with_zeroed_range(&block_buf, OFF_BMBT_CRC, 4);
        if computed != stored_crc {
            issues.push(ExtentIssue::BtreeCrcMismatch {
                block: fsblock,
                stored: stored_crc,
                computed,
            });
        }

        let expected_daddr = byte_offset / 512;
        let blkno = be_u64_at(&block_buf, OFF_BMBT_BLKNO)?;
        if blkno != expected_daddr {
            issues.push(ExtentIssue::BtreeBlknoMismatch {
                block: fsblock,
                expected: expected_daddr,
                found: blkno,
            });
        }

        if block_buf[OFF_BMBT_UUID..OFF_BMBT_UUID + 16] != ctx.sb.uuid {
            issues.push(ExtentIssue::BtreeUuidMismatch { block: fsblock });
        }

        let owner = be_u64_at(&block_buf, OFF_BMBT_OWNER)?;
        if owner != ctx.owner_ino {
            issues.push(ExtentIssue::BtreeOwnerMismatch {
                block: fsblock,
                expected: ctx.owner_ino,
                found: owner,
            });
        }
    }

    let level = be_u16_at(&block_buf, OFF_BMBT_LEVEL)?;
    if level != expected_level {
        issues.push(ExtentIssue::BtreeLevelMismatch {
            block: fsblock,
            expected: expected_level,
            found: level,
        });
    }

    let numrecs = be_u16_at(&block_buf, OFF_BMBT_NUMRECS)?;
    let avail = block_size.saturating_sub(hdr_len);

    if level == 0 {
        let max_recs = avail / 16;
        let recs_to_read = (numrecs as usize).min(max_recs);
        for i in 0..recs_to_read {
            let offset = hdr_len + i * 16;
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&block_buf[offset..offset + 16]);
            let extent = decode_bmbt_record(&raw);
            validate_single_extent(&extent, extents.len(), ctx.geometry.dblocks(), issues);
            extents.push(extent);
        }
    } else {
        if level > MAX_BMBT_LEVELS {
            issues.push(ExtentIssue::BtreeExcessiveDepth { level });
            return Ok(());
        }

        let maxrecs = avail / 16;
        let ptr_start = hdr_len + maxrecs * 8;
        let ptrs_to_read = (numrecs as usize).min(maxrecs);

        for i in 0..ptrs_to_read {
            let ptr_offset = ptr_start + i * 8;
            if ptr_offset + 8 > block_buf.len() {
                issues.push(ExtentIssue::TruncatedRecord {
                    needed: ptr_offset + 8,
                    available: block_buf.len(),
                });
                break;
            }
            let child_fsb = be_u64_at(&block_buf, ptr_offset)?;
            traverse_bmbt_node(ctx, child_fsb, level - 1, visited, extents, issues)?;
        }
    }

    Ok(())
}

fn validate_single_extent(
    extent: &FileExtent,
    index: usize,
    dblocks: u64,
    issues: &mut Vec<ExtentIssue>,
) {
    if extent.block_count == 0 {
        issues.push(ExtentIssue::ZeroBlockCount {
            index,
            logical_start: extent.logical_start,
        });
    }

    if extent
        .logical_start
        .checked_add(extent.block_count)
        .is_none()
        || extent.logical_end() > (1u64 << 54)
    {
        issues.push(ExtentIssue::LogicalStartOverflow {
            logical_start: extent.logical_start,
            block_count: extent.block_count,
        });
    }

    if extent
        .physical_start
        .checked_add(extent.block_count)
        .is_none()
    {
        issues.push(ExtentIssue::PhysicalStartOverflow {
            physical_start: extent.physical_start,
            block_count: extent.block_count,
        });
    } else if extent.physical_end() > dblocks {
        issues.push(ExtentIssue::PhysicalBlockOutOfBounds {
            physical_start: extent.physical_start,
            block_count: extent.block_count,
            dblocks,
        });
    }
}

fn validate_extent_sequence(extents: &[FileExtent], issues: &mut Vec<ExtentIssue>) {
    for window in extents.windows(2) {
        let prev = &window[0];
        let next = &window[1];

        if next.logical_start < prev.logical_start {
            issues.push(ExtentIssue::DecreasingLogicalOffset {
                prev_start: prev.logical_start,
                next_start: next.logical_start,
            });
        } else if next.logical_start < prev.logical_end() {
            issues.push(ExtentIssue::LogicalOverlap {
                prev_end: prev.logical_end(),
                next_start: next.logical_start,
            });
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidualConfidence {
    Probable,
    Ambiguous,
}

#[derive(Debug, Clone)]
pub struct ResidualInterpretation {
    pub extents: Vec<FileExtent>,
    pub confidence: ResidualConfidence,
    pub issues: Vec<ExtentIssue>,
}

pub fn interpret_residual_extents(
    inode: &Dinode,
    geometry: &Geometry,
) -> Option<ResidualInterpretation> {
    if inode.core.file_type != FileType::Unallocated && inode.core.nextents != 0 {
        return None;
    }

    let lit_offset = inode.core.literal_area_offset();
    if inode.raw.len() <= lit_offset {
        return None;
    }
    let data_raw = &inode.raw[lit_offset..];
    if data_raw.iter().all(|&b| b == 0) {
        return None;
    }

    let mut extents = Vec::new();
    let mut issues = Vec::new();
    let num_chunks = data_raw.len() / 16;

    for i in 0..num_chunks {
        let offset = i * 16;
        let mut raw = [0u8; 16];
        raw.copy_from_slice(&data_raw[offset..offset + 16]);
        if raw.iter().all(|&b| b == 0) {
            continue;
        }

        let extent = decode_bmbt_record(&raw);
        if extent.block_count == 0
            || extent.block_count > (1u64 << 21)
            || extent.physical_end() > geometry.dblocks()
        {
            continue;
        }
        validate_single_extent(&extent, extents.len(), geometry.dblocks(), &mut issues);
        extents.push(extent);
    }

    if extents.is_empty() {
        return None;
    }

    validate_extent_sequence(&extents, &mut issues);

    let confidence = if issues.is_empty() && !extents.is_empty() {
        ResidualConfidence::Probable
    } else {
        ResidualConfidence::Ambiguous
    };

    Some(ResidualInterpretation {
        extents,
        confidence,
        issues,
    })
}

pub struct ExtentReader<'a, R: ImageRead> {
    reader: &'a mut R,
    fs_base_offset: u64,
    geometry: Geometry,
    extents: Vec<FileExtent>,
    file_size: u64,
    block_size: u32,
}

impl<'a, R: ImageRead> ExtentReader<'a, R> {
    pub fn new(
        reader: &'a mut R,
        fs_base_offset: u64,
        geometry: &Geometry,
        extents: &[FileExtent],
        file_size: u64,
    ) -> Self {
        Self {
            reader,
            fs_base_offset,
            geometry: *geometry,
            extents: extents.to_vec(),
            file_size,
            block_size: geometry.fs_block_bytes(),
        }
    }

    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.file_size || buf.is_empty() {
            return Ok(0);
        }

        let available = self.file_size - offset;
        let to_read = (buf.len() as u64).min(available) as usize;
        let bsize = self.block_size as u64;

        let mut done = 0;
        while done < to_read {
            let cur_offset = offset + done as u64;
            let log_blk = cur_offset / bsize;
            let blk_off = cur_offset % bsize;
            let blk_remain = (bsize - blk_off) as usize;
            let chunk_len = (to_read - done).min(blk_remain);

            let matching_extent = self
                .extents
                .iter()
                .find(|e| e.contains_logical_block(log_blk));

            match matching_extent {
                Some(extent) => {
                    let extent_blk_offset = log_blk - extent.logical_start;
                    let extent_remain_blks = extent.block_count - extent_blk_offset;
                    let extent_remain_bytes = (extent_remain_blks * bsize - blk_off) as usize;
                    let cur_chunk = (to_read - done).min(extent_remain_bytes);

                    match extent.state {
                        ExtentState::Normal => {
                            let phys_blk = extent.physical_start + extent_blk_offset;
                            let phys_byte = fsblock_to_byte(&self.geometry, phys_blk)? + blk_off;
                            self.reader.read_at(
                                self.fs_base_offset + phys_byte,
                                &mut buf[done..done + cur_chunk],
                            )?;
                        }
                        ExtentState::Unwritten => {
                            buf[done..done + cur_chunk].fill(0);
                        }
                    }
                    done += cur_chunk;
                }
                None => {
                    // Sparse hole: find next extent starting after log_blk, or read up to chunk_len
                    let next_start = self
                        .extents
                        .iter()
                        .filter(|e| e.logical_start > log_blk)
                        .map(|e| e.logical_start)
                        .min();

                    let hole_remain_bytes = match next_start {
                        Some(next_blk) => {
                            let hole_blks = next_blk - log_blk;
                            (hole_blks * bsize - blk_off) as usize
                        }
                        None => to_read - done,
                    };

                    let cur_chunk = (to_read - done).min(hole_remain_bytes).max(chunk_len);
                    buf[done..done + cur_chunk].fill(0);
                    done += cur_chunk;
                }
            }
        }

        Ok(to_read)
    }

    pub fn read_all(&mut self) -> Result<Vec<u8>> {
        let size = usize::try_from(self.file_size).map_err(|_| Error::Malformed {
            structure: "file extent reader",
            reason: "file size exceeds system addressable memory",
        })?;
        let mut buf = vec![0u8; size];
        self.read_at(0, &mut buf)?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::MemImage;
    use crate::xfs::dinode::{DINODE_V3_CORE_SIZE, INODE_MAGIC, parse_dinode_core};
    use crate::xfs::inode_addr::InodeLocation;

    fn sample_geometry() -> Geometry {
        let (_sb, geo) =
            Superblock::parse_bytes(&crate::xfs::superblock::testing::golden_v5()).unwrap();
        geo
    }

    #[test]
    fn decodes_and_encodes_bmbt_record_round_trip() {
        let extent = FileExtent {
            logical_start: 12345,
            physical_start: 67890,
            block_count: 42,
            state: ExtentState::Normal,
        };

        let raw = encode_bmbt_record(&extent);
        let decoded = decode_bmbt_record(&raw);
        assert_eq!(extent, decoded);

        let unwritten_extent = FileExtent {
            logical_start: (1u64 << 54) - 100,
            physical_start: (1u64 << 52) - 200,
            block_count: (1u64 << 21) - 1,
            state: ExtentState::Unwritten,
        };
        let raw_unwritten = encode_bmbt_record(&unwritten_extent);
        let decoded_unwritten = decode_bmbt_record(&raw_unwritten);
        assert_eq!(unwritten_extent, decoded_unwritten);
    }

    #[test]
    fn validates_extent_sequence_and_flags_overlaps() {
        let mut issues = Vec::new();
        let extents = vec![
            FileExtent {
                logical_start: 0,
                physical_start: 100,
                block_count: 10,
                state: ExtentState::Normal,
            },
            FileExtent {
                logical_start: 8, // overlaps 8 < 10
                physical_start: 200,
                block_count: 5,
                state: ExtentState::Normal,
            },
            FileExtent {
                logical_start: 5, // decreasing 5 < 8
                physical_start: 300,
                block_count: 5,
                state: ExtentState::Normal,
            },
        ];

        validate_extent_sequence(&extents, &mut issues);
        assert!(
            issues
                .iter()
                .any(|i| matches!(i, ExtentIssue::LogicalOverlap { .. }))
        );
        assert!(
            issues
                .iter()
                .any(|i| matches!(i, ExtentIssue::DecreasingLogicalOffset { .. }))
        );
    }

    #[test]
    fn validates_single_extent_bounds() {
        let mut issues = Vec::new();
        let bad = FileExtent {
            logical_start: 0,
            physical_start: 99_995,
            block_count: 10, // 99995 + 10 = 100005 > 100000 dblocks
            state: ExtentState::Normal,
        };
        validate_single_extent(&bad, 0, 100_000, &mut issues);
        assert!(
            issues
                .iter()
                .any(|i| matches!(i, ExtentIssue::PhysicalBlockOutOfBounds { .. }))
        );

        let mut issues_zero = Vec::new();
        let zero_cnt = FileExtent {
            logical_start: 0,
            physical_start: 100,
            block_count: 0,
            state: ExtentState::Normal,
        };
        validate_single_extent(&zero_cnt, 0, 100_000, &mut issues_zero);
        assert!(
            issues_zero
                .iter()
                .any(|i| matches!(i, ExtentIssue::ZeroBlockCount { .. }))
        );
    }

    #[test]
    fn parses_extent_format_data_fork() {
        let geo = sample_geometry();
        let isize = 512;
        let mut buf = vec![0u8; isize];
        buf[0..2].copy_from_slice(&INODE_MAGIC.to_be_bytes());
        buf[2..4].copy_from_slice(&0o100644u16.to_be_bytes());
        buf[4] = 3;
        buf[5] = DataForkFormat::Extents.to_u8();
        buf[56..64].copy_from_slice(&8192u64.to_be_bytes());
        buf[64..72].copy_from_slice(&2u64.to_be_bytes());
        buf[76..80].copy_from_slice(&2u32.to_be_bytes()); // nextents = 2

        let ext1 = FileExtent {
            logical_start: 0,
            physical_start: 100,
            block_count: 1,
            state: ExtentState::Normal,
        };
        let ext2 = FileExtent {
            logical_start: 1,
            physical_start: 200,
            block_count: 1,
            state: ExtentState::Normal,
        };

        buf[DINODE_V3_CORE_SIZE..DINODE_V3_CORE_SIZE + 16]
            .copy_from_slice(&encode_bmbt_record(&ext1));
        buf[DINODE_V3_CORE_SIZE + 16..DINODE_V3_CORE_SIZE + 32]
            .copy_from_slice(&encode_bmbt_record(&ext2));

        let core = parse_dinode_core(&buf, isize).unwrap();
        let inode = Dinode {
            location: InodeLocation {
                ino: 128,
                ag_number: 0,
                ag_block: 16,
                slot: 0,
                byte_offset: 65536,
            },
            core,
            raw: buf,
        };

        let map = parse_extents_data_fork(
            &inode,
            &Superblock::parse_bytes(&crate::xfs::superblock::testing::golden_v5())
                .unwrap()
                .0,
            &geo,
        )
        .unwrap();
        assert_eq!(map.extents.len(), 2);
        assert_eq!(map.extents[0], ext1);
        assert_eq!(map.extents[1], ext2);
        assert!(map.issues.is_empty());
    }

    #[test]
    fn extent_reader_reads_sequential_extents_and_sparse_holes() {
        let geo = sample_geometry();
        let mut disk_data = vec![0u8; 1000 * 4096];

        // Block 100 contains "AAAA..."
        disk_data[100 * 4096..101 * 4096].fill(b'A');
        // Block 200 contains "CCCC..."
        disk_data[200 * 4096..201 * 4096].fill(b'C');

        let mut image = MemImage::new(&disk_data);

        // File layout:
        // Logical block 0: Physical block 100 (AAAA...)
        // Logical block 1: Sparse hole (zeros)
        // Logical block 2: Physical block 200 (CCCC...)
        let extents = vec![
            FileExtent {
                logical_start: 0,
                physical_start: 100,
                block_count: 1,
                state: ExtentState::Normal,
            },
            FileExtent {
                logical_start: 2,
                physical_start: 200,
                block_count: 1,
                state: ExtentState::Normal,
            },
        ];

        let file_size = 3 * 4096;
        let mut reader = ExtentReader::new(&mut image, 0, &geo, &extents, file_size);

        let content = reader.read_all().unwrap();
        assert_eq!(content.len(), 3 * 4096);
        assert!(content[0..4096].iter().all(|&b| b == b'A'));
        assert!(content[4096..8192].iter().all(|&b| b == 0));
        assert!(content[8192..12288].iter().all(|&b| b == b'C'));

        // Partial and unaligned reads
        let mut sub = [0u8; 10];
        reader.read_at(4090, &mut sub).unwrap();
        assert_eq!(&sub[0..6], &[b'A'; 6]);
        assert_eq!(&sub[6..10], &[0u8; 4]);
    }

    #[test]
    fn interprets_residual_extents_on_deleted_inode() {
        let geo = sample_geometry();
        let isize = 512;
        let mut buf = vec![0u8; isize];
        buf[0..2].copy_from_slice(&INODE_MAGIC.to_be_bytes());
        buf[2..4].copy_from_slice(&0u16.to_be_bytes()); // unallocated
        buf[4] = 3;
        buf[5] = DataForkFormat::Extents.to_u8();

        let ext = FileExtent {
            logical_start: 0,
            physical_start: 50,
            block_count: 10,
            state: ExtentState::Normal,
        };
        buf[DINODE_V3_CORE_SIZE..DINODE_V3_CORE_SIZE + 16]
            .copy_from_slice(&encode_bmbt_record(&ext));

        let core = parse_dinode_core(&buf, isize).unwrap();
        let inode = Dinode {
            location: InodeLocation {
                ino: 128,
                ag_number: 0,
                ag_block: 16,
                slot: 0,
                byte_offset: 65536,
            },
            core,
            raw: buf,
        };

        let residual = interpret_residual_extents(&inode, &geo).expect("residual interpretation");
        assert_eq!(residual.extents.len(), 1);
        assert_eq!(residual.extents[0], ext);
        assert_eq!(residual.confidence, ResidualConfidence::Probable);
    }

    #[test]
    fn packed_extent_bit_boundary_edge_cases() {
        let max_startoff = (1u64 << 54) - 1;
        let max_startblock = (1u64 << 52) - 1;
        let max_blockcount = (1u64 << 21) - 1;

        let max_extent = FileExtent {
            logical_start: max_startoff,
            physical_start: max_startblock,
            block_count: max_blockcount,
            state: ExtentState::Unwritten,
        };

        let raw = encode_bmbt_record(&max_extent);
        let decoded = decode_bmbt_record(&raw);
        assert_eq!(decoded.logical_start, max_startoff);
        assert_eq!(decoded.physical_start, max_startblock);
        assert_eq!(decoded.block_count, max_blockcount);
        assert_eq!(decoded.state, ExtentState::Unwritten);

        // Test normal state (flag = 0)
        let mut normal_extent = max_extent;
        normal_extent.state = ExtentState::Normal;
        let raw_norm = encode_bmbt_record(&normal_extent);
        assert_eq!(raw_norm[0] & 0x80, 0);
        let dec_norm = decode_bmbt_record(&raw_norm);
        assert_eq!(dec_norm.state, ExtentState::Normal);
    }

    #[test]
    fn parses_bmbt_data_fork_with_level_1_root_and_child_leaf() {
        let (sb, geo) =
            Superblock::parse_bytes(&crate::xfs::superblock::testing::golden_v5()).unwrap();
        let isize = sb.inode_size as usize;
        let block_size = sb.block_size as usize;

        // Create disk image buffer
        let mut disk_data = vec![0u8; 100 * block_size];

        // Child leaf block at physical block 20 (fsblock = 20)
        let child_fsb: u64 = 20;
        let child_byte = fsblock_to_byte(&geo, child_fsb).unwrap() as usize;

        // Build child leaf block
        let mut child_buf = vec![0u8; block_size];
        child_buf[OFF_BMBT_MAGIC..OFF_BMBT_MAGIC + 4]
            .copy_from_slice(&XFS_BMAP_CRC_MAGIC.to_be_bytes());
        child_buf[OFF_BMBT_LEVEL..OFF_BMBT_LEVEL + 2].copy_from_slice(&0u16.to_be_bytes()); // level 0 = leaf
        child_buf[OFF_BMBT_NUMRECS..OFF_BMBT_NUMRECS + 2].copy_from_slice(&2u16.to_be_bytes()); // 2 recs
        child_buf[OFF_BMBT_LEFTSIB..OFF_BMBT_LEFTSIB + 8]
            .copy_from_slice(&NULLFSBLOCK.to_be_bytes());
        child_buf[OFF_BMBT_RIGHTSIB..OFF_BMBT_RIGHTSIB + 8]
            .copy_from_slice(&NULLFSBLOCK.to_be_bytes());
        child_buf[OFF_BMBT_BLKNO..OFF_BMBT_BLKNO + 8]
            .copy_from_slice(&(child_byte as u64 / 512).to_be_bytes());
        child_buf[OFF_BMBT_UUID..OFF_BMBT_UUID + 16].copy_from_slice(&sb.uuid);
        child_buf[OFF_BMBT_OWNER..OFF_BMBT_OWNER + 8].copy_from_slice(&128u64.to_be_bytes());

        let ext1 = FileExtent {
            logical_start: 0,
            physical_start: 50,
            block_count: 4,
            state: ExtentState::Normal,
        };
        let ext2 = FileExtent {
            logical_start: 10,
            physical_start: 60,
            block_count: 2,
            state: ExtentState::Normal,
        };

        child_buf[HDR_BYTES_V5..HDR_BYTES_V5 + 16].copy_from_slice(&encode_bmbt_record(&ext1));
        child_buf[HDR_BYTES_V5 + 16..HDR_BYTES_V5 + 32].copy_from_slice(&encode_bmbt_record(&ext2));

        let crc = crc32c_with_zeroed_range(&child_buf, OFF_BMBT_CRC, 4);
        child_buf[OFF_BMBT_CRC..OFF_BMBT_CRC + 4].copy_from_slice(&crc.to_le_bytes());

        disk_data[child_byte..child_byte + block_size].copy_from_slice(&child_buf);

        // Build inode with level 1 BMBT root
        let mut inode_buf = vec![0u8; isize];
        inode_buf[0..2].copy_from_slice(&INODE_MAGIC.to_be_bytes());
        inode_buf[2..4].copy_from_slice(&0o100644u16.to_be_bytes());
        inode_buf[4] = 3;
        inode_buf[5] = DataForkFormat::Btree.to_u8();
        inode_buf[56..64].copy_from_slice(&49152u64.to_be_bytes()); // size

        let root_offset = DINODE_V3_CORE_SIZE;
        inode_buf[root_offset + OFF_BMDR_LEVEL..root_offset + OFF_BMDR_LEVEL + 2]
            .copy_from_slice(&1u16.to_be_bytes()); // level 1
        inode_buf[root_offset + OFF_BMDR_NUMRECS..root_offset + OFF_BMDR_NUMRECS + 2]
            .copy_from_slice(&1u16.to_be_bytes()); // 1 ptr

        // In BMDR root:
        // Key 0 at root_offset + 4 (8 bytes)
        // dmxr = (data_fork_size - 4) / 16
        let df_size = isize - DINODE_V3_CORE_SIZE;
        let dmxr = (df_size - BMDR_HEADER_BYTES) / 16;
        let key_offset = root_offset + BMDR_HEADER_BYTES;
        inode_buf[key_offset..key_offset + 8].copy_from_slice(&0u64.to_be_bytes());

        let ptr_offset = root_offset + BMDR_HEADER_BYTES + dmxr * 8;
        inode_buf[ptr_offset..ptr_offset + 8].copy_from_slice(&child_fsb.to_be_bytes());

        let core = parse_dinode_core(&inode_buf, isize).unwrap();
        let inode = Dinode {
            location: InodeLocation {
                ino: 128,
                ag_number: 0,
                ag_block: 16,
                slot: 0,
                byte_offset: 65536,
            },
            core,
            raw: inode_buf,
        };

        let mut image = MemImage::new(&disk_data);
        let map = parse_data_fork(&mut image, 0, &sb, &geo, &inode).expect("parse btree fork");
        assert_eq!(map.extents.len(), 2);
        assert_eq!(map.extents[0], ext1);
        assert_eq!(map.extents[1], ext2);
        assert!(map.issues.is_empty());
    }

    #[test]
    fn deterministic_bmbt_record_fuzzing_never_panics() {
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        let mut raw = [0u8; 16];

        for _ in 0..5000 {
            for b in raw.iter_mut() {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (state >> 33) as u8;
            }
            let extent = decode_bmbt_record(&raw);
            let re_encoded = encode_bmbt_record(&extent);
            let re_decoded = decode_bmbt_record(&re_encoded);
            assert_eq!(extent, re_decoded);
        }
    }
}
