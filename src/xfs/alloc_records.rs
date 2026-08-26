use crate::error::{Error, Result};
use crate::io::ImageRead;
use crate::util::be::{be_u16_at, be_u32_at, be_u64_at};
use crate::xfs::ag::{parse_agf, parse_agi};
use crate::xfs::btree::{
    AllocBtreeKind, BtreeIssue, RecordSource, RecordView, WalkMode, walk_alloc_btree,
};
use crate::xfs::superblock::{Geometry, Superblock};
use std::collections::BTreeMap;

pub const INODES_PER_CHUNK: u32 = 64;
pub const INODES_PER_HOLEMASK_BIT: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreeExtent {
    pub startblock: u32,
    pub blockcount: u32,
    pub source: RecordSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InobtRecord {
    pub startino: u32,
    pub holemask: u16,
    pub inode_count: u8,
    pub freecount: u32,
    pub free_mask: u64,
    pub source: RecordSource,
}

impl InobtRecord {
    pub fn is_sparse(&self) -> bool {
        self.holemask != 0
    }

    pub fn valid_mask(&self) -> u64 {
        if !self.is_sparse() {
            return u64::MAX;
        }
        let mut mask = u64::MAX;
        for group in 0..(INODES_PER_CHUNK / INODES_PER_HOLEMASK_BIT) {
            if self.holemask & (1 << group) != 0 {
                let lo = group * INODES_PER_HOLEMASK_BIT;
                mask &= !(((1u64 << INODES_PER_HOLEMASK_BIT) - 1) << lo);
            }
        }
        mask
    }

    pub fn computed_freecount(&self) -> u32 {
        (self.free_mask & self.valid_mask()).count_ones()
    }

    pub fn allocated_count(&self) -> u32 {
        self.valid_mask().count_ones() - self.computed_freecount()
    }

    pub fn slot_state(&self, slot: u32) -> Option<SlotState> {
        if slot >= INODES_PER_CHUNK {
            return None;
        }
        let bit = 1u64 << slot;
        if self.valid_mask() & bit == 0 {
            return Some(SlotState::Hole);
        }
        if self.free_mask & bit != 0 {
            Some(SlotState::Free)
        } else {
            Some(SlotState::Allocated)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    Allocated,
    Free,
    Hole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllocRecordIssue {
    ZeroLengthExtent {
        startblock: u32,
    },
    ExtentOutOfBounds {
        startblock: u32,
        blockcount: u32,
        ag_blocks: u32,
    },
    ChunkMisaligned {
        startino: u32,
    },
    ChunkOutOfBounds {
        startino: u32,
        capacity: u32,
    },
    FreecountMismatch {
        startino: u32,
        declared: u32,
        computed: u32,
    },
    InodeCountOutOfRange {
        startino: u32,
        count: u8,
    },
    FreeBitInHole {
        startino: u32,
        slot: u32,
    },
    CntSumMismatch {
        computed: u64,
        agf_freeblks: u32,
    },
    FinoZeroFreecount {
        startino: u32,
    },
    FinoUnknownChunk {
        startino: u32,
    },
    FinoFreecountDivergence {
        startino: u32,
        inobt_free: u32,
        fino_free: u32,
    },
    FinoMissingForFreeChunk {
        startino: u32,
    },
    Tree(BtreeIssue),
    TreeUnwalkable {
        tree: &'static str,
    },
    RecordUnreadable {
        tree: &'static str,
    },
}

fn decode_issue(issue: AllocRecordIssue) -> Error {
    Error::Malformed {
        structure: "allocation record",
        reason: issue_reason(&issue),
    }
}

fn issue_reason(issue: &AllocRecordIssue) -> &'static str {
    match issue {
        AllocRecordIssue::ZeroLengthExtent { .. } => "zero-length free extent",
        AllocRecordIssue::ExtentOutOfBounds { .. } => "free extent beyond allocation group",
        AllocRecordIssue::ChunkMisaligned { .. } => {
            "inode chunk start misaligned to 64-inode boundary"
        }
        AllocRecordIssue::ChunkOutOfBounds { .. } => "inode chunk beyond allocation group bounds",
        AllocRecordIssue::FreecountMismatch { .. } => {
            "declared freecount disagrees with free bitmask"
        }
        AllocRecordIssue::InodeCountOutOfRange { .. } => "inode count outside supported range",
        AllocRecordIssue::FreeBitInHole { .. } => "free bitmask marks a hole slot as inode-free",
        AllocRecordIssue::CntSumMismatch { .. } => {
            "cntbt extent sum disagrees with AGF free blocks"
        }
        AllocRecordIssue::FinoZeroFreecount { .. } => "finobt record carries zero free inodes",
        AllocRecordIssue::FinoUnknownChunk { .. } => "finobt chunk missing from inobt",
        AllocRecordIssue::FinoFreecountDivergence { .. } => "finobt freecount diverges from inobt",
        AllocRecordIssue::FinoMissingForFreeChunk { .. } => {
            "inobt chunk with free inodes absent from finobt"
        }
        AllocRecordIssue::Tree(_) => "btree traversal reported a metadata problem",
        AllocRecordIssue::TreeUnwalkable { .. } => {
            "btree unreadable in salvage mode; contents skipped"
        }
        AllocRecordIssue::RecordUnreadable { .. } => "record bytes failed low-level decoding",
    }
}

pub fn decode_free_extent(view: &RecordView<'_>) -> Result<FreeExtent> {
    Ok(FreeExtent {
        startblock: be_u32_at(view.raw, 0)?,
        blockcount: be_u32_at(view.raw, 4)?,
        source: view.source,
    })
}

pub fn validate_extent(
    extent: &FreeExtent,
    ag_blocks: u32,
) -> std::result::Result<(), AllocRecordIssue> {
    if extent.blockcount == 0 {
        return Err(AllocRecordIssue::ZeroLengthExtent {
            startblock: extent.startblock,
        });
    }
    if extent.startblock == 0 {
        return Err(AllocRecordIssue::ExtentOutOfBounds {
            startblock: extent.startblock,
            blockcount: extent.blockcount,
            ag_blocks,
        });
    }
    let end = extent.startblock.checked_add(extent.blockcount).ok_or(
        AllocRecordIssue::ExtentOutOfBounds {
            startblock: extent.startblock,
            blockcount: extent.blockcount,
            ag_blocks,
        },
    )?;
    if end > ag_blocks {
        return Err(AllocRecordIssue::ExtentOutOfBounds {
            startblock: extent.startblock,
            blockcount: extent.blockcount,
            ag_blocks,
        });
    }
    Ok(())
}

pub fn decode_inobt_record(sb_sparse: bool, view: &RecordView<'_>) -> Result<InobtRecord> {
    let startino = be_u32_at(view.raw, 0)?;
    let (holemask, inode_count, freecount) = if sb_sparse {
        (be_u16_at(view.raw, 4)?, view.raw[6], view.raw[7] as u32)
    } else {
        (0u16, INODES_PER_CHUNK as u8, be_u32_at(view.raw, 4)?)
    };
    Ok(InobtRecord {
        startino,
        holemask,
        inode_count,
        freecount,
        free_mask: be_u64_at(view.raw, 8)?,
        source: view.source,
    })
}

pub fn validate_inobt(
    rec: &InobtRecord,
    capacity: u32,
) -> std::result::Result<(), AllocRecordIssue> {
    if !rec.startino.is_multiple_of(INODES_PER_CHUNK) {
        return Err(AllocRecordIssue::ChunkMisaligned {
            startino: rec.startino,
        });
    }
    let last = rec.startino.checked_add(INODES_PER_CHUNK - 1).ok_or(
        AllocRecordIssue::ChunkOutOfBounds {
            startino: rec.startino,
            capacity,
        },
    )?;
    if last >= capacity {
        return Err(AllocRecordIssue::ChunkOutOfBounds {
            startino: rec.startino,
            capacity,
        });
    }
    if rec.inode_count < INODES_PER_HOLEMASK_BIT as u8 || rec.inode_count > INODES_PER_CHUNK as u8 {
        return Err(AllocRecordIssue::InodeCountOutOfRange {
            startino: rec.startino,
            count: rec.inode_count,
        });
    }
    if rec.freecount > INODES_PER_CHUNK {
        return Err(AllocRecordIssue::FreecountMismatch {
            startino: rec.startino,
            declared: rec.freecount,
            computed: rec.computed_freecount(),
        });
    }
    if rec.computed_freecount() != rec.freecount {
        return Err(AllocRecordIssue::FreecountMismatch {
            startino: rec.startino,
            declared: rec.freecount,
            computed: rec.computed_freecount(),
        });
    }
    for slot in 0..INODES_PER_CHUNK {
        let bit = 1u64 << slot;
        if rec.valid_mask() & bit == 0 && rec.free_mask & bit != 0 {
            return Err(AllocRecordIssue::FreeBitInHole {
                startino: rec.startino,
                slot,
            });
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct AgFreeSpace {
    pub ag_number: u32,
    pub bno_extents: Vec<FreeExtent>,
    pub cnt_extents: Vec<FreeExtent>,
    pub agf_free_blocks: u32,
    pub issues: Vec<AllocRecordIssue>,
}

impl AgFreeSpace {
    pub fn cnt_total_blocks(&self) -> u64 {
        self.cnt_extents.iter().map(|e| e.blockcount as u64).sum()
    }

    pub fn sums_match_agf(&self) -> bool {
        self.cnt_total_blocks() == self.agf_free_blocks as u64
    }
}

#[derive(Debug)]
pub struct InodeAllocationMap {
    pub ag_number: u32,
    pub capacity: u32,
    chunks: BTreeMap<u32, InobtRecord>,
    pub fino_records: Vec<InobtRecord>,
    pub finobt_scanned: bool,
    pub issues: Vec<AllocRecordIssue>,
}

impl InodeAllocationMap {
    pub fn from_chunks(ag_number: u32, capacity: u32, chunks: BTreeMap<u32, InobtRecord>) -> Self {
        Self {
            ag_number,
            capacity,
            chunks,
            fino_records: Vec::new(),
            finobt_scanned: false,
            issues: Vec::new(),
        }
    }

    pub fn chunk_starts(&self) -> impl Iterator<Item = u32> + '_ {
        self.chunks.keys().copied()
    }

    pub fn iter_chunks(&self) -> impl Iterator<Item = &InobtRecord> + '_ {
        self.chunks.values()
    }

    pub fn chunk_containing(&self, ag_inode: u32) -> Option<&InobtRecord> {
        let base = (ag_inode / INODES_PER_CHUNK) * INODES_PER_CHUNK;
        self.chunks.get(&base)
    }

    pub fn slot_state(&self, ag_inode: u32) -> Option<SlotState> {
        self.chunk_containing(ag_inode)?
            .slot_state(ag_inode % INODES_PER_CHUNK)
    }

    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    pub fn allocated_inodes(&self) -> u64 {
        self.chunks
            .values()
            .map(|r| r.allocated_count() as u64)
            .sum()
    }

    pub fn free_inodes(&self) -> u64 {
        self.chunks
            .values()
            .map(|r| r.computed_freecount() as u64)
            .sum()
    }

    fn cross_check_fino(&mut self) {
        for fino in &self.fino_records {
            if fino.freecount == 0 {
                self.issues.push(AllocRecordIssue::FinoZeroFreecount {
                    startino: fino.startino,
                });
                continue;
            }
            match self.chunks.get(&fino.startino) {
                None => self.issues.push(AllocRecordIssue::FinoUnknownChunk {
                    startino: fino.startino,
                }),
                Some(inobt_rec) => {
                    if inobt_rec.freecount != fino.freecount {
                        self.issues.push(AllocRecordIssue::FinoFreecountDivergence {
                            startino: fino.startino,
                            inobt_free: inobt_rec.freecount,
                            fino_free: fino.freecount,
                        });
                    }
                }
            }
        }
        if self.finobt_scanned {
            for chunk in self.chunks.values() {
                if chunk.computed_freecount() > 0
                    && !self
                        .fino_records
                        .iter()
                        .any(|f| f.startino == chunk.startino)
                {
                    self.issues.push(AllocRecordIssue::FinoMissingForFreeChunk {
                        startino: chunk.startino,
                    });
                }
            }
        }
    }
}

struct TreeRun<'a> {
    reader: &'a mut dyn ImageRead,
    fs_base_offset: u64,
    sb: &'a Superblock,
    geometry: &'a Geometry,
    ag_number: u32,
    root_block: u32,
    root_level: u32,
    kind: AllocBtreeKind,
    mode: WalkMode,
    tree_name: &'static str,
    issues: &'a mut Vec<AllocRecordIssue>,
}

fn run_tree(
    cx: &mut TreeRun<'_>,
    sink: &mut dyn FnMut(RecordView<'_>) -> std::result::Result<(), AllocRecordIssue>,
) -> Result<()> {
    let result = walk_alloc_btree::<()>(
        cx.reader,
        cx.fs_base_offset,
        cx.sb,
        cx.geometry,
        cx.ag_number,
        cx.root_block,
        cx.root_level,
        cx.kind,
        cx.mode,
        &mut |view| match sink(view) {
            Ok(()) => Ok(()),
            Err(issue) => {
                if cx.mode == WalkMode::Strict {
                    Err(decode_issue(issue))
                } else {
                    cx.issues.push(issue);
                    Ok(())
                }
            }
        },
    );
    match result {
        Ok(out) => cx
            .issues
            .extend(out.issues.into_iter().map(AllocRecordIssue::Tree)),
        Err(e) => {
            if cx.mode == WalkMode::Strict {
                return Err(e);
            }
            cx.issues
                .push(AllocRecordIssue::TreeUnwalkable { tree: cx.tree_name });
        }
    }
    Ok(())
}

pub fn collect_free_space(
    reader: &mut dyn ImageRead,
    fs_base_offset: u64,
    sb: &Superblock,
    geometry: &Geometry,
    ag_number: u32,
    mode: WalkMode,
) -> Result<AgFreeSpace> {
    let agf = parse_agf(reader, fs_base_offset, sb, geometry, ag_number)?;
    let ag_blocks = geometry.ag_blocks();
    let mut issues = Vec::new();

    let mut bno_extents = Vec::new();
    if agf.bnobt_root != 0 && agf.bnobt_level != 0 {
        run_tree(
            &mut TreeRun {
                reader,
                fs_base_offset,
                sb,
                geometry,
                ag_number,
                root_block: agf.bnobt_root,
                root_level: agf.bnobt_level.saturating_sub(1) as u32,
                kind: AllocBtreeKind::Bnobt,
                mode,
                tree_name: "bnobt",
                issues: &mut issues,
            },
            &mut |view| {
                let extent = decode_free_extent(&view)
                    .map_err(|_| AllocRecordIssue::RecordUnreadable { tree: "bnobt" })?;
                validate_extent(&extent, ag_blocks)?;
                bno_extents.push(extent);
                Ok(())
            },
        )?;
    }

    let mut cnt_extents = Vec::new();
    if agf.cntbt_root != 0 && agf.cntbt_level != 0 {
        run_tree(
            &mut TreeRun {
                reader,
                fs_base_offset,
                sb,
                geometry,
                ag_number,
                root_block: agf.cntbt_root,
                root_level: agf.cntbt_level.saturating_sub(1) as u32,
                kind: AllocBtreeKind::Cntbt,
                mode,
                tree_name: "cntbt",
                issues: &mut issues,
            },
            &mut |view| {
                let extent = decode_free_extent(&view)
                    .map_err(|_| AllocRecordIssue::RecordUnreadable { tree: "cntbt" })?;
                validate_extent(&extent, ag_blocks)?;
                cnt_extents.push(extent);
                Ok(())
            },
        )?;
    }

    bno_extents.sort_by_key(|e| e.startblock);

    let computed = cnt_extents.iter().map(|e| e.blockcount as u64).sum::<u64>();
    if computed != agf.free_blocks as u64 {
        let issue = AllocRecordIssue::CntSumMismatch {
            computed,
            agf_freeblks: agf.free_blocks,
        };
        if mode == WalkMode::Strict {
            return Err(decode_issue(issue));
        }
        issues.push(issue);
    }

    Ok(AgFreeSpace {
        ag_number,
        bno_extents,
        cnt_extents,
        agf_free_blocks: agf.free_blocks,
        issues,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn collect_inode_allocation(
    reader: &mut dyn ImageRead,
    fs_base_offset: u64,
    sb: &Superblock,
    geometry: &Geometry,
    ag_number: u32,
    mode: WalkMode,
) -> Result<InodeAllocationMap> {
    let agi = parse_agi(reader, fs_base_offset, sb, geometry, ag_number)?;
    let capacity = agi
        .length_blocks
        .saturating_mul(geometry.inodes_per_block());
    let sparse_layout = sb.sparse_inodes_enabled();

    let mut issues = Vec::new();
    let mut chunks: BTreeMap<u32, InobtRecord> = BTreeMap::new();

    if agi.inobt_root != 0 && agi.inobt_level != 0 {
        run_tree(
            &mut TreeRun {
                reader,
                fs_base_offset,
                sb,
                geometry,
                ag_number,
                root_block: agi.inobt_root,
                root_level: agi.inobt_level.saturating_sub(1) as u32,
                kind: AllocBtreeKind::Inobt,
                mode,
                tree_name: "inobt",
                issues: &mut issues,
            },
            &mut |view| {
                let rec = decode_inobt_record(sparse_layout, &view)
                    .map_err(|_| AllocRecordIssue::RecordUnreadable { tree: "inobt" })?;
                validate_inobt(&rec, capacity)?;
                chunks.insert(rec.startino, rec);
                Ok(())
            },
        )?;
    }

    let mut fino_records = Vec::new();
    if sb.finobt_enabled()
        && let Some((root, level)) = agi.finobt
        && root != 0
        && level != 0
    {
        run_tree(
            &mut TreeRun {
                reader,
                fs_base_offset,
                sb,
                geometry,
                ag_number,
                root_block: root,
                root_level: level.saturating_sub(1),
                kind: AllocBtreeKind::Finobt,
                mode,
                tree_name: "finobt",
                issues: &mut issues,
            },
            &mut |view| {
                let rec = decode_inobt_record(sparse_layout, &view)
                    .map_err(|_| AllocRecordIssue::RecordUnreadable { tree: "finobt" })?;
                validate_inobt(&rec, capacity)?;
                fino_records.push(rec);
                Ok(())
            },
        )?;
    }

    let mut map = InodeAllocationMap {
        ag_number,
        capacity,
        chunks,
        fino_records,
        finobt_scanned: sb.finobt_enabled(),
        issues,
    };
    map.cross_check_fino();
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xfs::superblock::testing::{golden_v4, golden_v5, put64};

    struct Ctx {
        sb: Superblock,
        geometry: Geometry,
    }

    fn ctx_v5() -> Ctx {
        let (sb, geometry) = Superblock::parse_bytes(&golden_v5()).expect("golden v5 sb");
        Ctx { sb, geometry }
    }

    fn ctx_v4() -> Ctx {
        let (sb, geometry) = Superblock::parse_bytes(&golden_v4()).expect("golden v4 sb");
        Ctx { sb, geometry }
    }

    const AG: u32 = 0;

    struct Src {
        data: Vec<u8>,
    }

    impl Src {
        fn for_blocks(ctx: &Ctx, highest_block: u32) -> Self {
            let end = ctx.geometry.ag_start_byte(AG).unwrap()
                + (highest_block as u64 + 2) * ctx.geometry.fs_block_bytes() as u64;
            Self {
                data: vec![0u8; end as usize],
            }
        }

        fn place(mut self, ctx: &Ctx, block: u32, bytes: &[u8]) -> Self {
            let offset = (ctx.geometry.ag_start_byte(AG).unwrap() + block as u64 * 4096) as usize;
            self.data[offset..offset + bytes.len()].copy_from_slice(bytes);
            self
        }

        fn place_agf(mut self, ctx: &Ctx, sector: &[u8]) -> Self {
            let offset = (ctx.geometry.ag_start_byte(AG).unwrap() + 512) as usize;
            self.data[offset..offset + sector.len()].copy_from_slice(sector);
            self
        }

        fn place_agi(mut self, ctx: &Ctx, sector: &[u8]) -> Self {
            let offset = (ctx.geometry.ag_start_byte(AG).unwrap() + 2 * 512) as usize;
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

    fn put16(dst: &mut [u8], off: usize, v: u16) {
        dst[off..off + 2].copy_from_slice(&v.to_be_bytes());
    }

    fn put32(dst: &mut [u8], off: usize, v: u32) {
        dst[off..off + 4].copy_from_slice(&v.to_be_bytes());
    }

    fn seal_agf(buf: &mut [u8]) {
        buf[216..220].copy_from_slice(&0u32.to_le_bytes());
        let crc = crate::util::crc32c::crc32c(buf);
        buf[216..220].copy_from_slice(&crc.to_le_bytes());
    }

    fn agf_sector(ctx: &Ctx, freeblks: u32, bno_root: u32, cnt_root: u32) -> Vec<u8> {
        let mut b = vec![0u8; ctx.sb.sector_size as usize];
        put32(&mut b, 0, 0x5841_4746);
        put32(&mut b, 4, 1);
        put32(&mut b, 8, AG);
        put32(&mut b, 12, ctx.sb.ag_blocks);
        put32(&mut b, 16, bno_root);
        put32(&mut b, 20, cnt_root);
        put32(&mut b, 28, 1);
        put32(&mut b, 32, 1);
        put32(&mut b, 52, freeblks);
        put32(&mut b, 56, freeblks);
        b[64..80].copy_from_slice(&ctx.sb.uuid);
        seal_agf(&mut b);
        b
    }

    fn leaf_block(
        ctx: &Ctx,
        kind: AllocBtreeKind,
        at_block: u32,
        raw_records: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut b = vec![0u8; 4096];
        let v5 = ctx.sb.version5();
        put32(&mut b, 0, kind.magic(v5));
        put16(&mut b, 4, 0);
        put16(&mut b, 6, raw_records.len() as u16);
        put32(&mut b, 8, u32::MAX);
        put32(&mut b, 12, u32::MAX);
        if v5 {
            b[OFF_UUID_TEST..OFF_UUID_TEST + 16].copy_from_slice(&ctx.sb.uuid);
            put32(&mut b, OFF_OWNER_TEST, AG);
            put64(&mut b, OFF_BLKNO_TEST, at_block as u64 * 8);
        }
        let hdr: usize = if v5 { 56 } else { 16 };
        for (i, rec) in raw_records.iter().enumerate() {
            b[hdr + i * rec.len()..hdr + (i + 1) * rec.len()].copy_from_slice(rec);
        }
        if v5 {
            buf_seal(&mut b, OFF_CRC_TEST);
        }
        b
    }

    const OFF_BLKNO_TEST: usize = 16;
    const OFF_UUID_TEST: usize = 32;
    const OFF_OWNER_TEST: usize = 48;
    const OFF_CRC_TEST: usize = 52;

    #[test]
    fn decodes_valid_free_extent() {
        let ctx = ctx_v5();
        let view_raw = [0u8, 0, 0, 13, 0, 0, 0, 3];
        let extent = decode_free_extent(&RecordView {
            source: test_source(),
            raw: &view_raw,
        })
        .unwrap();
        assert_eq!((extent.startblock, extent.blockcount), (13, 3));
        validate_extent(&extent, ctx.geometry.ag_blocks()).unwrap();
    }

    fn test_source() -> RecordSource {
        RecordSource {
            ag_number: 0,
            block_number: 1,
            slot: 0,
        }
    }

    #[test]
    fn boundary_extents_validate_and_overflows_do_not_panic() {
        let ctx = ctx_v5();
        let cap = ctx.geometry.ag_blocks();

        let edge = FreeExtent {
            startblock: cap - 1,
            blockcount: 1,
            source: test_source(),
        };
        validate_extent(&edge, cap).unwrap();
        assert!(matches!(
            validate_extent(
                &FreeExtent {
                    startblock: cap - 1,
                    blockcount: 2,
                    source: test_source()
                },
                cap
            ),
            Err(AllocRecordIssue::ExtentOutOfBounds { .. })
        ));

        let huge = FreeExtent {
            startblock: u32::MAX,
            blockcount: 1,
            source: test_source(),
        };
        assert!(matches!(
            validate_extent(&huge, cap),
            Err(AllocRecordIssue::ExtentOutOfBounds { .. })
        ));
    }

    #[test]
    fn zero_length_and_header_block_extents_rejected() {
        let ctx = ctx_v5();
        let zero = FreeExtent {
            startblock: 10,
            blockcount: 0,
            source: test_source(),
        };
        assert_eq!(
            validate_extent(&zero, ctx.geometry.ag_blocks()),
            Err(AllocRecordIssue::ZeroLengthExtent { startblock: 10 })
        );
        let header = FreeExtent {
            startblock: 0,
            blockcount: 9,
            source: test_source(),
        };
        assert!(matches!(
            validate_extent(&header, ctx.geometry.ag_blocks()),
            Err(AllocRecordIssue::ExtentOutOfBounds { .. })
        ));
    }

    fn legacy_rec(startino: u32, freecount: u32, free_mask: u64) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&startino.to_be_bytes());
        r.extend_from_slice(&freecount.to_be_bytes());
        r.extend_from_slice(&free_mask.to_be_bytes());
        r
    }

    fn sparse_rec(
        startino: u32,
        holemask: u16,
        count: u8,
        freecount: u8,
        free_mask: u64,
    ) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&startino.to_be_bytes());
        r.extend_from_slice(&holemask.to_be_bytes());
        r.push(count);
        r.push(freecount);
        r.extend_from_slice(&free_mask.to_be_bytes());
        r
    }

    #[test]
    fn legacy_inobt_record_decodes_with_full_validity() {
        let raw = legacy_rec(128, 61, 0xFFFF_FFFF_FFFF_FFF8);
        let owned: &'static [u8] = Box::leak(raw.into_boxed_slice());
        let rec = decode_inobt_record(
            false,
            &RecordView {
                source: test_source(),
                raw: owned,
            },
        )
        .unwrap();
        assert_eq!(rec.startino, 128);
        assert_eq!(rec.holemask, 0);
        assert_eq!(rec.inode_count, 64);
        assert_eq!(rec.freecount, 61);
        assert!(!rec.is_sparse());
        assert_eq!(rec.valid_mask(), u64::MAX);
        assert_eq!(rec.slot_state(0), Some(SlotState::Allocated));
        assert_eq!(rec.slot_state(5), Some(SlotState::Free));
        assert_eq!(rec.computed_freecount(), 61);
        assert_eq!(rec.allocated_count(), 3);
        validate_inobt(&rec, 16384 * 8).unwrap();
    }

    #[test]
    fn sparse_inobt_record_honors_holemask_groups_of_four() {
        let raw = sparse_rec(1024, 0xC000, 56, 2, 0x0000_0000_0000_000C);
        let owned: &'static [u8] = Box::leak(raw.into_boxed_slice());
        let rec = decode_inobt_record(
            true,
            &RecordView {
                source: test_source(),
                raw: owned,
            },
        )
        .unwrap();
        assert!(rec.is_sparse());
        assert_eq!(rec.valid_mask(), 0x00FF_FFFF_FFFF_FFFF);
        assert_eq!(rec.valid_mask().count_ones(), 56);
        assert_eq!(rec.slot_state(55), Some(SlotState::Allocated));
        assert_eq!(rec.slot_state(59), Some(SlotState::Hole));
        assert_eq!(rec.slot_state(60), Some(SlotState::Hole));
        assert_eq!(rec.slot_state(63), Some(SlotState::Hole));
        assert_eq!(rec.computed_freecount(), 2);
        assert_eq!(rec.allocated_count(), 54);
        validate_inobt(&rec, 16384 * 8).unwrap();
    }

    #[test]
    fn inobt_structural_violations_detected() {
        let ctx = ctx_v5();
        let cap = ctx.geometry.ag_blocks() * ctx.geometry.inodes_per_block();

        let misaligned = decode_inobt_record(false, &view_of(&legacy_rec(130, 0, 0))).unwrap();
        assert_eq!(
            validate_inobt(&misaligned, cap),
            Err(AllocRecordIssue::ChunkMisaligned { startino: 130 })
        );

        let past_end =
            decode_inobt_record(false, &view_of(&legacy_rec(cap - 64 + 64, 0, 0))).unwrap();
        assert!(matches!(
            validate_inobt(&past_end, cap),
            Err(AllocRecordIssue::ChunkOutOfBounds { .. })
        ));

        let bad_freecount =
            decode_inobt_record(false, &view_of(&legacy_rec(128, 5, 0xFFFF_FFFF_FFFF_FFF8)))
                .unwrap();
        assert_eq!(
            validate_inobt(&bad_freecount, cap),
            Err(AllocRecordIssue::FreecountMismatch {
                startino: 128,
                declared: 5,
                computed: 61
            })
        );

        let bad_count =
            decode_inobt_record(true, &view_of(&sparse_rec(128, 0, 3, 61, 0xF8))).unwrap();
        assert!(matches!(
            validate_inobt(&bad_count, cap),
            Err(AllocRecordIssue::InodeCountOutOfRange { .. })
        ));

        let hole_bit_free = decode_inobt_record(
            true,
            &view_of(&sparse_rec(128, 0x8000, 60, 60, u64::MAX >> 3)),
        )
        .unwrap();
        assert!(matches!(
            validate_inobt(&hole_bit_free, cap),
            Err(AllocRecordIssue::FreeBitInHole { slot: 60, .. })
        ));
    }

    fn view_of(raw: &[u8]) -> RecordView<'static> {
        RecordView {
            source: test_source(),
            raw: Box::leak(raw.to_vec().into_boxed_slice()),
        }
    }

    #[test]
    fn fino_cross_check_flags_divergence_missing_and_zero() {
        let good_chunk =
            decode_inobt_record(false, &view_of(&legacy_rec(128, 3, 0xFFFF_FFFF_FFFF_FFF8)))
                .unwrap();
        let full_chunk = decode_inobt_record(false, &view_of(&legacy_rec(192, 0, 0))).unwrap();
        let fino_good =
            decode_inobt_record(false, &view_of(&legacy_rec(128, 3, 0xFFFF_FFFF_FFFF_FFF8)))
                .unwrap();
        let fino_zero = decode_inobt_record(false, &view_of(&legacy_rec(256, 0, 0))).unwrap();
        let fino_divergent =
            decode_inobt_record(false, &view_of(&legacy_rec(128, 2, 0xFFFF_FFFF_FFFF_FFF8)))
                .unwrap();

        let mut map = InodeAllocationMap {
            ag_number: 0,
            capacity: 16384 * 8,
            chunks: BTreeMap::from([(128u32, good_chunk), (192u32, full_chunk)]),
            fino_records: vec![fino_good.clone(), fino_zero],
            finobt_scanned: true,
            issues: Vec::new(),
        };
        map.cross_check_fino();
        assert!(
            map.issues
                .contains(&AllocRecordIssue::FinoZeroFreecount { startino: 256 })
        );
        assert_eq!(map.issues.len(), 1);

        map.fino_records = vec![fino_zero];
        map.issues.clear();
        map.cross_check_fino();
        assert!(
            map.issues
                .contains(&AllocRecordIssue::FinoZeroFreecount { startino: 256 })
        );
        assert!(
            map.issues
                .contains(&AllocRecordIssue::FinoMissingForFreeChunk { startino: 128 })
        );

        map.fino_records = vec![fino_divergent];
        map.issues.clear();
        map.cross_check_fino();
        assert!(
            map.issues
                .contains(&AllocRecordIssue::FinoFreecountDivergence {
                    startino: 128,
                    inobt_free: 3,
                    fino_free: 2
                })
        );
        assert_eq!(map.issues.len(), 1);
    }

    #[test]
    fn collectors_walk_synthetic_trees_and_crosscheck_against_agf() {
        let ctx = ctx_v5();
        let e1 = [0u8, 0, 0, 13, 0, 0, 0, 3];
        let e2 = [0u8, 0, 0, 24, 0, 0, 0, 100];
        let leaf_bno = leaf_block(
            &ctx,
            AllocBtreeKind::Bnobt,
            500,
            &[e1.to_vec(), e2.to_vec()],
        );
        let leaf_cnt = leaf_block(
            &ctx,
            AllocBtreeKind::Cntbt,
            501,
            &[e2.to_vec(), e1.to_vec()],
        );
        let total: u64 = 103;

        let src = Src::for_blocks(&ctx, 700)
            .place(&ctx, 500, &leaf_bno)
            .place(&ctx, 501, &leaf_cnt)
            .place_agf(&ctx, &agf_sector(&ctx, total as u32, 500, 501));

        let space = collect_free_space(
            &mut Reader(&src.data),
            0,
            &ctx.sb,
            &ctx.geometry,
            AG,
            WalkMode::Strict,
        )
        .expect("collect free space");
        assert!(space.issues.is_empty());
        assert_eq!(space.cnt_total_blocks(), total);
        assert!(space.sums_match_agf());
        assert_eq!(
            space
                .bno_extents
                .iter()
                .map(|e| e.startblock)
                .collect::<Vec<_>>(),
            vec![13, 24]
        );

        let mismatching_agf = Src::for_blocks(&ctx, 700)
            .place(&ctx, 500, &leaf_bno)
            .place(&ctx, 501, &leaf_cnt)
            .place_agf(&ctx, &agf_sector(&ctx, total as u32 - 1, 500, 501));
        let salvage = collect_free_space(
            &mut Reader(&mismatching_agf.data),
            0,
            &ctx.sb,
            &ctx.geometry,
            AG,
            WalkMode::Salvage,
        )
        .expect("salvage sum mismatch");
        assert!(salvage.issues.contains(&AllocRecordIssue::CntSumMismatch {
            computed: total,
            agf_freeblks: total as u32 - 1
        }));
        assert!(
            collect_free_space(
                &mut Reader(&mismatching_agf.data),
                0,
                &ctx.sb,
                &ctx.geometry,
                AG,
                WalkMode::Strict
            )
            .is_err()
        );

        let out_of_range = vec![[0u8, 0, 0xFF, 0xFF, 0, 0, 0, 5].to_vec()];
        let bad_leaf = leaf_block(&ctx, AllocBtreeKind::Bnobt, 500, &out_of_range);
        let src_bad = Src::for_blocks(&ctx, 700)
            .place(&ctx, 500, &bad_leaf)
            .place_agf(&ctx, &agf_sector(&ctx, 5, 500, 501));
        let salvage_skip = collect_free_space(
            &mut Reader(&src_bad.data),
            0,
            &ctx.sb,
            &ctx.geometry,
            AG,
            WalkMode::Salvage,
        )
        .expect("salvage skips invalid extent");
        assert!(salvage_skip.bno_extents.is_empty());
        assert!(matches!(
            salvage_skip.issues.first(),
            Some(AllocRecordIssue::ExtentOutOfBounds { .. })
        ));
    }

    fn agi_sector(ctx: &Ctx, ino_root: u32, fino_root: u32) -> Vec<u8> {
        let mut b = vec![0u8; ctx.sb.sector_size as usize];
        put32(&mut b, 0, 0x5841_4749);
        put32(&mut b, 4, 1);
        put32(&mut b, 8, AG);
        put32(&mut b, 12, ctx.sb.ag_blocks);
        put32(&mut b, 16, 128);
        put32(&mut b, 20, ino_root);
        put32(&mut b, 24, 1);
        put32(&mut b, 28, 3);
        put32(&mut b, 32, 192);
        if ctx.sb.version5() {
            put32(&mut b, 328, fino_root);
            put32(&mut b, 332, 1);
        }
        b[296..312].copy_from_slice(&ctx.sb.uuid);
        buf_seal(&mut b, 312);
        b
    }

    fn buf_seal(buf: &mut [u8], crc_offset: usize) {
        buf[crc_offset..crc_offset + 4].copy_from_slice(&0u32.to_le_bytes());
        let crc = crate::util::crc32c::crc32c(buf);
        buf[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());
    }

    #[test]
    fn inode_collector_builds_queryable_map_from_tree() {
        let ctx = ctx_v5();
        let chunk_a = sparse_rec(128, 0, 64, 61, 0xFFFF_FFFF_FFFF_FFF8);
        let chunk_b = sparse_rec(192, 0, 64, 0, 0);
        let leaf = leaf_block(&ctx, AllocBtreeKind::Inobt, 600, &[chunk_a, chunk_b]);

        let fino_leaf = leaf_block(
            &ctx,
            AllocBtreeKind::Finobt,
            601,
            &[sparse_rec(128, 0, 64, 61, 0xFFFF_FFFF_FFFF_FFF8)],
        );
        let src = Src::for_blocks(&ctx, 700)
            .place(&ctx, 600, &leaf)
            .place(&ctx, 601, &fino_leaf)
            .place_agf(&ctx, &agf_sector(&ctx, 100, 500, 501))
            .place_agi(&ctx, &agi_sector(&ctx, 600, 601));

        let map = collect_inode_allocation(
            &mut Reader(&src.data),
            0,
            &ctx.sb,
            &ctx.geometry,
            AG,
            WalkMode::Strict,
        )
        .expect("collect inode allocation");

        assert!(map.finobt_scanned);
        assert_eq!(map.fino_records.len(), 1);
        assert_eq!(map.chunk_count(), 2);
        assert_eq!(map.slot_state(128), Some(SlotState::Allocated));
        assert_eq!(map.slot_state(131), Some(SlotState::Free));
        assert_eq!(map.slot_state(255), Some(SlotState::Allocated));
        assert_eq!(map.allocated_inodes(), 67);
        assert_eq!(map.free_inodes(), 61);
        assert_eq!(map.chunk_containing(200).unwrap().startino, 192);
        assert!(map.issues.is_empty());
    }

    #[test]
    fn legacy_layout_used_when_sparse_disabled() {
        let ctx = ctx_v4();
        let chunk = legacy_rec(128, 61, 0xFFFF_FFFF_FFFF_FFF8);
        let leaf = leaf_block(&ctx, AllocBtreeKind::Inobt, 600, &[chunk]);

        let fino_leaf = leaf_block(
            &ctx,
            AllocBtreeKind::Finobt,
            601,
            &[sparse_rec(128, 0, 64, 61, 0xFFFF_FFFF_FFFF_FFF8)],
        );
        let src = Src::for_blocks(&ctx, 700)
            .place(&ctx, 600, &leaf)
            .place(&ctx, 601, &fino_leaf)
            .place_agf(&ctx, &agf_sector(&ctx, 100, 500, 501))
            .place_agi(&ctx, &agi_sector(&ctx, 600, 601));

        let map = collect_inode_allocation(
            &mut Reader(&src.data),
            0,
            &ctx.sb,
            &ctx.geometry,
            AG,
            WalkMode::Strict,
        )
        .expect("v4 collector");
        assert_eq!(map.chunk_count(), 1);
        assert_eq!(map.slot_state(130), Some(SlotState::Allocated));
        assert_eq!(map.free_inodes(), 61);
        assert!(map.fino_records.is_empty());
        assert!(!map.finobt_scanned);
        assert!(map.issues.is_empty());
    }

    #[test]
    fn deterministic_garbage_never_panics_or_overflows() {
        let ctx = ctx_v5();
        let cap = ctx.geometry.ag_blocks() * ctx.geometry.inodes_per_block();
        let mut state = 0xDEAD_C0DE_1234_5678u64;
        let mut first_pass = Vec::new();
        for round in 0..96u32 {
            let mut raw = [0u8; 16];
            for byte in raw.iter_mut() {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *byte = (state >> 33) as u8;
            }
            if let Ok(rec) = decode_inobt_record(round % 2 == 0, &view_of(&raw)) {
                let outcome = validate_inobt(&rec, cap);
                if round < 48 {
                    first_pass.push(outcome.is_ok());
                }
            } else {
                let mut e = [0u8; 8];
                e.copy_from_slice(&raw[..8]);
                let _ = validate_extent(
                    &decode_free_extent(&view_of(&e)).unwrap(),
                    ctx.geometry.ag_blocks(),
                );
            }
        }
        assert_eq!(first_pass.len(), 48);
    }
}
