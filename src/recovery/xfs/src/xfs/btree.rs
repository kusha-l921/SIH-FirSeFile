use crate::error::{Error, Result};
use crate::io::ImageRead;
use crate::util::be::{be_u16_at, be_u32_at, be_u64_at};
use crate::util::crc32c::crc32c_with_zeroed_range;
use crate::xfs::superblock::{Geometry, Superblock};

const OFF_MAGIC: usize = 0;
const OFF_LEVEL: usize = 4;
const OFF_NUMRECS: usize = 6;
const OFF_LEFTSIB: usize = 8;
const OFF_RIGHTSIB: usize = 12;
const OFF_BLKNO: usize = 16;
const OFF_UUID: usize = 32;
const OFF_OWNER: usize = 48;
const OFF_CRC: usize = 52;

const HDR_BYTES_V4: usize = 16;
const HDR_BYTES_V5: usize = 56;

const MAX_TREE_LEVELS: u32 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocBtreeKind {
    Bnobt,
    Cntbt,
    Inobt,
    Finobt,
}

impl AllocBtreeKind {
    pub fn magic(self, v5: bool) -> u32 {
        match (self, v5) {
            (AllocBtreeKind::Bnobt, false) => 0x4142_5442,
            (AllocBtreeKind::Bnobt, true) => 0x4142_3342,
            (AllocBtreeKind::Cntbt, false) => 0x4142_5443,
            (AllocBtreeKind::Cntbt, true) => 0x4142_3343,
            (AllocBtreeKind::Inobt, false) => 0x4941_4254,
            (AllocBtreeKind::Inobt, true) => 0x4941_4233,
            (AllocBtreeKind::Finobt, false) => 0x4649_4254,
            (AllocBtreeKind::Finobt, true) => 0x4649_4233,
        }
    }

    pub fn key_bytes(self) -> usize {
        4
    }

    pub fn record_bytes(self) -> usize {
        match self {
            AllocBtreeKind::Bnobt | AllocBtreeKind::Cntbt => 8,
            AllocBtreeKind::Inobt | AllocBtreeKind::Finobt => 16,
        }
    }

    pub fn pointer_bytes(self) -> usize {
        4
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkMode {
    Strict,
    Salvage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordSource {
    pub ag_number: u32,
    pub block_number: u32,
    pub slot: usize,
}

#[derive(Debug)]
pub struct RecordView<'a> {
    pub source: RecordSource,
    pub raw: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtreeIssue {
    CrcMismatch {
        block: u32,
        stored: u32,
        computed: u32,
    },
    UuidMismatch {
        block: u32,
    },
    OwnerMismatch {
        block: u32,
        expected: u32,
        found: u32,
    },
    BlknoMismatch {
        block: u32,
        expected: u64,
        found: u64,
    },
    BadMagic {
        block: u32,
    },
    LevelMismatch {
        block: u32,
        expected_level: u16,
        found_level: u16,
    },
    NumrecsClamped {
        block: u32,
        declared: usize,
        limit: usize,
    },
    ChildOutOfRange {
        parent: u32,
        pointer: u32,
    },
    RepeatedBlock {
        block: u32,
    },
    SiblingInconsistent {
        block: u32,
    },
    DecodeFailed {
        block: u32,
        slot: usize,
    },
}

#[derive(Debug)]
pub struct BtreeWalk<R> {
    pub records: Vec<R>,
    pub issues: Vec<BtreeIssue>,
}

struct LoadedBlock {
    level: u16,
    numrecs: usize,
    leftsib: u32,
    rightsib: u32,
    buf: Vec<u8>,
}

struct Frame {
    level: u16,
    block_no: u32,
    buf: Vec<u8>,
    numrecs: usize,
    pointers: Vec<u32>,
    next: usize,
    prev_child: Option<(u32, u32)>,
}

fn malformed(reason: &'static str) -> Error {
    Error::Malformed {
        structure: "btree",
        reason,
    }
}

fn header_bytes(v5: bool) -> usize {
    if v5 { HDR_BYTES_V5 } else { HDR_BYTES_V4 }
}

fn max_records(kind: AllocBtreeKind, level: u16, v5: bool, block_bytes: usize) -> usize {
    let usable = block_bytes.saturating_sub(header_bytes(v5));
    if level == 0 {
        usable / kind.record_bytes()
    } else {
        usable / (kind.key_bytes() + kind.pointer_bytes())
    }
}

#[allow(clippy::too_many_arguments)]
fn load_block(
    reader: &mut dyn ImageRead,
    fs_base_offset: u64,
    sb: &Superblock,
    geometry: &Geometry,
    ag_number: u32,
    block_no: u32,
    kind: AllocBtreeKind,
    expected_level: u16,
    mode: WalkMode,
    is_root: bool,
    issues: &mut Vec<BtreeIssue>,
) -> Result<Option<LoadedBlock>> {
    let block_bytes = geometry.fs_block_bytes() as usize;
    if block_no == 0 || block_no as u64 >= geometry.ag_blocks() as u64 {
        return Err(malformed("block reference outside allocation group bounds"));
    }
    let byte_offset =
        fs_base_offset + geometry.ag_start_byte(ag_number)? + block_no as u64 * block_bytes as u64;
    let mut buf = vec![0u8; block_bytes];
    reader.read_at(byte_offset, &mut buf)?;

    if be_u32_at(&buf, OFF_MAGIC)? != kind.magic(sb.version5()) {
        issues.push(BtreeIssue::BadMagic { block: block_no });
        if mode == WalkMode::Strict || is_root {
            return Err(malformed("block magic does not match tree type"));
        }
        return Ok(None);
    }

    let level = be_u16_at(&buf, OFF_LEVEL)?;
    if level != expected_level {
        issues.push(BtreeIssue::LevelMismatch {
            block: block_no,
            expected_level,
            found_level: level,
        });
        if mode == WalkMode::Strict {
            return Err(malformed("block level disagrees with traversal position"));
        }
        return Ok(None);
    }

    let raw_numrecs = be_u16_at(&buf, OFF_NUMRECS)? as usize;
    let limit = max_records(kind, level, sb.version5(), block_bytes);
    let mut numrecs = raw_numrecs;
    if numrecs > limit {
        issues.push(BtreeIssue::NumrecsClamped {
            block: block_no,
            declared: raw_numrecs,
            limit,
        });
        if mode == WalkMode::Strict {
            return Err(malformed("record count exceeds block capacity"));
        }
        numrecs = limit;
    }

    let leftsib = be_u32_at(&buf, OFF_LEFTSIB)?;
    let rightsib = be_u32_at(&buf, OFF_RIGHTSIB)?;

    if sb.version5() {
        let uuid_ok = buf[OFF_UUID..OFF_UUID + 16] == sb.uuid;
        let owner_found = be_u32_at(&buf, OFF_OWNER)?;
        let owner_ok = owner_found == ag_number;
        let blkno_expected = (ag_number as u64 * geometry.ag_blocks() as u64 + block_no as u64)
            * (geometry.fs_block_bytes() as u64 / 512);
        let blkno_found = be_u64_at(&buf, OFF_BLKNO)?;
        let blkno_ok = blkno_found == blkno_expected;

        let stored = u32::from_le_bytes([
            buf[OFF_CRC],
            buf[OFF_CRC + 1],
            buf[OFF_CRC + 2],
            buf[OFF_CRC + 3],
        ]);
        let computed = crc32c_with_zeroed_range(&buf, OFF_CRC, 4);
        let crc_mismatch = stored != computed;

        if uuid_ok && owner_ok && blkno_ok && !crc_mismatch {
            return Ok(Some(LoadedBlock {
                level,
                numrecs,
                leftsib,
                rightsib,
                buf,
            }));
        }

        if !uuid_ok {
            issues.push(BtreeIssue::UuidMismatch { block: block_no });
        }
        if !owner_ok {
            issues.push(BtreeIssue::OwnerMismatch {
                block: block_no,
                expected: ag_number,
                found: owner_found,
            });
        }
        if !blkno_ok {
            issues.push(BtreeIssue::BlknoMismatch {
                block: block_no,
                expected: blkno_expected,
                found: blkno_found,
            });
        }
        if crc_mismatch {
            issues.push(BtreeIssue::CrcMismatch {
                block: block_no,
                stored,
                computed,
            });
        }
        if mode == WalkMode::Strict {
            return Err(malformed("v5 metadata validation failed"));
        }
        if !uuid_ok || !owner_ok || !blkno_ok {
            return Ok(None);
        }
    }

    Ok(Some(LoadedBlock {
        level,
        numrecs,
        leftsib,
        rightsib,
        buf,
    }))
}

struct PointerCtx<'a> {
    kind: AllocBtreeKind,
    v5: bool,
    block_bytes: usize,
    mode: WalkMode,
    issues: &'a mut Vec<BtreeIssue>,
    geometry: &'a Geometry,
    parent_block: u32,
}

fn collect_pointers(frame: &LoadedBlock, cx: &mut PointerCtx<'_>) -> Result<Vec<u32>> {
    let PointerCtx {
        kind,
        v5,
        block_bytes,
        mode,
        issues,
        geometry,
        parent_block,
    } = cx;
    let hdr = header_bytes(*v5);
    let maxrecs = max_records(*kind, 1, *v5, *block_bytes);
    let ptr_region = hdr.saturating_add(maxrecs * kind.key_bytes());
    let mut pointers = Vec::with_capacity(frame.numrecs);
    for i in 0..frame.numrecs {
        let off = ptr_region + i * kind.pointer_bytes();
        let ptr = be_u32_at(&frame.buf, off).map_err(|_| malformed("truncated pointer region"))?;
        let ptr: u32 = ptr;
        if ptr != 0 && (ptr as u64) < geometry.ag_blocks() as u64 {
            pointers.push(ptr);
        } else if *mode == WalkMode::Strict {
            return Err(malformed("child pointer outside allocation group bounds"));
        } else {
            issues.push(BtreeIssue::ChildOutOfRange {
                parent: *parent_block,
                pointer: ptr,
            });
        }
    }
    Ok(pointers)
}

#[allow(clippy::too_many_arguments)]
pub fn walk_alloc_btree<R>(
    reader: &mut dyn ImageRead,
    fs_base_offset: u64,
    sb: &Superblock,
    geometry: &Geometry,
    ag_number: u32,
    root_block: u32,
    root_level: u32,
    kind: AllocBtreeKind,
    mode: WalkMode,
    decode: &mut dyn FnMut(RecordView<'_>) -> Result<R>,
) -> Result<BtreeWalk<R>> {
    if root_block == 0 || root_block as u64 >= geometry.ag_blocks() as u64 {
        return Err(malformed("root block outside allocation group bounds"));
    }
    if root_level >= MAX_TREE_LEVELS {
        return Err(malformed("unreasonable tree depth"));
    }
    if root_level > u16::MAX as u32 {
        return Err(malformed("tree depth exceeds representable levels"));
    }

    let mut issues = Vec::new();
    let mut records = Vec::new();
    let mut visited = std::collections::HashSet::new();
    visited.insert(root_block);

    let root = match load_block(
        reader,
        fs_base_offset,
        sb,
        geometry,
        ag_number,
        root_block,
        kind,
        root_level as u16,
        mode,
        true,
        &mut issues,
    )? {
        Some(root) => root,
        None => return Ok(BtreeWalk { records, issues }),
    };

    let root_pointers = if root.level == 0 {
        Vec::new()
    } else {
        collect_pointers(
            &root,
            &mut PointerCtx {
                kind,
                v5: sb.version5(),
                block_bytes: geometry.fs_block_bytes() as usize,
                mode,
                issues: &mut issues,
                geometry,
                parent_block: root_block,
            },
        )?
    };

    let mut stack = vec![Frame {
        level: root.level,
        block_no: root_block,
        buf: root.buf,
        numrecs: root.numrecs,
        pointers: root_pointers,
        next: 0,
        prev_child: None,
    }];

    while let Some(frame) = stack.last_mut() {
        let exhausted = if frame.level == 0 {
            frame.next >= frame.numrecs
        } else {
            frame.next >= frame.pointers.len()
        };
        if exhausted {
            stack.pop();
            continue;
        }

        if frame.level == 0 {
            let hdr = header_bytes(sb.version5());
            let rec_bytes = kind.record_bytes();
            let start = hdr + frame.next * rec_bytes;
            let source = RecordSource {
                ag_number,
                block_number: frame.block_no,
                slot: frame.next,
            };
            let view = RecordView {
                source,
                raw: &frame.buf[start..start + rec_bytes],
            };
            match decode(view) {
                Ok(record) => records.push(record),
                Err(_) if mode == WalkMode::Salvage => {
                    issues.push(BtreeIssue::DecodeFailed {
                        block: frame.block_no,
                        slot: frame.next,
                    });
                }
                Err(e) => return Err(e),
            }
            stack.last_mut().unwrap().next += 1;
            continue;
        }

        let pointer = frame.pointers[frame.next];
        let parent_block = frame.block_no;
        let expected_child_level = frame.level - 1;
        let prev_child = frame.prev_child;

        if pointer == 0 || pointer as u64 >= geometry.ag_blocks() as u64 {
            if mode == WalkMode::Strict {
                return Err(malformed("child pointer outside allocation group bounds"));
            }
            issues.push(BtreeIssue::ChildOutOfRange {
                parent: parent_block,
                pointer,
            });
            frame.next += 1;
            continue;
        }
        if visited.contains(&pointer) {
            if mode == WalkMode::Strict {
                return Err(malformed("repeated block reference detected"));
            }
            issues.push(BtreeIssue::RepeatedBlock { block: pointer });
            frame.next += 1;
            continue;
        }

        let child = match load_block(
            reader,
            fs_base_offset,
            sb,
            geometry,
            ag_number,
            pointer,
            kind,
            expected_child_level,
            mode,
            false,
            &mut issues,
        ) {
            Ok(Some(child)) => child,
            Ok(None) => {
                frame.next += 1;
                continue;
            }
            Err(e) => return Err(e),
        };

        if let Some((prev_block, prev_rightsib)) = prev_child
            && (child.leftsib != prev_block || prev_rightsib != pointer)
        {
            if mode == WalkMode::Strict {
                return Err(malformed("sibling linkage inconsistent between children"));
            }
            issues.push(BtreeIssue::SiblingInconsistent { block: pointer });
        }
        visited.insert(pointer);

        let child_pointers = if child.level == 0 {
            Vec::new()
        } else {
            collect_pointers(
                &child,
                &mut PointerCtx {
                    kind,
                    v5: sb.version5(),
                    block_bytes: geometry.fs_block_bytes() as usize,
                    mode,
                    issues: &mut issues,
                    geometry,
                    parent_block: pointer,
                },
            )?
        };

        let new_prev = Some((pointer, child.rightsib));
        let frame = stack.last_mut().unwrap();
        frame.prev_child = new_prev;
        frame.next += 1;

        stack.push(Frame {
            level: expected_child_level,
            block_no: pointer,
            buf: child.buf,
            numrecs: child.numrecs,
            pointers: child_pointers,
            next: 0,
            prev_child: None,
        });
    }

    Ok(BtreeWalk { records, issues })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocRecord {
    pub startblock: u32,
    pub blockcount: u32,
    pub source: RecordSource,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xfs::superblock::testing::{golden_v4, golden_v5};

    const BS: usize = 4096;
    const NULLAGB: u32 = u32::MAX;

    struct Ctx {
        sb: Superblock,
        geometry: Geometry,
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
        fn for_blocks(ctx: &Ctx, ag: u32, highest_block: u32) -> Self {
            let end =
                ctx.geometry.ag_start_byte(ag).unwrap() + (highest_block as u64 + 2) * BS as u64;
            Self {
                data: vec![0u8; end as usize],
            }
        }

        fn place(mut self, ctx: &Ctx, ag: u32, block: u32, bytes: &[u8]) -> Self {
            let offset =
                (ctx.geometry.ag_start_byte(ag).unwrap() + block as u64 * BS as u64) as usize;
            self.data[offset..offset + bytes.len()].copy_from_slice(bytes);
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

    fn put64(dst: &mut [u8], off: usize, v: u64) {
        dst[off..off + 8].copy_from_slice(&v.to_be_bytes());
    }

    fn seal(buf: &mut [u8]) {
        buf[OFF_CRC..OFF_CRC + 4].copy_from_slice(&0u32.to_le_bytes());
        let crc = crate::util::crc32c::crc32c(buf);
        buf[OFF_CRC..OFF_CRC + 4].copy_from_slice(&crc.to_le_bytes());
    }

    fn leaf_block(
        ctx: &Ctx,
        kind: AllocBtreeKind,
        at_block: u32,
        leftsib: u32,
        rightsib: u32,
        records: &[(u32, u32)],
    ) -> Vec<u8> {
        let mut b = vec![0u8; BS];
        put32(&mut b, OFF_MAGIC, kind.magic(ctx.sb.version5()));
        put16(&mut b, OFF_LEVEL, 0);
        put16(&mut b, OFF_NUMRECS, records.len() as u16);
        put32(&mut b, OFF_LEFTSIB, leftsib);
        put32(&mut b, OFF_RIGHTSIB, rightsib);
        if ctx.sb.version5() {
            b[OFF_UUID..OFF_UUID + 16].copy_from_slice(&ctx.sb.uuid);
            put32(&mut b, OFF_OWNER, 0);
            let daddr = at_block as u64 * (BS as u64 / 512);
            put64(&mut b, OFF_BLKNO, daddr);
        }
        let hdr = header_bytes(ctx.sb.version5());
        for (i, (start, count)) in records.iter().enumerate() {
            put32(&mut b, hdr + i * 8, *start);
            put32(&mut b, hdr + i * 8 + 4, *count);
        }
        if ctx.sb.version5() {
            seal(&mut b);
        }
        b
    }

    fn internal_block(
        ctx: &Ctx,
        kind: AllocBtreeKind,
        at_block: u32,
        level: u16,
        children: &[(u32, u32)],
    ) -> Vec<u8> {
        let mut b = vec![0u8; BS];
        put32(&mut b, OFF_MAGIC, kind.magic(ctx.sb.version5()));
        put16(&mut b, OFF_LEVEL, level);
        put16(&mut b, OFF_NUMRECS, children.len() as u16);
        put32(&mut b, OFF_LEFTSIB, NULLAGB);
        put32(&mut b, OFF_RIGHTSIB, NULLAGB);
        if ctx.sb.version5() {
            b[OFF_UUID..OFF_UUID + 16].copy_from_slice(&ctx.sb.uuid);
            put32(&mut b, OFF_OWNER, 0);
            let daddr = at_block as u64 * (BS as u64 / 512);
            put64(&mut b, OFF_BLKNO, daddr);
        }
        let hdr = header_bytes(ctx.sb.version5());
        let maxrecs = max_records(kind, level, ctx.sb.version5(), BS);
        for (i, (key, ptr)) in children.iter().enumerate() {
            put32(&mut b, hdr + i * 4, *key);
            put32(&mut b, hdr + maxrecs * 4 + i * 4, *ptr);
        }
        if ctx.sb.version5() {
            seal(&mut b);
        }
        b
    }

    fn collect_alloc(view: RecordView<'_>) -> Result<AllocRecord> {
        Ok(AllocRecord {
            startblock: be_u32_at(view.raw, 0)?,
            blockcount: be_u32_at(view.raw, 4)?,
            source: view.source,
        })
    }

    fn walk<R>(
        ctx: &Ctx,
        src: &Src,
        root: u32,
        level: u32,
        kind: AllocBtreeKind,
        mode: WalkMode,
        decode: &mut dyn FnMut(RecordView<'_>) -> Result<R>,
    ) -> Result<BtreeWalk<R>> {
        walk_alloc_btree(
            &mut Reader(&src.data),
            0,
            &ctx.sb,
            &ctx.geometry,
            0,
            root,
            level,
            kind,
            mode,
            decode,
        )
    }

    #[test]
    fn single_leaf_root_yields_ordered_records_with_sources() {
        let ctx = ctx_v5();
        let leaf = leaf_block(
            &ctx,
            AllocBtreeKind::Bnobt,
            500,
            NULLAGB,
            NULLAGB,
            &[(10, 5), (20, 7), (30, 2)],
        );
        let src = Src::for_blocks(&ctx, 0, 500).place(&ctx, 0, 500, &leaf);

        for mode in [WalkMode::Strict, WalkMode::Salvage] {
            let out = walk(
                &ctx,
                &src,
                500,
                0,
                AllocBtreeKind::Bnobt,
                mode,
                &mut collect_alloc,
            )
            .expect("walk");
            assert!(out.issues.is_empty());
            assert_eq!(out.records.len(), 3);
            assert_eq!(
                out.records[0],
                AllocRecord {
                    startblock: 10,
                    blockcount: 5,
                    source: RecordSource {
                        ag_number: 0,
                        block_number: 500,
                        slot: 0
                    }
                }
            );
            assert_eq!(out.records[2].source.slot, 2);
            assert_eq!(out.records[2].startblock, 30);
        }
    }

    #[test]
    fn two_level_tree_traverses_children_in_order() {
        let ctx = ctx_v5();
        let c1 = leaf_block(
            &ctx,
            AllocBtreeKind::Bnobt,
            500,
            NULLAGB,
            501,
            &[(100, 1), (110, 2)],
        );
        let c2 = leaf_block(&ctx, AllocBtreeKind::Bnobt, 501, 500, NULLAGB, &[(200, 3)]);
        let root = internal_block(
            &ctx,
            AllocBtreeKind::Bnobt,
            900,
            1,
            &[(100, 500), (200, 501)],
        );
        let src = Src::for_blocks(&ctx, 0, 901)
            .place(&ctx, 0, 500, &c1)
            .place(&ctx, 0, 501, &c2)
            .place(&ctx, 0, 900, &root);

        let out = walk(
            &ctx,
            &src,
            900,
            1,
            AllocBtreeKind::Bnobt,
            WalkMode::Strict,
            &mut collect_alloc,
        )
        .expect("walk");
        assert!(out.issues.is_empty());
        let starts: Vec<u32> = out.records.iter().map(|r| r.startblock).collect();
        assert_eq!(starts, vec![100, 110, 200]);
        assert_eq!(out.records[0].source.block_number, 500);
        assert_eq!(out.records[2].source.block_number, 501);
        assert_eq!(out.records[2].source.ag_number, 0);
    }

    #[test]
    fn three_leaves_under_one_root_preserve_full_sibling_chain() {
        let ctx = ctx_v5();
        let l0 = leaf_block(&ctx, AllocBtreeKind::Cntbt, 600, NULLAGB, 601, &[(1, 1)]);
        let l1 = leaf_block(&ctx, AllocBtreeKind::Cntbt, 601, 600, 602, &[(2, 1)]);
        let l2 = leaf_block(&ctx, AllocBtreeKind::Cntbt, 602, 601, NULLAGB, &[(3, 1)]);
        let root = internal_block(
            &ctx,
            AllocBtreeKind::Cntbt,
            950,
            1,
            &[(1, 600), (2, 601), (3, 602)],
        );
        let src = Src::for_blocks(&ctx, 0, 951)
            .place(&ctx, 0, 600, &l0)
            .place(&ctx, 0, 601, &l1)
            .place(&ctx, 0, 602, &l2)
            .place(&ctx, 0, 950, &root);
        let out = walk(
            &ctx,
            &src,
            950,
            1,
            AllocBtreeKind::Cntbt,
            WalkMode::Strict,
            &mut collect_alloc,
        )
        .expect("walk");
        assert!(out.issues.is_empty());
        assert_eq!(out.records.len(), 3);
        assert_eq!(out.records[2].startblock, 3);
    }

    #[test]
    fn v4_trees_walk_without_crc_fields_and_inobt_records_are_16_bytes() {
        let ctx = ctx_v4();
        let mut b = vec![0u8; BS];
        put32(&mut b, OFF_MAGIC, AllocBtreeKind::Inobt.magic(false));
        put16(&mut b, OFF_LEVEL, 0);
        put16(&mut b, OFF_NUMRECS, 2);
        put32(&mut b, OFF_LEFTSIB, NULLAGB);
        put32(&mut b, OFF_RIGHTSIB, NULLAGB);
        for i in 0..2u32 {
            for byte in 0..16usize {
                b[HDR_BYTES_V4 + i as usize * 16 + byte] = (i * 16 + byte as u32) as u8;
            }
        }
        let src = Src::for_blocks(&ctx, 0, 700).place(&ctx, 0, 700, &b);
        let mut sizes = Vec::new();
        let out = walk(
            &ctx,
            &src,
            700,
            0,
            AllocBtreeKind::Inobt,
            WalkMode::Strict,
            &mut |view| {
                sizes.push(view.raw.len());
                Ok(())
            },
        )
        .expect("walk");
        assert!(out.issues.is_empty());
        assert_eq!(sizes, vec![16, 16]);
    }

    #[test]
    fn root_bad_magic_is_hard_error_in_both_modes() {
        let ctx = ctx_v5();
        let mut bad = leaf_block(&ctx, AllocBtreeKind::Bnobt, 500, 0, 0, &[]);
        bad[..4].copy_from_slice(&[1, 2, 3, 4]);
        let src = Src::for_blocks(&ctx, 0, 500).place(&ctx, 0, 500, &bad);
        for mode in [WalkMode::Strict, WalkMode::Salvage] {
            assert!(
                walk(
                    &ctx,
                    &src,
                    500,
                    0,
                    AllocBtreeKind::Bnobt,
                    mode,
                    &mut collect_alloc
                )
                .is_err()
            );
        }
    }

    #[test]
    fn child_bad_magic_pruned_in_salvage_but_survivor_branch_survives() {
        let ctx = ctx_v5();
        let good = leaf_block(&ctx, AllocBtreeKind::Bnobt, 501, 500, NULLAGB, &[(77, 1)]);
        let mut corrupt = leaf_block(&ctx, AllocBtreeKind::Bnobt, 500, NULLAGB, 501, &[(66, 1)]);
        corrupt[..4].copy_from_slice(&[9, 9, 9, 9]);
        let root = internal_block(&ctx, AllocBtreeKind::Bnobt, 900, 1, &[(66, 500), (77, 501)]);
        let src = Src::for_blocks(&ctx, 0, 901)
            .place(&ctx, 0, 500, &corrupt)
            .place(&ctx, 0, 501, &good)
            .place(&ctx, 0, 900, &root);

        assert!(
            walk(
                &ctx,
                &src,
                900,
                1,
                AllocBtreeKind::Bnobt,
                WalkMode::Strict,
                &mut collect_alloc
            )
            .is_err()
        );

        let salvage = walk(
            &ctx,
            &src,
            900,
            1,
            AllocBtreeKind::Bnobt,
            WalkMode::Salvage,
            &mut collect_alloc,
        )
        .expect("salvage");
        assert_eq!(
            salvage
                .records
                .iter()
                .map(|r| r.startblock)
                .collect::<Vec<_>>(),
            vec![77]
        );
        assert!(
            salvage
                .issues
                .contains(&BtreeIssue::BadMagic { block: 500 })
        );
    }

    #[test]
    fn crc_mismatch_strict_fails_salvage_keeps_records() {
        let ctx = ctx_v5();
        let mut leaf = leaf_block(
            &ctx,
            AllocBtreeKind::Bnobt,
            500,
            NULLAGB,
            NULLAGB,
            &[(42, 9)],
        );
        leaf[3000] ^= 0xFF;
        let src = Src::for_blocks(&ctx, 0, 500).place(&ctx, 0, 500, &leaf);

        assert!(
            walk(
                &ctx,
                &src,
                500,
                0,
                AllocBtreeKind::Bnobt,
                WalkMode::Strict,
                &mut collect_alloc
            )
            .is_err()
        );

        let salvage = walk(
            &ctx,
            &src,
            500,
            0,
            AllocBtreeKind::Bnobt,
            WalkMode::Salvage,
            &mut collect_alloc,
        )
        .expect("salvage");
        assert_eq!(salvage.records.len(), 1);
        assert!(matches!(
            salvage.issues.first(),
            Some(BtreeIssue::CrcMismatch { .. })
        ));
    }

    #[test]
    fn invalid_root_and_child_pointers_rejected() {
        let ctx = ctx_v5();
        assert!(
            walk(
                &ctx,
                &Src::for_blocks(&ctx, 0, 10),
                99_999,
                0,
                AllocBtreeKind::Bnobt,
                WalkMode::Strict,
                &mut collect_alloc
            )
            .is_err()
        );

        let root = internal_block(&ctx, AllocBtreeKind::Bnobt, 900, 1, &[(1, 99_999)]);
        let src = Src::for_blocks(&ctx, 0, 901).place(&ctx, 0, 900, &root);
        assert!(
            walk(
                &ctx,
                &src,
                900,
                1,
                AllocBtreeKind::Bnobt,
                WalkMode::Strict,
                &mut collect_alloc
            )
            .is_err()
        );
        let salvage = walk(
            &ctx,
            &src,
            900,
            1,
            AllocBtreeKind::Bnobt,
            WalkMode::Salvage,
            &mut collect_alloc,
        )
        .expect("salvage");
        assert!(salvage.records.is_empty());
        assert!(salvage.issues.contains(&BtreeIssue::ChildOutOfRange {
            parent: 900,
            pointer: 99_999
        }));
    }

    #[test]
    fn repeated_child_pointer_detected() {
        let ctx = ctx_v5();
        let dup = leaf_block(
            &ctx,
            AllocBtreeKind::Bnobt,
            500,
            NULLAGB,
            NULLAGB,
            &[(5, 5)],
        );
        let root = internal_block(&ctx, AllocBtreeKind::Bnobt, 900, 1, &[(5, 500), (5, 500)]);
        let src = Src::for_blocks(&ctx, 0, 901)
            .place(&ctx, 0, 500, &dup)
            .place(&ctx, 0, 900, &root);

        assert!(
            walk(
                &ctx,
                &src,
                900,
                1,
                AllocBtreeKind::Bnobt,
                WalkMode::Strict,
                &mut collect_alloc
            )
            .is_err()
        );
        let salvage = walk(
            &ctx,
            &src,
            900,
            1,
            AllocBtreeKind::Bnobt,
            WalkMode::Salvage,
            &mut collect_alloc,
        )
        .expect("salvage");
        assert_eq!(salvage.records.len(), 1);
        assert!(
            salvage
                .issues
                .contains(&BtreeIssue::RepeatedBlock { block: 500 })
        );
    }

    #[test]
    fn sibling_cycle_between_children_flagged_by_adjacency_check() {
        let ctx = ctx_v5();
        let c1 = leaf_block(&ctx, AllocBtreeKind::Bnobt, 500, NULLAGB, 500, &[(1, 1)]);
        let c2 = leaf_block(&ctx, AllocBtreeKind::Bnobt, 501, 501, NULLAGB, &[(2, 1)]);
        let root = internal_block(&ctx, AllocBtreeKind::Bnobt, 900, 1, &[(1, 500), (2, 501)]);
        let src = Src::for_blocks(&ctx, 0, 901)
            .place(&ctx, 0, 500, &c1)
            .place(&ctx, 0, 501, &c2)
            .place(&ctx, 0, 900, &root);

        assert!(
            walk(
                &ctx,
                &src,
                900,
                1,
                AllocBtreeKind::Bnobt,
                WalkMode::Strict,
                &mut collect_alloc
            )
            .is_err()
        );
        let salvage = walk(
            &ctx,
            &src,
            900,
            1,
            AllocBtreeKind::Bnobt,
            WalkMode::Salvage,
            &mut collect_alloc,
        )
        .expect("salvage");
        assert!(
            salvage
                .issues
                .contains(&BtreeIssue::SiblingInconsistent { block: 501 })
        );
        assert_eq!(salvage.records.len(), 2);
    }

    #[test]
    fn excessive_depth_and_impossible_numrecs_rejected() {
        let ctx = ctx_v5();
        assert!(
            walk(
                &ctx,
                &Src::for_blocks(&ctx, 0, 10),
                500,
                65,
                AllocBtreeKind::Bnobt,
                WalkMode::Strict,
                &mut collect_alloc
            )
            .is_err()
        );

        let mut huge = leaf_block(&ctx, AllocBtreeKind::Bnobt, 500, NULLAGB, NULLAGB, &[]);
        put16(&mut huge, OFF_NUMRECS, u16::MAX);
        seal(&mut huge);
        let src = Src::for_blocks(&ctx, 0, 500).place(&ctx, 0, 500, &huge);
        assert!(
            walk(
                &ctx,
                &src,
                500,
                0,
                AllocBtreeKind::Bnobt,
                WalkMode::Strict,
                &mut collect_alloc
            )
            .is_err()
        );
        let salvage = walk(
            &ctx,
            &src,
            500,
            0,
            AllocBtreeKind::Bnobt,
            WalkMode::Salvage,
            &mut |view: RecordView<'_>| {
                let _ = view.raw.len();
                Ok(())
            },
        )
        .expect("salvage clamp");
        assert!(salvage.issues.iter().any(|issue| matches!(
            issue,
            BtreeIssue::NumrecsClamped {
                declared: 65535,
                ..
            }
        )));
    }

    #[test]
    fn v5_identity_fields_validated_per_block() {
        let ctx = ctx_v5();

        let mut wrong_owner = leaf_block(
            &ctx,
            AllocBtreeKind::Bnobt,
            500,
            NULLAGB,
            NULLAGB,
            &[(1, 1)],
        );
        put32(&mut wrong_owner, OFF_OWNER, 9);
        seal(&mut wrong_owner);
        let src = Src::for_blocks(&ctx, 0, 500).place(&ctx, 0, 500, &wrong_owner);
        assert!(
            walk(
                &ctx,
                &src,
                500,
                0,
                AllocBtreeKind::Bnobt,
                WalkMode::Strict,
                &mut collect_alloc
            )
            .is_err()
        );
        let salvage = walk(
            &ctx,
            &src,
            500,
            0,
            AllocBtreeKind::Bnobt,
            WalkMode::Salvage,
            &mut collect_alloc,
        )
        .expect("salvage owner");
        assert!(salvage.issues.contains(&BtreeIssue::OwnerMismatch {
            block: 500,
            expected: 0,
            found: 9,
        }));

        let mut wrong_uuid = leaf_block(
            &ctx,
            AllocBtreeKind::Bnobt,
            500,
            NULLAGB,
            NULLAGB,
            &[(1, 1)],
        );
        wrong_uuid[OFF_UUID] ^= 0xFF;
        seal(&mut wrong_uuid);
        let src = Src::for_blocks(&ctx, 0, 500).place(&ctx, 0, 500, &wrong_uuid);
        assert!(
            walk(
                &ctx,
                &src,
                500,
                0,
                AllocBtreeKind::Bnobt,
                WalkMode::Strict,
                &mut collect_alloc
            )
            .is_err()
        );

        let mut wrong_blkno = leaf_block(
            &ctx,
            AllocBtreeKind::Bnobt,
            500,
            NULLAGB,
            NULLAGB,
            &[(1, 1)],
        );
        put64(&mut wrong_blkno, OFF_BLKNO, 999_999 * 8);
        seal(&mut wrong_blkno);
        let src = Src::for_blocks(&ctx, 0, 500).place(&ctx, 0, 500, &wrong_blkno);
        assert!(
            walk(
                &ctx,
                &src,
                500,
                0,
                AllocBtreeKind::Bnobt,
                WalkMode::Strict,
                &mut collect_alloc
            )
            .is_err()
        );
    }

    #[test]
    fn child_level_mismatch_strict_fails_salvage_prunes() {
        let ctx = ctx_v5();
        let mut weird = leaf_block(
            &ctx,
            AllocBtreeKind::Bnobt,
            500,
            NULLAGB,
            NULLAGB,
            &[(1, 1)],
        );
        put16(&mut weird, OFF_LEVEL, 5);
        seal(&mut weird);
        let root = internal_block(&ctx, AllocBtreeKind::Bnobt, 900, 1, &[(1, 500)]);
        let src = Src::for_blocks(&ctx, 0, 901)
            .place(&ctx, 0, 500, &weird)
            .place(&ctx, 0, 900, &root);

        assert!(
            walk(
                &ctx,
                &src,
                900,
                1,
                AllocBtreeKind::Bnobt,
                WalkMode::Strict,
                &mut collect_alloc
            )
            .is_err()
        );
        let salvage = walk(
            &ctx,
            &src,
            900,
            1,
            AllocBtreeKind::Bnobt,
            WalkMode::Salvage,
            &mut collect_alloc,
        )
        .expect("salvage");
        assert!(matches!(
            salvage.issues.first(),
            Some(BtreeIssue::LevelMismatch { .. })
        ));
        assert!(salvage.records.is_empty());
    }

    #[test]
    fn decode_failure_strict_propagates_salvage_records_issue() {
        let ctx = ctx_v5();
        let leaf = leaf_block(
            &ctx,
            AllocBtreeKind::Bnobt,
            500,
            NULLAGB,
            NULLAGB,
            &[(1, 1), (2, 1), (3, 1)],
        );
        let src = Src::for_blocks(&ctx, 0, 500).place(&ctx, 0, 500, &leaf);

        let mut picky = |view: RecordView<'_>| {
            if view.source.slot == 1 {
                Err(Error::Unsupported {
                    structure: "poison record",
                })
            } else {
                Ok(be_u32_at(view.raw, 0)?)
            }
        };
        assert!(
            walk(
                &ctx,
                &src,
                500,
                0,
                AllocBtreeKind::Bnobt,
                WalkMode::Strict,
                &mut picky
            )
            .is_err()
        );

        let mut salvager = |view: RecordView<'_>| {
            if view.source.slot == 1 {
                Err(Error::Unsupported {
                    structure: "poison record",
                })
            } else {
                Ok(be_u32_at(view.raw, 0)?)
            }
        };
        let salvage = walk(
            &ctx,
            &src,
            500,
            0,
            AllocBtreeKind::Bnobt,
            WalkMode::Salvage,
            &mut salvager,
        )
        .expect("salvage");
        assert_eq!(salvage.records, vec![1, 3]);
        assert!(salvage.issues.contains(&BtreeIssue::DecodeFailed {
            block: 500,
            slot: 1
        }));
    }

    #[test]
    fn truncated_tree_read_reports_out_of_bounds_without_panic() {
        let ctx = ctx_v5();
        let leaf = leaf_block(
            &ctx,
            AllocBtreeKind::Bnobt,
            500,
            NULLAGB,
            NULLAGB,
            &[(1, 1)],
        );
        let short = &leaf[..100];
        assert!(matches!(
            walk_alloc_btree(
                &mut Reader(short),
                0,
                &ctx.sb,
                &ctx.geometry,
                0,
                500,
                0,
                AllocBtreeKind::Bnobt,
                WalkMode::Salvage,
                &mut collect_alloc,
            ),
            Err(Error::OutOfBounds { .. })
        ));
    }

    #[test]
    fn never_panics_on_deterministic_garbage_blocks() {
        let ctx = ctx_v5();
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..96 {
            let mut block = vec![0u8; BS];
            for byte in block.iter_mut() {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *byte = (state >> 33) as u8;
            }
            let _ = walk_alloc_btree(
                &mut Reader(&block),
                0,
                &ctx.sb,
                &ctx.geometry,
                0,
                500,
                0,
                AllocBtreeKind::Bnobt,
                WalkMode::Salvage,
                &mut collect_alloc,
            );
        }
    }
}
