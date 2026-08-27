use crate::error::{Error, Result};
use crate::io::ImageRead;
use crate::xfs::superblock::{Geometry, Superblock};
use crate::xfs::{INODES_PER_CHUNK, InobtRecord, InodeAllocationMap, SlotState};

pub use crate::xfs::inode_addr::{
    InodeLocation, absolute_inode, ag_first_inode, inodes_per_ag_addressable, locate_inode,
};

pub const NULLAGINO: u32 = crate::xfs::inode_addr::NULLAGINO;
const RAW_SCAN_MAGIC: u16 = crate::xfs::inode_addr::INODE_MAGIC;

#[derive(Debug, Clone)]
pub struct DiscoveredInode {
    pub location: InodeLocation,
    pub state: SlotState,
}

#[derive(Debug, Clone, Default)]
pub struct DiscoveryOptions {
    pub include_holes: bool,
}

fn malformed(reason: &'static str) -> Error {
    Error::Malformed {
        structure: "inode scan",
        reason,
    }
}

pub fn discover_chunk_slots(
    sb: &Superblock,
    geometry: &Geometry,
    ag_number: u32,
    record: &InobtRecord,
    opts: &DiscoveryOptions,
) -> Result<Vec<DiscoveredInode>> {
    let mut out = Vec::with_capacity(INODES_PER_CHUNK as usize);
    for slot in 0..INODES_PER_CHUNK {
        let state = match record.slot_state(slot) {
            Some(state) => state,
            None => continue,
        };
        if state == SlotState::Hole && !opts.include_holes {
            continue;
        }
        let ino = absolute_inode(geometry, ag_number, record.startino + slot)?;
        let location = locate_inode(sb, geometry, ino).map_err(|e| {
            let _ = e;
            malformed("chunk slot resolves outside filesystem bounds")
        })?;
        out.push(DiscoveredInode { location, state });
    }
    Ok(out)
}

pub fn discover_inode_slots(
    map: &InodeAllocationMap,
    sb: &Superblock,
    geometry: &Geometry,
    opts: &DiscoveryOptions,
) -> Result<Vec<DiscoveredInode>> {
    let mut out = Vec::new();
    for record in map.iter_chunks() {
        out.extend(discover_chunk_slots(
            sb,
            geometry,
            map.ag_number,
            record,
            opts,
        )?);
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnlinkedHead {
    pub bucket: usize,
    pub ag_inode: u32,
    pub absolute_ino: Option<u64>,
    pub location: Option<InodeLocation>,
    pub geometrically_valid: bool,
}

pub fn collect_unlinked_heads(
    sb: &Superblock,
    geometry: &Geometry,
    ag_number: u32,
    buckets: &[u32; 64],
) -> Result<Vec<UnlinkedHead>> {
    let mut heads = Vec::with_capacity(buckets.len());
    for (bucket, &value) in buckets.iter().enumerate() {
        if value == 0 || value == NULLAGINO {
            continue;
        }
        let abs = absolute_inode(geometry, ag_number, value);
        let (absolute_ino, location, valid) = match abs {
            Ok(ino) => match locate_inode(sb, geometry, ino) {
                Ok(loc) => (Some(ino), Some(loc), true),
                Err(_) => (Some(ino), None, false),
            },
            Err(_) => (None, None, false),
        };
        heads.push(UnlinkedHead {
            bucket,
            ag_inode: value,
            absolute_ino,
            location,
            geometrically_valid: valid,
        });
    }
    Ok(heads)
}

pub fn collect_unlinked_heads_from_image(
    reader: &mut dyn ImageRead,
    fs_base_offset: u64,
    sb: &Superblock,
    geometry: &Geometry,
    ag_number: u32,
) -> Result<Vec<UnlinkedHead>> {
    let agi = crate::xfs::ag::parse_agi(reader, fs_base_offset, sb, geometry, ag_number)?;
    collect_unlinked_heads(sb, geometry, ag_number, &agi.unlinked_buckets)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawScanCandidate {
    pub location: InodeLocation,
}

pub fn experimental_raw_scan(
    reader: &mut dyn ImageRead,
    fs_base_offset: u64,
    sb: &Superblock,
    geometry: &Geometry,
    ag_number: u32,
) -> Result<Vec<RawScanCandidate>> {
    let per_ag = inodes_per_ag_addressable(geometry)?;
    let chunk_stride = INODES_PER_CHUNK as u64;
    let mut candidates = Vec::new();
    let mut probe = [0u8; 2];
    let mut startino: u64 = 0;
    while startino < per_ag {
        let Some(ino) = ag_first_inode(geometry, ag_number)
            .ok()
            .and_then(|first| first.checked_add(startino))
        else {
            break;
        };
        if let Ok(location) = locate_inode(sb, geometry, ino) {
            let read_ok = reader.read_at(fs_base_offset + location.byte_offset, &mut probe);
            if read_ok.is_ok() && u16::from_be_bytes(probe) == RAW_SCAN_MAGIC {
                candidates.push(RawScanCandidate { location });
            }
        }
        match startino.checked_add(chunk_stride) {
            Some(next) => startino = next,
            None => break,
        }
    }
    Ok(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xfs::superblock::testing::{golden_v4, golden_v5, put32};
    use crate::xfs::{InobtRecord, InodeAllocationMap};

    fn ctx_from(golden: &[u8]) -> (Superblock, Geometry) {
        Superblock::parse_bytes(golden).expect("golden sb")
    }

    fn ctx_v5() -> (Superblock, Geometry) {
        ctx_from(&golden_v5())
    }

    fn rec(startino: u32, holemask: u16, count: u8, freecount: u8, mask: u64) -> InobtRecord {
        InobtRecord {
            startino,
            holemask,
            inode_count: count,
            freecount: freecount as u32,
            free_mask: mask,
            source: crate::xfs::btree::RecordSource {
                ag_number: 0,
                block_number: 0,
                slot: 0,
            },
        }
    }

    #[test]
    fn discovery_yields_valid_slots_with_states_and_skips_holes() {
        let (sb, geo) = ctx_v5();
        let sparse = rec(128, 0xC000, 56, 2, 0x0000_0000_0000_000C);
        let map = InodeAllocationMap::from_chunks(0, 16384 * 8, BTreeMap::from([(128u32, sparse)]));

        let found = discover_inode_slots(&map, &sb, &geo, &DiscoveryOptions::default()).unwrap();
        assert_eq!(found.len(), 56);
        assert!(found.iter().all(|d| d.state != SlotState::Hole));
        assert_eq!(found[0].location.ino, 128);
        assert_eq!(found[0].location.slot, 0);
        assert_eq!(found[2].state, SlotState::Free);

        let with_holes = discover_inode_slots(
            &map,
            &sb,
            &geo,
            &DiscoveryOptions {
                include_holes: true,
            },
        )
        .unwrap();
        assert_eq!(with_holes.len(), 64);
        let holes: Vec<_> = with_holes
            .iter()
            .filter(|d| d.state == SlotState::Hole)
            .collect();
        assert_eq!(holes.len(), 8);
        assert_eq!(holes[0].location.ino, 128 + 56);
    }

    use std::collections::BTreeMap;

    struct Src {
        data: Vec<u8>,
    }

    impl Src {
        fn new(bytes: usize) -> Self {
            Self {
                data: vec![0u8; bytes],
            }
        }

        fn write_at(mut self, off: u64, bytes: &[u8]) -> Self {
            let off = off as usize;
            self.data[off..off + bytes.len()].copy_from_slice(bytes);
            self
        }
    }

    struct Reader<'a>(&'a [u8]);

    impl ImageRead for Reader<'_> {
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
            crate::MemImage::new(self.0).read_at(offset, buf)
        }
    }

    #[test]
    fn raw_scan_finds_aligned_magic_only_and_never_leaves_bounds() {
        let (sb, geo) = ctx_from(&golden_v5());
        let per_ag_bytes = geo.ag_blocks() as u64 * 4096;
        let mut src = Src::new((per_ag_bytes * 4) as usize);

        let first_chunk_off = locate_inode(&sb, &geo, 128).unwrap().byte_offset;
        src = src.write_at(first_chunk_off, &[0x49, 0x4E]);

        let second_chunk_off = locate_inode(&sb, &geo, 192).unwrap().byte_offset;
        src = src.write_at(second_chunk_off, &[0x49, 0x4E]);

        let mid_fp_off = locate_inode(&sb, &geo, 192 + 5).unwrap().byte_offset;
        src = src.write_at(mid_fp_off, &[0x49, 0x4E]);

        let candidates = experimental_raw_scan(&mut Reader(&src.data), 0, &sb, &geo, 0).unwrap();
        let inos: Vec<u64> = candidates.iter().map(|c| c.location.ino).collect();
        assert_eq!(inos, vec![128, 192]);
        assert!(!inos.contains(&(192 + 5)));

        let tiny = Src::new(4096);
        let limited = experimental_raw_scan(&mut Reader(&tiny.data), 0, &sb, &geo, 0).unwrap();
        let _ = limited;

        let authoritative_map = InodeAllocationMap::from_chunks(0, 16384 * 8, BTreeMap::new());
        let authoritative =
            discover_inode_slots(&authoritative_map, &sb, &geo, &DiscoveryOptions::default())
                .unwrap();
        assert!(authoritative.is_empty());
    }

    #[test]
    fn unlinked_heads_classify_nulls_invalid_and_valid() {
        let (sb, geo) = ctx_v5();
        let mut buckets = [0u32; 64];
        buckets[3] = NULLAGINO;
        buckets[7] = 137;
        buckets[11] = 500_000_000;
        let heads = collect_unlinked_heads(&sb, &geo, 1, &buckets).unwrap();
        assert_eq!(heads.len(), 2);

        let valid = heads.iter().find(|h| h.bucket == 7).unwrap();
        assert!(valid.geometrically_valid);
        assert_eq!(valid.absolute_ino.unwrap(), (1u64 << 17) + 137);
        assert_eq!(valid.location.as_ref().unwrap().ag_number, 1);

        let invalid = heads.iter().find(|h| h.bucket == 11).unwrap();
        assert!(!invalid.geometrically_valid);
        assert!(invalid.location.is_none());
    }

    #[test]
    fn unlinked_heads_from_image_reads_agi_buckets() {
        let (sb, geo) = ctx_from(&golden_v4());
        let mut b = vec![0u8; sb.sector_size as usize];
        put32(&mut b, 0, 0x5841_4749);
        put32(&mut b, 4, 1);
        put32(&mut b, 8, 0);
        put32(&mut b, 12, geo.ag_blocks());
        put32(&mut b, 16, 64);
        put32(&mut b, 20, 3);
        put32(&mut b, 24, 1);
        put32(&mut b, 40 + 9 * 4, 200);
        let mut src = Src::new(8192);
        let off = geo.ag_start_byte(0).unwrap() + 2 * 512;
        src.data[off as usize..off as usize + b.len()].copy_from_slice(&b);

        let heads =
            collect_unlinked_heads_from_image(&mut Reader(&src.data), 0, &sb, &geo, 0).unwrap();
        assert_eq!(heads.len(), 1);
        assert_eq!(heads[0].bucket, 9);
        assert_eq!(heads[0].ag_inode, 200);
        assert!(heads[0].geometrically_valid);
    }

    #[test]
    fn discovery_matches_full_synthetic_two_chunk_map() {
        let (sb, geo) = ctx_v5();
        let full_free = rec(128, 0, 64, 64, u64::MAX);
        let full_used = rec(192, 0, 64, 0, 0);
        let map = InodeAllocationMap::from_chunks(
            0,
            16384 * 8,
            BTreeMap::from([(128u32, full_free), (192u32, full_used)]),
        );
        let found = discover_inode_slots(&map, &sb, &geo, &DiscoveryOptions::default()).unwrap();
        assert_eq!(found.len(), 128);
        assert_eq!(found[63].location.ino, 191);
        assert_eq!(found[63].state, SlotState::Free);
        assert_eq!(found[64].location.ino, 192);
        assert_eq!(found[64].location.ag_block, 24);
        assert_eq!(found[127].state, SlotState::Allocated);

        let last_of_span = found.last().unwrap().location.byte_offset + sb.inode_size as u64;
        let next_first = locate_inode(&sb, &geo, 256).unwrap().byte_offset;
        assert_eq!(last_of_span, next_first);
    }

    #[test]
    fn garbage_records_in_map_cannot_produce_out_of_range_locations() {
        let (sb, geo) = ctx_v5();
        let wild = rec(u32::MAX - 32, 0, 64, 0, 0);
        let map =
            InodeAllocationMap::from_chunks(0, 16384 * 8, BTreeMap::from([(wild.startino, wild)]));
        assert!(discover_inode_slots(&map, &sb, &geo, &DiscoveryOptions::default()).is_err());
    }
}
