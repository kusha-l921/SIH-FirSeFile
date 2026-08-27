use crate::error::{Error, Result};
use crate::xfs::alloc_records::SlotState;
use crate::xfs::superblock::{Geometry, Superblock};

pub const NULLAGINO: u32 = u32::MAX;
pub const INODE_MAGIC: u16 = 0x494E;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeLocation {
    pub ino: u64,
    pub ag_number: u32,
    pub ag_block: u64,
    pub slot: u32,
    pub byte_offset: u64,
}

#[derive(Debug, Clone)]
pub struct DiscoveredInode {
    pub location: InodeLocation,
    pub state: SlotState,
}

fn malformed(reason: &'static str) -> Error {
    Error::Malformed {
        structure: "inode address",
        reason,
    }
}

pub fn inodes_per_ag_addressable(geometry: &Geometry) -> Result<u64> {
    let inopb_log = geometry
        .inodes_per_block()
        .checked_ilog2()
        .ok_or(Error::Malformed {
            structure: "geometry",
            reason: "inodes-per-block is not a power of two",
        })?;
    let shift = geometry.agblk_log() as u32 + inopb_log;
    if shift >= 64 {
        return Err(malformed("inode addressing shift exceeds 64 bits"));
    }
    Ok(1u64 << shift)
}

pub fn ag_first_inode(geometry: &Geometry, ag_number: u32) -> Result<u64> {
    if ag_number >= geometry.ag_count() {
        return Err(malformed("allocation group beyond superblock ag_count"));
    }
    let first = inodes_per_ag_addressable(geometry)?
        .checked_mul(ag_number as u64)
        .ok_or_else(|| malformed("first-inode computation overflows 64 bits"))?;
    Ok(first)
}

pub fn locate_inode(sb: &Superblock, geometry: &Geometry, ino: u64) -> Result<InodeLocation> {
    if ino == 0 {
        return Err(malformed("inode number zero is never valid"));
    }
    let (ag_number, ag_block, offset_in_block) = geometry.inode_locate(ino)?;
    let inode_size = sb.inode_size as u64;
    if inode_size == 0 || offset_in_block % inode_size != 0 {
        return Err(malformed("intra-block offset misaligned to inode size"));
    }
    let slot = u32::try_from(offset_in_block / inode_size)
        .map_err(|_| malformed("slot index exceeds 32-bit range"))?;
    let byte_offset = geometry.inode_fs_byte(ino)?;
    Ok(InodeLocation {
        ino,
        ag_number,
        ag_block,
        slot,
        byte_offset,
    })
}

pub fn absolute_inode(geometry: &Geometry, ag_number: u32, ag_inode: u32) -> Result<u64> {
    let first = ag_first_inode(geometry, ag_number)?;
    first
        .checked_add(ag_inode as u64)
        .ok_or_else(|| malformed("absolute inode computation overflows 64 bits"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xfs::superblock::testing::{golden_v5, put16, put32, put64};

    fn ctx_from(golden: &mut [u8; 512]) -> (Superblock, Geometry) {
        if golden[100..102] == [0xBD, 0x75] {
            golden[224..228].copy_from_slice(&0u32.to_le_bytes());
            let crc = crate::util::crc32c::crc32c(&golden[..224]);
            golden[224..228].copy_from_slice(&crc.to_le_bytes());
        }
        Superblock::parse_bytes(golden).expect("patched sb")
    }

    fn patched_v5(f: impl FnOnce(&mut [u8; 512])) -> (Superblock, Geometry) {
        let mut g = golden_v5();
        f(&mut g);
        ctx_from(&mut g)
    }

    fn patch_inode_geometry(b: &mut [u8; 512], isize_: u16) {
        put16(b, 104, isize_);
        b[122] = isize_.trailing_zeros() as u8;
        let inopb = (4096 / isize_ as u32) as u16;
        put16(b, 106, inopb);
        b[123] = inopb.trailing_zeros() as u8;
        let align = 64u32 * isize_ as u32 >> 12;
        put32(b, 180, align);
    }

    #[test]
    fn locates_across_default_golden_geometry() {
        let (sb, geo) = patched_v5(|_| {});
        assert_eq!(sb.inode_size, 512);

        let loc = locate_inode(&sb, &geo, 128).unwrap();
        assert_eq!(loc.ag_number, 0);
        assert_eq!(loc.ag_block, 16);
        assert_eq!(loc.slot, 0);
        assert_eq!(loc.byte_offset, 16 * 4096);

        let mid = locate_inode(&sb, &geo, 131).unwrap();
        assert_eq!((mid.ag_block, mid.slot), (16, 3));

        let (sb2, geo2) = patched_v5(|_| {});
        let crossing = locate_inode(&sb2, &geo2, 0x2_0000 + 8).unwrap();
        assert_eq!(crossing.ag_number, 1);
        assert_eq!(crossing.ag_block, 1);
        assert_eq!(crossing.slot, 0);
    }

    #[test]
    fn round_trip_holds_for_sampled_inodes() {
        for (sb, geo) in [
            patched_v5(|_| {}),
            patched_v5(|b| patch_inode_geometry(b, 256)),
            patched_v5(|b| patch_inode_geometry(b, 1024)),
            patched_v5(|b| patch_inode_geometry(b, 2048)),
        ] {
            let per_ag = inodes_per_ag_addressable(&geo).unwrap();
            for ag in 0u64..4 {
                for rel in [0u64, 7, 63, 64, 5000, per_ag - 1] {
                    let ino = ag * per_ag + rel;
                    if ino == 0 {
                        continue;
                    }
                    let loc = match locate_inode(&sb, &geo, ino) {
                        Ok(l) => l,
                        Err(_) => continue,
                    };
                    let rebuilt = ag_first_inode(&geo, loc.ag_number).unwrap()
                        + ((loc.ag_block * geo.inodes_per_block() as u64) + loc.slot as u64);
                    assert_eq!(rebuilt, ino, "round trip failed for {ino}");
                }
            }
        }
    }

    #[test]
    fn chunk_spanning_blocks_and_multi_chunk_blocks() {
        let (sb512, geo512) = patched_v5(|_| {});
        let a = locate_inode(&sb512, &geo512, 127).unwrap();
        let b = locate_inode(&sb512, &geo512, 128).unwrap();
        assert_eq!(a.ag_block, 15);
        assert_eq!(b.ag_block, 16);

        let (sb2k, geo2k) = patched_v5(|b| patch_inode_geometry(b, 2048));
        let c = locate_inode(&sb2k, &geo2k, 130).unwrap();
        assert_eq!((c.ag_block, c.slot), (65, 0));
        let d2 = locate_inode(&sb2k, &geo2k, 131).unwrap();
        assert_eq!((d2.ag_block, d2.slot), (65, 1));

        let (sb_big, geo_big) = patched_v5(|b| {
            put32(b, 4, 65_536);
            b[120] = 16;
            put16(b, 104, 512);
            b[122] = 9;
            put16(b, 106, 128);
            b[123] = 7;
            put32(b, 180, 0);
        });
        let d = locate_inode(&sb_big, &geo_big, 64).unwrap();
        let e = locate_inode(&sb_big, &geo_big, 128).unwrap();
        assert_eq!(d.slot, 64);
        assert_eq!(e.slot, 0);
        assert_eq!(d.ag_block, 0);
        assert_eq!(e.ag_block, 1);
        let f = locate_inode(&sb_big, &geo_big, 63).unwrap();
        let g = locate_inode(&sb_big, &geo_big, 64).unwrap();
        assert_eq!((f.ag_block, f.slot), (0, 63));
        assert_eq!((g.ag_block, g.slot), (0, 64));
        assert_eq!(f.byte_offset + sb_big.inode_size as u64, g.byte_offset);
    }

    #[test]
    fn non_power_of_two_ag_blocks_still_address() {
        let (sb, geo) = patched_v5(|b| {
            put32(b, 84, 12_288);
            b[124] = 14;
            put64(b, 8, 49_152);
        });
        let first_ag1 = 1 << (geo.agblk_log() as u32 + 3);
        let loc = locate_inode(&sb, &geo, first_ag1).unwrap();
        assert_eq!(loc.ag_number, 1);
        assert_eq!(loc.ag_block, 0);
        assert_eq!(ag_first_inode(&geo, 2).unwrap(), first_ag1 << 1);

        let hole_region_start = first_ag1 + 12_288 * geo.inodes_per_block() as u64;
        assert!(locate_inode(&sb, &geo, hole_region_start).is_err());
        let last_real_ag0 = 12_288 * geo.inodes_per_block() as u64 - 1;
        assert!(locate_inode(&sb, &geo, last_real_ag0).is_ok());
    }

    #[test]
    fn invalid_addresses_error_without_panicking() {
        let (sb, geo) = patched_v5(|_| {});
        assert!(locate_inode(&sb, &geo, 0).is_err());
        assert!(locate_inode(&sb, &geo, u64::MAX).is_err());
        let last_valid = geo.ag_blocks() as u64 * geo.inodes_per_block() as u64 - 1;
        let loc = locate_inode(&sb, &geo, last_valid).unwrap();
        assert_eq!(loc.ag_number, 0);
        assert_eq!(loc.ag_block, geo.ag_blocks() as u64 - 1);
        assert_eq!(loc.slot, geo.inodes_per_block() - 1);
    }

    #[test]
    fn unlinked_head_absolute_mapping() {
        let (sb, geo) = patched_v5(|_| {});
        let abs = absolute_inode(&geo, 2, 137).unwrap();
        assert_eq!(abs, (2 << (14 + 3)) + 137);
        let loc = locate_inode(&sb, &geo, abs).unwrap();
        assert_eq!(loc.ag_number, 2);
        assert!(absolute_inode(&geo, 9, 0).is_err());
    }
}
