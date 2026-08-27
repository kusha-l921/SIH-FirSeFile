use crate::error::{Error, Result};
use crate::xfs::dinode::{AttrForkFormat, DataForkFormat, Dinode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkRegion<'a> {
    pub raw: &'a [u8],
    pub offset_in_inode: usize,
    pub format: DataForkFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttrForkRegion<'a> {
    pub raw: &'a [u8],
    pub offset_in_inode: usize,
    pub format: AttrForkFormat,
}

pub fn data_fork_region<'a>(inode: &'a Dinode, inode_size: usize) -> Result<ForkRegion<'a>> {
    let lit_offset = inode.core.literal_area_offset();
    if inode.raw.len() < lit_offset {
        return Err(Error::Truncated {
            needed: lit_offset,
            available: inode.raw.len(),
        });
    }

    let len = inode.core.data_fork_size(inode_size);
    let end = lit_offset.saturating_add(len);
    if inode.raw.len() < end {
        return Err(Error::Truncated {
            needed: end,
            available: inode.raw.len(),
        });
    }

    Ok(ForkRegion {
        raw: &inode.raw[lit_offset..end],
        offset_in_inode: lit_offset,
        format: inode.core.format,
    })
}

pub fn attr_fork_region<'a>(
    inode: &'a Dinode,
    inode_size: usize,
) -> Result<Option<AttrForkRegion<'a>>> {
    if !inode.core.has_attr_fork() {
        return Ok(None);
    }

    let lit_offset = inode.core.literal_area_offset();
    let boff = (inode.core.forkoff as usize) << 3;
    let attr_start = lit_offset.saturating_add(boff);
    let len = inode.core.attr_fork_size(inode_size);
    let end = attr_start.saturating_add(len);

    if inode.raw.len() < end {
        return Err(Error::Truncated {
            needed: end,
            available: inode.raw.len(),
        });
    }

    Ok(Some(AttrForkRegion {
        raw: &inode.raw[attr_start..end],
        offset_in_inode: attr_start,
        format: inode.core.aformat,
    }))
}

pub fn local_data_bytes(inode: &Dinode, inode_size: usize) -> Result<&[u8]> {
    if inode.core.format != DataForkFormat::Local {
        return Err(Error::Malformed {
            structure: "data fork",
            reason: "requested inline bytes from non-local data fork",
        });
    }

    let region = data_fork_region(inode, inode_size)?;
    let size = inode.core.size as usize;
    if size > region.raw.len() {
        return Err(Error::Malformed {
            structure: "local data fork",
            reason: "inode size exceeds available literal data fork space",
        });
    }

    Ok(&region.raw[..size])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xfs::dinode::{DINODE_V3_CORE_SIZE, INODE_MAGIC, parse_dinode_core};
    use crate::xfs::inode_addr::InodeLocation;

    fn sample_inode(format: DataForkFormat, forkoff: u8, size: u64, isize: usize) -> Dinode {
        let mut buf = vec![0u8; isize];
        buf[0..2].copy_from_slice(&INODE_MAGIC.to_be_bytes());
        buf[2..4].copy_from_slice(&0o100644u16.to_be_bytes());
        buf[4] = 3; // v3
        buf[5] = format.to_u8();
        buf[56..64].copy_from_slice(&size.to_be_bytes());
        buf[82] = forkoff;
        if forkoff > 0 {
            buf[83] = AttrForkFormat::Local.to_u8();
        }

        // Fill payload
        for (i, b) in buf[DINODE_V3_CORE_SIZE..].iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }

        let core = parse_dinode_core(&buf, isize).expect("parse core");
        let loc = InodeLocation {
            ino: 128,
            ag_number: 0,
            ag_block: 16,
            slot: 0,
            byte_offset: 65536,
        };
        Dinode {
            location: loc,
            core,
            raw: buf,
        }
    }

    #[test]
    fn extracts_data_fork_without_attr_fork() {
        let inode = sample_inode(DataForkFormat::Extents, 0, 4096, 512);
        let region = data_fork_region(&inode, 512).unwrap();
        assert_eq!(region.offset_in_inode, DINODE_V3_CORE_SIZE);
        assert_eq!(region.raw.len(), 512 - DINODE_V3_CORE_SIZE);
        assert_eq!(region.format, DataForkFormat::Extents);

        let attr = attr_fork_region(&inode, 512).unwrap();
        assert!(attr.is_none());
    }

    #[test]
    fn extracts_both_forks_with_valid_forkoff() {
        let inode = sample_inode(DataForkFormat::Extents, 10, 4096, 512); // forkoff 10 -> 80 bytes
        let data = data_fork_region(&inode, 512).unwrap();
        assert_eq!(data.raw.len(), 80);
        assert_eq!(data.offset_in_inode, DINODE_V3_CORE_SIZE);

        let attr = attr_fork_region(&inode, 512).unwrap().expect("attr region");
        assert_eq!(attr.offset_in_inode, DINODE_V3_CORE_SIZE + 80);
        assert_eq!(attr.raw.len(), 512 - DINODE_V3_CORE_SIZE - 80);
        assert_eq!(attr.format, AttrForkFormat::Local);
    }

    #[test]
    fn extracts_local_data_safely_and_bounds_checks() {
        let inode = sample_inode(DataForkFormat::Local, 0, 15, 512);
        let bytes = local_data_bytes(&inode, 512).unwrap();
        assert_eq!(bytes.len(), 15);

        // Size larger than fork
        let overflow_inode = sample_inode(DataForkFormat::Local, 0, 1000, 512);
        assert!(local_data_bytes(&overflow_inode, 512).is_err());

        // Non-local format
        let non_local = sample_inode(DataForkFormat::Extents, 0, 15, 512);
        assert!(local_data_bytes(&non_local, 512).is_err());
    }
}
