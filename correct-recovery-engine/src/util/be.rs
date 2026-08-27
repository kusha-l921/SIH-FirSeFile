use crate::error::{Error, Result};

fn slice_at(buf: &[u8], offset: usize, width: usize) -> Result<&[u8]> {
    match offset
        .checked_add(width)
        .and_then(|end| buf.get(offset..end))
    {
        Some(bytes) => Ok(bytes),
        None => Err(Error::Truncated {
            needed: offset.saturating_add(width),
            available: buf.len(),
        }),
    }
}

pub fn be_u16_at(buf: &[u8], offset: usize) -> Result<u16> {
    let b = slice_at(buf, offset, 2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

pub fn be_u32_at(buf: &[u8], offset: usize) -> Result<u32> {
    let b = slice_at(buf, offset, 4)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

pub fn be_u64_at(buf: &[u8], offset: usize) -> Result<u64> {
    let b = slice_at(buf, offset, 8)?;
    Ok(u64::from_be_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

pub fn be_u16(buf: &[u8]) -> Result<u16> {
    be_u16_at(buf, 0)
}

pub fn be_u32(buf: &[u8]) -> Result<u32> {
    be_u32_at(buf, 0)
}

pub fn be_u64(buf: &[u8]) -> Result<u64> {
    be_u64_at(buf, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_valid_big_endian_values() {
        assert_eq!(be_u16(&[0x01, 0x02]).unwrap(), 0x0102);
        assert_eq!(be_u32(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap(), 0xDEAD_BEEF);
        assert_eq!(
            be_u64(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]).unwrap(),
            0x0123_4567_89AB_CDEF
        );
    }

    #[test]
    fn reads_at_nonzero_offsets() {
        let buf = [
            0x00, 0xAA, 0xBB, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        ];
        assert_eq!(be_u16_at(&buf, 1).unwrap(), 0xAABB);
        assert_eq!(be_u32_at(&buf, 3).unwrap(), 0x1234_5678);
        assert_eq!(be_u64_at(&buf, 2).unwrap(), 0xBB12_3456_789A_BCDE);
    }

    #[test]
    fn accepts_exact_length_buffers() {
        assert!(be_u16(&[0x00, 0x01]).is_ok());
        assert!(be_u32(&[0; 4]).is_ok());
        assert!(be_u64(&[0; 8]).is_ok());
    }

    #[test]
    fn rejects_too_short_buffers_with_details() {
        let err = be_u16(&[0x01]).unwrap_err();
        assert!(matches!(
            err,
            Error::Truncated {
                needed: 2,
                available: 1
            }
        ));

        let err = be_u32(&[0x01, 0x02, 0x03]).unwrap_err();
        assert!(matches!(
            err,
            Error::Truncated {
                needed: 4,
                available: 3
            }
        ));

        let err = be_u64(&[0; 7]).unwrap_err();
        assert!(matches!(
            err,
            Error::Truncated {
                needed: 8,
                available: 7
            }
        ));
    }

    #[test]
    fn rejects_empty_and_out_of_range_offsets() {
        assert!(matches!(
            be_u16(&[]),
            Err(Error::Truncated { needed: 2, .. })
        ));
        assert!(matches!(
            be_u32(&[]),
            Err(Error::Truncated { needed: 4, .. })
        ));
        assert!(matches!(
            be_u64(&[]),
            Err(Error::Truncated { needed: 8, .. })
        ));

        let buf = [0u8; 4];
        assert!(be_u16_at(&buf, 4).is_err());
        assert!(be_u32_at(&buf, 5).is_err());
        assert!(be_u64_at(&buf, usize::MAX).is_err());
    }

    #[test]
    fn never_panics_on_deterministic_malformed_input() {
        let mut state = 0x243F_6A88_85A3_08D3u64;
        let step = |buf: &[u8]| {
            for offset in 0..buf.len() + 3 {
                let _ = be_u16_at(buf, offset);
                let _ = be_u32_at(buf, offset);
                let _ = be_u64_at(buf, offset);
                let _ = be_u16(&buf[..buf.len().min(offset)]);
                let _ = be_u32(&buf[..buf.len().min(offset)]);
                let _ = be_u64(&buf[..buf.len().min(offset)]);
            }
        };

        let mut buf = vec![0u8; 17];
        for _ in 0..128 {
            for b in buf.iter_mut() {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (state >> 33) as u8;
            }
            step(&buf);
        }
    }
}
