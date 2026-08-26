use crate::filter::signature::{Candidate, FileType};

#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;

pub fn scan_signatures_simd(
    data: &[u8],
    source: &str,
    region_id: u64,
    block_id: u64,
    block_offset: u64,
) -> Vec<Candidate> {
    let mut candidates = Vec::new();

    #[cfg(target_arch = "aarch64")]
    {
        unsafe {
            scan_pattern_neon(
                data,
                b"\xFF\xD8\xFF",
                FileType::Jpeg,
                source,
                region_id,
                block_id,
                block_offset,
                &mut candidates,
            );

            scan_pattern_neon(
                data,
                b"\x89PNG",
                FileType::Png,
                source,
                region_id,
                block_id,
                block_offset,
                &mut candidates,
            );

            scan_pattern_neon(
                data,
                b"%PDF",
                FileType::Pdf,
                source,
                region_id,
                block_id,
                block_offset,
                &mut candidates,
            );

            scan_pattern_neon(
                data,
                b"PK\x03\x04",
                FileType::Zip,
                source,
                region_id,
                block_id,
                block_offset,
                &mut candidates,
            );
        }
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (
            data,
            source,
            region_id,
            block_id,
            block_offset,
        );
    }

    candidates.sort_by_key(|candidate| candidate.absolute_offset);

    candidates
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn scan_pattern_neon(
    data: &[u8],
    pattern: &[u8],
    file_type: FileType,
    source: &str,
    region_id: u64,
    block_id: u64,
    block_offset: u64,
    candidates: &mut Vec<Candidate>,
) {
    if pattern.is_empty() || data.len() < pattern.len() {
        return;
    }

    let first = vdup_n_u8(pattern[0]);

    let mut offset = 0;

    while offset + 16 <= data.len() {
        let chunk = unsafe {
            vld1_u8(data.as_ptr().add(offset))
        };

        let comparison = vceq_u8(chunk, first);

        let mut mask = [0u8; 8];

        unsafe {
            vst1_u8(mask.as_mut_ptr(), comparison);
        }

        for lane in 0..8 {
            if mask[lane] == 0xFF {
                let candidate_offset = offset + lane;

                if candidate_offset + pattern.len() <= data.len()
                    && data[candidate_offset
                        ..candidate_offset + pattern.len()]
                        == *pattern
                {
                    candidates.push(Candidate {
                        source: source.to_string(),
                        region_id,
                        block_id,
                        block_offset,
                        absolute_offset: block_offset
                            + candidate_offset as u64,
                        file_type,
                        detection_method:
                            "ARM64 NEON SIMD".to_string(),
                        confidence: 1.0,
                        block_data: data.to_vec(),
                    });
                }
            }
        }

        offset += 8;
    }

    // Scalar tail scan.
    while offset + pattern.len() <= data.len() {
        if &data[offset..offset + pattern.len()] == pattern {
            candidates.push(Candidate {
                source: source.to_string(),
                region_id,
                block_id,
                block_offset,
                absolute_offset: block_offset + offset as u64,
                file_type,
                detection_method:
                    "ARM64 NEON SIMD".to_string(),
                confidence: 1.0,
                block_data: data.to_vec(),
            });
        }

        offset += 1;
    }
}
