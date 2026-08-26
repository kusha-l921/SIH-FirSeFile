// Source: param-part3 storage-engine/src/filter/simd.rs (unchanged)
// ARM64 NEON SIMD path; scalar fallback on all other architectures.
use crate::filter::signature::Candidate;
#[cfg(target_arch = "aarch64")]
use crate::filter::signature::FileType;

#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;

pub fn scan_signatures_simd(
    data: &[u8],
    source: &str,
    region_id: u64,
    block_id: u64,
    block_offset: u64,
) -> Vec<Candidate> {
    #[cfg(target_arch = "aarch64")]
    let mut candidates = {
        let mut list = Vec::new();
        unsafe {
            for (pattern, file_type) in [
                (b"\xFF\xD8\xFF".as_slice(), FileType::Jpeg),
                (b"\x89PNG".as_slice(),      FileType::Png),
                (b"%PDF".as_slice(),         FileType::Pdf),
                (b"PK\x03\x04".as_slice(),  FileType::Zip),
            ] {
                scan_pattern_neon(data, pattern, file_type, source,
                                  region_id, block_id, block_offset, &mut list);
            }
        }
        list
    };

    #[cfg(not(target_arch = "aarch64"))]
    let mut candidates = crate::filter::signature::scan_signatures(
        data, source, region_id, block_id, block_offset,
    );

    candidates.sort_by_key(|c| c.absolute_offset);
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

    while offset + 8 <= data.len() {
        let chunk = vld1_u8(data.as_ptr().add(offset));
        let cmp   = vceq_u8(chunk, first);
        let mut mask = [0u8; 8];
        vst1_u8(mask.as_mut_ptr(), cmp);

        for lane in 0..8 {
            if mask[lane] == 0xFF {
                let pos = offset + lane;
                if pos + pattern.len() <= data.len()
                    && &data[pos..pos + pattern.len()] == pattern
                {
                    candidates.push(Candidate {
                        source: source.to_string(),
                        region_id,
                        block_id,
                        block_offset,
                        absolute_offset: block_offset + pos as u64,
                        file_type,
                        detection_method: "ARM64 NEON SIMD".to_string(),
                        confidence: 1.0,
                        block_data: data.to_vec(),
                    });
                }
            }
        }
        offset += 8;
    }

    // Scalar tail
    while offset + pattern.len() <= data.len() {
        if &data[offset..offset + pattern.len()] == pattern {
            candidates.push(Candidate {
                source: source.to_string(),
                region_id,
                block_id,
                block_offset,
                absolute_offset: block_offset + offset as u64,
                file_type,
                detection_method: "ARM64 NEON SIMD".to_string(),
                confidence: 1.0,
                block_data: data.to_vec(),
            });
        }
        offset += 1;
    }
}
