// Source: param-part3 storage-engine/src/fragment/extractor.rs (unchanged)
use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

use crate::filter::signature::Candidate;

/// A recovered fragment with complete provenance.
#[derive(Debug, Clone)]
pub struct Fragment {
    pub source: String,
    pub region_id: u64,
    pub block_id: u64,
    pub block_offset: u64,
    /// Absolute byte offset of the fragment in the source image.
    pub absolute_offset: u64,
    pub length: usize,
    pub sha256: String,
    pub data: Vec<u8>,
}

/// Extracts byte fragments from signature candidates.
pub struct FragmentExtractor;

impl FragmentExtractor {
    pub fn new() -> Self {
        Self
    }

    /// Extract `length` bytes beginning at the candidate's absolute offset.
    pub fn extract(&self, candidate: &Candidate, length: usize) -> Result<Fragment> {
        if length == 0 {
            return Err(anyhow!("fragment length must be greater than zero"));
        }

        let relative_offset = candidate
            .absolute_offset
            .checked_sub(candidate.block_offset)
            .ok_or_else(|| anyhow!("candidate absolute offset is before block offset"))?
            as usize;

        let end = relative_offset
            .checked_add(length)
            .ok_or_else(|| anyhow!("fragment range overflow"))?;

        if end > candidate.block_data.len() {
            return Err(anyhow!(
                "fragment extends beyond available block data: \
                 offset={}, length={}, block_size={}",
                relative_offset,
                length,
                candidate.block_data.len()
            ));
        }

        let data = candidate.block_data[relative_offset..end].to_vec();
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let sha256 = hex::encode(hasher.finalize());

        Ok(Fragment {
            source: candidate.source.clone(),
            region_id: candidate.region_id,
            block_id: candidate.block_id,
            block_offset: candidate.block_offset,
            absolute_offset: candidate.absolute_offset,
            length: data.len(),
            sha256,
            data,
        })
    }
}

impl Default for FragmentExtractor {
    fn default() -> Self {
        Self::new()
    }
}
