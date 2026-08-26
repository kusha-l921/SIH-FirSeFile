//! Shared data contract between the acquisition layer (Part 3) and
//! downstream recovery modules (Part 1 XFS, Part 2 Btrfs, etc.).
//!
//! A `RawFragment` is the unit of data that flows from acquisition into
//! any recovery pipeline.  It carries enough provenance to reconstruct
//! the exact source location of every byte.
//!
//! NEW — not present in either source branch; defined here to avoid
//! duplicating provenance fields across modules.

/// A raw byte fragment extracted from a storage source, with full provenance.
///
/// Produced by [`crate::fragment::FragmentExtractor`].
/// Consumed by downstream recovery engines (XFS, Btrfs, …).
#[derive(Debug, Clone)]
pub struct RawFragment {
    /// Path or identifier of the source image / block device.
    pub source: String,

    /// Storage region that contained this fragment (from `RegionPrioritizer`).
    pub region_id: u64,

    /// Block within the region.
    pub block_id: u64,

    /// Absolute byte offset of the start of the containing block.
    pub block_offset: u64,

    /// Absolute byte offset of the first byte of this fragment.
    pub absolute_offset: u64,

    /// Number of bytes in `data`.
    pub length: usize,

    /// SHA-256 hex digest of `data`.
    pub sha256: String,

    /// Raw extracted bytes.
    pub data: Vec<u8>,
}

impl RawFragment {
    /// Convert from the internal [`crate::fragment::Fragment`] type.
    pub fn from_fragment(f: crate::fragment::Fragment) -> Self {
        Self {
            source: f.source,
            region_id: f.region_id,
            block_id: f.block_id,
            block_offset: f.block_offset,
            absolute_offset: f.absolute_offset,
            length: f.length,
            sha256: f.sha256,
            data: f.data,
        }
    }
}
