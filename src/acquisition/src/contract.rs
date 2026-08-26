//! Shared data contract between the acquisition layer and downstream recovery
//! modules (XFS recovery, Btrfs adapter, ML reassembly, and forensic ledger).
//!
//! Defines canonical models for:
//! - `RawFragment`
//! - `RecoveredMetadata`
//! - `RecoveredFile`
//! - `RecoveryInput`

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A raw byte fragment extracted from a storage source, with full provenance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RawFragment {
    /// Unique fragment identifier.
    pub fragment_id: String,

    /// Path or identifier of the source image / block device.
    pub source_image: String,

    /// Absolute byte offset in the evidence source.
    pub source_offset: u64,

    /// Number of bytes in `raw_bytes`.
    pub length: usize,

    /// Detected filesystem (e.g. "xfs", "btrfs", "unknown").
    pub filesystem: String,

    /// Storage region that contained this fragment.
    pub region_id: u64,

    /// Block within the region.
    pub block_id: u64,

    /// Absolute byte offset of the start of the containing block.
    pub block_offset: u64,

    /// Raw extracted bytes.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub raw_bytes: Vec<u8>,

    /// SHA-256 hex digest of `raw_bytes`.
    pub sha256: String,

    /// Recovery or extraction method (e.g. "signature_scan", "unallocated_carve").
    pub recovery_method: String,

    /// Confidence score in [0.0, 1.0].
    pub confidence: f64,
}

impl RawFragment {
    /// Convert from the internal [`crate::fragment::Fragment`] type.
    pub fn from_fragment(f: crate::fragment::Fragment) -> Self {
        let frag_id = format!("frag_{}_{}_{}", f.region_id, f.block_id, f.absolute_offset);
        Self {
            fragment_id: frag_id,
            source_image: f.source,
            source_offset: f.absolute_offset,
            length: f.length,
            filesystem: "unknown".to_string(),
            region_id: f.region_id,
            block_id: f.block_id,
            block_offset: f.block_offset,
            raw_bytes: f.data,
            sha256: f.sha256,
            recovery_method: "signature_scan".to_string(),
            confidence: 1.0,
        }
    }
}

/// Ownership metadata (UID / GID).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ownership {
    pub uid: u32,
    pub gid: u32,
}

/// Detailed metadata recovered for an inode / file candidate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RecoveredMetadata {
    /// Filename if recovered or known.
    pub filename: Option<String>,

    /// File size in bytes.
    pub file_size: u64,

    /// Creation / birth timestamp (RFC 3339 / ISO 8601 string if available).
    pub created: Option<String>,

    /// Modification timestamp.
    pub modified: Option<String>,

    /// Access timestamp.
    pub accessed: Option<String>,

    /// Metadata change timestamp.
    pub changed: Option<String>,

    /// Whether this file is flagged as deleted in the filesystem structures.
    pub deleted_if_available: bool,

    /// Permissions formatted as POSIX string (e.g. "-rw-r--r--") or octal.
    pub permissions: Option<String>,

    /// Ownership (UID/GID).
    pub ownership: Option<Ownership>,

    /// Source filesystem ("xfs", "btrfs", etc.).
    pub filesystem: String,

    /// Physical byte offsets of contributing blocks in the source image.
    pub source_locations: Vec<u64>,

    /// Additional filesystem-specific attributes (e.g. XFS flags, Btrfs generation).
    pub additional_attributes: HashMap<String, String>,
}

/// A recovered or reconstructed file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecoveredFile {
    /// Unique identifier for the recovered file.
    pub file_id: String,

    /// Filename.
    pub filename: Option<String>,

    /// File format/type (e.g. "pdf", "png", "jpeg", "zip", "elf", "sqlite", "txt").
    pub file_type: Option<String>,

    /// Size in bytes.
    pub file_size: u64,

    /// Ordered sequence of fragments or extent regions.
    pub ordered_fragments: Vec<RawFragment>,

    /// Reconstructed byte stream (if fully extracted).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reconstructed_bytes: Option<Vec<u8>>,

    /// Recovered filesystem and file metadata.
    pub metadata: RecoveredMetadata,

    /// Physical byte offsets in the evidence image.
    pub source_locations: Vec<u64>,

    /// Recovery method ("xfs_unlinked_chain", "xfs_residual_extents", "btrfs_structural", "btrfs_carved", "ml_swin_reassembly").
    pub recovery_method: String,

    /// Confidence score in [0.0, 1.0].
    pub confidence: f64,

    /// Cryptographic SHA-256 hex digest of reconstructed data.
    pub sha256: Option<String>,
}

/// Unit of data that flows from acquisition into any recovery engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryInput {
    /// Source image or device path.
    pub source_image: String,

    /// Total size of the source in bytes.
    pub total_size: u64,

    /// Detected filesystem magic ("xfs", "btrfs", or None).
    pub detected_filesystem: Option<String>,

    /// Prioritized regions found during acquisition.
    pub prioritized_regions: Vec<crate::region::Region>,

    /// Extracted candidate blocks.
    pub raw_fragments: Vec<RawFragment>,

    /// SHA-256 digest of the entire disk image.
    pub image_sha256: Option<String>,
}
