//! # Acquisition — High-Speed Read-Only Acquisition & Fragment Extraction
//!
//! Part 3 of the FirSeFile forensic recovery pipeline.
//!
//! ## Architecture
//!
//! ```text
//! Disk Image / Block Device  (read-only)
//!          ↓
//!   AcquisitionEngine        (LinuxFastAcquisition on Linux; PortableImageAcquisition elsewhere)
//!          ↓
//!   RegionPrioritizer        (rank regions by forensic importance)
//!          ↓
//!   SignatureFilter          (baseline memmem + ARM64 NEON SIMD)
//!          ↓
//!   FragmentExtractor        (provenance-preserving extraction)
//!          ↓
//!   RecoveryInput            (shared contract → downstream recovery engines)
//! ```

pub mod contract;
pub mod filter;
pub mod fragment;
pub mod pipeline;
pub mod region;
pub mod storage;

#[cfg(target_os = "linux")]
pub mod io;

pub use contract::{Ownership, RawFragment, RecoveredFile, RecoveredMetadata, RecoveryInput};
pub use filter::signature::{Candidate, FileType, scan_signatures};
pub use filter::simd::scan_signatures_simd;
pub use fragment::{Fragment, FragmentExtractor};
pub use pipeline::{
    AcquisitionEngine, PortableImageAcquisition, default_acquisition_engine,
    is_high_performance_available, BTRFS_MAGIC, BTRFS_SUPER_OFFSET, XFS_MAGIC,
};
#[cfg(target_os = "linux")]
pub use pipeline::LinuxFastAcquisition;
pub use region::{Region, RegionPriority, RegionPrioritizer};
pub use storage::{BatchReader, Block};
