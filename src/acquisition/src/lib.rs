//! # Acquisition — High-Speed Read-Only Acquisition & Fragment Extraction
//!
//! Part 3 of the FirSeFile forensic recovery pipeline.
//!
//! ## Architecture
//!
//! ```text
//! Disk Image / Block Device  (read-only)
//!          ↓
//!   RegionPrioritizer        (rank regions by forensic importance)
//!          ↓
//!   BatchReader              (io_uring on Linux; std fallback elsewhere)
//!          ↓
//!   SignatureFilter          (baseline memmem + ARM64 NEON SIMD)
//!          ↓
//!   FragmentExtractor        (provenance-preserving extraction)
//!          ↓
//!   RawFragment              (shared contract → downstream recovery)
//! ```
//!
//! ## Sources
//! All logic ported from `param-part3` branch (`storage-engine/src/`).
//! `contract` module is new — defines the shared data contract consumed
//! by downstream crates (XFS recovery, Btrfs recovery, etc.).

pub mod contract;
pub mod filter;
pub mod fragment;
pub mod region;
pub mod storage;

#[cfg(target_os = "linux")]
pub mod io;

pub use contract::RawFragment;
pub use filter::signature::{Candidate, FileType, scan_signatures};
pub use filter::simd::scan_signatures_simd;
pub use fragment::{Fragment, FragmentExtractor};
pub use region::{Region, RegionPriority, RegionPrioritizer};
pub use storage::{BatchReader, Block};
