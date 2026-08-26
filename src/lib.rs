//! # XFS Recovery Engine
//!
//! A zero-dependency, forensically safe, read-only XFS structural analysis and recovery engine.
//!
//! ## Architecture & Integration Flow
//!
//! ```text
//! Raw Evidence Source (Disk Image / Partition / Memory)
//!                      ↓
//!              ImageRead Trait
//!                      ↓
//!           RecoveryEngine::open(...)
//!                      ↓
//!       ┌──────────────┴──────────────┐
//!       ↓                             ↓
//! FsInfo (Superblock & Geometry)  RecoveryReport (Candidates & Rejections)
//!                                     ↓
//!                             RecoveryCandidate[]
//!                                     ↓
//!                    ExtentReader::read_at(...) (File Content)
//! ```
//!
//! ## Example
//!
//! ```no_run
//! use xfs_recovery_engine::{FileImage, RecoveryEngine, RecoveryOptions};
//!
//! let image = FileImage::open("disk.raw").expect("open disk image");
//! let options = RecoveryOptions::default();
//! let mut engine = RecoveryEngine::open(image, options).expect("open recovery engine");
//!
//! println!("Filesystem UUID: {:x?}", engine.fs_info().uuid);
//! println!("Block size: {}", engine.fs_info().block_size);
//!
//! let report = engine.collect_candidates().expect("collect candidates");
//! for candidate in &report.candidates {
//!     println!(
//!         "Found candidate ino {} ({:?}, confidence: {:?})",
//!         candidate.ino, candidate.candidate_class, candidate.confidence
//!     );
//! }
//! ```

pub mod api;
pub mod error;
pub mod io;
pub mod recovery;
pub mod util;
pub mod xfs;

pub use api::{FsInfo, RecoveryEngine, RecoveryOptions};
pub use error::{Error, Result};
pub use io::{FileImage, ImageRead, MemImage};
pub use recovery::{
    CandidateClass, RecoveryCandidate, RecoveryConfidence, RecoveryEvidence, RecoveryMethod,
    RecoveryReport, RecoverySummary, Rejection, RejectionReason, classify_inode_candidate,
    collect_recovery_candidates,
};
pub use util::be::{be_u16, be_u16_at, be_u32, be_u32_at, be_u64, be_u64_at};
pub use util::crc32c::crc32c;
pub use xfs::superblock::{CrcStatus, Geometry, Superblock, SuperblockIssue};
pub use xfs::{
    AgFreeSpace, AgHeaderOffsets, AgIssue, Agf, Agfl, Agi, AllocBtreeKind, AllocRecordIssue,
    AllocationGroup, AttrForkFormat, AttrForkRegion, BtreeIssue, BtreeWalk, DataForkFormat, Dinode,
    DinodeCore, DinodeIssue, DiscoveredInode, DiscoveryOptions, ExtentIssue, ExtentMap,
    ExtentReader, ExtentState, FileExtent, FileType, ForkRegion, FreeExtent, InobtRecord,
    InodeAllocationMap, InodeLocation, NULLAGINO, RawScanCandidate, RefcountBtInfo,
    ResidualConfidence, ResidualInterpretation, RmapBtInfo, SlotState, Timestamp, UnlinkedHead,
    WalkMode, absolute_inode, ag_first_inode, ag_header_offsets, attr_fork_region,
    collect_free_space, collect_inode_allocation, collect_unlinked_heads,
    collect_unlinked_heads_from_image, data_fork_region, decode_bmbt_record, decode_free_extent,
    decode_inobt_record, discover_inode_slots, encode_bmbt_record, interpret_residual_extents,
    local_data_bytes, locate_inode, parse_agf, parse_agfl, parse_agi, parse_allocation_group,
    parse_data_fork, parse_dinode, parse_dinode_core, parse_dinode_from_bytes, validate_extent,
    validate_inobt, walk_alloc_btree,
};
