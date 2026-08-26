pub mod ag;
pub mod alloc_records;
pub mod btree;
pub mod dinode;
pub mod extents;
pub mod fork;
pub mod inode_addr;
pub mod inode_scan;
pub mod superblock;

pub use superblock::{CrcStatus, Geometry, Superblock, SuperblockIssue};

pub use ag::{
    AgHeaderOffsets, AgIssue, Agf, Agfl, Agi, AllocationGroup, RefcountBtInfo, RmapBtInfo,
};
pub use ag::{ag_header_offsets, parse_agf, parse_agfl, parse_agi, parse_allocation_group};

pub use alloc_records::{
    AgFreeSpace, AllocRecordIssue, FreeExtent, INODES_PER_CHUNK, InobtRecord, InodeAllocationMap,
    SlotState, collect_free_space, collect_inode_allocation, decode_free_extent,
    decode_inobt_record, validate_extent, validate_inobt,
};

pub use btree::{AllocBtreeKind, AllocRecord, BtreeIssue, BtreeWalk, walk_alloc_btree};
pub use btree::{RecordSource, RecordView, WalkMode};

pub use dinode::{
    AttrForkFormat, DataForkFormat, Dinode, DinodeCore, DinodeIssue, FileType, Timestamp,
    parse_dinode, parse_dinode_core, parse_dinode_from_bytes,
};
pub use extents::{
    ExtentIssue, ExtentMap, ExtentReader, ExtentState, FileExtent, ResidualConfidence,
    ResidualInterpretation, decode_bmbt_record, encode_bmbt_record, interpret_residual_extents,
    parse_data_fork,
};
pub use fork::{AttrForkRegion, ForkRegion, attr_fork_region, data_fork_region, local_data_bytes};
pub use inode_addr::{
    DiscoveredInode, InodeLocation, NULLAGINO, absolute_inode, ag_first_inode,
    inodes_per_ag_addressable, locate_inode,
};
pub use inode_scan::{
    DiscoveryOptions, RawScanCandidate, UnlinkedHead, collect_unlinked_heads,
    collect_unlinked_heads_from_image, discover_chunk_slots, discover_inode_slots,
    experimental_raw_scan,
};
