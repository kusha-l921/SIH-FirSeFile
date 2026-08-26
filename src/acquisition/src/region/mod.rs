// Source: param-part3 storage-engine/src/region/mod.rs (unchanged)
pub mod prioritizer;

pub use prioritizer::RegionPrioritizer;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RegionPriority {
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Region {
    pub id: u64,
    pub start_offset: u64,
    pub size: u64,
    pub priority: RegionPriority,
    pub reason: String,
}

impl Region {
    pub fn new(
        id: u64,
        start_offset: u64,
        size: u64,
        priority: RegionPriority,
        reason: impl Into<String>,
    ) -> Self {
        Self { id, start_offset, size, priority, reason: reason.into() }
    }
}
