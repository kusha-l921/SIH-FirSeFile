// Source: param-part3 storage-engine/src/region/prioritizer.rs (unchanged)
use super::Region;

pub struct RegionPrioritizer {
    regions: Vec<Region>,
}

impl RegionPrioritizer {
    pub fn new() -> Self {
        Self { regions: Vec::new() }
    }

    pub fn add_region(&mut self, region: Region) {
        self.regions.push(region);
    }

    /// Returns regions sorted highest-priority first.
    pub fn prioritized_regions(&mut self) -> Vec<Region> {
        self.regions.sort_by(|a, b| b.priority.cmp(&a.priority));
        self.regions.clone()
    }
}

impl Default for RegionPrioritizer {
    fn default() -> Self {
        Self::new()
    }
}
