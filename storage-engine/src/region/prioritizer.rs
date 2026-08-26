use super::Region;

pub struct RegionPrioritizer {
    regions: Vec<Region>,
}

impl RegionPrioritizer {
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    pub fn add_region(&mut self, region: Region) {
        self.regions.push(region);
    }

    pub fn prioritized_regions(&mut self) -> Vec<Region> {
        self.regions
            .sort_by(|a, b| b.priority.cmp(&a.priority));

        self.regions.clone()
    }
}
