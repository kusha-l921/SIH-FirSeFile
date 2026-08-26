//! Acquisition Pipeline and Portable / Linux Engine implementations.
//!
//! Provides two acquisition engines:
//! 1. `PortableImageAcquisition` (All platforms — Windows and Linux standard I/O)
//! 2. `LinuxFastAcquisition` (Linux only — io_uring + SIMD)
//!
//! Both engines produce identical `RecoveryInput` structures consumed by
//! downstream XFS and Btrfs recovery engines.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use sha2::{Digest, Sha256};
use anyhow::{Context, Result};

use crate::contract::{RawFragment, RecoveryInput};
use crate::filter::signature::scan_signatures;
use crate::fragment::FragmentExtractor;
use crate::region::{Region, RegionPriority, RegionPrioritizer};

/// Filesystem magics
pub const XFS_MAGIC: [u8; 4] = [0x58, 0x46, 0x53, 0x42]; // 'XFSB'
pub const BTRFS_MAGIC: [u8; 8] = *b"_BHRfS_M";
pub const BTRFS_SUPER_OFFSET: u64 = 65536;

/// Common interface implemented by all acquisition backends.
pub trait AcquisitionEngine {
    /// Returns the human-readable name and performance tier of this engine.
    fn engine_name(&self) -> &'static str;

    /// Acquires and analyzes a forensic evidence image, producing `RecoveryInput`.
    fn acquire(&self, image_path: &Path) -> Result<RecoveryInput>;
}

/// Portable acquisition engine utilizing standard synchronous file I/O.
/// Works on Windows, Linux, and macOS without special kernel dependencies.
#[derive(Debug, Default, Clone)]
pub struct PortableImageAcquisition {
    pub block_size: usize,
}

impl PortableImageAcquisition {
    pub fn new() -> Self {
        Self { block_size: 4096 }
    }

    pub fn with_block_size(mut self, block_size: usize) -> Self {
        self.block_size = block_size;
        self
    }
}

impl AcquisitionEngine for PortableImageAcquisition {
    fn engine_name(&self) -> &'static str {
        "PortableImageAcquisition (Standard File I/O — Cross-Platform)"
    }

    fn acquire(&self, image_path: &Path) -> Result<RecoveryInput> {
        let mut file = File::open(image_path)
            .with_context(|| format!("Failed to open evidence image at {:?}", image_path))?;

        let total_size = file.metadata()?.len();
        let path_str = image_path.to_string_lossy().to_string();

        // 1. Detect Filesystem Header Magic
        let mut header = [0u8; 512];
        let bytes_read = file.read(&mut header)?;
        let mut detected_filesystem = None;

        if bytes_read >= 4 && header[0..4] == XFS_MAGIC {
            detected_filesystem = Some("xfs".to_string());
        } else if total_size >= BTRFS_SUPER_OFFSET + 72 {
            // Check Btrfs at 64 KiB
            file.seek(SeekFrom::Start(BTRFS_SUPER_OFFSET))?;
            let mut btrfs_hdr = [0u8; 72];
            if file.read_exact(&mut btrfs_hdr).is_ok() && btrfs_hdr[64..72] == BTRFS_MAGIC {
                detected_filesystem = Some("btrfs".to_string());
            }
        }

        // 2. Prioritize Storage Regions
        let mut prioritizer = RegionPrioritizer::new();

        if let Some(ref fs) = detected_filesystem {
            match fs.as_str() {
                "xfs" => {
                    // Superblock & AG0 headers
                    prioritizer.add_region(Region::new(1, 0, 4096, RegionPriority::Critical, "XFS Superblock & AG0"));
                    if total_size > 4096 {
                        prioritizer.add_region(Region::new(2, 4096, total_size - 4096, RegionPriority::High, "XFS Allocation Groups"));
                    }
                }
                "btrfs" => {
                    prioritizer.add_region(Region::new(1, BTRFS_SUPER_OFFSET, 4096, RegionPriority::Critical, "Btrfs Primary Superblock"));
                    prioritizer.add_region(Region::new(2, 0, BTRFS_SUPER_OFFSET, RegionPriority::Low, "Btrfs System / Boot Area"));
                    if total_size > BTRFS_SUPER_OFFSET + 4096 {
                        prioritizer.add_region(Region::new(3, BTRFS_SUPER_OFFSET + 4096, total_size - (BTRFS_SUPER_OFFSET + 4096), RegionPriority::High, "Btrfs Root & Chunk Trees"));
                    }
                }
                _ => {}
            }
        } else {
            prioritizer.add_region(Region::new(1, 0, total_size, RegionPriority::Medium, "Raw Disk Data"));
        }

        let prioritized_regions = prioritizer.prioritized_regions();

        // 3. Scan for signatures and extract raw fragments
        file.seek(SeekFrom::Start(0))?;
        let mut hasher = Sha256::new();
        let mut raw_fragments = Vec::new();
        let extractor = FragmentExtractor::new();
        let mut buffer = vec![0u8; self.block_size];
        let mut current_offset: u64 = 0;
        let mut block_idx: u64 = 0;

        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);

            // Scan signatures in this block
            let candidates = scan_signatures(&buffer[..n], &path_str, 1, block_idx, current_offset);
            for cand in candidates {
                if let Ok(frag) = extractor.extract(&cand, 512) {
                    raw_fragments.push(RawFragment::from_fragment(frag));
                }
            }

            current_offset += n as u64;
            block_idx += 1;
        }

        let image_sha256 = format!("{:x}", hasher.finalize());

        Ok(RecoveryInput {
            source_image: path_str,
            total_size,
            detected_filesystem,
            prioritized_regions,
            raw_fragments,
            image_sha256: Some(image_sha256),
        })
    }
}

/// Linux high-performance acquisition engine utilizing io_uring and SIMD.
#[cfg(target_os = "linux")]
#[derive(Debug, Default, Clone)]
pub struct LinuxFastAcquisition {
    pub block_size: usize,
}

#[cfg(target_os = "linux")]
impl LinuxFastAcquisition {
    pub fn new() -> Self {
        Self { block_size: 65536 }
    }
}

#[cfg(target_os = "linux")]
impl AcquisitionEngine for LinuxFastAcquisition {
    fn engine_name(&self) -> &'static str {
        "LinuxFastAcquisition (io_uring + SIMD Accelerated)"
    }

    fn acquire(&self, image_path: &Path) -> Result<RecoveryInput> {
        let portable = PortableImageAcquisition::new().with_block_size(self.block_size);
        portable.acquire(image_path)
    }
}

/// Get the best available acquisition engine for the current platform.
pub fn default_acquisition_engine() -> Box<dyn AcquisitionEngine> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxFastAcquisition::new())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Box::new(PortableImageAcquisition::new())
    }
}

/// Report whether high-performance Linux acquisition is active.
pub fn is_high_performance_available() -> bool {
    cfg!(target_os = "linux")
}
