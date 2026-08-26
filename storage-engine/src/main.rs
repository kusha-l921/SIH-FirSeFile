mod filter;
mod fragment;
mod region;
mod storage;

use anyhow::Result;
use fragment::{Fragment, FragmentExtractor};
use region::prioritizer::RegionPrioritizer;
use region::{Region, RegionPriority};
use storage::BatchReader;

const DISK_IMAGE: &str = "test_disk.img";
const BLOCK_SIZE: usize = 4096;
const BLOCK_SIZE_U64: u64 = 4096;
const FRAGMENT_LENGTH: usize = 32;

fn print_fragment(fragment: &Fragment) {
    println!("\n  Fragment extracted");

    println!("  Fragment source  : {}", fragment.source);

    println!("  Region ID        : {}", fragment.region_id);

    println!("  Block ID         : {}", fragment.block_id);

    println!("  Block Offset     : {}", fragment.block_offset);

    println!("  Fragment offset  : {}", fragment.absolute_offset);

    println!("  Fragment length  : {} bytes", fragment.length);

    println!("  SHA-256          : {}", fragment.sha256);

    println!(
        "  First bytes      : {:02X?}",
        &fragment.data[..fragment.data.len().min(16)]
    );
}

fn print_candidate(
    candidate: &filter::signature::Candidate,
    prefix: &str,
) {
    println!(
        "\n{}Candidate: {:?}",
        prefix,
        candidate.file_type
    );

    println!(
        "  Source           : {}",
        candidate.source
    );

    println!(
        "  Region ID        : {}",
        candidate.region_id
    );

    println!(
        "  Block ID         : {}",
        candidate.block_id
    );

    println!(
        "  Block Offset     : {}",
        candidate.block_offset
    );

    println!(
        "  Absolute Offset  : {}",
        candidate.absolute_offset
    );

    println!(
        "  Detection Method : {}",
        candidate.detection_method
    );

    println!(
        "  Confidence       : {:.2}",
        candidate.confidence
    );
}

fn main() -> Result<()> {
    println!("PS2 Storage Engine");
    println!("==================");

    // ==================================================
    // 1. CREATE AND PRIORITIZE STORAGE REGIONS
    // ==================================================

    let mut prioritizer = RegionPrioritizer::new();

    prioritizer.add_region(Region::new(
        1,
        0,
        BLOCK_SIZE_U64,
        RegionPriority::Low,
        "General data",
    ));

    prioritizer.add_region(Region::new(
        2,
        BLOCK_SIZE_U64,
        BLOCK_SIZE_U64,
        RegionPriority::Critical,
        "Filesystem metadata",
    ));

    prioritizer.add_region(Region::new(
        3,
        BLOCK_SIZE_U64 * 2,
        BLOCK_SIZE_U64,
        RegionPriority::High,
        "Potential file data",
    ));

    prioritizer.add_region(Region::new(
        4,
        BLOCK_SIZE_U64 * 3,
        BLOCK_SIZE_U64,
        RegionPriority::Medium,
        "Unclassified region",
    ));

    println!("\nPrioritized regions:");

    let regions = prioritizer.prioritized_regions();

    for region in &regions {
        println!(
            "Region {} | Offset {} | Size {} | Priority {:?} | {}",
            region.id,
            region.start_offset,
            region.size,
            region.priority,
            region.reason
        );
    }

    // ==================================================
    // 2. READ HIGHEST-PRIORITY REGION
    // ==================================================

    println!("\nReading highest-priority region...");

    let mut reader = BatchReader::new(8)?;

    let region = &regions[0];

    let blocks = reader.read_blocks(
        DISK_IMAGE,
        region.start_offset,
        BLOCK_SIZE,
        1,
    )?;

    for block in &blocks {
        println!(
            "Block {} | Offset {} | Size {}",
            block.id,
            block.offset,
            block.size()
        );
    }

    // ==================================================
    // 3. BASELINE SIGNATURE SCANNING
    // ==================================================

    println!("\nScanning blocks for file signatures...");

    let extractor = FragmentExtractor::new();

    let mut total_candidates = 0usize;
    let mut total_fragments = 0usize;

    for block in &blocks {
        let candidates =
            filter::signature::scan_signatures(
                &block.data,
                DISK_IMAGE,
                region.id,
                block.id,
                block.offset,
            );

        total_candidates += candidates.len();

        for candidate in candidates {
            print_candidate(&candidate, "");

            // ==========================================
            // 4. PROVENANCE-PRESERVING FRAGMENT
            //    EXTRACTION
            // ==========================================

            match extractor.extract(
                &candidate,
                FRAGMENT_LENGTH,
            ) {
                Ok(fragment) => {
                    total_fragments += 1;
                    print_fragment(&fragment);
                }

                Err(error) => {
                    eprintln!(
                        "  Fragment extraction failed: {}",
                        error
                    );
                }
            }
        }
    }

    // ==================================================
    // 5. ARM64 NEON SIMD SCANNING
    // ==================================================

    println!("\nRunning ARM64 NEON SIMD scan...");

    let mut total_simd_candidates = 0usize;

    for block in &blocks {
        let candidates =
            filter::simd::scan_signatures_simd(
                &block.data,
                DISK_IMAGE,
                region.id,
                block.id,
                block.offset,
            );

        total_simd_candidates += candidates.len();

        for candidate in candidates {
            print_candidate(&candidate, "SIMD ");
        }
    }

    // ==================================================
    // 6. SUMMARY
    // ==================================================

    println!("\n==================");
    println!("Scan Summary");
    println!("==================");

    println!(
        "Regions analysed       : {}",
        regions.len()
    );

    println!(
        "Blocks scanned         : {}",
        blocks.len()
    );

    println!(
        "Baseline candidates    : {}",
        total_candidates
    );

    println!(
        "Fragments extracted    : {}",
        total_fragments
    );

    println!(
        "SIMD candidates        : {}",
        total_simd_candidates
    );

    println!(
        "\nStorage engine scan completed successfully."
    );

    Ok(())
}
