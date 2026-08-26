// Tests for the acquisition crate (Part 3).
// Sources verified against param-part3 branch behaviour.

use acquisition::{
    Block, Candidate, FileType, Fragment, FragmentExtractor, RawFragment, Region, RegionPriority,
    RegionPrioritizer, scan_signatures, scan_signatures_simd,
};

// -----------------------------------------------------------------------
// Block
// -----------------------------------------------------------------------

#[test]
fn block_stores_id_offset_data() {
    let b = Block::new(7, 4096, vec![0xAA; 512]);
    assert_eq!(b.id, 7);
    assert_eq!(b.offset, 4096);
    assert_eq!(b.size(), 512);
    assert_eq!(b.data[0], 0xAA);
}

// -----------------------------------------------------------------------
// RegionPrioritizer
// -----------------------------------------------------------------------

#[test]
fn prioritizer_orders_highest_first() {
    let mut p = RegionPrioritizer::new();
    p.add_region(Region::new(1, 0,    4096, RegionPriority::Low,      "low"));
    p.add_region(Region::new(2, 4096, 4096, RegionPriority::Critical, "critical"));
    p.add_region(Region::new(3, 8192, 4096, RegionPriority::Medium,   "medium"));
    p.add_region(Region::new(4, 12288,4096, RegionPriority::High,     "high"));

    let ordered = p.prioritized_regions();
    assert_eq!(ordered[0].priority, RegionPriority::Critical);
    assert_eq!(ordered[1].priority, RegionPriority::High);
    assert_eq!(ordered[2].priority, RegionPriority::Medium);
    assert_eq!(ordered[3].priority, RegionPriority::Low);
}

#[test]
fn prioritizer_empty_returns_empty() {
    let mut p = RegionPrioritizer::new();
    assert!(p.prioritized_regions().is_empty());
}

// -----------------------------------------------------------------------
// Signature scanner
// -----------------------------------------------------------------------

fn make_block(payload: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 4096];
    let len = payload.len().min(4096);
    data[..len].copy_from_slice(&payload[..len]);
    data
}

#[test]
fn scan_finds_jpeg_signature() {
    let mut data = make_block(b"\xFF\xD8\xFF\xE0 rest of jpeg header");
    let candidates = scan_signatures(&data, "test.img", 1, 0, 0);
    assert!(!candidates.is_empty());
    assert_eq!(candidates[0].file_type, FileType::Jpeg);
    assert_eq!(candidates[0].absolute_offset, 0);

    // Place a second JPEG at offset 100
    data[100..103].copy_from_slice(b"\xFF\xD8\xFF");
    let candidates = scan_signatures(&data, "test.img", 1, 0, 0);
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[1].absolute_offset, 100);
}

#[test]
fn scan_finds_png_signature() {
    let data = make_block(b"\x89PNG\r\n\x1a\n");
    let candidates = scan_signatures(&data, "img", 1, 0, 0);
    assert_eq!(candidates[0].file_type, FileType::Png);
}

#[test]
fn scan_finds_pdf_signature() {
    let data = make_block(b"%PDF-1.4");
    let candidates = scan_signatures(&data, "img", 1, 0, 0);
    assert_eq!(candidates[0].file_type, FileType::Pdf);
}

#[test]
fn scan_finds_zip_signature() {
    let data = make_block(b"PK\x03\x04");
    let candidates = scan_signatures(&data, "img", 1, 0, 0);
    assert_eq!(candidates[0].file_type, FileType::Zip);
}

#[test]
fn scan_empty_block_returns_no_candidates() {
    let data = vec![0u8; 4096];
    assert!(scan_signatures(&data, "img", 1, 0, 0).is_empty());
}

#[test]
fn scan_preserves_block_offset_in_absolute_offset() {
    let data = make_block(b"%PDF-1.4");
    // block starts at byte 8192 in the image
    let candidates = scan_signatures(&data, "img", 1, 0, 8192);
    assert_eq!(candidates[0].absolute_offset, 8192);
    assert_eq!(candidates[0].block_offset, 8192);
}

#[test]
fn scan_results_sorted_by_absolute_offset() {
    let mut data = vec![0u8; 4096];
    data[200..204].copy_from_slice(b"PK\x03\x04");
    data[50..53].copy_from_slice(b"\xFF\xD8\xFF");
    let candidates = scan_signatures(&data, "img", 1, 0, 0);
    for w in candidates.windows(2) {
        assert!(w[0].absolute_offset <= w[1].absolute_offset);
    }
}

// -----------------------------------------------------------------------
// SIMD scanner (result must match baseline on all platforms)
// -----------------------------------------------------------------------

#[test]
fn simd_scan_matches_baseline() {
    let mut data = vec![0u8; 4096];
    data[0..3].copy_from_slice(b"\xFF\xD8\xFF");
    data[512..516].copy_from_slice(b"\x89PNG");
    data[1024..1028].copy_from_slice(b"%PDF");

    let baseline = scan_signatures(&data, "img", 1, 0, 0);
    let simd     = scan_signatures_simd(&data, "img", 1, 0, 0);

    assert_eq!(baseline.len(), simd.len(), "SIMD and baseline must find same count");
    for (b, s) in baseline.iter().zip(simd.iter()) {
        assert_eq!(b.absolute_offset, s.absolute_offset);
        assert_eq!(b.file_type, s.file_type);
    }
}

// -----------------------------------------------------------------------
// FragmentExtractor
// -----------------------------------------------------------------------

fn make_candidate(block_offset: u64, sig_offset_in_block: usize, data: Vec<u8>) -> Candidate {
    Candidate {
        source: "test.img".to_string(),
        region_id: 1,
        block_id: 0,
        block_offset,
        absolute_offset: block_offset + sig_offset_in_block as u64,
        file_type: FileType::Pdf,
        detection_method: "Signature".to_string(),
        confidence: 1.0,
        block_data: data,
    }
}

#[test]
fn extractor_produces_correct_fragment() {
    let mut block = vec![0u8; 64];
    block[10..14].copy_from_slice(b"%PDF");
    let candidate = make_candidate(0, 10, block.clone());

    let extractor = FragmentExtractor::new();
    let frag = extractor.extract(&candidate, 4).unwrap();

    assert_eq!(frag.data, b"%PDF");
    assert_eq!(frag.length, 4);
    assert_eq!(frag.absolute_offset, 10);
    assert_eq!(frag.block_offset, 0);
    assert_eq!(frag.source, "test.img");
    assert_eq!(frag.sha256.len(), 64); // hex SHA-256
}

#[test]
fn extractor_zero_length_is_error() {
    let block = vec![0u8; 64];
    let candidate = make_candidate(0, 0, block);
    let extractor = FragmentExtractor::new();
    assert!(extractor.extract(&candidate, 0).is_err());
}

#[test]
fn extractor_overflow_beyond_block_is_error() {
    let block = vec![0u8; 16];
    let candidate = make_candidate(0, 10, block);
    let extractor = FragmentExtractor::new();
    assert!(extractor.extract(&candidate, 10).is_err());
}

#[test]
fn extractor_preserves_block_offset_in_fragment() {
    let mut block = vec![0u8; 128];
    block[0..4].copy_from_slice(b"\x89PNG");
    // block starts at 8192 in the image
    let candidate = make_candidate(8192, 0, block);
    let extractor = FragmentExtractor::new();
    let frag = extractor.extract(&candidate, 4).unwrap();
    assert_eq!(frag.absolute_offset, 8192);
    assert_eq!(frag.block_offset, 8192);
}

// -----------------------------------------------------------------------
// RawFragment contract
// -----------------------------------------------------------------------

#[test]
fn raw_fragment_from_fragment_preserves_all_fields() {
    let frag = Fragment {
        source: "disk.img".to_string(),
        region_id: 3,
        block_id: 7,
        block_offset: 28672,
        absolute_offset: 28680,
        length: 8,
        sha256: "abc123".to_string(),
        data: vec![1, 2, 3, 4, 5, 6, 7, 8],
    };

    let raw = RawFragment::from_fragment(frag);
    assert_eq!(raw.source, "disk.img");
    assert_eq!(raw.region_id, 3);
    assert_eq!(raw.block_id, 7);
    assert_eq!(raw.block_offset, 28672);
    assert_eq!(raw.absolute_offset, 28680);
    assert_eq!(raw.length, 8);
    assert_eq!(raw.sha256, "abc123");
    assert_eq!(raw.data, vec![1, 2, 3, 4, 5, 6, 7, 8]);
}

// -----------------------------------------------------------------------
// Read-only guarantee: BatchReader must not open files for writing
// -----------------------------------------------------------------------

#[test]
fn batch_reader_source_has_no_write_path() {
    // Verify the batch_reader source does not contain write-capable tokens.
    let src = include_str!("../src/storage/batch_reader.rs");
    for token in ["write(", "write_all", "io::Write", "truncate(", "set_len", "append("] {
        assert!(
            !src.contains(token),
            "forbidden write token {token:?} found in batch_reader.rs"
        );
    }
    assert!(src.contains(".read(true)"), "batch_reader must open files read-only");
}
