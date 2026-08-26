use std::io::Write;
use xfs_recovery_engine::{
    CandidateClass, CandidateHandoff, ExtentMap, ExtentState, FileExtent, FileImage, FileType,
    InodeLocation, MemImage, RecoveryCandidate, RecoveryConfidence, RecoveryEngine, RecoveryMethod,
    RecoveryOptions, Superblock, Timestamp, sha256_candidate_content, sha256_hex, sha256_image,
};

fn build_sample_sb() -> Vec<u8> {
    let mut sb_bytes = vec![0u8; 512];
    sb_bytes[0..4].copy_from_slice(&0x58465342u32.to_be_bytes()); // 'XFSB'
    sb_bytes[4..8].copy_from_slice(&4096u32.to_be_bytes()); // blocksize
    sb_bytes[8..16].copy_from_slice(&100_000u64.to_be_bytes()); // dblocks
    sb_bytes[56..64].copy_from_slice(&128u64.to_be_bytes()); // rootino
    sb_bytes[64..72].copy_from_slice(&129u64.to_be_bytes()); // rbmino
    sb_bytes[72..80].copy_from_slice(&130u64.to_be_bytes()); // rsumino
    sb_bytes[80..84].copy_from_slice(&1u32.to_be_bytes()); // rextsize
    sb_bytes[84..88].copy_from_slice(&25_000u32.to_be_bytes()); // agblocks
    sb_bytes[88..92].copy_from_slice(&4u32.to_be_bytes()); // agcount

    sb_bytes[100..102].copy_from_slice(&0x0004u16.to_be_bytes()); // v4
    sb_bytes[102..104].copy_from_slice(&512u16.to_be_bytes()); // sectsize
    sb_bytes[104..106].copy_from_slice(&256u16.to_be_bytes()); // inodesize
    sb_bytes[106..108].copy_from_slice(&16u16.to_be_bytes()); // inopblock
    sb_bytes[120] = 12; // blocklog
    sb_bytes[121] = 9; // sectlog
    sb_bytes[122] = 8; // inodelog
    sb_bytes[123] = 4; // inopblog
    sb_bytes[124] = 15; // agblklog
    sb_bytes
}

#[test]
fn sha256_known_nist_vectors() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(b"hello world"),
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
    assert_eq!(
        sha256_hex(b"123456789"),
        "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225"
    );
    assert_eq!(
        sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn sha256_large_streaming_matches_direct_digest() {
    // 512 KiB repeating pattern
    let pattern = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+";
    let mut large_data = Vec::with_capacity(512 * 1024);
    while large_data.len() < 512 * 1024 {
        large_data.extend_from_slice(pattern);
    }
    large_data.truncate(512 * 1024);

    let expected = sha256_hex(&large_data);
    let mut mem_image = MemImage::new(&large_data);
    let streamed = sha256_image(&mut mem_image).expect("streamed sha256");

    assert_eq!(streamed, expected);
    assert_eq!(streamed.len(), 64);
    assert!(
        streamed
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
    );
}

#[test]
fn sha256_file_image_streaming() {
    let temp_dir = std::env::temp_dir();
    let temp_file_path = temp_dir.join(format!("xre_test_hash_{}.bin", std::process::id()));

    let content = b"Forensic disk image sample payload for SHA-256 verification\n";
    {
        let mut file = std::fs::File::create(&temp_file_path).expect("create temp file");
        file.write_all(content).expect("write temp file");
        file.sync_all().expect("sync temp file");
    }

    let mut file_image = FileImage::open(&temp_file_path).expect("open temp file as FileImage");
    let computed_hash = sha256_image(&mut file_image).expect("compute sha256 of FileImage");
    let expected_hash = sha256_hex(content);

    let _ = std::fs::remove_file(&temp_file_path);

    assert_eq!(computed_hash, expected_hash);
}

#[test]
fn sha256_candidate_content_with_sparse_holes() {
    // Create in-memory filesystem with 4096-byte blocks
    let sb_bytes = build_sample_sb();
    let (_, geo) = Superblock::parse_bytes(&sb_bytes).expect("parse geometry");

    // Construct image buffer with block 10 containing "AAAA..." and block 12 containing "BBBB..."
    let mut image_data = vec![0u8; 100 * 4096];
    image_data[0..512].copy_from_slice(&sb_bytes);
    image_data[10 * 4096..11 * 4096].fill(b'A');
    image_data[12 * 4096..13 * 4096].fill(b'B');

    // Candidate has 3 logical blocks:
    // Block 0 -> Physical Block 10 ('A' * 4096)
    // Block 1 -> Sparse hole (zeros * 4096)
    // Block 2 -> Physical Block 12 ('B' * 4096)
    let candidate = RecoveryCandidate {
        ino: 500,
        location: InodeLocation {
            ino: 500,
            ag_number: 0,
            ag_block: 16,
            slot: 0,
            byte_offset: 65536,
        },
        ag_number: 0,
        file_type: FileType::RegularFile,
        mode: 0o100644,
        permissions: 0o644,
        uid: 1000,
        gid: 1000,
        nlink: 1,
        generation: 1,
        atime: Timestamp { sec: 100, nsec: 0 },
        mtime: Timestamp { sec: 100, nsec: 0 },
        ctime: Timestamp { sec: 100, nsec: 0 },
        crtime: None,
        original_size: Some(3 * 4096),
        observed_extent_bytes: 2 * 4096,
        extents: ExtentMap {
            extents: vec![
                FileExtent {
                    logical_start: 0,
                    physical_start: 10,
                    block_count: 1,
                    state: ExtentState::Normal,
                },
                FileExtent {
                    logical_start: 2,
                    physical_start: 12,
                    block_count: 1,
                    state: ExtentState::Normal,
                },
            ],
            issues: Vec::new(),
        },
        method: RecoveryMethod::XfsUnlinkedChain,
        candidate_class: CandidateClass::UnlinkedChainResidue,
        confidence: RecoveryConfidence::High,
        evidence: Vec::new(),
        issues: Vec::new(),
        is_experimental: false,
    };

    let mut expected_content = Vec::with_capacity(3 * 4096);
    expected_content.extend_from_slice(&[b'A'; 4096]);
    expected_content.extend_from_slice(&[0u8; 4096]); // hole
    expected_content.extend_from_slice(&[b'B'; 4096]);

    let expected_hash = sha256_hex(&expected_content);

    let mut mem_image = MemImage::new(&image_data);
    let computed_hash = sha256_candidate_content(&mut mem_image, 0, &geo, &candidate)
        .expect("compute candidate sha256");

    assert_eq!(computed_hash.sha256, expected_hash);
    assert_eq!(computed_hash.hashed_bytes, 3 * 4096);
    assert!(computed_hash.is_exact_logical_size);

    let handoff = CandidateHandoff::new(&candidate, Some(computed_hash));
    assert_eq!(handoff.content_sha256, Some(expected_hash));
    assert!(handoff.content_hash_exact);
    assert_eq!(handoff.ino, 500);
    assert_eq!(handoff.source_location, candidate.location);
    assert_eq!(handoff.original_size, Some(3 * 4096));
    assert_eq!(handoff.observed_extent_bytes, 2 * 4096);
    assert!(!handoff.is_experimental);
}

#[test]
fn sha256_candidate_content_with_unknown_original_size() {
    let sb_bytes = build_sample_sb();
    let (_, geo) = Superblock::parse_bytes(&sb_bytes).expect("parse geometry");

    let mut image_data = vec![0u8; 100 * 4096];
    image_data[0..512].copy_from_slice(&sb_bytes);
    image_data[15 * 4096..16 * 4096].fill(b'Z');

    let candidate = RecoveryCandidate {
        ino: 502,
        location: InodeLocation {
            ino: 502,
            ag_number: 0,
            ag_block: 16,
            slot: 2,
            byte_offset: 65536 + 2 * 256,
        },
        ag_number: 0,
        file_type: FileType::RegularFile,
        mode: 0o100644,
        permissions: 0o644,
        uid: 1000,
        gid: 1000,
        nlink: 0,
        generation: 2,
        atime: Timestamp { sec: 200, nsec: 0 },
        mtime: Timestamp { sec: 200, nsec: 0 },
        ctime: Timestamp { sec: 200, nsec: 0 },
        crtime: None,
        original_size: None, // Deleted file, size cleared by XFS
        observed_extent_bytes: 4096,
        extents: ExtentMap {
            extents: vec![FileExtent {
                logical_start: 0,
                physical_start: 15,
                block_count: 1,
                state: ExtentState::Normal,
            }],
            issues: Vec::new(),
        },
        method: RecoveryMethod::XfsResidualExtents,
        candidate_class: CandidateClass::FreedWithResidualExtents,
        confidence: RecoveryConfidence::Medium,
        evidence: Vec::new(),
        issues: Vec::new(),
        is_experimental: true,
    };

    let mut mem_image = MemImage::new(&image_data);
    let computed_hash = sha256_candidate_content(&mut mem_image, 0, &geo, &candidate)
        .expect("compute candidate sha256");

    let expected_stream_hash = sha256_hex(&[b'Z'; 4096]);
    assert_eq!(computed_hash.sha256, expected_stream_hash);
    assert_eq!(computed_hash.hashed_bytes, 4096);
    assert!(!computed_hash.is_exact_logical_size);

    let handoff = CandidateHandoff::new(&candidate, Some(computed_hash));
    assert_eq!(handoff.content_sha256, Some(expected_stream_hash));
    assert!(!handoff.content_hash_exact); // Not exact because original_size is None
    assert_eq!(handoff.ino, 502);
    assert_eq!(handoff.source_location, candidate.location);
    assert_eq!(handoff.original_size, None);
    assert_eq!(handoff.observed_extent_bytes, 4096);
    assert!(handoff.is_experimental);
}

#[test]
fn sha256_candidate_zero_size() {
    let sb_bytes = build_sample_sb();
    let (_, geo) = Superblock::parse_bytes(&sb_bytes).expect("parse geometry");

    let candidate = RecoveryCandidate {
        ino: 501,
        location: InodeLocation {
            ino: 501,
            ag_number: 0,
            ag_block: 16,
            slot: 0,
            byte_offset: 65536,
        },
        ag_number: 0,
        file_type: FileType::RegularFile,
        mode: 0o100644,
        permissions: 0o644,
        uid: 1000,
        gid: 1000,
        nlink: 0,
        generation: 1,
        atime: Timestamp { sec: 100, nsec: 0 },
        mtime: Timestamp { sec: 100, nsec: 0 },
        ctime: Timestamp { sec: 100, nsec: 0 },
        crtime: None,
        original_size: None,
        observed_extent_bytes: 0,
        extents: ExtentMap {
            extents: Vec::new(),
            issues: Vec::new(),
        },
        method: RecoveryMethod::XfsResidualExtents,
        candidate_class: CandidateClass::FreedWithResidualExtents,
        confidence: RecoveryConfidence::Medium,
        evidence: Vec::new(),
        issues: Vec::new(),
        is_experimental: true,
    };

    let mut mem_image = MemImage::new(&sb_bytes);
    let hash = sha256_candidate_content(&mut mem_image, 0, &geo, &candidate)
        .expect("hash zero-size candidate");

    assert_eq!(
        hash.sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(hash.hashed_bytes, 0);
    assert!(!hash.is_exact_logical_size);

    let handoff = CandidateHandoff::new(&candidate, Some(hash));
    assert_eq!(
        handoff.content_sha256,
        Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string())
    );
    assert!(!handoff.content_hash_exact);
    assert_eq!(handoff.source_location, candidate.location);
    assert!(handoff.is_experimental);
}

#[test]
#[ignore]
fn sha256_candidate_content_matches_real_fixture() {
    let Some(image_path) = std::env::var_os("XRE_TEST_IMAGE") else {
        eprintln!("skipped: set XRE_TEST_IMAGE=<raw xfs image path>");
        return;
    };

    let image = FileImage::open(&image_path).expect("open image");
    let options = RecoveryOptions::default();
    let mut engine = RecoveryEngine::open(image, options).expect("open engine");

    let image_hash = engine.sha256_image().expect("hash whole image");
    assert_eq!(image_hash.len(), 64);

    let report = engine.collect_candidates().expect("collect candidates");
    for candidate in &report.candidates {
        if candidate.observed_extent_bytes > 0 {
            let content_hash = engine
                .sha256_candidate_content(candidate)
                .expect("hash candidate");
            assert_eq!(content_hash.sha256.len(), 64);

            let handoff = engine
                .candidate_handoff(candidate)
                .expect("candidate handoff");
            assert_eq!(handoff.content_sha256, Some(content_hash.sha256));
            assert_eq!(handoff.source_location, candidate.location);
            assert_eq!(handoff.is_experimental, candidate.is_experimental);
        }
    }
}
