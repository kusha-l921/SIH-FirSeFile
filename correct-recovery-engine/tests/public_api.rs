use xfs_recovery_engine::{FileImage, MemImage, RecoveryEngine, RecoveryOptions, WalkMode};

#[test]
fn default_recovery_options_are_conservative() {
    let opts = RecoveryOptions::default();
    assert_eq!(opts.base_offset, 0);
    assert_eq!(opts.walk_mode, WalkMode::Strict);
    assert!(!opts.enable_experimental);

    let custom = RecoveryOptions::new()
        .with_base_offset(1024)
        .with_walk_mode(WalkMode::Salvage)
        .with_experimental(true);
    assert_eq!(custom.base_offset, 1024);
    assert_eq!(custom.walk_mode, WalkMode::Salvage);
    assert!(custom.enable_experimental);
}

fn build_valid_v4_sb() -> [u8; 512] {
    let mut sb = [0u8; 512];
    sb[0..4].copy_from_slice(&0x58465342u32.to_be_bytes()); // 'XFSB'
    sb[4..8].copy_from_slice(&4096u32.to_be_bytes()); // blocksize
    sb[8..16].copy_from_slice(&100_000u64.to_be_bytes()); // dblocks
    sb[16..24].copy_from_slice(&0u64.to_be_bytes()); // rblocks
    sb[24..32].copy_from_slice(&0u64.to_be_bytes()); // rextents
    sb[32..48].copy_from_slice(&[0x11; 16]); // uuid
    sb[48..56].copy_from_slice(&0u64.to_be_bytes()); // logstart
    sb[56..64].copy_from_slice(&128u64.to_be_bytes()); // rootino
    sb[64..72].copy_from_slice(&129u64.to_be_bytes()); // rbmino
    sb[72..80].copy_from_slice(&130u64.to_be_bytes()); // rsumino
    sb[80..84].copy_from_slice(&1u32.to_be_bytes()); // rextsize
    sb[84..88].copy_from_slice(&25_000u32.to_be_bytes()); // agblocks
    sb[88..92].copy_from_slice(&4u32.to_be_bytes()); // agcount
    sb[92..96].copy_from_slice(&0u32.to_be_bytes()); // rbmblocks
    sb[96..100].copy_from_slice(&1000u32.to_be_bytes()); // logblocks
    sb[100..102].copy_from_slice(&0x0004u16.to_be_bytes()); // version 4
    sb[102..104].copy_from_slice(&512u16.to_be_bytes()); // sectsize
    sb[104..106].copy_from_slice(&256u16.to_be_bytes()); // inodesize
    sb[106..108].copy_from_slice(&16u16.to_be_bytes()); // inopblock
    sb[120] = 12; // blocklog (4096 = 2^12)
    sb[121] = 9; // sectlog (512 = 2^9)
    sb[122] = 8; // inodelog (256 = 2^8)
    sb[123] = 4; // inopblog (16 = 2^4)
    sb[124] = 15; // agblklog (25000 <= 2^15 = 32768)
    sb
}

#[test]
fn public_api_opens_in_memory_image() {
    let sb_bytes = build_valid_v4_sb();
    let image = MemImage::new(&sb_bytes);
    let options = RecoveryOptions::default();
    let engine =
        RecoveryEngine::open(image, options).expect("open recovery engine on in-memory image");

    assert!(!engine.fs_info().is_v5);
    assert_eq!(engine.fs_info().block_size, 4096);
    assert_eq!(engine.fs_info().sector_size, 512);
    assert_eq!(engine.fs_info().ag_count, 4);
    assert_eq!(engine.options().base_offset, 0);
}

#[test]
fn rejects_invalid_base_offset_on_open() {
    let data = vec![0u8; 4096];
    let image = MemImage::new(&data);
    let options = RecoveryOptions::default().with_base_offset(100_000);
    assert!(RecoveryEngine::open(image, options).is_err());
}

#[test]
#[ignore]
fn public_api_smoke_test_against_real_fixture() {
    let Some(image_path) = std::env::var_os("XRE_TEST_IMAGE") else {
        eprintln!("skipped: set XRE_TEST_IMAGE=<raw xfs image path>");
        return;
    };

    let image = FileImage::open(&image_path).expect("open image");
    let options = RecoveryOptions::default();
    let mut engine = RecoveryEngine::open(image, options).expect("open recovery engine");

    let fs_info = engine.fs_info();
    assert!(fs_info.block_size >= 512);
    assert!(fs_info.ag_count >= 1);
    assert!(fs_info.total_bytes > 0);

    let report = engine.collect_candidates().expect("collect candidates");
    assert!(report.summary.total_inodes_scanned > 0);

    for candidate in &report.candidates {
        assert!(candidate.ino > 0);
        // Experimental candidates must NOT be present when experimental is disabled
        assert!(!candidate.is_experimental);

        if candidate.observed_extent_bytes > 0 {
            let content = engine
                .read_candidate_content(candidate)
                .expect("read candidate content");
            assert!(!content.is_empty());
        }
    }
}
