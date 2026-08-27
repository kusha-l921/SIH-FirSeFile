use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use xfs_recovery_engine::{
    CrcStatus, ExtentState, FileImage, FileType, RecoveryCandidate, RecoveryConfidence,
    RecoveryEngine, RecoveryEvidence, RecoveryMethod, RecoveryOptions, RejectionReason,
    WalkMode,
};

fn escape_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn file_type_str(ft: FileType) -> &'static str {
    match ft {
        FileType::RegularFile => "regular_file",
        FileType::Directory => "directory",
        FileType::Symlink => "symlink",
        FileType::BlockDevice => "block_device",
        FileType::CharacterDevice => "character_device",
        FileType::Fifo => "fifo",
        FileType::Socket => "socket",
        FileType::Unallocated => "unallocated",
        FileType::Unknown(_) => "unknown",
    }
}

fn recovery_method_str(m: RecoveryMethod) -> &'static str {
    match m {
        RecoveryMethod::XfsUnlinkedChain => "xfs_unlinked_chain",
        RecoveryMethod::XfsResidualExtents => "xfs_residual_extents",
        RecoveryMethod::XfsZeroLinkAnomaly => "xfs_zero_link_anomaly",
    }
}

fn confidence_str(c: RecoveryConfidence) -> &'static str {
    match c {
        RecoveryConfidence::High => "high",
        RecoveryConfidence::Medium => "medium",
        RecoveryConfidence::Low => "low",
    }
}

fn rejection_reason_str(r: RejectionReason) -> &'static str {
    match r {
        RejectionReason::LiveAllocatedInode => "live_allocated_inode",
        RejectionReason::InvalidDinode => "invalid_dinode",
        RejectionReason::InvalidExtentMap => "invalid_extent_map",
        RejectionReason::InvalidInodeLocation => "invalid_inode_location",
        RejectionReason::CorruptUnlinkedChain => "corrupt_unlinked_chain",
        RejectionReason::ResidualInterpretationFailed => "residual_interpretation_failed",
        RejectionReason::UnsupportedFormat => "unsupported_format",
        RejectionReason::InsufficientEvidence => "insufficient_evidence",
    }
}

fn evidence_str(ev: &RecoveryEvidence) -> String {
    match ev {
        RecoveryEvidence::UnlinkedChain { bucket, position } => {
            format!("unlinked_chain(bucket={bucket}, pos={position})")
        }
        RecoveryEvidence::FreeInodeSlot => "free_inode_slot".to_string(),
        RecoveryEvidence::FinobtVerified => "finobt_verified".to_string(),
        RecoveryEvidence::ValidDinodeCore => "valid_dinode_core".to_string(),
        RecoveryEvidence::ResidualExtentsFound { count } => {
            format!("residual_extents_found(count={count})")
        }
        RecoveryEvidence::ValidExtentBounds => "valid_extent_bounds".to_string(),
        RecoveryEvidence::ZeroLinkOnAllocated => "zero_link_on_allocated".to_string(),
        RecoveryEvidence::CrcVerified => "crc_verified".to_string(),
        RecoveryEvidence::CrcMismatch => "crc_mismatch".to_string(),
        RecoveryEvidence::NonZeroGeneration(g) => format!("nonzero_generation({g})"),
        RecoveryEvidence::ValidTimestamps => "valid_timestamps".to_string(),
    }
}

fn candidate_to_json(
    engine: &mut RecoveryEngine<FileImage>,
    c: &RecoveryCandidate,
) -> String {
    let content_hash_res = engine.sha256_candidate_content(c);
    let (sha256_val, hash_exact) = match &content_hash_res {
        Ok(ch) => (Some(ch.sha256.clone()), ch.is_exact_logical_size),
        Err(_) => (None, false),
    };

    let crtime_str = match &c.crtime {
        Some(t) => format!("{{\"sec\":{},\"nsec\":{}}}", t.sec, t.nsec),
        None => "null".to_string(),
    };

    let orig_size_str = match c.original_size {
        Some(s) => s.to_string(),
        None => "null".to_string(),
    };

    let sha256_str = match sha256_val {
        Some(h) => format!("\"{}\"", escape_json_str(&h)),
        None => "null".to_string(),
    };

    let mut extents_json = Vec::new();
    for e in &c.extents.extents {
        let state_str = match e.state {
            ExtentState::Normal => "normal",
            ExtentState::Unwritten => "unwritten",
        };
        extents_json.push(format!(
            "{{\"logical_start\":{},\"physical_start\":{},\"block_count\":{},\"state\":\"{}\"}}",
            e.logical_start, e.physical_start, e.block_count, state_str
        ));
    }

    let mut evidence_json = Vec::new();
    for ev in &c.evidence {
        evidence_json.push(format!("\"{}\"", escape_json_str(&evidence_str(ev))));
    }

    let mut issues_json = Vec::new();
    for iss in &c.issues {
        issues_json.push(format!("\"{}\"", escape_json_str(iss)));
    }

    format!(
        "{{\"ino\":{},\"source_location\":{{\"ino\":{},\"ag_number\":{},\"ag_block\":{},\"slot\":{},\"byte_offset\":{}}},\"ag_number\":{},\"file_type\":\"{}\",\"mode\":{},\"permissions\":{},\"uid\":{},\"gid\":{},\"nlink\":{},\"generation\":{},\"atime\":{{\"sec\":{},\"nsec\":{}}},\"mtime\":{{\"sec\":{},\"nsec\":{}}},\"ctime\":{{\"sec\":{},\"nsec\":{}}},\"crtime\":{},\"original_size\":{},\"observed_extent_bytes\":{},\"extents\":[{}],\"recovery_method\":\"{}\",\"candidate_class\":\"{:?}\",\"confidence\":\"{}\",\"evidence\":[{}],\"issues\":[{}],\"is_experimental\":{},\"content_sha256\":{},\"content_hash_exact\":{}}}",
        c.ino,
        c.location.ino,
        c.location.ag_number,
        c.location.ag_block,
        c.location.slot,
        c.location.byte_offset,
        c.ag_number,
        file_type_str(c.file_type),
        c.mode,
        c.permissions,
        c.uid,
        c.gid,
        c.nlink,
        c.generation,
        c.atime.sec,
        c.atime.nsec,
        c.mtime.sec,
        c.mtime.nsec,
        c.ctime.sec,
        c.ctime.nsec,
        crtime_str,
        orig_size_str,
        c.observed_extent_bytes,
        extents_json.join(","),
        recovery_method_str(c.method),
        c.candidate_class,
        confidence_str(c.confidence),
        evidence_json.join(","),
        issues_json.join(","),
        c.is_experimental,
        sha256_str,
        hash_exact
    )
}

fn run_scan(
    image_path: &Path,
    options: RecoveryOptions,
    json_mode: bool,
) -> Result<(), String> {
    let image = FileImage::open(image_path)
        .map_err(|e| format!("Failed to open image '{}': {}", image_path.display(), e))?;

    let mut engine = RecoveryEngine::open(image, options)
        .map_err(|e| format!("Failed to initialize RecoveryEngine on '{}': {}", image_path.display(), e))?;

    let report = engine
        .collect_candidates()
        .map_err(|e| format!("Candidate collection failed: {}", e))?;

    let fs_info = engine.fs_info().clone();
    let uuid_hex: String = fs_info.uuid.iter().map(|b| format!("{b:02x}")).collect();

    let crc_str = match fs_info.crc_status {
        CrcStatus::Verified => "verified",
        CrcStatus::Mismatch { .. } => "mismatch",
        CrcStatus::NotApplicable => "not_applicable",
    };

    if json_mode {
        let mut candidates_json = Vec::new();
        for c in &report.candidates {
            candidates_json.push(candidate_to_json(&mut engine, c));
        }

        let mut rejections_json = Vec::new();
        for r in &report.rejections {
            let ino_str = match r.ino {
                Some(i) => i.to_string(),
                None => "null".to_string(),
            };
            rejections_json.push(format!(
                "{{\"ino\":{},\"ag_number\":{},\"reason\":\"{}\",\"details\":\"{}\"}}",
                ino_str,
                r.ag_number,
                rejection_reason_str(r.reason),
                escape_json_str(&r.details)
            ));
        }

        let json = format!(
            "{{\"is_valid\":true,\"fs_info\":{{\"version_raw\":{},\"is_v5\":{},\"block_size\":{},\"sector_size\":{},\"inode_size\":{},\"ag_count\":{},\"ag_blocks\":{},\"dblocks\":{},\"total_bytes\":{},\"uuid\":\"{}\",\"crc_status\":\"{}\",\"root_inode\":{},\"has_finobt\":{},\"has_sparse_inobt\":{},\"has_nrext64\":{}}},\"summary\":{{\"total_inodes_scanned\":{},\"unlinked_chain_candidates\":{},\"residual_extent_candidates\":{},\"zero_link_candidates\":{},\"total_candidates\":{},\"total_rejections\":{},\"high_confidence\":{},\"medium_confidence\":{},\"low_confidence\":{}}},\"candidates\":[{}],\"rejections\":[{}]}}",
            fs_info.version_raw,
            fs_info.is_v5,
            fs_info.block_size,
            fs_info.sector_size,
            fs_info.inode_size,
            fs_info.ag_count,
            fs_info.ag_blocks,
            fs_info.dblocks,
            fs_info.total_bytes,
            uuid_hex,
            crc_str,
            fs_info.root_inode,
            fs_info.has_finobt,
            fs_info.has_sparse_inobt,
            fs_info.has_nrext64,
            report.summary.total_inodes_scanned,
            report.summary.unlinked_chain_candidates,
            report.summary.residual_extent_candidates,
            report.summary.zero_link_candidates,
            report.summary.total_candidates,
            report.summary.total_rejections,
            report.summary.high_confidence,
            report.summary.medium_confidence,
            report.summary.low_confidence,
            candidates_json.join(","),
            rejections_json.join(",")
        );
        println!("{json}");
    } else {
        println!("=======================================================");
        println!("            XFS RECOVERY ENGINE REPORT");
        println!("=======================================================");
        println!("Image:               {}", image_path.display());
        println!("Version:             {} (v5: {})", fs_info.version_raw, fs_info.is_v5);
        println!("Block Size:          {} bytes", fs_info.block_size);
        println!("Sector Size:         {} bytes", fs_info.sector_size);
        println!("Inode Size:          {} bytes", fs_info.inode_size);
        println!("AG Count:            {}", fs_info.ag_count);
        println!("Total Size:          {} bytes", fs_info.total_bytes);
        println!("UUID:                {}", uuid_hex);
        println!("CRC Status:          {}", crc_str);
        println!("-------------------------------------------------------");
        println!("Total Inodes Scanned: {}", report.summary.total_inodes_scanned);
        println!("Total Candidates:     {}", report.summary.total_candidates);
        println!("  - Unlinked Chain:   {}", report.summary.unlinked_chain_candidates);
        println!("  - Residual Extents: {}", report.summary.residual_extent_candidates);
        println!("  - Zero Link:        {}", report.summary.zero_link_candidates);
        println!("Total Rejections:     {}", report.summary.total_rejections);
        println!("-------------------------------------------------------");
        println!("CANDIDATES:");
        for (i, c) in report.candidates.iter().enumerate() {
            println!(
                " [{}] Inode {} | {:?} | {} | size: {:?} (observed: {} B) | conf: {:?} | experimental: {}",
                i + 1,
                c.ino,
                c.file_type,
                recovery_method_str(c.method),
                c.original_size,
                c.observed_extent_bytes,
                c.confidence,
                c.is_experimental
            );
            println!(
                "     Location: AG {} block {} slot {} (0x{:x})",
                c.location.ag_number,
                c.location.ag_block,
                c.location.slot,
                c.location.byte_offset
            );
            if let Ok(ch) = engine.sha256_candidate_content(c) {
                println!("     SHA-256:  {} (exact: {})", ch.sha256, ch.is_exact_logical_size);
            }
        }
        println!("=======================================================");
    }

    Ok(())
}

fn run_cat_candidate(
    image_path: &Path,
    target_ino: u64,
    options: RecoveryOptions,
) -> Result<(), String> {
    let image = FileImage::open(image_path)
        .map_err(|e| format!("Failed to open image '{}': {}", image_path.display(), e))?;

    let mut engine = RecoveryEngine::open(image, options)
        .map_err(|e| format!("Failed to initialize RecoveryEngine: {}", e))?;

    let report = engine
        .collect_candidates()
        .map_err(|e| format!("Candidate collection failed: {}", e))?;

    let candidate = report
        .candidates
        .iter()
        .find(|c| c.ino == target_ino)
        .ok_or_else(|| format!("Candidate inode {} not found in image", target_ino))?;

    let content = engine
        .read_candidate_content(candidate)
        .map_err(|e| format!("Failed to read content for inode {}: {}", target_ino, e))?;

    io::stdout()
        .write_all(&content)
        .map_err(|e| format!("Failed to write to stdout: {}", e))?;
    io::stdout().flush().map_err(|e| format!("Failed to flush stdout: {}", e))?;

    Ok(())
}

fn run_dump_candidates(
    image_path: &Path,
    output_dir: &Path,
    options: RecoveryOptions,
) -> Result<(), String> {
    fs::create_dir_all(output_dir)
        .map_err(|e| format!("Failed to create output directory '{}': {}", output_dir.display(), e))?;

    let image = FileImage::open(image_path)
        .map_err(|e| format!("Failed to open image '{}': {}", image_path.display(), e))?;

    let mut engine = RecoveryEngine::open(image, options)
        .map_err(|e| format!("Failed to initialize RecoveryEngine: {}", e))?;

    let report = engine
        .collect_candidates()
        .map_err(|e| format!("Candidate collection failed: {}", e))?;

    for c in &report.candidates {
        if let Ok(content) = engine.read_candidate_content(c) {
            let out_file = output_dir.join(format!("recovered_ino_{}.bin", c.ino));
            let _ = fs::write(&out_file, &content);
        }
    }

    Ok(())
}

fn print_usage() {
    eprintln!("Usage: xfs-recovery-engine <command> [options]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  scan <image>              Scan XFS image for recovery candidates");
    eprintln!("  cat-candidate <image> <ino> Stream candidate raw content to stdout");
    eprintln!("  dump-candidates <image> <out_dir> Save all candidates to output directory");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --json                    Output in JSON format");
    eprintln!("  --experimental            Enable experimental recovery methods (e.g. residual extents)");
    eprintln!("  --base-offset <bytes>     Filesystem base offset in image (default: 0)");
    eprintln!("  --walk-mode <strict|salvage> Inode discovery walk mode (default: strict)");
    eprintln!("  --version, -v             Print version");
    eprintln!("  --help, -h                Print help");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() <= 1 {
        print_usage();
        std::process::exit(1);
    }

    if args[1] == "--version" || args[1] == "-v" {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return;
    }

    if args[1] == "--help" || args[1] == "-h" {
        print_usage();
        return;
    }

    let mut command = "scan";
    let mut image_path: Option<PathBuf> = None;
    let mut target_ino: Option<u64> = None;
    let mut out_dir: Option<PathBuf> = None;
    let mut json_mode = false;
    let mut experimental = false;
    let mut base_offset = 0u64;
    let mut walk_mode = WalkMode::Strict;

    let mut idx = 1;
    if args[1] == "scan" || args[1] == "cat-candidate" || args[1] == "dump-candidates" {
        command = &args[1];
        idx = 2;
    }

    while idx < args.len() {
        match args[idx].as_str() {
            "--json" => {
                json_mode = true;
                idx += 1;
            }
            "--experimental" => {
                experimental = true;
                idx += 1;
            }
            "--base-offset" => {
                if idx + 1 < args.len() {
                    base_offset = args[idx + 1].parse().unwrap_or(0);
                    idx += 2;
                } else {
                    idx += 1;
                }
            }
            "--walk-mode" => {
                if idx + 1 < args.len() {
                    if args[idx + 1] == "salvage" {
                        walk_mode = WalkMode::Salvage;
                    }
                    idx += 2;
                } else {
                    idx += 1;
                }
            }
            other => {
                if image_path.is_none() {
                    image_path = Some(PathBuf::from(other));
                } else if command == "cat-candidate" && target_ino.is_none() {
                    target_ino = other.parse().ok();
                } else if command == "dump-candidates" && out_dir.is_none() {
                    out_dir = Some(PathBuf::from(other));
                }
                idx += 1;
            }
        }
    }

    let image = match image_path {
        Some(p) => p,
        None => {
            eprintln!("Error: Image path required.");
            print_usage();
            std::process::exit(1);
        }
    };

    let options = RecoveryOptions::new()
        .with_base_offset(base_offset)
        .with_walk_mode(walk_mode)
        .with_experimental(experimental);

    let result = match command {
        "scan" => run_scan(&image, options, json_mode),
        "cat-candidate" => {
            let ino = match target_ino {
                Some(i) => i,
                None => {
                    eprintln!("Error: Inode number required for cat-candidate.");
                    std::process::exit(1);
                }
            };
            run_cat_candidate(&image, ino, options)
        }
        "dump-candidates" => {
            let dir = match out_dir {
                Some(d) => d,
                None => {
                    eprintln!("Error: Output directory required for dump-candidates.");
                    std::process::exit(1);
                }
            };
            run_dump_candidates(&image, &dir, options)
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
