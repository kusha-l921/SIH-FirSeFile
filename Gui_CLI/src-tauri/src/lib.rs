mod models;

use models::{RecoveredFile, FileMetadata, LedgerBlock, RecoveryEventPayload};
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use acquisition::{AcquisitionEngine, PortableImageAcquisition};
use xfs_recovery_engine::{FileImage, RecoveryEngine, RecoveryOptions};

static GLOBAL_STATE: Mutex<Option<ScanSession>> = Mutex::new(None);

struct ScanSession {
    pub case_id: String,
    pub image_path: String,
    pub filesystem: String,
    pub status: String,
    pub files: Vec<RecoveredFile>,
    pub ledger: Vec<LedgerBlock>,
    pub blocks_processed: u64,
    pub total_blocks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseStatus {
    pub case_id: String,
    pub filesystem: String,
    pub status: String,
    pub files_recovered: u32,
    pub fragments_found: u32,
    pub blocks_processed: u64,
    pub total_blocks: u64,
}

pub fn scan_image_core(image_path: &str) -> Result<CaseStatus, String> {
    let path = Path::new(image_path);
    if !path.exists() {
        return Err(format!("Image file does not exist: {}", image_path));
    }

    let acq = PortableImageAcquisition::new();
    let recovery_input = acq.acquire(path).map_err(|e| e.to_string())?;

    let detected_fs = recovery_input.detected_filesystem.unwrap_or_else(|| "unknown".to_string());
    let mut recovered_files = Vec::new();
    let mut ledger_blocks = Vec::new();

    // 1. Ledger Genesis
    let image_hash = recovery_input.image_sha256.clone().unwrap_or_default();
    let genesis = blockchain_ledger_core::ledger::create_genesis(
        &image_hash,
        "default_operator_pubkey",
        "0000000000000000000000000000000000000000000000000000000000000000",
    ).map_err(|e| e.to_string())?;

    ledger_blocks.push(LedgerBlock {
        block_index: genesis.block_index,
        timestamp: genesis.timestamp,
        payload: RecoveryEventPayload {
            event_id: "EVT-GENESIS".into(),
            action: "genesis".into(),
            recovery_method: "evidence_intake".into(),
            file_id: Some("GENESIS".into()),
            source_location: Some(image_path.to_string()),
            confidence: Some(100.0),
            file_sha256: Some(image_hash.clone()),
        },
        prev_hash: Some(genesis.prev_hash),
        block_hash: genesis.block_hash,
        signature: genesis.signature,
        public_key_id: genesis.public_key_id,
    });

    // 2. Perform filesystem structural analysis
    if detected_fs == "xfs" {
        if let Ok(img) = FileImage::open(path) {
            let mut engine = RecoveryEngine::open(img, RecoveryOptions::default().with_experimental(true))
                .map_err(|e| e.to_string())?;

            if let Ok(report) = engine.collect_candidates() {
                for c in &report.candidates {
                    let sha = engine.sha256_candidate_content(c).ok().map(|h| h.hex_digest);
                    let file_type_str = format!("{:?}", c.file_type);
                    let size = c.original_size.unwrap_or(c.observed_extent_bytes);
                    let file_id = format!("xfs:ino{}", c.ino);
                    let filename = format!("recovered_ino_{}.{}", c.ino, file_type_str.to_lowercase());

                    recovered_files.push(RecoveredFile {
                        file_id: file_id.clone(),
                        filename: filename.clone(),
                        file_type: file_type_str,
                        size,
                        filesystem: "XFS".into(),
                        recovery_method: format!("{:?}", c.method),
                        confidence: Some(match c.confidence {
                            xfs_recovery_engine::RecoveryConfidence::High => 95.0,
                            xfs_recovery_engine::RecoveryConfidence::Medium => 75.0,
                            xfs_recovery_engine::RecoveryConfidence::Low => 50.0,
                        }),
                        source_locations: vec![format!("0x{:x}", c.location.byte_offset)],
                        metadata: FileMetadata {
                            modified: Some(format!("{}", c.mtime.sec)),
                            accessed: Some(format!("{}", c.atime.sec)),
                            changed: Some(format!("{}", c.ctime.sec)),
                            birth: c.crtime.map(|t| format!("{}", t.sec)),
                            permissions: Some(format!("{:o}", c.permissions)),
                            owner: Some(format!("uid:{} gid:{}", c.uid, c.gid)),
                        },
                        sha256: sha.clone(),
                    });

                    // Append recovery block to ledger
                    let prev = ledger_blocks.last().unwrap();
                    let payload_json = serde_json::json!({
                        "file_id": file_id,
                        "filename": filename,
                        "sha256": sha,
                        "size": size,
                    });

                    if let Ok(new_block) = blockchain_ledger_core::ledger::log_action(
                        "full_recovery",
                        payload_json,
                        &file_id,
                        &blockchain_ledger_core::model::Block {
                            block_type: blockchain_ledger_core::model::BlockType::Genesis,
                            block_index: prev.block_index,
                            timestamp: prev.timestamp.clone(),
                            file_id: prev.payload.file_id.clone().unwrap_or_default(),
                            prev_hash: prev.prev_hash.clone().unwrap_or_default(),
                            payload: serde_json::json!({}),
                            block_hash: prev.block_hash.clone(),
                            signature: prev.signature.clone(),
                            public_key_id: prev.public_key_id.clone(),
                        },
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    ) {
                        ledger_blocks.push(LedgerBlock {
                            block_index: new_block.block_index,
                            timestamp: new_block.timestamp,
                            payload: RecoveryEventPayload {
                                event_id: format!("EVT-{}", new_block.block_index),
                                action: "recovered".into(),
                                recovery_method: format!("{:?}", c.method),
                                file_id: Some(file_id),
                                source_location: Some(format!("0x{:x}", c.location.byte_offset)),
                                confidence: Some(95.0),
                                file_sha256: sha,
                            },
                            prev_hash: Some(new_block.prev_hash),
                            block_hash: new_block.block_hash,
                            signature: new_block.signature,
                            public_key_id: new_block.public_key_id,
                        });
                    }
                }
            }
        }
    }

    // 3. Add carved fragments from acquisition
    for frag in &recovery_input.raw_fragments {
        let f_id = frag.fragment_id.clone();
        recovered_files.push(RecoveredFile {
            file_id: f_id.clone(),
            filename: format!("{}.bin", f_id),
            file_type: "Fragment".into(),
            size: frag.length as u64,
            filesystem: detected_fs.clone(),
            recovery_method: frag.recovery_method.clone(),
            confidence: Some((frag.confidence * 100.0) as f32),
            source_locations: vec![format!("0x{:x}", frag.source_offset)],
            metadata: FileMetadata {
                modified: None,
                accessed: None,
                changed: None,
                birth: None,
                permissions: None,
                owner: None,
            },
            sha256: Some(frag.sha256.clone()),
        });
    }

    let total_blocks = (recovery_input.total_size / 4096).max(1);
    let session = ScanSession {
        case_id: format!("CASE-{}", &image_hash[..8]),
        image_path: image_path.to_string(),
        filesystem: detected_fs.clone(),
        status: "complete".into(),
        files: recovered_files,
        ledger: ledger_blocks,
        blocks_processed: total_blocks,
        total_blocks,
    };

    let status = CaseStatus {
        case_id: session.case_id.clone(),
        filesystem: session.filesystem.clone(),
        status: session.status.clone(),
        files_recovered: session.files.len() as u32,
        fragments_found: recovery_input.raw_fragments.len() as u32,
        blocks_processed: total_blocks,
        total_blocks,
    };

    let mut state = GLOBAL_STATE.lock().unwrap();
    *state = Some(session);

    Ok(status)
}

pub fn list_recovered_files_core() -> Vec<RecoveredFile> {
    let state = GLOBAL_STATE.lock().unwrap();
    state.as_ref().map(|s| s.files.clone()).unwrap_or_default()
}

pub fn get_ledger_core() -> Vec<LedgerBlock> {
    let state = GLOBAL_STATE.lock().unwrap();
    state.as_ref().map(|s| s.ledger.clone()).unwrap_or_default()
}

pub fn verify_chain_core() -> bool {
    let state = GLOBAL_STATE.lock().unwrap();
    if let Some(s) = state.as_ref() {
        !s.ledger.is_empty()
    } else {
        false
    }
}

pub fn get_case_status_core() -> CaseStatus {
    let state = GLOBAL_STATE.lock().unwrap();
    if let Some(s) = state.as_ref() {
        CaseStatus {
            case_id: s.case_id.clone(),
            filesystem: s.filesystem.clone(),
            status: s.status.clone(),
            files_recovered: s.files.len() as u32,
            fragments_found: 0,
            blocks_processed: s.blocks_processed,
            total_blocks: s.total_blocks,
        }
    } else {
        CaseStatus {
            case_id: "NO_ACTIVE_CASE".into(),
            filesystem: "NONE".into(),
            status: "idle".into(),
            files_recovered: 0,
            fragments_found: 0,
            blocks_processed: 0,
            total_blocks: 0,
        }
    }
}

pub fn export_report_core(case_id: String, investigator: String) -> Result<String, String> {
    let status = get_case_status_core();
    let files = list_recovered_files_core();
    let ledger = get_ledger_core();

    let mut report = String::new();
    report.push_str("FORENSIC RECOVERY REPORT\n");
    report.push_str("=========================\n\n");
    report.push_str(&format!("Case ID: {}\n", case_id));
    report.push_str(&format!("Investigator: {}\n\n", investigator));

    report.push_str("-- Case Status --\n");
    report.push_str(&format!("Filesystem: {}\n", status.filesystem));
    report.push_str(&format!("Status: {}\n", status.status));
    report.push_str(&format!("Files recovered: {}\n", status.files_recovered));
    report.push_str(&format!("Fragments found: {}\n", status.fragments_found));
    report.push_str(&format!(
        "Blocks processed: {} / {}\n\n",
        status.blocks_processed, status.total_blocks
    ));

    report.push_str("-- Recovered Files --\n");
    for f in &files {
        report.push_str(&format!(
            "{} | {} | {} bytes | filesystem={} | method={} | confidence={:?} | sha256={:?}\n",
            f.filename, f.file_type, f.size, f.filesystem, f.recovery_method, f.confidence, f.sha256
        ));
    }
    report.push_str("\n");

    report.push_str("-- Recovery Ledger --\n");
    for b in &ledger {
        report.push_str(&format!(
            "#{} | {} | method={} | file={:?} | hash={}\n",
            b.block_index,
            b.timestamp,
            b.payload.recovery_method,
            b.payload.file_id,
            b.block_hash
        ));
    }

    let output_path = format!("recovered_{}_report.txt", case_id);
    fs::write(&output_path, report).map_err(|e| format!("Failed to write report: {}", e))?;

    Ok(output_path)
}

#[tauri::command]
fn scan_image(image_path: String) -> Result<CaseStatus, String> {
    scan_image_core(&image_path)
}

#[tauri::command]
fn list_recovered_files() -> Vec<RecoveredFile> { list_recovered_files_core() }

#[tauri::command]
fn get_ledger() -> Vec<LedgerBlock> { get_ledger_core() }

#[tauri::command]
fn verify_chain() -> bool { verify_chain_core() }

#[tauri::command]
fn get_case_status() -> CaseStatus { get_case_status_core() }

#[tauri::command]
fn export_report(case_id: String, investigator: String) -> Result<String, String> { export_report_core(case_id, investigator) }

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            scan_image,
            list_recovered_files,
            get_ledger,
            verify_chain,
            get_case_status,
            export_report
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
