mod models;

use models::{RecoveredFile, FileMetadata, LedgerBlock, RecoveryEventPayload};
use serde::{Serialize, Deserialize};
use std::fs;

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

pub fn list_recovered_files_core() -> Vec<RecoveredFile> {
    vec![
        RecoveredFile {
            file_id: "REC-00021".into(),
            filename: "report.pdf".into(),
            file_type: "PDF".into(),
            size: 245760,
            filesystem: "XFS".into(),
            recovery_method: "inode_extent".into(),
            confidence: Some(96.4),
            source_locations: vec!["0x18F000".into()],
            metadata: FileMetadata {
                modified: Some("2026-08-20T10:42:11Z".into()),
                accessed: Some("2026-08-20T10:42:11Z".into()),
                changed: Some("2026-08-20T10:42:11Z".into()),
                birth: None,
                permissions: Some("0644".into()),
                owner: None,
            },
            sha256: Some("abc123...".into()),
        },
        RecoveredFile {
            file_id: "REC-00022".into(),
            filename: "image.jpg".into(),
            file_type: "JPEG".into(),
            size: 88213,
            filesystem: "XFS".into(),
            recovery_method: "carving".into(),
            confidence: Some(78.2),
            source_locations: vec!["0x8A0000".into()],
            metadata: FileMetadata {
                modified: None,
                accessed: None,
                changed: None,
                birth: None,
                permissions: None,
                owner: None,
            },
            sha256: None,
        },
    ]
}

pub fn get_ledger_core() -> Vec<LedgerBlock> {
    vec![
        LedgerBlock {
            block_index: 1,
            timestamp: "2026-08-20T10:42:11Z".into(),
            payload: RecoveryEventPayload {
                event_id: "EVT-001".into(),
                action: "recovered".into(),
                recovery_method: "inode_extent".into(),
                file_id: Some("REC-00021".into()),
                source_location: Some("0x18F000".into()),
                confidence: Some(96.4),
                file_sha256: Some("abc123...".into()),
            },
            prev_hash: None,
            block_hash: "0000hash1...".into(),
            signature: "sig1...".into(),
            public_key_id: "key-01".into(),
        },
    ]
}

pub fn verify_chain_core() -> bool {
    true
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

pub fn get_case_status_core() -> CaseStatus {
    CaseStatus {
        case_id: "CASE-001".into(),
        filesystem: "XFS".into(),
        status: "scanning".into(),
        files_recovered: 2,
        fragments_found: 5,
        blocks_processed: 84213,
        total_blocks: 120000,
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

    let output_path = format!("/tmp/{}_report.txt", case_id);
    fs::write(&output_path, report).map_err(|e| format!("Failed to write report: {}", e))?;

    Ok(output_path)
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
            greet,
            list_recovered_files,
            get_ledger,
            verify_chain,
            get_case_status,
            export_report
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
