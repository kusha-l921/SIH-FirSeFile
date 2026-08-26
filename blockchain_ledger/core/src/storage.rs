/// JSONL file storage for the block chain.
///
/// Each block is stored as a single JSON line in a `.jsonl` file.
/// Python callers use `append_block` and `load_chain` through PyO3 bindings,
/// passing file paths as strings.
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use crate::error::LedgerError;
use crate::model::Block;

/// Appends a single block as a JSON line to the chain file.
///
/// Creates the file (and any parent directories) if it doesn't exist.
/// Each block is written as a single line of JSON followed by a newline.
///
/// # Arguments
/// * `block` - The block to append
/// * `path` - Path to the JSONL chain file
///
/// # Errors
/// Returns `LedgerError::SerializationError` if JSON serialization fails,
/// or `LedgerError::ChainFileIo` if the file cannot be opened or written to.
pub fn append_block(block: &Block, path: &Path) -> Result<(), LedgerError> {
    // Create parent directories if they don't exist
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    let json_line = serde_json::to_string(block)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{}", json_line)?;
    Ok(())
}

/// Loads all blocks from a JSONL chain file.
///
/// Reads the file line by line, deserializing each line as a `Block`.
/// Empty lines are skipped.
///
/// # Arguments
/// * `path` - Path to the JSONL chain file
///
/// # Returns
/// A vector of blocks in the order they appear in the file.
///
/// # Errors
/// Returns `LedgerError::ChainFileIo` if the file cannot be read,
/// or `LedgerError::SerializationError` if any line is not valid Block JSON.
pub fn load_chain(path: &Path) -> Result<Vec<Block>, LedgerError> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut blocks = Vec::new();

    for (line_num, line_result) in reader.lines().enumerate() {
        let line = line_result?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let block: Block = serde_json::from_str(trimmed)
            .map_err(|e| LedgerError::SerializationError(
                format!("Failed to parse block at line {}: {}", line_num + 1, e)
            ))?;
        blocks.push(block);
    }

    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{create_genesis, log_action};
    use crate::signing::generate_keypair;
    use serde_json::json;
    use std::path::PathBuf;

    fn temp_chain_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("blockchain_ledger_test_{}.jsonl", rand::random::<u64>()));
        path
    }

    #[test]
    fn test_append_and_load_chain() {
        let path = temp_chain_path();
        let (private_key, public_key) = generate_keypair();
        let disk_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        // Build a 4-block chain
        let genesis = create_genesis(disk_hash, &public_key, &private_key).unwrap();
        let b1 = log_action(
            "metadata_only",
            json!({
                "filename": "a.pdf",
                "macb_timestamps": {"created": "2024-01-01T00:00:00Z"},
                "recovery_method": "mft"
            }),
            "f1",
            &genesis,
            &private_key,
        ).unwrap();
        let b2 = log_action(
            "data_only",
            json!({
                "recovered_file_sha256": "1122334455",
                "source_location": "sector_50",
                "size": 512,
                "recovery_method": "carver"
            }),
            "f2",
            &b1,
            &private_key,
        ).unwrap();
        let b3 = log_action(
            "full_recovery",
            json!({
                "filename": "a.pdf",
                "macb_timestamps": {"created": "2024-01-01T00:00:00Z"},
                "recovered_file_sha256": "1122334455",
                "size": 512,
                "source_location": "sector_50",
                "recovery_method": "mft_carver"
            }),
            "f3",
            &b2,
            &private_key,
        ).unwrap();

        let original_chain = vec![genesis, b1, b2, b3];

        // Write all blocks
        for block in &original_chain {
            append_block(block, &path).unwrap();
        }

        // Read them back
        let loaded_chain = load_chain(&path).unwrap();

        assert_eq!(loaded_chain.len(), original_chain.len());
        for (orig, loaded) in original_chain.iter().zip(loaded_chain.iter()) {
            assert_eq!(orig.block_index, loaded.block_index);
            assert_eq!(orig.block_hash, loaded.block_hash);
            assert_eq!(orig.prev_hash, loaded.prev_hash);
            assert_eq!(orig.signature, loaded.signature);
            assert_eq!(orig.timestamp, loaded.timestamp);
            assert_eq!(orig.file_id, loaded.file_id);
            assert_eq!(orig.payload, loaded.payload);
            assert_eq!(orig.public_key_id, loaded.public_key_id);
            assert_eq!(orig.block_type, loaded.block_type);
        }

        // Cleanup
        let _ = fs::remove_file(&path);
    }
}
