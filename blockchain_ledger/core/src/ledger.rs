/// Core ledger operations: genesis block creation and action logging.
///
/// These are the primary entry points for building a forensic recovery chain.
/// Rust services or Python wrappers use these functions to append cryptographically
/// verifiable blocks to a chain.
use serde_json::json;

use crate::error::LedgerError;
use crate::hashing::compute_block_hash;
use crate::model::{Block, BlockType};
use crate::signing::sign;

/// Validates that a payload contains all required fields for a given `BlockType`.
///
/// Required fields per block type:
/// - `Genesis`: `disk_baseline_sha256`, `operator_public_key`
/// - `MetadataOnly`: `filename`, `macb_timestamps`, `recovery_method`
/// - `DataOnly`: `recovered_file_sha256`, `source_location`, `size`, `recovery_method`
/// - `FullRecovery`: `filename`, `macb_timestamps`, `recovered_file_sha256`, `size`, `source_location`, `recovery_method`
///
/// # Errors
/// Returns `LedgerError::MissingPayloadField` if any required field is missing.
pub fn validate_payload(block_type: &BlockType, payload: &serde_json::Value) -> Result<(), LedgerError> {
    let required_fields: &[&str] = match block_type {
        BlockType::Genesis => &["disk_baseline_sha256", "operator_public_key"],
        BlockType::MetadataOnly => &["filename", "macb_timestamps", "recovery_method"],
        BlockType::DataOnly => &["recovered_file_sha256", "source_location", "size", "recovery_method"],
        BlockType::FullRecovery => &["filename", "macb_timestamps", "recovered_file_sha256", "size", "source_location", "recovery_method"],
    };
    for field in required_fields {
        if payload.get(*field).is_none() {
            return Err(LedgerError::MissingPayloadField {
                field: field.to_string(),
                block_type: block_type.to_string(),
            });
        }
    }
    Ok(())
}

/// Creates the genesis (first) block of a new forensic recovery chain.
///
/// The genesis block records the disk baseline hash and the operator's public key,
/// establishing the chain's provenance. It has `block_index = 0` and a `prev_hash`
/// of 64 zeros.
///
/// # Arguments
/// * `disk_baseline_sha256` - SHA-256 hash of the disk image being investigated
/// * `operator_pubkey_hex` - Hex-encoded Ed25519 public key of the operator
/// * `signing_key_hex` - Hex-encoded Ed25519 private key for signing
///
/// # Returns
/// The genesis `Block` with a valid hash, signature, and validated payload.
///
/// # Errors
/// Returns `LedgerError` if payload validation or signing fails.
pub fn create_genesis(
    disk_baseline_sha256: &str,
    operator_pubkey_hex: &str,
    signing_key_hex: &str,
) -> Result<Block, LedgerError> {
    let block_type = BlockType::Genesis;
    let block_index: u64 = 0;
    let prev_hash = "0".repeat(64);
    let file_id = String::new();
    let timestamp = chrono::Utc::now().to_rfc3339();
    let payload = json!({
        "disk_baseline_sha256": disk_baseline_sha256,
        "operator_public_key": operator_pubkey_hex,
    });

    validate_payload(&block_type, &payload)?;

    let block_hash = compute_block_hash(
        &prev_hash,
        &block_type,
        block_index,
        &file_id,
        &timestamp,
        &payload,
    );

    let signature = sign(signing_key_hex, &block_hash)?;

    Ok(Block {
        block_type,
        block_index,
        timestamp,
        file_id,
        prev_hash,
        payload,
        block_hash,
        signature,
        public_key_id: operator_pubkey_hex.to_string(),
    })
}

/// Logs a new action to the chain, appending a block after the given previous block.
///
/// This function is called once per recovery stage (structural recovery,
/// classifier/RCI, validation). The caller provides a payload dict describing
/// what happened; this function handles payload validation, hashing, linking, and signing.
///
/// # Public Key ID Propagation Assumption
/// Under the current design, `public_key_id` is propagated from `prev_block.public_key_id`.
/// This is based on the single-investigator-per-case assumption (the operator keypair
/// created at setup/genesis is used for all blocks in that case). If multi-investigator
/// custody transfer is implemented in the future, `public_key_id` can be derived from
/// the signing key provided in the call.
///
/// # Arguments
/// * `block_type` - One of `"metadata_only"`, `"data_only"`, or `"full_recovery"`
/// * `payload` - JSON object describing the recovery action (no raw file bytes!)
/// * `file_id` - Identifier for the file this action relates to
/// * `prev_block` - Reference to the most recent block in the chain
/// * `signing_key_hex` - Hex-encoded Ed25519 private key for signing
///
/// # Returns
/// A new `Block` correctly linked to `prev_block`.
///
/// # Errors
/// Returns `LedgerError` if `block_type` is invalid, required payload fields are missing,
/// or signing fails.
pub fn log_action(
    block_type: &str,
    payload: serde_json::Value,
    file_id: &str,
    prev_block: &Block,
    signing_key_hex: &str,
) -> Result<Block, LedgerError> {
    let bt: BlockType = block_type.parse()?;
    validate_payload(&bt, &payload)?;

    let block_index = prev_block.block_index + 1;
    let prev_hash = prev_block.block_hash.clone();
    let timestamp = chrono::Utc::now().to_rfc3339();

    let block_hash = compute_block_hash(
        &prev_hash,
        &bt,
        block_index,
        file_id,
        &timestamp,
        &payload,
    );

    let signature = sign(signing_key_hex, &block_hash)?;

    Ok(Block {
        block_type: bt,
        block_index,
        timestamp,
        file_id: file_id.to_string(),
        prev_hash,
        payload,
        block_hash,
        signature,
        public_key_id: prev_block.public_key_id.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::generate_keypair;
    use serde_json::json;

    #[test]
    fn test_create_genesis_and_log_action_chain() {
        let (private_key, public_key) = generate_keypair();
        let disk_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        // Create genesis
        let genesis = create_genesis(disk_hash, &public_key, &private_key).unwrap();
        assert_eq!(genesis.block_index, 0);
        assert_eq!(genesis.prev_hash, "0".repeat(64));
        assert_eq!(genesis.block_type, BlockType::Genesis);

        // Log metadata_only action
        let block1 = log_action(
            "metadata_only",
            json!({
                "filename": "document.pdf",
                "macb_timestamps": {"modified": "2024-01-01T00:00:00Z"},
                "recovery_method": "mft_carving"
            }),
            "file_001",
            &genesis,
            &private_key,
        ).unwrap();
        assert_eq!(block1.block_index, 1);
        assert_eq!(block1.prev_hash, genesis.block_hash);
        assert_eq!(block1.block_type, BlockType::MetadataOnly);

        // Log data_only action
        let block2 = log_action(
            "data_only",
            json!({
                "recovered_file_sha256": "abcdef123456",
                "source_location": "sector_5000",
                "size": 2048,
                "recovery_method": "header_footer_carver"
            }),
            "file_002",
            &block1,
            &private_key,
        ).unwrap();
        assert_eq!(block2.block_index, 2);
        assert_eq!(block2.prev_hash, block1.block_hash);
        assert_eq!(block2.block_type, BlockType::DataOnly);

        // Log full_recovery action
        let block3 = log_action(
            "full_recovery",
            json!({
                "filename": "document.pdf",
                "macb_timestamps": {"modified": "2024-01-01T00:00:00Z"},
                "recovered_file_sha256": "abcdef123456",
                "size": 2048,
                "source_location": "sector_5000",
                "recovery_method": "mft_plus_carver"
            }),
            "file_003",
            &block2,
            &private_key,
        ).unwrap();
        assert_eq!(block3.block_index, 3);
        assert_eq!(block3.prev_hash, block2.block_hash);
        assert_eq!(block3.block_type, BlockType::FullRecovery);

        // Verify chain linkage
        let chain = vec![genesis, block1, block2, block3];
        for i in 1..chain.len() {
            assert_eq!(chain[i].prev_hash, chain[i - 1].block_hash,
                "Block {} prev_hash doesn't match block {} hash", i, i - 1);
        }
    }

    #[test]
    fn test_log_action_invalid_block_type() {
        let (private_key, public_key) = generate_keypair();
        let genesis = create_genesis("hash", &public_key, &private_key).unwrap();
        let result = log_action("invalid_type", json!({}), "file", &genesis, &private_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_log_action_missing_required_fields() {
        let (private_key, public_key) = generate_keypair();
        let genesis = create_genesis("hash", &public_key, &private_key).unwrap();

        // Missing macb_timestamps and recovery_method
        let result = log_action(
            "metadata_only",
            json!({"filename": "test.txt"}),
            "file_001",
            &genesis,
            &private_key,
        );
        match result {
            Err(LedgerError::MissingPayloadField { field, block_type }) => {
                assert_eq!(field, "macb_timestamps");
                assert_eq!(block_type, "metadata_only");
            }
            _ => panic!("Expected MissingPayloadField error"),
        }
    }
}
