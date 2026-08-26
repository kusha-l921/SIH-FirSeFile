/// Chain verification: validates hash integrity, chain linkage, and signatures.
///
/// Python callers receive the `VerifyResult` as a dictionary with fields
/// `valid`, `broken_at_index`, and `reason`.
use serde::{Deserialize, Serialize};

use crate::hashing::compute_block_hash;
use crate::model::Block;
use crate::signing::verify_signature;

/// Result of a chain verification operation.
///
/// When `valid` is true, the entire chain passed all integrity checks.
/// When `valid` is false, `broken_at_index` identifies the first failing
/// block and `reason` describes which check failed.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifyResult {
    /// Whether the entire chain passed verification.
    pub valid: bool,
    /// Index of the first block that failed verification, if any.
    pub broken_at_index: Option<u64>,
    /// Human-readable description of what failed.
    pub reason: Option<String>,
}

/// Verifies the integrity of an entire block chain.
///
/// For each block, three checks are performed in order:
/// 1. **Hash integrity**: Recomputes the block hash from stored fields and
///    compares it to the stored `block_hash`.
/// 2. **Chain linkage**: Confirms `prev_hash` equals the previous block's
///    `block_hash` (for genesis, confirms it equals 64 zeros).
/// 3. **Signature validity**: Verifies the stored `signature` against the
///    provided public key and the stored `block_hash`.
///
/// Stops at the first failure and reports which block and which check failed.
///
/// # Arguments
/// * `blocks` - Slice of blocks in chain order (genesis first)
/// * `pubkey_hex` - Hex-encoded Ed25519 public key to verify signatures against
///
/// # Returns
/// A `VerifyResult` indicating success or the first point of failure.
pub fn verify_chain(blocks: &[Block], pubkey_hex: &str) -> VerifyResult {
    if blocks.is_empty() {
        return VerifyResult {
            valid: false,
            broken_at_index: None,
            reason: Some("Chain is empty".to_string()),
        };
    }

    for (i, block) in blocks.iter().enumerate() {
        // (a) Recompute block_hash and compare to stored value
        let recomputed_hash = compute_block_hash(
            &block.prev_hash,
            &block.block_type,
            block.block_index,
            &block.file_id,
            &block.timestamp,
            &block.payload,
        );
        if recomputed_hash != block.block_hash {
            return VerifyResult {
                valid: false,
                broken_at_index: Some(block.block_index),
                reason: Some(format!(
                    "Block {} hash mismatch: computed {} but stored {}",
                    block.block_index, recomputed_hash, block.block_hash
                )),
            };
        }

        // (b) Confirm prev_hash linkage
        if i == 0 {
            if block.prev_hash != "0".repeat(64) {
                return VerifyResult {
                    valid: false,
                    broken_at_index: Some(block.block_index),
                    reason: Some(format!(
                        "Genesis block prev_hash should be 64 zeros but was {}",
                        block.prev_hash
                    )),
                };
            }
        } else {
            let prev_block = &blocks[i - 1];
            if block.prev_hash != prev_block.block_hash {
                return VerifyResult {
                    valid: false,
                    broken_at_index: Some(block.block_index),
                    reason: Some(format!(
                        "Block {} prev_hash {} does not match previous block's hash {}",
                        block.block_index, block.prev_hash, prev_block.block_hash
                    )),
                };
            }
        }

        // (c) Verify signature
        if !verify_signature(pubkey_hex, &block.block_hash, &block.signature) {
            return VerifyResult {
                valid: false,
                broken_at_index: Some(block.block_index),
                reason: Some(format!(
                    "Block {} signature verification failed",
                    block.block_index
                )),
            };
        }
    }

    VerifyResult {
        valid: true,
        broken_at_index: None,
        reason: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{create_genesis, log_action};
    use crate::signing::generate_keypair;
    use serde_json::json;

    fn build_test_chain() -> (Vec<Block>, String, String) {
        let (private_key, public_key) = generate_keypair();
        let disk_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        let genesis = create_genesis(disk_hash, &public_key, &private_key).unwrap();
        let block1 = log_action(
            "metadata_only",
            json!({
                "filename": "test.pdf",
                "macb_timestamps": {"modified": "2024-01-01T00:00:00Z"},
                "recovery_method": "mft_carving"
            }),
            "f1",
            &genesis,
            &private_key,
        ).unwrap();
        let block2 = log_action(
            "data_only",
            json!({
                "recovered_file_sha256": "abcdef123456",
                "source_location": "sector_100",
                "size": 1024,
                "recovery_method": "carver"
            }),
            "f2",
            &block1,
            &private_key,
        ).unwrap();
        let block3 = log_action(
            "full_recovery",
            json!({
                "filename": "test.pdf",
                "macb_timestamps": {"modified": "2024-01-01T00:00:00Z"},
                "recovered_file_sha256": "abcdef123456",
                "size": 1024,
                "source_location": "sector_100",
                "recovery_method": "mft_carver"
            }),
            "f3",
            &block2,
            &private_key,
        ).unwrap();

        (vec![genesis, block1, block2, block3], public_key, private_key)
    }

    #[test]
    fn test_verify_valid_chain() {
        let (chain, public_key, _) = build_test_chain();
        let result = verify_chain(&chain, &public_key);
        assert!(result.valid, "Expected valid chain, got: {:?}", result.reason);
        assert!(result.broken_at_index.is_none());
        assert!(result.reason.is_none());
    }

    #[test]
    fn test_verify_chain_detects_tampered_payload() {
        let (mut chain, public_key, _) = build_test_chain();
        // Tamper with block 2's payload
        chain[2].payload = json!({"sectors": [999]});

        let result = verify_chain(&chain, &public_key);
        assert!(!result.valid);
        assert_eq!(result.broken_at_index, Some(2));
        assert!(result.reason.as_ref().unwrap().contains("hash mismatch"),
            "Expected hash mismatch reason, got: {:?}", result.reason);
    }

    #[test]
    fn test_verify_chain_detects_broken_linkage() {
        let (mut chain, public_key, _) = build_test_chain();
        // Break the prev_hash linkage of block 1
        chain[1].prev_hash = "f".repeat(64);

        let result = verify_chain(&chain, &public_key);
        assert!(!result.valid);
        // This will be caught as a hash mismatch since prev_hash is part of the hash input
        assert_eq!(result.broken_at_index, Some(1));
    }

    #[test]
    fn test_verify_chain_detects_wrong_public_key() {
        let (chain, _, _) = build_test_chain();
        let (_, wrong_public_key) = generate_keypair();

        let result = verify_chain(&chain, &wrong_public_key);
        assert!(!result.valid);
        assert_eq!(result.broken_at_index, Some(0));
        assert!(result.reason.as_ref().unwrap().contains("signature"),
            "Expected signature failure reason, got: {:?}", result.reason);
    }
}
