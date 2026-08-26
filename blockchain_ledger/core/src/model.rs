/// Data model types for the blockchain recovery ledger.
///
/// This module defines the block types and block structure used throughout
/// the ledger system. Python callers receive these as dictionaries after
/// serialization through PyO3.
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::error::LedgerError;

/// Represents the type of a block in the recovery chain.
///
/// Each variant corresponds to a stage in the forensic recovery process:
/// - `Genesis`: The initial block establishing chain provenance
/// - `MetadataOnly`: Records filesystem metadata recovery
/// - `DataOnly`: Records raw data recovery without metadata
/// - `FullRecovery`: Records complete file recovery with data and metadata
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlockType {
    /// The initial block that establishes chain provenance.
    Genesis,
    /// A block recording filesystem metadata recovery.
    MetadataOnly,
    /// A block recording raw data recovery without metadata.
    DataOnly,
    /// A block recording complete file recovery.
    FullRecovery,
}

impl fmt::Display for BlockType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockType::Genesis => write!(f, "genesis"),
            BlockType::MetadataOnly => write!(f, "metadata_only"),
            BlockType::DataOnly => write!(f, "data_only"),
            BlockType::FullRecovery => write!(f, "full_recovery"),
        }
    }
}

impl FromStr for BlockType {
    type Err = LedgerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "genesis" => Ok(BlockType::Genesis),
            "metadata_only" => Ok(BlockType::MetadataOnly),
            "data_only" => Ok(BlockType::DataOnly),
            "full_recovery" => Ok(BlockType::FullRecovery),
            other => Err(LedgerError::InvalidBlockType(other.to_string())),
        }
    }
}

/// A single block in the forensic recovery ledger chain.
///
/// Each block is cryptographically linked to its predecessor via `prev_hash`
/// and is signed with the operator's Ed25519 key. Python callers receive
/// this as a dictionary with the same field names.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    /// The type of this block (genesis, metadata_only, data_only, full_recovery).
    pub block_type: BlockType,
    /// Zero-based index of this block in the chain.
    pub block_index: u64,
    /// RFC 3339 timestamp of when this block was created.
    pub timestamp: String,
    /// Identifier for the file this block relates to (empty for genesis).
    pub file_id: String,
    /// SHA-256 hash of the previous block (64 zeros for genesis).
    pub prev_hash: String,
    /// The block's payload data (metadata, recovery info, etc.).
    pub payload: serde_json::Value,
    /// SHA-256 hash of this block's contents.
    pub block_hash: String,
    /// Hex-encoded Ed25519 signature of `block_hash`.
    pub signature: String,
    /// Hex-encoded public key identifying the signing operator.
    pub public_key_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_block_type_display_and_from_str() {
        let variants = vec![
            (BlockType::Genesis, "genesis"),
            (BlockType::MetadataOnly, "metadata_only"),
            (BlockType::DataOnly, "data_only"),
            (BlockType::FullRecovery, "full_recovery"),
        ];
        for (variant, expected_str) in &variants {
            assert_eq!(variant.to_string(), *expected_str);
            let parsed: BlockType = expected_str.parse().unwrap();
            assert_eq!(&parsed, variant);
        }
    }

    #[test]
    fn test_invalid_block_type_from_str() {
        let result: Result<BlockType, _> = "invalid".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_block_serialize_deserialize_roundtrip() {
        let block = Block {
            block_type: BlockType::FullRecovery,
            block_index: 42,
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            file_id: "file_abc123".to_string(),
            prev_hash: "a".repeat(64),
            payload: json!({"recovered_hash": "deadbeef", "size_bytes": 1024}),
            block_hash: "b".repeat(64),
            signature: "c".repeat(128),
            public_key_id: "d".repeat(64),
        };

        let json_str = serde_json::to_string(&block).unwrap();
        let deserialized: Block = serde_json::from_str(&json_str).unwrap();

        assert_eq!(deserialized.block_index, block.block_index);
        assert_eq!(deserialized.block_type, block.block_type);
        assert_eq!(deserialized.timestamp, block.timestamp);
        assert_eq!(deserialized.file_id, block.file_id);
        assert_eq!(deserialized.prev_hash, block.prev_hash);
        assert_eq!(deserialized.payload, block.payload);
        assert_eq!(deserialized.block_hash, block.block_hash);
        assert_eq!(deserialized.signature, block.signature);
        assert_eq!(deserialized.public_key_id, block.public_key_id);
    }
}
