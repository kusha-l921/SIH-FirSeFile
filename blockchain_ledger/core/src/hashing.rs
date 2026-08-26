/// Canonical JSON serialization and block hash computation.
///
/// This module provides deterministic JSON serialization (sorted keys) and
/// SHA-256 based block hashing. Python callers never interact with these
/// functions directly — they are used internally by `create_genesis` and
/// `log_action`.
use sha2::{Digest, Sha256};
use serde_json::Value;

use crate::model::BlockType;

/// Produces a deterministic JSON string by recursively sorting all object keys.
///
/// This ensures that two semantically identical JSON values always produce
/// the same string representation, regardless of insertion order.
///
/// # Arguments
/// * `value` - Any JSON value to canonicalize
///
/// # Returns
/// A deterministic JSON string with all object keys sorted alphabetically.
pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let entries: Vec<String> = keys
                .iter()
                .map(|k| {
                    let v = canonical_json(map.get(*k).expect("key must exist in map"));
                    format!("{}:{}", serde_json::to_string(k).expect("key serialization cannot fail"), v)
                })
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(|v| canonical_json(v)).collect();
            format!("[{}]", items.join(","))
        }
        // For primitives (string, number, bool, null), serde_json::to_string
        // produces a deterministic output.
        _ => serde_json::to_string(value).expect("primitive serialization cannot fail"),
    }
}

/// Computes the SHA-256 block hash over the concatenation of all block fields.
///
/// The payload is first canonicalized to ensure deterministic hashing regardless
/// of JSON key insertion order.
///
/// # Arguments
/// * `prev_hash` - Hash of the previous block (64 zeros for genesis)
/// * `block_type` - The type of this block
/// * `block_index` - Zero-based index of this block
/// * `file_id` - File identifier for this block
/// * `timestamp` - RFC 3339 timestamp string
/// * `payload` - The block's JSON payload
///
/// # Returns
/// Hex-encoded SHA-256 digest string (64 lowercase hex characters).
pub fn compute_block_hash(
    prev_hash: &str,
    block_type: &BlockType,
    block_index: u64,
    file_id: &str,
    timestamp: &str,
    payload: &Value,
) -> String {
    let canonical_payload = canonical_json(payload);
    let preimage = format!(
        "{}{}{}{}{}{}",
        prev_hash,
        block_type,
        block_index,
        file_id,
        timestamp,
        canonical_payload
    );
    let mut hasher = Sha256::new();
    hasher.update(preimage.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonical_json_sorts_keys() {
        let v1 = json!({"zebra": 1, "apple": 2, "mango": 3});
        let v2 = json!({"apple": 2, "mango": 3, "zebra": 1});
        assert_eq!(canonical_json(&v1), canonical_json(&v2));
    }

    #[test]
    fn test_canonical_json_nested_objects() {
        let v1 = json!({"outer": {"z": 1, "a": 2}});
        let v2 = json!({"outer": {"a": 2, "z": 1}});
        assert_eq!(canonical_json(&v1), canonical_json(&v2));
    }

    #[test]
    fn test_canonical_json_deterministic_output() {
        let v = json!({"b": [1, {"d": 4, "c": 3}], "a": "hello"});
        let expected = r#"{"a":"hello","b":[1,{"c":3,"d":4}]}"#;
        assert_eq!(canonical_json(&v), expected);
    }

    #[test]
    fn test_compute_block_hash_deterministic() {
        let payload1 = json!({"z_key": "value_z", "a_key": "value_a"});
        let payload2 = json!({"a_key": "value_a", "z_key": "value_z"});

        let hash1 = compute_block_hash(
            "0000", &BlockType::DataOnly, 1, "file1", "2024-01-01T00:00:00Z", &payload1
        );
        let hash2 = compute_block_hash(
            "0000", &BlockType::DataOnly, 1, "file1", "2024-01-01T00:00:00Z", &payload2
        );
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 hex is 64 chars
    }

    #[test]
    fn test_compute_block_hash_differs_on_different_input() {
        let payload = json!({"key": "value"});
        let hash1 = compute_block_hash(
            "0000", &BlockType::DataOnly, 1, "file1", "2024-01-01T00:00:00Z", &payload
        );
        let hash2 = compute_block_hash(
            "0001", &BlockType::DataOnly, 1, "file1", "2024-01-01T00:00:00Z", &payload
        );
        assert_ne!(hash1, hash2);
    }
}
