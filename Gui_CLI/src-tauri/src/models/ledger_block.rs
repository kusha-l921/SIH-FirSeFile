use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerBlock {
    pub block_index: u64,
    pub timestamp: String,

    pub payload: RecoveryEventPayload,

    pub prev_hash: Option<String>,
    pub block_hash: String,

    pub signature: String,
    pub public_key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryEventPayload {
    pub event_id: String,
    pub action: String,
    pub recovery_method: String,

    pub file_id: Option<String>,
    pub source_location: Option<String>,

    pub confidence: Option<f32>,
    pub file_sha256: Option<String>,
}