use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryEvent {
    pub event_id: String,
    pub timestamp: String,

    pub action: String,
    pub recovery_method: String,

    pub file_id: Option<String>,
    pub source_location: Option<String>,

    pub confidence: Option<f32>,
    pub file_sha256: Option<String>,

    pub details: Option<String>,
}