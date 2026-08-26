use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fragment {
    pub fragment_id: String,
    pub source_offset: u64,
    pub length: u64,

    pub filesystem: Option<String>,

    pub fragment_type: Option<String>,
    pub classification_confidence: Option<f32>,
    pub recovery_confidence: Option<f32>,
}