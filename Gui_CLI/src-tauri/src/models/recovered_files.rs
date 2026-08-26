use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredFile {
    pub file_id: String,
    pub filename: String,
    pub file_type: String,
    pub size: u64,

    pub filesystem: String,
    pub recovery_method: String,
    pub confidence: Option<f32>,

    pub source_locations: Vec<String>,
    pub metadata: FileMetadata,

    pub sha256: Option<String>,

    // ML classification fields
    pub ml_predicted_class: Option<String>,
    pub ml_confidence: Option<f32>,
    pub ml_top_k: Option<Vec<MlPrediction>>,
    pub validation_status: Option<String>,
    pub validation_is_valid: Option<bool>,
    pub reconstruction_confidence: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlPrediction {
    pub class_name: String,
    pub probability: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub modified: Option<String>,
    pub accessed: Option<String>,
    pub changed: Option<String>,
    pub birth: Option<String>,

    pub permissions: Option<String>,
    pub owner: Option<String>,
}