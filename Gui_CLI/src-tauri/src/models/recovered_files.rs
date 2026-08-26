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