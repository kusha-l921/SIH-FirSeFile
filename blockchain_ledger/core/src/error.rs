/// Error types for the blockchain recovery ledger.
///
/// All fallible operations in the ledger return `Result<T, LedgerError>`.
/// Python callers will see these as Python exceptions with descriptive messages.
use thiserror::Error;

/// Represents all possible errors that can occur in ledger operations.
#[derive(Error, Debug)]
pub enum LedgerError {
    /// The provided key bytes are not valid for Ed25519 operations.
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    /// The provided signature is not valid hex or not a valid Ed25519 signature.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// JSON serialization or deserialization failed.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Reading from or writing to the chain file failed.
    #[error("Chain file I/O error: {0}")]
    ChainFileIo(String),

    /// The provided block_type string does not match any known variant.
    #[error("Invalid block type: {0}")]
    InvalidBlockType(String),

    /// The payload is missing a required field for the given block_type.
    #[error("payload missing required field '{field}' for block_type '{block_type}'")]
    MissingPayloadField { field: String, block_type: String },

    /// Hex encoding/decoding failed.
    #[error("Hex encoding error: {0}")]
    HexError(String),
}

impl From<serde_json::Error> for LedgerError {
    fn from(e: serde_json::Error) -> Self {
        LedgerError::SerializationError(e.to_string())
    }
}

impl From<std::io::Error> for LedgerError {
    fn from(e: std::io::Error) -> Self {
        LedgerError::ChainFileIo(e.to_string())
    }
}

impl From<hex::FromHexError> for LedgerError {
    fn from(e: hex::FromHexError) -> Self {
        LedgerError::HexError(e.to_string())
    }
}
