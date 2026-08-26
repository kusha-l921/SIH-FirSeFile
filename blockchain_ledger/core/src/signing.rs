/// Ed25519 key generation, signing, and verification.
///
/// This module wraps `ed25519-dalek` to provide hex-encoded key and signature
/// operations. Python callers interact with these through the PyO3 bindings,
/// receiving and providing hex strings for all cryptographic material.
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use rand::rngs::OsRng;

use crate::error::LedgerError;

/// Generates a new Ed25519 keypair using the OS CSPRNG.
///
/// # Returns
/// A tuple of `(private_key_hex, public_key_hex)` where both are lowercase
/// hex-encoded strings. The private key is 64 hex characters (32 bytes)
/// and the public key is 64 hex characters (32 bytes).
///
/// # Security
/// The private key should be stored securely and never logged after initial
/// generation. The public key can be shared freely.
pub fn generate_keypair() -> (String, String) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let private_hex = hex::encode(signing_key.to_bytes());
    let public_hex = hex::encode(verifying_key.to_bytes());
    (private_hex, public_hex)
}

/// Signs a block hash with the given private key.
///
/// # Arguments
/// * `private_key_hex` - Hex-encoded 32-byte Ed25519 private key
/// * `block_hash` - The hex-encoded SHA-256 block hash to sign
///
/// # Returns
/// Hex-encoded Ed25519 signature (128 hex characters / 64 bytes).
///
/// # Errors
/// Returns `LedgerError::InvalidKeyFormat` if the private key hex is malformed
/// or not the correct length.
pub fn sign(private_key_hex: &str, block_hash: &str) -> Result<String, LedgerError> {
    let key_bytes = hex::decode(private_key_hex)
        .map_err(|e| LedgerError::InvalidKeyFormat(format!("invalid private key hex: {}", e)))?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| LedgerError::InvalidKeyFormat("private key must be exactly 32 bytes".to_string()))?;
    let signing_key = SigningKey::from_bytes(&key_array);
    let signature = signing_key.sign(block_hash.as_bytes());
    Ok(hex::encode(signature.to_bytes()))
}

/// Verifies an Ed25519 signature against a public key and block hash.
///
/// # Arguments
/// * `public_key_hex` - Hex-encoded 32-byte Ed25519 public key
/// * `block_hash` - The hex-encoded SHA-256 block hash that was signed
/// * `signature_hex` - Hex-encoded 64-byte Ed25519 signature
///
/// # Returns
/// `true` if the signature is valid for the given public key and hash,
/// `false` otherwise (including if any hex decoding fails).
pub fn verify_signature(public_key_hex: &str, block_hash: &str, signature_hex: &str) -> bool {
    let result = (|| -> Result<bool, LedgerError> {
        let pub_bytes = hex::decode(public_key_hex)
            .map_err(|e| LedgerError::InvalidKeyFormat(format!("invalid public key hex: {}", e)))?;
        let pub_array: [u8; 32] = pub_bytes
            .try_into()
            .map_err(|_| LedgerError::InvalidKeyFormat("public key must be exactly 32 bytes".to_string()))?;
        let verifying_key = VerifyingKey::from_bytes(&pub_array)
            .map_err(|e| LedgerError::InvalidKeyFormat(format!("invalid public key: {}", e)))?;

        let sig_bytes = hex::decode(signature_hex)
            .map_err(|e| LedgerError::InvalidSignature(format!("invalid signature hex: {}", e)))?;
        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| LedgerError::InvalidSignature("signature must be exactly 64 bytes".to_string()))?;
        let signature = Signature::from_bytes(&sig_array);

        Ok(verifying_key.verify(block_hash.as_bytes(), &signature).is_ok())
    })();

    result.unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair_format() {
        let (private_hex, public_hex) = generate_keypair();
        assert_eq!(private_hex.len(), 64);
        assert_eq!(public_hex.len(), 64);
        // Verify they are valid hex
        hex::decode(&private_hex).unwrap();
        hex::decode(&public_hex).unwrap();
    }

    #[test]
    fn test_sign_and_verify_success() {
        let (private_hex, public_hex) = generate_keypair();
        let block_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let signature = sign(&private_hex, block_hash).unwrap();
        assert!(verify_signature(&public_hex, block_hash, &signature));
    }

    #[test]
    fn test_verify_fails_with_mutated_hash() {
        let (private_hex, public_hex) = generate_keypair();
        let block_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let signature = sign(&private_hex, block_hash).unwrap();
        let mutated_hash = "0000001234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        assert!(!verify_signature(&public_hex, mutated_hash, &signature));
    }

    #[test]
    fn test_verify_fails_with_wrong_key() {
        let (private_hex, _public_hex) = generate_keypair();
        let (_other_private, other_public) = generate_keypair();
        let block_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let signature = sign(&private_hex, block_hash).unwrap();
        assert!(!verify_signature(&other_public, block_hash, &signature));
    }

    #[test]
    fn test_sign_with_invalid_key_returns_error() {
        let result = sign("not_valid_hex", "somehash");
        assert!(result.is_err());
    }
}
