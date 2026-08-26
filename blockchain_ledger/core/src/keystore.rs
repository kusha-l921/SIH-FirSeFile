/// Operator keystore management and machine-bound keypair setup.
///
/// Manages the operator keypair file (`~/.forensic_tool/keystore.json`),
/// ensuring that a single keypair is generated per machine and reused
/// across all cases to prove continuity of investigator identity.
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::LedgerError;
use crate::signing::generate_keypair;

/// A stored keypair record in the keystore.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    /// Machine identifier used as lookup key (MAC address or platform UUID).
    pub machine_id: String,
    /// Hex-encoded Ed25519 public key.
    pub public_key_hex: String,
    /// Hex-encoded Ed25519 private key.
    pub private_key_hex: String,
    /// ISO 8601 timestamp of when this keypair was first generated.
    pub created_at: String,
}

/// Returns the default path to the keystore file (`~/.forensic_tool/keystore.json`).
pub fn default_keystore_path() -> Result<PathBuf, LedgerError> {
    let home = dirs::home_dir()
        .ok_or_else(|| LedgerError::ChainFileIo("Could not determine home directory".to_string()))?;
    Ok(home.join(".forensic_tool").join("keystore.json"))
}

/// Computes a machine identifier for idempotency.
///
/// On Linux: reads `/etc/machine-id` or `/var/lib/dbus/machine-id`.
/// On macOS: queries `ioreg` for `IOPlatformUUID`.
/// On Windows: queries `wmic csproduct get uuid`.
/// Fallback: hostname.
///
/// This value is used ONLY as a lookup key, never as cryptographic material.
#[cfg(target_os = "linux")]
pub fn get_machine_id() -> String {
    if let Ok(id) = fs::read_to_string("/etc/machine-id") {
        let trimmed = id.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(id) = fs::read_to_string("/var/lib/dbus/machine-id") {
        let trimmed = id.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    hostname_fallback()
}

#[cfg(target_os = "macos")]
pub fn get_machine_id() -> String {
    let output = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                if line.contains("IOPlatformUUID") {
                    if let Some(uuid) = line.split('"').nth(3) {
                        return uuid.to_string();
                    }
                }
            }
        }
    }
    hostname_fallback()
}

#[cfg(target_os = "windows")]
pub fn get_machine_id() -> String {
    let output = std::process::Command::new("wmic")
        .args(["csproduct", "get", "uuid"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && trimmed != "UUID" {
                    return trimmed.to_string();
                }
            }
            hostname_fallback()
        }
        _ => hostname_fallback(),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn get_machine_id() -> String {
    hostname_fallback()
}

/// Fallback machine identifier using environment variables.
fn hostname_fallback() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-machine".to_string())
}

/// Sets file permissions to 0600 on Unix systems (user read/write only).
#[cfg(unix)]
pub fn set_secure_permissions(path: &Path) -> Result<(), LedgerError> {
    use std::os::unix::fs::PermissionsExt;
    let permissions = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
pub fn set_secure_permissions(_path: &Path) -> Result<(), LedgerError> {
    // Windows file permissions are handled by user profile directory isolation
    Ok(())
}

/// Loads an existing keystore record from the given path if it exists.
pub fn load_keystore_from(path: &Path) -> Result<Option<KeyRecord>, LedgerError> {
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path)?;
    let record: KeyRecord = serde_json::from_str(&content)?;
    Ok(Some(record))
}

/// Loads or generates a new keypair at the specified keystore path.
///
/// Returns `(KeyRecord, is_newly_generated)`.
pub fn load_or_generate_keypair_at(path: &Path) -> Result<(KeyRecord, bool), LedgerError> {
    let machine_id = get_machine_id();

    // Check for existing record
    if let Some(record) = load_keystore_from(path)? {
        if record.machine_id == machine_id {
            return Ok((record, false));
        }
    }

    // Generate new keypair via CSPRNG (NOT derived from machine ID)
    let (private_key_hex, public_key_hex) = generate_keypair();

    let record = KeyRecord {
        machine_id,
        public_key_hex,
        private_key_hex,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(&record)?;
    fs::write(path, &json)?;
    set_secure_permissions(path)?;

    Ok((record, true))
}

/// Loads or generates a new keypair in the default location (`~/.forensic_tool/keystore.json`).
pub fn load_or_generate_keypair() -> Result<(KeyRecord, bool), LedgerError> {
    let path = default_keystore_path()?;
    load_or_generate_keypair_at(&path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_keystore_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("test_keystore_{}.json", rand::random::<u64>()));
        path
    }

    #[test]
    fn test_get_machine_id() {
        let id = get_machine_id();
        assert!(!id.is_empty());
    }

    #[test]
    fn test_idempotent_setup_workflow() {
        let path = temp_keystore_path();

        // 1. Initial generation
        let (rec1, is_new1) = load_or_generate_keypair_at(&path).unwrap();
        assert!(is_new1);
        assert_eq!(rec1.public_key_hex.len(), 64);
        assert_eq!(rec1.private_key_hex.len(), 64);

        // 2. Second call should return the exact same key without regenerating
        let (rec2, is_new2) = load_or_generate_keypair_at(&path).unwrap();
        assert!(!is_new2);
        assert_eq!(rec1.public_key_hex, rec2.public_key_hex);
        assert_eq!(rec1.private_key_hex, rec2.private_key_hex);
        assert_eq!(rec1.created_at, rec2.created_at);

        // 3. Deleting keystore and running again creates a DIFFERENT keypair
        let _ = fs::remove_file(&path);
        let (rec3, is_new3) = load_or_generate_keypair_at(&path).unwrap();
        assert!(is_new3);
        assert_ne!(rec1.public_key_hex, rec3.public_key_hex);
        assert_ne!(rec1.private_key_hex, rec3.private_key_hex);

        // Cleanup
        let _ = fs::remove_file(&path);
    }
}
