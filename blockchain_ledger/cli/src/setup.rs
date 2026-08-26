/// Operator keypair setup — once per machine, idempotent CLI wrapper.
///
/// Delegates to `blockchain_ledger_core::keystore`.
use blockchain_ledger_core::keystore::{default_keystore_path, load_keystore_from, load_or_generate_keypair, KeyRecord};

pub fn load_keystore() -> Result<Option<KeyRecord>, Box<dyn std::error::Error>> {
    let path = default_keystore_path()?;
    let record = load_keystore_from(&path)?;
    Ok(record)
}

/// Runs the idempotent setup process from CLI.
pub fn run_setup() -> Result<(), Box<dyn std::error::Error>> {
    let (record, is_new) = load_or_generate_keypair()?;
    let path = default_keystore_path()?;

    // Print public key to stdout
    println!("{}", record.public_key_hex);

    // Print private key to stderr ONCE on first generation
    if is_new {
        eprintln!("╔══════════════════════════════════════════════════════════════╗");
        eprintln!("║  ⚠️  OPERATOR PRIVATE KEY — STORE THIS SECURELY!            ║");
        eprintln!("║  This key will NOT be displayed again.                      ║");
        eprintln!("║  Back it up if the keystore file is ever lost.              ║");
        eprintln!("╠══════════════════════════════════════════════════════════════╣");
        eprintln!("║  Private Key: {}  ║", &record.private_key_hex);
        eprintln!("║  Keystore:    {}  ║", path.display());
        eprintln!("╚══════════════════════════════════════════════════════════════╝");
    }

    Ok(())
}
