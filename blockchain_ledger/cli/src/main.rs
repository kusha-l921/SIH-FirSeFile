/// Blockchain Recovery Ledger CLI
///
/// Provides subcommands for initializing forensic recovery chains,
/// logging recovery actions, verifying chain integrity, and setting up
/// operator keypairs.
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod setup;

/// Blockchain Recovery Ledger — forensic chain-of-custody CLI
#[derive(Parser)]
#[command(name = "blockchain-ledger")]
#[command(about = "Forensic recovery chain-of-custody ledger")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new chain with a genesis block
    Init {
        /// SHA-256 hash of the disk image being investigated
        #[arg(long)]
        disk_hash: String,

        /// Path to the output JSONL chain file
        #[arg(long, short)]
        output: PathBuf,

        /// Hex-encoded private key (if omitted, loads from keystore via setup)
        #[arg(long)]
        key: Option<String>,
    },

    /// Log a recovery action to the chain
    Log {
        /// Path to the JSONL chain file
        #[arg(long)]
        chain: PathBuf,

        /// Block type: metadata_only, data_only, or full_recovery
        #[arg(long = "type")]
        block_type: String,

        /// File identifier for this recovery action
        #[arg(long)]
        file_id: String,

        /// Hex-encoded private key for signing
        #[arg(long)]
        key: String,
    },

    /// Verify the integrity of a chain file
    Verify {
        /// Path to the JSONL chain file
        #[arg(long)]
        chain: PathBuf,

        /// Hex-encoded public key to verify signatures against
        #[arg(long)]
        pubkey: String,
    },

    /// Set up operator keypair (once per machine, idempotent)
    Setup,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init { disk_hash, output, key } => cmd_init(&disk_hash, &output, key.as_deref()),
        Commands::Log { chain, block_type, file_id, key } => {
            cmd_log(&chain, &block_type, &file_id, &key)
        }
        Commands::Verify { chain, pubkey } => cmd_verify(&chain, &pubkey),
        Commands::Setup => cmd_setup(),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

/// Initializes a new chain with a genesis block.
fn cmd_init(
    disk_hash: &str,
    output: &PathBuf,
    key: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (private_key, public_key) = match key {
        Some(k) => {
            // Derive public key from private key
            let key_bytes = hex::decode(k)
                .map_err(|e| format!("Invalid private key hex: {}", e))?;
            let key_array: [u8; 32] = key_bytes.try_into()
                .map_err(|_| "Private key must be exactly 32 bytes")?;
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);
            let pub_hex = hex::encode(signing_key.verifying_key().to_bytes());
            (k.to_string(), pub_hex)
        }
        None => {
            // Try to load from keystore
            match setup::load_keystore()? {
                Some(record) => (record.private_key_hex, record.public_key_hex),
                None => {
                    return Err("No key provided and no keystore found. Run 'setup' first or provide --key.".into());
                }
            }
        }
    };

    let genesis = blockchain_ledger_core::ledger::create_genesis(
        disk_hash, &public_key, &private_key,
    )?;

    blockchain_ledger_core::storage::append_block(&genesis, output)?;

    // Print public key to stdout
    println!("{}", public_key);

    Ok(())
}

/// Logs a recovery action to the chain. Reads JSON payload from stdin.
fn cmd_log(
    chain_path: &PathBuf,
    block_type: &str,
    file_id: &str,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read payload from stdin
    let mut payload_str = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut payload_str)?;
    let payload: serde_json::Value = serde_json::from_str(&payload_str)
        .map_err(|e| format!("Invalid JSON payload from stdin: {}", e))?;

    // Load existing chain
    let chain = blockchain_ledger_core::storage::load_chain(chain_path)?;
    let prev_block = chain.last()
        .ok_or("Chain file is empty — no previous block found")?;

    let new_block = blockchain_ledger_core::ledger::log_action(
        block_type, payload, file_id, prev_block, key,
    )?;

    blockchain_ledger_core::storage::append_block(&new_block, chain_path)?;

    // Print the created block as JSON to stdout
    let json_output = serde_json::to_string_pretty(&new_block)?;
    println!("{}", json_output);

    Ok(())
}

/// Verifies the integrity of a chain file.
fn cmd_verify(
    chain_path: &PathBuf,
    pubkey: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let chain = blockchain_ledger_core::storage::load_chain(chain_path)?;
    let result = blockchain_ledger_core::verify::verify_chain(&chain, pubkey);

    let json_output = serde_json::to_string_pretty(&result)?;
    println!("{}", json_output);

    if !result.valid {
        std::process::exit(1);
    }

    Ok(())
}

/// Sets up the operator keypair (idempotent).
fn cmd_setup() -> Result<(), Box<dyn std::error::Error>> {
    setup::run_setup()?;
    Ok(())
}
