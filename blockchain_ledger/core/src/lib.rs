/// Blockchain Recovery Ledger — Core Library
///
/// This crate provides the cryptographic chain-of-custody ledger for forensic
/// disk recovery operations. It handles block creation, hashing, signing,
/// verification, and storage.
///
/// Python callers access this functionality through the `blockchain_ledger`
/// PyO3 module, which wraps these functions with automatic dict/JSON conversion.

pub mod error;
pub mod hashing;
pub mod keystore;
pub mod ledger;
pub mod model;
pub mod signing;
pub mod storage;
pub mod verify;
