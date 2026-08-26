/// PyO3 bindings for the Blockchain Recovery Ledger.
///
/// Exposes the core ledger functions as a Python module named `blockchain_ledger`.
/// All functions accept and return Python-native types (dicts, lists, strings)
/// — no manual JSON string conversion is needed on the Python side.
use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use pyo3::types::{PyDict, PyList};
use pyo3::IntoPyObjectExt;

use blockchain_ledger_core::error::LedgerError;
use blockchain_ledger_core::model::Block;

/// Converts a LedgerError into a Python ValueError.
fn to_py_err(e: LedgerError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

/// Converts a serde_json::Value into a Python object.
fn value_to_py(py: Python<'_>, val: &serde_json::Value) -> PyResult<PyObject> {
    match val {
        serde_json::Value::Null => Ok(py.None()),
        serde_json::Value::Bool(b) => (*b).into_py_any(py),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into_py_any(py)
            } else if let Some(f) = n.as_f64() {
                f.into_py_any(py)
            } else {
                Err(PyValueError::new_err("Unsupported number type"))
            }
        }
        serde_json::Value::String(s) => s.as_str().into_py_any(py),
        serde_json::Value::Array(arr) => {
            let list = PyList::empty(py);
            for item in arr {
                list.append(value_to_py(py, item)?)?;
            }
            Ok(list.into_any().unbind())
        }
        serde_json::Value::Object(map) => {
            let dict = PyDict::new(py);
            for (k, v) in map {
                dict.set_item(k, value_to_py(py, v)?)?;
            }
            Ok(dict.into_any().unbind())
        }
    }
}

/// Converts a Python object into a serde_json::Value.
fn py_to_value(obj: &Bound<'_, PyAny>) -> PyResult<serde_json::Value> {
    if obj.is_none() {
        return Ok(serde_json::Value::Null);
    }
    if let Ok(b) = obj.extract::<bool>() {
        return Ok(serde_json::Value::Bool(b));
    }
    if let Ok(i) = obj.extract::<i64>() {
        return Ok(serde_json::json!(i));
    }
    if let Ok(f) = obj.extract::<f64>() {
        return Ok(serde_json::json!(f));
    }
    if let Ok(s) = obj.extract::<String>() {
        return Ok(serde_json::Value::String(s));
    }
    if let Ok(list) = obj.downcast::<PyList>() {
        let mut arr = Vec::new();
        for item in list.iter() {
            arr.push(py_to_value(&item)?);
        }
        return Ok(serde_json::Value::Array(arr));
    }
    if let Ok(dict) = obj.downcast::<PyDict>() {
        let mut map = serde_json::Map::new();
        for (k, v) in dict.iter() {
            let key: String = k.extract()?;
            map.insert(key, py_to_value(&v)?);
        }
        return Ok(serde_json::Value::Object(map));
    }
    Err(PyValueError::new_err("Unsupported Python type for JSON conversion"))
}

/// Converts a Block into a Python dict.
fn block_to_py_dict(py: Python<'_>, block: &Block) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    dict.set_item("block_type", block.block_type.to_string())?;
    dict.set_item("block_index", block.block_index)?;
    dict.set_item("timestamp", &block.timestamp)?;
    dict.set_item("file_id", &block.file_id)?;
    dict.set_item("prev_hash", &block.prev_hash)?;
    dict.set_item("payload", value_to_py(py, &block.payload)?)?;
    dict.set_item("block_hash", &block.block_hash)?;
    dict.set_item("signature", &block.signature)?;
    dict.set_item("public_key_id", &block.public_key_id)?;
    Ok(dict.into_any().unbind())
}

/// Converts a Python dict into a Block.
fn py_dict_to_block(dict: &Bound<'_, PyDict>) -> PyResult<Block> {
    let block_type_str: String = dict.get_item("block_type")?
        .ok_or_else(|| PyValueError::new_err("missing 'block_type'"))?
        .extract()?;
    let block_type: blockchain_ledger_core::model::BlockType = block_type_str.parse()
        .map_err(|e: LedgerError| PyValueError::new_err(e.to_string()))?;

    let payload_obj = dict.get_item("payload")?
        .ok_or_else(|| PyValueError::new_err("missing 'payload'"))?;
    let payload = py_to_value(&payload_obj)?;

    Ok(Block {
        block_type,
        block_index: dict.get_item("block_index")?
            .ok_or_else(|| PyValueError::new_err("missing 'block_index'"))?.extract()?,
        timestamp: dict.get_item("timestamp")?
            .ok_or_else(|| PyValueError::new_err("missing 'timestamp'"))?.extract()?,
        file_id: dict.get_item("file_id")?
            .ok_or_else(|| PyValueError::new_err("missing 'file_id'"))?.extract()?,
        prev_hash: dict.get_item("prev_hash")?
            .ok_or_else(|| PyValueError::new_err("missing 'prev_hash'"))?.extract()?,
        payload,
        block_hash: dict.get_item("block_hash")?
            .ok_or_else(|| PyValueError::new_err("missing 'block_hash'"))?.extract()?,
        signature: dict.get_item("signature")?
            .ok_or_else(|| PyValueError::new_err("missing 'signature'"))?.extract()?,
        public_key_id: dict.get_item("public_key_id")?
            .ok_or_else(|| PyValueError::new_err("missing 'public_key_id'"))?.extract()?,
    })
}

/// Generates a new Ed25519 keypair using the OS CSPRNG.
///
/// Returns a tuple of (private_key_hex, public_key_hex).
/// The private key should be stored securely and never logged.
#[pyfunction]
fn generate_keypair() -> (String, String) {
    blockchain_ledger_core::signing::generate_keypair()
}

/// Creates the genesis (first) block of a new forensic recovery chain.
///
/// Args:
///     disk_baseline_sha256: SHA-256 hash of the disk image
///     operator_pubkey_hex: Hex-encoded Ed25519 public key
///     signing_key_hex: Hex-encoded Ed25519 private key
///
/// Returns:
///     A dict representing the genesis block
#[pyfunction]
fn create_genesis(
    py: Python<'_>,
    disk_baseline_sha256: &str,
    operator_pubkey_hex: &str,
    signing_key_hex: &str,
) -> PyResult<PyObject> {
    let block = blockchain_ledger_core::ledger::create_genesis(
        disk_baseline_sha256,
        operator_pubkey_hex,
        signing_key_hex,
    ).map_err(to_py_err)?;
    block_to_py_dict(py, &block)
}

/// Logs a new recovery action to the chain.
///
/// Args:
///     block_type: One of "metadata_only", "data_only", "full_recovery"
///     payload: A Python dict describing the recovery action
///     file_id: Identifier for the recovered file
///     prev_block: Dict of the previous block in the chain
///     signing_key_hex: Hex-encoded Ed25519 private key
///
/// Returns:
///     A dict representing the new block
#[pyfunction]
fn log_action(
    py: Python<'_>,
    block_type: &str,
    payload: &Bound<'_, PyAny>,
    file_id: &str,
    prev_block: &Bound<'_, PyDict>,
    signing_key_hex: &str,
) -> PyResult<PyObject> {
    let payload_value = py_to_value(payload)?;
    let prev = py_dict_to_block(prev_block)?;

    let block = blockchain_ledger_core::ledger::log_action(
        block_type,
        payload_value,
        file_id,
        &prev,
        signing_key_hex,
    ).map_err(to_py_err)?;

    block_to_py_dict(py, &block)
}

/// Verifies the integrity of a block chain.
///
/// Args:
///     blocks: A list of block dicts in chain order
///     pubkey_hex: Hex-encoded Ed25519 public key
///
/// Returns:
///     A dict with keys: valid (bool), broken_at_index (int or None), reason (str or None)
#[pyfunction]
fn verify_chain(
    py: Python<'_>,
    blocks: &Bound<'_, PyList>,
    pubkey_hex: &str,
) -> PyResult<PyObject> {
    let mut rust_blocks = Vec::new();
    for item in blocks.iter() {
        let dict = item.downcast::<PyDict>()?;
        rust_blocks.push(py_dict_to_block(dict)?);
    }

    let result = blockchain_ledger_core::verify::verify_chain(&rust_blocks, pubkey_hex);

    let dict = PyDict::new(py);
    dict.set_item("valid", result.valid)?;
    match result.broken_at_index {
        Some(idx) => dict.set_item("broken_at_index", idx)?,
        None => dict.set_item("broken_at_index", py.None())?,
    }
    match &result.reason {
        Some(r) => dict.set_item("reason", r)?,
        None => dict.set_item("reason", py.None())?,
    }
    Ok(dict.into_any().unbind())
}

/// Appends a block to a JSONL chain file.
///
/// Args:
///     block: A dict representing the block to append
///     path: Path to the JSONL chain file
#[pyfunction]
fn append_block(block: &Bound<'_, PyDict>, path: &str) -> PyResult<()> {
    let rust_block = py_dict_to_block(block)?;
    blockchain_ledger_core::storage::append_block(&rust_block, std::path::Path::new(path))
        .map_err(to_py_err)?;
    Ok(())
}

/// Loads all blocks from a JSONL chain file.
///
/// Args:
///     path: Path to the JSONL chain file
///
/// Returns:
///     A list of block dicts
#[pyfunction]
fn load_chain(py: Python<'_>, path: &str) -> PyResult<PyObject> {
    let blocks = blockchain_ledger_core::storage::load_chain(std::path::Path::new(path))
        .map_err(to_py_err)?;

    let list = PyList::empty(py);
    for block in &blocks {
        list.append(block_to_py_dict(py, block)?)?;
    }
    Ok(list.into_any().unbind())
}

/// Loads or generates a new keypair in the default location (`~/.forensic_tool/keystore.json`).
///
/// Returns a tuple of `(private_key_hex, public_key_hex, is_newly_generated)`.
#[pyfunction]
fn load_or_generate_keypair() -> PyResult<(String, String, bool)> {
    let (record, is_new) = blockchain_ledger_core::keystore::load_or_generate_keypair()
        .map_err(to_py_err)?;
    Ok((record.private_key_hex, record.public_key_hex, is_new))
}

/// Python module for the Blockchain Recovery Ledger.
#[pymodule]
fn blockchain_ledger(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(load_or_generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(create_genesis, m)?)?;
    m.add_function(wrap_pyfunction!(log_action, m)?)?;
    m.add_function(wrap_pyfunction!(verify_chain, m)?)?;
    m.add_function(wrap_pyfunction!(append_block, m)?)?;
    m.add_function(wrap_pyfunction!(load_chain, m)?)?;
    Ok(())
}
