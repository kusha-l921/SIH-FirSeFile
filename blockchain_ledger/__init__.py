"""
blockchain_ledger
=================
Python package providing cryptographic blockchain recovery ledger capabilities.
Serves as the native Python implementation and fallback for PyO3 bindings.
"""

from __future__ import annotations

import os
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


REQUIRED_PAYLOAD_FIELDS = {
    "genesis": ["disk_baseline_sha256", "operator_public_key"],
    "metadata_only": ["filename", "macb_timestamps", "recovery_method"],
    "data_only": ["recovered_file_sha256", "source_location", "size", "recovery_method"],
    "full_recovery": ["filename", "macb_timestamps", "recovered_file_sha256", "size", "source_location", "recovery_method"],
}


def generate_keypair() -> Tuple[str, str]:
    """
    Generate a new Ed25519 keypair.
    Returns (private_key_hex, public_key_hex).
    """
    priv = ed25519.Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes_raw()
    pub_bytes = priv.public_key().public_bytes_raw()
    return priv_bytes.hex(), pub_bytes.hex()


def load_or_generate_keypair(keystore_path: Optional[str] = None) -> Tuple[str, str, bool]:
    """
    Load or generate keypair in ~/.forensic_tool/keystore.json.
    Returns (private_key_hex, public_key_hex, is_newly_generated).
    """
    if keystore_path is None:
        keystore_dir = Path.home() / ".forensic_tool"
        keystore_file = keystore_dir / "keystore.json"
    else:
        keystore_file = Path(keystore_path)
        keystore_dir = keystore_file.parent

    if keystore_file.exists():
        try:
            data = json.loads(keystore_file.read_text(encoding="utf-8"))
            if "private_key_hex" in data and "public_key_hex" in data:
                return data["private_key_hex"], data["public_key_hex"], False
        except Exception:
            pass

    keystore_dir.mkdir(parents=True, exist_ok=True)
    priv_hex, pub_hex = generate_keypair()
    record = {
        "private_key_hex": priv_hex,
        "public_key_hex": pub_hex,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    keystore_file.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return priv_hex, pub_hex, True


def canonical_json(value: Any) -> str:
    """Deterministic JSON serialization with sorted keys and no extra whitespace."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def compute_block_hash(
    prev_hash: str,
    block_type: str,
    block_index: int,
    file_id: str,
    timestamp: str,
    payload: Any,
) -> str:
    """Compute SHA-256 block hash over block fields."""
    c_payload = canonical_json(payload)
    preimage = f"{prev_hash}{block_type}{block_index}{file_id}{timestamp}{c_payload}"
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()


def sign_hash(private_key_hex: str, block_hash: str) -> str:
    """Sign a block hash string with Ed25519 private key."""
    priv_bytes = bytes.fromhex(private_key_hex)
    priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    sig = priv_key.sign(block_hash.encode("utf-8"))
    return sig.hex()


def verify_signature(public_key_hex: str, block_hash: str, signature_hex: str) -> bool:
    """Verify an Ed25519 signature over a block hash."""
    try:
        pub_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig_bytes, block_hash.encode("utf-8"))
        return True
    except (InvalidSignature, Exception):
        return False


def validate_payload(block_type: str, payload: Dict[str, Any]) -> None:
    """Validate that required fields exist for given block type."""
    required = REQUIRED_PAYLOAD_FIELDS.get(block_type)
    if not required:
        raise ValueError(f"Invalid or unsupported block type: '{block_type}'")
    for field in required:
        if field not in payload:
            raise ValueError(f"Missing required field '{field}' for block type '{block_type}'")


def create_genesis(
    disk_baseline_sha256: str,
    operator_pubkey_hex: str,
    signing_key_hex: str,
) -> Dict[str, Any]:
    """Create the genesis block of a new forensic recovery chain."""
    block_type = "genesis"
    block_index = 0
    prev_hash = "0" * 64
    file_id = ""
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = {
        "disk_baseline_sha256": disk_baseline_sha256,
        "operator_public_key": operator_pubkey_hex,
    }

    validate_payload(block_type, payload)
    block_hash = compute_block_hash(prev_hash, block_type, block_index, file_id, timestamp, payload)
    signature = sign_hash(signing_key_hex, block_hash)

    return {
        "block_type": block_type,
        "block_index": block_index,
        "timestamp": timestamp,
        "file_id": file_id,
        "prev_hash": prev_hash,
        "payload": payload,
        "block_hash": block_hash,
        "signature": signature,
        "public_key_id": operator_pubkey_hex,
    }


def log_action(
    block_type: str,
    payload: Dict[str, Any],
    file_id: str,
    prev_block: Dict[str, Any],
    signing_key_hex: str,
) -> Dict[str, Any]:
    """Log a new recovery action block to the chain."""
    validate_payload(block_type, payload)

    block_index = prev_block["block_index"] + 1
    prev_hash = prev_block["block_hash"]
    timestamp = datetime.now(timezone.utc).isoformat()
    public_key_id = prev_block.get("public_key_id") or prev_block.get("payload", {}).get("operator_public_key", "")

    block_hash = compute_block_hash(prev_hash, block_type, block_index, file_id, timestamp, payload)
    signature = sign_hash(signing_key_hex, block_hash)

    return {
        "block_type": block_type,
        "block_index": block_index,
        "timestamp": timestamp,
        "file_id": file_id,
        "prev_hash": prev_hash,
        "payload": payload,
        "block_hash": block_hash,
        "signature": signature,
        "public_key_id": public_key_id,
    }


def verify_chain(blocks: List[Dict[str, Any]], pubkey_hex: str) -> Dict[str, Any]:
    """
    Verify full cryptographic integrity of the block chain.
    Returns {"valid": bool, "broken_at_index": int|None, "reason": str|None}.
    """
    if not blocks:
        return {"valid": False, "broken_at_index": 0, "reason": "empty chain"}

    # Genesis checks
    genesis = blocks[0]
    if genesis.get("block_index") != 0:
        return {"valid": False, "broken_at_index": 0, "reason": "genesis block_index != 0"}
    if genesis.get("prev_hash") != "0" * 64:
        return {"valid": False, "broken_at_index": 0, "reason": "genesis prev_hash must be 64 zeros"}

    for idx, b in enumerate(blocks):
        # Index check
        if b.get("block_index") != idx:
            return {"valid": False, "broken_at_index": idx, "reason": f"index mismatch: expected {idx}, got {b.get('block_index')}"}

        # Prev hash check
        if idx > 0:
            if b.get("prev_hash") != blocks[idx - 1].get("block_hash"):
                return {"valid": False, "broken_at_index": idx, "reason": f"prev_hash mismatch at block {idx}"}

        # Block hash check
        recomputed = compute_block_hash(
            b["prev_hash"],
            b["block_type"],
            b["block_index"],
            b.get("file_id", ""),
            b["timestamp"],
            b["payload"],
        )
        if recomputed != b.get("block_hash"):
            return {"valid": False, "broken_at_index": idx, "reason": f"hash mismatch at block {idx}: computed {recomputed} != recorded {b.get('block_hash')}"}

        # Signature check
        if not verify_signature(pubkey_hex, b["block_hash"], b["signature"]):
            return {"valid": False, "broken_at_index": idx, "reason": f"invalid signature at block {idx}"}

    return {"valid": True, "broken_at_index": None, "reason": None}


def append_block(block: Dict[str, Any], path: str) -> None:
    """Append block as a JSON line to the target JSONL file."""
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(block) + "\n")


def load_chain(path: str) -> List[Dict[str, Any]]:
    """Load chain of blocks from a JSONL file."""
    file_path = Path(path)
    if not file_path.exists():
        return []
    blocks = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                blocks.append(json.loads(line))
    return blocks
