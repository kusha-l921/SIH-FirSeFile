"""
adapter.py
==========
Forensic XFS Recovery Adapter for FirSeFile.

Bridges the authoritative Rust xfs-recovery-engine into the Python pipeline.
Operates strictly in READ-ONLY mode against evidence disk images.

Exposes:
  - Filesystem information (Superblock geometry, UUID, CRC status)
  - RecoveryCandidate[] with full forensic provenance:
      * inode number
      * source location (byte offset, AG, block, slot)
      * recovery method (unlinked chain, residual extents, zero link anomaly)
      * recovery confidence (high, medium, low)
      * original_size (None/null if deleted file size zeroed by XFS)
      * observed_extent_bytes (actual surviving extent bytes)
      * extents list (logical_start, physical_start, block_count, state)
      * forensic evidence & parser issues
      * experimental flag
      * content SHA-256 and exactness indicator
      * full binary candidate content streaming access
  - Canonical FirSeFile recovered_files schema mapping with format validation
"""

import os
import sys
import json
import shutil
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

# Project root path resolution
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.validation.validator import validate_reconstructed_file


def _find_xfs_engine_binary() -> Path:
    """Locate or build the Rust xfs-recovery-engine executable from correct-recovery-engine."""
    exe_name = "xfs-recovery-engine.exe" if sys.platform == "win32" else "xfs-recovery-engine"

    candidate_paths = [
        PROJECT_ROOT / "correct-recovery-engine" / "target" / "release" / exe_name,
        PROJECT_ROOT / "correct-recovery-engine" / "target" / "debug" / exe_name,
        PROJECT_ROOT / "target" / "release" / exe_name,
        PROJECT_ROOT / "target" / "debug" / exe_name,
    ]

    for p in candidate_paths:
        if p.exists() and os.access(p, os.X_OK):
            return p

    # Check system PATH
    which_bin = shutil.which(exe_name)
    if which_bin:
        return Path(which_bin)

    # Attempt automatic build via cargo in correct-recovery-engine/
    cargo_bin = shutil.which("cargo")
    if cargo_bin:
        correct_engine_dir = PROJECT_ROOT / "correct-recovery-engine"
        try:
            subprocess.run(
                [
                    cargo_bin,
                    "build",
                    "--release",
                    "--manifest-path",
                    str(correct_engine_dir / "Cargo.toml"),
                    "--bin",
                    "xfs-recovery-engine",
                    "--target-dir",
                    str(correct_engine_dir / "target"),
                ],
                cwd=str(correct_engine_dir),
                check=True,
                capture_output=True,
            )
            for p in candidate_paths:
                if p.exists() and os.access(p, os.X_OK):
                    return p
        except Exception:
            pass

    raise FileNotFoundError(
        f"Could not locate '{exe_name}'. Please build it using 'cargo build --release --manifest-path correct-recovery-engine/Cargo.toml --bin xfs-recovery-engine'."
    )


def _ts_to_iso(ts_dict: Optional[Dict[str, Any]]) -> Optional[str]:
    """Convert timestamp dict {sec, nsec} to ISO-8601 UTC string."""
    if not ts_dict:
        return None
    sec = ts_dict.get("sec", 0)
    if sec and sec > 0:
        try:
            return datetime.fromtimestamp(sec, tz=timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            return None
    return None


def _map_confidence_score(conf_str: str) -> float:
    """Map Rust RecoveryConfidence string to floating point confidence score."""
    clow = str(conf_str).lower()
    if clow == "high":
        return 0.95
    elif clow == "medium":
        return 0.75
    elif clow == "low":
        return 0.50
    try:
        return float(conf_str)
    except (ValueError, TypeError):
        return 0.70


class XfsRecoveryEngine:
    """
    Python wrapper invoking the authoritative Rust XFS forensic recovery engine.
    """

    def __init__(
        self,
        image_path: str,
        binary_path: Optional[str] = None,
        enable_experimental: bool = True,
        base_offset: int = 0,
        walk_mode: str = "strict",
    ):
        self.image_path = Path(image_path).resolve()
        if not self.image_path.exists():
            raise FileNotFoundError(f"Evidence image not found: {self.image_path}")

        self.binary_path = Path(binary_path) if binary_path else _find_xfs_engine_binary()
        self.enable_experimental = enable_experimental
        self.base_offset = base_offset
        self.walk_mode = walk_mode

    def scan(self) -> Dict[str, Any]:
        """
        Execute scan on the image and parse the full forensic JSON report.
        """
        cmd = [
            str(self.binary_path),
            "scan",
            str(self.image_path),
            "--json",
            "--base-offset", str(self.base_offset),
            "--walk-mode", self.walk_mode,
        ]
        if self.enable_experimental:
            cmd.append("--experimental")

        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )

        if res.returncode != 0:
            err_msg = res.stderr.strip() or f"xfs-recovery-engine exited with code {res.returncode}"
            return {
                "is_valid": False,
                "error": err_msg,
                "fs_info": {},
                "summary": {},
                "candidates": [],
                "rejections": [],
            }

        try:
            return json.loads(res.stdout)
        except json.JSONDecodeError as e:
            return {
                "is_valid": False,
                "error": f"Failed to parse engine JSON output: {e}",
                "raw_output": res.stdout,
                "fs_info": {},
                "summary": {},
                "candidates": [],
                "rejections": [],
            }

    def read_candidate_bytes(self, ino: int) -> bytes:
        """
        Read the full reconstructed byte stream for a specific candidate inode directly from Rust.
        """
        cmd = [
            str(self.binary_path),
            "cat-candidate",
            str(self.image_path),
            str(ino),
            "--base-offset", str(self.base_offset),
            "--walk-mode", self.walk_mode,
        ]
        if self.enable_experimental:
            cmd.append("--experimental")

        res = subprocess.run(
            cmd,
            capture_output=True,
            check=False,
        )

        if res.returncode != 0:
            err = res.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"Failed to read content for inode {ino}: {err}")

        return res.stdout

    def recover_structured(self) -> Dict[str, Any]:
        """
        Runs XFS recovery and converts candidates into canonical FirSeFile recovered_files format.
        Preserves all forensic metadata, structural extents, SHA-256 digests, and validation info.
        """
        scan_data = self.scan()
        if not scan_data.get("is_valid", False):
            return {
                "filesystem": "xfs",
                "is_valid_filesystem": False,
                "error": scan_data.get("error", "Invalid or corrupt XFS image"),
                "summary": scan_data.get("summary", {}),
                "recovered_files": [],
                "rejections": scan_data.get("rejections", []),
            }

        fs_info = scan_data.get("fs_info", {})
        block_size = fs_info.get("block_size", 4096)
        candidates = scan_data.get("candidates", [])
        rejections = scan_data.get("rejections", [])
        summary = scan_data.get("summary", {})

        recovered_files: List[Dict[str, Any]] = []

        for cand in candidates:
            ino = cand["ino"]
            loc = cand.get("source_location", {})
            byte_offset = loc.get("byte_offset", 0)

            # Retrieve candidate binary payload
            try:
                candidate_bytes = self.read_candidate_bytes(ino)
            except Exception as e:
                candidate_bytes = b""

            # Perform format-aware validation on recovered bytes
            val_report = validate_reconstructed_file(candidate_bytes)
            detected_ext = val_report.detected_format if val_report.detected_format != "unknown" else "bin"

            # Inode metadata & timestamps
            mtime_iso = _ts_to_iso(cand.get("mtime"))
            atime_iso = _ts_to_iso(cand.get("atime"))
            ctime_iso = _ts_to_iso(cand.get("ctime"))
            crtime_iso = _ts_to_iso(cand.get("crtime"))

            # Sizes: preserve original_size = None if deleted size zeroed out
            orig_size = cand.get("original_size")
            observed_bytes = cand.get("observed_extent_bytes", len(candidate_bytes))
            content_hash_exact = cand.get("content_hash_exact", False)
            content_sha256 = cand.get("content_sha256") or val_report.sha256

            # Compute effective file size for downstream tools
            eff_size = orig_size if orig_size is not None else observed_bytes

            # Confidence mapping: preserve canonical confidence score from Rust
            base_conf = _map_confidence_score(cand.get("confidence", "medium"))
            conf = base_conf

            # Mode & Permissions
            mode_val = cand.get("mode", 0o100644)
            perm_val = cand.get("permissions", 0o644)
            perm_oct = oct(perm_val)

            file_id = f"xfs:ino{ino}"
            filename = f"xfs_deleted_ino_{ino}.{detected_ext}"

            # Additional forensic attributes
            add_attrs = {
                "ino": ino,
                "ag_number": cand.get("ag_number", loc.get("ag_number", 0)),
                "ag_block": loc.get("ag_block", 0),
                "slot": loc.get("slot", 0),
                "generation": cand.get("generation", 0),
                "nlink": cand.get("nlink", 0),
                "candidate_class": cand.get("candidate_class"),
                "recovery_method": cand.get("recovery_method"),
                "is_experimental": cand.get("is_experimental", False),
                "content_hash_exact": content_hash_exact,
                "content_sha256": content_sha256,
                "evidence": cand.get("evidence", []),
                "issues": cand.get("issues", []),
                "extents": cand.get("extents", []),
                "validation_status": val_report.status,
            }

            metadata_entry = {
                "filename": filename,
                "file_size": eff_size,
                "size": eff_size,
                "original_size": orig_size,
                "observed_extent_bytes": observed_bytes,
                "created": crtime_iso,
                "modified": mtime_iso,
                "accessed": atime_iso,
                "changed": ctime_iso,
                "deleted_if_available": True,
                "permissions": perm_oct,
                "ownership": {
                    "uid": cand.get("uid", 0),
                    "gid": cand.get("gid", 0),
                },
                "filesystem": "xfs",
                "source_locations": [byte_offset],
                "additional_attributes": add_attrs,
            }

            file_entry = {
                "file_id": file_id,
                "filename": filename,
                "file_type": val_report.detected_format,
                "file_size": eff_size,
                "size": eff_size,
                "original_size": orig_size,
                "observed_extent_bytes": observed_bytes,
                "content_hash_exact": content_hash_exact,
                "reconstructed_bytes": candidate_bytes,
                "metadata": metadata_entry,
                "source_locations": [byte_offset],
                "recovery_method": cand.get("recovery_method", "xfs_residual_extents"),
                "confidence": conf,
                "confidence_class": cand.get("confidence", "medium"),
                "sha256": content_sha256,
                "validation": val_report.to_dict(),
                "is_experimental": cand.get("is_experimental", False),
            }

            recovered_files.append(file_entry)

        return {
            "filesystem": "xfs",
            "is_valid_filesystem": True,
            "block_size": block_size,
            "fs_info": fs_info,
            "summary": summary,
            "recovered_files": recovered_files,
            "rejections": rejections,
        }


def recover_xfs_image(
    image_path: str,
    enable_experimental: bool = True,
    base_offset: int = 0,
    walk_mode: str = "strict",
) -> Dict[str, Any]:
    """
    Convenience function to scan and recover artifacts from an XFS evidence image.
    """
    engine = XfsRecoveryEngine(
        image_path=image_path,
        enable_experimental=enable_experimental,
        base_offset=base_offset,
        walk_mode=walk_mode,
    )
    return engine.recover_structured()
