"""
test_end_to_end_pipeline.py
===========================
Comprehensive 3-Level Integration Test Suite for FirSeFile.

LEVEL 1 — Module Unit Tests
LEVEL 2 — Cross-Module Interoperability Tests
LEVEL 3 — Full End-to-End Pipeline Verification against Forensic Test Images
"""

import os
import sys
import json
import hashlib
import tempfile
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.validation.validator import validate_reconstructed_file
from src.representations.byte2image import bytes_to_byte2image
from src.models.zero_training_classifier import ZeroTrainingClassifier
from src.reassembly.graph import FragmentNode
from src.reassembly.edge_scoring import compute_edge_score, EdgeWeightConfig
from src.recovery.btrfs.btrfs_engine import BtrfsEngine
from tools.run_recovery import run_forensic_pipeline, XfsForensicScanner, ForensicLedger
from scripts.generate_synthetic_fixtures import (
    build_xfs_synthetic_image,
    build_btrfs_synthetic_image,
    SAMPLE_PDF,
    SAMPLE_PNG,
    SAMPLE_JPG,
    SAMPLE_ZIP,
    SAMPLE_SQLITE,
)


# ===========================================================================
# LEVEL 1 — Module Isolation Tests
# ===========================================================================

def test_level1_validator_formats():
    """Level 1: Validates PDF, PNG, and SQLite structural integrity checking."""
    pdf_report = validate_reconstructed_file(SAMPLE_PDF)
    assert pdf_report.is_valid
    assert pdf_report.detected_format == "pdf"
    assert pdf_report.sha256 == hashlib.sha256(SAMPLE_PDF).hexdigest()

    png_report = validate_reconstructed_file(SAMPLE_PNG)
    assert png_report.is_valid
    assert png_report.detected_format == "png"

    corrupted_data = b"%PDF-1.4\nCorrupted content without trailer"
    corrupt_report = validate_reconstructed_file(corrupted_data)
    assert not corrupt_report.is_valid


def test_level1_byte2image_transform():
    """Level 1: Verifies Byte2Image bit-sliding 2D grayscale transformation."""
    fragment = b"\x00\x01\x02\x03" * 128  # 512 bytes
    img_array = bytes_to_byte2image(fragment, target_size=(256, 256))
    assert img_array.shape == (256, 256)


# ===========================================================================
# LEVEL 2 — Cross-Module Interoperability Tests
# ===========================================================================

def test_level2_fragment_to_ml_classification():
    """
    Level 2: Fragment extraction -> Byte2Image / Zero-Training Classifier.
    Proves raw bytes extracted from disk can be directly classified.
    """
    classifier = ZeroTrainingClassifier()
    pdf_fragment = SAMPLE_PDF[:512]
    pred = classifier.predict_fragment(pdf_fragment)
    assert pred.predicted_class in ["pdf", "txt", "doc"]
    assert pred.confidence > 0.5


def test_level2_ml_to_graph_reassembly():
    """
    Level 2: Fragment sequence -> Edge scoring -> Composite affinity.
    Proves fragmented parts can be scored based on format and boundary compatibility.
    """
    frag1 = SAMPLE_PDF[:256]
    frag2 = SAMPLE_PDF[256:]

    node1 = FragmentNode(fragment_id="f1", raw_bytes=frag1, predicted_class="pdf", confidence=0.95, probabilities={"pdf": 0.95})
    node2 = FragmentNode(fragment_id="f2", raw_bytes=frag2, predicted_class="pdf", confidence=0.95, probabilities={"pdf": 0.95})
    node_unrelated = FragmentNode(fragment_id="f3", raw_bytes=SAMPLE_PNG[:256], predicted_class="png", confidence=0.90, probabilities={"png": 0.90})

    config = EdgeWeightConfig()
    score_related, _ = compute_edge_score(node1, node2, config)
    score_unrelated, _ = compute_edge_score(node1, node_unrelated, config)

    assert score_related > score_unrelated


def test_level2_recovery_to_ledger_chain():
    """
    Level 2: Recovery output -> Blockchain Ledger entry -> Cryptographic chaining.
    """
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        chain_path = Path(f.name)

    try:
        ledger = ForensicLedger(chain_path)
        genesis = ledger.init_chain(Path("evidence.img"), "abc123hash")
        assert genesis["block_index"] == 0
        assert genesis["prev_hash"] == "0" * 64

        block1 = ledger.record_recovery(
            file_id="xfs:ino128",
            recovery_method="xfs_residual_extents",
            file_sha256="deadbeef123",
            size_bytes=1024,
            metadata={"filename": "doc.pdf"},
        )
        assert block1["block_index"] == 1
        assert block1["prev_hash"] == genesis["block_hash"]

        # Verify JSONL on disk
        lines = chain_path.read_text().splitlines()
        assert len(lines) == 2
    finally:
        if chain_path.exists():
            chain_path.unlink()


# ===========================================================================
# LEVEL 3 — Full End-to-End Forensic Recovery Tests
# ===========================================================================

def test_level3_xfs_end_to_end_recovery():
    """
    Level 3: Full End-to-End recovery from synthetic XFS image.
    Flow:
      xfs_deleted_synthetic.img
          ↓
      Acquisition & Filesystem Detection
          ↓
      XFS Structural Analysis & Extent Recovery
          ↓
      Format Validation (PDF & PNG)
          ↓
      SHA-256 Verification
          ↓
      Ledger Recording
          ↓
      PASS
    """
    with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as img_f:
        img_path = Path(img_f.name)
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as ledger_f:
        ledger_path = Path(ledger_f.name)

    try:
        manifest = build_xfs_synthetic_image(img_path)
        assert img_path.stat().st_size == manifest["total_size"]

        results = run_forensic_pipeline(
            str(img_path),
            ledger_path=str(ledger_path),
        )

        assert results["detected_filesystem"] == "xfs"
        assert results["total_files_recovered"] >= 2

        # Check recovered files match expected SHA-256
        recovered_shas = {f.get("sha256") for f in results["recovered_files"]}
        expected_pdf_sha = hashlib.sha256(SAMPLE_PDF).hexdigest()
        expected_png_sha = hashlib.sha256(SAMPLE_PNG).hexdigest()

        assert expected_pdf_sha in recovered_shas, "Deleted PDF must be recovered with exact SHA-256"
        assert expected_png_sha in recovered_shas, "Deleted PNG must be recovered with exact SHA-256"

        # Verify ledger has records for all recovered files
        assert len(results["ledger_blocks"]) >= 3  # Genesis + at least 2 files
    finally:
        if img_path.exists():
            img_path.unlink()
        if ledger_path.exists():
            ledger_path.unlink()


def test_level3_btrfs_end_to_end_recovery():
    """
    Level 3: Full End-to-End recovery from synthetic Btrfs image.
    Flow:
      btrfs_deleted_synthetic.img
          ↓
      Acquisition & Filesystem Detection
          ↓
      Btrfs Inode / Carving Recovery
          ↓
      Format Validation
          ↓
      SHA-256 Verification
          ↓
      Ledger Recording
          ↓
      PASS
    """
    with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as img_f:
        img_path = Path(img_f.name)
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as ledger_f:
        ledger_path = Path(ledger_f.name)

    try:
        manifest = build_btrfs_synthetic_image(img_path)
        assert img_path.stat().st_size == 2097152

        results = run_forensic_pipeline(
            str(img_path),
            ledger_path=str(ledger_path),
        )

        assert results["detected_filesystem"] == "btrfs"
        assert results["total_files_recovered"] >= 2

        # Check recovered files
        recovered_shas = {f.get("sha256") for f in results["recovered_files"]}
        expected_pdf_sha = hashlib.sha256(SAMPLE_PDF).hexdigest()
        expected_png_sha = hashlib.sha256(SAMPLE_PNG).hexdigest()

        assert (expected_pdf_sha in recovered_shas or expected_png_sha in recovered_shas), \
            "At least one deleted artifact must be recovered with exact SHA-256"

        assert len(results["ledger_blocks"]) >= 2
    finally:
        if img_path.exists():
            img_path.unlink()
        if ledger_path.exists():
            ledger_path.unlink()
