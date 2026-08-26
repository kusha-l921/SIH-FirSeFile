"""
test_ml_integration.py
======================
Integration tests for the full ML pipeline:

  Fragment
    -> ML Classification (Byte2Image + Zero-Training / Swin V2)
    -> Graph-Based Reassembly (FragmentNode + edge scoring + beam search)
    -> Format Validation
    -> Blockchain Ledger Record
    -> GUI/CLI result shape verification
"""

import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from src.ml_pipeline import (
    FragmentInput,
    classify_fragment,
    classify_fragments,
    build_fragment_nodes,
    reassemble_fragments,
    validate_reconstruction,
    build_ledger_payload,
    run_ml_pipeline,
)
from src.reassembly.graph import FragmentNode
from src.reassembly.edge_scoring import compute_edge_score, EdgeWeightConfig
from src.validation.validator import validate_reconstructed_file
from scripts.generate_synthetic_fixtures import SAMPLE_PDF, SAMPLE_PNG, SAMPLE_ZIP, SAMPLE_SQLITE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fragment(frag_id: str, data: bytes, offset: int = 0) -> FragmentInput:
    return FragmentInput(
        fragment_id=frag_id,
        raw_bytes=data[:512].ljust(512, b"\x00"),
        source_offset=offset,
        filesystem_source="xfs",
    )


# ---------------------------------------------------------------------------
# Stage 1: ML Classification
# ---------------------------------------------------------------------------

class TestMLClassification:

    def test_classify_single_pdf_fragment(self):
        frag = _make_fragment("pdf_frag_0", SAMPLE_PDF)
        result = classify_fragment(frag, zero_training=True)

        assert result.fragment_id == "pdf_frag_0"
        assert result.predicted_class in ["pdf", "txt", "doc", "rtf"]
        assert 0.0 < result.confidence <= 1.0
        assert result.entropy >= 0.0
        assert len(result.top_k) >= 1
        assert result.model_info != ""

    def test_classify_png_fragment(self):
        frag = _make_fragment("png_frag_0", SAMPLE_PNG)
        result = classify_fragment(frag, zero_training=True)

        assert result.predicted_class in ["png", "jpg", "gif", "bmp", "webp"]
        assert result.confidence > 0.5

    def test_classify_batch(self):
        frags = [
            _make_fragment("f0", SAMPLE_PDF, offset=0),
            _make_fragment("f1", SAMPLE_PNG, offset=512),
            _make_fragment("f2", SAMPLE_ZIP, offset=1024),
        ]
        results = classify_fragments(frags, zero_training=True)

        assert len(results) == 3
        for r in results:
            assert r.fragment_id in ["f0", "f1", "f2"]
            assert 0.0 < r.confidence <= 1.0
            assert len(r.top_k) >= 1

    def test_classify_returns_top_k(self):
        frag = _make_fragment("f_topk", SAMPLE_PDF)
        result = classify_fragment(frag, zero_training=True, top_k=5)
        assert len(result.top_k) <= 5
        # Probabilities should be in descending order
        probs = [p for _, p in result.top_k]
        assert probs == sorted(probs, reverse=True)


# ---------------------------------------------------------------------------
# Stage 2: Graph-Based Reassembly
# ---------------------------------------------------------------------------

class TestGraphReassembly:

    def test_build_fragment_nodes(self):
        frags = [
            _make_fragment("f0", SAMPLE_PDF[:512], offset=0),
            _make_fragment("f1", SAMPLE_PDF[512:1024] if len(SAMPLE_PDF) > 512 else SAMPLE_PDF, offset=512),
        ]
        cls_results = classify_fragments(frags, zero_training=True)
        nodes = build_fragment_nodes(frags, cls_results)

        assert len(nodes) == 2
        for node in nodes:
            assert isinstance(node, FragmentNode)
            assert node.fragment_id in ["f0", "f1"]
            assert len(node.raw_bytes) == 512
            assert node.predicted_class != ""
            assert 0.0 < node.confidence <= 1.0

    def test_edge_score_same_class_higher_than_different(self):
        # pdf_node1: header fragment (starts with %PDF-)
        # pdf_node2: body fragment (no magic header, same class)
        # png_node: PNG header (magic header -> structural violation as successor)
        pdf_header = SAMPLE_PDF[:512].ljust(512, b"\x00")
        pdf_body = b"1 0 obj << /Type /Page >> endobj\n" + b"\x00" * 480  # no magic header
        png_header = SAMPLE_PNG[:512].ljust(512, b"\x00")

        pdf_node1 = FragmentNode("p1", pdf_header, "pdf", 0.95, {"pdf": 0.95})
        pdf_node2 = FragmentNode("p2", pdf_body, "pdf", 0.90, {"pdf": 0.90})
        png_node = FragmentNode("img1", png_header, "png", 0.92, {"png": 0.92})

        score_same, _ = compute_edge_score(pdf_node1, pdf_node2)
        score_diff, _ = compute_edge_score(pdf_node1, png_node)

        # PNG has magic header so it should be -1.0 (structural violation as successor)
        assert score_diff == -1.0
        # pdf body fragment has no magic header, so same-class edge should be positive
        assert score_same > 0.0

    def test_reassemble_two_pdf_fragments(self):
        chunk1 = SAMPLE_PDF[:256].ljust(512, b"\x00")
        chunk2 = SAMPLE_PDF[256:512].ljust(512, b"\x00") if len(SAMPLE_PDF) > 256 else SAMPLE_PDF[:256].ljust(512, b"\x00")

        frags = [
            _make_fragment("pdf_0", chunk1, offset=0),
            _make_fragment("pdf_1", chunk2, offset=512),
        ]
        cls_results = classify_fragments(frags, zero_training=True)
        nodes = build_fragment_nodes(frags, cls_results)
        result = reassemble_fragments(nodes)

        assert result.fragment_count == 2
        assert result.total_size_bytes == 1024
        assert len(result.sha256) == 64
        assert result.detected_primary_type != ""
        assert result.reconstruction_confidence >= 0.0

    def test_reassemble_single_fragment(self):
        frags = [_make_fragment("solo", SAMPLE_PDF)]
        cls_results = classify_fragments(frags, zero_training=True)
        nodes = build_fragment_nodes(frags, cls_results)
        result = reassemble_fragments(nodes)

        assert result.fragment_count == 1
        assert result.total_size_bytes == 512
        assert result.unused_fragment_ids == []


# ---------------------------------------------------------------------------
# Stage 3: Format Validation
# ---------------------------------------------------------------------------

class TestFormatValidation:

    def test_validate_pdf_reconstruction(self):
        frags = [_make_fragment("pdf_v", SAMPLE_PDF)]
        cls_results = classify_fragments(frags, zero_training=True)
        nodes = build_fragment_nodes(frags, cls_results)
        recon = reassemble_fragments(nodes)
        report = validate_reconstruction(recon)

        assert report.sha256 == hashlib.sha256(recon.reconstructed_bytes).hexdigest()
        assert report.reconstructed_size == 512

    def test_validate_full_pdf_bytes(self):
        report = validate_reconstructed_file(SAMPLE_PDF)
        assert report.is_valid
        assert report.detected_format == "pdf"
        assert report.sha256 == hashlib.sha256(SAMPLE_PDF).hexdigest()

    def test_validate_full_png_bytes(self):
        report = validate_reconstructed_file(SAMPLE_PNG)
        assert report.is_valid
        assert report.detected_format == "png"

    def test_validate_corrupted_pdf(self):
        corrupted = b"%PDF-1.4\nno trailer or eof here"
        report = validate_reconstructed_file(corrupted)
        assert not report.is_valid


# ---------------------------------------------------------------------------
# Stage 4: Blockchain Ledger Payload
# ---------------------------------------------------------------------------

class TestLedgerPayload:

    def test_ledger_payload_has_required_fields(self):
        frags = [_make_fragment("lp_frag", SAMPLE_PDF)]
        cls_results = classify_fragments(frags, zero_training=True)
        nodes = build_fragment_nodes(frags, cls_results)
        recon = reassemble_fragments(nodes)
        report = validate_reconstruction(recon)
        payload = build_ledger_payload(recon, report, cls_results)

        # Must satisfy full_recovery block schema
        required = ["filename", "macb_timestamps", "recovered_file_sha256", "size", "source_location", "recovery_method"]
        for field in required:
            assert field in payload, f"Missing required ledger field: {field}"

        assert payload["recovered_file_sha256"] == recon.sha256
        assert payload["size"] == recon.total_size_bytes
        assert "ml_metadata" in payload
        assert payload["ml_metadata"]["fragment_count"] == 1

    def test_ledger_payload_ml_metadata(self):
        frags = [
            _make_fragment("lm0", SAMPLE_PDF[:512], offset=0),
            _make_fragment("lm1", SAMPLE_PDF[:512], offset=512),
        ]
        cls_results = classify_fragments(frags, zero_training=True)
        nodes = build_fragment_nodes(frags, cls_results)
        recon = reassemble_fragments(nodes)
        report = validate_reconstruction(recon)
        payload = build_ledger_payload(recon, report, cls_results)

        ml = payload["ml_metadata"]
        assert ml["fragment_count"] == 2
        assert len(ml["ordered_fragment_ids"]) == 2
        assert ml["validation_is_valid"] == report.is_valid
        assert len(ml["top_classifications"]) == 2


# ---------------------------------------------------------------------------
# Full Pipeline (end-to-end)
# ---------------------------------------------------------------------------

class TestFullPipeline:

    def test_run_ml_pipeline_single_fragment(self):
        frags = [_make_fragment("e2e_0", SAMPLE_PDF)]
        result = run_ml_pipeline(frags, zero_training=True)

        assert len(result.classifications) == 1
        assert result.reassembly is not None
        assert result.validation is not None
        assert result.ledger_payload != {}

        cls = result.classifications[0]
        assert cls.fragment_id == "e2e_0"
        assert cls.predicted_class != ""

        recon = result.reassembly
        assert recon.fragment_count == 1
        assert recon.total_size_bytes == 512

        val = result.validation
        assert "is_valid" in val
        assert "sha256" in val

        payload = result.ledger_payload
        assert payload["recovered_file_sha256"] == recon.sha256

    def test_run_ml_pipeline_multi_fragment(self):
        frags = [
            _make_fragment("m0", SAMPLE_PDF[:512], offset=0),
            _make_fragment("m1", SAMPLE_PDF[:512], offset=512),
            _make_fragment("m2", SAMPLE_PDF[:512], offset=1024),
        ]
        result = run_ml_pipeline(frags, zero_training=True)

        assert len(result.classifications) == 3
        assert result.reassembly.fragment_count == 3
        assert result.reassembly.total_size_bytes == 1536
        assert result.validation["sha256"] == result.reassembly.sha256

    def test_run_ml_pipeline_empty_input(self):
        result = run_ml_pipeline([], zero_training=True)
        assert result.classifications == []
        assert result.reassembly is None
        assert result.validation is None
        assert result.ledger_payload == {}

    def test_pipeline_result_ledger_payload_is_json_serializable(self):
        frags = [_make_fragment("json_test", SAMPLE_PDF)]
        result = run_ml_pipeline(frags, zero_training=True)
        # Must be JSON-serializable for blockchain ledger recording
        serialized = json.dumps(result.ledger_payload)
        assert len(serialized) > 0

    def test_pipeline_sha256_is_stable(self):
        """Same input bytes must always produce the same SHA-256."""
        frags = [_make_fragment("stable", SAMPLE_PDF)]
        r1 = run_ml_pipeline(frags, zero_training=True)
        r2 = run_ml_pipeline(frags, zero_training=True)
        assert r1.reassembly.sha256 == r2.reassembly.sha256

    def test_pipeline_with_mixed_types(self):
        """Mixed-type fragments should still produce a valid pipeline result."""
        frags = [
            _make_fragment("mix_pdf", SAMPLE_PDF[:512], offset=0),
            _make_fragment("mix_png", SAMPLE_PNG[:512], offset=512),
            _make_fragment("mix_zip", SAMPLE_ZIP[:512], offset=1024),
        ]
        result = run_ml_pipeline(frags, zero_training=True)
        assert len(result.classifications) == 3
        assert result.reassembly is not None
        assert result.reassembly.fragment_count == 3


# ---------------------------------------------------------------------------
# GUI/CLI result shape verification
# ---------------------------------------------------------------------------

class TestGuiCliResultShape:
    """
    Verify that pipeline outputs match the shapes expected by the GUI/CLI
    (Tauri MlResultSummary and RecoveredFile types).
    """

    def test_ml_result_summary_shape(self):
        frags = [_make_fragment("gui_frag", SAMPLE_PDF)]
        result = run_ml_pipeline(frags, zero_training=True)

        cls = result.classifications[0]
        recon = result.reassembly
        val = result.validation

        # Simulate what get_ml_results_core() would return
        summary = {
            "file_id": cls.fragment_id,
            "predicted_class": cls.predicted_class,
            "ml_confidence": cls.confidence,
            "top_k": [{"class_name": c, "probability": p} for c, p in cls.top_k],
            "validation_status": val["status"],
            "validation_is_valid": val["is_valid"],
            "reconstruction_confidence": recon.reconstruction_confidence,
            "sha256": recon.sha256,
            "ledger_block_index": None,
        }

        assert summary["file_id"] == "gui_frag"
        assert isinstance(summary["predicted_class"], str)
        assert 0.0 <= summary["ml_confidence"] <= 1.0
        assert isinstance(summary["top_k"], list)
        assert isinstance(summary["validation_is_valid"], bool)
        assert len(summary["sha256"]) == 64

    def test_recovered_file_ml_fields_shape(self):
        """Verify the ML fields that lib.rs populates on RecoveredFile."""
        frags = [_make_fragment("rf_frag", SAMPLE_PDF)]
        result = run_ml_pipeline(frags, zero_training=True)
        cls = result.classifications[0]
        recon = result.reassembly
        val = result.validation

        # Simulate what scan_image_core would set on RecoveredFile
        recovered_file_ml_fields = {
            "ml_predicted_class": cls.predicted_class,
            "ml_confidence": cls.confidence,
            "ml_top_k": [{"class_name": c, "probability": p} for c, p in cls.top_k],
            "validation_status": val["status"],
            "validation_is_valid": val["is_valid"],
            "reconstruction_confidence": recon.reconstruction_confidence,
        }

        assert recovered_file_ml_fields["ml_predicted_class"] != ""
        assert 0.0 <= recovered_file_ml_fields["ml_confidence"] <= 1.0
        assert isinstance(recovered_file_ml_fields["ml_top_k"], list)
        assert isinstance(recovered_file_ml_fields["validation_is_valid"], bool)


# ---------------------------------------------------------------------------
# Complete Pipeline Integration: Fragment -> ML -> Graph -> Validator -> Ledger -> GUI
# ---------------------------------------------------------------------------

class TestEndToEndIntegratedPipeline:
    """
    Validates the complete end-to-end integration:
      512-byte raw fragment
        -> Byte2Image transform
        -> Swin Transformer V2 / Zero-Training Classifier
        -> FragmentNode construction
        -> Graph-based edge scoring and beam search reassembly
        -> Format-aware structural validation
        -> Ed25519-signed Blockchain Recovery Ledger block recording
        -> Cryptographic chain verification
        -> GUI/CLI summary and metadata generation
    """

    def test_full_pipeline_with_ed25519_blockchain_ledger(self):
        import blockchain_ledger

        # 1. Fragment extraction & input preparation
        frag1_bytes = SAMPLE_PDF[:512].ljust(512, b"\x00")
        frag2_bytes = SAMPLE_PDF[512:1024].ljust(512, b"\x00") if len(SAMPLE_PDF) > 512 else b"%PDF-1.4\n%%EOF\n".ljust(512, b"\x00")

        fragments = [
            FragmentInput(fragment_id="frag_sec_0x1000", raw_bytes=frag1_bytes, source_offset=0x1000, filesystem_source="xfs"),
            FragmentInput(fragment_id="frag_sec_0x1200", raw_bytes=frag2_bytes, source_offset=0x1200, filesystem_source="xfs"),
        ]

        # 2. Keypair generation for forensic investigator
        priv_key, pub_key = blockchain_ledger.generate_keypair()
        assert len(priv_key) == 64
        assert len(pub_key) == 64

        # 3. Initialize Blockchain Genesis Block
        disk_sha = hashlib.sha256(b"synthetic_evidence_image_bytes").hexdigest()
        genesis_block = blockchain_ledger.create_genesis(disk_sha, pub_key, priv_key)
        assert genesis_block["block_type"] == "genesis"
        assert genesis_block["block_index"] == 0
        assert genesis_block["prev_hash"] == "0" * 64
        assert len(genesis_block["signature"]) == 128

        # 4. Execute ML Pipeline (Classification -> Graph -> Validation -> Ledger Payload)
        pipeline_res = run_ml_pipeline(fragments, zero_training=True)

        assert len(pipeline_res.classifications) == 2
        for cls_res in pipeline_res.classifications:
            assert cls_res.predicted_class in ["pdf", "txt", "doc", "rtf"]
            assert cls_res.confidence > 0.0
            assert len(cls_res.top_k) >= 1

        recon = pipeline_res.reassembly
        assert recon is not None
        assert recon.fragment_count == 2
        assert len(recon.sha256) == 64
        assert recon.total_size_bytes == 1024

        val = pipeline_res.validation
        assert val is not None
        assert "is_valid" in val
        assert val["detected_format"] == "pdf"

        # 5. Log recovery action into Blockchain Ledger
        recovery_block = blockchain_ledger.log_action(
            "full_recovery",
            pipeline_res.ledger_payload,
            file_id="rec_pdf_001",
            prev_block=genesis_block,
            signing_key_hex=priv_key,
        )

        assert recovery_block["block_type"] == "full_recovery"
        assert recovery_block["block_index"] == 1
        assert recovery_block["prev_hash"] == genesis_block["block_hash"]
        assert len(recovery_block["signature"]) == 128
        assert recovery_block["payload"]["recovered_file_sha256"] == recon.sha256

        # 6. Verify cryptographic custody chain
        chain = [genesis_block, recovery_block]
        verification = blockchain_ledger.verify_chain(chain, pub_key)
        assert verification["valid"] is True
        assert verification["broken_at_index"] is None

        # 7. Verify JSONL chain persistence
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            tmp_chain_path = f.name

        try:
            for b in chain:
                blockchain_ledger.append_block(b, tmp_chain_path)
            loaded_chain = blockchain_ledger.load_chain(tmp_chain_path)
            assert len(loaded_chain) == 2
            loaded_verification = blockchain_ledger.verify_chain(loaded_chain, pub_key)
            assert loaded_verification["valid"] is True
        finally:
            if Path(tmp_chain_path).exists():
                Path(tmp_chain_path).unlink()

        # 8. Verify GUI / CLI integration summary structure
        gui_ml_summary = {
            "file_id": "rec_pdf_001",
            "predicted_class": recon.detected_primary_type,
            "ml_confidence": recon.reconstruction_confidence,
            "top_k": [
                {"class_name": c, "probability": p}
                for c, p in pipeline_res.classifications[0].top_k
            ],
            "validation_status": val["status"],
            "validation_is_valid": val["is_valid"],
            "reconstruction_confidence": recon.reconstruction_confidence,
            "sha256": recon.sha256,
            "ledger_block_index": recovery_block["block_index"],
        }
        assert gui_ml_summary["file_id"] == "rec_pdf_001"
        assert gui_ml_summary["predicted_class"] == "pdf"
        assert gui_ml_summary["validation_is_valid"] is True
        assert gui_ml_summary["ledger_block_index"] == 1

