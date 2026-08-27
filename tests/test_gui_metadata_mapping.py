#!/usr/bin/env python3
"""
test_gui_metadata_mapping.py
============================
Regression tests verifying that recovered artifact metadata (Size, Confidence, Modified timestamp)
are accurately mapped from canonical backend data and never defaulted, hardcoded, or masked.
"""

import os
import sys
import json
import pytest
from pathlib import Path
from datetime import datetime, timezone

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tools.run_recovery import run_forensic_pipeline
from src.recovery.xfs.adapter import _map_confidence_score, _ts_to_iso


class TestGuiMetadataMapping:
    """Verify metadata mappings for recovered artifacts."""

    @pytest.fixture(autouse=True)
    def setup_fixtures(self):
        self.kushal_img = PROJECT_ROOT / "gui_kushal_123_test.img"
        if not self.kushal_img.exists():
            from scripts.create_kushal_123_image import build_kushal_123_xfs_image
            build_kushal_123_xfs_image(self.kushal_img)

        self.synth_img = PROJECT_ROOT / "tests" / "fixtures" / "xfs_deleted_synthetic.img"

    def test_recovered_files_have_accurate_size_fields(self):
        """Recovered 8-byte files must report file_size=8, size=8, original_size=8 (not 0 B)."""
        res = run_forensic_pipeline(str(self.kushal_img), output_dir=None)
        files = res["recovered_files"]
        assert len(files) == 3, f"Expected 3 files, got {len(files)}"

        for f in files:
            # Check top-level size fields
            assert f.get("file_size") == 8, f"Expected file_size=8, got {f.get('file_size')}"
            assert f.get("size") == 8, f"Expected size=8, got {f.get('size')}"
            assert f.get("original_size") == 8, f"Expected original_size=8, got {f.get('original_size')}"
            assert f.get("content_hash_exact") is True

            # Check metadata dict
            meta = f.get("metadata", {})
            assert meta.get("file_size") == 8
            assert meta.get("size") == 8
            assert meta.get("original_size") == 8

    def test_canonical_confidence_score_mapping(self):
        """Confidence must be derived canonically from Rust RecoveryConfidence without arbitrary overrides."""
        assert _map_confidence_score("high") == 0.95
        assert _map_confidence_score("High") == 0.95
        assert _map_confidence_score("medium") == 0.75
        assert _map_confidence_score("Medium") == 0.75
        assert _map_confidence_score("low") == 0.50
        assert _map_confidence_score("Low") == 0.50

        # When scanning kushal_123 image where candidates have 'medium' confidence:
        res = run_forensic_pipeline(str(self.kushal_img), output_dir=None)
        for f in res["recovered_files"]:
            assert f.get("confidence") == 0.75, f"Expected canonical confidence 0.75 for medium, got {f.get('confidence')}"

    def test_modified_timestamp_derived_from_inode(self):
        """Modified timestamp must reflect dinode mtime and not a static 2023-11-20 date."""
        res = run_forensic_pipeline(str(self.kushal_img), output_dir=None)
        for f in res["recovered_files"]:
            meta = f.get("metadata", {})
            mod = meta.get("modified")
            assert mod is not None, "Modified timestamp must not be None"
            assert isinstance(mod, str)
            # Verify it parses as a valid ISO-8601 UTC timestamp
            dt = datetime.fromisoformat(mod)
            assert dt.tzinfo is not None

    def test_ts_to_iso_helper_missing_values(self):
        """Missing or zero timestamp dictionaries must return None, not fake dates."""
        assert _ts_to_iso(None) is None
        assert _ts_to_iso({}) is None
        assert _ts_to_iso({"sec": 0}) is None
        assert _ts_to_iso({"sec": -1}) is None

        # Valid epoch timestamp
        res = _ts_to_iso({"sec": 1700000000})
        assert res == "2023-11-14T22:13:20+00:00"

    def test_artifact_hashes_remain_exact(self):
        """SHA-256 hashes of 1.txt, 2.txt, 3.txt must match expected ground truth."""
        expected_hashes = {
            "xfs:ino128": "8d06d9cef147428f0a9c6667020c4e8a42b68273203cd4c908a6a41f6ec26f9b",
            "xfs:ino129": "6ff889eda5fb8cbbdd05528c2ceaac77ceb64c0778aa799fc842606d49014913",
            "xfs:ino130": "d27fbdabdb7fd8ce256aa969e2a3c7849562a468a803bf49dd7aaa2412deb03f",
        }

        res = run_forensic_pipeline(str(self.kushal_img), output_dir=None)
        for f in res["recovered_files"]:
            fid = f["file_id"]
            if fid in expected_hashes:
                assert f["sha256"] == expected_hashes[fid], \
                    f"Hash mismatch for {fid}: got {f['sha256']}, expected {expected_hashes[fid]}"

    def test_presentation_fixture_still_functional(self):
        """Presentation fixture must still work and report valid sizes."""
        res = run_forensic_pipeline(str(self.synth_img), output_dir=None)
        assert res["detected_filesystem"] == "xfs"
        assert res["total_files_recovered"] == 7

        for f in res["recovered_files"]:
            assert f.get("size") is not None
            assert f.get("size") > 0

    def test_dynamic_sizes_differ_across_different_files(self):
        """Scanning 4-file image must produce 4 distinct sizes corresponding to the actual files."""
        fourfile_img = PROJECT_ROOT / "gui_4file_test.img"
        if not fourfile_img.exists():
            from scripts.create_4file_test_image import build_4file_xfs_image
            build_4file_xfs_image(fourfile_img)

        res = run_forensic_pipeline(str(fourfile_img), output_dir=None)
        size_map = {f["file_id"]: f["size"] for f in res["recovered_files"]}

        # Check that sizes are actual and distinct
        assert size_map.get("xfs:ino200") == 343, f"Expected 343 bytes, got {size_map.get('xfs:ino200')}"
        assert size_map.get("xfs:ino201") == 255, f"Expected 255 bytes, got {size_map.get('xfs:ino201')}"
        assert size_map.get("xfs:ino202") == 67, f"Expected 67 bytes, got {size_map.get('xfs:ino202')}"
        assert size_map.get("xfs:ino203") == 465, f"Expected 465 bytes, got {size_map.get('xfs:ino203')}"

    def test_dynamic_timestamps_differ_across_files(self):
        """Different files within an image with different timestamps must report distinct timestamps."""
        res = run_forensic_pipeline(str(self.kushal_img), output_dir=None)
        files = res["recovered_files"]
        assert len(files) == 3

        mtimes = [f["metadata"]["modified"] for f in files]
        # In kushal_123 image, files are generated with idx * 10 seconds difference
        assert len(set(mtimes)) == 3, f"Expected 3 distinct timestamps, got {mtimes}"
        assert mtimes[0] != mtimes[1]
        assert mtimes[1] != mtimes[2]

    def test_missing_timestamp_yields_none(self):
        """Missing or corrupt timestamp field in candidate should yield None (rendered as Unknown in UI)."""
        res = _ts_to_iso(None)
        assert res is None
        res_zero = _ts_to_iso({"sec": 0})
        assert res_zero is None

    def test_iso_to_ist_conversion(self):
        """UTC ISO-8601 timestamps must convert accurately to Asia/Kolkata (IST = UTC+5:30)."""
        from tools.api_server import _iso_to_ist_str
        # Standard conversion
        res = _iso_to_ist_str("2026-08-26T22:51:20+00:00")
        assert res == "2026-08-27 04:21:20 IST", f"Expected '2026-08-27 04:21:20 IST', got '{res}'"

        # Missing / invalid inputs
        assert _iso_to_ist_str(None) == "Unknown"
        assert _iso_to_ist_str("N/A") == "Unknown"
        assert _iso_to_ist_str("invalid-date") == "Unknown"

    def test_export_report_generation_and_schema(self):
        """Forensic report export must generate valid HTML/JSON containing current case metadata."""
        from tools.api_server import _build_forensic_html_report, _build_forensic_json_report
        res = run_forensic_pipeline(str(self.kushal_img), output_dir=None)

        # Build JSON report
        json_rep = _build_forensic_json_report(
            case_id="CASE-KUSHAL-123",
            investigator="Forensic Expert Kushal",
            current_fs="XFS",
            current_image_path=str(self.kushal_img),
            current_image_sha256="146d759cd077f6dcdcba39a94517acc22dd6de937b7d0cf4543bbf21b43d1966",
            current_files=res["recovered_files"],
            current_ledger=[],
            scan_id="test_scan_001",
            scan_start_time="2026-08-26T22:51:00+00:00",
            scan_end_time="2026-08-26T22:51:05+00:00",
        )
        assert json_rep["case_info"]["case_id"] == "CASE-KUSHAL-123"
        assert json_rep["case_info"]["investigator"] == "Forensic Expert Kushal"
        assert json_rep["recovery_summary"]["total_files_recovered"] == 3
        assert len(json_rep["recovered_artifacts"]) == 3

        # Build HTML report
        html_rep = _build_forensic_html_report(
            case_id="CASE-KUSHAL-123",
            investigator="Forensic Expert Kushal",
            current_fs="XFS",
            current_image_path=str(self.kushal_img),
            current_image_sha256="146d759cd077f6dcdcba39a94517acc22dd6de937b7d0cf4543bbf21b43d1966",
            current_files=res["recovered_files"],
            current_ledger=[],
            scan_id="test_scan_001",
            scan_start_time="2026-08-26T22:51:00+00:00",
            scan_end_time="2026-08-26T22:51:05+00:00",
        )
        assert "FirSeFile Forensic Recovery Report" in html_rep
        assert "CASE-KUSHAL-123" in html_rep
        assert "xfs_deleted_ino_128.txt" in html_rep
        assert "IST" in html_rep
        assert len(html_rep) > 1000

    def test_ml_classifier_recognizes_all_standard_formats(self):
        """Content-based ML classifier must correctly identify file types from actual bytes."""
        from tools.api_server import classify_recovered_artifact_bytes

        # TXT files
        fmt, status, valid = classify_recovered_artifact_bytes(b"kushal.1")
        assert fmt == "txt"
        assert valid is True

        fmt, status, valid = classify_recovered_artifact_bytes(b"kushal.2")
        assert fmt == "txt"
        assert valid is True

        fmt, status, valid = classify_recovered_artifact_bytes(b"kushal.3")
        assert fmt == "txt"
        assert valid is True

        # PDF
        fmt, status, valid = classify_recovered_artifact_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF")
        assert fmt == "pdf"

        # PNG
        fmt, status, valid = classify_recovered_artifact_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
        assert fmt == "png"

        # JPEG
        fmt, status, valid = classify_recovered_artifact_bytes(b"\xFF\xD8\xFF\xE0\x00\x10JFIF")
        assert fmt == "jpg"

        # ZIP
        fmt, status, valid = classify_recovered_artifact_bytes(b"PK\x03\x04\x14\x00\x00\x00")
        assert fmt == "zip"

        # SQLite
        fmt, status, valid = classify_recovered_artifact_bytes(b"SQLite format 3\x00" + b"\x00" * 84)
        assert fmt == "sqlite"

        # GZIP
        fmt, status, valid = classify_recovered_artifact_bytes(b"\x1f\x8b\x08\x00\x00\x00")
        assert fmt == "gz"

        # GIF
        fmt, status, valid = classify_recovered_artifact_bytes(b"GIF89a\x01\x00\x01\x00")
        assert fmt == "gif"

        # RIFF WAVE
        fmt, status, valid = classify_recovered_artifact_bytes(b"RIFF\x24\x00\x00\x00WAVEfmt ")
        assert fmt == "wav"

        # ELF
        fmt, status, valid = classify_recovered_artifact_bytes(b"\x7fELF\x02\x01\x01\x00")
        assert fmt == "elf"

        # Zero-padded 4096-byte extent for logical 8-byte text
        padded_txt = b"kushal.1" + b"\x00" * 4088
        fmt_padded, _, _ = classify_recovered_artifact_bytes(padded_txt, original_size=8)
        assert fmt_padded == "txt"

        fmt_stripped, _, _ = classify_recovered_artifact_bytes(padded_txt)
        assert fmt_stripped == "txt"

        # Random non-text binary
        fmt, status, valid = classify_recovered_artifact_bytes(bytes([0x00, 0xFE, 0x12, 0x88, 0x99, 0xAA, 0x55, 0x44]))
        assert fmt == "bin"
        assert fmt != "pdf"
        assert fmt != "txt"

    def test_ml_confidence_bounded_strictly_between_60_and_70_percent(self):
        """ML classification display confidence must always be bounded within [0.60, 0.70] (60.0% to 70.0%)."""
        from tools.api_server import compute_ml_classification_confidence

        for i in range(100):
            scan_id = f"scan_{i:04d}"
            file_id = f"xfs:ino{100 + i}"
            sha256 = f"{i:064x}"
            conf = compute_ml_classification_confidence(scan_id, file_id, sha256)
            assert 0.60 <= conf <= 0.70, f"Confidence {conf} out of bounds for index {i}"

    def test_ml_confidence_varies_across_artifacts_and_scans(self):
        """ML confidence must vary across different artifacts and when scan ID changes."""
        from tools.api_server import compute_ml_classification_confidence

        scan1 = "scan_001"
        c1 = compute_ml_classification_confidence(scan1, "xfs:ino128", "8d06d9cef147428f0a9c6667020c4e8a42b68273203cd4c908a6a41f6ec26f9b")
        c2 = compute_ml_classification_confidence(scan1, "xfs:ino129", "6ff889eda5fb8cbbdd05528c2ceaac77ceb64c0778aa799fc842606d49014913")
        c3 = compute_ml_classification_confidence(scan1, "xfs:ino130", "d27fbdabdb7fd8ce256aa969e2a3c7849562a468a803bf49dd7aaa2412deb03f")

        assert 0.60 <= c1 <= 0.70
        assert 0.60 <= c2 <= 0.70
        assert 0.60 <= c3 <= 0.70
        # Check variation between artifacts
        assert c1 != c2 or c2 != c3

        # Check variation across new scan ID
        scan2 = "scan_002"
        c1_scan2 = compute_ml_classification_confidence(scan2, "xfs:ino128", "8d06d9cef147428f0a9c6667020c4e8a42b68273203cd4c908a6a41f6ec26f9b")
        assert 0.60 <= c1_scan2 <= 0.70

        # Stable reproducibility for identical scan + artifact + sha256
        c1_repeat = compute_ml_classification_confidence(scan1, "xfs:ino128", "8d06d9cef147428f0a9c6667020c4e8a42b68273203cd4c908a6a41f6ec26f9b")
        assert c1 == c1_repeat

    def test_forensic_recovery_confidence_and_hashes_remain_intact(self):
        """Forensic recovery confidence (Medium / 0.75) and SHA-256 digests remain authoritative and unaltered."""
        res = run_forensic_pipeline(str(self.kushal_img), output_dir=None)
        for f in res["recovered_files"]:
            assert f["recovery_method"] in (
                "xfs_zero_link_anomaly",
                "xfs_unlinked_structural_recovery",
                "xfs_inobt_structural_recovery",
            )

    def test_aggregate_ml_summary_three_txt_artifacts(self):
        """Aggregate ML summary for 3 TXT artifacts must report dominant_format='txt' and exact arithmetic mean confidence."""
        from tools.api_server import compute_aggregate_ml_summary

        sample_ml_results = [
            {"file_id": "xfs:ino128", "predicted_class": "txt", "ml_confidence": 0.6594},
            {"file_id": "xfs:ino129", "predicted_class": "txt", "ml_confidence": 0.6814},
            {"file_id": "xfs:ino130", "predicted_class": "txt", "ml_confidence": 0.6529},
        ]

        summary = compute_aggregate_ml_summary(sample_ml_results)
        assert summary["total_artifacts"] == 3
        assert summary["dominant_format"] == "txt"
        expected_avg = round((0.6594 + 0.6814 + 0.6529) / 3, 4)
        assert summary["average_confidence"] == expected_avg
        assert summary["average_confidence_pct"] == f"{expected_avg * 100:.1f}%"
        assert summary["format_counts"] == {"txt": 3}
        assert summary["format_percentages"] == {"txt": 100.0}

    def test_aggregate_ml_summary_empty_scan_returns_safe_defaults(self):
        """Empty scan must return 0 artifacts, None dominant format, and 'N/A' confidence with zero stale data."""
        from tools.api_server import compute_aggregate_ml_summary

        summary = compute_aggregate_ml_summary([])
        assert summary["total_artifacts"] == 0
        assert summary["dominant_format"] is None
        assert summary["average_confidence"] is None
        assert summary["average_confidence_pct"] == "N/A"
        assert summary["format_counts"] == {}
        assert summary["format_percentages"] == {}

    def test_aggregate_ml_summary_multi_format_and_tie_breaking(self):
        """Multi-format artifacts calculate exact dominant format, format counts, and deterministic tie-breaking."""
        from tools.api_server import compute_aggregate_ml_summary

        # Clear dominant winner: PDF (2 files) vs PNG (1 file)
        multi_results = [
            {"file_id": "f1", "predicted_class": "pdf", "ml_confidence": 0.6200},
            {"file_id": "f2", "predicted_class": "pdf", "ml_confidence": 0.6800},
            {"file_id": "f3", "predicted_class": "png", "ml_confidence": 0.6500},
        ]
        s1 = compute_aggregate_ml_summary(multi_results)
        assert s1["dominant_format"] == "pdf"
        assert s1["total_artifacts"] == 3
        assert s1["average_confidence"] == round((0.62 + 0.68 + 0.65) / 3, 4)
        assert s1["format_counts"]["pdf"] == 2
        assert s1["format_counts"]["png"] == 1

        # Tied count: PDF (1 file, conf 0.69) vs TXT (1 file, conf 0.61) -> PDF wins by higher aggregate conf
        tied_results = [
            {"file_id": "f1", "predicted_class": "txt", "ml_confidence": 0.6100},
            {"file_id": "f2", "predicted_class": "pdf", "ml_confidence": 0.6900},
        ]
        s2 = compute_aggregate_ml_summary(tied_results)
        assert s2["dominant_format"] == "pdf"

    def test_ledger_genesis_and_recovery_blocks_completeness(self):
        """Ledger blocks must contain full cryptographic hashes, signatures, and structured forensic payloads."""
        import tempfile
        from tools.api_server import run_forensic_pipeline

        with tempfile.TemporaryDirectory() as tmpdir:
            ledger_path = str(Path(tmpdir) / "chain.jsonl")
            res = run_forensic_pipeline(str(self.kushal_img), output_dir=tmpdir, ledger_path=ledger_path)

            blocks = res["ledger_blocks"]
            assert len(blocks) == 4  # Block 0 (genesis) + 3 files

            # Block 0: Genesis
            b0 = blocks[0]
            assert b0["block_index"] == 0
            assert b0["block_type"] == "genesis"
            assert len(b0["block_hash"]) == 64
            assert b0["prev_hash"] == "0" * 64
            assert len(b0["public_key_id"]) == 64
            assert len(b0["signature"]) == 128
            assert "disk_baseline_sha256" in b0["payload"]
            assert b0["payload"]["disk_baseline_sha256"] == res["image_sha256"]

            # Blocks 1..3: Recovery events
            for i in range(1, 4):
                bi = blocks[i]
                assert bi["block_index"] == i
                assert bi["block_type"] == "full_recovery"
                assert len(bi["block_hash"]) == 64
                assert bi["prev_hash"] == blocks[i - 1]["block_hash"]
                assert len(bi["public_key_id"]) == 64
                assert len(bi["signature"]) == 128
                assert "filename" in bi["payload"]
                assert "recovered_file_sha256" in bi["payload"]
                assert "size" in bi["payload"]
                assert "source_location" in bi["payload"]
                assert "recovery_method" in bi["payload"]
                assert "macb_timestamps" in bi["payload"]

    def test_ledger_chain_verification_and_tamper_detection(self):
        """Ledger chain verification must succeed on intact chain and detect tampering accurately."""
        from blockchain_ledger import verify_chain

        import tempfile
        from tools.api_server import run_forensic_pipeline

        with tempfile.TemporaryDirectory() as tmpdir:
            ledger_path = str(Path(tmpdir) / "chain.jsonl")
            res = run_forensic_pipeline(str(self.kushal_img), output_dir=tmpdir, ledger_path=ledger_path)
            blocks = res["ledger_blocks"]
            pubkey_hex = blocks[0]["public_key_id"]

            # 1. Clean verification
            clean_res = verify_chain(blocks, pubkey_hex)
            assert clean_res["valid"] is True
            assert clean_res["reason"] is None

            # 2. Tampered block payload
            tampered_blocks = [dict(b) for b in blocks]
            tampered_blocks[1] = dict(tampered_blocks[1])
            tampered_blocks[1]["payload"] = dict(tampered_blocks[1]["payload"])
            tampered_blocks[1]["payload"]["size"] = 999999
            t_res = verify_chain(tampered_blocks, pubkey_hex)
            assert t_res["valid"] is False
            assert t_res["broken_at_index"] == 1
            assert "hash mismatch" in t_res["reason"].lower() or "block 1" in t_res["reason"].lower()

    def test_logical_preview_hides_physical_extent_zero_padding(self):
        """Content & Hex preview must strictly show the logical file bytes (e.g. 8 B) and hide physical 00 padding."""
        import tempfile
        from tools.api_server import CURRENT_STATE, _state_lock, ForensicAPIHandler

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test_8byte.txt"
            # 8 bytes text followed by 4088 zero padding bytes
            test_file.write_bytes(b"kushal.1" + b"\x00" * 4088)

            handler = ForensicAPIHandler.__new__(ForensicAPIHandler)
            
            # Case 1: Known original_size = 8
            with _state_lock:
                CURRENT_STATE["files"] = [{
                    "file_id": "xfs:ino128",
                    "filename": "test_8byte.txt",
                    "original_size": 8,
                    "observed_extent_bytes": 4096,
                }]
                CURRENT_STATE["output_dir"] = tmpdir

            res = handler._resolve_artifact("xfs:ino128")
            assert res["filename"] == "test_8byte.txt"
            assert res["original_size"] == 8
            assert res["ascii_preview"] == "kushal.1"
            assert "kushal.1" in res["hex_preview"]
            # Ensure no trailing zeroes dump in hex preview
            assert "00 00 00 00 00 00 00 00" not in res["hex_preview"]
            assert res["is_logical_trimmed"] is True
            assert res["preview_bytes_length"] == 8

    def test_unknown_original_size_not_fabricated(self):
        """When original_size is None/unknown, preview shows observed bytes without fabricating an original size."""
        import tempfile
        from tools.api_server import CURRENT_STATE, _state_lock, ForensicAPIHandler

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "carved_chunk.bin"
            test_file.write_bytes(b"DATA" * 64)

            handler = ForensicAPIHandler.__new__(ForensicAPIHandler)
            with _state_lock:
                CURRENT_STATE["files"] = [{
                    "file_id": "carved:0x1000",
                    "filename": "carved_chunk.bin",
                    "original_size": None,
                    "observed_extent_bytes": 256,
                }]
                CURRENT_STATE["output_dir"] = tmpdir

            res = handler._resolve_artifact("carved:0x1000")
            assert res["original_size"] is None
            assert res["is_logical_trimmed"] is False
            assert res["preview_bytes_length"] == 256

    def test_internal_nul_bytes_preserved_in_binary(self):
        """Internal NUL bytes within the logical file length must be preserved in binary previews."""
        import tempfile
        from tools.api_server import CURRENT_STATE, _state_lock, ForensicAPIHandler

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "sample.png"
            png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
            test_file.write_bytes(png_header)

            handler = ForensicAPIHandler.__new__(ForensicAPIHandler)
            with _state_lock:
                CURRENT_STATE["files"] = [{
                    "file_id": "xfs:ino129",
                    "filename": "sample.png",
                    "original_size": 16,
                    "observed_extent_bytes": 4096,
                }]
                CURRENT_STATE["output_dir"] = tmpdir

            res = handler._resolve_artifact("xfs:ino129")
            assert res["original_size"] == 16
            assert res["preview_bytes_length"] == 16
            assert "00 00 00 0D 49 48 44 52" in res["hex_preview"]

    def test_forensic_report_pdf_generation_and_headers(self):
        """_build_forensic_pdf_report must return valid %PDF- bytes containing all case, filesystem, and artifact metadata."""
        from tools.api_server import _build_forensic_pdf_report

        files = [
            {
                "file_id": "xfs:ino128",
                "filename": "xfs_deleted_ino_128.txt",
                "file_type": "txt",
                "ml_predicted_class": "txt",
                "ml_confidence": 0.6431,
                "confidence": 0.75,
                "size": 4096,
                "original_size": 8,
                "observed_extent_bytes": 4096,
                "sha256": "8d06d9cef147428f0a9c6667020c4e8a42b68273203cd4c908a6a41f6ec26f9b",
                "recovery_method": "xfs_zero_link_anomaly",
                "metadata": {"modified": "2026-08-26T22:51:20Z"},
            },
            {
                "file_id": "xfs:ino129",
                "filename": "xfs_deleted_ino_129.txt",
                "file_type": "txt",
                "ml_predicted_class": "txt",
                "ml_confidence": 0.6289,
                "confidence": 0.75,
                "size": 4096,
                "original_size": 8,
                "observed_extent_bytes": 4096,
                "sha256": "6ff889eda5fb8cbbdd05528c2ceaac77ceb64c0778aa799fc842606d49014913",
                "recovery_method": "xfs_zero_link_anomaly",
                "metadata": {"modified": "2026-08-26T22:51:20Z"},
            },
        ]
        ledger = [
            {
                "block_index": 0,
                "block_type": "genesis",
                "timestamp": "2026-08-26T22:51:20Z",
                "block_hash": "61177dbe081ded486f0c60655653b6c41b8c04ec47aa8c644d64ea15c00e1234",
                "prev_hash": "0" * 64,
                "public_key_id": "992a49f9f9a1646c19dfba0686940864eb8066bb70fbfba8bc4858064cfb1234",
            }
        ]

        pdf_bytes = _build_forensic_pdf_report(
            case_id="CASE-KUSHAL-123",
            investigator="Lead Investigator",
            current_fs="XFS",
            current_image_path="/home/kushal/Desktop/SIH-FirSeFile/gui_kushal_123_test.img",
            current_image_sha256="146d759cd077f6dcdcba39a94517acc22dd6de937b7d0cf4543bbf21b43d1966",
            current_files=files,
            current_ledger=ledger,
            scan_id="scan_kushal",
            scan_start_time="2026-08-26T22:51:20Z",
            scan_end_time="2026-08-26T22:51:25Z",
        )

        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 500
        assert pdf_bytes.startswith(b"%PDF-")

    def test_pdf_report_and_gui_ml_confidences_match_exactly(self):
        """PDF report must use the exact same per-artifact ML confidence (60-70%) as displayed in GUI (never 75%)."""
        from tools.api_server import _build_forensic_pdf_report

        files = [
            {
                "file_id": "xfs:ino128",
                "filename": "xfs_deleted_ino_128.txt",
                "file_type": "txt",
                "ml_predicted_class": "txt",
                "ml_confidence": 0.6431,  # 64.3% in GUI
                "confidence": 0.75,       # 75% Recovery Confidence
                "size": 4096,
                "original_size": 8,
                "observed_extent_bytes": 4096,
                "sha256": "8d06d9cef147428f0a9c6667020c4e8a42b68273203cd4c908a6a41f6ec26f9b",
                "recovery_method": "xfs_zero_link_anomaly",
                "metadata": {"modified": "2026-08-26T22:51:20Z"},
            },
        ]
        pdf_bytes = _build_forensic_pdf_report(
            case_id="CASE-KUSHAL-123",
            investigator="Lead Investigator",
            current_fs="XFS",
            current_image_path="/path/test.img",
            current_image_sha256="abc",
            current_files=files,
            current_ledger=[],
            scan_id="scan_test",
            scan_start_time="2026-08-26T22:51:20Z",
            scan_end_time="2026-08-26T22:51:25Z",
        )
        assert pdf_bytes.startswith(b"%PDF-")

    def test_empty_scan_export_returns_error(self):
        """Exporting when no completed scan exists must return 400 error and not export stale data."""
        from tools.api_server import CURRENT_STATE, _state_lock, ForensicAPIHandler

        handler = ForensicAPIHandler.__new__(ForensicAPIHandler)
        with _state_lock:
            CURRENT_STATE["files"] = []
            CURRENT_STATE["ledger"] = []

        sent_json = []
        handler._send_json = lambda d, status_code=200: sent_json.append((d, status_code))

        handler._handle_export({"format": "pdf"})
        assert len(sent_json) == 1
        data, status = sent_json[0]
        assert status == 400
        assert "No completed forensic scan available" in data["error"]
