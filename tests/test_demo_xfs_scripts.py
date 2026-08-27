"""
tests/test_demo_xfs_scripts.py
==============================
Automated unit and integration test suite for the two-script presentation workflow:
  - scripts/create_demo_xfs.py
  - scripts/delete_demo_xfs.py
"""

import os
import json
import pytest
import tempfile
import hashlib
from pathlib import Path

from scripts.create_demo_xfs import (
    sanitize_filename,
    compute_sha256,
    generate_minimal_pdf,
    generate_minimal_png,
    generate_minimal_zip,
    infer_format_from_filename,
    generate_file_bytes,
)
from src.validation.validator import identify_format, validate_reconstructed_file


class TestDemoXfsScripts:
    def test_sanitize_filename_valid(self):
        """Standard valid filenames must pass without exception."""
        assert sanitize_filename("1.txt") == "1.txt"
        assert sanitize_filename("data.json") == "data.json"
        assert sanitize_filename("sample_doc.pdf") == "sample_doc.pdf"
        assert sanitize_filename("notes.md") == "notes.md"

    def test_sanitize_filename_path_traversal_rejected(self):
        """Path traversal and dangerous characters must be rejected."""
        with pytest.raises(ValueError, match="slashes"):
            sanitize_filename("../secret.txt")

        with pytest.raises(ValueError, match="slashes"):
            sanitize_filename("/etc/passwd")

        with pytest.raises(ValueError, match="slashes"):
            sanitize_filename("dir/file.txt")

        with pytest.raises(ValueError, match="slashes"):
            sanitize_filename("..\\windows\\system32")

        with pytest.raises(ValueError, match="empty"):
            sanitize_filename("   ")

    def test_blocked_system_devices_rejected(self):
        """System device paths must be rejected by sanitize_filename."""
        with pytest.raises(ValueError):
            sanitize_filename("/dev/sda")

        with pytest.raises(ValueError):
            sanitize_filename("/dev/nvme0n1")

    def test_format_inference(self):
        """Format must be accurately inferred from extension."""
        assert infer_format_from_filename("1.txt") == "txt"
        assert infer_format_from_filename("records.json") == "json"
        assert infer_format_from_filename("table.csv") == "csv"
        assert infer_format_from_filename("README.md") == "md"
        assert infer_format_from_filename("document.pdf") == "pdf"
        assert infer_format_from_filename("image.png") == "png"
        assert infer_format_from_filename("archive.zip") == "zip"

    def test_pdf_generator_is_valid_structure(self):
        """Generated PDF must have valid header, stream, and xref table."""
        pdf_bytes = generate_minimal_pdf("Kushal PDF Presentation")
        assert pdf_bytes.startswith(b"%PDF-1.4")
        assert b"%%EOF" in pdf_bytes
        val = validate_reconstructed_file(pdf_bytes, expected_format="pdf")
        assert val.is_valid is True

    def test_png_generator_is_valid_structure(self):
        """Generated PNG must have valid magic header, IHDR, IDAT, and IEND chunks."""
        png_bytes = generate_minimal_png()
        assert png_bytes.startswith(b"\x89PNG\r\n\x1a\n")
        assert png_bytes.endswith(b"IEND\xae\x42\x60\x82")
        val = validate_reconstructed_file(png_bytes, expected_format="png")
        assert val.is_valid is True

    def test_zip_generator_is_valid_structure(self):
        """Generated ZIP must have valid PK zip header and readable entries."""
        zip_bytes = generate_minimal_zip("test.txt", b"FirSeFile demo content")
        assert zip_bytes.startswith(b"PK\x03\x04")
        val = validate_reconstructed_file(zip_bytes, expected_format="zip")
        assert val.is_valid is True

    def test_generate_file_bytes_formats(self):
        """generate_file_bytes must produce valid bytes for all supported formats."""
        txt_b = generate_file_bytes("1.txt", "txt", "kushal.1")
        assert txt_b == b"kushal.1"

        json_b = generate_file_bytes("data.json", "json", '{"test": 123}')
        parsed = json.loads(json_b.decode("utf-8"))
        assert parsed["test"] == 123

        csv_b = generate_file_bytes("data.csv", "csv", "col1,col2\nval1,val2\n")
        assert b"col1,col2" in csv_b

        md_b = generate_file_bytes("doc.md", "md", "# Header\nText")
        assert b"# Header" in md_b

    def test_ground_truth_hash_calculation(self):
        """compute_sha256 matches exact hashlib digest."""
        sample_bytes = b"kushal.1"
        expected = hashlib.sha256(sample_bytes).hexdigest()
        assert compute_sha256(sample_bytes) == expected

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(sample_bytes)
            tf_path = Path(tf.name)

        try:
            assert compute_sha256(tf_path) == expected
        finally:
            tf_path.unlink()

    def test_manifest_schema_and_roundtrip(self):
        """Manifest JSON schema must serialize and deserialize with all required fields."""
        manifest_data = {
            "manifest_version": "1.0",
            "created_at_utc": "2026-08-27T04:21:20+00:00",
            "image_path": "/tmp/demo.img",
            "image_size_bytes": 536870912,
            "mount_point": "/tmp/firsefile_demo_123",
            "status": "mounted_with_files",
            "total_files": 3,
            "files": [
                {
                    "filename": "1.txt",
                    "inode": 128,
                    "size": 8,
                    "sha256": "8d06d9cef147428f0a9c6667020c4e8a42b68273203cd4c908a6a41f6ec26f9b",
                    "format": "txt",
                    "mtime_iso": "2026-08-27T04:21:20+00:00",
                    "content_preview": "kushal.1",
                },
                {
                    "filename": "2.txt",
                    "inode": 129,
                    "size": 8,
                    "sha256": "6ff889eda5fb8cbbdd05528c2ceaac77ceb64c0778aa799fc842606d49014913",
                    "format": "txt",
                    "mtime_iso": "2026-08-27T04:21:30+00:00",
                    "content_preview": "kushal.2",
                },
            ],
        }

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            tf_path = Path(tf.name)
            tf_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

        try:
            loaded = json.loads(tf_path.read_text(encoding="utf-8"))
            assert loaded["manifest_version"] == "1.0"
            assert loaded["total_files"] == 3
            assert len(loaded["files"]) == 2
            assert loaded["files"][0]["filename"] == "1.txt"
            assert loaded["files"][0]["size"] == 8
        finally:
            tf_path.unlink()
