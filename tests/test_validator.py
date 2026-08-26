"""
Unit tests for format-aware structural validator.
"""

import io
import zipfile
import pytest

from src.validation.validator import (
    identify_format, validate_pdf, validate_zip_docx,
    validate_png, validate_elf, validate_sqlite,
    validate_script, validate_reconstructed_file
)


def test_identify_format():
    assert identify_format(b"%PDF-1.4 sample") == "pdf"
    assert identify_format(b"\x89PNG\r\n\x1a\n\x00\x00") == "png"
    assert identify_format(b"\xFF\xD8\xFF\xE0") == "jpg"
    assert identify_format(b"PK\x03\x04\x14\x00") == "zip"
    assert identify_format(b"\x7fELF\x02\x01\x01\x00") == "elf"
    assert identify_format(b"SQLite format 3\x00") == "sqlite"
    assert identify_format(b"#!/bin/bash\necho hello") == "sh"


def test_validate_pdf():
    valid_pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\nxref\ntrailer<</Root 1 0 R>>\nstartxref\n100\n%%EOF\n"
    is_valid, status, details = validate_pdf(valid_pdf)
    assert is_valid is True
    assert details["has_eof_marker"] is True

    corrupted_pdf = b"%PDF-1.4\ncorrupted random bytes without trailer or eof"
    is_valid_c, status_c, _ = validate_pdf(corrupted_pdf)
    assert is_valid_c is False


def test_validate_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("test.txt", "forensic recovery")
    zip_bytes = buf.getvalue()

    is_valid, status, details = validate_zip_docx(zip_bytes)
    assert is_valid is True
    assert details["crc_test_passed"] is True
    assert "test.txt" in details["entries"]


def test_validate_elf():
    # Construct minimal valid 64-bit little endian ELF header
    elf_bytes = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56)
    is_valid, status, details = validate_elf(bytes(elf_bytes))
    assert is_valid is True
    assert details["architecture"] == "64-bit"
    assert details["endianness"] == "little-endian"


def test_validate_sqlite():
    sqlite_bytes = bytearray(b"SQLite format 3\x00" + b"\x00" * 84)
    sqlite_bytes[16] = 0x02  # page size 512
    sqlite_bytes[17] = 0x00
    is_valid, status, details = validate_sqlite(bytes(sqlite_bytes))
    assert is_valid is True
    assert details["page_size"] == 512
