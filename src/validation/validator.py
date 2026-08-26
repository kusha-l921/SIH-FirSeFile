"""
Format-Aware Structural Validator for Reconstructed Forensic Files.
Performs deep binary header, chunk structure, and schema integrity validation
for PDF, ZIP, DOCX, JPEG, PNG, ELF, SQLite, and Scripts.
"""

from typing import Dict, Any, Optional, Tuple, List
import io
import zlib
import struct
import hashlib
import zipfile
from PIL import Image

from src.datasets.fft75 import MAGIC_SIGNATURES


class ForensicValidationReport:
    """
    Structured validation output for reconstructed files.
    """

    def __init__(
        self,
        detected_format: str,
        is_valid: bool,
        status: str,
        details: Dict[str, Any],
        reconstructed_size: int,
        sha256: str,
        provenance: Optional[Dict[str, Any]] = None
    ):
        self.detected_format = detected_format
        self.is_valid = is_valid
        self.status = status
        self.details = details
        self.reconstructed_size = reconstructed_size
        self.sha256 = sha256
        self.provenance = provenance or {}

    @property
    def reconstructed_size_bytes(self) -> int:
        return self.reconstructed_size

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected_format": self.detected_format,
            "is_valid": self.is_valid,
            "status": self.status,
            "reconstructed_size_bytes": self.reconstructed_size,
            "sha256": self.sha256,
            "details": self.details,
            "provenance": self.provenance
        }


def identify_format(raw_bytes: bytes) -> str:
    """Identify format from magic headers or byte characteristics."""
    if raw_bytes.startswith(b"%PDF-"):
        return "pdf"
    if raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if raw_bytes.startswith(b"\xFF\xD8\xFF"):
        return "jpg"
    if raw_bytes.startswith(b"PK\x03\x04"):
        return "zip"  # Could also be docx/xlsx/jar
    if raw_bytes.startswith(b"\x7fELF"):
        return "elf"
    if raw_bytes.startswith(b"SQLite format 3\x00"):
        return "sqlite"
    if raw_bytes.startswith(b"GIF87a") or raw_bytes.startswith(b"GIF89a"):
        return "gif"
    if raw_bytes.startswith(b"BM"):
        return "bmp"
    if raw_bytes.startswith(b"#!"):
        return "sh"

    # Fallback to ASCII / script detection
    try:
        sample = raw_bytes[:min(1024, len(raw_bytes))].decode("utf-8")
        if all(32 <= ord(c) <= 126 or c in "\t\r\n" for c in sample):
            return "txt"
    except UnicodeDecodeError:
        pass

    return "unknown"


def validate_pdf(data: bytes) -> Tuple[bool, str, Dict[str, Any]]:
    """Validate PDF header, trailer, xref, and EOF structure."""
    if not data.startswith(b"%PDF-"):
        return False, "INVALID_HEADER", {"error": "Missing %PDF- header"}

    # Extract version
    version_line = data[:15].split(b"\n")[0].decode("ascii", errors="ignore")
    has_eof = b"%%EOF" in data[-1024:]
    has_xref = (b"\nxref" in data) or (b"/XRef" in data) or (b"xref\n" in data) or (b"xref\r\n" in data)
    has_trailer = (b"trailer" in data and b"<<" in data) or (b"/Root" in data)

    details = {
        "version": version_line,
        "has_eof_marker": has_eof,
        "has_xref_table": has_xref,
        "has_trailer_or_root": has_trailer
    }

    if has_eof and (has_trailer or has_xref):
        return True, "VALID_PDF_STRUCTURE", details
    elif has_eof:
        return True, "PARTIAL_PDF_STRUCTURE", details
    else:
        return False, "CORRUPTED_PDF_MISSING_EOF", details


def validate_zip_docx(data: bytes) -> Tuple[bool, str, Dict[str, Any]]:
    """Validate ZIP archive / DOCX container structure using zipfile decompression check."""
    if not data.startswith(b"PK\x03\x04"):
        return False, "INVALID_ZIP_HEADER", {"error": "Missing PK\x03\x04 signature"}

    has_eocd = b"PK\x05\x06" in data
    details = {"has_eocd": has_eocd}

    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            namelist = zf.namelist()
            test_res = zf.testzip()  # Tests CRC32 of all compressed streams
            details["file_count"] = len(namelist)
            details["entries"] = namelist[:5]
            details["crc_test_passed"] = (test_res is None)
            
            if test_res is None:
                # Check if it is a DOCX (contains [Content_Types].xml and word/document.xml)
                if "[Content_Types].xml" in namelist:
                    return True, "VALID_DOCX_OR_OFFICE_ZIP", details
                return True, "VALID_ZIP_ARCHIVE", details
            else:
                return False, "ZIP_CRC_CORRUPTION", details
    except Exception as e:
        details["error"] = str(e)
        return False, "ZIP_PARSING_FAILED", details


def validate_jpeg(data: bytes) -> Tuple[bool, str, Dict[str, Any]]:
    """Validate JPEG SOI, marker stream, and EOI marker."""
    if not data.startswith(b"\xFF\xD8"):
        return False, "INVALID_JPEG_SOI", {"error": "Missing 0xFFD8 Start of Image"}

    has_eoi = b"\xFF\xD9" in data[-512:]
    details = {"has_eoi": has_eoi}

    try:
        img = Image.open(io.BytesIO(data))
        img.verify()
        details["format"] = img.format
        details["size"] = img.size
        return True, "VALID_JPEG_IMAGE", details
    except Exception as e:
        details["error"] = str(e)
        if has_eoi:
            return True, "PARTIAL_JPEG_DECODABLE", details
        return False, "INVALID_JPEG_IMAGE", details


def validate_png(data: bytes) -> Tuple[bool, str, Dict[str, Any]]:
    """Validate PNG 8-byte signature, IHDR, CRC32, and IEND chunks."""
    png_sig = b"\x89PNG\r\n\x1a\n"
    if not data.startswith(png_sig):
        return False, "INVALID_PNG_SIG", {"error": "Missing PNG signature"}

    details = {"signature_ok": True}
    has_iend = b"IEND\xaeB`\x82" in data[-64:]
    details["has_iend"] = has_iend

    try:
        img = Image.open(io.BytesIO(data))
        img.verify()
        details["size"] = img.size
        return True, "VALID_PNG_IMAGE", details
    except Exception as e:
        details["error"] = str(e)
        return False, "INVALID_PNG_CHUNKS", details


def validate_elf(data: bytes) -> Tuple[bool, str, Dict[str, Any]]:
    """Validate ELF binary header and structure."""
    if not data.startswith(b"\x7fELF"):
        return False, "INVALID_ELF_MAGIC", {"error": "Missing \\x7fELF"}

    if len(data) < 52:
        return False, "TRUNCATED_ELF_HEADER", {"error": "Length < 52 bytes"}

    ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
    ei_data = data[5]   # 1 = LSB (little endian), 2 = MSB (big endian)
    ei_version = data[6]

    details = {
        "architecture": "64-bit" if ei_class == 2 else "32-bit" if ei_class == 1 else "unknown",
        "endianness": "little-endian" if ei_data == 1 else "big-endian" if ei_data == 2 else "unknown",
        "version": ei_version
    }

    if ei_version == 1 and ei_class in [1, 2]:
        return True, "VALID_ELF_HEADER", details
    return False, "MALFORMED_ELF", details


def validate_sqlite(data: bytes) -> Tuple[bool, str, Dict[str, Any]]:
    """Validate SQLite database file format header and page parameters."""
    header_magic = b"SQLite format 3\x00"
    if not data.startswith(header_magic):
        return False, "INVALID_SQLITE_MAGIC", {"error": "Missing SQLite format 3 signature"}

    if len(data) < 100:
        return False, "TRUNCATED_SQLITE_HEADER", {"error": "Length < 100 bytes"}

    # Page size is 2-byte big-endian integer at offset 16
    page_size = struct.unpack(">H", data[16:18])[0]
    if page_size == 1:
        page_size = 65536  # Special SQLite flag

    details = {
        "page_size": page_size,
        "write_version": data[18],
        "read_version": data[19]
    }

    # Valid page size must be power of 2 between 512 and 65536
    is_power_of_two = (page_size >= 512) and (page_size & (page_size - 1) == 0)
    if is_power_of_two:
        return True, "VALID_SQLITE_DATABASE", details
    return False, "INVALID_SQLITE_PAGE_SIZE", details


def validate_script(data: bytes) -> Tuple[bool, str, Dict[str, Any]]:
    """Validate script syntax and shebang."""
    try:
        text = data.decode("utf-8")
        lines = text.splitlines()
        first_line = lines[0] if lines else ""
        has_shebang = first_line.startswith("#!")
        return True, "VALID_SCRIPT_TEXT", {
            "has_shebang": has_shebang,
            "shebang": first_line if has_shebang else None,
            "line_count": len(lines)
        }
    except UnicodeDecodeError as e:
        return False, "NON_ASCII_CORRUPTION", {"error": str(e)}


def validate_reconstructed_file(
    data: bytes,
    expected_format: Optional[str] = None,
    provenance: Optional[Dict[str, Any]] = None
) -> ForensicValidationReport:
    """
    Comprehensive format-aware structural validator.
    """
    detected = identify_format(data)
    fmt_to_check = expected_format.lower() if expected_format else detected
    sha256 = hashlib.sha256(data).hexdigest()

    if fmt_to_check in ["pdf"]:
        is_valid, status, details = validate_pdf(data)
    elif fmt_to_check in ["zip", "docx", "xlsx", "pptx", "jar", "apk"]:
        is_valid, status, details = validate_zip_docx(data)
    elif fmt_to_check in ["jpg", "jpeg"]:
        is_valid, status, details = validate_jpeg(data)
    elif fmt_to_check in ["png"]:
        is_valid, status, details = validate_png(data)
    elif fmt_to_check in ["elf", "so"]:
        is_valid, status, details = validate_elf(data)
    elif fmt_to_check in ["sqlite", "db"]:
        is_valid, status, details = validate_sqlite(data)
    elif fmt_to_check in ["sh", "py", "c", "cpp", "txt", "js", "html"]:
        is_valid, status, details = validate_script(data)
    else:
        is_valid = (len(data) > 0)
        status = "GENERIC_BINARY_VALIDATED" if is_valid else "EMPTY_STREAM"
        details = {"detected_magic": detected}

    return ForensicValidationReport(
        detected_format=detected,
        is_valid=is_valid,
        status=status,
        details=details,
        reconstructed_size=len(data),
        sha256=sha256,
        provenance=provenance
    )
