#!/usr/bin/env python3
"""
scripts/create_demo_xfs.py
==========================
Interactive presentation tool to create a real 512 MiB XFS evidence image
and populate it with user-selected files.

Leaves the filesystem mounted after creation so the presenter can demonstrate
the physical files to the audience before deletion.

Authoritative FirSeFile Recovery Workflow:
  Step 1: python3 scripts/create_demo_xfs.py  (creates & mounts files)
  Step 2: Inspect files live with ls / cat
  Step 3: python3 scripts/delete_demo_xfs.py  (deletes files, syncs, unmounts)
  Step 4: Load image into FirSeFile GUI for forensic recovery
"""

import os
import sys
import json
import time
import struct
import zlib
import io
import zipfile
import hashlib
import argparse
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_IMAGE_NAME = "demo_xfs_evidence.img"
DEFAULT_MANIFEST_NAME = "demo_xfs_ground_truth.json"
DEFAULT_IMAGE_SIZE_MB = 512

BLOCKED_DEVICE_PREFIXES = ("/dev/", "\\\\.\\", "/proc", "/sys")


def sanitize_filename(name: str) -> str:
    """Ensure filename does not contain path traversal or dangerous characters."""
    name = name.strip()
    if not name:
        raise ValueError("Filename cannot be empty.")
    if any(prefix in name.lower() for prefix in BLOCKED_DEVICE_PREFIXES):
        raise ValueError(f"Invalid filename: contains blocked system path prefix '{name}'")
    if "/" in name or "\\" in name or ".." in name or "\x00" in name:
        raise ValueError(f"Filename '{name}' must not contain slashes, backslashes, or '..'")
    return name


def compute_sha256(data_or_path: Any) -> str:
    """Compute SHA-256 hex digest of bytes or a file path."""
    h = hashlib.sha256()
    if isinstance(data_or_path, (bytes, bytearray)):
        h.update(data_or_path)
    elif isinstance(data_or_path, (str, Path)):
        p = Path(data_or_path)
        with open(p, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
    else:
        raise TypeError("Expected bytes or path")
    return h.hexdigest()


def generate_minimal_pdf(text: str = "Forensic Sample Document") -> bytes:
    """Generate genuine minimal valid PDF-1.4 binary structure."""
    clean_text = "".join(c for c in text if 32 <= ord(c) <= 126).replace("(", "").replace(")", "")
    if not clean_text:
        clean_text = "FirSeFile Forensic Evidence"
    stream_content = f"BT /F1 12 Tf 50 700 Td ({clean_text}) Tj ET".encode("ascii")
    stream_len = len(stream_content)
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >> endobj\n"
        + f"4 0 obj << /Length {stream_len} >> stream\n".encode("ascii")
        + stream_content
        + b"\nendstream\nendobj\n"
        b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000216 00000 n \n"
        b"trailer << /Size 5 /Root 1 0 R >>\nstartxref\n310\n%%EOF\n"
    )
    return pdf


def generate_minimal_png() -> bytes:
    """Generate genuine minimal valid 1x1 transparent PNG binary structure."""
    header = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    ihdr_crc = struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF)
    ihdr = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + ihdr_crc
    raw_pixel = b"\x00\x00\x00\x00\x00"
    compressed = zlib.compress(raw_pixel)
    idat_crc = struct.pack(">I", zlib.crc32(b"IDAT" + compressed) & 0xFFFFFFFF)
    idat = struct.pack(">I", len(compressed)) + b"IDAT" + compressed + idat_crc
    iend = b"\x00\x00\x00\x00IEND\xae\x42\x60\x82"
    return header + ihdr + idat + iend


def generate_minimal_zip(inner_name: str = "evidence.txt", inner_content: bytes = b"FirSeFile forensic sample\n") -> bytes:
    """Generate genuine minimal valid ZIP archive binary structure."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(inner_name, inner_content)
    return buf.getvalue()


def infer_format_from_filename(filename: str) -> str:
    """Infer file format from extension."""
    ext = Path(filename).suffix.lower()
    if ext in (".txt", ".text", ".log", ".conf", ".ini"):
        return "txt"
    elif ext == ".json":
        return "json"
    elif ext == ".csv":
        return "csv"
    elif ext in (".md", ".markdown"):
        return "md"
    elif ext == ".pdf":
        return "pdf"
    elif ext in (".png", ".png_"):
        return "png"
    elif ext in (".zip", ".jar"):
        return "zip"
    return "txt"


def generate_file_bytes(filename: str, format_type: str, user_content: str) -> bytes:
    """Generate authentic bytes for the selected format and content."""
    fmt = (format_type or infer_format_from_filename(filename)).lower()

    if fmt == "pdf":
        return generate_minimal_pdf(user_content or f"Sample PDF: {filename}")
    elif fmt == "png":
        return generate_minimal_png()
    elif fmt == "zip":
        return generate_minimal_zip(inner_name="readme.txt", inner_content=(user_content or "FirSeFile Zip Data\n").encode("utf-8"))
    elif fmt == "json":
        text = user_content.strip()
        if not text:
            text = json.dumps({"filename": filename, "created_at": datetime.now(timezone.utc).isoformat(), "verified": True}, indent=2)
        else:
            try:
                parsed = json.loads(text)
                text = json.dumps(parsed, indent=2)
            except Exception:
                pass
        return text.encode("utf-8")
    elif fmt == "csv":
        text = user_content if user_content.strip() else f"id,filename,timestamp\n1,{filename},{datetime.now(timezone.utc).isoformat()}\n"
        return text.encode("utf-8")
    elif fmt == "md":
        text = user_content if user_content.strip() else f"# Forensic Evidence: {filename}\n\nCreated for FirSeFile validation.\n"
        return text.encode("utf-8")
    else:
        # Default text
        return user_content.encode("utf-8") if user_content else b""


def create_xfs_disk_image(img_path: Path, size_mb: int = DEFAULT_IMAGE_SIZE_MB) -> None:
    """Create a real 512 MiB XFS formatted sparse/raw disk image."""
    img_path.parent.mkdir(parents=True, exist_ok=True)
    # 1. Truncate image
    res = subprocess.run(["truncate", "-s", f"{size_mb}M", str(img_path)], capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"truncate failed: {res.stderr}")

    # 2. Format with mkfs.xfs
    res = subprocess.run(["mkfs.xfs", "-f", str(img_path)], capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"mkfs.xfs failed: {res.stderr}")


def mount_loop_image(img_path: Path, mount_dir: Path) -> None:
    """Mount XFS disk image to loop mount directory."""
    mount_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["sudo", "mount", "-o", "loop", str(img_path), str(mount_dir)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Failed to mount {img_path} at {mount_dir}: {res.stderr.strip() or 'Permission denied'}")

    # Grant write permissions so normal user can create test files
    chmod_cmd = ["sudo", "chmod", "777", str(mount_dir)]
    subprocess.run(chmod_cmd, capture_output=True, text=True)


def is_mounted(mount_dir: Path) -> bool:
    """Check if mount_dir is an active mountpoint."""
    try:
        res = subprocess.run(["mountpoint", "-q", str(mount_dir)])
        return res.returncode == 0
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(description="Create real XFS evidence image and populate with demo files.")
    parser.add_argument("--image", "-i", default=DEFAULT_IMAGE_NAME, help=f"Path to output XFS image (default: {DEFAULT_IMAGE_NAME})")
    parser.add_argument("--manifest", "-m", default=DEFAULT_MANIFEST_NAME, help=f"Path to output ground-truth manifest (default: {DEFAULT_MANIFEST_NAME})")
    parser.add_argument("--size-mb", type=int, default=DEFAULT_IMAGE_SIZE_MB, help=f"Image size in MiB (default: {DEFAULT_IMAGE_SIZE_MB})")
    parser.add_argument("--non-interactive", action="store_true", help="Run without interactive prompts (for automation/tests)")
    parser.add_argument("--files", type=str, default="", help="JSON string or file containing file specs for non-interactive mode")
    parser.add_argument("--force", action="store_true", help="Overwrite existing image without confirmation")
    args = parser.parse_args()

    img_path = Path(args.image).resolve()
    manifest_path = Path(args.manifest).resolve()

    # Safety checks
    if any(str(img_path).startswith(p) for p in BLOCKED_DEVICE_PREFIXES):
        print(f"\n[ERROR] Target image path '{img_path}' references a physical system device. Operation blocked for safety.")
        sys.exit(1)

    print("\n=======================================================")
    print("      FIRSEFILE DEMO EVIDENCE GENERATOR (STEP 1/2)     ")
    print("=======================================================")
    print(f"Target XFS Image:   {img_path}")
    print(f"Image Size:         {args.size_mb} MiB ({args.size_mb * 1024 * 1024} bytes)")
    print(f"Ground Truth File:  {manifest_path}")

    # Check existing file
    if img_path.exists():
        if not args.force and not args.non_interactive:
            print(f"\n[WARNING] File '{img_path}' already exists.")
            resp = input("Overwrite this image? [y/N]: ").strip().lower()
            if resp != "y":
                print("Aborted by user.")
                sys.exit(0)

    # File specifications to create
    file_specs: List[Dict[str, str]] = []

    if args.non_interactive:
        if args.files:
            try:
                if Path(args.files).exists():
                    file_specs = json.loads(Path(args.files).read_text(encoding="utf-8"))
                else:
                    file_specs = json.loads(args.files)
            except Exception as e:
                print(f"[ERROR] Failed to parse --files JSON: {e}")
                sys.exit(1)
        else:
            # Default automated demo files (1.txt, 2.txt, 3.txt)
            file_specs = [
                {"filename": "1.txt", "format": "txt", "content": "kushal.1"},
                {"filename": "2.txt", "format": "txt", "content": "kushal.2"},
                {"filename": "3.txt", "format": "txt", "content": "kushal.3"},
            ]
    else:
        # Interactive prompts
        print("\n--- Configure Test Evidence Files ---")
        while True:
            try:
                n_str = input("How many files do you want to create? (1-50): ").strip()
                n = int(n_str)
                if 1 <= n <= 50:
                    break
                print("Please enter a number between 1 and 50.")
            except ValueError:
                print("Invalid integer.")

        print(f"\nSupported formats: TXT, JSON, CSV, Markdown (.md), PDF, PNG, ZIP\n")

        for idx in range(1, n + 1):
            print(f"--- File {idx}/{n} ---")
            while True:
                fn = input(f"  File {idx} filename (e.g. {idx}.txt, data.json, doc.pdf): ").strip()
                try:
                    fn = sanitize_filename(fn)
                    if any(s["filename"] == fn for s in file_specs):
                        print(f"  [!] Filename '{fn}' already added. Please choose a unique name.")
                        continue
                    break
                except ValueError as e:
                    print(f"  [!] {e}")

            inferred_fmt = infer_format_from_filename(fn)
            fmt = input(f"  File {idx} format [{inferred_fmt}]: ").strip() or inferred_fmt

            if fmt.lower() in ("pdf", "png", "zip"):
                print(f"  [i] Binary format '{fmt.upper()}' selected. Enter custom text/metadata or press Enter for default genuine binary.")
                content = input(f"  File {idx} text label: ")
            else:
                content = input(f"  File {idx} content text: ")

            file_specs.append({
                "filename": fn,
                "format": fmt.lower(),
                "content": content,
            })

    print(f"\n[*] Creating {args.size_mb} MiB XFS disk image...")
    try:
        create_xfs_disk_image(img_path, args.size_mb)
    except Exception as e:
        print(f"[ERROR] Failed to create XFS image: {e}")
        sys.exit(1)

    mount_dir = Path(f"/tmp/firsefile_demo_{os.getpid()}_{int(time.time())}")
    print(f"[*] Mounting image via loop device to: {mount_dir}")
    try:
        mount_loop_image(img_path, mount_dir)
    except Exception as e:
        print(f"[ERROR] Mount failed: {e}")
        print("Tip: If sudo password is required, run in an interactive terminal.")
        sys.exit(1)

    # Write files and collect ground truth
    ground_truth_files = []
    print("\n[*] Writing files to mounted XFS filesystem...")

    for spec in file_specs:
        fn = spec["filename"]
        fmt = spec["format"]
        raw_content = spec.get("content", "")
        file_bytes = generate_file_bytes(fn, fmt, raw_content)

        dest = mount_dir / fn
        try:
            dest.write_bytes(file_bytes)
        except Exception as e:
            print(f"[ERROR] Failed to write '{fn}' to mount: {e}")
            sys.exit(1)

        # Stat file from live mounted filesystem
        st = dest.stat()
        sha256_val = compute_sha256(file_bytes)

        # Decode preview safely
        preview = ""
        try:
            preview = file_bytes.decode("utf-8", errors="replace")[:100]
        except Exception:
            preview = f"<binary {fmt.upper()} {len(file_bytes)} bytes>"

        record = {
            "filename": fn,
            "path_on_mount": str(dest),
            "inode": st.st_ino,
            "size": len(file_bytes),
            "sha256": sha256_val,
            "format": fmt,
            "atime_iso": datetime.fromtimestamp(st.st_atime, timezone.utc).isoformat(),
            "mtime_iso": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
            "ctime_iso": datetime.fromtimestamp(st.st_ctime, timezone.utc).isoformat(),
            "content_preview": preview,
        }
        ground_truth_files.append(record)

    # Sync filesystem writes
    subprocess.run(["sync"])

    # Save manifest outside the image
    manifest = {
        "manifest_version": "1.0",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "image_path": str(img_path),
        "image_size_bytes": img_path.stat().st_size,
        "mount_point": str(mount_dir),
        "status": "mounted_with_files",
        "total_files": len(ground_truth_files),
        "files": ground_truth_files,
    }

    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print("\n=======================================================")
    print("      FILES CREATED ON MOUNTED XFS EVIDENCE IMAGE      ")
    print("=======================================================")
    print(f"{'Filename':<20} | {'Inode':<7} | {'Size':<8} | {'Format':<6} | {'SHA-256':<16} | Content Preview")
    print("-" * 80)
    for f in ground_truth_files:
        print(f"{f['filename']:<20} | {f['inode']:<7} | {f['size']:<8} | {f['format']:<6} | {f['sha256'][:16]}... | {repr(f['content_preview'])}")

    print("\n" + "=" * 65)
    print("  >>> LIVE INSPECTION READY (FILES REMAIN MOUNTED) <<<")
    print("=" * 65)
    print(f"Evidence Image:   {img_path}")
    print(f"Mount Point:      {mount_dir}")
    print(f"Ground Truth:     {manifest_path}")
    print(f"\nYou can now demonstrate that the files exist in the mounted XFS image:")
    print(f"    ls -lah {mount_dir}")
    if ground_truth_files:
        print(f"    cat {mount_dir}/{ground_truth_files[0]['filename']}")

    print("\n" + "-" * 65)
    print("NEXT STEP:")
    print("When ready to delete the files for the forensic recovery demonstration, run:")
    print(f"    python3 scripts/delete_demo_xfs.py")
    print("-" * 65 + "\n")


if __name__ == "__main__":
    main()
