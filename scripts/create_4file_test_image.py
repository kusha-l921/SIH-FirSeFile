#!/usr/bin/env python3
"""
create_4file_test_image.py
==========================
Generates a DISTINCT XFS synthetic forensic test image containing 4 new files
with unique content that does NOT match the existing presentation fixture.

This image is used to prove:
  1. The GUI scans the submitted image (not a hardcoded fixture)
  2. Results differ when a different image is provided
  3. No stale 7-artifact presentation data leaks into new scans

The 4 files have DIFFERENT content, DIFFERENT names, DIFFERENT types,
and DIFFERENT inode numbers from the existing xfs_deleted_synthetic.img fixture.

Output:
  - gui_4file_test.img          (XFS evidence image)
  - gui_4file_ground_truth.json (ground truth manifest)
"""

import os
import sys
import struct
import hashlib
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# 4 DISTINCT test file contents — unique to this image
# ---------------------------------------------------------------------------

# File 1: Text file with unique content
ALPHA_TXT = (
    b"FIRSEFILE REAL TEST ALPHA\n"
    b"This file was created specifically for the 4-file forensic verification test.\n"
    b"Purpose: Prove that the GUI scans the actual submitted image,\n"
    b"not a hardcoded fixture or stale presentation data.\n"
    b"Unique marker: ALPHA-4FILE-VERIFICATION-2026\n"
    b"The content of this file is completely different from any presentation fixture.\n"
)

# File 2: JSON file with unique content
BETA_JSON = (
    b'{"test_name":"FirSeFile 4-File Verification","file_id":"gui_real_beta",'
    b'"purpose":"Verify data-driven recovery pipeline",'
    b'"unique_marker":"BETA-4FILE-VERIFICATION-2026",'
    b'"expected_behavior":"This file should only appear when THIS specific image is scanned"}\n'
)

# File 3: Minimal valid PNG (1x1 red pixel — different from the presentation fixture's PNG)
GAMMA_PNG = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
    b"\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)

# File 4: Minimal valid PDF with unique content
DELTA_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n"
    b"4 0 obj\n<< /Length 48 >>\nstream\n"
    b"BT /F1 12 Tf 100 700 Td (DELTA-4FILE-VERIFY) Tj ET\n"
    b"endstream\nendobj\n"
    b"xref\n0 5\n"
    b"0000000000 65535 f \n"
    b"0000000009 00000 n \n"
    b"0000000058 00000 n \n"
    b"0000000115 00000 n \n"
    b"0000000215 00000 n \n"
    b"trailer\n<< /Size 5 /Root 1 0 R >>\n"
    b"startxref\n315\n"
    b"%%EOF\n"
)


def build_4file_xfs_image(out_path: Path) -> dict:
    """
    Constructs a valid XFS v4 image with 4 distinct deleted inodes
    (200, 201, 202, 203) at different data block offsets.
    """
    img_size = 16 * 1024 * 1024  # 16 MiB
    img = bytearray(4096 * 80)   # Buffer for headers + data blocks

    # 1. Superblock (512 bytes at offset 0)
    struct.pack_into(">I", img, 0, 0x58465342)       # magic 'XFSB'
    struct.pack_into(">I", img, 4, 4096)             # block_size = 4096
    struct.pack_into(">Q", img, 8, img_size // 4096) # dblocks
    struct.pack_into(">Q", img, 56, 200)             # rootino = 200 (DIFFERENT from fixture's 128)
    struct.pack_into(">I", img, 84, 4096)            # agblocks = 4096
    struct.pack_into(">I", img, 88, 1)               # agcount = 1
    struct.pack_into(">H", img, 100, 4)              # version = 4
    struct.pack_into(">H", img, 102, 512)            # sectsize = 512
    struct.pack_into(">H", img, 104, 256)            # inodesize = 256
    struct.pack_into(">H", img, 106, 16)             # inopblock = 16
    img[120] = 12  # blocklog
    img[121] = 9   # sectlog
    img[122] = 8   # inodelog
    img[123] = 4   # inopblog
    img[124] = 12  # agblklog

    # AGF at sector 1 (512)
    struct.pack_into(">I", img, 512 + 0, 0x58414746)  # XAGF
    struct.pack_into(">I", img, 512 + 4, 1)
    struct.pack_into(">I", img, 512 + 8, 0)
    struct.pack_into(">I", img, 512 + 12, 4096)
    struct.pack_into(">I", img, 512 + 16, 4)
    struct.pack_into(">I", img, 512 + 20, 5)
    struct.pack_into(">I", img, 512 + 28, 1)
    struct.pack_into(">I", img, 512 + 32, 1)
    struct.pack_into(">I", img, 512 + 52, 3000)
    struct.pack_into(">I", img, 512 + 56, 3000)

    # AGI at sector 2 (1024)
    struct.pack_into(">I", img, 1024 + 0, 0x58414749)  # XAGI
    struct.pack_into(">I", img, 1024 + 4, 1)
    struct.pack_into(">I", img, 1024 + 8, 0)
    struct.pack_into(">I", img, 1024 + 12, 4096)
    struct.pack_into(">I", img, 1024 + 16, 64)
    struct.pack_into(">I", img, 1024 + 20, 3)
    struct.pack_into(">I", img, 1024 + 24, 1)
    struct.pack_into(">I", img, 1024 + 28, 60)
    for b in range(64):
        struct.pack_into(">I", img, 1024 + 40 + b * 4, 0xFFFFFFFF)

    # Block 3 (12288) - INOBT leaf
    struct.pack_into(">I", img, 12288 + 0, 0x49414254)  # IABT
    struct.pack_into(">H", img, 12288 + 4, 0)
    struct.pack_into(">H", img, 12288 + 6, 1)
    struct.pack_into(">I", img, 12288 + 8, 0xFFFFFFFF)
    struct.pack_into(">I", img, 12288 + 12, 0xFFFFFFFF)
    struct.pack_into(">I", img, 12288 + 16 + 0, 192)  # startino 192 (not 128!)
    struct.pack_into(">I", img, 12288 + 16 + 4, 60)   # freecount 60
    # Slots: 200,201,202,203 are allocated (bit positions 8-11 from startino 192)
    # Bitmap: all free (1) except positions 8,9,10,11 (0)
    bitmask = 0xFFFFFFFFFFFFFFFF & ~(0xF << 8)
    struct.pack_into(">Q", img, 12288 + 16 + 8, bitmask)

    # Block 4 (16384) - BNOBT leaf
    struct.pack_into(">I", img, 16384 + 0, 0x41425442)  # ABTB
    struct.pack_into(">H", img, 16384 + 4, 0)
    struct.pack_into(">H", img, 16384 + 6, 1)
    struct.pack_into(">I", img, 16384 + 8, 0xFFFFFFFF)
    struct.pack_into(">I", img, 16384 + 12, 0xFFFFFFFF)
    struct.pack_into(">I", img, 16384 + 16 + 0, 48)
    struct.pack_into(">I", img, 16384 + 16 + 4, 3000)

    # Block 5 (20480) - CNTBT leaf
    struct.pack_into(">I", img, 20480 + 0, 0x41425443)  # ABTC
    struct.pack_into(">H", img, 20480 + 4, 0)
    struct.pack_into(">H", img, 20480 + 6, 1)
    struct.pack_into(">I", img, 20480 + 8, 0xFFFFFFFF)
    struct.pack_into(">I", img, 20480 + 12, 0xFFFFFFFF)
    struct.pack_into(">I", img, 20480 + 16 + 0, 48)
    struct.pack_into(">I", img, 20480 + 16 + 4, 3000)

    # ---------------------------------------------------------------------------
    # Inode chunk at block 12 (offset 49152) — startino=192, so ino 200 is at slot 8
    # Slot index within chunk: ino - startino = 200 - 192 = 8
    # Each inode is 256 bytes, so offset within chunk = 8 * 256 = 2048
    # ---------------------------------------------------------------------------
    chunk_base = 49152  # block 12

    # Data blocks start at block 48 (offset 196608)
    data_blocks = {
        200: 48,   # block 48
        201: 49,   # block 49
        202: 50,   # block 50
        203: 51,   # block 51
    }

    test_files = [
        (200, ALPHA_TXT, "txt",  0o100644, 1700100000, 1700100001, 1700100002),
        (201, BETA_JSON, "json", 0o100644, 1700200000, 1700200001, 1700200002),
        (202, GAMMA_PNG, "png",  0o100644, 1700300000, 1700300001, 1700300002),
        (203, DELTA_PDF, "pdf",  0o100644, 1700400000, 1700400001, 1700400002),
    ]

    manifest_files = []

    for ino, content, ftype, mode, atime, mtime, ctime in test_files:
        slot = ino - 192  # slot within inode chunk
        ino_off = chunk_base + slot * 256
        data_blk = data_blocks[ino]
        data_off = data_blk * 4096

        # Write file content into data block
        img[data_off:data_off + len(content)] = content

        # Write dinode
        struct.pack_into(">H", img, ino_off + 0, 0x494e)       # magic 'IN'
        struct.pack_into(">H", img, ino_off + 2, mode)          # mode
        img[ino_off + 4] = 2                                    # version 2
        img[ino_off + 5] = 2                                    # format: extents
        struct.pack_into(">I", img, ino_off + 16, 0)            # nlink = 0 (DELETED)
        struct.pack_into(">I", img, ino_off + 8, 1000)          # uid
        struct.pack_into(">I", img, ino_off + 12, 1000)         # gid
        struct.pack_into(">Q", img, ino_off + 56, len(content)) # size
        struct.pack_into(">Q", img, ino_off + 64, 1)            # nblocks
        struct.pack_into(">I", img, ino_off + 76, 1)            # nextents
        struct.pack_into(">I", img, ino_off + 32, atime)        # atime
        struct.pack_into(">I", img, ino_off + 40, mtime)        # mtime
        struct.pack_into(">I", img, ino_off + 48, ctime)        # ctime
        img[ino_off + 90] = 0                                   # forkoff

        # Extent descriptor: startoff=0, startblock=data_blk, blockcount=1
        struct.pack_into(">Q", img, ino_off + 100, 0)
        struct.pack_into(">Q", img, ino_off + 108, (data_blk << 21) | 1)

        sha256 = hashlib.sha256(content).hexdigest()
        manifest_files.append({
            "filename": f"xfs_deleted_ino_{ino}.{ftype}",
            "file_id": f"xfs:ino{ino}",
            "file_type": ftype,
            "inode": ino,
            "size_bytes": len(content),
            "sha256": sha256,
            "data_block": data_blk,
            "data_offset": data_off,
        })

    # Write the image
    with open(out_path, "wb") as f:
        f.truncate(img_size)
    with open(out_path, "r+b") as f:
        f.write(img)

    # Compute image hash
    with open(out_path, "rb") as f:
        image_sha256 = hashlib.sha256(f.read()).hexdigest()

    return {
        "image_path": str(out_path),
        "image_sha256": image_sha256,
        "image_size_bytes": img_size,
        "filesystem": "xfs",
        "test_files": manifest_files,
    }


def main():
    image_path = PROJECT_ROOT / "gui_4file_test.img"
    manifest_path = PROJECT_ROOT / "gui_4file_ground_truth.json"

    print("=== FirSeFile 4-File XFS Test Image Generator ===")
    print(f"Image:    {image_path}")
    print(f"Manifest: {manifest_path}")
    print()

    result = build_4file_xfs_image(image_path)

    print(f"Image SHA-256: {result['image_sha256']}")
    print(f"Image size:    {result['image_size_bytes']} bytes")
    print()
    print("Test files embedded:")
    for f in result["test_files"]:
        print(f"  [{f['file_id']}] {f['filename']} — {f['size_bytes']} bytes — SHA-256: {f['sha256'][:16]}...")
    print()

    # Write manifest
    manifest_path.write_text(json.dumps(result, indent=2))
    print(f"Manifest written to {manifest_path}")
    print()
    print("=== Done ===")


if __name__ == "__main__":
    main()
