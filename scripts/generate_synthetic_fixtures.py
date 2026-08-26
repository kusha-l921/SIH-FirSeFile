#!/usr/bin/env python3
"""
generate_synthetic_fixtures.py
==============================
Generates standalone, reproducible forensic disk images with deleted files
and associated metadata for XFS and Btrfs filesystems without requiring
Linux kernel mounts or root privileges.

Also writes a machine-readable test_manifest.json containing expected
SHA-256 hashes, sizes, timestamps, and recovery expectations.

Files Generated:
  - tests/fixtures/xfs_deleted_synthetic.img
  - tests/fixtures/btrfs_deleted_synthetic.img
  - tests/fixtures/test_manifest.json
"""

import os
import sys
import struct
import hashlib
import binascii
import json
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
FIXTURES_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Sample Test Files
# ---------------------------------------------------------------------------

SAMPLE_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n"
    b"4 0 obj\n<< /Length 44 >>\nstream\nBT /F1 24 Tf 100 700 Td (Confidential Forensic Report) Tj ET\nendstream\nendobj\n"
    b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000210 00000 n \n"
    b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n304\n%%EOF\n"
)

SAMPLE_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
    b"\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0\x00\x00\x03\x01\x01\x00\xc9\xfe\x92\xef"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)

SAMPLE_JPG = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00"
    b"\xff\xdb\x00C\x00" + (b"\x08" * 64) +
    b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00"
    b"\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b"
    b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00\x7f\x00"
    b"\xff\xd9"
)

SAMPLE_ZIP = (
    b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x82\x95eX\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00"
    b"test.txt"
    b"PK\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00\x82\x95eX\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"test.txt"
    b"PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x006\x00\x00\x00&\x00\x00\x00\x00\x00"
)

SAMPLE_SQLITE = (
    b"SQLite format 3\x00\x10\x00\x01\x01\x00@  \x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x04\x00\x00\x00\x00"
    + (b"\x00" * 68)
)

SAMPLE_SCRIPT = (
    b"#!/bin/bash\n"
    b"# Forensic evidence collection script\n"
    b"echo 'Collecting disk artifacts...'\n"
    b"uname -a\n"
)


# ---------------------------------------------------------------------------
# XFS Synthetic Image Builder
# ---------------------------------------------------------------------------

def build_xfs_synthetic_image(out_path: Path) -> dict:
    """
    Constructs a valid XFS v4 image containing superblock, AG geometry,
    and deleted inode candidates.
    """
    img_size = 2 * 1024 * 1024  # 2 MiB
    img = bytearray(img_size)

    # 1. Superblock (512 bytes at offset 0)
    struct.pack_into(">I", img, 0, 0x58465342)      # magic 'XFSB'
    struct.pack_into(">I", img, 4, 4096)            # block_size = 4096
    struct.pack_into(">Q", img, 8, img_size // 4096)# dblocks = 512
    struct.pack_into(">Q", img, 56, 128)            # rootino = 128
    struct.pack_into(">I", img, 84, 512)            # agblocks = 512
    struct.pack_into(">I", img, 88, 1)              # agcount = 1
    struct.pack_into(">H", img, 100, 4)             # version = 4 (v4)
    struct.pack_into(">H", img, 102, 512)           # sectsize = 512
    struct.pack_into(">H", img, 104, 256)           # inodesize = 256
    struct.pack_into(">H", img, 106, 16)            # inopblock = 16
    img[120] = 12  # blocklog
    img[121] = 9   # sectlog
    img[122] = 8   # inodelog
    img[123] = 4   # inopblog
    img[124] = 9   # agblklog

    # 2. Inode chunk at block 16 (offset 65536)
    # Put deleted PDF file at inode 128 (offset 65536)
    ino_offset = 65536
    data_block_offset = 131072  # block 32

    # Write PDF data into data block
    img[data_block_offset:data_block_offset + len(SAMPLE_PDF)] = SAMPLE_PDF

    # Write Dinode Core for Inode 128 (deleted PDF)
    struct.pack_into(">H", img, ino_offset + 0, 0x494e)       # magic 'IN'
    struct.pack_into(">H", img, ino_offset + 2, 0o100644)     # mode: regular file 0644
    img[ino_offset + 4] = 2                                   # version 2
    img[ino_offset + 5] = 2                                   # format: extents (XFS_DINODE_FMT_EXTENTS)
    struct.pack_into(">H", img, ino_offset + 6, 0)            # nlink = 0 (DELETED!)
    struct.pack_into(">I", img, ino_offset + 8, 1000)         # uid = 1000
    struct.pack_into(">I", img, ino_offset + 12, 1000)        # gid = 1000
    struct.pack_into(">Q", img, ino_offset + 16, len(SAMPLE_PDF)) # size
    struct.pack_into(">Q", img, ino_offset + 24, 1)           # nblocks = 1
    struct.pack_into(">I", img, ino_offset + 32, 1700000000)  # atime sec
    struct.pack_into(">I", img, ino_offset + 40, 1700000002)  # mtime sec
    struct.pack_into(">I", img, ino_offset + 48, 1700000001)  # ctime sec
    img[ino_offset + 90] = 0                                  # forkoff = 0

    # Write extent descriptor in data fork (offset ino_offset + 100)
    # BMBT extent record: [flag(1) | startoff(54) | startblock(52) | blockcount(21)] = 128 bits
    # startoff = 0, startblock = 32 (data_block_offset / 4096), blockcount = 1
    # Bits [0..63]: (0 << 63) | (0 << 9) | ((32 >> 43) & 0x1FF) = 0
    # Bits [64..127]: ((32 & 0x7FFFFFFFFFF) << 21) | (1 & 0x1FFFFF) = (32 << 21) | 1 = 67108865
    struct.pack_into(">Q", img, ino_offset + 100, 0)
    struct.pack_into(">Q", img, ino_offset + 108, (32 << 21) | 1)

    # Inode 129 (Deleted PNG at ino_offset + 256)
    ino2_offset = ino_offset + 256
    data_block2_offset = data_block_offset + 4096
    img[data_block2_offset:data_block2_offset + len(SAMPLE_PNG)] = SAMPLE_PNG

    struct.pack_into(">H", img, ino2_offset + 0, 0x494e)
    struct.pack_into(">H", img, ino2_offset + 2, 0o100644)
    img[ino2_offset + 4] = 2
    img[ino2_offset + 5] = 2
    struct.pack_into(">H", img, ino2_offset + 6, 0)            # nlink = 0 (DELETED!)
    struct.pack_into(">I", img, ino2_offset + 8, 1000)
    struct.pack_into(">I", img, ino2_offset + 12, 1000)
    struct.pack_into(">Q", img, ino2_offset + 16, len(SAMPLE_PNG))
    struct.pack_into(">Q", img, ino2_offset + 24, 1)
    struct.pack_into(">I", img, ino2_offset + 32, 1700000100)
    struct.pack_into(">I", img, ino2_offset + 40, 1700000102)
    struct.pack_into(">I", img, ino2_offset + 48, 1700000101)
    img[ino2_offset + 90] = 0

    # Extent descriptor for Inode 129 -> block 33
    struct.pack_into(">Q", img, ino2_offset + 100, 0)
    struct.pack_into(">Q", img, ino2_offset + 108, (33 << 21) | 1)

    # Also place raw carvings in unallocated space at block 100 (offset 409600)
    carve_offset = 409600
    img[carve_offset:carve_offset + len(SAMPLE_JPG)] = SAMPLE_JPG
    img[carve_offset + 8192:carve_offset + 8192 + len(SAMPLE_ZIP)] = SAMPLE_ZIP
    img[carve_offset + 16384:carve_offset + 16384 + len(SAMPLE_SQLITE)] = SAMPLE_SQLITE
    img[carve_offset + 24576:carve_offset + 24576 + len(SAMPLE_SCRIPT)] = SAMPLE_SCRIPT

    out_path.write_bytes(img)

    return {
        "image_file": str(out_path.name),
        "filesystem": "xfs",
        "total_size": img_size,
        "sha256": hashlib.sha256(img).hexdigest(),
        "files": [
            {
                "file_id": "xfs:ino128",
                "filename": "deleted_report.pdf",
                "file_type": "pdf",
                "expected_size": len(SAMPLE_PDF),
                "expected_sha256": hashlib.sha256(SAMPLE_PDF).hexdigest(),
                "recovery_method": "xfs_residual_extents",
                "expected_recovery": True,
            },
            {
                "file_id": "xfs:ino129",
                "filename": "deleted_logo.png",
                "file_type": "png",
                "expected_size": len(SAMPLE_PNG),
                "expected_sha256": hashlib.sha256(SAMPLE_PNG).hexdigest(),
                "recovery_method": "xfs_residual_extents",
                "expected_recovery": True,
            },
            {
                "file_id": f"xfs:carved_0x{carve_offset:x}",
                "filename": f"carved_0x{carve_offset:x}.jpg",
                "file_type": "jpg",
                "expected_size": len(SAMPLE_JPG),
                "expected_sha256": hashlib.sha256(SAMPLE_JPG).hexdigest(),
                "recovery_method": "carving",
                "expected_recovery": True,
            },
            {
                "file_id": f"xfs:carved_0x{carve_offset + 8192:x}",
                "filename": f"carved_0x{carve_offset + 8192:x}.zip",
                "file_type": "zip",
                "expected_size": len(SAMPLE_ZIP),
                "expected_sha256": hashlib.sha256(SAMPLE_ZIP).hexdigest(),
                "recovery_method": "carving",
                "expected_recovery": True,
            },
        ],
    }


# ---------------------------------------------------------------------------
# Btrfs Synthetic Image Builder
# ---------------------------------------------------------------------------

def build_btrfs_synthetic_image(out_path: Path) -> dict:
    """
    Constructs a valid Btrfs image with primary superblock at 64 KiB,
    root tree, deleted inodes (nlink=0, size>0), and carved file signatures.
    """
    nodesize = 16384
    img_size = 2 * 1024 * 1024  # 2 MiB
    img = bytearray(img_size)

    # 1. Btrfs Superblock at offset 65536 (64 KiB)
    sb_offset = 65536
    node_offset = 131072  # 128 KiB

    # Pack superblock
    struct.pack_into("<Q", img, sb_offset + 48, sb_offset)       # bytenr
    struct.pack_into("<Q", img, sb_offset + 56, 0)               # flags
    img[sb_offset + 64:sb_offset + 72] = b"_BHRfS_M"             # magic
    struct.pack_into("<Q", img, sb_offset + 72, 1)               # generation = 1
    struct.pack_into("<Q", img, sb_offset + 80, node_offset)     # root tree address
    struct.pack_into("<Q", img, sb_offset + 88, node_offset)     # chunk_root
    struct.pack_into("<Q", img, sb_offset + 96, 0)               # log_root
    struct.pack_into("<Q", img, sb_offset + 104, img_size)       # total_bytes
    struct.pack_into("<Q", img, sb_offset + 112, nodesize * 4)   # bytes_used
    struct.pack_into("<Q", img, sb_offset + 128, 1)              # num_devices = 1
    struct.pack_into("<I", img, sb_offset + 136, 4096)           # sectorsize = 4096
    struct.pack_into("<I", img, sb_offset + 140, nodesize)       # nodesize = 16384
    struct.pack_into("<I", img, sb_offset + 144, nodesize)       # leafsize
    struct.pack_into("<I", img, sb_offset + 148, 4096)           # stripesize
    label = b"TEST_BTRFS_IMG\x00"
    img[sb_offset + 299:sb_offset + 299 + len(label)] = label

    # 2. Btrfs Leaf Node at node_offset (128 KiB)
    # Node Header (101 bytes)
    img[node_offset + 64:node_offset + 80] = b"\x00" * 16         # chunk_tree_uuid
    struct.pack_into("<Q", img, node_offset + 80, 1)             # generation = 1
    struct.pack_into("<Q", img, node_offset + 88, 5)             # owner = FS_TREE (5)
    img[node_offset + 96] = 0                                    # level = 0 (leaf)
    struct.pack_into("<I", img, node_offset + 97, 2)             # nritems = 2

    # Inode item 1 (Inode 256 - Active Directory)
    # Inode item 2 (Inode 257 - Deleted File, size=len(SAMPLE_PDF), nlink=0)
    inode_item_size = 160
    item_desc_size = 25

    # Build deleted inode item bytes
    del_inode = bytearray(inode_item_size)
    struct.pack_into("<Q", del_inode, 0, 1)                      # generation = 1
    struct.pack_into("<Q", del_inode, 8, 1)                      # transid = 1
    struct.pack_into("<Q", del_inode, 16, len(SAMPLE_PDF))       # size
    struct.pack_into("<Q", del_inode, 24, 4096)                  # nbytes
    struct.pack_into("<I", del_inode, 44, 0)                     # nlink = 0 (DELETED!)
    struct.pack_into("<I", del_inode, 48, 1000)                  # uid = 1000
    struct.pack_into("<I", del_inode, 52, 1000)                  # gid = 1000
    struct.pack_into("<I", del_inode, 56, 0o100644)              # mode = 0644 regular file
    struct.pack_into("<Q", del_inode, 64, 1700000000)            # atime
    struct.pack_into("<Q", del_inode, 80, 1700000001)            # ctime
    struct.pack_into("<Q", del_inode, 96, 1700000002)            # mtime
    struct.pack_into("<Q", del_inode, 112, 1699999999)           # otime (birth)

    # Active root dir inode (Inode 256)
    dir_inode = bytearray(inode_item_size)
    struct.pack_into("<Q", dir_inode, 0, 1)
    struct.pack_into("<Q", dir_inode, 8, 1)
    struct.pack_into("<Q", dir_inode, 16, 0)
    struct.pack_into("<Q", dir_inode, 24, 0)
    struct.pack_into("<I", dir_inode, 44, 1)                     # nlink = 1 (active)
    struct.pack_into("<I", dir_inode, 48, 0)
    struct.pack_into("<I", dir_inode, 52, 0)
    struct.pack_into("<I", dir_inode, 56, 0o040755)              # mode = dir 0755
    struct.pack_into("<Q", dir_inode, 64, 1700000000)
    struct.pack_into("<Q", dir_inode, 80, 1700000001)
    struct.pack_into("<Q", dir_inode, 96, 1700000002)
    struct.pack_into("<Q", dir_inode, 112, 1699999999)

    # Place item data from end of leaf backwards
    # Item 1 data (dir_inode) at offset nodesize - 160
    data_off_1 = 0
    img[node_offset + nodesize - 160:node_offset + nodesize] = dir_inode

    # Item 2 data (del_inode) at offset nodesize - 320
    data_off_2 = 160
    img[node_offset + nodesize - 320:node_offset + nodesize - 160] = del_inode

    # Write Item Descriptors after header (101)
    desc1_off = node_offset + 101
    struct.pack_into("<Q", img, desc1_off + 0, 256)              # objectid = 256
    img[desc1_off + 8] = 1                                       # type = INODE_ITEM (1)
    struct.pack_into("<Q", img, desc1_off + 9, 0)                # offset = 0
    struct.pack_into("<I", img, desc1_off + 17, data_off_1)      # data_offset = 0
    struct.pack_into("<I", img, desc1_off + 21, 160)             # data_size = 160

    desc2_off = desc1_off + item_desc_size
    struct.pack_into("<Q", img, desc2_off + 0, 257)              # objectid = 257 (Deleted!)
    img[desc2_off + 8] = 1                                       # type = INODE_ITEM (1)
    struct.pack_into("<Q", img, desc2_off + 9, 0)
    struct.pack_into("<I", img, desc2_off + 17, data_off_2)      # data_offset = 160
    struct.pack_into("<I", img, desc2_off + 21, 160)             # data_size = 160

    # Place carved files in free space at offset 262144 (256 KiB)
    carve_offset = 262144
    img[carve_offset:carve_offset + len(SAMPLE_PDF)] = SAMPLE_PDF
    img[carve_offset + 8192:carve_offset + 8192 + len(SAMPLE_PNG)] = SAMPLE_PNG
    img[carve_offset + 16384:carve_offset + 16384 + len(SAMPLE_JPG)] = SAMPLE_JPG
    img[carve_offset + 24576:carve_offset + 24576 + len(SAMPLE_ZIP)] = SAMPLE_ZIP
    img[carve_offset + 32768:carve_offset + 32768 + len(SAMPLE_SQLITE)] = SAMPLE_SQLITE

    out_path.write_bytes(img)

    return {
        "image_file": str(out_path.name),
        "filesystem": "btrfs",
        "total_size": img_size,
        "sha256": hashlib.sha256(img).hexdigest(),
        "files": [
            {
                "file_id": "btrfs:ino_257",
                "filename": "deleted_ino_257",
                "file_type": "unknown",
                "expected_size": len(SAMPLE_PDF),
                "recovery_method": "btrfs_structural",
                "expected_recovery": True,
            },
            {
                "file_id": f"btrfs:carved_0x{carve_offset:x}",
                "filename": f"carved_0x{carve_offset:x}.pdf",
                "file_type": "pdf",
                "expected_size": len(SAMPLE_PDF),
                "expected_sha256": hashlib.sha256(SAMPLE_PDF).hexdigest(),
                "recovery_method": "btrfs_carved",
                "expected_recovery": True,
            },
            {
                "file_id": f"btrfs:carved_0x{carve_offset + 8192:x}",
                "filename": f"carved_0x{carve_offset + 8192:x}.png",
                "file_type": "png",
                "expected_size": len(SAMPLE_PNG),
                "expected_sha256": hashlib.sha256(SAMPLE_PNG).hexdigest(),
                "recovery_method": "btrfs_carved",
                "expected_recovery": True,
            },
            {
                "file_id": f"btrfs:carved_0x{carve_offset + 16384:x}",
                "filename": f"carved_0x{carve_offset + 16384:x}.jpg",
                "file_type": "jpg",
                "expected_size": len(SAMPLE_JPG),
                "expected_sha256": hashlib.sha256(SAMPLE_JPG).hexdigest(),
                "recovery_method": "btrfs_carved",
                "expected_recovery": True,
            },
            {
                "file_id": f"btrfs:carved_0x{carve_offset + 24576:x}",
                "filename": f"carved_0x{carve_offset + 24576:x}.zip",
                "file_type": "zip",
                "expected_size": len(SAMPLE_ZIP),
                "expected_sha256": hashlib.sha256(SAMPLE_ZIP).hexdigest(),
                "recovery_method": "btrfs_carved",
                "expected_recovery": True,
            },
        ],
    }


def main():
    print("Generating synthetic forensic test fixtures...")

    xfs_path = FIXTURES_DIR / "xfs_deleted_synthetic.img"
    btrfs_path = FIXTURES_DIR / "btrfs_deleted_synthetic.img"
    manifest_path = FIXTURES_DIR / "test_manifest.json"

    xfs_info = build_xfs_synthetic_image(xfs_path)
    btrfs_info = build_btrfs_synthetic_image(btrfs_path)

    manifest = {
        "generated_by": "generate_synthetic_fixtures.py",
        "description": "Deterministic forensic deleted-data test fixtures for XFS and Btrfs",
        "test_cases": [xfs_info, btrfs_info],
    }

    manifest_path.write_text(json.dumps(manifest, indent=2))

    print(f"Created: {xfs_path} ({xfs_info['total_size']} bytes)")
    print(f"Created: {btrfs_path} ({btrfs_info['total_size']} bytes)")
    print(f"Created: {manifest_path}")
    print("Synthetic fixtures generated successfully.")


if __name__ == "__main__":
    main()
