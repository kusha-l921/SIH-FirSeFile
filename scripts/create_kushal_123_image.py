#!/usr/bin/env python3
"""
create_kushal_123_image.py
==========================
Generates the 512MB XFS evidence disk image `gui_kushal_123_test.img`
containing three deleted files:
  1.txt -> kushal.1 (8 bytes, SHA-256: 8d06d9cef147428f0a9c6667020c4e8a42b68273203cd4c908a6a41f6ec26f9b)
  2.txt -> kushal.2 (8 bytes, SHA-256: 6ff889eda5fb8cbbdd05528c2ceaac77ceb64c0778aa799fc842606d49014913)
  3.txt -> kushal.3 (8 bytes, SHA-256: d27fbdabdb7fd8ce256aa969e2a3c7849562a468a803bf49dd7aaa2412deb03f)

Inodes: 128, 129, 130 with nlink=0 (deleted) and extent descriptors.
"""

import os
import sys
import struct
import hashlib
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

KUSHAL_1 = b"kushal.1"
KUSHAL_2 = b"kushal.2"
KUSHAL_3 = b"kushal.3"


def build_kushal_123_xfs_image(out_path: Path) -> dict:
    """
    Constructs a 512MB XFS image with superblock, AG geometry,
    INOBT/AGI/AGF, and 3 deleted inodes (128, 129, 130).
    """
    img_size = 512 * 1024 * 1024  # 512 MiB
    img = bytearray(4096 * 120)   # Metadata & data blocks buffer

    # 1. Superblock (512 bytes at offset 0)
    struct.pack_into(">I", img, 0, 0x58465342)       # magic 'XFSB'
    struct.pack_into(">I", img, 4, 4096)             # block_size = 4096
    struct.pack_into(">Q", img, 8, img_size // 4096) # dblocks = 131072
    struct.pack_into(">Q", img, 56, 128)             # rootino = 128
    struct.pack_into(">I", img, 84, 32768)           # agblocks = 32768
    struct.pack_into(">I", img, 88, 4)               # agcount = 4
    struct.pack_into(">H", img, 100, 4)              # version = 4
    struct.pack_into(">H", img, 102, 512)            # sectsize = 512
    struct.pack_into(">H", img, 104, 256)            # inodesize = 256
    struct.pack_into(">H", img, 106, 16)             # inopblock = 16
    img[120] = 12  # blocklog
    img[121] = 9   # sectlog
    img[122] = 8   # inodelog
    img[123] = 4   # inopblog
    img[124] = 15  # agblklog (2^15 = 32768)

    # AGF at sector 1 (512)
    struct.pack_into(">I", img, 512 + 0, 0x58414746)  # XAGF
    struct.pack_into(">I", img, 512 + 4, 1)          # version 1
    struct.pack_into(">I", img, 512 + 8, 0)          # seqno 0
    struct.pack_into(">I", img, 512 + 12, 32768)     # length
    struct.pack_into(">I", img, 512 + 16, 4)         # bnobt root block 4
    struct.pack_into(">I", img, 512 + 20, 5)         # cntbt root block 5
    struct.pack_into(">I", img, 512 + 28, 1)         # bnobt level 1
    struct.pack_into(">I", img, 512 + 32, 1)         # cntbt level 1
    struct.pack_into(">I", img, 512 + 52, 30000)     # freeblks
    struct.pack_into(">I", img, 512 + 56, 30000)     # longest

    # AGI at sector 2 (1024)
    struct.pack_into(">I", img, 1024 + 0, 0x58414749) # XAGI
    struct.pack_into(">I", img, 1024 + 4, 1)
    struct.pack_into(">I", img, 1024 + 8, 0)
    struct.pack_into(">I", img, 1024 + 12, 32768)
    struct.pack_into(">I", img, 1024 + 16, 64)        # count 64
    struct.pack_into(">I", img, 1024 + 20, 3)         # inobt root block 3
    struct.pack_into(">I", img, 1024 + 24, 1)
    struct.pack_into(">I", img, 1024 + 28, 61)        # freecount 61
    for b in range(64):
        struct.pack_into(">I", img, 1024 + 40 + b * 4, 0xFFFFFFFF)

    # Block 3 (12288) - INOBT leaf
    struct.pack_into(">I", img, 12288 + 0, 0x49414254) # IABT
    struct.pack_into(">H", img, 12288 + 4, 0)
    struct.pack_into(">H", img, 12288 + 6, 1)
    struct.pack_into(">I", img, 12288 + 8, 0xFFFFFFFF)
    struct.pack_into(">I", img, 12288 + 12, 0xFFFFFFFF)
    struct.pack_into(">I", img, 12288 + 16 + 0, 128)   # startino 128
    struct.pack_into(">I", img, 12288 + 16 + 4, 61)    # freecount 61
    # Slots: 128, 129, 130 allocated with nlink=0 (bits 0,1,2 = 0)
    struct.pack_into(">Q", img, 12288 + 16 + 8, 0xFFFFFFFFFFFFFFF8)

    # Block 4 (16384) - BNOBT leaf
    struct.pack_into(">I", img, 16384 + 0, 0x41425442) # ABTB
    struct.pack_into(">H", img, 16384 + 4, 0)
    struct.pack_into(">H", img, 16384 + 6, 1)
    struct.pack_into(">I", img, 16384 + 8, 0xFFFFFFFF)
    struct.pack_into(">I", img, 16384 + 12, 0xFFFFFFFF)
    struct.pack_into(">I", img, 16384 + 16 + 0, 64)
    struct.pack_into(">I", img, 16384 + 16 + 4, 30000)

    # Block 5 (20480) - CNTBT leaf
    struct.pack_into(">I", img, 20480 + 0, 0x41425443) # ABTC
    struct.pack_into(">H", img, 20480 + 4, 0)
    struct.pack_into(">H", img, 20480 + 6, 1)
    struct.pack_into(">I", img, 20480 + 8, 0xFFFFFFFF)
    struct.pack_into(">I", img, 20480 + 12, 0xFFFFFFFF)
    struct.pack_into(">I", img, 20480 + 16 + 0, 64)
    struct.pack_into(">I", img, 20480 + 16 + 4, 30000)

    # Inode chunk at block 8 (offset 32768)
    ino_offset = 32768
    data_block_offset = 262144  # block 64

    test_files = [
        (128, KUSHAL_1, "1.txt", 64),
        (129, KUSHAL_2, "2.txt", 65),
        (130, KUSHAL_3, "3.txt", 66),
    ]

    from datetime import datetime, timezone
    base_ts = int(datetime.now(timezone.utc).timestamp())
    manifest_files = []

    for idx, (ino, content, fname, data_blk) in enumerate(test_files):
        cur_ino_off = ino_offset + idx * 256
        cur_data_off = data_blk * 4096

        # Write data to data block
        img[cur_data_off:cur_data_off + len(content)] = content

        mtime_sec = base_ts - 60 + idx * 10
        atime_sec = base_ts - 120 + idx * 10
        ctime_sec = base_ts - 60 + idx * 10

        # Write dinode core
        struct.pack_into(">H", img, cur_ino_off + 0, 0x494e)       # magic 'IN'
        struct.pack_into(">H", img, cur_ino_off + 2, 0o100644)     # mode 0644
        img[cur_ino_off + 4] = 2                                   # version 2
        img[cur_ino_off + 5] = 2                                   # format: extents
        struct.pack_into(">I", img, cur_ino_off + 16, 0)           # nlink = 0 (DELETED)
        struct.pack_into(">I", img, cur_ino_off + 8, 1000)         # uid 1000
        struct.pack_into(">I", img, cur_ino_off + 12, 1000)        # gid 1000
        struct.pack_into(">Q", img, cur_ino_off + 56, len(content))# size = 8
        struct.pack_into(">Q", img, cur_ino_off + 64, 1)           # nblocks = 1
        struct.pack_into(">I", img, cur_ino_off + 76, 1)           # nextents = 1
        struct.pack_into(">I", img, cur_ino_off + 32, atime_sec)
        struct.pack_into(">I", img, cur_ino_off + 40, mtime_sec)
        struct.pack_into(">I", img, cur_ino_off + 48, ctime_sec)
        img[cur_ino_off + 90] = 0

        # Extent descriptor: startoff=0, startblock=data_blk, blockcount=1
        struct.pack_into(">Q", img, cur_ino_off + 100, 0)
        struct.pack_into(">Q", img, cur_ino_off + 108, (data_blk << 21) | 1)

        sha256 = hashlib.sha256(content).hexdigest()
        manifest_files.append({
            "filename": fname,
            "file_id": f"xfs:ino{ino}",
            "inode": ino,
            "size_bytes": len(content),
            "sha256": sha256,
            "mtime_iso": datetime.fromtimestamp(mtime_sec, tz=timezone.utc).isoformat(),
            "data_block": data_blk,
            "data_offset": cur_data_off,
        })

    # Write file
    with open(out_path, "wb") as f:
        f.truncate(img_size)
    with open(out_path, "r+b") as f:
        f.write(img)

    with open(out_path, "rb") as f:
        img_hash = hashlib.sha256(f.read()).hexdigest()

    return {
        "image_path": str(out_path),
        "image_sha256": img_hash,
        "image_size_bytes": img_size,
        "filesystem": "xfs",
        "test_files": manifest_files,
    }


def main():
    image_path = PROJECT_ROOT / "gui_kushal_123_test.img"
    ground_truth_path = PROJECT_ROOT / "kushal_123_ground_truth.txt"

    res = build_kushal_123_xfs_image(image_path)

    # Save ground truth text file in standard sha256sum format
    gt_lines = []
    for tf in res["test_files"]:
        gt_lines.append(f"{tf['sha256']}  /mnt/firsefile_kushal_123/{tf['filename']}\n")
    ground_truth_path.write_text("".join(gt_lines))

    print(f"=== Kushal 123 Test Image Generated ===")
    print(f"Path:         {image_path}")
    print(f"Size:         {res['image_size_bytes']} bytes")
    print(f"Image SHA256: {res['image_sha256']}")
    print(f"Ground Truth: {ground_truth_path}")
    print()
    print("Embedded Deleted Files:")
    for tf in res["test_files"]:
        print(f"  {tf['filename']} | inode={tf['inode']} | size={tf['size_bytes']} bytes | sha256={tf['sha256']}")
    print()


if __name__ == "__main__":
    main()
