"""
checksum/__init__.py
====================
CRC32C implementation for Btrfs checksum verification.

Btrfs uses CRC-32C (Castagnoli), NOT the standard CRC-32/ISO-HDLC that
Python's binascii.crc32() computes.  They share the same algorithm structure
but use different generator polynomials:
  CRC-32/ISO-HDLC : 0xEDB88320 (reflected 0x04C11DB7)
  CRC-32C         : 0x82F63B78 (reflected 0x1EDC6F41)

This module provides a pure-Python CRC32C that works on Windows without
any native extension.  It is ~10x slower than a C extension but correct.

If the optional `crc32c` package is installed, it is used automatically.
"""

import struct
from typing import Optional

# ---------------------------------------------------------------------------
# Try fast native CRC32C first
# ---------------------------------------------------------------------------
try:
    import crc32c as _crc32c_ext
    def crc32c(data: bytes, value: int = 0) -> int:
        return _crc32c_ext.crc32c(data, value)
    _USING_NATIVE = True
except ImportError:
    _USING_NATIVE = False

if not _USING_NATIVE:
    # Pure-Python CRC32C table (Castagnoli polynomial 0x82F63B78)
    _TABLE: list = []

    def _build_table() -> None:
        poly = 0x82F63B78
        for i in range(256):
            crc = i
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ poly
                else:
                    crc >>= 1
            _TABLE.append(crc)

    _build_table()

    def crc32c(data: bytes, value: int = 0) -> int:
        """Compute CRC32C (Castagnoli) of data, optionally continuing from value."""
        crc = value ^ 0xFFFFFFFF
        for byte in data:
            crc = _TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
        return crc ^ 0xFFFFFFFF


def verify_btrfs_csum(stored_csum: bytes, data: bytes) -> bool:
    """
    Verify a Btrfs CRC32C checksum.

    Btrfs stores the CRC32C of the block (with the csum field zeroed) in the
    first 4 bytes of the 32-byte csum field at the start of every tree block
    and the superblock.

    Args:
        stored_csum: The full 32-byte csum field from the on-disk block.
        data:        The block bytes with the csum field already zeroed.
    """
    if len(stored_csum) < 4:
        return False
    stored = struct.unpack_from('<I', stored_csum, 0)[0]
    computed = crc32c(data) & 0xFFFFFFFF
    return computed == stored


def compute_block_csum(block: bytes) -> int:
    """
    Compute the CRC32C that Btrfs would store for a tree block.
    The first 32 bytes (csum field) are treated as zero during computation.
    """
    zeroed = b'\x00' * 32 + block[32:]
    return crc32c(zeroed) & 0xFFFFFFFF
