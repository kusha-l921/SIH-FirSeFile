"""
test_helpers.py
===============
Synthetic Btrfs structure builders for tests.
No real block device or mkfs.btrfs required.
"""

import struct
import tempfile
import os

from btrfs_structs import (
    BTRFS_MAGIC, BTRFS_SUPER_OFFSET,
    BTRFS_INODE_ITEM_KEY, BTRFS_NODE_HEADER_SIZE, BTRFS_ITEM_SIZE,
)


def pack_superblock(generation=42, root=0, total_bytes=100*1024*1024,
                    bytes_used=1*1024*1024, nodesize=16384, label=b'testfs') -> bytes:
    """Build a minimal 4096-byte Btrfs superblock."""
    sb = bytearray(4096)
    sb[32:48] = b'\xAB' * 16                          # fsid
    struct.pack_into('<Q', sb, 48, BTRFS_SUPER_OFFSET) # bytenr
    struct.pack_into('<Q', sb, 56, 0)                  # flags
    sb[64:72] = BTRFS_MAGIC
    struct.pack_into('<Q', sb, 72, generation)
    struct.pack_into('<Q', sb, 80, root)
    struct.pack_into('<Q', sb, 88, 0)                  # chunk_root
    struct.pack_into('<Q', sb, 96, 0)                  # log_root
    struct.pack_into('<Q', sb, 104, total_bytes)
    struct.pack_into('<Q', sb, 112, bytes_used)
    struct.pack_into('<Q', sb, 128, 1)                 # num_devices
    struct.pack_into('<I', sb, 136, 4096)              # sectorsize
    struct.pack_into('<I', sb, 140, nodesize)
    struct.pack_into('<I', sb, 144, nodesize)          # leafsize
    struct.pack_into('<I', sb, 148, 4096)              # stripesize
    sb[299:299+len(label)] = label
    return bytes(sb)


def pack_inode_item(generation=1, size=1024, nbytes=4096, nlink=1,
                    uid=1000, gid=1000, mode=0o100644,
                    atime=1700000000, ctime=1700000001,
                    mtime=1700000002, otime=1699999999) -> bytes:
    """Build a 160-byte Btrfs inode item."""
    buf = bytearray(160)
    struct.pack_into('<Q', buf, 0,   generation)
    struct.pack_into('<Q', buf, 16,  size)
    struct.pack_into('<Q', buf, 24,  nbytes)
    struct.pack_into('<I', buf, 44,  nlink)
    struct.pack_into('<I', buf, 48,  uid)
    struct.pack_into('<I', buf, 52,  gid)
    struct.pack_into('<I', buf, 56,  mode)
    struct.pack_into('<Q', buf, 64,  atime)
    struct.pack_into('<Q', buf, 80,  ctime)
    struct.pack_into('<Q', buf, 96,  mtime)
    struct.pack_into('<Q', buf, 112, otime)
    return bytes(buf)


def pack_leaf_node(inode_num: int, inode_data: bytes, nodesize=16384) -> bytes:
    """
    Build a minimal leaf node with one BTRFS_INODE_ITEM_KEY entry.

    Leaf layout:
      [0:101]              node header (level=0, nritems=1)
      [101:126]            item descriptor: key(17) + data_offset(4) + data_size(4)
      [nodesize-160:end]   inode item data (stored from end of node)
    """
    node = bytearray(nodesize)
    node[96] = 0                                    # level = 0 (leaf)
    struct.pack_into('<I', node, 97, 1)             # nritems = 1

    # Item descriptor at offset 101
    struct.pack_into('<Q', node, 101, inode_num)    # key objectid
    node[109] = BTRFS_INODE_ITEM_KEY               # key type
    struct.pack_into('<Q', node, 110, 0)            # key offset
    struct.pack_into('<I', node, 118, 0)            # data_offset (from end)
    struct.pack_into('<I', node, 122, len(inode_data))  # data_size

    # Place inode data at end of node
    node[nodesize - len(inode_data):nodesize] = inode_data
    return bytes(node)


def make_image(superblock: bytes, leaf_node: bytes = b'',
               nodesize=16384, image_size=4*1024*1024) -> bytes:
    """
    Assemble a minimal image:
      [0 : BTRFS_SUPER_OFFSET]              zeros
      [BTRFS_SUPER_OFFSET : +4096]          superblock
      [BTRFS_SUPER_OFFSET+4096 : +nodesize] leaf node (if provided)
    """
    img = bytearray(image_size)
    img[BTRFS_SUPER_OFFSET: BTRFS_SUPER_OFFSET + len(superblock)] = superblock
    if leaf_node:
        node_offset = BTRFS_SUPER_OFFSET + 4096
        img[node_offset: node_offset + len(leaf_node)] = leaf_node
    return bytes(img)


def write_tmp_image(data: bytes) -> str:
    """Write bytes to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix='.img')
    os.write(fd, data)
    os.close(fd)
    return path
