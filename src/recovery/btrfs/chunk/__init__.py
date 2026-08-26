"""
chunk/__init__.py
=================
Btrfs logical-to-physical address mapping via the chunk tree.

Every Btrfs logical address must be resolved through the chunk tree before
reading from the image file.  This module implements that mapping layer.

The superblock contains a sys_chunk_array that bootstraps the chunk tree
(it holds the chunk tree's own mapping so we can find it).  After parsing
the sys_chunk_array we can read the full chunk tree and build a complete map.
"""

import struct
from typing import List, Optional, BinaryIO

from btrfs_structs import (
    ChunkMapping,
    BTRFS_CHUNK_ITEM_KEY, BTRFS_CHUNK_ITEM_SIZE, BTRFS_STRIPE_SIZE,
    BTRFS_NODE_HEADER_SIZE, BTRFS_ITEM_SIZE, BTRFS_KEY_PTR_SIZE,
    parse_node_header, parse_key,
    BtrfsKey,
)


class ChunkMap:
    """
    Maintains the logical→physical mapping for a single Btrfs filesystem.

    Usage:
        cm = ChunkMap()
        cm.load_sys_chunk_array(superblock_data, sys_chunk_array_size)
        cm.load_chunk_tree(fh, chunk_root_logical, nodesize)
        phys = cm.resolve(logical_address)
    """

    def __init__(self):
        # Sorted list of ChunkMapping, ordered by logical_start
        self._chunks: List[ChunkMapping] = []

    # ------------------------------------------------------------------
    # Bootstrap: sys_chunk_array in the superblock
    # ------------------------------------------------------------------

    def load_sys_chunk_array(self, superblock_data: bytes,
                              array_size: int) -> None:
        """
        Parse the sys_chunk_array embedded in the superblock.

        The array starts at superblock offset 2345 and contains alternating
        Btrfs keys (17 bytes) and chunk items.  This gives us the chunk tree's
        own physical location so we can read it.

        Superblock layout reference: btrfs-progs/ctree.h btrfs_super_block
        sys_chunk_array is at offset 2345 within the 4096-byte superblock.
        """
        SYS_CHUNK_ARRAY_OFFSET = 2345
        if len(superblock_data) < SYS_CHUNK_ARRAY_OFFSET + array_size:
            return

        data = superblock_data[SYS_CHUNK_ARRAY_OFFSET:
                               SYS_CHUNK_ARRAY_OFFSET + array_size]
        pos = 0
        while pos + 17 <= len(data):
            # Key: objectid(8) + type(1) + offset(8) = 17 bytes
            key = parse_key(data, pos)
            pos += 17

            if key.type != BTRFS_CHUNK_ITEM_KEY:
                break

            chunk = self._parse_chunk_item(data, pos, key.offset)
            if chunk:
                self._add_chunk(chunk)
                # Advance past this chunk item
                if pos + BTRFS_CHUNK_ITEM_SIZE <= len(data):
                    num_stripes = struct.unpack_from('<H', data, pos + 44)[0]
                    item_len = BTRFS_CHUNK_ITEM_SIZE + num_stripes * BTRFS_STRIPE_SIZE
                    pos += item_len
                else:
                    break
            else:
                break

    # ------------------------------------------------------------------
    # Full chunk tree traversal
    # ------------------------------------------------------------------

    def load_chunk_tree(self, fh: BinaryIO, chunk_root_logical: int,
                        nodesize: int, max_depth: int = 8) -> None:
        """
        Traverse the chunk tree starting from chunk_root_logical and
        populate the full logical→physical map.
        """
        if chunk_root_logical == 0:
            return
        phys = self.resolve(chunk_root_logical)
        if phys is None:
            return
        self._traverse_chunk_node(fh, phys, nodesize, max_depth, set())

    def _traverse_chunk_node(self, fh: BinaryIO, physical: int,
                              nodesize: int, depth: int,
                              visited: set) -> None:
        if depth <= 0 or physical in visited:
            return
        visited.add(physical)

        try:
            fh.seek(physical)
            data = fh.read(nodesize)
        except OSError:
            return

        hdr = parse_node_header(data, physical)
        if not hdr or hdr.nritems == 0 or hdr.nritems > 4096:
            return

        if hdr.level == 0:
            # Leaf node: parse chunk items
            self._parse_chunk_leaf(data, hdr.nritems, nodesize)
        else:
            # Internal node: follow child pointers
            off = BTRFS_NODE_HEADER_SIZE
            for _ in range(min(hdr.nritems, 512)):
                if off + BTRFS_KEY_PTR_SIZE > len(data):
                    break
                child_logical = struct.unpack_from('<Q', data, off + 17)[0]
                child_phys = self.resolve(child_logical)
                if child_phys is not None:
                    self._traverse_chunk_node(fh, child_phys, nodesize,
                                              depth - 1, visited)
                off += BTRFS_KEY_PTR_SIZE

    def _parse_chunk_leaf(self, data: bytes, nritems: int,
                          nodesize: int) -> None:
        off = BTRFS_NODE_HEADER_SIZE
        for _ in range(min(nritems, 4096)):
            if off + BTRFS_ITEM_SIZE > len(data):
                break
            key = parse_key(data, off)
            data_off  = struct.unpack_from('<I', data, off + 17)[0]
            data_size = struct.unpack_from('<I', data, off + 21)[0]
            off += BTRFS_ITEM_SIZE

            if key.type != BTRFS_CHUNK_ITEM_KEY:
                continue

            item_start = nodesize - data_off - data_size
            if item_start < 0 or item_start + data_size > len(data):
                continue

            chunk = self._parse_chunk_item(data, item_start, key.offset)
            if chunk:
                self._add_chunk(chunk)

    # ------------------------------------------------------------------
    # Chunk item parsing
    # ------------------------------------------------------------------

    def _parse_chunk_item(self, data: bytes, offset: int,
                          logical_start: int) -> Optional[ChunkMapping]:
        """
        Parse a btrfs_chunk item.

        btrfs_chunk layout (80 bytes fixed + 32 bytes per stripe):
          [0:8]   length
          [8:16]  owner
          [16:24] stripe_len
          [24:32] type (block group flags)
          [32:36] io_align
          [36:40] io_width
          [40:44] sector_size
          [44:46] num_stripes
          [46:48] sub_stripes
          stripe[0]:
            [48:56]  devid
            [56:64]  offset  ← physical offset
            [64:80]  dev_uuid
        """
        if offset + BTRFS_CHUNK_ITEM_SIZE > len(data):
            return None

        length      = struct.unpack_from('<Q', data, offset)[0]
        chunk_type  = struct.unpack_from('<Q', data, offset + 24)[0]
        num_stripes = struct.unpack_from('<H', data, offset + 44)[0]

        if num_stripes == 0:
            return None

        stripe_off = offset + BTRFS_CHUNK_ITEM_SIZE
        if stripe_off + BTRFS_STRIPE_SIZE > len(data):
            return None

        phys_offset = struct.unpack_from('<Q', data, stripe_off + 8)[0]
        dev_uuid    = data[stripe_off + 16: stripe_off + 32]

        return ChunkMapping(
            logical_start=logical_start,
            length=length,
            physical_offset=phys_offset,
            device_uuid=dev_uuid,
            type=chunk_type,
            num_stripes=num_stripes,
        )

    # ------------------------------------------------------------------
    # Address resolution
    # ------------------------------------------------------------------

    def resolve(self, logical: int) -> Optional[int]:
        """
        Resolve a Btrfs logical address to a physical image offset.

        Returns None if no mapping covers the address.
        """
        for chunk in self._chunks:
            if chunk.logical_start <= logical < chunk.logical_start + chunk.length:
                return chunk.physical_offset + (logical - chunk.logical_start)
        return None

    def _add_chunk(self, chunk: ChunkMapping) -> None:
        """Insert a chunk mapping, keeping the list sorted."""
        # Avoid duplicates
        for existing in self._chunks:
            if existing.logical_start == chunk.logical_start:
                return
        self._chunks.append(chunk)
        self._chunks.sort(key=lambda c: c.logical_start)

    @property
    def chunk_count(self) -> int:
        return len(self._chunks)

    def dump(self) -> List[dict]:
        """Return all mappings as dicts (for debugging/reporting)."""
        return [
            {
                'logical_start': hex(c.logical_start),
                'length': hex(c.length),
                'physical_offset': hex(c.physical_offset),
                'type': hex(c.type),
            }
            for c in self._chunks
        ]
