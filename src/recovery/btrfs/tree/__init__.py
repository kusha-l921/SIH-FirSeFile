"""
tree/__init__.py
================
Btrfs B-tree traversal engine.

Implements actual tree walking (not flat scanning):
  root → internal nodes → child pointers → leaf nodes → items

Supports:
  - strict mode: reject any block with invalid checksum or header
  - salvage mode: continue past corrupt blocks, collect what's readable

All reads go through the ChunkMap for correct logical→physical resolution.
"""

import struct
from typing import List, Optional, Iterator, Tuple, BinaryIO, Set

from btrfs_structs import (
    BTRFS_NODE_HEADER_SIZE, BTRFS_ITEM_SIZE, BTRFS_KEY_PTR_SIZE,
    BtrfsKey, BtrfsNodeHeader,
    parse_node_header, parse_key,
)
from checksum import verify_btrfs_csum, compute_block_csum


# Maximum tree depth to prevent infinite loops on corrupt images
MAX_TREE_DEPTH = 16


class TreeItem:
    """A single item from a leaf node."""
    __slots__ = ('key', 'data', 'node_physical', 'node_generation')

    def __init__(self, key: BtrfsKey, data: bytes,
                 node_physical: int, node_generation: int):
        self.key = key
        self.data = data
        self.node_physical = node_physical
        self.node_generation = node_generation


class TreeBlock:
    """A parsed tree block (header + raw data)."""
    __slots__ = ('header', 'data', 'physical')

    def __init__(self, header: BtrfsNodeHeader, data: bytes, physical: int):
        self.header = header
        self.data = data
        self.physical = physical


class BtrfsTreeReader:
    """
    Reads and traverses a single Btrfs B-tree.

    Args:
        fh:         Open binary file handle (read-only).
        chunk_map:  ChunkMap instance for logical→physical resolution.
        nodesize:   Tree node size in bytes (from superblock).
        salvage:    If True, continue past corrupt blocks.
        fsid:       Expected filesystem UUID (for header validation).
    """

    def __init__(self, fh: BinaryIO, chunk_map, nodesize: int,
                 salvage: bool = False, fsid: Optional[bytes] = None):
        self._fh = fh
        self._chunk_map = chunk_map
        self._nodesize = nodesize
        self._salvage = salvage
        self._fsid = fsid
        # LRU-style block cache: physical_offset → TreeBlock
        self._cache: dict = {}
        self._cache_max = 128

    # ------------------------------------------------------------------
    # Public: iterate all items in a tree
    # ------------------------------------------------------------------

    def iter_tree(self, root_logical: int) -> Iterator[TreeItem]:
        """
        Walk the entire tree rooted at root_logical and yield every
        leaf item in key order.
        """
        yield from self._walk(root_logical, depth=0, visited=set())

    def iter_tree_physical(self, root_physical: int) -> Iterator[TreeItem]:
        """
        Walk a tree whose root is already at a known physical offset.
        Used for the chunk tree bootstrap.
        """
        yield from self._walk_physical(root_physical, depth=0, visited=set())

    # ------------------------------------------------------------------
    # Internal: recursive tree walk
    # ------------------------------------------------------------------

    def _walk(self, logical: int, depth: int, visited: Set[int]
              ) -> Iterator[TreeItem]:
        if depth > MAX_TREE_DEPTH:
            return
        physical = self._chunk_map.resolve(logical)
        if physical is None:
            return
        yield from self._walk_physical(physical, depth, visited)

    def _walk_physical(self, physical: int, depth: int, visited: Set[int]
                       ) -> Iterator[TreeItem]:
        if depth > MAX_TREE_DEPTH or physical in visited:
            return
        visited.add(physical)

        block = self._read_block(physical)
        if block is None:
            return

        hdr = block.header
        if hdr.level == 0:
            yield from self._iter_leaf(block)
        else:
            yield from self._iter_internal(block, depth, visited)

    def _iter_leaf(self, block: TreeBlock) -> Iterator[TreeItem]:
        """Yield all items from a leaf node."""
        hdr = block.header
        data = block.data
        nodesize = self._nodesize
        off = BTRFS_NODE_HEADER_SIZE

        for _ in range(min(hdr.nritems, 4096)):
            if off + BTRFS_ITEM_SIZE > len(data):
                break

            key       = parse_key(data, off)
            data_off  = struct.unpack_from('<I', data, off + 17)[0]
            data_size = struct.unpack_from('<I', data, off + 21)[0]
            off += BTRFS_ITEM_SIZE

            if data_size == 0:
                continue

            # Item data is stored from the end of the node backwards
            item_start = nodesize - data_off - data_size
            if item_start < BTRFS_NODE_HEADER_SIZE or item_start + data_size > nodesize:
                if not self._salvage:
                    break
                continue

            item_data = data[item_start: item_start + data_size]
            yield TreeItem(
                key=key,
                data=item_data,
                node_physical=block.physical,
                node_generation=hdr.generation,
            )

    def _iter_internal(self, block: TreeBlock, depth: int,
                       visited: Set[int]) -> Iterator[TreeItem]:
        """Follow child pointers in an internal node."""
        hdr = block.header
        data = block.data
        off = BTRFS_NODE_HEADER_SIZE

        for _ in range(min(hdr.nritems, 4096)):
            if off + BTRFS_KEY_PTR_SIZE > len(data):
                break
            child_logical = struct.unpack_from('<Q', data, off + 17)[0]
            off += BTRFS_KEY_PTR_SIZE
            yield from self._walk(child_logical, depth + 1, visited)

    # ------------------------------------------------------------------
    # Block reading and caching
    # ------------------------------------------------------------------

    def _read_block(self, physical: int) -> Optional[TreeBlock]:
        if physical in self._cache:
            return self._cache[physical]

        try:
            self._fh.seek(physical)
            data = self._fh.read(self._nodesize)
        except OSError:
            return None

        if len(data) < BTRFS_NODE_HEADER_SIZE:
            return None

        hdr = parse_node_header(data, physical)
        if hdr is None:
            return None

        # Validate nritems sanity
        if hdr.nritems > 4096:
            if not self._salvage:
                return None

        # Validate FSID if we know it
        if self._fsid and hdr.fsid != self._fsid:
            if not self._salvage:
                return None

        # Validate checksum
        zeroed = b'\x00' * 32 + data[32:]
        hdr.checksum_valid = verify_btrfs_csum(hdr.csum, zeroed)
        if not hdr.checksum_valid and not self._salvage:
            return None

        block = TreeBlock(header=hdr, data=data, physical=physical)

        # Simple bounded cache
        if len(self._cache) >= self._cache_max:
            # Evict oldest entry
            oldest = next(iter(self._cache))
            del self._cache[oldest]
        self._cache[physical] = block
        return block

    def clear_cache(self) -> None:
        self._cache.clear()
