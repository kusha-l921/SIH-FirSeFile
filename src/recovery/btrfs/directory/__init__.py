"""
directory/__init__.py
=====================
Btrfs directory item and inode reference parsing.

Implements filename and path recovery from:
  - BTRFS_INODE_REF_KEY    (inode → name in parent dir)
  - BTRFS_INODE_EXTREF_KEY (extended inode ref, for hardlinks)
  - BTRFS_DIR_ITEM_KEY     (directory entry by name hash)
  - BTRFS_DIR_INDEX_KEY    (directory entry by index)

Path reconstruction:
  inode → inode_ref → parent_inode → inode_ref → ... → root
"""

import struct
from typing import Optional, List, Dict, Tuple

from btrfs_structs import (
    BtrfsInodeRef, BtrfsDirItem,
    BTRFS_INODE_REF_BASE, BTRFS_DIR_ITEM_FIXED,
    BTRFS_FT_REG_FILE, BTRFS_FT_DIR, BTRFS_FT_SYMLINK,
    BTRFS_FS_TREE_OBJECTID,
)


def parse_inode_ref(data: bytes, inode_number: int,
                    parent_inode: int) -> List[BtrfsInodeRef]:
    """
    Parse a BTRFS_INODE_REF_KEY item.

    An inode_ref item can contain multiple entries (for hardlinks).
    Each entry:
      [0:8]  index (u64) — directory index
      [8:10] name_len (u16)
      [10:10+name_len] name bytes
    """
    refs = []
    pos = 0
    while pos + BTRFS_INODE_REF_BASE <= len(data):
        index    = struct.unpack_from('<Q', data, pos)[0]
        name_len = struct.unpack_from('<H', data, pos + 8)[0]
        pos += BTRFS_INODE_REF_BASE

        if name_len == 0 or pos + name_len > len(data):
            break

        name = data[pos: pos + name_len].decode('utf-8', errors='replace')
        pos += name_len

        refs.append(BtrfsInodeRef(
            inode_number=inode_number,
            parent_inode=parent_inode,
            index=index,
            name=name,
        ))
    return refs


def parse_inode_extref(data: bytes, inode_number: int) -> List[BtrfsInodeRef]:
    """
    Parse a BTRFS_INODE_EXTREF_KEY item (extended inode reference).

    Used when an inode has more than one hardlink and the normal inode_ref
    space is exhausted.

    Each entry:
      [0:8]  parent_objectid (u64)
      [8:16] index (u64)
      [16:18] name_len (u16)
      [18:18+name_len] name bytes
    """
    refs = []
    pos = 0
    while pos + 18 <= len(data):
        parent_oid = struct.unpack_from('<Q', data, pos)[0]
        index      = struct.unpack_from('<Q', data, pos + 8)[0]
        name_len   = struct.unpack_from('<H', data, pos + 16)[0]
        pos += 18

        if name_len == 0 or pos + name_len > len(data):
            break

        name = data[pos: pos + name_len].decode('utf-8', errors='replace')
        pos += name_len

        refs.append(BtrfsInodeRef(
            inode_number=inode_number,
            parent_inode=parent_oid,
            index=index,
            name=name,
        ))
    return refs


def parse_dir_item(data: bytes, parent_inode: int) -> List[BtrfsDirItem]:
    """
    Parse a BTRFS_DIR_ITEM_KEY or BTRFS_DIR_INDEX_KEY item.

    Each dir_item entry:
      [0:17]  location key (child objectid, type, offset)
      [17:25] transid (u64)
      [25:27] data_len (u16)
      [27:29] name_len (u16)
      [29]    type (BTRFS_FT_*)
      [30:30+name_len] name bytes
      [30+name_len : 30+name_len+data_len] xattr data (ignored here)
    """
    items = []
    pos = 0
    while pos + BTRFS_DIR_ITEM_FIXED <= len(data):
        child_oid  = struct.unpack_from('<Q', data, pos)[0]
        # child key type at pos+8, child key offset at pos+9
        transid    = struct.unpack_from('<Q', data, pos + 17)[0]
        data_len   = struct.unpack_from('<H', data, pos + 25)[0]
        name_len   = struct.unpack_from('<H', data, pos + 27)[0]
        item_type  = data[pos + 29] if pos + 29 < len(data) else 0
        pos += BTRFS_DIR_ITEM_FIXED

        if name_len == 0 or pos + name_len > len(data):
            break

        name = data[pos: pos + name_len].decode('utf-8', errors='replace')
        pos += name_len + data_len

        items.append(BtrfsDirItem(
            parent_inode=parent_inode,
            name=name,
            child_objectid=child_oid,
            child_type=item_type,
            transid=transid,
        ))
    return items


class PathResolver:
    """
    Reconstructs full paths from inode references.

    Build the resolver by feeding it all inode_refs and dir_items
    collected during tree traversal, then call resolve(inode_number).
    """

    def __init__(self):
        # inode_number → list of BtrfsInodeRef
        self._refs: Dict[int, List[BtrfsInodeRef]] = {}
        # inode_number → name (from dir_items, keyed by child objectid)
        self._dir_names: Dict[int, str] = {}

    def add_inode_ref(self, ref: BtrfsInodeRef) -> None:
        self._refs.setdefault(ref.inode_number, []).append(ref)

    def add_dir_item(self, item: BtrfsDirItem) -> None:
        if item.child_objectid not in self._dir_names:
            self._dir_names[item.child_objectid] = item.name

    def get_filename(self, inode_number: int) -> Optional[str]:
        """Return the first known filename for this inode."""
        refs = self._refs.get(inode_number)
        if refs:
            return refs[0].name
        return self._dir_names.get(inode_number)

    def get_parent(self, inode_number: int) -> Optional[int]:
        """Return the parent inode number, if known."""
        refs = self._refs.get(inode_number)
        if refs:
            return refs[0].parent_inode
        return None

    def resolve_path(self, inode_number: int,
                     max_depth: int = 32) -> Optional[str]:
        """
        Walk up the inode_ref chain to reconstruct the full path.

        Returns None if the path cannot be determined.
        Returns '/<name>' if only one level is known.
        """
        parts = []
        current = inode_number
        visited = set()

        for _ in range(max_depth):
            if current in visited:
                break
            visited.add(current)

            # Root of FS tree (objectid 5 or 256) — stop here
            if current <= BTRFS_FS_TREE_OBJECTID:
                break

            name = self.get_filename(current)
            if name is None:
                break
            parts.append(name)

            parent = self.get_parent(current)
            if parent is None or parent == current:
                break
            current = parent

        if not parts:
            return None

        parts.reverse()
        return '/' + '/'.join(parts)
