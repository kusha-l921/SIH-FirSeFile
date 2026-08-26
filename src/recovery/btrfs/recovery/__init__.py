"""
recovery/__init__.py
====================
Btrfs recovery orchestration.

Ties together:
  - Root tree traversal (discover all subvolume/snapshot roots)
  - Historical generation recovery (older tree roots)
  - Per-tree inode + dir + extent collection
  - File reconstruction
  - Deletion candidate identification
"""

import struct
from typing import List, Dict, Optional, Iterator, BinaryIO, Set

from btrfs_structs import (
    BtrfsInode, BtrfsInodeRef, BtrfsDirItem, BtrfsFileExtent,
    BtrfsSnapshot, RecoveryCandidate, RecoveredFile,
    BtrfsKey,
    BTRFS_INODE_ITEM_KEY, BTRFS_INODE_REF_KEY, BTRFS_INODE_EXTREF_KEY,
    BTRFS_DIR_ITEM_KEY, BTRFS_DIR_INDEX_KEY, BTRFS_EXTENT_DATA_KEY,
    BTRFS_ROOT_ITEM_KEY, BTRFS_ROOT_REF_KEY, BTRFS_ROOT_BACKREF_KEY,
    BTRFS_ORPHAN_ITEM_KEY,
    BTRFS_ROOT_TREE_OBJECTID, BTRFS_FS_TREE_OBJECTID,
    BTRFS_FIRST_FREE_OBJECTID,
    BTRFS_NODE_HEADER_SIZE,
    parse_node_header,
)
from inode import parse_inode_item, make_recovery_candidate, _score_confidence
from directory import (
    parse_inode_ref, parse_inode_extref, parse_dir_item, PathResolver
)
from extent import parse_file_extent, FileReconstructor
from tree import BtrfsTreeReader, TreeItem


# Root item on-disk size (fixed portion we need)
# btrfs_root_item: inode(160)+generation(8)+root_dirid(8)+bytenr(8)+
#   byte_limit(8)+bytes_used(8)+last_snapshot(8)+flags(8)+refs(4)+
#   drop_progress(17)+drop_level(1)+level(1) = 239 bytes minimum
BTRFS_ROOT_ITEM_MIN_SIZE = 239


def parse_root_item(data: bytes) -> Optional[dict]:
    """
    Parse a BTRFS_ROOT_ITEM_KEY item to extract the subvolume root bytenr
    and generation.

    btrfs_root_item layout (relevant fields):
      [0:160]   inode item (embedded)
      [160:168] generation
      [168:176] root_dirid
      [176:184] bytenr  ← logical address of this root's tree root node
      [184:192] byte_limit
      [192:200] bytes_used
      [200:208] last_snapshot
      [208:216] flags
      [216:220] refs
      [220:237] drop_progress (btrfs_key, 17 bytes)
      [237]     drop_level
      [238]     level
    """
    if len(data) < BTRFS_ROOT_ITEM_MIN_SIZE:
        return None
    u64 = lambda o: struct.unpack_from('<Q', data, o)[0]
    u32 = lambda o: struct.unpack_from('<I', data, o)[0]
    return {
        'generation':    u64(160),
        'root_dirid':    u64(168),
        'bytenr':        u64(176),
        'last_snapshot': u64(200),
        'flags':         u64(208),
        'refs':          u32(216),
        'level':         data[238] if len(data) > 238 else 0,
    }


class BtrfsRecoveryEngine:
    """
    High-level recovery orchestrator.

    Discovers all roots, traverses each tree, collects inodes/refs/extents,
    resolves filenames/paths, and reconstructs deleted files.
    """

    def __init__(self, fh: BinaryIO, chunk_map, superblock,
                 salvage: bool = False):
        self._fh = fh
        self._chunk_map = chunk_map
        self._sb = superblock
        self._salvage = salvage
        self._nodesize = superblock.nodesize or 16384
        self._fsid = superblock.fsid

        self._tree_reader = BtrfsTreeReader(
            fh, chunk_map, self._nodesize, salvage, self._fsid
        )
        self._reconstructor = FileReconstructor(fh, chunk_map)
        self._path_resolver = PathResolver()

        # Collected data
        self._inodes: Dict[str, BtrfsInode] = {}   # '<tree>:<ino>' → inode
        self._extents: Dict[str, List[BtrfsFileExtent]] = {}  # same key
        self._snapshots: List[BtrfsSnapshot] = []
        self._orphan_inodes: Set[int] = set()

    # ------------------------------------------------------------------
    # Root discovery
    # ------------------------------------------------------------------

    def discover_roots(self) -> List[BtrfsSnapshot]:
        """
        Traverse the root tree to discover all subvolumes and snapshots.

        Also records historical roots (last_snapshot pointer) for
        generation-based recovery.
        """
        root_logical = self._sb.root
        if root_logical == 0:
            return []

        for item in self._tree_reader.iter_tree(root_logical):
            if item.key.type == BTRFS_ROOT_ITEM_KEY:
                self._handle_root_item(item)
            elif item.key.type in (BTRFS_ROOT_REF_KEY, BTRFS_ROOT_BACKREF_KEY):
                self._handle_root_ref(item)

        return self._snapshots

    def _handle_root_item(self, item: TreeItem) -> None:
        obj_id = item.key.objectid
        ri = parse_root_item(item.data)
        if ri is None or ri['bytenr'] == 0:
            return

        snap = BtrfsSnapshot(
            id=obj_id,
            parent_id=BTRFS_FS_TREE_OBJECTID,
            root_offset=ri['bytenr'],
            generation=ri['generation'],
            name=f'tree_{obj_id}',
            path=f'/tree_{obj_id}',
        )
        self._snapshots.append(snap)

        # If last_snapshot != 0, there is a historical root we can also traverse
        if ri['last_snapshot'] != 0 and ri['last_snapshot'] != ri['bytenr']:
            hist_snap = BtrfsSnapshot(
                id=obj_id,
                parent_id=obj_id,
                root_offset=ri['last_snapshot'],
                generation=ri['generation'] - 1,
                name=f'tree_{obj_id}_historical',
                path=f'/tree_{obj_id}_historical',
            )
            self._snapshots.append(hist_snap)

    def _handle_root_ref(self, item: TreeItem) -> None:
        """Update snapshot name from ROOT_REF items."""
        if len(item.data) < 18:
            return
        name_len = struct.unpack_from('<H', item.data, 16)[0]
        if name_len > 0 and 18 + name_len <= len(item.data):
            name = item.data[18: 18 + name_len].decode('utf-8', errors='replace')
            # Find the matching snapshot and update its name
            for snap in self._snapshots:
                if snap.id == item.key.objectid:
                    snap.name = name
                    snap.path = f'/{name}'
                    break

    # ------------------------------------------------------------------
    # Tree scanning: collect inodes, refs, extents
    # ------------------------------------------------------------------

    def scan_tree(self, tree_logical: int, tree_id: int) -> None:
        """
        Scan a single FS tree, collecting all inodes, inode refs,
        dir items, and extent data items.
        """
        for item in self._tree_reader.iter_tree(tree_logical):
            key = item.key
            inode_key = f'{tree_id}:{key.objectid}'

            if key.type == BTRFS_INODE_ITEM_KEY:
                inode = parse_inode_item(
                    item.data,
                    inode_number=key.objectid,
                    source_tree=tree_id,
                    logical_address=key.objectid,
                    physical_offset=item.node_physical,
                    node_generation=item.node_generation,
                )
                if inode:
                    self._inodes[inode_key] = inode

            elif key.type == BTRFS_INODE_REF_KEY:
                refs = parse_inode_ref(item.data, key.objectid,
                                       parent_inode=key.offset)
                for ref in refs:
                    self._path_resolver.add_inode_ref(ref)
                    inode = self._inodes.get(inode_key)
                    if inode and inode.filename is None:
                        inode.filename = ref.name
                        inode.parent_inode = ref.parent_inode

            elif key.type == BTRFS_INODE_EXTREF_KEY:
                refs = parse_inode_extref(item.data, key.objectid)
                for ref in refs:
                    self._path_resolver.add_inode_ref(ref)
                    inode = self._inodes.get(inode_key)
                    if inode and inode.filename is None:
                        inode.filename = ref.name
                        inode.parent_inode = ref.parent_inode

            elif key.type in (BTRFS_DIR_ITEM_KEY, BTRFS_DIR_INDEX_KEY):
                dir_items = parse_dir_item(item.data, key.objectid)
                for di in dir_items:
                    self._path_resolver.add_dir_item(di)

            elif key.type == BTRFS_EXTENT_DATA_KEY:
                ext = parse_file_extent(
                    item.data,
                    inode_number=key.objectid,
                    file_offset=key.offset,
                    node_generation=item.node_generation,
                )
                if ext:
                    self._extents.setdefault(inode_key, []).append(ext)

            elif key.type == BTRFS_ORPHAN_ITEM_KEY:
                self._orphan_inodes.add(key.offset)

    def resolve_paths(self) -> None:
        """Resolve filenames and paths for all collected inodes."""
        for key, inode in self._inodes.items():
            if inode.filename is None:
                inode.filename = self._path_resolver.get_filename(
                    inode.inode_number)
            if inode.parent_inode is None:
                inode.parent_inode = self._path_resolver.get_parent(
                    inode.inode_number)
            path = self._path_resolver.resolve_path(inode.inode_number)
            if path:
                inode.path = path

            # Orphan list strengthens deletion evidence
            if inode.inode_number in self._orphan_inodes:
                if 'orphan_item_present' not in inode.evidence:
                    inode.evidence.append('orphan_item_present')
                    inode.is_deleted = True

            # Update confidence after path resolution
            if inode.filename:
                if 'valid_inode_ref' not in inode.evidence:
                    inode.evidence.append('valid_inode_ref')
            if inode.path:
                if 'valid_dir_item' not in inode.evidence:
                    inode.evidence.append('valid_dir_item')
            inode.confidence = _score_confidence(inode.evidence)

    # ------------------------------------------------------------------
    # Deleted file candidates
    # ------------------------------------------------------------------

    def find_deleted_candidates(self) -> List[RecoveryCandidate]:
        """
        Return RecoveryCandidate objects for all inodes classified as deleted.
        """
        candidates = []
        for inode in self._inodes.values():
            if inode.is_deleted and not inode.is_directory:
                candidates.append(make_recovery_candidate(inode))
        return candidates

    # ------------------------------------------------------------------
    # File reconstruction
    # ------------------------------------------------------------------

    def recover_file(self, inode_key: str) -> Optional[RecoveredFile]:
        """
        Attempt to reconstruct the file identified by inode_key.

        inode_key format: '<tree_id>:<inode_number>'
        """
        inode = self._inodes.get(inode_key)
        if inode is None:
            return None

        extents = self._extents.get(inode_key, [])
        method = 'historical' if 'historical' in inode_key else 'structural'

        return self._reconstructor.build_recovered_file(
            inode, extents, inode_key, method
        )

    def recover_all_deleted(self) -> List[RecoveredFile]:
        """Attempt reconstruction of every deleted file candidate."""
        results = []
        for key, inode in self._inodes.items():
            if inode.is_deleted and not inode.is_directory:
                rf = self.recover_file(key)
                if rf:
                    results.append(rf)
        return results

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def inodes(self) -> Dict[str, BtrfsInode]:
        return self._inodes

    @property
    def snapshots(self) -> List[BtrfsSnapshot]:
        return self._snapshots

    @property
    def path_resolver(self) -> PathResolver:
        return self._path_resolver
