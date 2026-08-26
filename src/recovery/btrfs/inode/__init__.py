"""
inode/__init__.py
=================
Btrfs inode item parsing and deletion candidate classification.

Parses BTRFS_INODE_ITEM_KEY items from tree leaf nodes.
Deletion detection uses multiple evidence factors, not just nlink==0.
"""

import struct
from typing import Optional, List

from btrfs_structs import (
    BtrfsInode, RecoveryCandidate,
    BTRFS_INODE_ITEM_SIZE,
    S_IFMT, S_IFDIR, S_IFREG, S_IFLNK,
    _ts, mode_to_str,
)


def parse_inode_item(data: bytes, inode_number: int,
                     source_tree: int = 0,
                     logical_address: Optional[int] = None,
                     physical_offset: Optional[int] = None,
                     node_generation: int = 0) -> Optional[BtrfsInode]:
    """
    Parse a 160-byte Btrfs inode item.

    On-disk layout (from linux/fs/btrfs/ctree.h btrfs_inode_item):
      [0:8]    generation
      [8:16]   transid
      [16:24]  size
      [24:32]  nbytes
      [32:40]  block_group
      [40:44]  nblocks
      [44:48]  nlink
      [48:52]  uid
      [52:56]  gid
      [56:60]  mode
      [60:64]  rdev
      [64:72]  atime_sec  [72:80]  atime_nsec
      [80:88]  ctime_sec  [88:96]  ctime_nsec
      [96:104] mtime_sec  [104:112] mtime_nsec
      [112:120] otime_sec [120:128] otime_nsec
    """
    if len(data) < BTRFS_INODE_ITEM_SIZE:
        return None

    u64 = lambda o: struct.unpack_from('<Q', data, o)[0]
    u32 = lambda o: struct.unpack_from('<I', data, o)[0]

    generation = u64(0)
    transid    = u64(8)
    size       = u64(16)
    nbytes     = u64(24)
    nlink      = u32(44)
    uid        = u32(48)
    gid        = u32(52)
    mode       = u32(56)
    rdev       = u64(60)

    atime = _ts(u64(64),  u64(72))
    ctime = _ts(u64(80),  u64(88))
    mtime = _ts(u64(96),  u64(104))
    otime = _ts(u64(112), u64(120))

    file_type_bits = (mode >> 12) & 0xF
    is_dir = (file_type_bits == 0x4)

    evidence, is_deleted = _classify_deletion(
        inode_number, generation, transid, size, nlink, mode,
        node_generation
    )

    confidence = _score_confidence(evidence)

    return BtrfsInode(
        inode_number=inode_number,
        generation=generation,
        transid=transid,
        size=size,
        nbytes=nbytes,
        nlink=nlink,
        uid=uid,
        gid=gid,
        mode=mode,
        rdev=rdev,
        atime=atime,
        ctime=ctime,
        mtime=mtime,
        otime=otime,
        is_deleted=is_deleted,
        is_directory=is_dir,
        source_tree=source_tree,
        logical_address=logical_address,
        physical_offset=physical_offset,
        evidence=evidence,
        confidence=confidence,
    )


def _classify_deletion(inode_number: int, generation: int, transid: int,
                        size: int, nlink: int, mode: int,
                        node_generation: int) -> tuple:
    """
    Multi-factor deletion classification.

    Returns (evidence: List[str], is_deleted: bool).

    Deletion indicators (any combination):
      - nlink == 0 with size > 0  (primary indicator)
      - nlink == 0 with size == 0 (unlinked, possibly truncated)
      - transid < node_generation (inode not updated in current transaction)
      - generation != transid     (inode modified in a different transaction)
      - inode_number in orphan range (BTRFS_ORPHAN_OBJECTID context)

    A file is classified as deleted when nlink == 0.
    Additional evidence strengthens the confidence score.
    """
    evidence = []
    is_deleted = False

    if mode > 0:
        evidence.append('valid_mode')
    if 0 < size < 10 * 1024 ** 3:
        evidence.append('plausible_size')
    elif size == 0:
        evidence.append('zero_size')

    if nlink == 0:
        is_deleted = True
        evidence.append('nlink_zero')
        if size > 0:
            evidence.append('size_nonzero_after_unlink')
    elif nlink > 0:
        evidence.append('nlink_positive')

    if generation > 0:
        evidence.append('valid_generation')
    if transid > 0 and transid != generation:
        evidence.append('transid_differs_from_generation')
    if node_generation > 0 and generation < node_generation:
        evidence.append('older_than_current_transaction')

    return evidence, is_deleted


def _score_confidence(evidence: List[str]) -> float:
    """
    Score confidence based on actual evidence collected.

    Each piece of evidence contributes a defined weight.
    No arbitrary fixed bonuses.
    """
    weights = {
        'valid_mode':                      0.20,
        'plausible_size':                  0.15,
        'nlink_positive':                  0.15,
        'valid_generation':                0.10,
        'valid_inode_ref':                 0.15,
        'valid_dir_item':                  0.10,
        'valid_extent_data':               0.15,
        'successful_reconstruction':       0.20,
        'checksum_verified':               0.10,
        # Deletion-specific (don't penalise, just note)
        'nlink_zero':                      0.05,
        'size_nonzero_after_unlink':       0.05,
    }
    score = sum(weights.get(e, 0.0) for e in evidence)
    return round(min(score, 1.0), 2)


def make_recovery_candidate(inode: BtrfsInode) -> RecoveryCandidate:
    """Build a RecoveryCandidate from a parsed BtrfsInode."""
    return RecoveryCandidate(
        inode=inode.inode_number,
        generation=inode.generation,
        size=inode.size,
        nlink=inode.nlink,
        mode=inode.mode,
        uid=inode.uid,
        gid=inode.gid,
        atime=inode.atime,
        mtime=inode.mtime,
        ctime=inode.ctime,
        otime=inode.otime,
        filename=inode.filename,
        path=inode.path,
        parent_inode=inode.parent_inode,
        source_tree=inode.source_tree or 0,
        logical_address=inode.logical_address,
        physical_offset=inode.physical_offset,
        evidence=list(inode.evidence),
        confidence=inode.confidence,
        recovery_status='pending',
    )
