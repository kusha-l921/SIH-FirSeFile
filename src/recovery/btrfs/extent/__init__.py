"""
extent/__init__.py
==================
Btrfs file extent parsing and file content reconstruction.

Parses BTRFS_EXTENT_DATA_KEY items and reconstructs file content by:
  1. Collecting all extent records for an inode
  2. Ordering by file logical offset
  3. Resolving physical locations via ChunkMap
  4. Reading blocks from the image
  5. Accounting for holes/sparse regions
  6. Truncating to the logical file size
"""

import hashlib
import struct
from typing import List, Optional, BinaryIO, Dict

from btrfs_structs import (
    BtrfsFileExtent, SourceExtent, RecoveredFile,
    BTRFS_FILE_EXTENT_INLINE, BTRFS_FILE_EXTENT_REG, BTRFS_FILE_EXTENT_PREALLOC,
    BTRFS_FILE_EXTENT_FIXED,
    mode_to_str, detect_file_type,
)


def parse_file_extent(data: bytes, inode_number: int,
                      file_offset: int,
                      node_generation: int = 0) -> Optional[BtrfsFileExtent]:
    """
    Parse a BTRFS_EXTENT_DATA_KEY item.

    Fixed header (21 bytes):
      [0:8]   generation (u64)
      [8:16]  ram_bytes (u64)
      [16]    compression (u8)
      [17]    encryption (u8)
      [18:20] other_encoding (u16)
      [20]    type (u8): 0=inline, 1=regular, 2=prealloc

    For type == INLINE (0):
      [21:] inline data bytes

    For type == REG (1) or PREALLOC (2):
      [21:29]  disk_bytenr (u64)  — logical address of extent (0=hole)
      [29:37]  disk_num_bytes (u64)
      [37:45]  offset (u64)       — offset within the disk extent
      [45:53]  num_bytes (u64)    — logical length of this file region
    """
    if len(data) < BTRFS_FILE_EXTENT_FIXED:
        return None

    generation  = struct.unpack_from('<Q', data, 0)[0]
    ram_bytes   = struct.unpack_from('<Q', data, 8)[0]
    compression = data[16]
    encryption  = data[17]
    extent_type = data[20]

    ext = BtrfsFileExtent(
        inode_number=inode_number,
        file_offset=file_offset,
        generation=generation,
        ram_bytes=ram_bytes,
        compression=compression,
        encryption=encryption,
        extent_type=extent_type,
    )

    if extent_type == BTRFS_FILE_EXTENT_INLINE:
        ext.inline_data = data[BTRFS_FILE_EXTENT_FIXED:]
        ext.num_bytes = len(ext.inline_data)

    elif extent_type in (BTRFS_FILE_EXTENT_REG, BTRFS_FILE_EXTENT_PREALLOC):
        if len(data) < 53:
            return None
        ext.disk_bytenr    = struct.unpack_from('<Q', data, 21)[0]
        ext.disk_num_bytes = struct.unpack_from('<Q', data, 29)[0]
        ext.extent_offset  = struct.unpack_from('<Q', data, 37)[0]
        ext.num_bytes      = struct.unpack_from('<Q', data, 45)[0]

    else:
        return None

    return ext


class FileReconstructor:
    """
    Reconstructs file content from a list of BtrfsFileExtent records.

    Usage:
        rec = FileReconstructor(fh, chunk_map)
        content, source_extents = rec.reconstruct(extents, file_size)
    """

    def __init__(self, fh: BinaryIO, chunk_map):
        self._fh = fh
        self._chunk_map = chunk_map

    def reconstruct(self, extents: List[BtrfsFileExtent],
                    file_size: int) -> tuple:
        """
        Reconstruct file content from extent records.

        Returns:
            (content: bytes, source_extents: List[SourceExtent])

        content is exactly file_size bytes (zero-padded for holes/missing).
        Returns (None, []) if no extents are available.
        """
        if not extents:
            return None, []

        # Sort by file logical offset
        sorted_extents = sorted(extents, key=lambda e: e.file_offset)

        buf = bytearray(file_size)
        source_extents = []
        any_data = False

        for ext in sorted_extents:
            if ext.file_offset >= file_size:
                continue

            region_len = min(ext.num_bytes, file_size - ext.file_offset)
            if region_len <= 0:
                continue

            if ext.extent_type == BTRFS_FILE_EXTENT_INLINE:
                inline = ext.inline_data or b''
                copy_len = min(len(inline), region_len)
                buf[ext.file_offset: ext.file_offset + copy_len] = inline[:copy_len]
                source_extents.append(SourceExtent(
                    file_offset=ext.file_offset,
                    length=copy_len,
                    physical_offset=ext.physical_offset or 0,
                    logical_address=0,
                    compression=ext.compression,
                    extent_type='inline',
                ))
                any_data = True

            elif ext.extent_type in (BTRFS_FILE_EXTENT_REG,
                                     BTRFS_FILE_EXTENT_PREALLOC):
                if ext.disk_bytenr == 0:
                    # Sparse hole — leave as zeros
                    source_extents.append(SourceExtent(
                        file_offset=ext.file_offset,
                        length=region_len,
                        physical_offset=0,
                        logical_address=0,
                        compression=0,
                        extent_type='hole',
                    ))
                    continue

                # Resolve logical → physical
                logical = ext.disk_bytenr + ext.extent_offset
                physical = self._chunk_map.resolve(logical)
                if physical is None:
                    continue

                ext.physical_offset = physical

                try:
                    self._fh.seek(physical)
                    raw = self._fh.read(region_len)
                except OSError:
                    continue

                if not raw:
                    continue

                copy_len = min(len(raw), region_len)
                buf[ext.file_offset: ext.file_offset + copy_len] = raw[:copy_len]
                source_extents.append(SourceExtent(
                    file_offset=ext.file_offset,
                    length=copy_len,
                    physical_offset=physical,
                    logical_address=ext.disk_bytenr,
                    compression=ext.compression,
                    extent_type='regular',
                ))
                any_data = True

        if not any_data:
            return None, source_extents

        return bytes(buf), source_extents

    def build_recovered_file(self, inode, extents: List[BtrfsFileExtent],
                              file_id: str,
                              recovery_method: str = 'structural') -> RecoveredFile:
        """
        Build a RecoveredFile from an inode and its extent records.
        """
        content, source_extents = self.reconstruct(extents, inode.size)

        sha256 = None
        if content is not None:
            sha256 = hashlib.sha256(content).hexdigest()

        source_offsets = [se.physical_offset for se in source_extents
                          if se.physical_offset > 0]

        # Add reconstruction evidence
        evidence = list(inode.evidence)
        if source_extents:
            evidence.append('valid_extent_data')
        if content is not None:
            evidence.append('successful_reconstruction')
        if sha256:
            evidence.append('sha256_computed')

        from inode import _score_confidence
        confidence = _score_confidence(evidence)

        return RecoveredFile(
            file_id=file_id,
            filename=inode.filename,
            path=inode.path,
            size=inode.size,
            inode=inode.inode_number,
            generation=inode.generation,
            extents=source_extents,
            source_offsets=source_offsets,
            filesystem='btrfs',
            atime=inode.atime,
            mtime=inode.mtime,
            ctime=inode.ctime,
            otime=inode.otime,
            uid=inode.uid,
            gid=inode.gid,
            mode=inode.mode,
            permissions=mode_to_str(inode.mode),
            file_type=detect_file_type(content) if content else None,
            recovery_method=recovery_method,
            sha256=sha256,
            content=content,
            confidence=confidence,
            evidence=evidence,
            source_tree=inode.source_tree or 0,
        )
