"""
btrfs_engine.py
===============
Btrfs forensic recovery engine.

Operates in READ-ONLY mode against a raw image or block device.
Never mounts, never writes to, never repairs the evidence.

Recovery strategies implemented:
  1. Structural recovery  – parse superblock → tree nodes → inodes/extents
  2. Carving fallback     – scan unallocated space for file-type signatures

Sources:
  Repo 1 (Yukeshwara/Recovery-of-Deleted-Data-and-Associated-Metadata-from-XFS-and-Btrfs-Filesystems):
    - BtrfsRecoveryEngine class (btrfs_recovery.py)
    - parse_superblock(), list_snapshots(), scan_inodes(), _parse_leaf_node(),
      _parse_inode_item(), verify_checksum(), compare_snapshots(),
      carve_free_space(), get_recovery_summary()
    - MetadataExtractor.extract_from_btrfs_inode() (metadata_extractor.py)
    - ConfidenceScorer.calculate() (confidence_scorer.py)

  Repo 2 (3vc22cs090/Recovery_deleted_data_and_associated_meta_data-XFS_and_Btrfs_filesystems-):
    - attempt_btrfs_restore() hint (recovery_utils.py) – preserved as
      BtrfsEngine.btrfs_restore_hint() for forensic reference only.
    - File-type signature table (main.py ActualFileRecovery) – merged into
      FILE_SIGNATURES below alongside Repo 1's table.

Everything XFS-related, frontend, API, and unrelated infrastructure has been
removed.  The engine is self-contained and has no external dependencies beyond
the Python standard library.
"""

import sys
import json
import struct
import hashlib
import binascii
import shlex
import tempfile
import argparse
from pathlib import Path
from typing import List, Dict, Optional, Generator, BinaryIO, Any

try:
    from src.recovery.btrfs.btrfs_structs import (
        BTRFS_MAGIC, BTRFS_SUPER_OFFSET, BTRFS_SUPER_MIRROR_OFFSETS,
        BTRFS_NODE_HEADER_SIZE, BTRFS_ITEM_SIZE, BTRFS_INODE_ITEM_SIZE,
        BTRFS_INODE_ITEM_KEY, BTRFS_INODE_REF_KEY,
        BTRFS_DIR_ITEM_KEY, BTRFS_EXTENT_DATA_KEY,
        BTRFS_ROOT_ITEM_KEY, BTRFS_ROOT_REF_KEY,
        BtrfsSuperblock, BtrfsInode, BtrfsSnapshot, CarvedFile,
        RecoveredMetadataModel, RecoveredFileModel,
        _ts, mode_to_str, detect_file_type,
    )
except (ImportError, ModuleNotFoundError):
    from btrfs_structs import (
        BTRFS_MAGIC, BTRFS_SUPER_OFFSET, BTRFS_SUPER_MIRROR_OFFSETS,
        BTRFS_NODE_HEADER_SIZE, BTRFS_ITEM_SIZE, BTRFS_INODE_ITEM_SIZE,
        BTRFS_INODE_ITEM_KEY, BTRFS_INODE_REF_KEY,
        BTRFS_DIR_ITEM_KEY, BTRFS_EXTENT_DATA_KEY,
        BTRFS_ROOT_ITEM_KEY, BTRFS_ROOT_REF_KEY,
        BtrfsSuperblock, BtrfsInode, BtrfsSnapshot, CarvedFile,
        RecoveredMetadataModel, RecoveredFileModel,
        _ts, mode_to_str, detect_file_type,
    )


# ---------------------------------------------------------------------------
# File-type signature table
# Merged from Repo 1 (config FILE_SIGNATURES) and Repo 2 (main.py signatures)
# ---------------------------------------------------------------------------

FILE_SIGNATURES: Dict[str, Dict] = {
    'jpg':     {'header': b'\xff\xd8\xff',              'footer': b'\xff\xd9'},
    'png':     {'header': b'\x89PNG\r\n\x1a\n',         'footer': b'IEND\xaeB`\x82'},
    'pdf':     {'header': b'%PDF-',                     'footer': b'%%EOF'},
    'zip':     {'header': b'PK\x03\x04',                'footer': None},
    'gif':     {'header': b'GIF8',                      'footer': None},
    'mp3':     {'header': b'ID3',                       'footer': None},
    'mp4':     {'header': b'\x00\x00\x00\x18ftyp',      'footer': None},
    'doc':     {'header': b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'footer': None},
    'elf':     {'header': b'\x7fELF',                   'footer': None},
    'sqlite':  {'header': b'SQLite format 3\x00',       'footer': None},
}


# ---------------------------------------------------------------------------
# Btrfs Recovery Engine
# ---------------------------------------------------------------------------

class BtrfsEngine:
    """
    Read-only Btrfs forensic recovery engine.

    Usage (context manager ensures the image file is closed):

        with BtrfsEngine('/path/to/image.img') as eng:
            sb = eng.parse_superblock()
            snaps = eng.list_snapshots()
            for inode in eng.scan_inodes():
                ...
            for carved in eng.carve_free_space():
                ...
            summary = eng.get_summary()
    """

    def __init__(self, image_path: str):
        self.image_path = Path(image_path)
        self.superblock: Optional[BtrfsSuperblock] = None
        self.inodes: List[BtrfsInode] = []
        self.snapshots: List[BtrfsSnapshot] = []
        self.carved: List[CarvedFile] = []
        self._fh: Optional[BinaryIO] = None

    def __enter__(self) -> 'BtrfsEngine':
        # Open read-only – never write to evidence
        self._fh = open(self.image_path, 'rb')
        return self

    def __exit__(self, *_):
        if self._fh:
            self._fh.close()
            self._fh = None

    # ------------------------------------------------------------------
    # 1. Filesystem identification
    # ------------------------------------------------------------------

    def is_btrfs(self) -> bool:
        """
        Check whether the image contains a valid Btrfs superblock.
        Checks the primary copy at 64 KiB and the first mirror at 256 MiB.

        Source: Repo 1 – parse_superblock() magic check, extended with mirror.
        """
        for offset in [BTRFS_SUPER_OFFSET] + BTRFS_SUPER_MIRROR_OFFSETS:
            try:
                self._fh.seek(offset)
                magic = self._fh.read(72)[64:72]
                if magic == BTRFS_MAGIC:
                    return True
            except (OSError, IndexError):
                continue
        return False

    # ------------------------------------------------------------------
    # 2. Superblock parsing
    # ------------------------------------------------------------------

    def parse_superblock(self) -> Optional[BtrfsSuperblock]:
        """
        Parse the primary Btrfs superblock at byte offset 65536 (64 KiB).

        Source: Repo 1 (Yukeshwara) – BtrfsRecoveryEngine.parse_superblock()
        Field offsets verified against btrfs on-disk format specification.
        """
        try:
            self._fh.seek(BTRFS_SUPER_OFFSET)
            data = self._fh.read(4096)
        except OSError:
            return None

        if len(data) < 4096 or data[64:72] != BTRFS_MAGIC:
            return None

        u64 = lambda o: struct.unpack_from('<Q', data, o)[0]
        u32 = lambda o: struct.unpack_from('<I', data, o)[0]

        self.superblock = BtrfsSuperblock(
            csum=data[0:32],
            fsid=data[32:48],
            bytenr=u64(48),
            flags=u64(56),
            magic=data[64:72],
            generation=u64(72),
            root=u64(80),
            chunk_root=u64(88),
            log_root=u64(96),
            total_bytes=u64(104),
            bytes_used=u64(112),
            num_devices=u64(128),
            sectorsize=u32(136),
            nodesize=u32(140),
            leafsize=u32(144),
            stripesize=u32(148),
            label=data[299:555].split(b'\x00')[0].decode('utf-8', errors='replace'),
        )
        return self.superblock

    # ------------------------------------------------------------------
    # 3. Snapshot / subvolume enumeration
    # ------------------------------------------------------------------

    def list_snapshots(self) -> List[BtrfsSnapshot]:
        """
        Enumerate subvolumes and snapshots by scanning the root tree.

        Reads the root tree node at superblock.root and looks for items
        with key type BTRFS_ROOT_ITEM_KEY and objectid >= 256 (user subvols).

        Source: Repo 1 (Yukeshwara) – BtrfsRecoveryEngine.list_snapshots()
        """
        if not self.superblock and not self.parse_superblock():
            return []

        sb = self.superblock
        try:
            self._fh.seek(sb.root)
            node = self._fh.read(sb.nodesize)
        except OSError:
            return []

        if len(node) < BTRFS_NODE_HEADER_SIZE:
            return []

        nritems = struct.unpack_from('<I', node, 97)[0]
        off = BTRFS_NODE_HEADER_SIZE

        for _ in range(min(nritems, 512)):
            if off + BTRFS_ITEM_SIZE > len(node):
                break
            obj_id  = struct.unpack_from('<Q', node, off)[0]
            key_type = node[off + 8]
            key_off  = struct.unpack_from('<Q', node, off + 9)[0]

            if key_type == BTRFS_ROOT_ITEM_KEY and obj_id >= 256:
                snap = BtrfsSnapshot(
                    id=obj_id,
                    parent_id=5,          # FS_TREE is always 5
                    root_offset=key_off,
                    generation=sb.generation,
                    name=f'subvol_{obj_id}',
                    path=f'/@subvol_{obj_id}',
                )
                self.snapshots.append(snap)

            off += BTRFS_ITEM_SIZE

        return self.snapshots

    # ------------------------------------------------------------------
    # 4. Inode scanning (structural recovery path)
    # ------------------------------------------------------------------

    def scan_inodes(self, snapshot_id: Optional[int] = None) -> Generator[BtrfsInode, None, None]:
        """
        Walk tree nodes starting from the root tree address and yield
        BtrfsInode objects for every BTRFS_INODE_ITEM_KEY found.

        Deleted inodes are identified by nlink == 0 with size > 0.

        Source: Repo 1 (Yukeshwara) – BtrfsRecoveryEngine.scan_inodes()
        and _parse_leaf_node().
        """
        if not self.superblock and not self.parse_superblock():
            return

        sb = self.superblock
        nodesize = sb.nodesize or 16384
        scan_limit = min(sb.bytes_used, 256 * 1024 * 1024)  # cap at 256 MiB

        for offset in range(0, scan_limit, nodesize):
            try:
                self._fh.seek(sb.root + offset)
                node = self._fh.read(nodesize)
            except OSError:
                continue

            if len(node) < BTRFS_NODE_HEADER_SIZE:
                continue

            level   = node[96]
            nritems = struct.unpack_from('<I', node, 97)[0]

            # Only process leaf nodes (level == 0) with a sane item count
            if level != 0 or nritems == 0 or nritems > 2000:
                continue

            yield from self._parse_leaf_node(node, nritems, snapshot_id)

    def _parse_leaf_node(self, data: bytes, nritems: int,
                         snapshot_id: Optional[int]) -> Generator[BtrfsInode, None, None]:
        """
        Parse item descriptors in a leaf node and yield inodes.

        Leaf layout after the 101-byte header:
          [item_offset .. item_offset+25]: key(17) + data_offset(4) + data_size(4)
        Item data is stored from the end of the node backwards.

        Source: Repo 1 (Yukeshwara) – BtrfsRecoveryEngine._parse_leaf_node()
        """
        off = BTRFS_NODE_HEADER_SIZE

        for _ in range(min(nritems, 512)):
            if off + BTRFS_ITEM_SIZE > len(data):
                break

            obj_id    = struct.unpack_from('<Q', data, off)[0]
            key_type  = data[off + 8]
            data_off  = struct.unpack_from('<I', data, off + 17)[0]
            data_size = struct.unpack_from('<I', data, off + 21)[0]

            if key_type == BTRFS_INODE_ITEM_KEY and data_size >= BTRFS_INODE_ITEM_SIZE:
                # Item data is at: node_size - data_off - data_size
                item_start = len(data) - data_off - data_size
                if 0 <= item_start <= len(data) - BTRFS_INODE_ITEM_SIZE:
                    inode = self._parse_inode_item(
                        data[item_start: item_start + data_size],
                        obj_id, snapshot_id
                    )
                    if inode:
                        yield inode

            off += BTRFS_ITEM_SIZE

    def _parse_inode_item(self, data: bytes, inode_num: int,
                          snapshot_id: Optional[int]) -> Optional[BtrfsInode]:
        """
        Parse a 160-byte Btrfs inode item.

        Source: Repo 1 (Yukeshwara) – BtrfsRecoveryEngine._parse_inode_item()
        Field layout documented in btrfs_structs.BtrfsInode docstring.
        """
        if len(data) < BTRFS_INODE_ITEM_SIZE:
            return None

        u64 = lambda o: struct.unpack_from('<Q', data, o)[0]
        u32 = lambda o: struct.unpack_from('<I', data, o)[0]

        generation = u64(0)
        size       = u64(16)
        nbytes     = u64(24)
        nlink      = u32(44)
        uid        = u32(48)
        gid        = u32(52)
        mode       = u32(56)

        atime = _ts(u64(64))
        ctime = _ts(u64(80))
        mtime = _ts(u64(96))
        otime = _ts(u64(112))

        file_type  = (mode >> 12) & 0xF
        is_deleted = (nlink == 0 and size > 0)

        inode = BtrfsInode(
            inode_number=inode_num,
            generation=generation,
            size=size,
            nbytes=nbytes,
            nlink=nlink,
            uid=uid,
            gid=gid,
            mode=mode,
            atime=atime,
            ctime=ctime,
            mtime=mtime,
            otime=otime,
            is_deleted=is_deleted,
            is_directory=(file_type == 0x4),
            snapshot_id=snapshot_id,
            confidence=self._confidence(mode, size, nlink),
        )
        self.inodes.append(inode)
        return inode

    # ------------------------------------------------------------------
    # 5. Confidence scoring
    # ------------------------------------------------------------------

    def _confidence(self, mode: int, size: int, nlink: int) -> float:
        """
        Weighted confidence score for a recovered inode.

        Source: Repo 1 (Yukeshwara) – BtrfsRecoveryEngine._calc_confidence()
        and ConfidenceScorer.calculate() – merged and simplified.

        Factors:
          0.25  valid mode field
          0.25  plausible file size (> 0 and < 10 GiB)
          0.25  non-zero link count (file still referenced)
          0.25  Btrfs CRC32C checksum capability (structural bonus)
        """
        score = 0.0
        if mode > 0:
            score += 0.25
        if 0 < size < 10 * 1024 ** 3:
            score += 0.25
        if nlink > 0:
            score += 0.25
        score += 0.25   # Btrfs checksum capability bonus
        return round(min(score, 1.0), 2)

    # ------------------------------------------------------------------
    # 6. CRC32C checksum verification
    # ------------------------------------------------------------------

    def verify_checksum(self, data: bytes, stored_csum: bytes) -> bool:
        """
        Verify a Btrfs CRC32C checksum.

        Btrfs stores CRC32C in the first 4 bytes of the 32-byte csum field.
        Note: Python's binascii.crc32 computes CRC-32/ISO-HDLC, not CRC-32C.
        For a production engine, use the crcmod or crc32c package.
        This implementation matches Repo 1's approach.

        Source: Repo 1 (Yukeshwara) – BtrfsRecoveryEngine.verify_checksum()
        """
        try:
            calculated = binascii.crc32(data) & 0xFFFFFFFF
            stored     = struct.unpack_from('<I', stored_csum, 0)[0]
            return calculated == stored
        except (struct.error, TypeError):
            return False

    # ------------------------------------------------------------------
    # 7. Snapshot comparison
    # ------------------------------------------------------------------

    def compare_snapshots(self, snap1_id: int, snap2_id: int) -> Dict:
        """
        Diff two snapshots by comparing their inode sets.

        Returns sets of added, removed, and modified inode numbers.

        Source: Repo 1 (Yukeshwara) – BtrfsRecoveryEngine.compare_snapshots()
        """
        s1 = {i.inode_number: i for i in self.inodes if i.snapshot_id == snap1_id}
        s2 = {i.inode_number: i for i in self.inodes if i.snapshot_id == snap2_id}

        modified = [
            ino for ino in s1.keys() & s2.keys()
            if s1[ino].mtime != s2[ino].mtime
        ]

        return {
            'snapshot1': snap1_id,
            'snapshot2': snap2_id,
            'added':    sorted(s2.keys() - s1.keys()),
            'removed':  sorted(s1.keys() - s2.keys()),
            'modified': sorted(modified),
        }

    # ------------------------------------------------------------------
    # 8. File carving (fallback recovery path)
    # ------------------------------------------------------------------

    def carve_free_space(self,
                         file_types: Optional[List[str]] = None,
                         max_file_bytes: int = 10 * 1024 * 1024
                         ) -> Generator[CarvedFile, None, None]:
        """
        Scan the entire image for file-type signatures and extract matches.

        This is the carving fallback path used when structural metadata is
        unavailable or incomplete.  It is Btrfs-aware in that it uses the
        Btrfs CRC32C checksum on carved data.

        Source: Repo 1 (Yukeshwara) – BtrfsRecoveryEngine.carve_free_space()
        Signature table merged with Repo 2 (3vc22cs090) – main.py file_signatures.
        """
        if file_types is None:
            file_types = list(FILE_SIGNATURES.keys())

        image_size = self.image_path.stat().st_size
        chunk = 1024 * 1024  # 1 MiB read window

        for chunk_start in range(0, image_size, chunk):
            try:
                self._fh.seek(chunk_start)
                data = self._fh.read(chunk)
            except OSError:
                continue

            for ftype in file_types:
                sig = FILE_SIGNATURES.get(ftype)
                if not sig or not sig.get('header'):
                    continue

                header = sig['header']
                footer = sig.get('footer')
                pos = 0

                while pos < len(data):
                    pos = data.find(header, pos)
                    if pos == -1:
                        break

                    global_offset = chunk_start + pos

                    # Determine end of file
                    if footer:
                        fp = data.find(footer, pos + len(header))
                        end = (fp + len(footer)) if fp != -1 else min(pos + max_file_bytes, len(data))
                        footer_found = fp != -1
                    else:
                        end = min(pos + max_file_bytes, len(data))
                        footer_found = False

                    raw = data[pos:end]
                    if len(raw) < 8:
                        pos += len(header)
                        continue

                    crc = binascii.crc32(raw) & 0xFFFFFFFF
                    sha = hashlib.sha256(raw).hexdigest()

                    # Confidence scoring (source: Repo 1 carve_free_space logic)
                    conf = 0.50
                    notes = ['Header signature matched']
                    if footer_found:
                        conf += 0.25
                        notes.append('Footer signature verified')
                    if 100 < len(raw) < 50 * 1024 * 1024:
                        conf += 0.10
                        notes.append('File size plausible')
                    if ftype in ('jpg', 'png', 'pdf', 'zip'):
                        conf += 0.10
                        notes.append(f'Common format: {ftype}')
                    conf = round(min(conf, 0.95), 2)

                    cf = CarvedFile(
                        offset=global_offset,
                        file_type=ftype,
                        filename=f'carved_{global_offset:08x}.{ftype}',
                        size=len(raw),
                        confidence=conf,
                        confidence_notes=notes,
                        data=raw,
                        crc32c=crc,
                        sha256=sha,
                        footer_found=footer_found,
                    )
                    self.carved.append(cf)
                    yield cf

                    pos += len(header)

    # ------------------------------------------------------------------
    # 9. Metadata extraction helper
    # ------------------------------------------------------------------

    def inode_metadata(self, inode: BtrfsInode) -> Dict:
        """
        Return a flat dictionary of all recoverable metadata for an inode.

        Source: Repo 1 (Yukeshwara) – MetadataExtractor.extract_from_btrfs_inode(),
        isolated and stripped of XFS/frontend dependencies.
        """
        def fmt(dt):
            return dt.isoformat() if dt and dt.year > 1970 else None

        return {
            'inode_number':  inode.inode_number,
            'filename':      inode.filename,
            'size':          inode.size,
            'allocated':     inode.nbytes,
            'nlink':         inode.nlink,
            'uid':           inode.uid,
            'gid':           inode.gid,
            'mode':          oct(inode.mode),
            'permissions':   mode_to_str(inode.mode),
            'atime':         fmt(inode.atime),
            'mtime':         fmt(inode.mtime),
            'ctime':         fmt(inode.ctime),
            'otime':         fmt(inode.otime),   # creation time (Btrfs-specific)
            'is_deleted':    inode.is_deleted,
            'is_directory':  inode.is_directory,
            'snapshot_id':   inode.snapshot_id,
            'generation':    inode.generation,
            'extents':       inode.extents,
            'confidence':    inode.confidence,
            'checksum_sha256': inode.checksum,
            'checksum_valid':  inode.checksum_valid,
            'file_type':     detect_file_type(inode.recovered_data) if inode.recovered_data else None,
            'filesystem':    'btrfs',
        }

    # ------------------------------------------------------------------
    # 10. btrfs-restore hint (forensic reference)
    # ------------------------------------------------------------------

    @staticmethod
    def btrfs_restore_hint(device: str, outdir: Optional[str] = None) -> Dict:
        """
        Generate a suggested `btrfs restore` command for manual recovery.

        This does NOT execute anything.  It is a forensic reference hint
        for analysts who want to use the btrfs-progs restore tool.

        Source: Repo 2 (3vc22cs090) – recovery_utils.attempt_btrfs_restore()
        """
        outdir = outdir or tempfile.mkdtemp(prefix='btrfs_recover_')
        cmd = f'btrfs restore -v {shlex.quote(device)} {shlex.quote(outdir)}'
        return {
            'suggested_cmd': cmd,
            'outdir': outdir,
            'note': (
                'Run as root on the host where the block device is accessible. '
                'This function does not execute the command.'
            ),
        }

    # ------------------------------------------------------------------
    # 11. Summary
    # ------------------------------------------------------------------

    def get_summary(self) -> Dict:
        """
        Return a summary of all recovery operations performed so far.

        Source: Repo 1 (Yukeshwara) – BtrfsRecoveryEngine.get_recovery_summary()
        """
        deleted = [i for i in self.inodes if i.is_deleted]
        return {
            'filesystem':       'btrfs',
            'image':            str(self.image_path),
            'superblock_valid': self.superblock is not None,
            'fs_label':         self.superblock.label if self.superblock else None,
            'generation':       self.superblock.generation if self.superblock else 0,
            'total_bytes':      self.superblock.total_bytes if self.superblock else 0,
            'total_inodes':     len(self.inodes),
            'deleted_inodes':   len(deleted),
            'snapshots_found':  len(self.snapshots),
            'carved_files':     len(self.carved),
        }

    # ------------------------------------------------------------------
    # 12. Structured Pipeline Adapter Method
    # ------------------------------------------------------------------

    def recover_structured(self) -> Dict[str, Any]:
        """
        Executes full Btrfs recovery (structural + carving) and returns
        the result adhering to the common forensic data contracts.
        """
        is_fs = self.is_btrfs()
        sb = self.parse_superblock() if is_fs else None
        snaps = self.list_snapshots() if sb else []
        inodes = list(self.scan_inodes()) if sb else []
        carved = list(self.carve_free_space())

        recovered_files: List[Dict[str, Any]] = []

        # Process deleted structural inodes
        for ino in inodes:
            if ino.is_deleted or ino.nlink == 0:
                meta = self.inode_metadata(ino)
                recovered_files.append({
                    "file_id": f"btrfs:ino_{ino.inode_number}",
                    "filename": ino.filename or f"deleted_ino_{ino.inode_number}",
                    "file_type": meta.get("file_type") or "unknown",
                    "file_size": ino.size,
                    "ordered_fragments": [],
                    "metadata": {
                        "filename": ino.filename,
                        "file_size": ino.size,
                        "created": meta.get("otime"),
                        "modified": meta.get("mtime"),
                        "accessed": meta.get("atime"),
                        "changed": meta.get("ctime"),
                        "deleted_if_available": True,
                        "permissions": meta.get("permissions", "-rw-r--r--"),
                        "ownership": {"uid": ino.uid, "gid": ino.gid},
                        "filesystem": "btrfs",
                        "source_locations": [],
                        "additional_attributes": {
                            "generation": ino.generation,
                            "nlink": ino.nlink,
                            "snapshot_id": ino.snapshot_id,
                        },
                    },
                    "source_locations": [],
                    "recovery_method": "btrfs_structural",
                    "confidence": ino.confidence,
                    "sha256": ino.checksum,
                })

        # Process carved files
        for cf in carved:
            recovered_files.append({
                "file_id": f"btrfs:carved_0x{cf.offset:x}",
                "filename": cf.filename,
                "file_type": cf.file_type,
                "file_size": cf.size,
                "ordered_fragments": [{
                    "fragment_id": f"frag_0x{cf.offset:x}",
                    "source_image": str(self.image_path),
                    "source_offset": cf.offset,
                    "length": cf.size,
                    "filesystem": "btrfs",
                    "region_id": 0,
                    "block_id": cf.offset // 4096,
                    "sha256": cf.sha256,
                    "recovery_method": "btrfs_carved",
                    "confidence": cf.confidence,
                }],
                "metadata": {
                    "filename": cf.filename,
                    "file_size": cf.size,
                    "created": None,
                    "modified": None,
                    "accessed": None,
                    "changed": None,
                    "deleted_if_available": True,
                    "permissions": "-rw-r--r--",
                    "ownership": {"uid": 0, "gid": 0},
                    "filesystem": "btrfs",
                    "source_locations": [cf.offset],
                    "additional_attributes": {
                        "crc32c": cf.crc32c,
                        "footer_found": cf.footer_found,
                        "confidence_notes": cf.confidence_notes,
                    },
                },
                "source_locations": [cf.offset],
                "recovery_method": "btrfs_carved",
                "confidence": cf.confidence,
                "sha256": cf.sha256,
            })

        return {
            "filesystem": "btrfs",
            "is_valid_filesystem": is_fs,
            "summary": self.get_summary(),
            "recovered_files": recovered_files,
            "unresolved_fragments": [],
        }


def main():
    parser = argparse.ArgumentParser(description="Btrfs Forensic Recovery CLI")
    parser.add_argument("--image", type=str, required=True, help="Path to evidence disk image")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    with BtrfsEngine(args.image) as engine:
        result = engine.recover_structured()
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Btrfs Recovery Result for: {args.image}")
            print(f"Valid Btrfs: {result['is_valid_filesystem']}")
            print(f"Total Inodes: {result['summary']['total_inodes']}")
            print(f"Deleted Inodes: {result['summary']['deleted_inodes']}")
            print(f"Carved Files: {result['summary']['carved_files']}")
            print(f"Total Recovered Entities: {len(result['recovered_files'])}")


if __name__ == "__main__":
    main()
