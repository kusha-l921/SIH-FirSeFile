"""
btrfs_structs.py
================
Pure data structures for Btrfs on-disk layout.

Sources:
  - Repo 1 (Yukeshwara): BtrfsInode, BtrfsSuperblock, BtrfsSnapshot dataclasses
  - Btrfs kernel documentation for field offsets

No XFS, no frontend, no API dependencies.
"""

import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Any


# ---------------------------------------------------------------------------
# On-disk constants
# ---------------------------------------------------------------------------

BTRFS_MAGIC = b'_BHRfS_M'
BTRFS_SUPER_OFFSET = 65536          # Primary superblock at 64 KiB
BTRFS_SUPER_MIRROR_OFFSETS = [      # Mirror copies
    256 * 1024 * 1024,              # 256 MiB
    68 * 1024 * 1024 * 1024,        # 68 GiB
]

# Btrfs item key types (from kernel btrfs_tree.h)
BTRFS_INODE_ITEM_KEY   = 1
BTRFS_INODE_REF_KEY    = 12
BTRFS_DIR_ITEM_KEY     = 84
BTRFS_EXTENT_DATA_KEY  = 108
BTRFS_ROOT_ITEM_KEY    = 132
BTRFS_ROOT_REF_KEY     = 156

# Btrfs tree node header size (csum[32] + fsid[16] + bytenr[8] + flags[8] +
#   chunk_tree_uuid[16] + generation[8] + owner[8] + nritems[4] + level[1] = 101)
BTRFS_NODE_HEADER_SIZE = 101

# Btrfs leaf item descriptor size (key[17] + offset[4] + size[4] = 25)
BTRFS_ITEM_SIZE = 25

# Btrfs inode item on-disk size
BTRFS_INODE_ITEM_SIZE = 160

# File type bits in mode
S_IFMT  = 0o170000
S_IFREG = 0o100000
S_IFDIR = 0o040000
S_IFLNK = 0o120000


# ---------------------------------------------------------------------------
# Data structures (source: Repo 1 Yukeshwara, cleaned and isolated)
# ---------------------------------------------------------------------------

@dataclass
class BtrfsSuperblock:
    """
    Btrfs superblock fields parsed from the 4096-byte block at offset 64 KiB.
    Field offsets follow the on-disk layout documented in btrfs-progs.

    Source: Repo 1 (Yukeshwara) – BtrfsSuperblock dataclass, parse_superblock()
    """
    csum: bytes          # [0:32]   CRC32C of the rest of the superblock
    fsid: bytes          # [32:48]  Filesystem UUID
    bytenr: int          # [48:56]  Physical address of this superblock copy
    flags: int           # [56:64]
    magic: bytes         # [64:72]  Must equal BTRFS_MAGIC
    generation: int      # [72:80]  Transaction generation
    root: int            # [80:88]  Logical address of the root tree root
    chunk_root: int      # [88:96]  Logical address of the chunk tree root
    log_root: int        # [96:104] Logical address of the log tree root
    total_bytes: int     # [104:112]
    bytes_used: int      # [112:120]
    num_devices: int     # [128:136]
    sectorsize: int      # [136:140]
    nodesize: int        # [140:144] Tree node / leaf size (usually 16 KiB)
    leafsize: int        # [144:148] (deprecated alias of nodesize)
    stripesize: int      # [148:152]
    label: str           # [299:555] Volume label, null-terminated UTF-8


@dataclass
class BtrfsInode:
    """
    Btrfs inode item (BTRFS_INODE_ITEM_KEY) parsed from a leaf node.

    Source: Repo 1 (Yukeshwara) – BtrfsInode dataclass, _parse_inode_item()
    Btrfs inode item on-disk layout (160 bytes):
      [0:8]    generation
      [8:16]   transid
      [16:24]  size
      [24:32]  nbytes (allocated bytes)
      [32:40]  block_group
      [40:44]  nblocks
      [44:48]  nlink
      [48:52]  uid
      [52:56]  gid
      [56:60]  mode
      [60:64]  rdev
      [64:72]  atime (seconds)
      [72:80]  atime (nanoseconds)
      [80:88]  ctime (seconds)
      [88:96]  ctime (nanoseconds)
      [96:104] mtime (seconds)
      [104:112] mtime (nanoseconds)
      [112:120] otime/crtime (seconds)
      [120:128] otime/crtime (nanoseconds)
    """
    inode_number: int
    generation: int
    size: int
    nbytes: int          # Allocated bytes on disk
    nlink: int           # Hard link count; 0 = deleted
    uid: int
    gid: int
    mode: int
    atime: datetime      # Last access
    ctime: datetime      # Last metadata change
    mtime: datetime      # Last data modification
    otime: datetime      # Creation time (Btrfs-specific, not in POSIX)
    extents: List[Dict] = field(default_factory=list)
    is_deleted: bool = False
    is_directory: bool = False
    filename: Optional[str] = None
    recovered_data: Optional[bytes] = None
    checksum: Optional[str] = None       # SHA-256 of recovered_data
    checksum_valid: Optional[bool] = None
    snapshot_id: Optional[int] = None
    confidence: float = 0.0


@dataclass
class BtrfsSnapshot:
    """
    A Btrfs subvolume or snapshot entry found in the root tree.

    Source: Repo 1 (Yukeshwara) – BtrfsSnapshot dataclass, list_snapshots()
    """
    id: int              # Subvolume object ID (>= 256 for user subvolumes)
    parent_id: int
    root_offset: int     # Logical address of this subvolume's root node
    generation: int
    name: str
    path: str
    created: Optional[datetime] = None


@dataclass
class BtrfsExtent:
    """
    A file extent descriptor (BTRFS_EXTENT_DATA_KEY).
    Newly defined here to support future extent parsing.
    Marked as NEW – not present in either source repository.
    """
    logical_offset: int   # Offset within the file
    disk_bytenr: int      # Physical byte address on disk (0 = inline/hole)
    disk_num_bytes: int   # Length on disk
    num_bytes: int        # Logical length
    compression: int      # 0=none, 1=zlib, 2=lzo, 3=zstd
    encryption: int
    type: int             # 0=inline, 1=regular, 2=prealloc


@dataclass
class CarvedFile:
    """
    A file recovered by signature carving from unallocated space.

    Source: Repo 1 (Yukeshwara) – carve_free_space() return dict, cleaned.
    """
    offset: int           # Byte offset in the image where the header was found
    file_type: str        # e.g. 'jpg', 'pdf'
    filename: str         # Generated name: carved_<offset_hex>.<ext>
    size: int
    confidence: float
    confidence_notes: List[str]
    data: bytes           # Raw recovered bytes
    crc32c: int           # CRC32C of data
    sha256: str           # SHA-256 hex of data
    footer_found: bool


# ---------------------------------------------------------------------------
# Common Contract Types for Recovery Pipeline Integration
# ---------------------------------------------------------------------------

@dataclass
class RecoveredMetadataModel:
    filename: Optional[str]
    file_size: int
    created: Optional[str]
    modified: Optional[str]
    accessed: Optional[str]
    changed: Optional[str]
    deleted_if_available: bool
    permissions: str
    ownership: Dict[str, int]
    filesystem: str
    source_locations: List[int]
    additional_attributes: Dict[str, Any]


@dataclass
class RecoveredFileModel:
    file_id: str
    filename: Optional[str]
    file_type: Optional[str]
    file_size: int
    ordered_fragments: List[Dict[str, Any]]
    metadata: RecoveredMetadataModel
    source_locations: List[int]
    recovery_method: str
    confidence: float
    sha256: Optional[str]


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _ts(seconds: int) -> datetime:
    """Convert a Unix timestamp to datetime, returning datetime.min on 0."""
    if seconds <= 0:
        return datetime.min
    try:
        return datetime.fromtimestamp(seconds)
    except (OSError, OverflowError, ValueError):
        return datetime.min


def mode_to_str(mode: int) -> str:
    """
    Convert a POSIX mode integer to a 10-character permission string.
    Source: Repo 1 (Yukeshwara) – MetadataExtractor._mode_to_string(), isolated here.
    """
    file_type = (mode >> 12) & 0xF
    type_char = {0x1: 'p', 0x2: 'c', 0x4: 'd',
                 0x6: 'b', 0x8: '-', 0xA: 'l', 0xC: 's'}.get(file_type, '?')
    perms = ''
    for shift in (6, 3, 0):
        bits = (mode >> shift) & 0x7
        perms += ('r' if bits & 4 else '-')
        perms += ('w' if bits & 2 else '-')
        perms += ('x' if bits & 1 else '-')
    return type_char + perms


def detect_file_type(data: bytes) -> Optional[str]:
    """
    Identify file type from magic bytes.
    Source: Repo 1 (Yukeshwara) – MetadataExtractor._detect_file_type(), isolated here.
    """
    if not data or len(data) < 4:
        return None
    MAGIC = [
        (b'\xFF\xD8\xFF',          'jpeg'),
        (b'\x89PNG\r\n\x1a\n',    'png'),
        (b'GIF8',                  'gif'),
        (b'%PDF-',                 'pdf'),
        (b'PK\x03\x04',           'zip'),
        (b'\x7fELF',              'elf'),
        (b'MZ',                    'exe'),
        (b'ID3',                   'mp3'),
        (b'\x00\x00\x00\x18ftyp', 'mp4'),
        (b'\xd0\xcf\x11\xe0',     'doc'),
        (b'SQLite format 3\x00',   'sqlite'),
    ]
    for sig, ftype in MAGIC:
        if data[:len(sig)] == sig:
            return ftype
    try:
        sample = data[:512].decode('utf-8')
        if '\n' in sample or sample.isprintable():
            return 'text'
    except (UnicodeDecodeError, ValueError):
        pass
    return 'binary'
