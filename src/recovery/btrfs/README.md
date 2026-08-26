# Btrfs Recovery Engine

Standalone, read-only Btrfs forensic recovery module.
No XFS, no frontend, no API, no ML dependencies.

## Files

```
btrfs_recovery/
  btrfs_structs.py   – on-disk data structures and parsing helpers
  btrfs_engine.py    – recovery engine (structural + carving paths)
  tests/
    test_helpers.py        – synthetic image builders (no mkfs.btrfs needed)
    test_btrfs_engine.py   – 11 test cases
```

## Usage

```python
from btrfs_engine import BtrfsEngine

with BtrfsEngine('/path/to/image.img') as eng:
    if not eng.is_btrfs():
        raise ValueError('Not a Btrfs image')

    sb     = eng.parse_superblock()
    snaps  = eng.list_snapshots()

    # Structural recovery path
    for inode in eng.scan_inodes():
        meta = eng.inode_metadata(inode)
        if inode.is_deleted:
            print('DELETED', meta)

    # Carving fallback path
    for cf in eng.carve_free_space(file_types=['jpg', 'pdf', 'png']):
        print('CARVED', cf.filename, cf.offset, cf.confidence)

    print(eng.get_summary())
```

## Running tests

```
cd btrfs_recovery
python -m pytest tests/ -v
# or
python -m unittest discover tests -v
```

---

## Source provenance

### Functionality taken from Repo 1 (Yukeshwara)

| Function / Class | Source file |
|---|---|
| `BtrfsSuperblock` dataclass | `backend/recovery/btrfs_recovery.py` |
| `BtrfsInode` dataclass | `backend/recovery/btrfs_recovery.py` |
| `BtrfsSnapshot` dataclass | `backend/recovery/btrfs_recovery.py` |
| `parse_superblock()` – field offsets, magic check | `backend/recovery/btrfs_recovery.py` |
| `list_snapshots()` – root tree scan for ROOT_ITEM_KEY | `backend/recovery/btrfs_recovery.py` |
| `scan_inodes()` – node-level loop with scan limit | `backend/recovery/btrfs_recovery.py` |
| `_parse_leaf_node()` – item descriptor loop | `backend/recovery/btrfs_recovery.py` |
| `_parse_inode_item()` – 160-byte inode struct | `backend/recovery/btrfs_recovery.py` |
| `verify_checksum()` – CRC32C via binascii | `backend/recovery/btrfs_recovery.py` |
| `compare_snapshots()` – inode set diff | `backend/recovery/btrfs_recovery.py` |
| `carve_free_space()` – signature scan + confidence | `backend/recovery/btrfs_recovery.py` |
| `get_recovery_summary()` | `backend/recovery/btrfs_recovery.py` |
| `extract_from_btrfs_inode()` → `inode_metadata()` | `backend/recovery/metadata_extractor.py` |
| `_mode_to_string()` → `mode_to_str()` | `backend/recovery/metadata_extractor.py` |
| `_detect_file_type()` → `detect_file_type()` | `backend/recovery/metadata_extractor.py` |
| `ConfidenceScorer.calculate()` → `_confidence()` | `backend/recovery/confidence_scorer.py` |
| `BtrfsImageGenerator` (test image creation concept) | `datasets/scripts/create_btrfs_image.py` |

### Functionality taken from Repo 2 (3vc22cs090)

| Function / Class | Source file |
|---|---|
| `attempt_btrfs_restore()` → `btrfs_restore_hint()` | `recovery_utils.py` |
| File-type signature table (doc/gif/mp3/mp4) | `main.py` – `ActualFileRecovery.file_signatures` |

### Merged / deduplicated

| Feature | Repo 1 | Repo 2 | Resolution |
|---|---|---|---|
| File-type signatures | jpg/png/pdf/zip/elf | jpg/png/pdf/doc/zip/gif/mp3/mp4 | Merged into `FILE_SIGNATURES`; Repo 1 elf added, Repo 2 gif/mp3/mp4/doc added |
| File carving logic | Full Btrfs-aware scan | Generic Windows temp-folder scan | Repo 1 retained; Repo 2 discarded (not Btrfs-specific) |
| Confidence scoring | Weighted multi-factor | None | Repo 1 retained |

### Functionality NOT implemented in either repository

The following Btrfs features are defined as key constants but never actually
parsed in either source repository.  They are listed here for completeness and
marked as future work for the Rust rewrite:

| Feature | Status |
|---|---|
| `BTRFS_INODE_REF_KEY` parsing → filename recovery | Not implemented |
| `BTRFS_DIR_ITEM_KEY` parsing → directory entry recovery | Not implemented |
| `BTRFS_EXTENT_DATA_KEY` parsing → file block mapping | Not implemented |
| `BTRFS_ROOT_REF_KEY` parsing → snapshot name recovery | Not implemented |
| Chunk tree traversal → logical-to-physical address mapping | Not implemented |
| Log tree traversal → journal-based recovery | Not implemented |
| Inline extent extraction | Not implemented |
| Compressed extent decompression (zlib/lzo/zstd) | Not implemented |
| Multi-device (RAID) image support | Not implemented |

---

## Forensic requirements

- The engine opens images with `open(..., 'rb')` — read-only.
- It never mounts, writes to, or repairs the evidence image.
- `btrfs_restore_hint()` generates a command string only; it never executes it.

---

## Rust rewrite notes

The module is structured so each method maps cleanly to a Rust function:

| Python | Rust equivalent (future) |
|---|---|
| `BtrfsEngine::parse_superblock` | `fn parse_superblock(r: &mut impl Read) -> Result<Superblock>` |
| `BtrfsEngine::scan_inodes` | `fn scan_inodes(r: &mut impl Read+Seek, sb: &Superblock) -> impl Iterator<Item=Inode>` |
| `BtrfsEngine::carve_free_space` | `fn carve(r: &mut impl Read, sigs: &[Signature]) -> impl Iterator<Item=CarvedFile>` |
| `BtrfsEngine::verify_checksum` | `fn verify_crc32c(data: &[u8], stored: &[u8; 32]) -> bool` |
| `mode_to_str` | `fn mode_to_str(mode: u32) -> String` |
