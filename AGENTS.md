# AGENTS.md

## Status

- Library-first Rust crate (`xfs-recovery-engine`): `src/lib.rs` re-exports `error::{Error, Result}`; `src/main.rs` is a deliberately thin stub (prints name + version; real CLI arrives with the public API milestone).
- Implementation follows a 12-milestone plan. **M0–M7 are complete** (scaffolding; image I/O; primitives; superblock; AG headers in `src/xfs/ag.rs`; generic alloc-class B+tree walker in `src/xfs/btree.rs`; record decoders + FreeExtentMap/InodeAllocationMap in `src/xfs/alloc_records.rs`; inode addressing + chunk discovery in `src/xfs/inode_addr.rs`/`inode_scan.rs`); next milestone is **M8**: dinode core parser v1/v2/v3 (`src/xfs/dinode.rs`). Do not jump ahead or implement fork/extent parsing early.
- Inode addressing (kernel-verified): `ag = ino >> (agblklog+inopblog)`; AG numbering uses agblklog BITS, so with non-pow2 `sb_agblocks` addressable-but-unallocated gaps exist between AGs (locate must reject those); slot = intra-block offset / `sb_inodesize`; inobt `ir_startino` is AG-RELATIVE — absolute ino = `(ag << shift) + ir_startino`; NULLAGINO=0xFFFFFFFF sentinel for AGI buckets. Experimental raw-scan (`experimental_raw_scan`) is opt-in-only, chunk-aligned, magic-probed, and never feeds authoritative discovery.
- Inobt record facts (kernel-verified): 16B records; legacy = startino(u32)|freecount(u32)|free-mask(u64), sparse-era (feature-gated) = startino|holecnt... precisely `holemask(u16)|count(u8)|freecount(u8)|free-mask`; each holemask bit covers a 4-inode region (`XFS_INODES_PER_HOLEMASK_BIT=4`, 16 bits/chunk); computed freecount = popcount(free_mask & allocmask(holemask)); kernel checks: chunk aligned to 64, fully inside AG, `4 <= ir_count <= 64`, `freecount<=64`, computed==declared. FINOBT mirrors INOBT only for chunks with free>0.
- B+tree facts (verified vs kernel + real fixture): short-form header = magic@0, level@4(be16), numrecs@6(be16), leftsib/rightsib@8/12; v5 adds blkno(**be64 daddr**)@16, lsn@24, uuid@32, owner@48, crc(le)@52 → hdr 16B v4 / 56B v5; CRC covers whole fsblock with field zeroed. v5 trees use CRC magic variants (`AB3B`/`AB3C`/`IAB3`/`FIB3`). Internal-node ptr array starts after a FULL maxrecs-sized key region (`hdr + maxrecs*keysize`), not after numrecs keys. **AGF/AGI `level` fields are tree HEIGHTS (≥1); root block `bb_level` = height−1.** xfs_db 6.x: no `ag` command; use absolute `fsblock = ag*agblocks + agbno`.
- AG header layout verified vs kernel: per-AG sector order is **SB=0, AGF=1, AGI=2, AGFL=3** (× `sb_sectsize` within the AG); AGF CRC@216, AGI CRC@312, AGFL v5 header is 36 bytes (magic/seqno/uuid/lsn/crc) with entries after it; AGFL capacity = `(sectsize−36)/4` v5, `sectsize/4` v4; NULLAGINO = 0xFFFFFFFF; AGFL entry order wraps `flfirst..flfirst+flcount` modulo capacity. All v5 header CRCs cover the whole sector with the CRC field zeroed (same scheme as SB).
- Superblock layout was verified against kernel `xfs_format.h`/`xfs_sb.c`: four v5 feature masks at offsets 208–220 (`features_compat/ro_compat/incompat/log_incompat`, NOT a `features_lo/hi` pair), CRC at offset 224 stored **little-endian** as `~crc`, computed over the **whole sector (`sb_sectsize` bytes)** with the CRC field folded in as four zero bytes — not just `[0,224)`. Keep future parsing (AG headers, btrees) aligned with those sources.
- Stock XFS always reserves `rbmino=129`/`rsumino=130`/`rextsize=1` even with no realtime device; realtime presence is `sb_rblocks != 0`. Differential test vs `xfs_db`: `XRE_TEST_IMAGE=<img> cargo test --test xfs_db_diff -- --ignored`; fixture recipe: 512 MiB sparse file + `mkfs.xfs -f -L m3diff <img>` (mkfs refuses <300 MiB).
- CRC failure and unknown feature bits are soft issues (`sb.crc_status`, `sb.issues`), not parse errors — forensic images are damaged by definition. Hard rejects: magic/geometry/log-consistency violations, bad version, mkfs-in-progress.
- I/O layer contract (`src/io.rs`): `ImageRead::read_at(offset, buf)` fills the buffer completely or errors (`Error::OutOfBounds` / `Error::Io`); base FS offset is deliberately NOT part of this layer — callers pass it to `Superblock::parse(reader, fs_base_offset)`.
- Scope: XFS structural recovery only. Output must never depend on GUI, ML, blockchain, or Btrfs code — guaranteed structurally by keeping `[dependencies]` empty.

## Hard constraints

- **Zero external dependencies**, permanently: CRC32C, big-endian readers, and error handling are hand-rolled (`src/util/` lands with the primitives milestone).
- `[lints.rust]` denies `unsafe_code` and `warnings`; keep all code warning-free.
- Forensic read-only discipline: images may only ever be opened read-only (enforced by construction in the I/O layer); never add write paths.

## Toolchain

- Edition 2024 requires Rust ≥ 1.85 (`rustup update stable` if edition parsing fails).

## Git

- Repo has zero commits; default branch is `master` (not `main`). Initial commit pending user approval.

## Verification

- Every milestone must keep green: `cargo build && cargo test && cargo fmt --check && cargo clippy`.
- Single-area tests: use name filters (e.g. `cargo test dinode`) once modules land.
- Fixture-heavy integration tests (fixture tooling milestone) run under `cargo test -- --ignored`; they require `xfsprogs` (`mkfs.xfs`, `xfs_db`) installed locally.
