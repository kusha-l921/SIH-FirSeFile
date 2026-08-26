# AGENTS.md

## Status

- Library-first Rust crate (`xfs-recovery-engine`): `src/lib.rs` re-exports `error::{Error, Result}`; `src/main.rs` is a deliberately thin stub (prints name + version; real CLI arrives with the public API milestone).
- Implementation follows a 12-milestone plan. **M0–M3 are complete** (scaffolding; read-only image I/O; hand-rolled primitives `src/util/be.rs` + `src/util/crc32c.rs`; XFS superblock parser `src/xfs/superblock.rs`); next milestone is **M4**: AG header parsers (AGF/AGFL/AGI) in `src/xfs/ag.rs`. Do not jump ahead or implement inode parsing early.
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
