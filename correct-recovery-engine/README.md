# XFS Recovery Engine

A read-only, forensic XFS recovery engine written in Rust for identifying deleted-file candidates and reconstructing surviving file data from XFS filesystem structures.

The engine is designed as a modular forensic component that can be integrated with acquisition, machine-learning, validation, chain-of-custody, and GUI components.

---

## Features

- Read-only XFS filesystem analysis
- XFS v4 and v5 superblock parsing
- Allocation Group traversal
- AGF / AGI / AGFL parsing
- Allocation B+tree traversal
- Free-space and inode-allocation map construction
- Inode addressing and discovery
- XFS dinode parsing
- Data and attribute fork handling
- BMBT and extent extraction
- Sparse-file and unwritten-extent handling
- Deleted/unlinked inode candidate identification
- Residual extent-based experimental recovery
- Streaming recovered-content reads
- SHA-256 hashing of evidence images and recovered content
- Forensic evidence, confidence, issue, and rejection tracking
- Stable public `RecoveryEngine` integration API
- Strict and salvage traversal modes
- Zero external Rust dependencies
- `#![deny(unsafe_code)]`
- `#![deny(warnings)]`

---

## Architecture

The recovery engine follows a filesystem-aware recovery pipeline:

```text
Raw XFS Disk Image
        │
        ▼
Read-Only ImageRead
        │
        ▼
XFS Superblock
        │
        ▼
Allocation Groups
   ┌────┼────┐
   ▼    ▼    ▼
 AGF  AGI  AGFL
        │
        ▼
 Allocation B+Trees
        │
        ▼
 Inode Allocation Maps
        │
        ▼
 Inode Location
        │
        ▼
 Dinode Parsing
        │
        ▼
 Data / Attribute Forks
        │
        ▼
 BMBT / Extent Extraction
        │
        ▼
 Deleted-File Candidate Classification
        │
        ▼
 RecoveryCandidate
        │
        ├──────────────► ExtentReader
        │                    │
        │                    ▼
        │              Recovered Content
        │
        └──────────────► SHA-256 / Forensic Handoff
