# FirSeFile Execution & Operations Guide (Linux & Windows)

An end-to-end guide for setting up, running, testing, and operating the **FirSeFile Multi-Layer Digital Forensic Recovery System** across Windows and Linux environments.

---

## 1. System Architecture & Target Pipeline

FirSeFile integrates structural filesystem recovery with deep representation learning, graph-based sequence reassembly, format parsing, and tamper-proof blockchain custody logging:

```
[ Evidence Image (.img / .raw / .dd) ]
                 │
                 ├── 1. Filesystem Identification (XFS / Btrfs)
                 │      └── Structural inode/dinode parsing & extent extraction
                 │
                 ├── 2. Residual Fragment Carving & Extraction
                 │      └── 512-byte raw candidate fragments
                 │
                 ├── 3. Byte2Image 2D Transformation
                 │      └── 1-bit sliding window (497×128 native → 256×256 grayscale)
                 │
                 ├── 4. ML / Zero-Training Forensic Classification
                 │      └── Swin Transformer V2 Tiny / Hierarchical Structural Classifier
                 │          (Top-k predictions, confidence %, Shannon entropy)
                 │
                 ├── 5. Graph-Based Fragment Reassembly
                 │      └── Directed FragmentNodes + Multi-component Edge Scoring + Beam Search
                 │
                 ├── 6. Format-Aware Structural Validation
                 │      └── Deep binary validation: PDF (xref/EOF), PNG (IHDR/IEND),
                 │          JPG, ZIP (EOCD), SQLite (B-tree schema), ELF, Scripts
                 │
                 ├── 7. Cryptographic Blockchain Recovery Ledger
                 │      └── Ed25519 signatures + SHA-256 block hash chaining in JSONL
                 │
                 └── 8. Reconstructed Artifacts & GUI/CLI Presentation
                        └── Exported recovered files with SHA-256 cryptographic verification
```

---

## 2. Prerequisites

### Software Requirements
- **Python**: Version `3.10` or higher (Python 3.11 / 3.12 / 3.13 supported)
- **Node.js & npm**: Node.js `18.0+` (recommended `20+` or `22+`) for GUI frontend
- **Rust / Cargo** *(Optional)*: For compiling native Rust binaries and PyO3 extensions (pure-Python fallbacks are built-in).

---

## 3. Quick Start (One-Click Launchers)

FirSeFile provides automated launchers for both operating systems:

### On Windows
Double-click `start.bat` or run in PowerShell / Command Prompt:
```cmd
start.bat
```
*Or directly with Python:*
```powershell
python run.py
```

### On Linux / macOS
Grant executable permission and run `start.sh`:
```bash
chmod +x start.sh
./start.sh
```
*Or directly with Python:*
```bash
python3 run.py
```

---

## 4. Interactive Console Menu

Running `python run.py` (or `start.bat` / `./start.sh`) opens the interactive console dispatcher:

```text
========================================================================
  ______ _       _____       ______ _ _      
  |  ___(_)     /  ___|      |  ___(_) |     
  | |_   _ _ __ \ `--.  ___  | |_   _| | ___ 
  |  _| | | '__| `--. \/ _ \ |  _| | | |/ _ \
  | |   | | |   /\__/ /  __/ | |   | | |  __/
  \_|   |_|_|   \____/ \___| \_|   |_|_|\___|
  
  Automated Multi-Layer Digital Forensic Recovery System
========================================================================

  Select an action:
  ---------------------------------------------------------
  [1] Launch Interactive GUI Workbench (Browser / Localhost)
  [2] Run Forensic Recovery on XFS Evidence Image
  [3] Run Forensic Recovery on Btrfs Evidence Image
  [4] Run Single-Fragment ML Classifier on Sample Fragment
  [5] Run Complete Test Suite (51 Pytest + 8 Ledger tests)
  [6] Run Graph Reassembly & Format Validation Benchmark
  [7] Run Pipeline Smoke Audit (verify_smoke_pipeline.py)
  [8] Regenerate Synthetic Evidence Images
  [0] Exit
  ---------------------------------------------------------
```

---

## 5. Command-Line Interface (CLI) Guide

### A. End-to-End Forensic Recovery

Run complete recovery on an evidence disk image, validate recovered files, log cryptographic custody blocks, and export files to disk:

#### Windows (PowerShell):
```powershell
# Scan XFS evidence disk image and export files
python tools/run_recovery.py tests/fixtures/xfs_deleted_synthetic.img --output-dir recovered_xfs_output --ledger-chain xfs_chain.jsonl

# Scan Btrfs evidence disk image with JSON output
python tools/run_recovery.py tests/fixtures/btrfs_deleted_synthetic.img --json
```

#### Linux / macOS (Bash):
```bash
# Scan XFS evidence disk image
python3 tools/run_recovery.py tests/fixtures/xfs_deleted_synthetic.img --output-dir recovered_xfs_output --ledger-chain xfs_chain.jsonl

# Scan Btrfs evidence disk image with JSON output
python3 tools/run_recovery.py tests/fixtures/btrfs_deleted_synthetic.img --json
```

---

### B. Single-Fragment Forensic Classification CLI

Classify an isolated 512-byte raw fragment or binary file:

```powershell
# Visual ASCII report with probability distributions
python predict.py --fragment recovered_xfs_output/xfs_deleted_ino_256.pdf --engine zero_training

# Structured JSON output for downstream tooling
python predict.py --fragment recovered_xfs_output/xfs_deleted_ino_257.png --engine zero_training --json
```

---

### C. Blockchain Custody Ledger Verification

Verify that every block in the custody ledger is cryptographically sound and untampered:

```powershell
# Run the 8-test blockchain ledger integration suite
python blockchain_ledger/test_integration.py

# Verify a generated chain file from Python CLI
python -c "import blockchain_ledger; chain = blockchain_ledger.load_chain('xfs_chain.jsonl'); print(blockchain_ledger.verify_chain(chain, chain[0]['public_key_id']))"
```

---

## 6. Graphical User Interface (GUI) Workbench

FirSeFile includes a modern React + TypeScript + Tauri forensic workbench.

### Launching the GUI:
```powershell
# Via universal launcher:
python run.py --gui

# Or manually via npm:
cd Gui_CLI
npm install
npm run dev
```

### Accessing the Dashboard:
Open your browser at: **[http://127.0.0.1:1420/](http://127.0.0.1:1420/)**

### Dashboard Features:
1. **Case Setup**: Select evidence disk images (`.img`, `.raw`, `.dd`, `.bin`) and initiate automated recovery.
2. **Overview**: View all recovered files, file sizes, creation/modification timestamps, and confidence scores.
3. **ML Results**: Inspect ML classification outputs, top-k format distributions, confidence bars, and structural format validation results.
4. **Recovery Ledger**: View Ed25519-signed chain-of-custody blocks and click **Verify Chain** to validate SHA-256 hash chaining.

---

## 7. Running the Test Suite

FirSeFile includes 51 unit and integration tests covering every subsystem:

```powershell
# Run all 51 Python tests
python -m pytest

# Run with verbose output
python -m pytest -v

# Run with universal launcher
python run.py --test
```

### Test Suite Breakdown:
- `tests/test_byte2image.py`: 1-bit sliding window, 497×128 native array, 256×256 tensor adaptation.
- `tests/test_swin_v2.py`: Swin Transformer V2 Tiny forward pass, classification heads, feature channels.
- `tests/test_zero_training.py`: Zero-training hierarchical classifier, boundary frequency histogram, texture matching.
- `tests/test_reassembly.py`: Edge scoring, beam search ordering, byte reconstruction.
- `tests/test_validator.py`: Binary format parsing for PDF, PNG, JPG, ZIP, SQLITE, ELF, and Shell scripts.
- `tests/test_ml_integration.py`: 23 full-pipeline integration tests (Fragment $\to$ ML $\to$ Graph $\to$ Validator $\to$ Ledger $\to$ GUI).
- `tests/test_end_to_end_pipeline.py`: 3-level integration verification against synthetic XFS and Btrfs disk images.
- `blockchain_ledger/test_integration.py`: 8 cryptographic ledger tests (Ed25519, hashing, tamper detection, JSONL storage).

---

## 8. Benchmark & Evaluation Scripts

```powershell
# Graph Reassembly & Format Integrity Benchmark
python scripts/run_reassembly_eval.py

# Zero-Training 75-Class Baseline Benchmark
python scripts/run_zero_training_benchmark.py

# Phase 0 ML Pipeline Smoke Test & Audit
python scripts/verify_smoke_pipeline.py
```

---

## 9. Troubleshooting & FAQ

### Q1: Why are deleted files found when I haven't deleted any files on my PC?
> **Answer**: FirSeFile scans virtual evidence disk images (`tests/fixtures/*.img`), which simulate seized target hard drives containing deleted files. It never scans or modifies your personal storage drive.

### Q2: What if I am offline without GPU accelerators?
> **Answer**: FirSeFile includes both a GPU/CPU Swin Transformer V2 implementation and a deterministic **Zero-Training Hierarchical Classifier** that runs 100% offline at ~950 fragments/sec on standard CPUs without downloading external weights.

### Q3: How do I export recovered files to a specific directory?
> **Answer**: Add `--output-dir <directory_name>` to your `run_recovery.py` command:
> ```powershell
> python tools/run_recovery.py tests/fixtures/xfs_deleted_synthetic.img --output-dir my_recovered_files
> ```
