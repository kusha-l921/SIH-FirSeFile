# FirSeFile — Complete Start-to-Finish Operating Guide

FirSeFile is an automated multi-layer digital forensic file recovery platform. It accepts raw filesystem evidence disk images (such as XFS and Btrfs), performs deep structural filesystem reconstruction, extracts and classifies residual data fragments using secondary neural/heuristic machine learning (Byte2Image and Swin-V2), validates structural integrity against file format specifications, and records an immutable, cryptographically signed chain-of-custody audit log into an Ed25519 blockchain ledger.

> [!IMPORTANT]
> The authoritative XFS recovery engine is implemented in high-performance Rust inside:
> ```
> correct-recovery-engine/
> ```
> It directly inspects superblock geometry, allocation group free-space B+trees (`cntbt` / `bnobt`), unlinked inode chains in Allocation Group Inode headers (`AGI`), and residual Inode B+trees (`inobt`) to perform forensically sound recovery without modifying evidence.

---

## 1. Project Structure

```text
SIH-FirSeFile/
├── correct-recovery-engine/   # Authoritative Rust XFS structural recovery engine
│   ├── Cargo.toml             # Rust package manifest & dependencies
│   ├── src/                   # Core XFS parsers (dinode, btree, extents, hashing)
│   └── target/release/        # Compiled release binary (xfs-recovery-engine)
├── src/                       # Python core engine & integration layer
│   ├── models/                # Byte2Image & Swin-V2 zero-training classifier models
│   ├── recovery/              # Filesystem recovery adapters
│   │   ├── xfs/               # Python adapter boundary to Rust recovery engine
│   │   └── btrfs/             # Btrfs structural parser and file extractor
│   ├── reassembly/            # Graph-based fragment reassembly algorithms
│   └── validation/            # Format-aware validators (PDF, PNG, JPG, ZIP, SQLite)
├── tools/                     # Forensic orchestration CLI & REST API backend
│   ├── run_recovery.py        # End-to-end command-line recovery pipeline
│   └── api_server.py          # REST API server bridging recovery engine to GUI
├── Gui_CLI/                   # Interactive React / Vite / Tailwind forensic desktop GUI
│   ├── src/                   # UI components, ledger viewer, inspector, report exporter
│   ├── package.json           # Node.js dependencies
│   └── vite.config.ts         # Vite build configuration
├── blockchain_ledger/         # Ed25519 cryptographically signed audit ledger
│   ├── ledger.py              # Chain-of-custody block creation & signature verification
│   └── test_integration.py   # Ledger test suite
├── scripts/                   # Presentation and evidence creation/deletion helpers
│   ├── create_demo_xfs.py     # Interactive script: creates & populates live XFS image
│   ├── delete_demo_xfs.py     # Interactive script: deletes files, syncs & unmounts
│   └── generate_synthetic_fixtures.py # Deterministic multi-format test fixture generator
├── tests/                     # Automated test suites & test fixtures
│   ├── fixtures/              # Deterministic test images (xfs_deleted_synthetic.img)
│   └── test_gui_metadata_mapping.py # Metadata mapping, preview & PDF export tests
├── recovered_output/          # Default destination directory for carved files
├── requirements.txt           # Python package dependencies
├── run.py                     # Universal launcher (interactive CLI / GUI / test runner)
├── README.md                  # High-level architecture overview
└── README-START.md            # Complete start-to-finish operating guide (this file)
```

### Component Roles
- **`correct-recovery-engine/`**: The authoritative, memory-safe Rust recovery engine. Parses XFS metadata structures down to bit-level B+tree records and performs zero-link unlinked inode salvage.
- **`src/recovery/xfs/`**: Integration boundary bridging the Rust binary execution and JSON outputs with the Python forensic pipeline.
- **`tools/`**: Contains `run_recovery.py` (orchestrates acquisition, structural parsing, ML classification, format validation, and ledger recording) and `api_server.py` (REST API server running on port `8765`).
- **`Gui_CLI/`**: Modern React/Vite workbench running on port `1420` providing visual triage, artifact inspection, and PDF reporting.
- **`blockchain_ledger/`**: Tamper-evident, cryptographically chained audit log recording every evidence acquisition and artifact recovery event with Ed25519 digital signatures.
- **`scripts/`**: Interactive scripts enabling live, reproducible terminal demonstrations on real XFS disk images.
- **`tests/`**: Unit, integration, differential, and end-to-end verification suites.

---

## 2. System Requirements

### Required Tools
- **Linux OS** (Ubuntu 20.04+, Debian 11+, Fedora 36+, or Arch Linux)
- **Python**: version `3.10` or newer
- **Rust & Cargo**: version `1.75` or newer
- **Node.js & npm**: Node `18+` and npm `9+`
- **XFS Userland Utilities**: `xfsprogs` (`mkfs.xfs`, `xfs_db`, `xfs_info`)
- **System Utilities**: `mount`, `umount`, `losetup`, `sudo`, `file`, `sha256sum`, `xxd`

### Install Required Linux Packages (Debian / Ubuntu)
```bash
sudo apt update
sudo apt install -y build-essential python3 python3-venv python3-pip cargo rustc nodejs npm xfsprogs poppler-utils
```

### Verify Tooling Versions
```bash
python3 --version
cargo --version
rustc --version
npm --version
mkfs.xfs -V
xfs_db -V
```

---

## 3. Clone & Enter Project

Clone the repository or navigate to the local workspace:

```bash
cd ~/Desktop/SIH-FirSeFile
```

Verify your current working directory:
```bash
pwd
```
*Expected Output:*
```
/home/<user>/Desktop/SIH-FirSeFile
```

---

## 4. Python Virtual Environment Setup

Create and activate an isolated Python virtual environment, then install required packages:

```bash
# 1. Create virtual environment
python3 -m venv venv

# 2. Activate virtual environment
source venv/bin/activate

# 3. Upgrade pip
python3 -m pip install --upgrade pip

# 4. Install dependencies
pip install -r requirements.txt
```

### Verify Virtual Environment Activation
When activated, your terminal prompt will be prefixed with `(venv)`. Verify the Python binary path:
```bash
which python3
```
*Expected Output:* `/home/.../SIH-FirSeFile/venv/bin/python3`

---

## 5. Build the Authoritative Rust Engine

Compile the release binary of the Rust XFS recovery engine:

```bash
cargo build --release \
  --manifest-path correct-recovery-engine/Cargo.toml \
  --bin xfs-recovery-engine \
  --target-dir correct-recovery-engine/target
```

### Verify the Compiled Engine
```bash
./correct-recovery-engine/target/release/xfs-recovery-engine --version
```
*Expected Output:*
```
xfs-recovery-engine 0.1.0
```

> [!NOTE]
> The compiled binary must exist at `./correct-recovery-engine/target/release/xfs-recovery-engine` for the Python adapter and API server to invoke native XFS recovery.

---

## 6. Run Automated Tests

Run the full verification suite to confirm that every subsystem is functioning correctly.

### 1. Authoritative Rust Engine Tests (139+ tests)
```bash
cargo test --manifest-path correct-recovery-engine/Cargo.toml
```

### 2. Pytest Forensic & Metadata Mapping Test Suite (97+ tests)
```bash
venv/bin/pytest -v
```

### 3. Blockchain Ledger Cryptographic Integrity Tests (8 tests)
```bash
venv/bin/python blockchain_ledger/test_integration.py
```

### 4. End-to-End Pipeline Universal Test Runner
```bash
venv/bin/python run.py --test
```

### 5. Frontend GUI Build Verification
```bash
cd Gui_CLI
npm install
npm run build
cd ..
```

*Expected Result:* All tests pass with zero errors.

---

## 7. Simplest Manual Demo Workflow

The recommended presentation sequence provides a transparent, verifiable demonstration of forensic file recovery:

```text
  [1] Create Fresh XFS Image  ──▶  python3 scripts/create_demo_xfs.py
               │
  [2] Live Ground-Truth Check ──▶  ls -lah / cat / sha256sum on mounted files
               │
  [3] Delete Files & Unmount  ──▶  python3 scripts/delete_demo_xfs.py
               │
  [4] Record Image SHA-256    ──▶  sha256sum demo_xfs_evidence.img
               │
  [5] Direct Rust Scan        ──▶  ./correct-recovery-engine/target/release/xfs-recovery-engine scan ...
               │
  [6] Launch GUI & Recover    ──▶  python3 run.py --gui  (enter image path)
               │
  [7] Visual Triage & Inspect ──▶  Verify logical sizes, clean hex preview, IST dates
               │
  [8] Verify Blockchain Chain ──▶  Click "Validate Entire Chain"
               │
  [9] Export Forensic Report  ──▶  Download & open genuine PDF report
```

---

## 8. Two Demo Scripts

FirSeFile provides two dedicated presentation scripts in `scripts/`:

1. **`scripts/create_demo_xfs.py`**:
   - Creates a clean 512 MiB sparse image formatted with genuine XFS.
   - Mounts the image via loopback to a secure temporary directory.
   - Interactively prompts for $N$ files, formats, and contents.
   - Writes the files, flushes buffers, and prints the exact live mount point.
   - **Leaves the image mounted** so the audience can inspect physical files prior to deletion.

2. **`scripts/delete_demo_xfs.py`**:
   - Reads the active mount point from `demo_xfs_ground_truth.json`.
   - Displays the files scheduled for deletion and requests confirmation (`DELETE`).
   - Deletes the files, invokes kernel sync, unmounts the loopback device, and removes the mount directory.
   - Computes and displays the authoritative SHA-256 digest of the unmounted evidence image.

---

## 9. Create a New Test Image

Run the creation script from the project root:

```bash
python3 scripts/create_demo_xfs.py
```

### Example Interactive Session
```text
======================================================================
  FirSeFile Interactive XFS Evidence Image Creator
======================================================================

[*] Target Image Path: /home/kushal/Desktop/SIH-FirSeFile/demo_xfs_evidence.img
[*] Allocating 512 MiB disk image...
[+] Formatting image with mkfs.xfs...
[+] Mounting image to /tmp/firsefile_demo_xxxxxx ...

How many files do you want to create? [Default: 3]: 3

--- File #1 of 3 ---
Enter filename [Default: 1.txt]: 1.txt
Select format ([txt], pdf, png, jpg, bin): txt
Enter text content [Default: kushal.1]: kushal.1
[+] Created /tmp/firsefile_demo_xxxxxx/1.txt (8 bytes)

--- File #2 of 3 ---
Enter filename [Default: 2.txt]: 2.txt
Select format ([txt], pdf, png, jpg, bin): txt
Enter text content [Default: kushal.2]: kushal.2
[+] Created /tmp/firsefile_demo_xxxxxx/2.txt (8 bytes)

--- File #3 of 3 ---
Enter filename [Default: 3.txt]: 3.txt
Select format ([txt], pdf, png, jpg, bin): txt
Enter text content [Default: kushal.3]: kushal.3
[+] Created /tmp/firsefile_demo_xxxxxx/3.txt (8 bytes)

======================================================================
[+] 3 files successfully created in mounted XFS filesystem!
[*] Live Mount Point: <MOUNT_POINT>
======================================================================
```

> [!NOTE]
> The script prints `<MOUNT_POINT>` (e.g. `/tmp/firsefile_demo_xxxxxx`). Keep this path for the next step.

---

## 10. Show the Files Before Deletion

Demonstrate to the audience that the files exist in the mounted filesystem with exact sizes and hashes:

### List Files
```bash
ls -lah <MOUNT_POINT>
```

### View Content
```bash
cat <MOUNT_POINT>/1.txt
cat <MOUNT_POINT>/2.txt
cat <MOUNT_POINT>/3.txt
```

### Inspect Metadata (Inodes and Sizes)
```bash
stat -c '%n | inode=%i | size=%s bytes' <MOUNT_POINT>/1.txt <MOUNT_POINT>/2.txt <MOUNT_POINT>/3.txt
```

### Record Ground-Truth SHA-256 Hashes
```bash
sha256sum <MOUNT_POINT>/1.txt <MOUNT_POINT>/2.txt <MOUNT_POINT>/3.txt
```

*Expected Output:*
```text
8d06d9cef147428f0a9c6667020c4e8a42b68273203cd4c908a6a41f6ec26f9b  <MOUNT_POINT>/1.txt
6ff889eda5fb8cbbdd05528c2ceaac77ceb64c0778aa799fc842606d49014913  <MOUNT_POINT>/2.txt
d27fbdabdb7fd8ce256aa969e2a3c7849562a468a803bf49dd7aaa2412deb03f  <MOUNT_POINT>/3.txt
```

---

## 11. Delete the Test Files

Execute the deletion script to remove the files, sync the filesystem, unmount cleanly, and finalize the evidence disk image:

```bash
python3 scripts/delete_demo_xfs.py
```

### Prompts & Execution
1. The script lists the 3 files detected in the ground-truth manifest.
2. Type `DELETE` when prompted.
3. The script executes `rm`, syncs XFS metadata buffers, unmounts the loop device, and outputs the evidence image path and SHA-256 hash.

```text
======================================================================
[+] Evidence image ready for forensic recovery!
[*] Image Path: <IMAGE_PATH>
[*] Image SHA-256: <IMAGE_SHA256>
======================================================================
```

---

## 12. Verify Image is Unmounted

Ensure the evidence image is completely unmounted before performing forensic recovery:

```bash
mount | grep firsefile || echo "[+] Verified: Evidence image is fully unmounted."
```

---

## 13. Verify Evidence Image

Inspect the unmounted evidence disk image:

```bash
# Check size
ls -lh <IMAGE_PATH>

# Inspect XFS geometry
xfs_info <IMAGE_PATH>

# Verify baseline SHA-256 digest
sha256sum <IMAGE_PATH>
```

> [!NOTE]
> The computed SHA-256 digest is the baseline disk hash stored in Block #0 (Genesis Block) of the blockchain ledger.

---

## 14. Direct Rust CLI Test

Directly invoke the authoritative Rust recovery engine to inspect recovery candidates prior to launching the GUI:

```bash
./correct-recovery-engine/target/release/xfs-recovery-engine \
  scan <IMAGE_PATH> \
  --json \
  --experimental
```

### Key Output Fields Explained
- `is_valid`: Boolean indicating if the image contains a structurally valid XFS filesystem.
- `fs_info`: Block size (e.g. 4096), AG count, inode size (e.g. 512 bytes).
- `candidates`: List of recovered unlinked/residual inode records.
- `recovery_method`: e.g. `xfs_zero_link_anomaly`, `xfs_unlinked_structural_recovery`.
- `confidence`: Authoritative forensic confidence score (`0.75` / `Medium` or `0.95` / `High`).
- `content_sha256`: SHA-256 digest of carved content.

> [!IMPORTANT]
> In digital forensics, recovering zero candidates can be a valid forensic outcome if filesystem transactions or overwrites destroyed residual inode structures. The tool accurately reports true filesystem state without fabricating results.

---

## 15. Direct FirSeFile Python CLI

Run the full end-to-end Python pipeline (structural recovery, Byte2Image classification, format validation, and blockchain recording) from the terminal:

```bash
python3 tools/run_recovery.py \
  <IMAGE_PATH> \
  --output-dir recovered_output/manual_test \
  --ledger-chain manual_test_chain.jsonl
```

### Pipeline Execution Steps
1. **Acquisition & FS Detection**: Identifies XFS filesystem geometry and computes baseline hash.
2. **Structural Recovery**: Calls Rust engine to extract deleted inode records and extents.
3. **ML Fragment Classification**: Extracts Byte2Image features and performs zero-training classification.
4. **Format Validation**: Validates file structure.
5. **Ledger Recording**: Logs each recovery event into `manual_test_chain.jsonl` with Ed25519 signatures.

---

## 16. Check Recovered Files

Verify the carved artifacts on disk:

```bash
# List recovered files and sizes
find recovered_output/manual_test -type f -printf '%p | %s bytes\n'

# Inspect file types
file recovered_output/manual_test/*

# Verify SHA-256 digests against pre-deletion ground truth
sha256sum recovered_output/manual_test/*
```

*Expected Result:* Recovered file hashes match pre-deletion ground truth digests identically.

---

## 17. Start the Website GUI

### Recommended Method (Universal Launcher)
```bash
python3 run.py --gui
```
*This starts both the Python REST API server on `http://127.0.0.1:8765` and Vite React GUI on `http://127.0.0.1:1420`, then automatically opens your web browser.*

### Alternative: Start Backend and Frontend Separately

**Terminal 1 (Backend REST API):**
```bash
cd ~/Desktop/SIH-FirSeFile
source venv/bin/activate
venv/bin/python -c "from tools.api_server import start_server; start_server(8765)"
```

**Terminal 2 (Frontend React Workbench):**
```bash
cd ~/Desktop/SIH-FirSeFile/Gui_CLI
npm run dev -- --host 127.0.0.1 --port 1420
```

Open your browser to: **`http://127.0.0.1:1420`**

---

## 18. GUI — New Scan

1. On the top navigation bar, ensure you are on the **Forensic Scan** view.
2. Under **Case Settings & Evidence Acquisition**:
   - **Case Identifier**: Enter e.g. `CASE-KUSHAL-123`
   - **Forensic Investigator**: Enter e.g. `Lead Investigator`
   - **Target Evidence Image Path**: Enter the exact absolute image path (e.g. `/home/kushal/Desktop/SIH-FirSeFile/demo_xfs_evidence.img`).

> [!CAUTION]
> The **Target Evidence Image Path** field must contain **ONLY** the raw file path (e.g. `/home/.../image.img`). Do **NOT** paste labels like `Target Image: /home/...`.

3. Click **Launch Forensic Recovery**.
4. The system executes structural recovery, Byte2Image analysis, and blockchain logging in real time.

---

## 19. GUI — Recovered Files

Once the scan completes, inspect the **Recovered Files** section:

- **Artifact Filename**: e.g. `xfs_deleted_ino_128.txt`
- **File Type**: `TXT`
- **Size**: Shows logical size (e.g. `8 B`) alongside physical extent size (`4096 B`).
- **Modified (IST)**: Authoritative timestamp formatted in India Standard Time (`YYYY-MM-DD HH:MM:SS IST`).
- **Recovery Confidence**: Authoritative Rust forensic score (e.g. `Medium (75%)`).
- **ML Classification**: Secondary Byte2Image classifier result (e.g. `TXT`).
- **ML Confidence**: Presentation content classification confidence (e.g. `68.6%`).
- **SHA-256 Digest**: Exact cryptographic checksum of recovered file bytes.

---

## 20. GUI — Inspect Artifact

Click on any recovered file card to open the **Artifact Inspector**:

1. **Artifact Details**: Displays Inode ID, Original Size (e.g. `8 B`), Extent Allocation (`4096 B`), Recovery Method, and Hash.
2. **ASCII Byte Stream**: Shows recovered logical text (e.g. `kushal.1`).
3. **Live Hex Dump (16-byte format)**:
   ```text
   00000000  6B 75 73 68 61 6C 2E 31                           |kushal.1|
   ```

> [!TIP]
> **Logical-Size-Aware Preview**: When the original file size is known ($8\text{ B}$), the hex preview displays only the 8 logical bytes and automatically suppresses the 4,088 trailing physical zero padding bytes.

---

## 21. GUI — ML Classification

The **ML Reassembly / Fragment Classification** tab contains two distinct sections:

1. **Top-Level Recovered Artifacts Summary**:
   - **Dominant Format**: Derived strictly from the current scan's recovered files (e.g. `TXT` for three text files).
   - **Average ML Confidence**: Exact arithmetic mean of individual artifact ML scores (between $60.0\%$ and $70.0\%$).
   - **Format Breakdown**: Percentage distribution of recovered file types.

2. **Interactive Live Fragment Tester (Demo Sandbox)**:
   - Allows dropping or typing arbitrary raw bytes to test the standalone neural classifier.
   - Sandbox testing is completely isolated and does **not** alter the scan summary or report.

---

## 22. GUI — Audit Ledger

Click the **Audit Ledger** tab to view the tamper-evident chain of custody:

- **Block #0 (Genesis)**: Records evidence image baseline SHA-256, case ID, acquisition timestamp, and investigator public key.
- **Block #1..N (Recovery Events)**: Records individual file recovery events, carved SHA-256 hashes, source locations, and recovery methods.
- **Cryptographic Signatures**: Every block is signed with Ed25519 and chained via `prev_hash`.

### Verify Blockchain Integrity
Click **Validate Entire Chain**.
- **Success Banner**:
  ```text
  Cryptographic Chain Verified:
  All Ed25519 signatures and block hash preimages are valid.
  ```
- *Forensic meaning*: Proves no records or metadata inside the ledger have been altered, added, or deleted since acquisition.

---

## 23. GUI — Ledger Block Inspection

Click on any block card in the ledger to expand the raw block data:
- `block_index`: Sequential integer index (`0`, `1`, `2`, ...)
- `block_type`: `genesis` or `full_recovery`
- `block_hash`: 64-character SHA-256 preimage hash
- `prev_hash`: Hash of the preceding block (`0000...` for genesis)
- `public_key_id`: 64-character Ed25519 public key of the investigator
- `signature`: 128-character Ed25519 digital signature
- `payload`: Structured JSON containing file attributes, MACB timestamps, and source offsets.

---

## 24. GUI — Export Forensics Report

Click the **Export Forensic Report** button in the header or sidebar:

1. The backend dynamically compiles a publication-grade landscape PDF report.
2. The browser automatically downloads:
   ```text
   FirSeFile_Forensic_Report_<case_id>.pdf
   ```
   *(e.g. `FirSeFile_Forensic_Report_CASE-KUSHAL-123.pdf`)*

### Verify Downloaded PDF in Terminal
```bash
# Verify file type
file ~/Downloads/FirSeFile_Forensic_Report_*.pdf

# Verify PDF signature
xxd -l 16 ~/Downloads/FirSeFile_Forensic_Report_*.pdf
```
*Expected Output:*
```text
PDF document, version 1.4, 1 page(s)
00000000: 2550 4446 2d31 2e34 ...  %PDF-1.4...
```

---

## 25. Report Content Verification

The generated PDF report includes:
- **Case Information**: Case ID, Investigator, Detected Filesystem, Evidence Image Path, Evidence SHA-256, Scan Timestamps in IST & UTC.
- **Recovery & ML Summary**: Total Artifacts Analyzed, Dominant Format (`TXT`), Average ML Confidence (`65.9%`).
- **Recovered Forensic Artifacts Table**: Inode ID, Filename, Format, Original Size, Extent Size, Recovery Confidence (`Medium (75%)`), ML Classification (`TXT`), ML Confidence (`68.6%`), Modified Timestamp (IST), SHA-256 Digest.
- **Cryptographic Chain of Custody Table**: Block Index, Block Type, Timestamp (IST), Block Hash, Previous Hash, Signer Public Key.

---

## 26. Timestamp Policy

- **Authoritative Stored Timestamp**: Stored internally and in blockchain blocks as UTC ISO-8601 strings (e.g. `2026-08-26T22:51:20Z`).
- **Display Formatting**: Converted dynamically in the GUI and PDF reports to India Standard Time (**IST** / `Asia/Kolkata` / $\text{UTC}+5:30$):
  ```text
  2026-08-26 22:51:20 UTC  ──▶  2026-08-27 04:21:20 IST
  ```
- *Forensic Rule*: Underlying timestamps extracted from inodes are never overwritten or altered.

---

## 27. Hash Verification

FirSeFile utilizes distinct cryptographic hashes across layers:

1. **Evidence Image SHA-256**: Hash of the entire raw evidence disk image before analysis.
2. **Recovered Artifact SHA-256**: Hash of the extracted file content bytes.
3. **Ledger Block Hash**: SHA-256 hash computed over `index + prev_hash + timestamp + payload_json + public_key`.
4. **Ed25519 Signature**: Asymmetric cryptographic signature proving the authenticity and authorship of each ledger block.

---

## 28. Forensic Confidence vs ML Confidence

| Property | Forensic Recovery Confidence | ML Classification Confidence |
| :--- | :--- | :--- |
| **Source** | Rust XFS Recovery Engine | Byte2Image / Zero-Training Classifier |
| **Basis** | Inode structural integrity & extent validity | Byte distribution & content header features |
| **Scale / Values** | `Low` / `Medium (75%)` / `High (95%)` | Percentage strictly between `60.0%` and `70.0%` |
| **Purpose** | Confidence that file was recovered accurately | Confidence in detected format/content type |

---

## 29. Common Presentation Demo (Copy & Paste)

Execute the complete end-to-end presentation flow in seconds:

```bash
# 1. Enter repository & activate environment
cd ~/Desktop/SIH-FirSeFile
source venv/bin/activate

# 2. Build Rust Engine
cargo build --release \
  --manifest-path correct-recovery-engine/Cargo.toml \
  --bin xfs-recovery-engine \
  --target-dir correct-recovery-engine/target

# 3. Create & populate XFS evidence image
python3 scripts/create_demo_xfs.py

# 4. In a second terminal (or next step), delete files and unmount image
python3 scripts/delete_demo_xfs.py

# 5. Launch FirSeFile GUI workbench
python3 run.py --gui
```
*In the browser GUI, enter the image path printed by `delete_demo_xfs.py` and click **Launch Forensic Recovery**.*

---

## 30. Known Test Case: Three TXT Files

### Ground Truth Manifest
- `1.txt` $\rightarrow$ Content: `kushal.1` (8 bytes) $\rightarrow$ SHA-256: `8d06d9cef147428f0a9c6667020c4e8a42b68273203cd4c908a6a41f6ec26f9b`
- `2.txt` $\rightarrow$ Content: `kushal.2` (8 bytes) $\rightarrow$ SHA-256: `6ff889eda5fb8cbbdd05528c2ceaac77ceb64c0778aa799fc842606d49014913`
- `3.txt` $\rightarrow$ Content: `kushal.3` (8 bytes) $\rightarrow$ SHA-256: `d27fbdabdb7fd8ce256aa969e2a3c7849562a468a803bf49dd7aaa2412deb03f`

### Expected Recovery Behavior
- **Files Recovered**: 3 artifacts (`xfs_deleted_ino_128.txt`, `129`, `130`).
- **Logical Size**: Exactly `8 B` (extent block `4096 B`).
- **Classifier Result**: `TXT` for all three files.
- **Dominant Format**: `TXT` ($100\%$).
- **ML Confidence**: Dynamic values between $60.0\%$ and $70.0\%$.

---

## 31. Presentation Fixture

FirSeFile includes a pre-generated, deterministic multi-format test image at:
```
tests/fixtures/xfs_deleted_synthetic.img
```
This fixture contains structured deleted artifacts across formats (`PDF`, `PNG`, `JPG`, `ZIP`, `SQLite`, `TXT`) for automated testing and offline presentations.

To regenerate fixtures at any time:
```bash
python3 scripts/generate_synthetic_fixtures.py
```

---

## 32. Troubleshooting Table

| Problem | Potential Cause | Verification & Fix |
| :--- | :--- | :--- |
| **"Image not found" error** | Path is relative or contains field labels | Provide the full absolute path (e.g. `/home/.../image.img`). Ensure no prefix like `Target: ` is pasted. |
| **GUI stuck on "Executing Scan"** | Backend API server is stopped | Check backend status: `curl -s http://127.0.0.1:8765/api/status`. Restart with `python3 run.py --gui`. |
| **Port 1420 or 8765 in use** | A previous server instance is running | Kill processes on ports: `fuser -k 1420/tcp 8765/tcp`. |
| **No candidates recovered** | XFS cleared residual inode extents | Check direct Rust CLI: `./correct-recovery-engine/target/release/xfs-recovery-engine scan <IMG> --json --experimental`. Zero candidates can be valid forensic outcome. |
| **Hex Preview shows 4088 zeroes** | Raw extent displayed without logical bound | Verify backend has `is_logical_trimmed` active and `original_size` mapped from inode. |
| **Report exports as HTML** | Frontend requesting deprecated format | Verify export handler sends `format: "pdf"`. Clear browser cache. |
| **ML shows PDF for TXT scan** | Interactive demo state conflated with scan | Ensure ML Summary reflects `CURRENT_STATE["files"]` rather than sample fragment tester state. |
| **Timestamps appear off by 5.5 hours** | Viewing UTC instead of IST | Timestamps stored in UTC are displayed in IST ($\text{UTC}+5:30$). |

---

## 33. Cleanup After a Demo

Safely remove temporary demo images and recovery outputs without altering source code or test fixtures:

```bash
# Remove temporary demo evidence image
rm -f demo_xfs_evidence.img

# Remove demo ground-truth manifest
rm -f demo_xfs_ground_truth.json

# Remove temporary test chain log
rm -f manual_test_chain.jsonl presentation_chain.jsonl

# Clean recovered output folder
rm -rf recovered_output/manual_test recovered_output/presentation
```

> [!CAUTION]
> Never execute blanket deletion commands such as `rm -rf *` or modify files inside `correct-recovery-engine/` or `tests/fixtures/`.

---

## 34. Git & Repository Best Practices

Before committing changes, check repository status:

```bash
# Check modified files
git status --short

# Pull latest branch updates
git pull

# Stage specific changes
git add README-START.md

# Commit with a descriptive message
git commit -m "docs: add comprehensive start-to-finish operating guide"
```

### What should NOT be committed

Never commit:
- forensic evidence images (e.g. `*.img`, `*.raw`, `*.dd`, `*.E01`, `*.001`)
- raw disk images
- recovered evidence (e.g. `recovered_output/`, `recovered_files/`, `recovered_xfs_output/`)
- generated chain ledgers (e.g. `chain.jsonl`, `*_chain.jsonl`, `manual_test_chain.jsonl`, `presentation_chain.jsonl`)
- generated forensic reports (e.g. `FirSeFile_Forensic_Report_*.pdf`, `FirSeFile_Forensic_Report_*.json`, `FirSeFile_Forensic_Report_*.html`)
- local virtual environments (e.g. `venv/`, `.venv/`)
- build artifacts (e.g. `target/`, `node_modules/`, `dist/`, `build/`)
- API secrets / private keys (e.g. `*.pem`, `*.key`)
- `.env` files

Instead commit:
- source code
- recovery engine (Rust code under `correct-recovery-engine/`)
- scripts that generate test images (e.g. `scripts/create_demo_xfs.py`)
- deterministic small test fixtures when intentionally required (e.g. `tests/fixtures/xfs_deleted_synthetic.img`)
- tests
- documentation

### Manual Test Image Policy
Commands such as:
```bash
python3 scripts/create_demo_xfs.py
```
create local evidence images (e.g. `demo_xfs_evidence.img`) for demonstration. Those images remain **LOCAL ONLY**. The repository should contain the creation and deletion scripts, but not the generated disk images.

---

## 35. What NOT To Do

- **DO NOT** modify raw evidence disk images during analysis.
- **DO NOT** mount evidence images read-write during forensic triage.
- **DO NOT** carve recovered files directly onto the target evidence drive.
- **DO NOT** conflate ML classification confidence ($60\%-70\%$) with forensic recovery confidence ($75\%/95\%$).
- **DO NOT** fabricate residual inode records when XFS has wiped structures.
- **DO NOT** commit forensic disk images or sensitive case data to Git.

---

## 36. Quick Start — 10 Minute Version

```bash
# 1. Setup environment
cd ~/Desktop/SIH-FirSeFile
source venv/bin/activate

# 2. Build Rust recovery engine
cargo build --release \
  --manifest-path correct-recovery-engine/Cargo.toml \
  --bin xfs-recovery-engine \
  --target-dir correct-recovery-engine/target

# 3. Create test XFS disk image with 3 files
python3 scripts/create_demo_xfs.py

# 4. Delete the files & unmount
python3 scripts/delete_demo_xfs.py

# 5. Launch GUI Workbench
python3 run.py --gui

# 6. Open browser to http://127.0.0.1:1420
#    Paste the printed <IMAGE_PATH> and click 'Launch Forensic Recovery'
```

---

## 37. Final Pre-Demo Checklist

- [ ] Python virtual environment is activated (`which python3` points to `venv/`).
- [ ] Rust engine binary is compiled at `./correct-recovery-engine/target/release/xfs-recovery-engine`.
- [ ] All automated tests pass (`python run.py --test`).
- [ ] XFS test disk image created via `python3 scripts/create_demo_xfs.py`.
- [ ] Pre-deletion files inspected with `ls -lah`, `cat`, and `sha256sum`.
- [ ] Files deleted and disk image cleanly unmounted via `python3 scripts/delete_demo_xfs.py`.
- [ ] Unmounted image status verified (`mount | grep firsefile` returns nothing).
- [ ] Baseline evidence SHA-256 recorded.
- [ ] GUI launched (`python3 run.py --gui`).
- [ ] Absolute image path entered into GUI without extra label prefixes.
- [ ] Recovered files inspected (logical sizes, clean hex dump without 4088 zeroes, IST dates).
- [ ] Blockchain ledger verified via **Validate Entire Chain**.
- [ ] Forensic PDF report exported and verified with `file` command (`%PDF-1.4`).
- [ ] No temporary evidence files staged or committed to Git.
