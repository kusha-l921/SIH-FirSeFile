#!/usr/bin/env bash
# ==============================================================================
# generate_test_fixtures.sh
# ==============================================================================
# Generates real Linux kernel-formatted XFS and Btrfs filesystem disk images
# with known test files, deletes selected files, unmounts the filesystem,
# and outputs evidence images along with a verification manifest.
#
# Requirements:
#   - Linux host or WSL2 Ubuntu
#   - root privileges (sudo) for loop-mounting
#   - xfsprogs, btrfs-progs, e2fsprogs
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/tests/fixtures"

mkdir -p "${OUTPUT_DIR}"
TEMP_DIR="$(mktemp -d /tmp/forensic_fixtures_XXXXXX)"
trap 'rm -rf "${TEMP_DIR}"' EXIT

echo "=== FirSeFile Forensic Fixture Generator (WSL2 / Linux) ==="
echo "Output Directory: ${OUTPUT_DIR}"

# Check for required tools
for cmd in mkfs.xfs mkfs.btrfs losetup mount umount; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: Required tool '$cmd' is not installed."
        echo "Install with: sudo apt-get update && sudo apt-get install -y xfsprogs btrfs-progs util-linux"
        exit 1
    fi
done

# ------------------------------------------------------------------------------
# 1. Create XFS Test Image
# ------------------------------------------------------------------------------
echo ""
echo "[-] Building XFS test image with deleted files..."

XFS_IMG="${OUTPUT_DIR}/xfs_deleted_wsl.img"
XFS_MNT="${TEMP_DIR}/mnt_xfs"
mkdir -p "${XFS_MNT}"

# Create 64 MiB zeroed image
dd if=/dev/zero of="${XFS_IMG}" bs=1M count=64 status=none

# Format as XFS
mkfs.xfs -f -b size=4096 -m crc=1,finobt=1 "${XFS_IMG}" >/dev/null

# Mount image
sudo mount -o loop "${XFS_IMG}" "${XFS_MNT}"

# Populate test files
echo "Creating test evidence..."
mkdir -p "${XFS_MNT}/documents" "${XFS_MNT}/media" "${XFS_MNT}/system"

# 1. Text file
echo "Important confidential forensic report - Case 2026-XFS" > "${XFS_MNT}/documents/case_summary.txt"
# 2. PDF file
cat << 'EOF' > "${XFS_MNT}/documents/confidential.pdf"
%PDF-1.4
1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj
2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj
3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>endobj
4 0 obj<< /Length 36 >>stream
BT /F1 12 Tf 100 700 Td (Forensic XFS Evidence) Tj ET
endstream endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000210 00000 n 
trailer<< /Size 5 /Root 1 0 R >>
startxref
296
%%EOF
EOF

# 3. Script file
cat << 'EOF' > "${XFS_MNT}/system/backup.sh"
#!/bin/bash
echo "Performing automated backup..."
tar -czf /var/backup.tar.gz /home
EOF
chmod +x "${XFS_MNT}/system/backup.sh"

# Sync to ensure written to disk
sync

# Delete selected files to create forensic deleted-file recovery scenario
echo "Deleting test files..."
rm -f "${XFS_MNT}/documents/confidential.pdf"
rm -f "${XFS_MNT}/system/backup.sh"

# Sync and unmount cleanly
sync
sudo umount "${XFS_MNT}"

echo "[+] XFS Image created: ${XFS_IMG}"

# ------------------------------------------------------------------------------
# 2. Create Btrfs Test Image
# ------------------------------------------------------------------------------
echo ""
echo "[-] Building Btrfs test image with deleted files..."

BTRFS_IMG="${OUTPUT_DIR}/btrfs_deleted_wsl.img"
BTRFS_MNT="${TEMP_DIR}/mnt_btrfs"
mkdir -p "${BTRFS_MNT}"

# Create 64 MiB zeroed image
dd if=/dev/zero of="${BTRFS_IMG}" bs=1M count=64 status=none

# Format as Btrfs
mkfs.btrfs -f -s 4096 -n 16384 "${BTRFS_IMG}" >/dev/null

# Mount image
sudo mount -o loop "${BTRFS_IMG}" "${BTRFS_MNT}"

# Populate test files
mkdir -p "${BTRFS_MNT}/evidence" "${BTRFS_MNT}/logs"

cat << 'EOF' > "${BTRFS_MNT}/evidence/btrfs_report.pdf"
%PDF-1.4
1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj
2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj
3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>endobj
4 0 obj<< /Length 38 >>stream
BT /F1 12 Tf 100 700 Td (Btrfs Forensic Artifact) Tj ET
endstream endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000210 00000 n 
trailer<< /Size 5 /Root 1 0 R >>
startxref
298
%%EOF
EOF

echo "Log entry: Security event audit log" > "${BTRFS_MNT}/logs/security.log"

sync

# Delete selected files
echo "Deleting test files..."
rm -f "${BTRFS_MNT}/evidence/btrfs_report.pdf"

sync
sudo umount "${BTRFS_MNT}"

echo "[+] Btrfs Image created: ${BTRFS_IMG}"

echo ""
echo "=== Fixture Generation Complete ==="
echo "Images saved to: ${OUTPUT_DIR}"
