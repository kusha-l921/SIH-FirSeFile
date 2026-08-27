#!/usr/bin/env bash
# =============================================================================
# create_4file_test_image.sh
# =============================================================================
# Creates a fresh XFS evidence image with 4 distinct test files, records their
# metadata as ground truth, then deletes them. The result is a real XFS image
# with genuinely deleted files for forensic recovery testing.
#
# Requirements: mkfs.xfs, losetup, mount, umount (with sudo)
# =============================================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE_NAME="gui_4file_test.img"
IMAGE_PATH="${PROJECT_ROOT}/${IMAGE_NAME}"
MOUNT_POINT="/tmp/firsefile_xfs_test_mnt"
MANIFEST_PATH="${PROJECT_ROOT}/gui_4file_ground_truth.json"

echo "=== FirSeFile 4-File XFS Test Image Generator ==="
echo "Image:    ${IMAGE_PATH}"
echo "Manifest: ${MANIFEST_PATH}"
echo ""

# Clean up from any previous run
sudo umount "${MOUNT_POINT}" 2>/dev/null || true
rm -f "${IMAGE_PATH}"
rm -rf "${MOUNT_POINT}"

# 1. Create blank image
echo "[1/6] Creating 300MB blank image..."
truncate -s 300M "${IMAGE_PATH}"

# 2. Format as XFS
echo "[2/6] Formatting as XFS..."
mkfs.xfs -f "${IMAGE_PATH}" 2>&1 | head -5

# 3. Mount
echo "[3/6] Mounting..."
mkdir -p "${MOUNT_POINT}"
sudo mount -o loop "${IMAGE_PATH}" "${MOUNT_POINT}"

# 4. Create 4 distinct test files
echo "[4/6] Creating 4 test files..."

# File 1: Text file
sudo bash -c "cat > ${MOUNT_POINT}/gui_real_alpha.txt << 'ENDTXT'
FIRSEFILE REAL TEST ALPHA
This file was created specifically for the current 4-file forensic verification test.
Generated at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Purpose: Prove that the GUI scans the actual submitted image, not a hardcoded fixture.
The content of this file is unique and should NOT appear in any presentation fixture.
ENDTXT"

# File 2: JSON file
sudo bash -c "cat > ${MOUNT_POINT}/gui_real_beta.json << 'ENDJSON'
{
  \"test_name\": \"FirSeFile 4-File Verification\",
  \"file_id\": \"gui_real_beta\",
  \"purpose\": \"Verify data-driven recovery pipeline\",
  \"unique_marker\": \"BETA-4FILE-VERIFICATION-2026\",
  \"created_utc\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
  \"expected_behavior\": \"This file should only appear when THIS specific image is scanned\"
}
ENDJSON"

# File 3: PNG file (minimal valid 1x1 red PNG)
sudo bash -c 'printf "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB\x60\x82" > '"${MOUNT_POINT}"'/gui_real_gamma.png'

# File 4: PDF file (minimal valid PDF)
sudo bash -c 'cat > '"${MOUNT_POINT}"'/gui_real_delta.pdf << "ENDPDF"
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]
   /Contents 4 0 R /Resources << >> >>
endobj
4 0 obj
<< /Length 44 >>
stream
BT /F1 12 Tf 100 700 Td (DELTA-4FILE) Tj ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000232 00000 n 
trailer << /Size 5 /Root 1 0 R >>
startxref
328
%%EOF
ENDPDF'

sync

# 5. Record ground truth BEFORE deletion
echo "[5/6] Recording ground truth manifest..."

# Build JSON manifest
python3 - "${MOUNT_POINT}" "${MANIFEST_PATH}" "${IMAGE_PATH}" << 'PYEOF'
import sys, os, json, hashlib, subprocess

mount_point = sys.argv[1]
manifest_path = sys.argv[2]
image_path = sys.argv[3]

files = ["gui_real_alpha.txt", "gui_real_beta.json", "gui_real_gamma.png", "gui_real_delta.pdf"]
manifest = {"image_path": image_path, "test_files": []}

for fname in files:
    fpath = os.path.join(mount_point, fname)
    with open(fpath, "rb") as f:
        data = f.read()
    sha256 = hashlib.sha256(data).hexdigest()
    stat = os.stat(fpath)
    # Get inode number
    inode = stat.st_ino
    manifest["test_files"].append({
        "filename": fname,
        "size_bytes": len(data),
        "inode": inode,
        "sha256": sha256,
    })
    print(f"  {fname}: size={len(data)}, ino={inode}, sha256={sha256[:16]}...")

with open(manifest_path, "w") as f:
    json.dump(manifest, f, indent=2)
print(f"\nManifest written to {manifest_path}")
PYEOF

# 6. Delete all 4 files
echo "[6/6] Deleting test files and syncing..."
sudo rm "${MOUNT_POINT}/gui_real_alpha.txt"
sudo rm "${MOUNT_POINT}/gui_real_beta.json"
sudo rm "${MOUNT_POINT}/gui_real_gamma.png"
sudo rm "${MOUNT_POINT}/gui_real_delta.pdf"
sync

# Verify they're gone
echo ""
echo "Files remaining after deletion:"
ls -la "${MOUNT_POINT}/" 2>/dev/null || echo "(none)"

# Unmount
sudo umount "${MOUNT_POINT}"
rmdir "${MOUNT_POINT}" 2>/dev/null || true

# Record image hash
IMAGE_SHA256=$(sha256sum "${IMAGE_PATH}" | cut -d' ' -f1)
echo ""
echo "=== Test Image Created Successfully ==="
echo "Path:      ${IMAGE_PATH}"
echo "Size:      $(stat --printf=%s "${IMAGE_PATH}") bytes"
echo "SHA-256:   ${IMAGE_SHA256}"
echo ""

# Update manifest with image hash
python3 -c "
import json
with open('${MANIFEST_PATH}') as f:
    m = json.load(f)
m['image_sha256'] = '${IMAGE_SHA256}'
m['image_size_bytes'] = $(stat --printf=%s "${IMAGE_PATH}")
with open('${MANIFEST_PATH}', 'w') as f:
    json.dump(m, f, indent=2)
print('Manifest updated with image SHA-256.')
"

echo ""
echo "=== Ground Truth Manifest ==="
cat "${MANIFEST_PATH}"
echo ""
echo "=== Done ==="
