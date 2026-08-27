#!/usr/bin/env python3
"""
scripts/delete_demo_xfs.py
==========================
Interactive presentation tool to delete test files from a mounted XFS evidence image,
sync residual structures to disk, unmount cleanly, and compute the final evidence SHA-256 digest.

Authoritative FirSeFile Recovery Workflow:
  Step 1: python3 scripts/create_demo_xfs.py  (creates & mounts files)
  Step 2: Inspect files live with ls / cat
  Step 3: python3 scripts/delete_demo_xfs.py  (deletes files, syncs, unmounts)
  Step 4: Load image into FirSeFile GUI for forensic recovery
"""

import os
import sys
import json
import time
import hashlib
import argparse
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_IMAGE_NAME = "demo_xfs_evidence.img"
DEFAULT_MANIFEST_NAME = "demo_xfs_ground_truth.json"

BLOCKED_DEVICE_PREFIXES = ("/dev/", "\\\\.\\", "/proc", "/sys")


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hex digest of a file path."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def is_mounted(mount_dir: Path) -> bool:
    """Check if mount_dir is currently mounted."""
    try:
        res = subprocess.run(["mountpoint", "-q", str(mount_dir)], capture_output=True)
        return res.returncode == 0
    except Exception:
        # Fallback reading /proc/mounts
        try:
            with open("/proc/mounts", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == str(mount_dir):
                        return True
        except Exception:
            pass
    return False


def remount_image(img_path: Path, mount_dir: Path) -> None:
    """Remount an unmounted image if needed for deletion."""
    mount_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["sudo", "mount", "-o", "loop", str(img_path), str(mount_dir)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Failed to mount {img_path} to {mount_dir}: {res.stderr.strip()}")
    subprocess.run(["sudo", "chmod", "777", str(mount_dir)], capture_output=True)


def unmount_image(mount_dir: Path) -> None:
    """Cleanly unmount loop mountpoint."""
    cmd = ["sudo", "umount", str(mount_dir)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Failed to unmount {mount_dir}: {res.stderr.strip()}")
    try:
        mount_dir.rmdir()
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="Delete demo files from XFS evidence image and prepare for recovery.")
    parser.add_argument("image_arg", nargs="?", default="", help="Optional path to target XFS image")
    parser.add_argument("--image", "-i", default="", help="Path to target XFS image")
    parser.add_argument("--manifest", "-m", default=DEFAULT_MANIFEST_NAME, help=f"Path to ground-truth manifest (default: {DEFAULT_MANIFEST_NAME})")
    parser.add_argument("--yes", "--confirm-delete", action="store_true", help="Confirm deletion non-interactively (for automated tests)")
    args = parser.parse_args()

    # Determine image path
    raw_img = args.image_arg or args.image or DEFAULT_IMAGE_NAME
    img_path = Path(raw_img).resolve()
    manifest_path = Path(args.manifest).resolve()

    # Safety checks
    if any(str(img_path).startswith(p) for p in BLOCKED_DEVICE_PREFIXES):
        print(f"\n[ERROR] Target image path '{img_path}' references a physical system device. Operation blocked for safety.")
        sys.exit(1)

    print("\n=======================================================")
    print("      FIRSEFILE DEMO EVIDENCE PREPARATION (STEP 2/2)   ")
    print("=======================================================")
    print(f"Target Evidence Image:   {img_path}")
    print(f"Ground Truth Manifest:   {manifest_path}")

    if not img_path.exists():
        print(f"\n[ERROR] Evidence image '{img_path}' does not exist.")
        print("Please run 'python3 scripts/create_demo_xfs.py' first to create the demo image.")
        sys.exit(1)

    if not manifest_path.exists():
        print(f"\n[ERROR] Ground truth manifest '{manifest_path}' not found.")
        print("Please ensure the manifest from create_demo_xfs.py exists in the project directory.")
        sys.exit(1)

    # Load manifest
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"\n[ERROR] Failed to parse manifest '{manifest_path}': {e}")
        sys.exit(1)

    mount_dir = Path(manifest.get("mount_point", f"/tmp/firsefile_demo_default"))
    files_to_delete = manifest.get("files", [])

    if not files_to_delete:
        print("\n[WARNING] Manifest reports 0 files to delete.")
        sys.exit(0)

    # Check if mount exists
    if not is_mounted(mount_dir):
        print(f"\n[*] Image is not currently mounted at '{mount_dir}'. Attempting loop mount...")
        try:
            remount_image(img_path, mount_dir)
        except Exception as e:
            print(f"[ERROR] Could not mount image: {e}")
            print("Tip: Run in an interactive terminal with sudo privileges.")
            sys.exit(1)

    # Pre-deletion verification of files on mounted filesystem
    print("\n[*] Verifying live files on mounted XFS filesystem...")
    verified_files = []
    for fspec in files_to_delete:
        fn = fspec["filename"]
        target = mount_dir / fn
        if not target.exists():
            print(f"[ERROR] Expected file '{fn}' does not exist on mountpoint '{mount_dir}'. Aborting.")
            sys.exit(1)

        # Check current live stat
        st = target.stat()
        current_hash = compute_sha256(target)
        if current_hash != fspec["sha256"]:
            print(f"[WARNING] File '{fn}' hash mismatch! Expected {fspec['sha256'][:16]}..., observed {current_hash[:16]}...")

        verified_files.append({
            "filename": fn,
            "path": str(target),
            "inode": st.st_ino,
            "size": st.st_size,
            "sha256": current_hash,
            "mtime_iso": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
        })

    # Display deletion warning & require exact confirmation
    print("\n" + "!" * 65)
    print("WARNING: The following files will be permanently deleted from the TEST XFS image:")
    print("!" * 65)
    for vf in verified_files:
        print(f"  • {vf['filename']:<20} (inode {vf['inode']}, {vf['size']} bytes, SHA: {vf['sha256'][:16]}...)")

    if not args.yes:
        print("\nTo confirm deletion, type 'DELETE' exactly:")
        confirmation = input("Confirmation: ").strip()
        if confirmation != "DELETE":
            print("\n[INFO] Deletion canceled by user. Files and mount remain completely untouched.")
            sys.exit(0)

    # Execute deletion
    print("\n[*] Deleting files from mounted filesystem (rm)...")
    for vf in verified_files:
        p = Path(vf["path"])
        try:
            p.unlink()
            print(f"  [-] Deleted: {vf['filename']}")
        except Exception as e:
            print(f"[ERROR] Failed to delete '{vf['filename']}': {e}")
            sys.exit(1)

    # Sync kernel file system caches to image
    print("[*] Flushing filesystem cache (sync)...")
    subprocess.run(["sync"])

    # Verify directory is empty of deleted files
    remaining = [f for f in os.listdir(mount_dir) if not f.startswith(".")]
    if any(vf["filename"] in remaining for vf in verified_files):
        print(f"[ERROR] Deletion verification failed: some files still present in {mount_dir}")
        sys.exit(1)

    # Unmount image
    print(f"[*] Unmounting {mount_dir}...")
    try:
        unmount_image(mount_dir)
        print("[+] Unmount completed successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to unmount: {e}")
        sys.exit(1)

    # Compute final evidence image SHA-256
    print("[*] Computing final evidence image cryptographic digest...")
    final_img_sha256 = compute_sha256(img_path)
    img_size = img_path.stat().st_size

    # Update manifest
    manifest["status"] = "deleted_and_unmounted"
    manifest["deleted_at_utc"] = datetime.now(timezone.utc).isoformat()
    manifest["final_image_sha256"] = final_img_sha256
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # Presentation-ready output
    print("\n" + "=" * 65)
    print("       FIRSEFILE DEMO EVIDENCE PREPARATION COMPLETE       ")
    print("=" * 65)
    print(f"Evidence Image:       {img_path}")
    print(f"Filesystem:           XFS")
    print(f"Image Size:           {img_size} bytes ({img_size // (1024 * 1024)} MiB)")
    print(f"Final Evidence SHA:   {final_img_sha256}")
    print(f"Ground Truth File:    {manifest_path}")
    print(f"\nDeleted Artifacts (Ground Truth):")
    for f in manifest.get("files", []):
        print(f"  • {f['filename']}")
        print(f"      inode:    {f.get('inode')}")
        print(f"      size:     {f.get('size')} bytes")
        print(f"      SHA-256:  {f.get('sha256')}")
        print(f"      mtime:    {f.get('mtime_iso')}")

    print("\n" + "-" * 65)
    print(">>> THE EVIDENCE IMAGE IS NOW READY FOR FORENSIC RECOVERY <<<")
    print("-" * 65)
    print("Next Steps:")
    print("  1. Open FirSeFile GUI in your browser: http://127.0.0.1:1420")
    print("  2. Navigate to 'Evidence Input' Tab")
    print(f"  3. Enter Evidence Image Path:")
    print(f"     {img_path}")
    print("  4. Click 'Launch Forensic Recovery Pipeline'")
    print("  5. Inspect the recovered artifacts against the Ground Truth above!")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
