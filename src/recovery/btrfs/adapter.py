"""
adapter.py
==========
Forensic Btrfs Recovery Adapter for FirSeFile.

Exposes a clean structured interface callable from Python or via CLI/subprocess
from Rust core or external tools.

Output adheres to canonical forensic data contracts:
  - RecoveredMetadataModel
  - RecoveredFileModel
  - RecoverySummary
"""

import sys
import json
import argparse
from pathlib import Path
from typing import Dict, Any, Optional, List

from src.recovery.btrfs.btrfs_engine import BtrfsEngine
from src.recovery.btrfs.btrfs_structs import detect_file_type


def recover_btrfs_image(image_path: str, extract_carved: bool = True) -> Dict[str, Any]:
    """
    Analyzes an evidence image using the read-only Btrfs recovery engine
    and returns a structured recovery report.
    """
    path = Path(image_path)
    if not path.exists():
        return {
            "error": f"Image file not found: {image_path}",
            "filesystem": "btrfs",
            "is_valid_filesystem": False,
            "recovered_files": [],
        }

    with BtrfsEngine(str(path)) as engine:
        result = engine.recover_structured()
        return result


def main():
    parser = argparse.ArgumentParser(description="FirSeFile Btrfs Forensic Adapter")
    parser.add_argument("--image", type=str, required=True, help="Path to evidence disk image")
    parser.add_argument("--json", action="store_true", default=True, help="Output JSON (default: True)")

    args = parser.parse_args()
    report = recover_btrfs_image(args.image)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
