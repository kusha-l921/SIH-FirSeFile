#!/usr/bin/env bash
# FirSeFile Forensic Recovery System Launcher (Linux / macOS)

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "========================================================================"
echo "  FirSeFile Forensic Recovery System Launcher (Linux / macOS)"
echo "========================================================================"
echo ""

if command -v python3 &>/dev/null; then
    PYTHON_CMD=python3
elif command -v python &>/dev/null; then
    PYTHON_CMD=python
else
    echo "[ERROR] Python 3 is not installed or not in PATH."
    echo "Please install Python 3.10+ (e.g., sudo apt install python3 python3-pip)"
    exit 1
fi

"$PYTHON_CMD" run.py "$@"
