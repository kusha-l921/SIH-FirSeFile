#!/usr/bin/env python3
"""
FirSeFile Universal Launcher
============================
Cross-platform interactive launcher and command dispatcher for Linux and Windows.

Usage:
  python run.py             # Interactive menu
  python run.py --gui       # Launch GUI workbench and open browser
  python run.py --scan <img # Run end-to-end recovery scan
  python run.py --predict <f# Run ML fragment classifier
  python run.py --test      # Run complete automated test suite
  python run.py --fixtures  # Generate synthetic forensic test disk images
"""

import os
import sys
import time
import shutil
import argparse
import subprocess
import webbrowser
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
os.chdir(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))


def print_banner():
    banner = r"""
========================================================================
  ______ _       _____       ______ _ _      
  |  ___(_)     /  ___|      |  ___(_) |     
  | |_   _ _ __ \ `--.  ___  | |_   _| | ___ 
  |  _| | | '__| `--. \/ _ \ |  _| | | |/ _ \
  | |   | | |   /\__/ /  __/ | |   | | |  __/
  \_|   |_|_|   \____/ \___| \_|   |_|_|\___|
  
  Automated Multi-Layer Digital Forensic Recovery System
  (Filesystem Reconstruction + Byte2Image Swin-V2 + Blockchain Ledger)
========================================================================
"""
    print(banner)


def check_and_generate_fixtures():
    """Ensure sample synthetic evidence images exist."""
    fixtures_dir = PROJECT_ROOT / "tests" / "fixtures"
    xfs_img = fixtures_dir / "xfs_deleted_synthetic.img"
    btrfs_img = fixtures_dir / "btrfs_deleted_synthetic.img"

    if not xfs_img.exists() or not btrfs_img.exists():
        print("[*] Generating synthetic forensic evidence disk images...")
        try:
            from scripts.generate_synthetic_fixtures import generate_fixtures
            generate_fixtures()
            print("[+] Evidence disk images ready in tests/fixtures/")
        except Exception as e:
            print(f"[!] Warning: Could not generate fixtures automatically: {e}")
    else:
        print("[+] Evidence disk images verified in tests/fixtures/")


def run_gui():
    """Launch the Python API server and Vite React GUI development server and open browser."""
    import threading

    # Start API server in background thread/process
    def start_api():
        try:
            from tools.api_server import start_server
            start_server(8765)
        except Exception as e:
            print(f"[!] API Server notice: {e}")

    api_thread = threading.Thread(target=start_api, daemon=True)
    api_thread.start()
    time.sleep(0.5)

    gui_dir = PROJECT_ROOT / "Gui_CLI"
    if not (gui_dir / "node_modules").exists():
        print("[*] Installing GUI frontend dependencies (npm install)...")
        npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
        subprocess.run([npm_cmd, "install"], cwd=gui_dir, check=True)

    print("\n[*] Starting FirSeFile GUI Workbench on http://127.0.0.1:1420 ...")
    print("[*] Backend Forensic REST API live on http://127.0.0.1:8765 ...")
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    
    # Open browser after short delay
    def open_browser():
        time.sleep(1.5)
        webbrowser.open("http://127.0.0.1:1420")

    threading.Thread(target=open_browser, daemon=True).start()

    try:
        subprocess.run([npm_cmd, "run", "dev", "--", "--host", "127.0.0.1", "--port", "1420"], cwd=gui_dir)
    except KeyboardInterrupt:
        print("\n[*] GUI Server stopped.")



def run_scan(image_path: str, output_dir: str = "recovered_files", ledger_chain: str = "chain.jsonl"):
    """Run full end-to-end recovery pipeline on an image."""
    from tools.run_recovery import run_forensic_pipeline

    print(f"\n[*] Starting forensic recovery on: {image_path}")
    print(f"[*] Output directory: {output_dir}")
    print(f"[*] Ledger chain:     {ledger_chain}\n")

    cmd = [
        sys.executable,
        str(PROJECT_ROOT / "tools" / "run_recovery.py"),
        image_path,
        "--output-dir", output_dir,
        "--ledger-chain", ledger_chain,
    ]
    subprocess.run(cmd)


def run_predict(fragment_path: str, engine: str = "zero_training"):
    """Run single-fragment ML classifier CLI."""
    cmd = [
        sys.executable,
        str(PROJECT_ROOT / "predict.py"),
        "--fragment", fragment_path,
        "--engine", engine,
    ]
    subprocess.run(cmd)


def run_tests():
    """Run full test suite (pytest + blockchain ledger integration tests)."""
    print("\n=======================================================")
    print("  RUNNING FULL INTEGRATION TEST SUITE")
    print("=======================================================\n")
    
    print("[1/2] Running Pytest Suite (51 tests)...")
    res_pytest = subprocess.run([sys.executable, "-m", "pytest"])

    print("\n[2/2] Running Blockchain Recovery Ledger Tests (8 tests)...")
    res_ledger = subprocess.run([sys.executable, str(PROJECT_ROOT / "blockchain_ledger" / "test_integration.py")])

    print("\n=======================================================")
    if res_pytest.returncode == 0 and res_ledger.returncode == 0:
        print("  >>> ALL INTEGRATION & UNIT TESTS PASSED SUCCESSFULLY! <<<")
    else:
        print("  >>> SOME TESTS FAILED! CHECK OUTPUT ABOVE. <<<")
    print("=======================================================\n")


def run_benchmarks():
    """Run reassembly evaluation benchmark."""
    cmd = [sys.executable, str(PROJECT_ROOT / "scripts" / "run_reassembly_eval.py")]
    subprocess.run(cmd)


def interactive_menu():
    """Interactive console menu for easy access to all project components."""
    check_and_generate_fixtures()

    while True:
        print_banner()
        print("  Select an action:")
        print("  ---------------------------------------------------------")
        print("  [1] Launch Interactive GUI Workbench (Browser / Localhost)")
        print("  [2] Run Forensic Recovery on XFS Evidence Image")
        print("  [3] Run Forensic Recovery on Btrfs Evidence Image")
        print("  [4] Run Single-Fragment ML Classifier on Sample Fragment")
        print("  [5] Run Complete Test Suite (51 Pytest + 8 Ledger tests)")
        print("  [6] Run Graph Reassembly & Format Validation Benchmark")
        print("  [7] Run Pipeline Smoke Audit (verify_smoke_pipeline.py)")
        print("  [8] Regenerate Synthetic Evidence Images")
        print("  [0] Exit")
        print("  ---------------------------------------------------------")

        try:
            choice = input("Enter choice [0-8]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break

        if choice == "1":
            run_gui()
        elif choice == "2":
            img = PROJECT_ROOT / "tests" / "fixtures" / "xfs_deleted_synthetic.img"
            run_scan(str(img), output_dir="recovered_xfs_output", ledger_chain="xfs_chain.jsonl")
            input("\nPress Enter to continue...")
        elif choice == "3":
            img = PROJECT_ROOT / "tests" / "fixtures" / "btrfs_deleted_synthetic.img"
            run_scan(str(img), output_dir="recovered_btrfs_output", ledger_chain="btrfs_chain.jsonl")
            input("\nPress Enter to continue...")
        elif choice == "4":
            sample_frag = PROJECT_ROOT / "recovered_xfs_output" / "xfs_deleted_ino_256.pdf"
            if not sample_frag.exists():
                # fallback to creating temporary fragment
                from scripts.generate_synthetic_fixtures import SAMPLE_PDF
                sample_frag = PROJECT_ROOT / "sample_fragment.bin"
                sample_frag.write_bytes(SAMPLE_PDF[:512])
            run_predict(str(sample_frag))
            input("\nPress Enter to continue...")
        elif choice == "5":
            run_tests()
            input("\nPress Enter to continue...")
        elif choice == "6":
            run_benchmarks()
            input("\nPress Enter to continue...")
        elif choice == "7":
            subprocess.run([sys.executable, str(PROJECT_ROOT / "scripts" / "verify_smoke_pipeline.py")])
            input("\nPress Enter to continue...")
        elif choice == "8":
            check_and_generate_fixtures()
            input("\nPress Enter to continue...")
        elif choice == "0":
            print("Goodbye!")
            break
        else:
            print("[!] Invalid option. Please choose between 0 and 8.")
            time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description="FirSeFile Universal Forensic Runner")
    parser.add_argument("--gui", action="store_true", help="Launch GUI dev server in browser")
    parser.add_argument("--scan", type=str, default=None, help="Path to evidence disk image to scan")
    parser.add_argument("--output-dir", "-o", type=str, default="recovered_files", help="Directory for recovered files")
    parser.add_argument("--ledger-chain", "-l", type=str, default="chain.jsonl", help="Path for JSONL ledger chain")
    parser.add_argument("--predict", type=str, default=None, help="Path to isolated binary fragment to classify")
    parser.add_argument("--engine", type=str, default="zero_training", choices=["zero_training", "swin_v2"])
    parser.add_argument("--test", action="store_true", help="Run full test suite")
    parser.add_argument("--benchmark", action="store_true", help="Run reassembly benchmark")
    parser.add_argument("--fixtures", action="store_true", help="Generate synthetic evidence disk images")

    args = parser.parse_args()

    if args.fixtures:
        check_and_generate_fixtures()
    elif args.gui:
        run_gui()
    elif args.scan:
        run_scan(args.scan, output_dir=args.output_dir, ledger_chain=args.ledger_chain)
    elif args.predict:
        run_predict(args.predict, engine=args.engine)
    elif args.test:
        run_tests()
    elif args.benchmark:
        run_benchmarks()
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
