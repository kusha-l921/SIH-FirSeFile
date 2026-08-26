"""
Graph-Based Fragment Reassembly and Format Validation Benchmark.
Evaluates reconstruction accuracy and structural validity across 3, 5, 10, and 20 fragment partitions.
"""

import os
import sys
import json
import zipfile
import io
import struct
import numpy as np
import pandas as pd
from PIL import Image

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.reassembly.synthetic import run_reassembly_experiment, generate_multifragment_test_file
from src.validation.validator import validate_reconstructed_file


def create_sample_files() -> dict:
    """Create valid binary sample files for multiple forensic formats."""
    samples = {}

    # 1. Valid Minimal PDF
    pdf_content = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Contents 4 0 R>>endobj\n"
        b"4 0 obj<</Length 44>>stream\n"
        b"BT /F1 12 Tf 72 712 Td (Forensic Recovery) Tj ET\nendstream\nendobj\n"
        b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000056 00000 n \n0000000111 00000 n \n0000000212 00000 n \n"
        b"trailer<</Size 5/Root 1 0 R>>\nstartxref\n300\n%%EOF\n"
    )
    samples["pdf"] = pdf_content

    # 2. Valid ZIP Archive
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("evidence.txt", "Deleted forensic file content from Btrfs/XFS partition.")
        zf.writestr("metadata.json", json.dumps({"case_id": "FORENSIC-2026-X1"}))
    samples["zip"] = zip_buf.getvalue()

    # 3. Valid Minimal PNG generated via PIL
    png_buf = io.BytesIO()
    img = Image.new("RGB", (8, 8), color="red")
    img.save(png_buf, format="PNG")
    samples["png"] = png_buf.getvalue()

    # 4. Valid Shell Script
    script_content = (
        b"#!/bin/bash\n"
        b"# Layered Forensic File Recovery Script\n"
        b"echo 'Recovering fragments from XFS / Btrfs...'\n"
        b"for i in {1..10}; do\n"
        b"    echo \"Processing fragment $i\"\n"
        b"done\n"
        b"exit 0\n"
    )
    samples["sh"] = script_content

    # 5. Valid SQLite Header
    sqlite_header = bytearray(b"SQLite format 3\x00" + b"\x00" * 84)
    # page size 512 at offset 16
    sqlite_header[16] = 0x02
    sqlite_header[17] = 0x00
    sqlite_header[18] = 0x01
    sqlite_header[19] = 0x01
    samples["sqlite"] = bytes(sqlite_header)

    return samples


def main():
    print("\n=======================================================")
    print("  GRAPH-BASED FRAGMENT REASSEMBLY BENCHMARK")
    print("=======================================================")

    formats = ["pdf", "zip", "png", "sh", "sqlite"]
    fragment_counts = [3, 5, 10, 20]

    print(f"Testing formats: {formats}")
    print(f"Testing fragment counts: {fragment_counts}")
    print("Simulating orphaned shuffled fragments, multi-component edge scoring, and beam search ordering...\n")

    results = run_reassembly_experiment(fragment_counts=fragment_counts, formats=formats, seed=42)

    # Format Summary Table
    table_rows = []
    for count, summary in results["summary"].items():
        table_rows.append({
            "Fragments": count,
            "Exact Seq Accuracy": f"{summary['exact_seq_acc']*100:.1f}%",
            "Pairwise Adjacency": f"{summary['pairwise_adj_acc']*100:.1f}%",
            "Position Accuracy": f"{summary['position_acc']*100:.1f}%",
            "Byte Accuracy": f"{summary['byte_acc']*100:.1f}%",
            "Total Runs": summary["total_runs"]
        })

    df = pd.DataFrame(table_rows)
    print(df.to_string(index=False))

    # Format Validation Test on Reconstructed Files
    print("\n-------------------------------------------------------")
    print("  FORMAT-AWARE VALIDATION OF RECONSTRUCTED FILES")
    print("-------------------------------------------------------")
    for fmt in formats:
        test_file = generate_multifragment_test_file(fmt, n_fragments=5, seed=42)
        report = validate_reconstructed_file(test_file, expected_format=fmt)
        status_icon = "[PASS]" if report.is_valid else "[FAIL]"
        print(f"  {status_icon} Format: {fmt.upper():<8} | Valid: {str(report.is_valid):<5} | Status: {report.status}")
        print(f"         SHA256: {report.sha256[:24]}... | Size: {report.reconstructed_size_bytes} bytes")

    output_path = "experiments/reassembly_benchmark_results.json"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results["summary"], f, indent=2)
    print(f"\nSaved reassembly benchmark results to: {output_path}\n")


if __name__ == "__main__":
    main()
