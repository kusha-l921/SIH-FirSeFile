"""
Script to execute notebook cells 1 to 6 with persistent kernel state and save real execution outputs.
"""

import os
import sys
import json
import nbformat
from nbclient import NotebookClient

def execute_cells():
    nb_path = "notebooks/01_byte2image_swin_v2_training.ipynb"
    print(f"Reading notebook: {nb_path}...")
    with open(nb_path, "r", encoding="utf-8") as f:
        nb = nbformat.read(f, as_version=4)

    client = NotebookClient(nb, timeout=300, kernel_name="python3")
    
    print("Executing cells 0 to 6 with persistent kernel...")
    with client.setup_kernel():
        for idx in range(1, 7):
            cell = nb.cells[idx]
            if cell.cell_type == "code":
                print(f"\n=======================================================")
                print(f"Executing Cell {idx}...")
                print(f"=======================================================")
                
                # Execute cell inside the active kernel
                client.execute_cell(cell, idx)
                
                for out in cell.outputs:
                    if out.get("output_type") == "stream":
                        for line in out.get("text", "").splitlines():
                            try:
                                print("  [stdout]", line)
                            except Exception:
                                print("  [stdout]", line.encode('ascii', 'replace').decode('ascii'))
                    elif out.get("output_type") == "error":
                        print("  [error]", out.get("ename"), ":", out.get("evalue"))
                        for tb in out.get("traceback", []):
                            print("    ", tb)

    with open(nb_path, "w", encoding="utf-8") as f:
        nbformat.write(nb, f)
    print(f"\n[SUCCESS] Notebook {nb_path} executed successfully with all cell outputs saved!")

if __name__ == "__main__":
    execute_cells()
