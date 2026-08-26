"""
Export Sample Byte2Image Visualizations across different forensic formats.
Verifies deterministic transformation and saves inspection PNGs.
"""

import os
import sys
import numpy as np

# Ensure project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.representations.byte2image import (
    bytes_to_byte2image, extract_intrabyte_bitshifts, save_byte2image_sample
)
from src.datasets.fft75 import MAGIC_SIGNATURES


def generate_sample_fragment(format_type: str, fragment_size: int = 512) -> bytes:
    """Generate representative 512-byte fragment for visualization."""
    sigs = MAGIC_SIGNATURES.get(format_type, [])
    if sigs:
        sig = sigs[0]
        body = np.random.RandomState(42).bytes(fragment_size - len(sig))
        return sig + body
    elif format_type == "py":
        code_str = "#!/usr/bin/env python3\nimport os, sys, torch\nprint('Forensic intelligence')\n" * 15
        return code_str.encode("utf-8")[:fragment_size].ljust(fragment_size, b" ")
    else:
        return np.random.RandomState(42).bytes(fragment_size)


def main():
    output_dir = "experiments/byte2image_samples"
    os.makedirs(output_dir, exist_ok=True)
    print(f"Exporting Byte2Image sample PNG visualizations to: {output_dir}")

    sample_formats = ["pdf", "jpg", "png", "zip", "elf", "sqlite", "py", "gz"]

    for fmt in sample_formats:
        frag_bytes = generate_sample_fragment(fmt, 512)
        out_file = os.path.join(output_dir, f"byte2image_{fmt}_sample.png")
        save_byte2image_sample(frag_bytes, out_file, target_size=(256, 256))
        
        # Test deterministic conversion
        img1 = bytes_to_byte2image(frag_bytes, target_size=(256, 256))
        img2 = bytes_to_byte2image(frag_bytes, target_size=(256, 256))
        assert np.array_equal(img1, img2), f"Non-deterministic conversion for {fmt}!"
        
        print(f"  [OK] {fmt.upper():<8} -> {out_file} (256x256 grayscale, shape: {img1.shape})")

    # Also save a sample fragment binary for CLI prediction testing
    sample_bin_path = "data/sample_fragment.bin"
    os.makedirs(os.path.dirname(sample_bin_path), exist_ok=True)
    with open(sample_bin_path, "wb") as f:
        f.write(generate_sample_fragment("pdf", 512))
    print(f"\nSaved sample binary fragment to: {sample_bin_path}")


if __name__ == "__main__":
    main()
