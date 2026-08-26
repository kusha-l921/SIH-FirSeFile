"""
Unit tests for Byte2Image transformation module.
"""

import numpy as np
import torch
import pytest

from src.representations.byte2image import (
    extract_intrabyte_bitshifts,
    bytes_to_byte2image,
    Byte2ImageTransform,
    compute_byte_transition_matrix
)


def test_extract_intrabyte_bitshifts():
    # 512-byte random input
    raw_data = bytes([0xAA, 0x55, 0xFF, 0x00] * 128)
    shifts = extract_intrabyte_bitshifts(raw_data)
    
    assert shifts.shape == (8, 512), f"Expected shape (8, 512), got {shifts.shape}"
    assert np.array_equal(shifts[0], np.frombuffer(raw_data, dtype=np.uint8)), "Shift 0 must match raw bytes"
    assert shifts.dtype == np.uint8, "Expected uint8 data type"


def test_bytes_to_byte2image_deterministic():
    raw_data = b"%PDF-1.4 header fragment test for deterministic byte2image" * 10
    raw_data = raw_data[:512].ljust(512, b"\x00")

    img1 = bytes_to_byte2image(raw_data, target_size=(256, 256), normalize=True)
    img2 = bytes_to_byte2image(raw_data, target_size=(256, 256), normalize=True)

    assert img1.shape == (256, 256), f"Expected shape (256, 256), got {img1.shape}"
    assert np.all(img1 >= 0.0) and np.all(img1 <= 1.0), "Normalized values must be in [0.0, 1.0]"
    assert np.array_equal(img1, img2), "Byte2Image must be strictly deterministic"


def test_byte2image_transform_tensor():
    raw_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 504
    transform = Byte2ImageTransform(target_size=(256, 256), normalize=True)
    tensor = transform(raw_data)

    assert isinstance(tensor, torch.Tensor), "Expected PyTorch Tensor"
    assert tensor.shape == (1, 256, 256), f"Expected shape (1, 256, 256), got {tensor.shape}"
    assert tensor.dtype == torch.float32, "Expected float32 tensor"
