"""
Byte2Image Representation for File Fragments.
Transforms 1D byte sequences into 2D grayscale representations by exposing
intra-byte (bit-level shifting) and inter-byte correlation patterns.
"""

from typing import Tuple, Optional, Union, Dict
import numpy as np
import torch
import torch.nn.functional as F
from PIL import Image
import os


def extract_intrabyte_bitshifts(raw_bytes: bytes) -> np.ndarray:
    """
    Expose intra-byte bit-level patterns via a sliding byte window with 1-bit stride.
    For a sequence of N bytes (8*N bits), this extracts 8 shifted sequences (shift 0..7).

    Args:
        raw_bytes: Binary data (e.g., 512 bytes).

    Returns:
        np.ndarray of shape (8, len(raw_bytes)) with uint8 values in [0, 255].
    """
    byte_arr = np.frombuffer(raw_bytes, dtype=np.uint8)
    n_bytes = len(byte_arr)
    if n_bytes == 0:
        return np.zeros((8, 1), dtype=np.uint8)

    shifted_matrix = np.zeros((8, n_bytes), dtype=np.uint8)
    # Shift 0 is the original byte sequence
    shifted_matrix[0] = byte_arr

    # Shifts 1 through 7: slide window bit-by-bit
    for k in range(1, 8):
        # High bits from current byte, low bits from next byte
        curr_shifted = ((byte_arr[:-1].astype(np.uint16) << k) & 0xFF).astype(np.uint8)
        next_shifted = (byte_arr[1:].astype(np.uint16) >> (8 - k)).astype(np.uint8)
        shifted_matrix[k, :-1] = curr_shifted | next_shifted
        # For the final byte, wrap or zero-pad
        shifted_matrix[k, -1] = ((int(byte_arr[-1]) << k) & 0xFF)

    return shifted_matrix


def compute_byte_transition_matrix(raw_bytes: bytes, grid_size: int = 16) -> np.ndarray:
    """
    Compute a localized 2D inter-byte co-occurrence transition pattern.
    Maps byte transitions into a 2D intensity grid.
    """
    byte_arr = np.frombuffer(raw_bytes, dtype=np.uint8)
    if len(byte_arr) < 2:
        return np.zeros((grid_size, grid_size), dtype=np.float32)

    # Quantize byte transitions into a grid_size x grid_size matrix
    high_nibble = byte_arr >> 4
    low_nibble = byte_arr & 0x0F
    matrix = np.zeros((16, 16), dtype=np.float32)
    np.add.at(matrix, (high_nibble, low_nibble), 1.0)
    
    # Normalize
    max_val = matrix.max()
    if max_val > 0:
        matrix = matrix / max_val
    return matrix


def bytes_to_byte2image(
    raw_bytes: bytes,
    target_size: Tuple[int, int] = (256, 256),
    normalize: bool = True
) -> np.ndarray:
    """
    Convert a raw binary file fragment into a deterministic 2D grayscale image representation.
    Combines intra-byte bit-shifting (8 rows of bit-shifted bytes) with row-wise n-gram stacking
    and deterministic spatial expansion to match the target Swin Transformer input dimensions.

    Args:
        raw_bytes: Raw binary fragment (typically 512 bytes).
        target_size: (Height, Width) for the output 2D image (default (256, 256)).
        normalize: If True, scale pixel values to [0.0, 1.0] float32; else [0, 255] uint8.

    Returns:
        2D numpy array of shape (target_size[0], target_size[1]).
    """
    if len(raw_bytes) == 0:
        out = np.zeros(target_size, dtype=np.float32 if normalize else np.uint8)
        return out

    # 1. Extract 8-channel intra-byte bit-shifted representation (8 x N)
    bitshifts = extract_intrabyte_bitshifts(raw_bytes)  # (8, N)
    n_shifts, n_bytes = bitshifts.shape

    # 2. Build 2D Intra-Byte and N-Gram Representation Matrix
    # We construct a base 2D representation:
    # Top section: 8 rows of bit-shifted bytes repeated/expanded to expose intrabyte textures
    # Bottom section: 2D byte value matrix reshaped from raw bytes & difference signals
    byte_arr = bitshifts[0]  # original bytes
    diff_signal = np.abs(np.diff(byte_arr.astype(np.int16), prepend=byte_arr[0])).astype(np.uint8)

    # Stack bitshifts (8 rows) and difference row (1 row) -> (9, n_bytes)
    stacked_repr = np.vstack([bitshifts, diff_signal.reshape(1, -1)])  # Shape (9, 512)

    # Convert to PIL Image for high-quality deterministic bicubic/bilinear resizing
    base_img = Image.fromarray(stacked_repr)
    resized_img = base_img.resize((target_size[1], target_size[0]), resample=Image.Resampling.BILINEAR)
    img_array = np.array(resized_img, dtype=np.float32)

    if normalize:
        img_array = img_array / 255.0
    else:
        img_array = np.clip(img_array, 0, 255).astype(np.uint8)

    return img_array


def byte2image_native(raw_bytes: bytes, **kwargs) -> np.ndarray:
    """Native Byte2Image representation alias for compatibility."""
    return bytes_to_byte2image(raw_bytes, **kwargs)


class Byte2ImageTransform:
    """
    PyTorch-compatible callable transform for converting raw bytes to a 1-channel 2D Tensor.
    Output tensor shape: (1, target_height, target_width), dtype: torch.float32 in [0.0, 1.0].
    """

    def __init__(self, target_size: Tuple[int, int] = (256, 256), normalize: bool = True):
        self.target_size = target_size
        self.normalize = normalize

    def __call__(self, raw_bytes: Union[bytes, bytearray, np.ndarray]) -> torch.Tensor:
        if isinstance(raw_bytes, (bytearray, np.ndarray)):
            raw_bytes = bytes(raw_bytes)
        img_2d = bytes_to_byte2image(raw_bytes, target_size=self.target_size, normalize=self.normalize)
        tensor_img = torch.from_numpy(img_2d).unsqueeze(0).float()  # (1, H, W)
        return tensor_img


def save_byte2image_sample(
    raw_bytes: bytes,
    output_path: str,
    target_size: Tuple[int, int] = (256, 256),
    title: Optional[str] = None
) -> str:
    """
    Save a visualization PNG of the Byte2Image conversion for inspection and reporting.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    img_array = bytes_to_byte2image(raw_bytes, target_size=target_size, normalize=False)
    pil_img = Image.fromarray(img_array)
    pil_img.save(output_path, format="PNG")
    return output_path
