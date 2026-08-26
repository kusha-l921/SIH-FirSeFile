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


DEFAULT_FRAGMENT_SIZE = 512
DEFAULT_NGRAM = 16


def sliding_byte_window(raw_bytes: Union[bytes, bytearray, np.ndarray]) -> np.ndarray:
    """
    Generate the (512, 8) shifted-byte matrix via a 1-bit sliding window.
    """
    raw = np.frombuffer(bytes(raw_bytes), dtype=np.uint8)
    n_bytes = len(raw)
    if n_bytes == 0:
        return np.zeros((DEFAULT_FRAGMENT_SIZE, 8), dtype=np.uint8)
    
    # Pad or truncate to DEFAULT_FRAGMENT_SIZE
    if n_bytes < DEFAULT_FRAGMENT_SIZE:
        raw = np.pad(raw, (0, DEFAULT_FRAGMENT_SIZE - n_bytes), mode="constant")
    elif n_bytes > DEFAULT_FRAGMENT_SIZE:
        raw = raw[:DEFAULT_FRAGMENT_SIZE]

    bits = np.unpackbits(raw)
    bits = np.pad(bits, (0, 7), mode="constant")

    shifted_sequences = []
    for shift in range(8):
        shifted_bits = bits[shift:shift + DEFAULT_FRAGMENT_SIZE * 8]
        shifted_bytes = np.packbits(
            shifted_bits.reshape(DEFAULT_FRAGMENT_SIZE, 8),
            axis=1
        ).reshape(DEFAULT_FRAGMENT_SIZE)
        shifted_sequences.append(shifted_bytes)

    return np.stack(shifted_sequences, axis=1)  # Shape (512, 8)


def extract_intrabyte_bitshifts(raw_bytes: bytes) -> np.ndarray:
    """Compatibility alias returning (8, 512)."""
    return sliding_byte_window(raw_bytes).T


def byte2image_native(raw_bytes: Union[bytes, bytearray, np.ndarray], ngram: int = DEFAULT_NGRAM) -> np.ndarray:
    """
    Construct the native published Byte2Image grayscale representation.
    For Ns=512 and n=16 -> (497, 128) uint8.
    """
    shifted = sliding_byte_window(raw_bytes)  # (512, 8)
    height = DEFAULT_FRAGMENT_SIZE - ngram + 1
    width = 8 * ngram

    image = np.empty((height, width), dtype=np.uint8)
    for row in range(height):
        block = shifted[row:row + ngram]
        image[row] = block.reshape(-1)

    return image


def compute_byte_transition_matrix(raw_bytes: bytes, grid_size: int = 16) -> np.ndarray:
    """
    Compute a localized 2D inter-byte co-occurrence transition pattern.
    Maps byte transitions into a 2D intensity grid.
    """
    byte_arr = np.frombuffer(raw_bytes, dtype=np.uint8)
    if len(byte_arr) < 2:
        return np.zeros((grid_size, grid_size), dtype=np.float32)

    high_nibble = byte_arr >> 4
    low_nibble = byte_arr & 0x0F
    matrix = np.zeros((16, 16), dtype=np.float32)
    np.add.at(matrix, (high_nibble, low_nibble), 1.0)
    
    max_val = matrix.max()
    if max_val > 0:
        matrix = matrix / max_val
    return matrix


def bytes_to_byte2image(
    raw_bytes: Union[bytes, bytearray, np.ndarray],
    target_size: Optional[Tuple[int, int]] = (256, 256),
    ngram: int = DEFAULT_NGRAM,
    normalize: bool = True
) -> np.ndarray:
    """
    Native Byte2Image -> optional 256x256 model-input adaptation.
    """
    native = byte2image_native(raw_bytes, ngram=ngram)

    if target_size is None:
        return native

    image = Image.fromarray(native, mode="L")
    image = image.resize(
        (target_size[1], target_size[0]),
        resample=Image.Resampling.BICUBIC
    )

    image_array = np.asarray(image, dtype=np.float32)

    if normalize:
        image_array /= 255.0

    return image_array



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
