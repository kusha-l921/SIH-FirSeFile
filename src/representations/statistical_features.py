"""
Statistical & Information-Theoretic Feature Extraction for Zero-Training Forensic Profiling.
Extracts:
1. 256-bin Normalized Byte Frequency Histogram (BFH)
2. Shannon Entropy & Normalized Information Density
3. Consecutive Byte Difference / Transition Rate
4. Printable ASCII & Control Character Proportions
5. 2D Spatial Texture & Energy Descriptors from Byte2Image representations
"""

import math
from typing import Dict, Any, Tuple
import numpy as np
from src.representations.byte2image import bytes_to_byte2image


def compute_byte_frequency_histogram(raw_bytes: bytes) -> np.ndarray:
    """
    Compute 256-bin normalized byte frequency distribution.
    Returns: float32 array of shape (256,), sum equals 1.0.
    """
    if len(raw_bytes) == 0:
        return np.zeros(256, dtype=np.float32)

    counts = np.bincount(np.frombuffer(raw_bytes, dtype=np.uint8), minlength=256)
    freqs = counts.astype(np.float32) / len(raw_bytes)
    return freqs


def compute_shannon_entropy(raw_bytes: bytes) -> float:
    """
    Compute Shannon entropy in bits per byte (range: 0.0 to 8.0).
    H(X) = - sum(p_i * log2(p_i))
    """
    if len(raw_bytes) == 0:
        return 0.0

    counts = np.bincount(np.frombuffer(raw_bytes, dtype=np.uint8), minlength=256)
    non_zero = counts[counts > 0].astype(np.float64) / len(raw_bytes)
    entropy = -np.sum(non_zero * np.log2(non_zero))
    return float(entropy)


def compute_byte_deltas(raw_bytes: bytes) -> Tuple[float, float]:
    """
    Compute mean and variance of consecutive byte differences.
    Delta = |b_{i+1} - b_i|
    """
    if len(raw_bytes) < 2:
        return 0.0, 0.0

    arr = np.frombuffer(raw_bytes, dtype=np.uint8).astype(np.float32)
    diffs = np.abs(np.diff(arr))
    return float(np.mean(diffs)), float(np.var(diffs))


def compute_ascii_statistics(raw_bytes: bytes) -> Dict[str, float]:
    """
    Compute printable ASCII, whitespace, null, and non-printable ratios.
    """
    if len(raw_bytes) == 0:
        return {"printable_ratio": 0.0, "whitespace_ratio": 0.0, "null_ratio": 0.0, "high_byte_ratio": 0.0}

    arr = np.frombuffer(raw_bytes, dtype=np.uint8)
    n = len(arr)

    printable_mask = ((arr >= 32) & (arr <= 126)) | (arr == 9) | (arr == 10) | (arr == 13)
    whitespace_mask = (arr == 32) | (arr == 9) | (arr == 10) | (arr == 13)
    null_mask = (arr == 0)
    high_byte_mask = (arr >= 128)

    return {
        "printable_ratio": float(np.sum(printable_mask) / n),
        "whitespace_ratio": float(np.sum(whitespace_mask) / n),
        "null_ratio": float(np.sum(null_mask) / n),
        "high_byte_ratio": float(np.sum(high_byte_mask) / n)
    }


def compute_byte2image_texture_descriptors(raw_bytes: bytes, target_size: Tuple[int, int] = (64, 64)) -> Dict[str, float]:
    """
    Extract 2D spatial texture descriptors from Byte2Image transformation:
    - Contrast (intensity difference variance)
    - Homogeneity (smoothness)
    - Energy / Angular Second Moment
    - Spectral variance via 2D FFT
    """
    img = bytes_to_byte2image(raw_bytes, target_size=target_size, normalize=True)

    # 1. Horizontal and Vertical gradients
    dx = np.diff(img, axis=1)
    dy = np.diff(img, axis=0)
    contrast = float(np.mean(dx**2) + np.mean(dy**2))
    homogeneity = float(np.mean(1.0 / (1.0 + np.abs(dx))) + np.mean(1.0 / (1.0 + np.abs(dy)))) / 2.0

    # 2. Energy (sum of squared intensities)
    energy = float(np.mean(img**2))

    # 3. Spectral centroid / variance via 2D FFT
    fft = np.abs(np.fft.fft2(img))
    fft_energy = float(np.mean(fft[:8, :8])) / (float(np.mean(fft)) + 1e-8)

    return {
        "contrast": contrast,
        "homogeneity": homogeneity,
        "energy": energy,
        "spectral_low_freq_ratio": fft_energy
    }


def extract_full_statistical_profile(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Extract unified statistical and information-theoretic profile of a fragment.
    """
    bfh = compute_byte_frequency_histogram(raw_bytes)
    entropy = compute_shannon_entropy(raw_bytes)
    mean_delta, var_delta = compute_byte_deltas(raw_bytes)
    ascii_stats = compute_ascii_statistics(raw_bytes)
    texture_stats = compute_byte2image_texture_descriptors(raw_bytes, target_size=(64, 64))

    return {
        "bfh": bfh,
        "entropy": entropy,
        "mean_delta": mean_delta,
        "var_delta": var_delta,
        **ascii_stats,
        **texture_stats
    }
