"""
Dataset package for file fragment intelligence.
"""

from src.datasets.fft75 import (
    FFT75_CLASSES, CLASS_TO_IDX, IDX_TO_CLASS,
    MAGIC_SIGNATURES, CATEGORY_MAP, get_class_idx, get_class_name,
    create_leak_free_split
)
from src.datasets.fragment_dataset import (
    FileFragmentDataset, generate_synthetic_fragment_manifest,
    create_fragment_dataloaders
)

__all__ = [
    "FFT75_CLASSES", "CLASS_TO_IDX", "IDX_TO_CLASS",
    "MAGIC_SIGNATURES", "CATEGORY_MAP", "get_class_idx", "get_class_name",
    "create_leak_free_split", "FileFragmentDataset",
    "generate_synthetic_fragment_manifest", "create_fragment_dataloaders"
]
