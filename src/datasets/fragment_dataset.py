"""
Dataset classes and loaders for FFT-75 and File Fragment processing.
"""

from typing import List, Dict, Optional, Tuple, Callable, Union
import os
import random
import numpy as np
import torch
from torch.utils.data import Dataset, DataLoader

from src.datasets.fft75 import (
    FFT75_CLASSES, CLASS_TO_IDX, IDX_TO_CLASS,
    MAGIC_SIGNATURES, CATEGORY_MAP, get_class_idx
)


class FileFragmentDataset(Dataset):
    """
    PyTorch Dataset for file fragments.
    Can operate on raw bytes, manifest metadata, or disk files.
    """

    def __init__(
        self,
        manifest: List[Dict[str, any]],
        transform: Optional[Callable[[bytes], torch.Tensor]] = None,
        fragment_size: int = 512,
        cache_in_memory: bool = False
    ):
        """
        Args:
            manifest: List of dicts with keys:
                      'fragment_id', 'class_name' (or 'class_idx'),
                      and either 'raw_bytes' or 'file_path'.
            transform: Callable transforming raw bytes -> torch.Tensor (e.g. Byte2Image)
            fragment_size: Expected fragment size in bytes (default 512)
            cache_in_memory: Whether to pre-transform and cache tensors in RAM
        """
        self.manifest = manifest
        self.transform = transform
        self.fragment_size = fragment_size
        self.cache_in_memory = cache_in_memory
        self._cache: Dict[int, Tuple[torch.Tensor, int]] = {}

        if self.cache_in_memory:
            self._preload()

    def _preload(self):
        for idx in range(len(self.manifest)):
            self._cache[idx] = self._load_item(idx)

    def _load_item(self, idx: int) -> Tuple[torch.Tensor, int, str]:
        item = self.manifest[idx]
        
        # 1. Retrieve raw bytes
        if "raw_bytes" in item and item["raw_bytes"] is not None:
            raw_data = item["raw_bytes"]
        elif "file_path" in item and os.path.exists(item["file_path"]):
            with open(item["file_path"], "rb") as f:
                raw_data = f.read(self.fragment_size)
        else:
            raise ValueError(f"Manifest item at index {idx} lacks valid raw_bytes or file_path")

        # Ensure correct fragment length
        if len(raw_data) < self.fragment_size:
            raw_data = raw_data.ljust(self.fragment_size, b"\x00")
        elif len(raw_data) > self.fragment_size:
            raw_data = raw_data[:self.fragment_size]

        # 2. Get class index
        if "class_idx" in item:
            class_idx = int(item["class_idx"])
        else:
            class_idx = get_class_idx(item["class_name"])

        # 3. Apply transformation (e.g., Byte2Image)
        if self.transform is not None:
            tensor_data = self.transform(raw_data)
        else:
            # Fallback to normalized 1D float tensor
            tensor_data = torch.from_numpy(np.frombuffer(raw_data, dtype=np.uint8)).float() / 255.0

        frag_id = item.get("fragment_id", f"frag_{idx}")
        return tensor_data, class_idx, frag_id

    def __len__(self) -> int:
        return len(self.manifest)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, int, str]:
        if self.cache_in_memory and idx in self._cache:
            return self._cache[idx]
        return self._load_item(idx)


def generate_synthetic_fragment_manifest(
    samples_per_class: int = 100,
    fragment_size: int = 512,
    seed: int = 42
) -> List[Dict[str, any]]:
    """
    Generate synthetic, deterministic file fragments for testing/smoke runs.
    Simulates real entropy, header signatures, text/binary patterns per FFT-75 class.
    """
    rng = random.Random(seed)
    np_rng = np.random.RandomState(seed)
    manifest = []

    for cls_name in FFT75_CLASSES:
        cls_idx = CLASS_TO_IDX[cls_name]
        category = CATEGORY_MAP.get(cls_name, "Document")
        signatures = MAGIC_SIGNATURES.get(cls_name, [])

        for s_idx in range(samples_per_class):
            frag_id = f"synth_{cls_name}_{s_idx:05d}"
            
            # Synthesize realistic byte patterns based on category
            if s_idx % 4 == 0 and len(signatures) > 0:
                # Header fragment: inject known magic bytes at offset 0
                sig = rng.choice(signatures)
                body = np_rng.bytes(fragment_size - len(sig))
                raw_bytes = sig + body
            elif category == "Code" or cls_name in ["txt", "csv", "json", "xml", "html"]:
                # High-frequency printable ASCII / UTF-8 distribution
                chars = (
                    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \t\n\r"
                    b"{}[]()<>;:=+-*/.,_\"'\\#&|!?"
                )
                raw_bytes = bytes(rng.choices(chars, k=fragment_size))
            elif category in ["Archive", "Video", "Audio", "Image"]:
                # High entropy (compressed/encrypted/multimedia stream)
                raw_bytes = np_rng.bytes(fragment_size)
            elif category in ["Executable", "Database"]:
                # Mixed code/data sections with zero-padding and pointer tables
                chunk1 = np_rng.bytes(fragment_size // 2)
                chunk2 = bytes(rng.choices([0x00, 0x90, 0xCC, 0xFF, 0x55, 0x48], k=fragment_size // 2))
                raw_bytes = chunk1 + chunk2
            else:
                raw_bytes = np_rng.bytes(fragment_size)

            manifest.append({
                "fragment_id": frag_id,
                "source_file_id": f"src_{cls_name}_{(s_idx // 2):04d}",
                "class_name": cls_name,
                "class_idx": cls_idx,
                "raw_bytes": raw_bytes,
                "fragment_size": fragment_size
            })

    return manifest


def create_fragment_dataloaders(
    train_manifest: List[Dict[str, any]],
    val_manifest: List[Dict[str, any]],
    test_manifest: Optional[List[Dict[str, any]]] = None,
    transform: Optional[Callable[[bytes], torch.Tensor]] = None,
    batch_size: int = 64,
    num_workers: int = 0,
    fragment_size: int = 512,
    pin_memory: bool = True
) -> Dict[str, DataLoader]:
    """
    Build train/val/test DataLoaders for PyTorch.
    """
    train_ds = FileFragmentDataset(train_manifest, transform=transform, fragment_size=fragment_size)
    val_ds = FileFragmentDataset(val_manifest, transform=transform, fragment_size=fragment_size)

    loaders = {
        "train": DataLoader(
            train_ds, batch_size=batch_size, shuffle=True,
            num_workers=num_workers, pin_memory=pin_memory, drop_last=True
        ),
        "val": DataLoader(
            val_ds, batch_size=batch_size, shuffle=False,
            num_workers=num_workers, pin_memory=pin_memory
        )
    }

    if test_manifest is not None:
        test_ds = FileFragmentDataset(test_manifest, transform=transform, fragment_size=fragment_size)
        loaders["test"] = DataLoader(
            test_ds, batch_size=batch_size, shuffle=False,
            num_workers=num_workers, pin_memory=pin_memory
        )

    return loaders
