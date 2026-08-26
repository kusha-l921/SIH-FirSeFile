"""
Unit tests for FFT-75 Dataset ontology, manifest creation, and leak-free splitting.
"""

import pytest
from src.datasets.fft75 import (
    FFT75_CLASSES, CLASS_TO_IDX, IDX_TO_CLASS,
    get_class_idx, get_class_name, create_leak_free_split
)
from src.datasets.fragment_dataset import (
    FileFragmentDataset, generate_synthetic_fragment_manifest,
    create_fragment_dataloaders
)
from src.representations.byte2image import Byte2ImageTransform


def test_fft75_class_count():
    assert len(FFT75_CLASSES) == 75, "FFT-75 must have exactly 75 classes"
    assert len(CLASS_TO_IDX) == 75
    assert len(IDX_TO_CLASS) == 75
    assert get_class_name(0) == FFT75_CLASSES[0]
    assert get_class_idx("pdf") == CLASS_TO_IDX["pdf"]


def test_leak_free_split():
    # Create manifest with multiple fragments per source file
    manifest = []
    for cls in ["pdf", "jpg", "zip"]:
        for src_i in range(10):
            src_id = f"src_{cls}_{src_i}"
            for frag_i in range(4):
                manifest.append({
                    "fragment_id": f"{src_id}_frag_{frag_i}",
                    "source_file_id": src_id,
                    "class_name": cls,
                    "raw_bytes": b"\x00" * 512
                })

    train_m, val_m, test_m = create_leak_free_split(manifest, train_ratio=0.8, val_ratio=0.1, test_ratio=0.1, seed=42)

    train_srcs = {item["source_file_id"] for item in train_m}
    val_srcs = {item["source_file_id"] for item in val_m}
    test_srcs = {item["source_file_id"] for item in test_m}

    # Verify zero leakage across source files
    assert len(train_srcs.intersection(val_srcs)) == 0, "Train and Val must not share source files"
    assert len(train_srcs.intersection(test_srcs)) == 0, "Train and Test must not share source files"
    assert len(val_srcs.intersection(test_srcs)) == 0, "Val and Test must not share source files"


def test_fragment_dataloader():
    manifest = generate_synthetic_fragment_manifest(samples_per_class=2, fragment_size=512, seed=42)
    train_m, val_m, _ = create_leak_free_split(manifest, train_ratio=0.8, val_ratio=0.2, test_ratio=0.0)

    transform = Byte2ImageTransform(target_size=(256, 256), normalize=True)
    loaders = create_fragment_dataloaders(
        train_manifest=train_m,
        val_manifest=val_m,
        transform=transform,
        batch_size=4,
        num_workers=0
    )

    batch = next(iter(loaders["train"]))
    inputs, targets, frag_ids = batch

    assert inputs.shape == (4, 1, 256, 256), f"Expected shape (4, 1, 256, 256), got {inputs.shape}"
    assert targets.shape == (4,)
    assert len(frag_ids) == 4
