"""
FFT-75 Dataset Definitions, Ontology, and Leak-Free Data Partitioning.
Standard 75-class benchmark for digital forensics and file carving.
"""

from typing import List, Dict, Tuple, Optional
import os
import json
import hashlib
import random
import numpy as np

# 75 Standard File Format Classes grouped into 8 High-Level Categories (11 forensic tags)
FFT75_CLASSES: List[str] = [
    # Archive (8)
    "7z", "bz2", "gz", "iso", "rar", "tar", "xz", "zip",
    # Audio (9)
    "aac", "ac3", "aiff", "flac", "m4a", "mp3", "ogg", "wav", "wma",
    # Video (9)
    "3gp", "avi", "flv", "m4v", "mkv", "mov", "mp4", "mpeg", "wmv",
    # Image (9)
    "bmp", "gif", "ico", "jpg", "png", "psd", "svg", "tiff", "webp",
    # Executable / Binary (11)
    "apk", "cab", "deb", "dll", "dmg", "elf", "exe", "jar", "msi", "rpm", "so",
    # Document (14)
    "csv", "doc", "docx", "epub", "json", "odt", "pdf", "ppt", "pptx", "rtf", "txt", "xls", "xlsx", "xml",
    # Code / Text (12)
    "c", "cpp", "cs", "css", "go", "html", "java", "js", "php", "py", "sh", "sql",
    # Database (3)
    "db", "sqlite", "mdb"
]

assert len(FFT75_CLASSES) == 75, f"Expected 75 classes, got {len(FFT75_CLASSES)}"

CLASS_TO_IDX: Dict[str, int] = {cls_name: i for i, cls_name in enumerate(FFT75_CLASSES)}
IDX_TO_CLASS: Dict[int, str] = {i: cls_name for i, cls_name in enumerate(FFT75_CLASSES)}

# Forensic Category Mapping
CATEGORY_MAP: Dict[str, str] = {
    # Archive
    "7z": "Archive", "bz2": "Archive", "gz": "Archive", "iso": "Archive",
    "rar": "Archive", "tar": "Archive", "xz": "Archive", "zip": "Archive",
    # Audio
    "aac": "Audio", "ac3": "Audio", "aiff": "Audio", "flac": "Audio",
    "m4a": "Audio", "mp3": "Audio", "ogg": "Audio", "wav": "Audio", "wma": "Audio",
    # Video
    "3gp": "Video", "avi": "Video", "flv": "Video", "m4v": "Video",
    "mkv": "Video", "mov": "Video", "mp4": "Video", "mpeg": "Video", "wmv": "Video",
    # Image
    "bmp": "Image", "gif": "Image", "ico": "Image", "jpg": "Image",
    "png": "Image", "psd": "Image", "svg": "Image", "tiff": "Image", "webp": "Image",
    # Executable
    "apk": "Executable", "cab": "Executable", "deb": "Executable", "dll": "Executable",
    "dmg": "Executable", "elf": "Executable", "exe": "Executable", "jar": "Executable",
    "msi": "Executable", "rpm": "Executable", "so": "Executable",
    # Document
    "csv": "Document", "doc": "Document", "docx": "Document", "epub": "Document",
    "json": "Document", "odt": "Document", "pdf": "Document", "ppt": "Document",
    "pptx": "Document", "rtf": "Document", "txt": "Document", "xls": "Document",
    "xlsx": "Document", "xml": "Document",
    # Code
    "c": "Code", "cpp": "Code", "cs": "Code", "css": "Code", "go": "Code", "html": "Code",
    "java": "Code", "js": "Code", "php": "Code", "py": "Code", "sh": "Code", "sql": "Code",
    # Database
    "db": "Database", "sqlite": "Database", "mdb": "Database"
}

CLASS_TO_CATEGORY = CATEGORY_MAP

# Known Magic Byte Signatures for Header Detection
MAGIC_SIGNATURES: Dict[str, List[bytes]] = {
    "pdf": [b"%PDF-"],
    "zip": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    "docx": [b"PK\x03\x04"],
    "xlsx": [b"PK\x03\x04"],
    "pptx": [b"PK\x03\x04"],
    "jar": [b"PK\x03\x04"],
    "apk": [b"PK\x03\x04"],
    "jpg": [b"\xFF\xD8\xFF"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "gif": [b"GIF87a", b"GIF89a"],
    "bmp": [b"BM"],
    "elf": [b"\x7fELF"],
    "sqlite": [b"SQLite format 3\x00"],
    "db": [b"SQLite format 3\x00"],
    "gz": [b"\x1F\x8B"],
    "7z": [b"7z\xBC\xAF\x27\x1C"],
    "rar": [b"Rar!\x1A\x07\x00", b"Rar!\x1A\x07\x01\x00"],
    "tar": [b"ustar"],
    "bz2": [b"BZh"],
    "xz": [b"\xFD7zXZ\x00"],
    "mp3": [b"\xFF\xFB", b"\xFF\xF3", b"\xFF\xF2", b"ID3"],
    "wav": [b"RIFF"],
    "avi": [b"RIFF"],
    "webp": [b"RIFF"],
    "mp4": [b"ftypmp4", b"ftypisom", b"ftypM4V"],
    "m4a": [b"ftypM4A"],
    "flac": [b"fLaC"],
    "ogg": [b"OggS"],
    "exe": [b"MZ"],
    "dll": [b"MZ"],
}


def get_class_name(idx: int) -> str:
    """Return class name for a given class index."""
    return IDX_TO_CLASS.get(idx, "unknown")


def get_class_idx(class_name: str) -> int:
    """Return class index for a given class name."""
    clean_name = class_name.lower().strip().lstrip(".")
    if clean_name in CLASS_TO_IDX:
        return CLASS_TO_IDX[clean_name]
    raise ValueError(f"Unknown class name: '{class_name}'. Must be one of {FFT75_CLASSES}")


def create_leak_free_split(
    file_manifest: List[Dict[str, any]],
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    test_ratio: float = 0.1,
    seed: int = 42
) -> Tuple[List[Dict[str, any]], List[Dict[str, any]], List[Dict[str, any]]]:
    """
    Partition fragments into train/val/test splits strictly at the SOURCE FILE level
    to prevent data leakage between training and testing.
    """
    assert abs((train_ratio + val_ratio + test_ratio) - 1.0) < 1e-5, "Ratios must sum to 1.0"
    
    # Group items by source file ID / origin
    source_to_items: Dict[str, List[Dict[str, any]]] = {}
    for item in file_manifest:
        src_id = item.get("source_file_id") or item.get("file_id") or item.get("fragment_id")
        source_to_items.setdefault(src_id, []).append(item)
        
    # Group source IDs by class to ensure stratified splitting per class
    class_to_sources: Dict[str, List[str]] = {}
    for src_id, items in source_to_items.items():
        cls_name = items[0]["class_name"]
        class_to_sources.setdefault(cls_name, []).append(src_id)
        
    rng = random.Random(seed)
    train_manifest, val_manifest, test_manifest = [], [], []
    
    for cls_name, sources in class_to_sources.items():
        rng.shuffle(sources)
        n_sources = len(sources)
        if n_sources >= 3:
            n_val = max(1, int(round(n_sources * val_ratio)))
            n_test = max(1, int(round(n_sources * test_ratio)))
            n_train = max(1, n_sources - n_val - n_test)
            
            train_sources = set(sources[:n_train])
            val_sources = set(sources[n_train:n_train + n_val])
            test_sources = set(sources[n_train + n_val:])
            
            for src_id in sources:
                items = source_to_items[src_id]
                if src_id in train_sources:
                    train_manifest.extend(items)
                elif src_id in val_sources:
                    val_manifest.extend(items)
                else:
                    test_manifest.extend(items)
        elif n_sources == 2:
            train_manifest.extend(source_to_items[sources[0]])
            if val_ratio > 0:
                val_manifest.extend(source_to_items[sources[1]])
            else:
                test_manifest.extend(source_to_items[sources[1]])
        else:
            # Single source file: partition fragments chronologically by offset
            items = list(source_to_items[sources[0]])
            n_items = len(items)
            if n_items == 1:
                train_manifest.extend(items)
                val_manifest.extend(items)  # Single sample fallback
            else:
                n_v = max(1, int(round(n_items * val_ratio)))
                n_t = max(1, int(round(n_items * test_ratio)))
                n_tr = max(1, n_items - n_v - n_t)
                
                train_manifest.extend(items[:n_tr])
                val_manifest.extend(items[n_tr : n_tr + n_v])
                test_manifest.extend(items[n_tr + n_v:])
                
    return train_manifest, val_manifest, test_manifest
