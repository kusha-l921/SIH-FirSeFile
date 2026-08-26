"""
Unit Tests for Zero-Training Forensic Classification and Feature Extraction Pipeline.
"""

import pytest
import numpy as np

from src.datasets.fft75 import FFT75_CLASSES, MAGIC_SIGNATURES
from src.representations.statistical_features import (
    compute_byte_frequency_histogram,
    compute_shannon_entropy,
    compute_ascii_statistics,
    compute_byte_deltas,
    compute_byte2image_texture_descriptors,
    extract_full_statistical_profile
)
from src.models.zero_training_classifier import ZeroTrainingClassifier
from src.reassembly.graph import FragmentNode
from src.reassembly.edge_scoring import compute_edge_score


def test_statistical_feature_extraction():
    # 1. Null block (Entropy = 0.0)
    null_bytes = b"\x00" * 512
    null_entropy = compute_shannon_entropy(null_bytes)
    assert null_entropy == 0.0, f"Expected 0.0 entropy for uniform nulls, got {null_entropy}"

    null_bfh = compute_byte_frequency_histogram(null_bytes)
    assert null_bfh.shape == (256,)
    assert null_bfh[0] == 1.0
    assert np.isclose(np.sum(null_bfh), 1.0)

    # 2. Maximum entropy block (Entropy ~ 8.0 bits)
    rand_bytes = bytes(range(256)) * 2
    rand_entropy = compute_shannon_entropy(rand_bytes)
    assert 7.95 <= rand_entropy <= 8.0, f"Expected ~8.0 bits entropy, got {rand_entropy}"

    # 3. ASCII statistics
    ascii_bytes = b"Hello, World! 1234\n" * 20
    stats = compute_ascii_statistics(ascii_bytes)
    assert stats["printable_ratio"] == 1.0
    assert stats["null_ratio"] == 0.0

    # 4. Texture descriptors from Byte2Image
    texture = compute_byte2image_texture_descriptors(ascii_bytes, target_size=(64, 64))
    assert "contrast" in texture and "homogeneity" in texture and "energy" in texture
    assert texture["homogeneity"] >= 0.0


def test_zero_training_header_classification():
    classifier = ZeroTrainingClassifier()

    # Test PDF header
    pdf_frag = (b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n" + b"A" * 400)[:512]
    pred_pdf = classifier.predict_fragment(pdf_frag)
    assert pred_pdf.predicted_class == "pdf"
    assert pred_pdf.confidence >= 0.90
    assert pred_pdf.entropy < 1.0

    # Test PNG header
    png_frag = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 400)[:512]
    pred_png = classifier.predict_fragment(png_frag)
    assert pred_png.predicted_class == "png"
    assert pred_png.confidence >= 0.90

    # Test ZIP header
    zip_frag = (b"PK\x03\x04\x14\x00\x00\x00" + b"\x00" * 400)[:512]
    pred_zip = classifier.predict_fragment(zip_frag)
    assert pred_zip.predicted_class in ["zip", "docx", "xlsx", "pptx", "jar"]
    assert pred_zip.confidence >= 0.90

    # Test ELF header
    elf_frag = (b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 400)[:512]
    pred_elf = classifier.predict_fragment(elf_frag)
    assert pred_elf.predicted_class == "elf"
    assert pred_elf.confidence >= 0.90

    # Test SQLite header
    sqlite_frag = (b"SQLite format 3\x00\x02\x00\x01\x01" + b"\x00" * 400)[:512]
    pred_sqlite = classifier.predict_fragment(sqlite_frag)
    assert pred_sqlite.predicted_class == "sqlite"
    assert pred_sqlite.confidence >= 0.90


def test_zero_training_inner_grammar_tokens():
    classifier = ZeroTrainingClassifier()

    # Test PDF intermediate stream chunk (no magic header at offset 0)
    pdf_inner = (b"12 0 obj<</Length 45>>stream\nForensic stream payload data\nendstream\nendobj\n" + b" " * 400)[:512]
    pred = classifier.predict_fragment(pdf_inner)
    assert pred.predicted_class == "pdf"
    assert pred.confidence >= 0.75

    # Test Shell script chunk
    sh_chunk = (b"#!/bin/bash\nset -e\necho 'Analyzing sector'\nexport FORENSIC_TARGET=1\n" + b"x" * 400)[:512]
    pred_sh = classifier.predict_fragment(sh_chunk)
    assert pred_sh.predicted_class == "sh"
    assert pred_sh.confidence >= 0.80


def test_zero_training_reassembly_integration():
    classifier = ZeroTrainingClassifier()

    frag1_bytes = (b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n" + b"A" * 400)[:512]
    frag2_bytes = (b"xref\n0 2\ntrailer<< /Root 1 0 R >>\nstartxref\n100\n%%EOF\n" + b" " * 400)[:512]

    pred1 = classifier.predict_fragment(frag1_bytes)
    pred2 = classifier.predict_fragment(frag2_bytes)

    node1 = FragmentNode(
        fragment_id="f01",
        raw_bytes=frag1_bytes,
        predicted_class=pred1.predicted_class,
        confidence=pred1.confidence,
        entropy=pred1.entropy
    )

    node2 = FragmentNode(
        fragment_id="f02",
        raw_bytes=frag2_bytes,
        predicted_class=pred2.predicted_class,
        confidence=pred2.confidence,
        entropy=pred2.entropy
    )

    score, comp = compute_edge_score(node1, node2)
    assert score > 0.40, f"Expected compatible score, got {score}"
    assert node1.predicted_class == "pdf" and node2.predicted_class == "pdf"
