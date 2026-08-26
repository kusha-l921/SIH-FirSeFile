"""
Unit tests for Swin Transformer V2 1-Channel Adaptation and Classifier.
"""

import torch
import pytest

from src.models.swin_v2 import SwinV2TinyGrayscale
from src.models.classifier import FragmentClassifier


def test_swin_v2_tiny_forward_pass():
    # Instantiate model with 75 classes and 1 input channel
    model = SwinV2TinyGrayscale(
        num_classes=75,
        pretrained=False,
        img_size=256,
        in_chans=1
    )
    model.eval()

    # Dummy batch of 2 1-channel 256x256 grayscale images
    dummy_input = torch.randn(2, 1, 256, 256, dtype=torch.float32)
    with torch.no_grad():
        logits = model(dummy_input)

    assert logits.shape == (2, 75), f"Expected output shape (2, 75), got {logits.shape}"


def test_swin_v2_staged_fine_tuning():
    model = SwinV2TinyGrayscale(
        num_classes=75,
        pretrained=False,
        img_size=256,
        in_chans=1
    )

    # Test Stage A configuration (head trainable, lower layers frozen)
    model.set_fine_tuning_stage("A")
    trainable_a = [p for p in model.parameters() if p.requires_grad]
    total_a = list(model.parameters())
    assert len(trainable_a) < len(total_a), "Stage A should freeze lower stages"
    assert all(p.requires_grad for p in model.head.parameters()), "Head must be trainable in Stage A"

    # Test Stage B configuration (all trainable)
    model.set_fine_tuning_stage("B")
    trainable_b = [p for p in model.parameters() if p.requires_grad]
    assert len(trainable_b) == len(total_a), "Stage B should unfreeze all parameters"


def test_classifier_predict_fragment():
    model = SwinV2TinyGrayscale(num_classes=75, pretrained=False, img_size=256, in_chans=1)
    classifier = FragmentClassifier(model=model, device="cpu", img_size=256)

    dummy_fragment = b"%PDF-1.5" + b"\x00" * 504
    pred = classifier.predict_fragment(dummy_fragment, top_k=5)

    assert "predicted_class" in pred
    assert "confidence" in pred
    assert len(pred["top_k_classes"]) == 5
    assert len(pred["top_k_probabilities"]) == 5
    assert abs(sum(pred["all_probabilities"].values()) - 1.0) < 1e-4, "Softmax probabilities must sum to 1.0"
