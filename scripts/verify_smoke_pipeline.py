"""
Phase 0 Smoke Test and Pipeline Integrity Verification Script.
Rigidly verifies:
1. Dataset loading and Byte2Image conversion
2. Forward pass and finite loss calculation
3. Backward pass, gradient computation, and weight updates
4. Checkpoint saving to disk and reloading
5. Checkpoint weights matching state
6. Post-reload inference and validation execution
"""

import os
import sys
import json
import time
import torch
import torch.nn as nn
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.datasets.fft75 import FFT75_CLASSES, create_leak_free_split
from src.datasets.fragment_dataset import generate_synthetic_fragment_manifest, create_fragment_dataloaders
from src.representations.byte2image import Byte2ImageTransform
from src.models.swin_v2 import SwinV2TinyGrayscale
from src.models.classifier import FragmentClassifier
from src.training.evaluate import evaluate_model


def run_smoke_verification():
    print("\n=======================================================")
    print("      PHASE 0 — SMOKE TEST & PIPELINE INTEGRITY AUDIT")
    print("=======================================================")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Execution Device:  {device}")
    print(f"PyTorch Version:   {torch.__version__}")

    # 1. Dataset generation and Byte2Image transform verification
    print("\n[Step 1/6] Generating synthetic dataset and applying Byte2Image...")
    samples_per_class = 6
    manifest = generate_synthetic_fragment_manifest(samples_per_class=samples_per_class, fragment_size=512, seed=42)
    train_m, val_m, test_m = create_leak_free_split(manifest, train_ratio=0.67, val_ratio=0.33, test_ratio=0.0, seed=42)
    
    transform = Byte2ImageTransform(target_size=(256, 256), normalize=True)
    loaders = create_fragment_dataloaders(
        train_manifest=train_m,
        val_manifest=val_m,
        transform=transform,
        batch_size=8,
        num_workers=0
    )

    batch = next(iter(loaders["train"]))
    inputs, targets, frag_ids = batch
    inputs, targets = inputs.to(device), targets.to(device)

    print(f"  Batch input tensor shape:  {list(inputs.shape)} (dtype: {inputs.dtype})")
    print(f"  Batch target tensor shape: {list(targets.shape)} (min: {targets.min().item()}, max: {targets.max().item()})")
    assert inputs.shape == (8, 1, 256, 256), "Input shape mismatch!"

    # 2. Forward pass and Loss check
    print("\n[Step 2/6] Executing Swin V2 Tiny forward pass and loss check...")
    model = SwinV2TinyGrayscale(num_classes=75, pretrained=False, img_size=256, in_chans=1).to(device)
    model.set_fine_tuning_stage("A")

    criterion = nn.CrossEntropyLoss()
    logits = model(inputs)
    loss = criterion(logits, targets)

    print(f"  Logits output shape:       {list(logits.shape)}")
    print(f"  Initial CrossEntropy Loss: {loss.item():.4f}")
    assert logits.shape == (8, 75), "Output shape mismatch!"
    assert torch.isfinite(loss), "Loss is not finite (NaN or Inf)!"

    # 3. Backward pass, Gradient flow, and Weight updates
    print("\n[Step 3/6] Verifying backward pass, gradient flow, and weight updates...")
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-4)
    
    # Store pre-update weights of head
    pre_weight = model.head[2].weight.clone().detach()

    optimizer.zero_grad()
    loss.backward()

    # Check gradients
    grad_norm = model.head[2].weight.grad.norm().item()
    print(f"  Classification head gradient norm: {grad_norm:.6f}")
    assert grad_norm > 0, "Gradients are zero or missing!"

    optimizer.step()
    post_weight = model.head[2].weight.clone().detach()
    weight_diff = (post_weight - pre_weight).abs().max().item()
    print(f"  Max parameter delta after step:    {weight_diff:.6f}")
    assert weight_diff > 0, "Weights did not update after optimizer step!"

    # 4. Checkpoint saving and reloading
    print("\n[Step 4/6] Testing checkpoint serialization and reloading...")
    os.makedirs("experiments/smoke_test_verify", exist_ok=True)
    ckpt_path = "experiments/smoke_test_verify/smoke_checkpoint.pt"
    
    model.eval()
    with torch.no_grad():
        post_step_eval_logits = model(inputs)

    torch.save({
        "epoch": 1,
        "model_state_dict": model.state_dict(),
        "optimizer_state_dict": optimizer.state_dict(),
        "loss": loss.item()
    }, ckpt_path)
    assert os.path.exists(ckpt_path), "Checkpoint file was not created!"
    print(f"  Saved checkpoint ({os.path.getsize(ckpt_path):,} bytes) -> {ckpt_path}")

    # Reload into fresh model instance
    fresh_model = SwinV2TinyGrayscale(num_classes=75, pretrained=False, img_size=256, in_chans=1).to(device)
    state = torch.load(ckpt_path, map_location=device, weights_only=False)
    fresh_model.load_state_dict(state["model_state_dict"])
    fresh_model.eval()
    print("  Reloaded model state dictionary successfully.")

    # 5. Output equivalence after reload
    with torch.no_grad():
        reloaded_logits = fresh_model(inputs)
    diff = (reloaded_logits - post_step_eval_logits).abs().max().item()
    print(f"  Max logit discrepancy after reload: {diff:.8f}")
    assert diff < 1e-5, "Reloaded model outputs do not match original model!"

    # 6. Evaluation validation loop
    print("\n[Step 6/6] Running validation evaluation loop...")
    val_metrics = evaluate_model(
        model=fresh_model,
        dataloader=loaders["val"],
        device=device,
        class_names=FFT75_CLASSES,
        output_dir="experiments/smoke_test_verify",
        prefix="smoke"
    )

    print(f"  Validation Top-1 Accuracy: {val_metrics['top1_accuracy']*100:.2f}%")
    print(f"  Validation Top-5 Accuracy: {val_metrics['top5_accuracy']*100:.2f}%")
    print(f"  Validation Macro-F1:       {val_metrics['macro_f1']:.4f}")
    print(f"  Per-fragment Latency:      {val_metrics['latency_ms_per_fragment']:.2f} ms/fragment")
    print(f"  Throughput:                {val_metrics['throughput_fps']:.1f} fragments/sec")

    print("\n=======================================================")
    print("  [SUCCESS] PHASE 0 SMOKE PIPELINE VERIFIED 100% OPERATIONAL")
    print("=======================================================\n")

    return {
        "status": "PASSED",
        "loss": float(loss.item()),
        "gradient_norm": float(grad_norm),
        "weight_delta": float(weight_diff),
        "val_metrics": val_metrics
    }


if __name__ == "__main__":
    run_smoke_verification()
