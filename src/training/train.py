"""
Staged Fine-Tuning and Training Pipeline for Swin Transformer V2 on FFT-75.
Supports Phase 0 (Smoke Test), Phase 1 (Pilot Run), and Phase 2 (Main Run).
Includes mixed precision, AdamW, cosine annealing, and experiment tracking.
"""

from typing import Dict, Any, Optional, List, Tuple
import os
import sys
import json
import time
import shutil
import random
import numpy as np
import torch
import torch.nn as nn
from torch.optim import AdamW
from torch.optim.lr_scheduler import CosineAnnealingLR, LinearLR, SequentialLR

from src.datasets.fft75 import FFT75_CLASSES, create_leak_free_split
from src.datasets.fragment_dataset import (
    FileFragmentDataset, generate_synthetic_fragment_manifest,
    create_fragment_dataloaders
)
from src.representations.byte2image import Byte2ImageTransform
from src.models.swin_v2 import SwinV2TinyGrayscale
from src.training.evaluate import evaluate_model
from src.training.metrics import plot_training_history, save_metrics_report


def set_seed(seed: int = 42):
    """Ensure strict deterministic reproducibility."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False


def train_epoch(
    model: nn.Module,
    train_loader: torch.utils.data.DataLoader,
    criterion: nn.Module,
    optimizer: torch.optim.Optimizer,
    scaler: Optional[torch.amp.GradScaler],
    device: torch.device,
    scheduler: Optional[Any] = None
) -> Tuple[float, float, float]:
    """Train for a single epoch."""
    model.train()
    total_loss = 0.0
    correct = 0
    total_samples = 0
    start_time = time.perf_counter()

    use_amp = (device.type == "cuda" and scaler is not None)

    for step, batch in enumerate(train_loader):
        inputs, targets = batch[0].to(device, non_blocking=True), batch[1].to(device, non_blocking=True)
        batch_size = inputs.size(0)

        optimizer.zero_grad()

        if use_amp:
            with torch.amp.autocast(device_type="cuda", dtype=torch.float16):
                logits = model(inputs)
                loss = criterion(logits, targets)
            scaler.scale(loss).backward()
            scaler.step(optimizer)
            scaler.update()
        else:
            logits = model(inputs)
            loss = criterion(logits, targets)
            loss.backward()
            optimizer.step()

        if scheduler is not None:
            scheduler.step()

        total_loss += loss.item() * batch_size
        preds = logits.argmax(dim=-1)
        correct += (preds == targets).sum().item()
        total_samples += batch_size

    epoch_time = time.perf_counter() - start_time
    avg_loss = total_loss / max(1, total_samples)
    accuracy = correct / max(1, total_samples)

    return avg_loss, accuracy, epoch_time


def run_staged_training(
    config: Dict[str, Any],
    train_manifest: Optional[List[Dict[str, Any]]] = None,
    val_manifest: Optional[List[Dict[str, Any]]] = None,
    test_manifest: Optional[List[Dict[str, Any]]] = None,
    drive_backup_dir: Optional[str] = None
) -> Dict[str, Any]:
    """
    Execute full staged training experiment according to config.
    """
    # 1. Config & Reproducibility
    seed = config.get("seed", 42)
    set_seed(seed)

    exp_name = config.get("experiment_name", "swin_v2_fft75_exp")
    output_dir = config.get("output_dir", f"experiments/{exp_name}")
    os.makedirs(output_dir, exist_ok=True)
    checkpoints_dir = os.path.join(output_dir, "checkpoints")
    os.makedirs(checkpoints_dir, exist_ok=True)

    # 2. Device Selection & Info
    device_name = config.get("device", "cuda")
    if device_name == "cuda" and not torch.cuda.is_available():
        device_name = "cpu"
    device = torch.device(device_name)
    
    print(f"\n=======================================================")
    print(f"  STARTING EXPERIMENT: {exp_name}")
    print(f"  Device: {device} | PyTorch: {torch.__version__}")
    if device.type == "cuda":
        print(f"  GPU: {torch.cuda.get_device_name(0)}")
        print(f"  VRAM: {torch.cuda.get_device_properties(0).total_memory / (1024**3):.2f} GB")
    print(f"=======================================================\n")

    # 3. Dataset Setup
    samples_per_class = config.get("samples_per_class", 100)
    fragment_size = config.get("fragment_size", 512)
    img_size = config.get("img_size", 256)

    if train_manifest is None or val_manifest is None:
        print(f"Generating synthetic dataset partition ({samples_per_class} samples/class)...")
        full_manifest = generate_synthetic_fragment_manifest(
            samples_per_class=samples_per_class,
            fragment_size=fragment_size,
            seed=seed
        )
        train_manifest, val_manifest, test_manifest = create_leak_free_split(
            full_manifest, train_ratio=0.8, val_ratio=0.1, test_ratio=0.1, seed=seed
        )

    print(f"Dataset summary: Train={len(train_manifest)} | Val={len(val_manifest)} | Test={len(test_manifest) if test_manifest else 0}")

    transform = Byte2ImageTransform(target_size=(img_size, img_size), normalize=True)
    batch_size = config.get("batch_size", 32)
    num_workers = config.get("num_workers", 0)

    loaders = create_fragment_dataloaders(
        train_manifest=train_manifest,
        val_manifest=val_manifest,
        test_manifest=test_manifest,
        transform=transform,
        batch_size=batch_size,
        num_workers=num_workers,
        fragment_size=fragment_size
    )

    # 4. Instantiate Model
    num_classes = config.get("num_classes", 75)
    pretrained = config.get("pretrained", True)
    model = SwinV2TinyGrayscale(
        num_classes=num_classes,
        pretrained=pretrained,
        img_size=img_size,
        in_chans=1,
        drop_rate=config.get("drop_rate", 0.1),
        drop_path_rate=config.get("drop_path_rate", 0.1)
    ).to(device)

    # Staged fine-tuning setup
    ft_stage = config.get("fine_tuning_stage", "A")
    model.set_fine_tuning_stage(ft_stage)

    # 5. Optimizer, Loss, and Scheduler
    lr = float(config.get("learning_rate", 1e-4))
    weight_decay = float(config.get("weight_decay", 0.05))
    epochs = int(config.get("epochs", 3))

    trainable_params = [p for p in model.parameters() if p.requires_grad]
    optimizer = AdamW(trainable_params, lr=lr, weight_decay=weight_decay)
    criterion = nn.CrossEntropyLoss(label_smoothing=config.get("label_smoothing", 0.05))

    total_steps = epochs * len(loaders["train"])
    warmup_steps = max(1, int(0.1 * total_steps))
    warmup_sched = LinearLR(optimizer, start_factor=0.1, total_iters=warmup_steps)
    cosine_sched = CosineAnnealingLR(optimizer, T_max=max(1, total_steps - warmup_steps), eta_min=1e-6)
    scheduler = SequentialLR(optimizer, schedulers=[warmup_sched, cosine_sched], milestones=[warmup_steps])

    use_amp = (device.type == "cuda")
    scaler = torch.amp.GradScaler(device_type="cuda") if use_amp else None

    # Save Experiment Config
    exp_config_path = os.path.join(output_dir, "experiment_config.json")
    with open(exp_config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    # 6. Training Loop
    history: Dict[str, List[float]] = {
        "train_loss": [], "train_acc": [],
        "val_loss": [], "val_acc": [], "val_macro_f1": [],
        "lr": [], "epoch_duration_sec": []
    }

    best_val_f1 = -1.0
    best_epoch = 0
    patience = config.get("early_stopping_patience", 3)
    patience_counter = 0

    print(f"Starting training: {epochs} epochs | Batch Size={batch_size} | Stage={ft_stage}")

    for epoch in range(1, epochs + 1):
        epoch_start_time = time.perf_counter()
        
        train_loss, train_acc, epoch_time = train_epoch(
            model=model,
            train_loader=loaders["train"],
            criterion=criterion,
            optimizer=optimizer,
            scaler=scaler,
            device=device,
            scheduler=scheduler
        )

        current_lr = optimizer.param_groups[0]["lr"]

        # Run Validation Evaluation
        val_metrics = evaluate_model(
            model=model,
            dataloader=loaders["val"],
            device=device,
            class_names=FFT75_CLASSES
        )

        val_acc = val_metrics["top1_accuracy"]
        val_macro_f1 = val_metrics["macro_f1"]

        # Compute validation loss
        val_loss = 0.0
        with torch.no_grad():
            for v_batch in loaders["val"]:
                v_inputs, v_targets = v_batch[0].to(device), v_batch[1].to(device)
                v_logits = model(v_inputs)
                val_loss += criterion(v_logits, v_targets).item() * v_inputs.size(0)
        val_loss /= max(1, len(val_manifest))

        history["train_loss"].append(train_loss)
        history["train_acc"].append(train_acc)
        history["val_loss"].append(val_loss)
        history["val_acc"].append(val_acc)
        history["val_macro_f1"].append(val_macro_f1)
        history["lr"].append(current_lr)
        history["epoch_duration_sec"].append(epoch_time)

        print(
            f"Epoch [{epoch:02d}/{epochs:02d}] "
            f"Train Loss: {train_loss:.4f} | Train Acc: {train_acc*100:.2f}% | "
            f"Val Loss: {val_loss:.4f} | Val Acc: {val_acc*100:.2f}% | "
            f"Val Macro-F1: {val_macro_f1:.4f} | Time: {epoch_time:.1f}s"
        )

        # Checkpoint Saving
        checkpoint_data = {
            "epoch": epoch,
            "model_state_dict": model.state_dict(),
            "optimizer_state_dict": optimizer.state_dict(),
            "best_val_macro_f1": val_macro_f1,
            "config": config
        }

        latest_ckpt_path = os.path.join(checkpoints_dir, "latest_model.pt")
        torch.save(checkpoint_data, latest_ckpt_path)

        if val_macro_f1 > best_val_f1:
            best_val_f1 = val_macro_f1
            best_epoch = epoch
            best_ckpt_path = os.path.join(checkpoints_dir, "best_model.pt")
            torch.save(checkpoint_data, best_ckpt_path)
            print(f"  --> Saved new best model checkpoint (Val Macro-F1: {val_macro_f1:.4f})")
            patience_counter = 0

            # Backup to Google Drive if configured
            if drive_backup_dir and os.path.exists(drive_backup_dir):
                shutil.copy(best_ckpt_path, os.path.join(drive_backup_dir, f"{exp_name}_best.pt"))
        else:
            patience_counter += 1
            if patience_counter >= patience and epoch >= 3:
                print(f"Early stopping triggered: Validation Macro-F1 has plateaued for {patience} epochs.")
                break

    # Save training curves plot and metrics history
    plot_training_history(history, output_dir, title_suffix=f"({exp_name})")
    with open(os.path.join(output_dir, "training_history.json"), "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)

    # 7. Final Test Evaluation (if test split exists)
    test_metrics = None
    if "test" in loaders and len(loaders["test"]) > 0:
        print("\nEvaluating best checkpoint on Test Split...")
        best_ckpt = torch.load(os.path.join(checkpoints_dir, "best_model.pt"), map_location=device, weights_only=False)
        model.load_state_dict(best_ckpt["model_state_dict"])
        test_metrics = evaluate_model(
            model=model,
            dataloader=loaders["test"],
            device=device,
            class_names=FFT75_CLASSES,
            output_dir=output_dir,
            prefix="test"
        )
        print(f"Test Top-1 Accuracy: {test_metrics['top1_accuracy']*100:.2f}% | Test Macro-F1: {test_metrics['macro_f1']:.4f}")

    return {
        "best_epoch": best_epoch,
        "best_val_macro_f1": best_val_f1,
        "history": history,
        "test_metrics": test_metrics,
        "checkpoints_dir": checkpoints_dir
    }
