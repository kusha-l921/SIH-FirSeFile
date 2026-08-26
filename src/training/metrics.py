"""
Comprehensive Forensic Classification Metrics and Plotting Tools.
Calculates Top-1, Top-5, Macro/Weighted F1, Per-Class metrics, Confusion Matrix,
and generates publication-quality visualization plots.
"""

from typing import Dict, Any, List, Optional, Tuple
import os
import json
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, top_k_accuracy_score, precision_recall_fscore_support,
    confusion_matrix, classification_report
)

from src.datasets.fft75 import FFT75_CLASSES, IDX_TO_CLASS, get_class_name


def calculate_metrics(
    y_true: np.ndarray,
    y_pred_probs: np.ndarray,
    class_names: Optional[List[str]] = None,
    latency_ms_per_fragment: float = 0.0,
    throughput_fps: float = 0.0
) -> Dict[str, Any]:
    """
    Compute full suite of classification and performance metrics.
    """
    if class_names is None:
        class_names = FFT75_CLASSES

    num_classes = len(class_names)
    y_pred = np.argmax(y_pred_probs, axis=1)

    # 1. Top-1 Accuracy
    top1_acc = float(accuracy_score(y_true, y_pred))

    # 2. Top-5 Accuracy
    labels_all = np.arange(num_classes)
    try:
        top5_acc = float(top_k_accuracy_score(y_true, y_pred_probs, k=min(5, num_classes), labels=labels_all))
    except Exception:
        top5_acc = top1_acc

    # 3. Macro & Weighted Metrics
    precision_macro, recall_macro, f1_macro, _ = precision_recall_fscore_support(
        y_true, y_pred, average="macro", zero_division=0
    )
    precision_weighted, recall_weighted, f1_weighted, _ = precision_recall_fscore_support(
        y_true, y_pred, average="weighted", zero_division=0
    )

    # 4. Per-Class Metrics
    p_per_class, r_per_class, f1_per_class, support_per_class = precision_recall_fscore_support(
        y_true, y_pred, labels=labels_all, average=None, zero_division=0
    )

    per_class_metrics = {}
    for idx, name in enumerate(class_names):
        per_class_metrics[name] = {
            "precision": float(p_per_class[idx]),
            "recall": float(r_per_class[idx]),
            "f1": float(f1_per_class[idx]),
            "support": int(support_per_class[idx])
        }

    # 5. Confusion Matrix
    cm = confusion_matrix(y_true, y_pred, labels=labels_all)

    metrics_dict = {
        "top1_accuracy": top1_acc,
        "top5_accuracy": top5_acc,
        "macro_precision": float(precision_macro),
        "macro_recall": float(recall_macro),
        "macro_f1": float(f1_macro),
        "weighted_f1": float(f1_weighted),
        "latency_ms_per_fragment": latency_ms_per_fragment,
        "throughput_fps": throughput_fps,
        "per_class": per_class_metrics,
        "confusion_matrix": cm.tolist()
    }

    return metrics_dict


def save_metrics_report(
    metrics: Dict[str, Any],
    output_dir: str,
    prefix: str = "eval"
) -> Tuple[str, str]:
    """
    Save metrics to JSON and CSV formats.
    """
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, f"{prefix}_metrics.json")
    csv_path = os.path.join(output_dir, f"{prefix}_per_class_metrics.csv")

    # Save JSON summary
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    # Save Per-Class CSV
    per_class_data = []
    for cls_name, vals in metrics.get("per_class", {}).items():
        row = {"class_name": cls_name}
        row.update(vals)
        per_class_data.append(row)

    df_per_class = pd.DataFrame(per_class_data)
    df_per_class.to_csv(csv_path, index=False)

    return json_path, csv_path


def plot_training_history(
    history: Dict[str, List[float]],
    output_dir: str,
    title_suffix: str = ""
):
    """
    Plot and save training/validation loss and accuracy curves.
    """
    os.makedirs(output_dir, exist_ok=True)
    epochs = range(1, len(history.get("train_loss", [])) + 1)
    if not epochs:
        return

    plt.figure(figsize=(12, 5))

    # Loss subplot
    plt.subplot(1, 2, 1)
    plt.plot(epochs, history.get("train_loss", []), "o-", label="Train Loss", color="#1f77b4")
    if "val_loss" in history:
        plt.plot(epochs, history.get("val_loss", []), "s--", label="Val Loss", color="#ff7f0e")
    plt.xlabel("Epoch")
    plt.ylabel("Loss")
    plt.title(f"Loss Curves {title_suffix}")
    plt.grid(True, alpha=0.3)
    plt.legend()

    # Accuracy subplot
    plt.subplot(1, 2, 2)
    plt.plot(epochs, history.get("train_acc", []), "o-", label="Train Top-1", color="#2ca02c")
    if "val_acc" in history:
        plt.plot(epochs, history.get("val_acc", []), "s--", label="Val Top-1", color="#d62728")
    if "val_macro_f1" in history:
        plt.plot(epochs, history.get("val_macro_f1", []), "^-.", label="Val Macro-F1", color="#9467bd")
    plt.xlabel("Epoch")
    plt.ylabel("Accuracy / F1")
    plt.title(f"Validation Metrics {title_suffix}")
    plt.grid(True, alpha=0.3)
    plt.legend()

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "training_curves.png"), dpi=300)
    plt.close()


def plot_confusion_matrix(
    cm_array: np.ndarray,
    class_names: List[str],
    output_path: str,
    top_n_classes: int = 25
):
    """
    Plot confusion matrix heatmap (can focus on top N classes for readability).
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    
    if len(class_names) > top_n_classes:
        # Show top N most frequent/active classes
        sub_cm = cm_array[:top_n_classes, :top_n_classes]
        sub_names = class_names[:top_n_classes]
    else:
        sub_cm = cm_array
        sub_names = class_names

    plt.figure(figsize=(14, 12))
    sns.heatmap(
        sub_cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=sub_names,
        yticklabels=sub_names,
        cbar=True
    )
    plt.xlabel("Predicted Class")
    plt.ylabel("True Class")
    plt.title(f"Confusion Matrix (Top {len(sub_names)} FFT-75 Classes)")
    plt.xticks(rotation=45, ha="right")
    plt.yticks(rotation=0)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()


def plot_per_class_f1(
    per_class_metrics: Dict[str, Dict[str, float]],
    output_path: str,
    top_n: int = 30
):
    """
    Plot horizontal bar chart of F1-scores per file format.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    
    items = sorted(per_class_metrics.items(), key=lambda x: x[1].get("f1", 0.0), reverse=True)
    if len(items) > top_n:
        items = items[:top_n]

    classes = [it[0] for it in items][::-1]
    f1_scores = [it[1].get("f1", 0.0) for it in items][::-1]

    plt.figure(figsize=(10, 12))
    colors = plt.cm.viridis(np.linspace(0.2, 0.9, len(classes)))
    plt.barh(classes, f1_scores, color=colors)
    plt.xlabel("Macro F1-Score")
    plt.ylabel("File Class")
    plt.title(f"Top-{len(classes)} File Format Classification F1-Scores")
    plt.xlim(0, 1.05)
    plt.grid(axis="x", alpha=0.3)
    
    for i, v in enumerate(f1_scores):
        plt.text(v + 0.01, i, f"{v:.2f}", va="center", fontsize=8)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()
