"""
Evaluation Engine for File-Fragment Classification.
Runs rigorous evaluation over DataLoaders, measures latency/throughput,
and generates structured metric reports.
"""

from typing import Dict, Any, List, Optional, Tuple
import time
import torch
import torch.nn.functional as F
import numpy as np
from torch.utils.data import DataLoader

from src.datasets.fft75 import FFT75_CLASSES
from src.training.metrics import calculate_metrics, save_metrics_report, plot_confusion_matrix, plot_per_class_f1


def evaluate_model(
    model: torch.nn.Module,
    dataloader: DataLoader,
    device: torch.device,
    class_names: Optional[List[str]] = None,
    output_dir: Optional[str] = None,
    prefix: str = "eval"
) -> Dict[str, Any]:
    """
    Run full model evaluation on a DataLoader.

    Args:
        model: PyTorch model.
        dataloader: PyTorch DataLoader.
        device: Target execution device (cuda or cpu).
        class_names: List of class names (default FFT75_CLASSES).
        output_dir: If provided, saves JSON/CSV metrics and plots here.
        prefix: Prefix for output files.

    Returns:
        metrics_dict containing top-1, top-5, macro F1, confusion matrix, latency, etc.
    """
    if class_names is None:
        class_names = FFT75_CLASSES

    model.eval()
    all_targets: List[int] = []
    all_probs: List[np.ndarray] = []
    all_frag_ids: List[str] = []

    total_samples = 0
    start_time = time.perf_counter()

    use_amp = (device.type == "cuda")

    with torch.no_grad():
        for batch in dataloader:
            if len(batch) == 3:
                inputs, targets, frag_ids = batch
            else:
                inputs, targets = batch[:2]
                frag_ids = [f"frag_{i}" for i in range(len(targets))]

            inputs = inputs.to(device, non_blocking=True)
            batch_size = inputs.size(0)
            total_samples += batch_size

            if use_amp:
                with torch.amp.autocast(device_type="cuda", dtype=torch.float16):
                    logits = model(inputs)
            else:
                logits = model(inputs)

            probs = F.softmax(logits, dim=-1).cpu().numpy()
            
            all_targets.extend(targets.numpy().tolist() if isinstance(targets, torch.Tensor) else targets)
            all_probs.append(probs)
            all_frag_ids.extend(frag_ids)

    total_eval_time = time.perf_counter() - start_time
    latency_ms = (total_eval_time / max(1, total_samples)) * 1000.0
    throughput_fps = total_samples / max(1e-6, total_eval_time)

    y_true = np.array(all_targets, dtype=np.int64)
    y_pred_probs = np.vstack(all_probs) if len(all_probs) > 0 else np.zeros((0, len(class_names)))

    metrics = calculate_metrics(
        y_true=y_true,
        y_pred_probs=y_pred_probs,
        class_names=class_names,
        latency_ms_per_fragment=latency_ms,
        throughput_fps=throughput_fps
    )

    if output_dir:
        save_metrics_report(metrics, output_dir=output_dir, prefix=prefix)
        # Generate visual plots
        cm_array = np.array(metrics["confusion_matrix"])
        plot_confusion_matrix(
            cm_array,
            class_names=class_names,
            output_path=f"{output_dir}/{prefix}_confusion_matrix.png"
        )
        plot_per_class_f1(
            metrics["per_class"],
            output_path=f"{output_dir}/{prefix}_per_class_f1.png"
        )

    return metrics
