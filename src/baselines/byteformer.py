"""
ByteFormer Baseline Reference and Literature Comparison Module.
Encapsulates published FFT-75 benchmark results and protocol comparisons.
"""

from typing import Dict, Any, List, Optional
import pandas as pd


# Official Published Literature Benchmarks for FFT-75 Scenario #1 (512-byte sectors, 75 classes)
PUBLISHED_BENCHMARKS: Dict[str, Dict[str, Any]] = {
    "ByteFormer": {
        "method": "ByteFormer (Transformer-based 1D)",
        "fragment_size": 512,
        "num_classes": 75,
        "top1_accuracy": 0.7250,  # ~72.5% Top-1 on 512-byte Scenario #1
        "top5_accuracy": 0.8840,
        "macro_f1": 0.7180,
        "source": "Published Literature (IEEE/arXiv FFT-75 Benchmark)",
        "evaluation_protocol": "FFT-75 Scenario #1 (Clean 512B sectors)",
        "is_measured": False
    },
    "FiFTy": {
        "method": "FiFTy (CNN Baseline)",
        "fragment_size": 512,
        "num_classes": 75,
        "top1_accuracy": 0.6520,
        "top5_accuracy": 0.8110,
        "macro_f1": 0.6390,
        "source": "Published Literature (FiFTy Benchmark)",
        "evaluation_protocol": "FFT-75 Scenario #1 (Clean 512B sectors)",
        "is_measured": False
    }
}


def create_comparison_table(
    our_measured_metrics: Optional[Dict[str, Any]] = None,
    include_fifty: bool = True
) -> pd.DataFrame:
    """
    Generate a standardized forensic baseline comparison table.
    Strictly distinguishes between Published Literature Values and Our Experimentally Measured Results.

    Args:
        our_measured_metrics: Metrics dict from evaluating our Byte2Image + Swin Transformer V2.
        include_fifty: Whether to include the older FiFTy CNN baseline.

    Returns:
        pd.DataFrame formatted for reporting and publication.
    """
    rows = []

    # 1. Add ByteFormer Baseline
    bf = PUBLISHED_BENCHMARKS["ByteFormer"]
    rows.append({
        "Method": bf["method"],
        "Fragment Size": f"{bf['fragment_size']} B",
        "Classes": bf["num_classes"],
        "Top-1 Accuracy": f"{bf['top1_accuracy']*100:.2f}%",
        "Top-5 Accuracy": f"{bf['top5_accuracy']*100:.2f}%",
        "Macro F1": f"{bf['macro_f1']:.4f}",
        "Inference Speed": "N/A (Published)",
        "Result Source": bf["source"],
        "Evaluation Protocol": bf["evaluation_protocol"]
    })

    # 2. Add FiFTy if requested
    if include_fifty:
        fifty = PUBLISHED_BENCHMARKS["FiFTy"]
        rows.append({
            "Method": fifty["method"],
            "Fragment Size": f"{fifty['fragment_size']} B",
            "Classes": fifty["num_classes"],
            "Top-1 Accuracy": f"{fifty['top1_accuracy']*100:.2f}%",
            "Top-5 Accuracy": f"{fifty['top5_accuracy']*100:.2f}%",
            "Macro F1": f"{fifty['macro_f1']:.4f}",
            "Inference Speed": "N/A (Published)",
            "Result Source": fifty["source"],
            "Evaluation Protocol": fifty["evaluation_protocol"]
        })

    # 3. Add Our Proposed Model (Experimentally Measured)
    if our_measured_metrics is not None:
        top1 = our_measured_metrics.get("top1_accuracy", 0.0)
        top5 = our_measured_metrics.get("top5_accuracy", 0.0)
        macro_f1 = our_measured_metrics.get("macro_f1", 0.0)
        latency = our_measured_metrics.get("latency_ms_per_fragment", 0.0)
        fps = our_measured_metrics.get("throughput_fps", 0.0)
        speed_str = f"{latency:.2f} ms/frag ({fps:.1f} fps)" if latency > 0 else "Measured"

        rows.append({
            "Method": "Our Byte2Image + Swin Transformer V2 (Tiny)",
            "Fragment Size": "512 B",
            "Classes": 75,
            "Top-1 Accuracy": f"{top1*100:.2f}%",
            "Top-5 Accuracy": f"{top5*100:.2f}%",
            "Macro F1": f"{macro_f1:.4f}",
            "Inference Speed": speed_str,
            "Result Source": "Our Measured Experimental Prototype",
            "Evaluation Protocol": "FFT-75 512B Split (Leak-Free Source Partition)"
        })

    df = pd.DataFrame(rows)
    return df
