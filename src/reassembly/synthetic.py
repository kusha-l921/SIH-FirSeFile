"""
Synthetic Reassembly Ground-Truth Generator and Benchmark Suite.
Validates graph reassembly against known files with exact metric tracking.
"""

from typing import List, Dict, Any, Tuple, Optional
import random
import hashlib
import numpy as np

from src.reassembly.graph import FragmentNode, ReassemblyGraph
from src.reassembly.edge_scoring import EdgeWeightConfig, build_complete_reassembly_graph
from src.reassembly.ordering import order_fragments_beam_search
from src.reassembly.reconstruct import reconstruct_file_from_ordering, ReconstructionResult


def fragment_file(
    file_bytes: bytes,
    file_class: str,
    file_id: str = "file_01",
    fragment_size: int = 512,
    simulated_confidence: float = 0.92
) -> Tuple[List[FragmentNode], List[str]]:
    """
    Split a known file into ordered fragments and create ground-truth FragmentNodes.

    Returns:
        fragments: List[FragmentNode]
        ground_truth_order: List of fragment_ids in true sequence
    """
    n_bytes = len(file_bytes)
    n_frags = (n_bytes + fragment_size - 1) // fragment_size
    fragments = []
    ground_truth_order = []

    for i in range(n_frags):
        start = i * fragment_size
        end = min(start + fragment_size, n_bytes)
        chunk = file_bytes[start:end]

        # Pad last chunk if needed
        if len(chunk) < fragment_size:
            chunk = chunk.ljust(fragment_size, b"\x00")

        frag_id = f"{file_id}_frag_{i:03d}"
        ground_truth_order.append(frag_id)

        node = FragmentNode(
            fragment_id=frag_id,
            raw_bytes=chunk,
            predicted_class=file_class,
            confidence=simulated_confidence,
            source_offset=start
        )
        fragments.append(node)

    return fragments, ground_truth_order


def evaluate_reassembly(
    predicted_order: List[str],
    ground_truth_order: List[str],
    reconstructed_bytes: bytes,
    original_bytes: bytes
) -> Dict[str, Any]:
    """
    Calculate rigorous reassembly benchmarks:
    - Exact Sequence Accuracy (boolean 1.0 or 0.0)
    - Pairwise Adjacency Accuracy (fraction of correct (u, v) pairs)
    - Position Placement Percentage (fraction of items at correct index)
    - Reconstructed Byte Accuracy (byte-for-byte match percentage)
    """
    n_true = len(ground_truth_order)
    n_pred = len(predicted_order)

    # 1. Exact Sequence Accuracy
    exact_sequence_match = float(predicted_order == ground_truth_order)

    # 2. Pairwise Adjacency Accuracy
    true_pairs = set()
    for i in range(n_true - 1):
        true_pairs.add((ground_truth_order[i], ground_truth_order[i + 1]))

    pred_pairs = set()
    for i in range(n_pred - 1):
        pred_pairs.add((predicted_order[i], predicted_order[i + 1]))

    if len(true_pairs) > 0:
        correct_pairs = len(true_pairs.intersection(pred_pairs))
        pairwise_adjacency_acc = float(correct_pairs / len(true_pairs))
    else:
        pairwise_adjacency_acc = 1.0

    # 3. Position Placement Percentage
    correct_positions = 0
    for idx in range(min(n_true, n_pred)):
        if predicted_order[idx] == ground_truth_order[idx]:
            correct_positions += 1
    position_accuracy = float(correct_positions / max(1, n_true))

    # 4. Byte Accuracy
    min_len = min(len(original_bytes), len(reconstructed_bytes))
    matching_bytes = sum(1 for i in range(min_len) if original_bytes[i] == reconstructed_bytes[i])
    byte_accuracy = float(matching_bytes / max(1, len(original_bytes)))

    return {
        "exact_sequence_accuracy": exact_sequence_match,
        "pairwise_adjacency_accuracy": round(pairwise_adjacency_acc, 4),
        "position_accuracy": round(position_accuracy, 4),
        "byte_accuracy": round(byte_accuracy, 4),
        "fragment_count": n_true
    }


import io
import zipfile
from PIL import Image


def generate_multifragment_test_file(
    format_name: str,
    n_fragments: int,
    fragment_size: int = 512,
    seed: int = 42
) -> bytes:
    """
    Generate an authentic, structurally valid multi-fragment binary file whose
    header is in fragment 0, content spans fragments 1..N-2, and trailer/EOF is in fragment N-1.
    """
    target_size = n_fragments * fragment_size
    rng = random.Random(seed)
    fmt = format_name.lower()

    if fmt == "pdf":
        header = b"%PDF-1.4\n"
        body_parts = []
        for p in range(1, max(2, n_fragments)):
            stream_data = f"Page {p} forensic object payload: ".encode("ascii") + bytes(rng.choices(range(65, 90), k=fragment_size - 80)) + b"\n"
            obj = f"{p} 0 obj<</Length {len(stream_data)}>>stream\n".encode("ascii") + stream_data + b"endstream\nendobj\n"
            body_parts.append(obj)
        body = b"".join(body_parts)
        trailer = b"xref\n0 10\ntrailer<</Size 10/Root 1 0 R>>\nstartxref\n500\n%%EOF\n"
        content = header + body + trailer
        if len(content) < target_size:
            pad = b" " * (target_size - len(content))
            content = header + body + pad + trailer
        return content[:target_size]

    elif fmt in ["zip", "docx"]:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            for f_idx in range(max(1, n_fragments - 1)):
                zf.writestr(f"evidence_{f_idx:03d}.dat", bytes(rng.choices(range(32, 126), k=fragment_size - 80)))
        data = buf.getvalue()
        if len(data) < target_size:
            data = data.ljust(target_size, b" ")
        return data[:target_size]

    elif fmt == "png":
        dim = max(16, int(np.sqrt((target_size * 2) / 3)) + 8)
        img = Image.new("RGB", (dim, dim), color="blue")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        data = buf.getvalue()
        if len(data) < target_size:
            data = data.ljust(target_size, b"\x00")
        return data[:target_size]

    elif fmt in ["sh", "py"]:
        lines = ["#!/bin/bash", "# Digital Forensics Multi-Fragment Script", "set -e"]
        while sum(len(line) + 1 for line in lines) < target_size - 60:
            lines.append(f"echo 'Analyzing block {len(lines)}' && true")
        lines.append("exit 0\n")
        data = "\n".join(lines).encode("utf-8")
        if len(data) < target_size:
            data = data.ljust(target_size, b"\n")
        return data[:target_size]

    elif fmt in ["sqlite", "db"]:
        header = bytearray(b"SQLite format 3\x00" + b"\x00" * 84)
        header[16] = 0x02  # page size 512
        header[17] = 0x00
        header[18] = 0x01
        header[19] = 0x01
        pages = [bytes(header)]
        for p_idx in range(1, n_fragments):
            page_data = bytes([0x0D, 0x00, 0x00, 0x00]) + bytes(rng.choices(range(256), k=508))
            pages.append(page_data)
        return b"".join(pages)[:target_size]

    else:
        return bytes(rng.choices(range(256), k=target_size))


def run_reassembly_experiment(
    sample_files: Optional[Dict[str, bytes]] = None,
    fragment_counts: List[int] = [3, 5, 10, 20],
    formats: Optional[List[str]] = None,
    seed: int = 42
) -> Dict[str, Any]:
    """
    Run automated reassembly evaluation across multiple formats and fragment counts.
    """
    if formats is None:
        formats = ["pdf", "zip", "png", "sh", "sqlite"]

    rng = random.Random(seed)
    results_by_count: Dict[int, List[Dict[str, Any]]] = {k: [] for k in fragment_counts}

    for fmt in formats:
        for n_frags in fragment_counts:
            if sample_files and fmt in sample_files and len(sample_files[fmt]) >= n_frags * 512:
                test_bytes = sample_files[fmt][:n_frags * 512]
            else:
                test_bytes = generate_multifragment_test_file(fmt, n_fragments=n_frags, seed=seed + n_frags)

            frags, gt_order = fragment_file(
                test_bytes,
                file_class=fmt,
                file_id=f"test_{fmt}_{n_frags}",
                fragment_size=512
            )

            # Shuffle fragments to simulate orphaned unordered pool
            shuffled_frags = frags.copy()
            rng.shuffle(shuffled_frags)

            # Build graph and order
            graph = build_complete_reassembly_graph(shuffled_frags)
            ordered_ids, score, conf, unused = order_fragments_beam_search(graph, beam_width=5)
            recon = reconstruct_file_from_ordering(ordered_ids, graph, score, conf, unused)

            metrics = evaluate_reassembly(
                predicted_order=ordered_ids,
                ground_truth_order=gt_order,
                reconstructed_bytes=recon.reconstructed_bytes,
                original_bytes=test_bytes
            )
            metrics["format"] = fmt
            results_by_count[n_frags].append(metrics)

    # Compute aggregate summary
    summary = {}
    for n_frags, metric_list in results_by_count.items():
        summary[n_frags] = {
            "exact_seq_acc": float(np.mean([m["exact_sequence_accuracy"] for m in metric_list])),
            "pairwise_adj_acc": float(np.mean([m["pairwise_adjacency_accuracy"] for m in metric_list])),
            "position_acc": float(np.mean([m["position_accuracy"] for m in metric_list])),
            "byte_acc": float(np.mean([m["byte_accuracy"] for m in metric_list])),
            "total_runs": len(metric_list)
        }

    return {"summary": summary, "details": results_by_count}
