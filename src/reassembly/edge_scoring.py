"""
Modular Multi-Component Edge Scoring for Fragment Reassembly.
Combines Type Compatibility, Classifier Confidence, Boundary Seam Continuity,
Format Structural Priors, and Filesystem Locality.
"""

from typing import Dict, Any, Tuple, Optional, List
import math
import numpy as np

from src.datasets.fft75 import MAGIC_SIGNATURES, CATEGORY_MAP
from src.reassembly.graph import FragmentNode, ReassemblyGraph


# Known EOF Signatures indicating end-of-file
EOF_SIGNATURES = {
    "pdf": [b"%%EOF"],
    "jpg": [b"\xFF\xD9"],
    "png": [b"IEND\xaeB`\x82"],
    "zip": [b"PK\x05\x06"],
    "docx": [b"PK\x05\x06"],
    "xlsx": [b"PK\x05\x06"],
    "pptx": [b"PK\x05\x06"]
}


class EdgeWeightConfig:
    """Configurable weights for the multi-component edge scoring function."""

    def __init__(
        self,
        w_type: float = 0.35,
        w_conf: float = 0.15,
        w_boundary: float = 0.30,
        w_format: float = 0.15,
        w_locality: float = 0.05
    ):
        self.w_type = w_type
        self.w_conf = w_conf
        self.w_boundary = w_boundary
        self.w_format = w_format
        self.w_locality = w_locality

    def normalize(self):
        total = self.w_type + self.w_conf + self.w_boundary + self.w_format + self.w_locality
        if total > 0:
            self.w_type /= total
            self.w_conf /= total
            self.w_boundary /= total
            self.w_format /= total
            self.w_locality /= total


def score_type_compatibility(u: FragmentNode, v: FragmentNode) -> float:
    """
    Score compatibility based on predicted file format classes and probability distributions.
    """
    if u.predicted_class == v.predicted_class:
        base_score = 0.8
    else:
        # Category matching fallback (e.g., both are Document or Code)
        cat_u = CATEGORY_MAP.get(u.predicted_class, "Unknown_U")
        cat_v = CATEGORY_MAP.get(v.predicted_class, "Unknown_V")
        base_score = 0.4 if cat_u == cat_v else 0.0

    # Cross-entropy / dot product of shared probability distributions if present
    shared_classes = set(u.probabilities.keys()).intersection(set(v.probabilities.keys()))
    if shared_classes:
        vec_u = np.array([u.probabilities[c] for c in shared_classes])
        vec_v = np.array([v.probabilities[c] for c in shared_classes])
        norm_u, norm_v = np.linalg.norm(vec_u), np.linalg.norm(vec_v)
        if norm_u > 1e-6 and norm_v > 1e-6:
            cos_sim = float(np.dot(vec_u, vec_v) / (norm_u * norm_v))
            return 0.5 * base_score + 0.5 * cos_sim

    return base_score


def score_confidence(u: FragmentNode, v: FragmentNode) -> float:
    """Joint confidence score."""
    return float(math.sqrt(max(1e-6, u.confidence * v.confidence)))


def compute_byte_entropy(data: bytes) -> float:
    """Compute Shannon entropy for a byte slice."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / len(data)
    return float(-np.sum(probs * np.log2(probs)))


def score_byte_boundary(u: FragmentNode, v: FragmentNode, seam_window: int = 16) -> float:
    """
    Evaluate continuity across the 512-byte seam: tail of u -> head of v.
    Analyzes:
    1. Entropy continuity between u's tail and v's head.
    2. Byte value delta smoothly transitioning across boundary seam.
    3. Ascii / text consistency if text format.
    """
    tail_u = u.raw_bytes[-seam_window:]
    head_v = v.raw_bytes[:seam_window]

    if not tail_u or not head_v:
        return 0.5

    # 1. Entropy diff across seam
    ent_u = compute_byte_entropy(tail_u)
    ent_v = compute_byte_entropy(head_v)
    ent_diff = abs(ent_u - ent_v)
    ent_score = max(0.0, 1.0 - (ent_diff / 4.0))  # Max entropy is 8.0

    # 2. Seam byte delta: |u[-1] - v[0]|
    last_byte = tail_u[-1]
    first_byte = head_v[0]
    byte_delta = abs(int(last_byte) - int(first_byte))
    delta_score = max(0.0, 1.0 - (byte_delta / 255.0))

    # 3. Text continuity bonus
    is_text_u = all(32 <= b <= 126 or b in [9, 10, 13] for b in tail_u)
    is_text_v = all(32 <= b <= 126 or b in [9, 10, 13] for b in head_v)
    text_bonus = 0.2 if (is_text_u and is_text_v) else 0.0

    boundary_score = np.clip(0.5 * ent_score + 0.3 * delta_score + text_bonus, 0.0, 1.0)
    return float(boundary_score)


def score_format_structure(u: FragmentNode, v: FragmentNode) -> float:
    """
    Check structural constraints:
    - If v contains a known header signature at offset 0, it CANNOT be a successor (score = -1.0).
    - If u contains a known EOF signature, it CANNOT have a successor (score = -1.0).
    """
    # Check if v is a file header
    for cls_name, sigs in MAGIC_SIGNATURES.items():
        for sig in sigs:
            if v.raw_bytes.startswith(sig):
                return -1.0  # Header cannot be in middle or end

    # Check if u contains EOF marker (and is not also the header fragment)
    u_is_header = any(u.raw_bytes.startswith(sig) for sigs in MAGIC_SIGNATURES.values() for sig in sigs)
    for cls_name, sigs in EOF_SIGNATURES.items():
        for sig in sigs:
            if sig in u.raw_bytes and not u_is_header:
                return -1.0  # Terminal EOF fragment cannot precede another fragment

    return 0.5  # Neutral valid structure transition


def score_locality(u: FragmentNode, v: FragmentNode, default_fragment_size: int = 512) -> float:
    """
    Filesystem sector offset locality prior.
    """
    if u.source_offset is not None and v.source_offset is not None:
        expected_next = u.source_offset + u.fragment_size
        offset_diff = abs(v.source_offset - expected_next)
        if offset_diff == 0:
            return 1.0  # Exact contiguous adjacent sector on disk
        elif offset_diff <= default_fragment_size * 4:
            return 0.7  # Nearby cluster
        else:
            return max(0.0, 1.0 - (offset_diff / (default_fragment_size * 64)))
    return 0.5  # Locality neutral when metadata absent


def compute_edge_score(
    u: FragmentNode,
    v: FragmentNode,
    config: Optional[EdgeWeightConfig] = None
) -> Tuple[float, Dict[str, float]]:
    """
    Compute combined directed edge compatibility score for u -> v.
    """
    if config is None:
        config = EdgeWeightConfig()

    s_struct = score_format_structure(u, v)
    if s_struct < 0:
        # Hard structural constraint violation
        return -1.0, {"struct": s_struct}

    s_type = score_type_compatibility(u, v)
    s_conf = score_confidence(u, v)
    s_bound = score_byte_boundary(u, v)
    s_local = score_locality(u, v)

    total_score = (
        config.w_type * s_type +
        config.w_conf * s_conf +
        config.w_boundary * s_bound +
        config.w_format * s_struct +
        config.w_locality * s_local
    )

    breakdown = {
        "type_score": s_type,
        "conf_score": s_conf,
        "boundary_score": s_bound,
        "struct_score": s_struct,
        "locality_score": s_local
    }

    return float(np.clip(total_score, 0.0, 1.0)), breakdown


def build_complete_reassembly_graph(
    fragments: List[FragmentNode],
    config: Optional[EdgeWeightConfig] = None,
    min_edge_threshold: float = 0.05
) -> ReassemblyGraph:
    """
    Construct fully-connected directed candidate graph for a set of fragments.
    """
    graph = ReassemblyGraph()
    for frag in fragments:
        graph.add_fragment(frag)

    n = len(fragments)
    for i in range(n):
        for j in range(n):
            if i == j:
                continue
            u, v = fragments[i], fragments[j]
            score, breakdown = compute_edge_score(u, v, config)
            if score >= min_edge_threshold:
                graph.add_edge(u.fragment_id, v.fragment_id, score, breakdown)

    return graph
