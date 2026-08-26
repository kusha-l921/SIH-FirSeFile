"""
ml_pipeline.py
==============
Clean interface for the FirSeFile ML pipeline.

Pipeline:
  raw 512-byte fragment
    -> Byte2Image (497x128 native, resized 256x256)
    -> Swin Transformer V2 Tiny
    -> FragmentClassification
    -> FragmentNode (graph node)
    -> Graph-Based Reassembly (edge scoring + beam search)
    -> ReconstructionResult
    -> ForensicValidationReport

Each stage is independently callable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import hashlib

from src.models.classifier import FragmentClassifier
from src.models.zero_training_classifier import ZeroTrainingClassifier
from src.reassembly.graph import FragmentNode, ReassemblyGraph
from src.reassembly.edge_scoring import build_complete_reassembly_graph, EdgeWeightConfig
from src.reassembly.ordering import order_fragments_beam_search
from src.reassembly.reconstruct import reconstruct_file_from_ordering, ReconstructionResult
from src.validation.validator import validate_reconstructed_file, ForensicValidationReport


# ---------------------------------------------------------------------------
# ML Input / Output contracts
# ---------------------------------------------------------------------------

@dataclass
class FragmentInput:
    """Input contract for a single fragment entering the ML pipeline."""
    fragment_id: str
    raw_bytes: bytes          # exactly 512 bytes (padded/truncated internally)
    source_offset: Optional[int] = None
    filesystem_source: Optional[str] = None


@dataclass
class FragmentClassificationResult:
    """Output contract from the ML classification stage."""
    fragment_id: str
    predicted_class: str
    confidence: float
    entropy: float
    top_k: List[Tuple[str, float]]   # [(class_name, probability), ...]
    all_probabilities: Dict[str, float]
    model_info: str
    checkpoint: Optional[str] = None


@dataclass
class ReassemblyResult:
    """Output contract from the graph reassembly stage."""
    ordered_fragment_ids: List[str]
    reconstructed_bytes: bytes
    sha256: str
    graph_score: float
    reconstruction_confidence: float
    detected_primary_type: str
    unused_fragment_ids: List[str]
    fragment_count: int
    total_size_bytes: int


@dataclass
class PipelineResult:
    """Full end-to-end pipeline output."""
    classifications: List[FragmentClassificationResult]
    reassembly: Optional[ReassemblyResult]
    validation: Optional[Dict[str, Any]]
    ledger_payload: Dict[str, Any]


# ---------------------------------------------------------------------------
# Stage 1: ML Classification
# ---------------------------------------------------------------------------

def classify_fragment(
    fragment: FragmentInput,
    classifier: Optional[FragmentClassifier] = None,
    zero_training: bool = False,
    top_k: int = 5,
) -> FragmentClassificationResult:
    """
    Classify a single 512-byte fragment.

    Args:
        fragment: FragmentInput with raw bytes and metadata.
        classifier: Optional pre-loaded FragmentClassifier (Swin V2).
                    If None and zero_training=False, uses untrained Swin V2.
        zero_training: Use deterministic zero-training classifier instead.
        top_k: Number of top predictions to return.

    Returns:
        FragmentClassificationResult
    """
    raw = fragment.raw_bytes[:512].ljust(512, b"\x00")

    if zero_training:
        zt = ZeroTrainingClassifier()
        pred = zt.predict_fragment(raw)
        return FragmentClassificationResult(
            fragment_id=fragment.fragment_id,
            predicted_class=pred.predicted_class,
            confidence=pred.confidence,
            entropy=pred.entropy,
            top_k=pred.top5[:top_k],
            all_probabilities={cls: float(p) for cls, p in pred.top5},
            model_info="Zero-Training Hierarchical Forensic Engine",
            checkpoint=None,
        )

    clf = classifier or FragmentClassifier()
    result = clf.predict_fragment(raw, top_k=top_k)
    return FragmentClassificationResult(
        fragment_id=fragment.fragment_id,
        predicted_class=result["predicted_class"],
        confidence=result["confidence"],
        entropy=result["entropy"],
        top_k=list(zip(result["top_k_classes"], result["top_k_probabilities"])),
        all_probabilities=result["all_probabilities"],
        model_info="Byte2Image + Swin Transformer V2 Tiny",
        checkpoint=getattr(clf, "_checkpoint_path", None),
    )


def classify_fragments(
    fragments: List[FragmentInput],
    classifier: Optional[FragmentClassifier] = None,
    zero_training: bool = False,
    top_k: int = 5,
) -> List[FragmentClassificationResult]:
    """Classify a list of fragments. Uses batch inference for Swin V2."""
    if not fragments:
        return []

    if zero_training:
        return [classify_fragment(f, zero_training=True, top_k=top_k) for f in fragments]

    clf = classifier or FragmentClassifier()
    raw_list = [f.raw_bytes[:512].ljust(512, b"\x00") for f in fragments]
    batch_results = clf.predict_batch(raw_list, top_k=top_k)

    out = []
    for frag, result in zip(fragments, batch_results):
        out.append(FragmentClassificationResult(
            fragment_id=frag.fragment_id,
            predicted_class=result["predicted_class"],
            confidence=result["confidence"],
            entropy=result["entropy"],
            top_k=list(zip(result["top_k_classes"], result["top_k_probabilities"])),
            all_probabilities=result["all_probabilities"],
            model_info="Byte2Image + Swin Transformer V2 Tiny",
            checkpoint=None,
        ))
    return out


# ---------------------------------------------------------------------------
# Stage 2: Graph-Based Reassembly
# ---------------------------------------------------------------------------

def build_fragment_nodes(
    fragments: List[FragmentInput],
    classifications: List[FragmentClassificationResult],
) -> List[FragmentNode]:
    """Convert classified fragments into FragmentNode objects for the graph."""
    nodes = []
    for frag, cls_result in zip(fragments, classifications):
        node = FragmentNode(
            fragment_id=frag.fragment_id,
            raw_bytes=frag.raw_bytes[:512].ljust(512, b"\x00"),
            predicted_class=cls_result.predicted_class,
            confidence=cls_result.confidence,
            probabilities=cls_result.all_probabilities,
            source_offset=frag.source_offset,
            filesystem_source=frag.filesystem_source,
            entropy=cls_result.entropy,
        )
        nodes.append(node)
    return nodes


def reassemble_fragments(
    fragment_nodes: List[FragmentNode],
    edge_config: Optional[EdgeWeightConfig] = None,
    beam_width: int = 5,
    min_edge_threshold: float = 0.05,
) -> ReassemblyResult:
    """
    Run graph-based reassembly on a list of classified FragmentNodes.

    Args:
        fragment_nodes: List of FragmentNode objects (from build_fragment_nodes).
        edge_config: Optional EdgeWeightConfig for scoring weights.
        beam_width: Beam search width.
        min_edge_threshold: Minimum edge score to include in graph.

    Returns:
        ReassemblyResult
    """
    graph = build_complete_reassembly_graph(
        fragment_nodes,
        config=edge_config,
        min_edge_threshold=min_edge_threshold,
    )
    ordered_ids, graph_score, avg_conf, unused = order_fragments_beam_search(
        graph, beam_width=beam_width
    )
    recon = reconstruct_file_from_ordering(
        ordered_ids, graph, graph_score, avg_conf, unused
    )
    return ReassemblyResult(
        ordered_fragment_ids=recon.ordered_fragment_ids,
        reconstructed_bytes=recon.reconstructed_bytes,
        sha256=recon.sha256,
        graph_score=recon.graph_score,
        reconstruction_confidence=recon.reconstruction_confidence,
        detected_primary_type=recon.detected_primary_type,
        unused_fragment_ids=recon.unused_fragment_ids,
        fragment_count=len(recon.ordered_fragment_ids),
        total_size_bytes=recon.total_size,
    )


# ---------------------------------------------------------------------------
# Stage 3: Format Validation
# ---------------------------------------------------------------------------

def validate_reconstruction(
    reassembly: ReassemblyResult,
    provenance: Optional[Dict[str, Any]] = None,
) -> ForensicValidationReport:
    """Validate the reconstructed file bytes for format integrity."""
    return validate_reconstructed_file(
        reassembly.reconstructed_bytes,
        expected_format=reassembly.detected_primary_type,
        provenance=provenance,
    )


# ---------------------------------------------------------------------------
# Stage 4: Blockchain Ledger Payload Builder
# ---------------------------------------------------------------------------

def build_ledger_payload(
    reassembly: ReassemblyResult,
    validation: ForensicValidationReport,
    classifications: List[FragmentClassificationResult],
    recovery_method: str = "ml_graph_reassembly",
    source_location: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build the blockchain ledger payload from ML/reassembly/validation results.

    Matches the full_recovery block type schema required by blockchain_ledger_core.
    """
    top_class = reassembly.detected_primary_type
    avg_conf = reassembly.reconstruction_confidence

    return {
        "filename": f"reconstructed.{top_class}",
        "macb_timestamps": {
            "modified": None,
            "accessed": None,
            "created": None,
        },
        "recovered_file_sha256": reassembly.sha256,
        "size": reassembly.total_size_bytes,
        "source_location": source_location or f"fragments:{','.join(reassembly.ordered_fragment_ids[:3])}",
        "recovery_method": recovery_method,
        # Extended ML provenance (stored as extra fields in payload)
        "ml_metadata": {
            "detected_type": top_class,
            "reconstruction_confidence": round(avg_conf, 4),
            "graph_score": round(reassembly.graph_score, 4),
            "fragment_count": reassembly.fragment_count,
            "ordered_fragment_ids": reassembly.ordered_fragment_ids,
            "unused_fragment_ids": reassembly.unused_fragment_ids,
            "validation_status": validation.status,
            "validation_is_valid": validation.is_valid,
            "top_classifications": [
                {
                    "fragment_id": c.fragment_id,
                    "predicted_class": c.predicted_class,
                    "confidence": round(c.confidence, 4),
                }
                for c in classifications[:10]
            ],
        },
    }


# ---------------------------------------------------------------------------
# Full Pipeline (convenience entry point)
# ---------------------------------------------------------------------------

def run_ml_pipeline(
    fragments: List[FragmentInput],
    classifier: Optional[FragmentClassifier] = None,
    zero_training: bool = False,
    top_k: int = 5,
    beam_width: int = 5,
    edge_config: Optional[EdgeWeightConfig] = None,
) -> PipelineResult:
    """
    Run the complete ML pipeline on a list of fragments.

    Fragment -> Byte2Image -> Swin V2 -> Classification
      -> FragmentNode -> Graph -> Reassembly -> Validation -> Ledger Payload

    Args:
        fragments: List of FragmentInput objects.
        classifier: Optional pre-loaded FragmentClassifier.
        zero_training: Use zero-training classifier.
        top_k: Top-k predictions per fragment.
        beam_width: Beam search width for reassembly.
        edge_config: Optional edge weight configuration.

    Returns:
        PipelineResult with all stage outputs.
    """
    if not fragments:
        return PipelineResult(
            classifications=[],
            reassembly=None,
            validation=None,
            ledger_payload={},
        )

    # Stage 1: Classify
    classifications = classify_fragments(
        fragments, classifier=classifier, zero_training=zero_training, top_k=top_k
    )

    # Stage 2: Reassemble (only if >1 fragment)
    reassembly: Optional[ReassemblyResult] = None
    validation_report: Optional[ForensicValidationReport] = None
    ledger_payload: Dict[str, Any] = {}

    if len(fragments) >= 1:
        nodes = build_fragment_nodes(fragments, classifications)
        reassembly = reassemble_fragments(nodes, edge_config=edge_config, beam_width=beam_width)

        # Stage 3: Validate
        validation_report = validate_reconstruction(reassembly)

        # Stage 4: Build ledger payload
        ledger_payload = build_ledger_payload(reassembly, validation_report, classifications)

    return PipelineResult(
        classifications=classifications,
        reassembly=reassembly,
        validation=validation_report.to_dict() if validation_report else None,
        ledger_payload=ledger_payload,
    )
