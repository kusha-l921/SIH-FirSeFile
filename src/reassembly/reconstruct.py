"""
Reassembly Byte Reconstruction Module.
Stitches ordered fragment sequences into contiguous reconstructed files.
"""

from typing import Dict, Any, List, Optional
import hashlib
from src.reassembly.graph import FragmentNode, ReassemblyGraph


class ReconstructionResult:
    """
    Holds the output of a file fragment reassembly operation.
    """

    def __init__(
        self,
        ordered_fragment_ids: List[str],
        reconstructed_bytes: bytes,
        graph_score: float,
        reconstruction_confidence: float,
        unused_fragment_ids: List[str],
        detected_primary_type: str
    ):
        self.ordered_fragment_ids = ordered_fragment_ids
        self.reconstructed_bytes = reconstructed_bytes
        self.graph_score = graph_score
        self.reconstruction_confidence = reconstruction_confidence
        self.unused_fragment_ids = unused_fragment_ids
        self.detected_primary_type = detected_primary_type
        self.sha256 = hashlib.sha256(reconstructed_bytes).hexdigest()
        self.total_size = len(reconstructed_bytes)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ordered_fragment_ids": self.ordered_fragment_ids,
            "fragment_count": len(self.ordered_fragment_ids),
            "reconstructed_size_bytes": self.total_size,
            "sha256": self.sha256,
            "graph_score": round(self.graph_score, 4),
            "reconstruction_confidence": round(self.reconstruction_confidence, 4),
            "unused_fragment_ids": self.unused_fragment_ids,
            "detected_primary_type": self.detected_primary_type
        }


def reconstruct_file_from_ordering(
    ordered_ids: List[str],
    graph: ReassemblyGraph,
    graph_score: float = 0.0,
    reconstruction_confidence: float = 0.0,
    unused_ids: Optional[List[str]] = None
) -> ReconstructionResult:
    """
    Concatenate raw fragment bytes in determined order into a single byte stream.
    """
    if unused_ids is None:
        all_ids = set(graph.nodes.keys())
        unused_ids = list(all_ids - set(ordered_ids))

    byte_chunks = []
    class_votes: Dict[str, float] = {}

    for frag_id in ordered_ids:
        node = graph.nodes[frag_id]
        byte_chunks.append(node.raw_bytes)
        # Tally weighted class votes
        class_votes[node.predicted_class] = class_votes.get(node.predicted_class, 0.0) + node.confidence

    reconstructed_bytes = b"".join(byte_chunks)
    primary_type = max(class_votes.items(), key=lambda x: x[1])[0] if class_votes else "unknown"

    return ReconstructionResult(
        ordered_fragment_ids=ordered_ids,
        reconstructed_bytes=reconstructed_bytes,
        graph_score=graph_score,
        reconstruction_confidence=reconstruction_confidence,
        unused_fragment_ids=unused_ids,
        detected_primary_type=primary_type
    )
