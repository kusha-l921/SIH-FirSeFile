"""
Forensic Fragment Node and Directed Reassembly Graph Formulation.
"""

from typing import Dict, Any, List, Optional, Tuple, Set
import numpy as np


class FragmentNode:
    """
    Represents a single orphaned or recovered file fragment.
    """

    def __init__(
        self,
        fragment_id: str,
        raw_bytes: bytes,
        predicted_class: str,
        confidence: float,
        probabilities: Optional[Dict[str, float]] = None,
        source_offset: Optional[int] = None,
        filesystem_source: Optional[str] = None,
        entropy: Optional[float] = None
    ):
        self.fragment_id = fragment_id
        self.raw_bytes = raw_bytes
        self.fragment_size = len(raw_bytes)
        self.predicted_class = predicted_class
        self.confidence = float(confidence)
        self.probabilities = probabilities or {predicted_class: self.confidence}
        self.source_offset = source_offset
        self.filesystem_source = filesystem_source
        self.entropy = entropy

    @property
    def header_bytes(self) -> bytes:
        """First 16 bytes of fragment."""
        return self.raw_bytes[:min(16, len(self.raw_bytes))]

    @property
    def tail_bytes(self) -> bytes:
        """Last 16 bytes of fragment."""
        return self.raw_bytes[max(0, len(self.raw_bytes) - 16):]

    def __repr__(self) -> str:
        return f"FragmentNode(id={self.fragment_id}, class={self.predicted_class}, conf={self.confidence:.2f})"


class ReassemblyGraph:
    """
    Directed Graph where Nodes represent file fragments and Edges represent
    candidate transitions with multi-component compatibility weights.
    """

    def __init__(self):
        self.nodes: Dict[str, FragmentNode] = {}
        # Adjacency list: u_id -> {v_id -> edge_weight_dict}
        self.adjacency: Dict[str, Dict[str, Dict[str, float]]] = {}

    def add_fragment(self, fragment: FragmentNode):
        """Add a fragment node to the graph."""
        self.nodes[fragment.fragment_id] = fragment
        if fragment.fragment_id not in self.adjacency:
            self.adjacency[fragment.fragment_id] = {}

    def add_edge(
        self,
        u_id: str,
        v_id: str,
        total_score: float,
        score_breakdown: Optional[Dict[str, float]] = None
    ):
        """Add a directed candidate adjacency edge from u to v."""
        if u_id not in self.adjacency:
            self.adjacency[u_id] = {}
        
        edge_data = {"total_score": float(total_score)}
        if score_breakdown:
            edge_data.update(score_breakdown)
        self.adjacency[u_id][v_id] = edge_data

    def get_edge_score(self, u_id: str, v_id: str) -> float:
        """Return total score of edge u -> v, or -inf if no edge."""
        if u_id in self.adjacency and v_id in self.adjacency[u_id]:
            return self.adjacency[u_id][v_id].get("total_score", -1.0)
        return -float("inf")

    def get_successors(self, u_id: str) -> List[Tuple[str, float]]:
        """Return list of (successor_id, score) sorted by score descending."""
        if u_id not in self.adjacency:
            return []
        edges = [(v_id, data.get("total_score", 0.0)) for v_id, data in self.adjacency[u_id].items()]
        edges.sort(key=lambda x: x[1], reverse=True)
        return edges

    def __len__(self) -> int:
        return len(self.nodes)
