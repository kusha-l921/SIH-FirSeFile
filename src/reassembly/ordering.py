"""
Deterministic Fragment Ordering Engine using Graph Search.
Finds the highest-scoring plausible linear sequence of file fragments.
"""

from typing import List, Dict, Any, Tuple, Set, Optional
import numpy as np

from src.datasets.fft75 import MAGIC_SIGNATURES
from src.reassembly.graph import ReassemblyGraph, FragmentNode


def find_candidate_start_nodes(graph: ReassemblyGraph) -> List[Tuple[str, float]]:
    """
    Identify and rank potential starting fragments based on:
    1. Magic signature presence at offset 0.
    2. High out-degree and low in-degree in the candidate graph.
    """
    candidates = []

    for frag_id, node in graph.nodes.items():
        start_score = 0.0
        # Check magic signature
        for cls_name, sigs in MAGIC_SIGNATURES.items():
            if any(node.raw_bytes.startswith(sig) for sig in sigs):
                start_score += 2.0
                break

        # Check out-degree vs in-degree
        out_edges = graph.get_successors(frag_id)
        out_weight = sum(score for _, score in out_edges)
        start_score += 0.1 * out_weight

        candidates.append((frag_id, start_score))

    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates


def order_fragments_beam_search(
    graph: ReassemblyGraph,
    beam_width: int = 5,
    max_length: Optional[int] = None
) -> Tuple[List[str], float, float, List[str]]:
    """
    Beam-search heuristic path optimizer to find the highest-scoring sequence of fragments.

    Args:
        graph: ReassemblyGraph containing nodes and weighted edges.
        beam_width: Number of top candidate paths maintained per step.
        max_length: Maximum path length (defaults to total number of nodes).

    Returns:
        Tuple of:
        - ordered_fragment_ids: List[str]
        - total_path_score: float
        - average_confidence: float
        - unused_fragment_ids: List[str]
    """
    total_nodes = len(graph.nodes)
    if total_nodes == 0:
        return [], 0.0, 0.0, []
    if total_nodes == 1:
        single_id = list(graph.nodes.keys())[0]
        node = graph.nodes[single_id]
        return [single_id], 1.0, node.confidence, []

    if max_length is None:
        max_length = total_nodes

    # 1. Initialize beams from candidate starting nodes
    start_candidates = find_candidate_start_nodes(graph)
    # Beams: List of (path, visited_set, cumulative_score)
    beams: List[Tuple[List[str], Set[str], float]] = []
    
    # Take top start nodes
    for start_id, _ in start_candidates[:max(beam_width, 1)]:
        beams.append(([start_id], {start_id}, 0.0))

    # 2. Expand beams iteratively until all nodes visited or length reached
    for step in range(1, max_length):
        new_beams: List[Tuple[List[str], Set[str], float]] = []

        for path, visited, score in beams:
            curr_node_id = path[-1]
            successors = graph.get_successors(curr_node_id)
            expanded = False

            for next_id, edge_score in successors:
                if next_id not in visited and edge_score > 0:
                    new_path = path + [next_id]
                    new_visited = visited.union({next_id})
                    new_score = score + edge_score
                    new_beams.append((new_path, new_visited, new_score))
                    expanded = True

            # If no valid unvisited successor with positive score, check unvisited nodes with greedy fallback
            if not expanded and len(visited) < total_nodes:
                unvisited = [nid for nid in graph.nodes if nid not in visited]
                for next_id in unvisited[:2]:
                    # Small default transition score for fallback
                    new_path = path + [next_id]
                    new_visited = visited.union({next_id})
                    new_score = score + 0.01
                    new_beams.append((new_path, new_visited, new_score))

        if not new_beams:
            break

        # Keep top beam_width paths ranked by average edge score + coverage
        new_beams.sort(key=lambda x: (len(x[0]), x[2]), reverse=True)
        beams = new_beams[:beam_width]

        # Early exit if a beam covers all nodes
        if len(beams[0][0]) == total_nodes:
            break

    # 3. Select Best Path
    best_path, best_visited, best_score = beams[0]
    all_node_ids = set(graph.nodes.keys())
    unused = list(all_node_ids - best_visited)

    # Compute average reconstruction confidence
    path_confs = [graph.nodes[nid].confidence for nid in best_path]
    avg_conf = float(np.mean(path_confs)) if path_confs else 0.0

    return best_path, float(best_score), avg_conf, unused
