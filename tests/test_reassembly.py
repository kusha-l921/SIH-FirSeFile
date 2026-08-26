"""
Unit tests for graph-based fragment reassembly and ordering algorithms.
"""

import pytest
from src.reassembly.graph import FragmentNode, ReassemblyGraph
from src.reassembly.edge_scoring import (
    score_type_compatibility, score_confidence, score_byte_boundary,
    compute_edge_score, build_complete_reassembly_graph
)
from src.reassembly.ordering import order_fragments_beam_search
from src.reassembly.reconstruct import reconstruct_file_from_ordering
from src.reassembly.synthetic import fragment_file, evaluate_reassembly


def test_edge_scoring_compatibility():
    node1 = FragmentNode(
        fragment_id="frag_01",
        raw_bytes=b"%PDF-1.4 header fragment test" + b"\x00" * 483,
        predicted_class="pdf",
        confidence=0.95
    )
    node2 = FragmentNode(
        fragment_id="frag_02",
        raw_bytes=b"body text obj 1 0 << /Type >>" + b"\x00" * 482,
        predicted_class="pdf",
        confidence=0.90
    )
    node3 = FragmentNode(
        fragment_id="frag_03",
        raw_bytes=b"\x89PNG\r\n\x1a\n" + b"\x00" * 504,
        predicted_class="png",
        confidence=0.92
    )

    # pdf -> pdf should have higher score than pdf -> png
    score_12, _ = compute_edge_score(node1, node2)
    score_13, _ = compute_edge_score(node1, node3)

    assert score_12 > score_13, f"Expected same-class score {score_12} > different-class score {score_13}"
    # node3 has PNG magic header, so node1 -> node3 violates structural constraint
    assert score_13 == -1.0, "Header fragment cannot follow another fragment"


def test_beam_search_reassembly_synthetic():
    frag0_bytes = (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" + b"A" * 512)[:512]
    frag1_bytes = (b"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n" + b"B" * 512)[:512]
    frag2_bytes = (b"xref\n0 4\n0000000000 65535 f\ntrailer<< /Root 1 0 R >>\nstartxref\n100\n%%EOF\n" + b" " * 512)[:512]
    full_data = frag0_bytes + frag1_bytes + frag2_bytes
    
    frags, gt_order = fragment_file(full_data, file_class="pdf", file_id="doc1", fragment_size=512)
    assert len(frags) == 3

    # Reverse order to simulate shuffled input
    shuffled_frags = frags[::-1]
    graph = build_complete_reassembly_graph(shuffled_frags)
    ordered_ids, score, conf, unused = order_fragments_beam_search(graph, beam_width=5)

    assert len(ordered_ids) == 3
    # Start fragment should be correctly identified as the header fragment (frag_000)
    assert ordered_ids[0] == gt_order[0], f"Expected start node {gt_order[0]}, got {ordered_ids[0]}"

    recon = reconstruct_file_from_ordering(ordered_ids, graph, score, conf, unused)
    assert recon.total_size == 1536
    assert recon.reconstructed_bytes.startswith(b"%PDF-1.4")


def test_reassembly_metric_equations():
    """
    Manually verified unit tests for exact sequence, adjacency, position, and byte accuracy.
    """
    gt_order = ["A", "B", "C", "D"]
    gt_bytes = b"A" * 512 + b"B" * 512 + b"C" * 512 + b"D" * 512

    # Case 1: Perfect Match (A -> B -> C -> D)
    pred_perfect = ["A", "B", "C", "D"]
    bytes_perfect = b"A" * 512 + b"B" * 512 + b"C" * 512 + b"D" * 512
    res_perfect = evaluate_reassembly(pred_perfect, gt_order, bytes_perfect, gt_bytes)

    assert res_perfect["exact_sequence_accuracy"] == 1.0
    assert res_perfect["pairwise_adjacency_accuracy"] == 1.0
    assert res_perfect["position_accuracy"] == 1.0
    assert res_perfect["byte_accuracy"] == 1.0

    # Case 2: Swapped Middle Elements (A -> C -> B -> D)
    pred_swapped = ["A", "C", "B", "D"]
    bytes_swapped = b"A" * 512 + b"C" * 512 + b"B" * 512 + b"D" * 512
    res_swapped = evaluate_reassembly(pred_swapped, gt_order, bytes_swapped, gt_bytes)

    assert res_swapped["exact_sequence_accuracy"] == 0.0
    assert res_swapped["pairwise_adjacency_accuracy"] == 0.0  # (A,C), (C,B), (B,D) vs (A,B), (B,C), (C,D) -> 0 matches
    assert res_swapped["position_accuracy"] == 0.5            # A at 0 and D at 3 match (2/4 = 0.5)
    assert res_swapped["byte_accuracy"] == 0.5                # 1024 out of 2048 bytes match

    # Case 3: Circular Shift (B -> C -> D -> A)
    pred_shift = ["B", "C", "D", "A"]
    bytes_shift = b"B" * 512 + b"C" * 512 + b"D" * 512 + b"A" * 512
    res_shift = evaluate_reassembly(pred_shift, gt_order, bytes_shift, gt_bytes)

    assert res_shift["exact_sequence_accuracy"] == 0.0
    assert abs(res_shift["pairwise_adjacency_accuracy"] - (2.0 / 3.0)) < 1e-3  # (B,C) and (C,D) match (2/3)
    assert res_shift["position_accuracy"] == 0.0                              # None at correct index (0/4)
    assert res_shift["byte_accuracy"] == 0.0
