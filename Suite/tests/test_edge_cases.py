"""
test_edge_cases.py - Unit tests for numeric edge cases

Tests boundary conditions and edge cases in Suite modules.
"""

import sys
import numpy as np
from pathlib import Path

# Add Suite to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def test_causal_node_empty_observations():
    """Test CausalNode with no observations."""
    from Suite.core.graph.causal_node import CausalNode, NodeType

    node = CausalNode("test", NodeType.INFRASTRUCTURE, "Test Node")

    # Should not crash with empty observations
    assert node._stats.mean == 0.0
    assert node._stats.std == 0.0
    # Entropy returns 0 for empty/invalid distributions
    entropy = node.calculate_entropy()
    assert entropy == 0.0


def test_causal_node_single_observation():
    """Test CausalNode with single observation."""
    from Suite.core.graph.causal_node import CausalNode, NodeType

    node = CausalNode("test", NodeType.INFRASTRUCTURE, "Test Node")
    node.add_observation(100.0, 0)

    assert node._stats.mean == 100.0
    # With single observation, std should be 0
    assert node._stats.std == 0.0


def test_causal_node_identical_observations():
    """Test CausalNode with identical observations (zero variance)."""
    from Suite.core.graph.causal_node import CausalNode, NodeType

    node = CausalNode("test", NodeType.INFRASTRUCTURE, "Test Node")
    for i in range(10):
        node.add_observation(50.0, i)

    assert node._stats.mean == 50.0
    assert node._stats.std == 0.0
    # Entropy of constant distribution should be 0 or very small
    entropy = node.calculate_entropy()
    assert entropy <= 0.1  # Allow small numerical error


def test_causal_edge_zero_strength():
    """Test CausalEdge with zero initial strength."""
    from Suite.core.graph.causal_edge import CausalEdge, CausalityType

    edge = CausalEdge("src", "dst", CausalityType.DIRECT, 0.0)

    assert edge.strength == 0.0
    # Edge should still be usable
    assert edge.source_id == "src"
    assert edge.target_id == "dst"


def test_causal_edge_boundary_strength():
    """Test CausalEdge with boundary strength values."""
    from Suite.core.graph.causal_edge import CausalEdge, CausalityType

    # Minimum strength
    edge_min = CausalEdge("src", "dst", CausalityType.DIRECT, 0.0)
    assert edge_min.strength == 0.0

    # Maximum strength
    edge_max = CausalEdge("src", "dst", CausalityType.DIRECT, 1.0)
    assert edge_max.strength == 1.0


def test_causal_graph_empty():
    """Test CausalSecurityGraph with no nodes or edges."""
    from Suite.core.graph.causal_graph import CausalSecurityGraph

    graph = CausalSecurityGraph()

    assert graph.node_count == 0
    assert graph.edge_count == 0
    assert graph.is_valid_dag() == True


def test_causal_graph_self_loop_rejected():
    """Test that self-loops are rejected."""
    from Suite.core.graph.causal_graph import CausalSecurityGraph
    from Suite.core.graph.causal_node import NodeType
    from Suite.core.graph.causal_edge import CausalityType

    graph = CausalSecurityGraph()
    graph.add_node("A", NodeType.INFRASTRUCTURE, "Node A")

    # Self-loop should fail cycle check
    result = graph.add_edge("A", "A", CausalityType.DIRECT, 0.5)
    assert result is None  # Edge not added


def test_causal_graph_cycle_detection():
    """Test cycle detection in DAG."""
    from Suite.core.graph.causal_graph import CausalSecurityGraph
    from Suite.core.graph.causal_node import NodeType
    from Suite.core.graph.causal_edge import CausalityType

    graph = CausalSecurityGraph()
    graph.add_node("A", NodeType.INFRASTRUCTURE, "A")
    graph.add_node("B", NodeType.INFRASTRUCTURE, "B")
    graph.add_node("C", NodeType.INFRASTRUCTURE, "C")

    # Create chain A -> B -> C
    graph.add_edge("A", "B", CausalityType.DIRECT, 0.5)
    graph.add_edge("B", "C", CausalityType.DIRECT, 0.5)

    # Try to add C -> A (would create cycle)
    result = graph.add_edge("C", "A", CausalityType.DIRECT, 0.5)
    assert result is None  # Edge not added due to cycle


def test_dijkstra_unreachable_nodes():
    """Test Dijkstra with unreachable target."""
    from Suite.core.graph.causal_graph import CausalSecurityGraph
    from Suite.core.graph.causal_node import NodeType
    from Suite.core.graph.causal_edge import CausalityType

    graph = CausalSecurityGraph()
    graph.add_node("A", NodeType.INFRASTRUCTURE, "A")
    graph.add_node("B", NodeType.INFRASTRUCTURE, "B")
    # No edges - B is unreachable from A

    result = graph.find_max_probability_path("A", "B")
    assert result is None


def test_dijkstra_very_small_strength():
    """Test Dijkstra with very small edge strength (log overflow)."""
    from Suite.core.graph.causal_graph import CausalSecurityGraph
    from Suite.core.graph.causal_node import NodeType
    from Suite.core.graph.causal_edge import CausalityType

    graph = CausalSecurityGraph()
    graph.add_node("A", NodeType.INFRASTRUCTURE, "A")
    graph.add_node("B", NodeType.INFRASTRUCTURE, "B")

    # Very small strength (near zero)
    edge = graph.add_edge("A", "B", CausalityType.DIRECT, 1e-10)

    # Should still find path but with very low probability
    result = graph.find_max_probability_path("A", "B")
    assert result is not None
    assert result.probability < 1e-9


def test_bayesian_validator_no_candidates():
    """Test BayesianBypassValidator with no candidates."""
    from Suite.core.validation.bayesian_validator import BayesianBypassValidator

    validator = BayesianBypassValidator()

    # Should return None with no candidates
    result = validator.select_next_exploit_thompson()
    assert result is None


def test_bayesian_validator_reproducibility():
    """Test that BayesianBypassValidator is reproducible with seed."""
    from Suite.utils.config import set_global_seed
    from Suite.core.validation.bayesian_validator import BayesianBypassValidator

    # Set seed for reproducibility
    set_global_seed(42)

    validator1 = BayesianBypassValidator()
    validator1.add_candidate("test1", "sqli", "' OR 1=1")
    validator1.add_candidate("test2", "xss", "<script>")
    sample1 = [validator1.select_next_exploit_thompson() for _ in range(5)]

    # Reset seed and create new validator
    set_global_seed(42)

    validator2 = BayesianBypassValidator()
    validator2.add_candidate("test1", "sqli", "' OR 1=1")
    validator2.add_candidate("test2", "xss", "<script>")
    sample2 = [validator2.select_next_exploit_thompson() for _ in range(5)]

    # Should get same results
    ids1 = [s.exploit_id if s else None for s in sample1]
    ids2 = [s.exploit_id if s else None for s in sample2]
    assert ids1 == ids2


def test_taxonomy_empty_patterns():
    """Test SelfLearningTaxonomy with node having no patterns."""
    from Suite.modules.taxonomy.adaptive_taxonomy import SelfLearningTaxonomy

    taxonomy = SelfLearningTaxonomy()

    # Classification should work even with sparse patterns
    result = taxonomy.classify("test payload")
    assert result is not None
    assert hasattr(result, 'node_name')
    assert hasattr(result, 'confidence')


def test_correlation_empty_entities():
    """Test HybridCorrelationEngine with no entities."""
    from Suite.core.correlation.hybrid_correlator import HybridCorrelationEngine

    engine = HybridCorrelationEngine()

    # Should return empty list, not crash
    correlations = engine.find_all_correlations()
    assert correlations == []


def test_correlation_single_entity():
    """Test HybridCorrelationEngine with single entity."""
    from Suite.core.correlation.hybrid_correlator import HybridCorrelationEngine
    import numpy as np

    engine = HybridCorrelationEngine()
    engine.register_entity("entity1", vector=np.array([1.0, 2.0, 3.0]))

    # Should return empty (no pairs possible)
    correlations = engine.find_all_correlations()
    assert correlations == []


def test_dag_validation():
    """Test DAG validation method."""
    from Suite.core.graph.causal_graph import CausalSecurityGraph
    from Suite.core.graph.causal_node import NodeType
    from Suite.core.graph.causal_edge import CausalityType

    graph = CausalSecurityGraph()
    graph.add_node("A", NodeType.INFRASTRUCTURE, "A")
    graph.add_node("B", NodeType.INFRASTRUCTURE, "B")
    graph.add_edge("A", "B", CausalityType.DIRECT, 0.5)

    is_valid, issues = graph.validate_dag()
    assert is_valid == True
    assert len(issues) == 0


def run_all_tests():
    """Run all edge case tests."""
    tests = [
        ("CausalNode empty observations", test_causal_node_empty_observations),
        ("CausalNode single observation", test_causal_node_single_observation),
        ("CausalNode identical observations", test_causal_node_identical_observations),
        ("CausalEdge zero strength", test_causal_edge_zero_strength),
        ("CausalEdge boundary strength", test_causal_edge_boundary_strength),
        ("CausalGraph empty", test_causal_graph_empty),
        ("CausalGraph self-loop rejected", test_causal_graph_self_loop_rejected),
        ("CausalGraph cycle detection", test_causal_graph_cycle_detection),
        ("Dijkstra unreachable nodes", test_dijkstra_unreachable_nodes),
        ("Dijkstra very small strength", test_dijkstra_very_small_strength),
        ("BayesianValidator no candidates", test_bayesian_validator_no_candidates),
        ("BayesianValidator reproducibility", test_bayesian_validator_reproducibility),
        ("Taxonomy empty patterns", test_taxonomy_empty_patterns),
        ("Correlation empty entities", test_correlation_empty_entities),
        ("Correlation single entity", test_correlation_single_entity),
        ("DAG validation", test_dag_validation),
    ]

    print("=" * 60)
    print("Edge Case Tests")
    print("=" * 60)

    passed = 0
    failed = 0

    for name, test_func in tests:
        try:
            test_func()
            print(f"  ✓ {name}")
            passed += 1
        except Exception as e:
            print(f"  ✗ {name}: {e}")
            failed += 1

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
