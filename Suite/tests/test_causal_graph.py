"""
Tests for causal graph module.
"""

import pytest
import numpy as np
import time

from ..core.graph.causal_node import CausalNode, NodeType, NodeStatistics
from ..core.graph.causal_edge import CausalEdge, CausalityType
from ..core.graph.causal_graph import CausalSecurityGraph


class TestCausalNode:
    """Tests for CausalNode class."""

    def test_create_node(self):
        """Test node creation."""
        node = CausalNode(
            node_id='test_node',
            node_type=NodeType.ENDPOINT,
            name='Test Node'
        )

        assert node.node_id == 'test_node'
        assert node.node_type == NodeType.ENDPOINT
        assert node.name == 'Test Node'

    def test_add_observation(self):
        """Test adding observations."""
        node = CausalNode('test', NodeType.BEHAVIOR)

        node.add_observation(1.0, time.time())
        node.add_observation(2.0, time.time())
        node.add_observation(3.0, time.time())

        stats = node.get_statistics()
        assert stats.count == 3
        assert stats.mean == pytest.approx(2.0, rel=0.01)

    def test_anomaly_detection(self):
        """Test anomaly detection."""
        node = CausalNode('test', NodeType.BEHAVIOR)

        # Add normal observations
        for i in range(20):
            node.add_observation(np.random.normal(10, 1), time.time())

        # Normal value should not be anomalous
        is_anom, prob = node.is_anomalous(10.0)
        assert not is_anom

        # Extreme value should be anomalous
        is_anom, prob = node.is_anomalous(50.0)
        assert is_anom

    def test_entropy_calculation(self):
        """Test entropy calculation."""
        node = CausalNode('test', NodeType.BEHAVIOR)

        # Uniform distribution should have higher entropy
        for i in range(100):
            node.add_observation(np.random.uniform(0, 10), time.time())

        entropy = node.calculate_entropy()
        assert entropy > 0

    def test_serialization(self):
        """Test serialization/deserialization."""
        node = CausalNode('test', NodeType.ENDPOINT, 'Test', {'key': 'value'})
        node.add_observation(1.0, time.time())

        data = node.to_dict()
        restored = CausalNode.from_dict(data)

        assert restored.node_id == node.node_id
        assert restored.node_type == node.node_type
        assert restored.name == node.name


class TestCausalEdge:
    """Tests for CausalEdge class."""

    def test_create_edge(self):
        """Test edge creation."""
        edge = CausalEdge(
            source_id='node_a',
            target_id='node_b',
            causality_type=CausalityType.DIRECT,
            initial_strength=0.7
        )

        assert edge.source_id == 'node_a'
        assert edge.target_id == 'node_b'
        assert edge.strength == pytest.approx(0.7)

    def test_self_loop_rejected(self):
        """Test that self-loops are rejected."""
        with pytest.raises(ValueError):
            CausalEdge('node_a', 'node_a')

    def test_add_evidence(self):
        """Test evidence accumulation."""
        edge = CausalEdge('a', 'b', initial_strength=0.5)

        # Add strong evidence
        for _ in range(10):
            edge.add_evidence(
                source_value=1.0,
                target_value=1.0,
                time_delta=0.1,
                strength_contribution=0.9
            )

        # Strength should increase
        assert edge.strength > 0.5
        assert edge.get_evidence_count() == 10

    def test_bayesian_estimate(self):
        """Test Bayesian strength estimation."""
        edge = CausalEdge('a', 'b', initial_strength=0.5)

        # Add evidence
        for _ in range(20):
            edge.add_evidence(1.0, 1.0, 0.1, strength_contribution=0.8)

        mean, lower, upper = edge.get_bayesian_estimate()
        assert lower < mean < upper
        assert mean > 0.5

    def test_serialization(self):
        """Test serialization/deserialization."""
        edge = CausalEdge('a', 'b', CausalityType.CONDITIONAL, 0.6)
        edge.add_condition('c')
        edge.add_evidence(1.0, 1.0, 0.1)

        data = edge.to_dict()
        restored = CausalEdge.from_dict(data)

        assert restored.source_id == edge.source_id
        assert restored.target_id == edge.target_id
        assert restored.causality_type == edge.causality_type


class TestCausalSecurityGraph:
    """Tests for CausalSecurityGraph class."""

    def test_create_graph(self):
        """Test graph creation."""
        graph = CausalSecurityGraph()
        assert graph.node_count == 0
        assert graph.edge_count == 0

    def test_add_nodes(self):
        """Test adding nodes."""
        graph = CausalSecurityGraph()

        node1 = graph.add_node('n1', NodeType.ENDPOINT, 'Node 1')
        node2 = graph.add_node('n2', NodeType.BEHAVIOR, 'Node 2')

        assert graph.node_count == 2
        assert graph.get_node('n1') == node1

    def test_add_edges(self):
        """Test adding edges."""
        graph = CausalSecurityGraph()

        graph.add_node('n1', NodeType.ENDPOINT)
        graph.add_node('n2', NodeType.BEHAVIOR)
        graph.add_node('n3', NodeType.VULNERABILITY)

        edge1 = graph.add_edge('n1', 'n2', CausalityType.DIRECT, 0.8)
        edge2 = graph.add_edge('n2', 'n3', CausalityType.INDIRECT, 0.6)

        assert graph.edge_count == 2
        assert edge1 is not None
        assert edge2 is not None

    def test_cycle_prevention(self):
        """Test that cycles are prevented."""
        graph = CausalSecurityGraph()

        graph.add_node('n1', NodeType.ENDPOINT)
        graph.add_node('n2', NodeType.BEHAVIOR)
        graph.add_node('n3', NodeType.VULNERABILITY)

        graph.add_edge('n1', 'n2')
        graph.add_edge('n2', 'n3')

        # This would create a cycle
        cycle_edge = graph.add_edge('n3', 'n1')
        assert cycle_edge is None

    def test_max_probability_path(self):
        """Test finding maximum probability path."""
        graph = CausalSecurityGraph()

        graph.add_node('start', NodeType.ENDPOINT)
        graph.add_node('mid1', NodeType.BEHAVIOR)
        graph.add_node('mid2', NodeType.BEHAVIOR)
        graph.add_node('end', NodeType.VULNERABILITY)

        # Path 1: start -> mid1 -> end (0.8 * 0.9 = 0.72)
        graph.add_edge('start', 'mid1', strength=0.8)
        graph.add_edge('mid1', 'end', strength=0.9)

        # Path 2: start -> mid2 -> end (0.5 * 0.5 = 0.25)
        graph.add_edge('start', 'mid2', strength=0.5)
        graph.add_edge('mid2', 'end', strength=0.5)

        result = graph.find_max_probability_path('start', 'end')

        assert result is not None
        assert result.path == ['start', 'mid1', 'end']
        assert result.probability == pytest.approx(0.72, rel=0.01)

    def test_vulnerability_inference(self):
        """Test vulnerability inference from anomaly."""
        graph = CausalSecurityGraph()

        graph.add_node('source', NodeType.ENDPOINT)
        graph.add_node('middle', NodeType.BEHAVIOR)
        graph.add_node('anomaly', NodeType.VULNERABILITY)

        graph.add_edge('source', 'middle', strength=0.7)
        graph.add_edge('middle', 'anomaly', strength=0.8)

        inferences = graph.infer_vulnerability_from_anomaly('anomaly')

        assert len(inferences) > 0
        assert 'source' in inferences[0].source_nodes or 'middle' in inferences[0].source_nodes

    def test_belief_propagation(self):
        """Test belief propagation."""
        graph = CausalSecurityGraph()

        graph.add_node('n1', NodeType.ENDPOINT)
        graph.add_node('n2', NodeType.BEHAVIOR)
        graph.add_node('n3', NodeType.VULNERABILITY)

        graph.add_edge('n1', 'n2', strength=0.9)
        graph.add_edge('n2', 'n3', strength=0.8)

        # Set evidence
        evidence = {'n1': 1.0}
        beliefs = graph.propagate_beliefs(evidence)

        # Beliefs should propagate with decay
        assert beliefs['n1'] == 1.0
        assert beliefs['n2'] > 0.5
        assert beliefs['n3'] > 0.3

    def test_topological_sort(self):
        """Test topological sorting."""
        graph = CausalSecurityGraph()

        graph.add_node('a', NodeType.ENDPOINT)
        graph.add_node('b', NodeType.BEHAVIOR)
        graph.add_node('c', NodeType.VULNERABILITY)

        graph.add_edge('a', 'b')
        graph.add_edge('b', 'c')

        order = graph.topological_sort()

        assert order.index('a') < order.index('b')
        assert order.index('b') < order.index('c')

    def test_serialization(self):
        """Test graph serialization."""
        graph = CausalSecurityGraph()

        graph.add_node('n1', NodeType.ENDPOINT)
        graph.add_node('n2', NodeType.BEHAVIOR)
        graph.add_edge('n1', 'n2', strength=0.7)

        data = graph.to_dict()
        restored = CausalSecurityGraph.from_dict(data)

        assert restored.node_count == graph.node_count
        assert restored.edge_count == graph.edge_count


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
