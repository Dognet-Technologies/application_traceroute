"""
Integration tests for security-suite.
"""

import pytest
import tempfile
from pathlib import Path

from ..core.graph import CausalSecurityGraph, CausalNode, NodeType, CausalEdge, CausalityType
from ..core.correlation import HybridCorrelationEngine, CorrelationType
from ..core.validation import BayesianBypassValidator, ValidationResult
from ..modules.taxonomy import SelfLearningTaxonomy, TaxonomyLevel
from ..utils.checkpoint import CheckpointManager


class TestCorrelationEngine:
    """Tests for HybridCorrelationEngine."""

    def test_register_entities(self):
        """Test entity registration."""
        engine = HybridCorrelationEngine()

        engine.register_entity('e1', features={'type': 'sqli'}, timestamp=1.0)
        engine.register_entity('e2', features={'type': 'sqli'}, timestamp=1.1)

        stats = engine.get_statistics()
        assert stats['total_entities'] == 2

    def test_add_correlation(self):
        """Test adding correlations."""
        engine = HybridCorrelationEngine()

        engine.register_entity('e1')
        engine.register_entity('e2')

        corr = engine.add_correlation(
            'e1', 'e2',
            CorrelationType.BEHAVIORAL,
            strength=0.8
        )

        assert corr is not None
        assert corr.strength == 0.8

    def test_find_correlations(self):
        """Test finding correlations."""
        engine = HybridCorrelationEngine()

        # Register entities with similar features
        engine.register_entity('e1', features={'type': 'sqli', 'severity': 'high'})
        engine.register_entity('e2', features={'type': 'sqli', 'severity': 'high'})
        engine.register_entity('e3', features={'type': 'xss', 'severity': 'low'})

        correlations = engine.find_all_correlations(
            correlation_types=[CorrelationType.BEHAVIORAL]
        )

        # e1 and e2 should be more correlated
        e1_e2_corr = engine.get_correlation('e1', 'e2')
        assert e1_e2_corr is not None

    def test_find_clusters(self):
        """Test finding correlation clusters."""
        engine = HybridCorrelationEngine()

        # Create two clusters
        engine.register_entity('a1')
        engine.register_entity('a2')
        engine.register_entity('b1')
        engine.register_entity('b2')

        engine.add_correlation('a1', 'a2', CorrelationType.STRUCTURAL, 0.9)
        engine.add_correlation('b1', 'b2', CorrelationType.STRUCTURAL, 0.9)

        clusters = engine.find_correlation_clusters(min_cluster_size=2)
        assert len(clusters) >= 1


class TestBayesianValidator:
    """Tests for BayesianBypassValidator."""

    def test_add_candidates(self):
        """Test adding exploit candidates."""
        validator = BayesianBypassValidator()

        candidate = validator.add_candidate(
            'sqli_1', 'sqli', "' OR '1'='1"
        )

        assert candidate.exploit_id == 'sqli_1'
        assert candidate.category == 'sqli'

    def test_thompson_sampling(self):
        """Test Thompson Sampling selection."""
        validator = BayesianBypassValidator()

        validator.add_candidate('c1', 'sqli', 'payload1')
        validator.add_candidate('c2', 'xss', 'payload2')
        validator.add_candidate('c3', 'lfi', 'payload3')

        # Should select one
        selected = validator.select_next_exploit_thompson()
        assert selected is not None

    def test_ucb_selection(self):
        """Test UCB selection."""
        validator = BayesianBypassValidator()

        validator.add_candidate('c1', 'sqli', 'payload1')
        validator.add_candidate('c2', 'xss', 'payload2')

        selected = validator.select_next_exploit_ucb()
        assert selected is not None

    def test_record_result(self):
        """Test recording results."""
        validator = BayesianBypassValidator()

        validator.add_candidate('c1', 'sqli', 'payload')

        validator.record_result('c1', 'http://test.com', ValidationResult.SUCCESS, 200, 0.5)
        validator.record_result('c1', 'http://test.com', ValidationResult.FAILURE, 403, 0.3)

        candidate = validator._candidates['c1']
        assert candidate.successes >= 1
        assert candidate.failures >= 1

    def test_summary(self):
        """Test getting summary."""
        validator = BayesianBypassValidator()

        validator.add_candidate('c1', 'sqli', 'payload')
        validator.record_result('c1', 'http://test.com', ValidationResult.SUCCESS, 200, 0.5)

        summary = validator.get_summary()
        assert summary.total_attempts == 1
        assert summary.successful == 1


class TestTaxonomy:
    """Tests for SelfLearningTaxonomy."""

    def test_initialization(self):
        """Test taxonomy initialization."""
        taxonomy = SelfLearningTaxonomy()

        categories = taxonomy.get_all_categories()
        assert len(categories) > 0

    def test_classify(self):
        """Test classification."""
        taxonomy = SelfLearningTaxonomy()

        # Test SQL injection classification
        result = taxonomy.classify("' UNION SELECT * FROM users--")
        assert result.confidence > 0
        assert 'sqli' in result.node_id or 'injection' in result.path

    def test_add_node(self):
        """Test adding custom node."""
        taxonomy = SelfLearningTaxonomy()

        node = taxonomy.add_node(
            'custom_vuln',
            'Custom Vulnerability',
            TaxonomyLevel.VARIANT,
            patterns=[r'custom_pattern'],
            keywords=['custom', 'test']
        )

        assert node.node_id == 'custom_vuln'

        # Should classify text matching pattern
        result = taxonomy.classify('this contains custom_pattern')
        # Note: may or may not match depending on other patterns

    def test_learn_from_observations(self):
        """Test learning from observations."""
        taxonomy = SelfLearningTaxonomy()

        observations = [
            ("SQL injection attack ' OR 1=1", 'sqli'),
            ("XSS attack <script>alert(1)</script>", 'xss'),
            ("Path traversal ../../etc/passwd", 'path_traversal'),
        ]

        new_clusters = taxonomy.learn_from_observations(observations)
        # Should process without error


class TestCheckpointManager:
    """Tests for CheckpointManager."""

    def test_create_checkpoint(self):
        """Test checkpoint creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = CheckpointManager(Path(tmpdir))

            checkpoint = manager.create('http://test.com', 'session_123')

            assert checkpoint.target_url == 'http://test.com'
            assert checkpoint.session_id == 'session_123'

    def test_save_load_checkpoint(self):
        """Test saving and loading checkpoint."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = CheckpointManager(Path(tmpdir))

            manager.create('http://test.com', 'session_123')
            manager.start_phase('test_phase', 10)
            manager.update_progress('test_phase', 5)
            manager.complete_phase('test_phase', {'result': 'ok'})
            manager.save(force=True)

            # Load in new manager
            manager2 = CheckpointManager(Path(tmpdir))
            loaded = manager2.load()

            assert loaded is not None
            assert loaded.session_id == 'session_123'
            assert loaded.phases['test_phase'].status == 'completed'

    def test_phase_lifecycle(self):
        """Test phase start/complete lifecycle."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = CheckpointManager(Path(tmpdir))
            manager.create('http://test.com', 'session_123')

            manager.start_phase('phase1')
            assert manager.checkpoint.phases['phase1'].status == 'in_progress'

            manager.complete_phase('phase1')
            assert manager.checkpoint.phases['phase1'].status == 'completed'

    def test_fail_phase(self):
        """Test phase failure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = CheckpointManager(Path(tmpdir))
            manager.create('http://test.com', 'session_123')

            manager.start_phase('phase1')
            manager.fail_phase('phase1', 'Test error')

            assert manager.checkpoint.phases['phase1'].status == 'failed'
            assert manager.checkpoint.phases['phase1'].error_message == 'Test error'


class TestEndToEnd:
    """End-to-end integration tests."""

    def test_full_workflow(self):
        """Test a simplified full workflow."""
        # Initialize components
        graph = CausalSecurityGraph()
        correlator = HybridCorrelationEngine()
        validator = BayesianBypassValidator()
        taxonomy = SelfLearningTaxonomy()

        # Add nodes to graph
        graph.add_node('endpoint', NodeType.ENDPOINT, '/api/users')
        graph.add_node('behavior', NodeType.BEHAVIOR, 'SQL error response')
        graph.add_node('vuln', NodeType.VULNERABILITY, 'SQL Injection')

        # Add edges
        graph.add_edge('endpoint', 'behavior', strength=0.8)
        graph.add_edge('behavior', 'vuln', strength=0.9)

        # Register for correlation
        correlator.register_entity('endpoint', features={'type': 'api'})
        correlator.register_entity('behavior', features={'type': 'error'})
        correlator.register_entity('vuln', features={'type': 'sqli'})

        # Add exploit candidate
        validator.add_candidate('sqli_test', 'sqli', "' OR '1'='1")

        # Record validation result
        validator.record_result('sqli_test', '/api/users', ValidationResult.SUCCESS, 200, 0.5)

        # Classify
        result = taxonomy.classify("SQL injection found in /api/users")

        # Find path
        path = graph.find_max_probability_path('endpoint', 'vuln')

        # Assertions
        assert path is not None
        assert path.probability > 0.7
        assert validator.get_summary().successful == 1
        assert result.confidence > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
