#!/usr/bin/env python3
"""
Quick test script for Security Testing Suite
"""

import sys
sys.path.insert(0, '/home/user/application_traceroute')

print("=" * 60)
print("Security Testing Suite - Quick Test")
print("=" * 60)

# Test 1: Import modules
print("\n[1] Testing imports...")
try:
    from Suite.core.graph.causal_node import CausalNode, NodeType
    from Suite.core.graph.causal_edge import CausalEdge, CausalityType
    from Suite.core.graph.causal_graph import CausalSecurityGraph
    from Suite.core.correlation.hybrid_correlator import HybridCorrelationEngine
    from Suite.core.validation.bayesian_validator import BayesianBypassValidator, ValidationResult
    from Suite.modules.taxonomy.adaptive_taxonomy import SelfLearningTaxonomy
    print("    ✓ All modules imported successfully")
except Exception as e:
    print(f"    ✗ Import error: {e}")
    sys.exit(1)

# Test 2: CausalNode
print("\n[2] Testing CausalNode...")
try:
    import time
    node = CausalNode('test_node', NodeType.ENDPOINT, 'Test Node')
    for i in range(10):
        node.add_observation(10 + i * 0.5, time.time())

    stats = node.get_statistics()
    print(f"    ✓ Node created with {stats.count} observations")
    print(f"      Mean: {stats.mean:.2f}, Std: {stats.std:.2f}")

    entropy = node.calculate_entropy()
    print(f"      Entropy: {entropy:.4f}")
except Exception as e:
    print(f"    ✗ Error: {e}")

# Test 3: CausalGraph
print("\n[3] Testing CausalSecurityGraph...")
try:
    graph = CausalSecurityGraph()

    # Add nodes
    graph.add_node('server', NodeType.INFRASTRUCTURE, 'Web Server')
    graph.add_node('endpoint', NodeType.ENDPOINT, '/api/users')
    graph.add_node('vuln', NodeType.VULNERABILITY, 'SQL Injection')

    # Add edges
    graph.add_edge('server', 'endpoint', CausalityType.DIRECT, 0.9)
    graph.add_edge('endpoint', 'vuln', CausalityType.INDIRECT, 0.7)

    print(f"    ✓ Graph created: {graph.node_count} nodes, {graph.edge_count} edges")

    # Test max probability path
    path = graph.find_max_probability_path('server', 'vuln')
    if path:
        print(f"      Max prob path: {' -> '.join(path.path)} (p={path.probability:.2f})")
except Exception as e:
    print(f"    ✗ Error: {e}")

# Test 4: HybridCorrelationEngine
print("\n[4] Testing HybridCorrelationEngine...")
try:
    from Suite.core.correlation.hybrid_correlator import CorrelationType

    engine = HybridCorrelationEngine()
    engine.register_entity('e1', features={'type': 'sqli'}, timestamp=1.0)
    engine.register_entity('e2', features={'type': 'sqli'}, timestamp=1.1)
    engine.register_entity('e3', features={'type': 'xss'}, timestamp=2.0)

    corr = engine.add_correlation('e1', 'e2', CorrelationType.BEHAVIORAL, strength=0.8)
    stats = engine.get_statistics()
    print(f"    ✓ Engine: {stats['total_entities']} entities, {stats['total_correlations']} correlations")
except Exception as e:
    print(f"    ✗ Error: {e}")

# Test 5: BayesianBypassValidator
print("\n[5] Testing BayesianBypassValidator...")
try:
    validator = BayesianBypassValidator()

    # Add candidates
    validator.add_candidate('sqli_1', 'sqli', "' OR '1'='1")
    validator.add_candidate('xss_1', 'xss', '<script>alert(1)</script>')

    # Simulate results
    validator.record_result('sqli_1', 'http://test.com', ValidationResult.SUCCESS, 200, 0.5)
    validator.record_result('sqli_1', 'http://test.com', ValidationResult.FAILURE, 403, 0.3)

    # Thompson sampling
    selected = validator.select_next_exploit_thompson()
    if selected:
        print(f"    ✓ Thompson sampling selected: {selected.exploit_id}")
        print(f"      Success rate: {selected.mean_success_rate:.2f}")

    summary = validator.get_summary()
    print(f"      Total attempts: {summary.total_attempts}, Success rate: {summary.success_rate:.2f}")
except Exception as e:
    print(f"    ✗ Error: {e}")

# Test 6: SelfLearningTaxonomy
print("\n[6] Testing SelfLearningTaxonomy...")
try:
    taxonomy = SelfLearningTaxonomy()

    # Test classification
    result = taxonomy.classify("' UNION SELECT * FROM users--")
    print(f"    ✓ Classification: {result.node_name} (confidence: {result.confidence:.2f})")
    print(f"      Path: {' > '.join(result.path)}")

    categories = taxonomy.get_all_categories()
    print(f"      Total categories: {len(categories)}")
except Exception as e:
    print(f"    ✗ Error: {e}")

# Test 7: Differential Analyzer (dry run)
print("\n[7] Testing DifferentialCausalAnalyzer (dry run)...")
try:
    from Suite.core.behavioral.differential_analyzer import DifferentialCausalAnalyzer

    analyzer = DifferentialCausalAnalyzer()
    print(f"    ✓ Analyzer initialized")
    print(f"      Baseline samples: {analyzer.n_baseline_samples}")
    print(f"      Perturbations: {analyzer.n_perturbations}")
    print(f"      KL threshold: {analyzer.kl_threshold}")
except Exception as e:
    print(f"    ✗ Error: {e}")

print("\n" + "=" * 60)
print("All tests completed!")
print("=" * 60)

# Suggest next steps
print("\nPer eseguire un'analisi completa su un target:")
print("  python -c \"")
print("    from Suite.cli.orchestrator import SecuritySuiteOrchestrator, AnalysisConfig")
print("    from pathlib import Path")
print("    config = AnalysisConfig(")
print("        target_url='https://httpbin.org/status/403',")
print("        results_dir=Path('results')")
print("    )")
print("    orchestrator = SecuritySuiteOrchestrator(config)")
print("    orchestrator.run()")
print("  \"")
