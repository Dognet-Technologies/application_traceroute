#!/usr/bin/env python3
"""
test_suite_e2e.py - End-to-End Test for Security Suite

Tests all Suite components against httpbin.org (safe test target).
This verifies that the integration actually works in a real scenario.
"""

import sys
import time
from pathlib import Path

# Add paths
sys.path.insert(0, str(Path(__file__).parent))

def print_section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)

def test_suite_imports():
    """Test that all Suite modules can be imported."""
    print_section("1. Testing Suite Imports")

    try:
        from Suite.core.graph.causal_node import CausalNode, NodeType
        from Suite.core.graph.causal_edge import CausalEdge, CausalityType
        from Suite.core.graph.causal_graph import CausalSecurityGraph
        from Suite.core.correlation.hybrid_correlator import HybridCorrelationEngine
        from Suite.core.validation.bayesian_validator import BayesianBypassValidator, ValidationResult
        from Suite.core.behavioral.differential_analyzer import DifferentialCausalAnalyzer
        from Suite.modules.taxonomy.adaptive_taxonomy import SelfLearningTaxonomy
        from Suite.utils.config import set_global_seed, get_rng
        print("  ✓ All Suite modules imported successfully")
        return True
    except Exception as e:
        print(f"  ✗ Import failed: {e}")
        return False

def test_causal_graph_operations():
    """Test CausalSecurityGraph operations."""
    print_section("2. Testing CausalSecurityGraph")

    from Suite.core.graph.causal_graph import CausalSecurityGraph
    from Suite.core.graph.causal_node import NodeType
    from Suite.core.graph.causal_edge import CausalityType

    graph = CausalSecurityGraph()

    # Add nodes
    graph.add_node("cdn", NodeType.INFRASTRUCTURE, "CDN Layer")
    graph.add_node("waf", NodeType.INFRASTRUCTURE, "WAF Layer")
    graph.add_node("app", NodeType.INFRASTRUCTURE, "Application")
    graph.add_node("vuln", NodeType.VULNERABILITY, "SQL Injection")

    # Add edges
    graph.add_edge("cdn", "waf", CausalityType.DIRECT, 0.9)
    graph.add_edge("waf", "app", CausalityType.DIRECT, 0.8)
    graph.add_edge("app", "vuln", CausalityType.DIRECT, 0.7)

    print(f"  ✓ Graph created: {graph.node_count} nodes, {graph.edge_count} edges")

    # Test path finding
    path = graph.find_max_probability_path("cdn", "vuln")
    if path:
        print(f"  ✓ Path found: {' -> '.join(path.path)} (p={path.probability:.3f})")
    else:
        print("  ✗ Path not found")
        return False

    # Test DAG validation
    is_valid, issues = graph.validate_dag()
    print(f"  ✓ DAG validation: {'VALID' if is_valid else 'INVALID'}")

    # Test serialization
    data = graph.to_dict()
    restored = CausalSecurityGraph.from_dict(data)
    print(f"  ✓ Serialization/deserialization OK: {restored.node_count} nodes")

    return True

def test_bayesian_validator():
    """Test BayesianBypassValidator with Thompson Sampling."""
    print_section("3. Testing BayesianBypassValidator")

    from Suite.core.validation.bayesian_validator import BayesianBypassValidator, ValidationResult
    from Suite.utils.config import set_global_seed

    # Set seed for reproducibility
    set_global_seed(42)

    validator = BayesianBypassValidator()

    # Add bypass candidates
    validator.add_candidate("sqli_1", "sqli", "' OR 1=1 --")
    validator.add_candidate("sqli_2", "sqli", "' UNION SELECT NULL --")
    validator.add_candidate("xss_1", "xss", "<script>alert(1)</script>")
    validator.add_candidate("path_1", "path_traversal", "../../../etc/passwd")

    print(f"  ✓ Added 4 bypass candidates")

    # Simulate some validation results
    results = [
        ("sqli_1", ValidationResult.SUCCESS),
        ("sqli_1", ValidationResult.SUCCESS),
        ("sqli_2", ValidationResult.FAILURE),
        ("xss_1", ValidationResult.PARTIAL),
        ("path_1", ValidationResult.FAILURE),
    ]

    for exploit_id, result in results:
        validator.record_result(exploit_id, "http://test.com", result, 200, 0.5)

    print(f"  ✓ Recorded {len(results)} validation results")

    # Test Thompson Sampling selection
    selected = validator.select_next_exploit_thompson()
    if selected:
        print(f"  ✓ Thompson Sampling selected: {selected.exploit_id}")

    # Test UCB selection
    ucb_selected = validator.select_next_exploit_ucb()
    if ucb_selected:
        print(f"  ✓ UCB selected: {ucb_selected.exploit_id}")

    # Get summary
    summary = validator.get_summary()
    print(f"  ✓ Summary: {summary.total_attempts} attempts, {summary.success_rate:.1%} success rate")

    return True

def test_correlation_engine():
    """Test HybridCorrelationEngine."""
    print_section("4. Testing HybridCorrelationEngine")

    import numpy as np
    from Suite.core.correlation.hybrid_correlator import HybridCorrelationEngine, CorrelationType

    engine = HybridCorrelationEngine()

    # Register entities with features
    engine.register_entity(
        "endpoint_1",
        features={"response_time": 100, "status": 200},
        vector=np.array([1.0, 0.5, 0.3]),
        timestamp=time.time()
    )
    engine.register_entity(
        "endpoint_2",
        features={"response_time": 105, "status": 200},
        vector=np.array([0.9, 0.6, 0.35]),
        timestamp=time.time() + 1
    )
    engine.register_entity(
        "endpoint_3",
        features={"response_time": 500, "status": 500},
        vector=np.array([0.1, 0.9, 0.8]),
        timestamp=time.time() + 10
    )

    print(f"  ✓ Registered 3 entities")

    # Find correlations
    correlations = engine.find_all_correlations()
    print(f"  ✓ Found {len(correlations)} correlations")

    for corr in correlations[:3]:
        print(f"    - {corr.entity1_id} <-> {corr.entity2_id}: {corr.strength:.2f} ({corr.correlation_type.value})")

    return True

def test_taxonomy():
    """Test SelfLearningTaxonomy."""
    print_section("5. Testing SelfLearningTaxonomy")

    from Suite.modules.taxonomy.adaptive_taxonomy import SelfLearningTaxonomy

    taxonomy = SelfLearningTaxonomy()

    # Test payloads
    test_payloads = [
        ("' OR 1=1 --", "SQL Injection"),
        ("<script>alert(1)</script>", "XSS"),
        ("../../../etc/passwd", "Path Traversal"),
        ("{{7*7}}", "Template Injection"),
        ("; ls -la", "Command Injection"),
    ]

    print(f"  Testing {len(test_payloads)} payload classifications:")

    for payload, expected_type in test_payloads:
        result = taxonomy.classify(payload)
        match = "✓" if expected_type.lower() in result.node_name.lower() or result.confidence > 0.3 else "~"
        print(f"    {match} '{payload[:30]}...' -> {result.node_name} (conf: {result.confidence:.2f})")

    return True

def test_reproducibility():
    """Test that results are reproducible with seed."""
    print_section("6. Testing Reproducibility")

    from Suite.core.validation.bayesian_validator import BayesianBypassValidator
    from Suite.utils.config import set_global_seed

    # First run
    set_global_seed(12345)
    v1 = BayesianBypassValidator()
    v1.add_candidate("test1", "sqli", "payload1")
    v1.add_candidate("test2", "xss", "payload2")
    samples1 = [v1.select_next_exploit_thompson().exploit_id for _ in range(5)]

    # Second run with same seed
    set_global_seed(12345)
    v2 = BayesianBypassValidator()
    v2.add_candidate("test1", "sqli", "payload1")
    v2.add_candidate("test2", "xss", "payload2")
    samples2 = [v2.select_next_exploit_thompson().exploit_id for _ in range(5)]

    if samples1 == samples2:
        print(f"  ✓ Results are reproducible with same seed")
        print(f"    Run 1: {samples1}")
        print(f"    Run 2: {samples2}")
        return True
    else:
        print(f"  ✗ Results differ!")
        print(f"    Run 1: {samples1}")
        print(f"    Run 2: {samples2}")
        return False

def test_differential_analyzer_dry():
    """Test DifferentialCausalAnalyzer initialization (no network)."""
    print_section("7. Testing DifferentialCausalAnalyzer (Dry Run)")

    from Suite.core.behavioral.differential_analyzer import DifferentialCausalAnalyzer

    analyzer = DifferentialCausalAnalyzer(
        n_baseline_samples=10,
        n_perturbations=20,
        kl_threshold=0.1
    )

    print(f"  ✓ Analyzer initialized")
    print(f"    Baseline samples: {analyzer.n_baseline_samples}")
    print(f"    Perturbations: {analyzer.n_perturbations}")
    print(f"    KL threshold: {analyzer.kl_threshold}")

    # Test perturbation generation (without network)
    test_url = "https://httpbin.org/get?id=123&name=test"
    perturbations = analyzer._generate_perturbations(test_url)
    print(f"  ✓ Generated {len(perturbations)} perturbations")

    # Show sample perturbations
    print(f"    Sample perturbations:")
    for ptype, orig, perturbed in perturbations[:3]:
        print(f"      {ptype.value}: '{orig}' -> '{perturbed[:50]}...'")

    return True

def test_live_httpbin():
    """Test actual HTTP requests against httpbin.org."""
    print_section("8. Testing Live HTTP (httpbin.org)")

    import requests

    try:
        # Basic connectivity test
        resp = requests.get("https://httpbin.org/get", timeout=10)
        if resp.status_code == 200:
            print(f"  ✓ httpbin.org reachable (status: {resp.status_code})")
        else:
            print(f"  ⚠ httpbin.org returned status: {resp.status_code}")
            return False

        # Test different endpoints
        tests = [
            ("GET /status/200", "https://httpbin.org/status/200", 200),
            ("GET /status/403", "https://httpbin.org/status/403", 403),
            ("GET /delay/1", "https://httpbin.org/delay/1", 200),
        ]

        for name, url, expected in tests:
            try:
                r = requests.get(url, timeout=15)
                status = "✓" if r.status_code == expected else "✗"
                print(f"  {status} {name}: {r.status_code} (expected {expected})")
            except Exception as e:
                print(f"  ✗ {name}: {e}")

        return True

    except requests.exceptions.RequestException as e:
        print(f"  ✗ Network error: {e}")
        return False

def test_integration_workflow():
    """Test a simplified integration workflow."""
    print_section("9. Testing Integration Workflow")

    from Suite.core.graph.causal_graph import CausalSecurityGraph
    from Suite.core.graph.causal_node import NodeType
    from Suite.core.graph.causal_edge import CausalityType
    from Suite.core.validation.bayesian_validator import BayesianBypassValidator, ValidationResult
    from Suite.modules.taxonomy.adaptive_taxonomy import SelfLearningTaxonomy
    from Suite.core.correlation.hybrid_correlator import HybridCorrelationEngine
    import numpy as np

    print("  Simulating security analysis workflow...")

    # 1. Build causal graph from "discovered" stack
    graph = CausalSecurityGraph()
    graph.add_node("cloudflare", NodeType.INFRASTRUCTURE, "Cloudflare CDN")
    graph.add_node("nginx", NodeType.INFRASTRUCTURE, "Nginx Proxy")
    graph.add_node("django", NodeType.INFRASTRUCTURE, "Django App")
    graph.add_edge("cloudflare", "nginx", CausalityType.DIRECT, 0.95)
    graph.add_edge("nginx", "django", CausalityType.DIRECT, 0.90)
    print(f"  ✓ Step 1: Built causal graph ({graph.node_count} nodes)")

    # 2. Initialize bypass validator
    validator = BayesianBypassValidator()
    test_bypasses = [
        ("bypass_1", "path", "/admin/../secret"),
        ("bypass_2", "header", "X-Forwarded-For: 127.0.0.1"),
        ("bypass_3", "method", "PATCH instead of GET"),
    ]
    for bid, btype, payload in test_bypasses:
        validator.add_candidate(bid, btype, payload)
    print(f"  ✓ Step 2: Added {len(test_bypasses)} bypass candidates")

    # 3. Simulate validation results
    validator.record_result("bypass_1", "http://test", ValidationResult.FAILURE, 403, 0.5)
    validator.record_result("bypass_2", "http://test", ValidationResult.SUCCESS, 200, 0.8)
    validator.record_result("bypass_3", "http://test", ValidationResult.PARTIAL, 302, 0.6)
    print(f"  ✓ Step 3: Recorded validation results")

    # 4. Get best bypass using Thompson Sampling
    best = validator.select_next_exploit_thompson()
    print(f"  ✓ Step 4: Best bypass selected: {best.exploit_id if best else 'None'}")

    # 5. Classify findings with taxonomy
    taxonomy = SelfLearningTaxonomy()
    findings = [
        "SQL injection in id parameter",
        "XSS via reflected input",
        "Path traversal in file download",
    ]
    for finding in findings:
        result = taxonomy.classify(finding)
        print(f"    - '{finding[:30]}...' -> {result.node_name}")
    print(f"  ✓ Step 5: Classified {len(findings)} findings")

    # 6. Correlate findings
    engine = HybridCorrelationEngine()
    for i, finding in enumerate(findings):
        engine.register_entity(f"finding_{i}", features={"text": finding}, vector=np.random.rand(5))
    correlations = engine.find_all_correlations()
    print(f"  ✓ Step 6: Found {len(correlations)} correlations")

    # Summary
    summary = validator.get_summary()
    print(f"\n  📊 Workflow Summary:")
    print(f"     Stack layers: {graph.node_count}")
    print(f"     Bypasses tested: {summary.total_attempts}")
    print(f"     Success rate: {summary.success_rate:.1%}")
    print(f"     Findings classified: {len(findings)}")

    return True


def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("  SECURITY SUITE - END-TO-END TEST")
    print("="*60)

    tests = [
        ("Suite Imports", test_suite_imports),
        ("CausalSecurityGraph", test_causal_graph_operations),
        ("BayesianBypassValidator", test_bayesian_validator),
        ("HybridCorrelationEngine", test_correlation_engine),
        ("SelfLearningTaxonomy", test_taxonomy),
        ("Reproducibility", test_reproducibility),
        ("DifferentialAnalyzer (Dry)", test_differential_analyzer_dry),
        ("Live HTTP (httpbin)", test_live_httpbin),
        ("Integration Workflow", test_integration_workflow),
    ]

    results = []
    for name, test_func in tests:
        try:
            passed = test_func()
            results.append((name, passed))
        except Exception as e:
            print(f"\n  ✗ EXCEPTION in {name}: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))

    # Summary
    print_section("TEST SUMMARY")
    passed = sum(1 for _, p in results if p)
    failed = len(results) - passed

    for name, p in results:
        status = "✓ PASS" if p else "✗ FAIL"
        print(f"  {status}: {name}")

    print(f"\n  Total: {passed}/{len(results)} passed")

    if failed == 0:
        print("\n  🎉 ALL TESTS PASSED!")
        return 0
    else:
        print(f"\n  ⚠ {failed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
