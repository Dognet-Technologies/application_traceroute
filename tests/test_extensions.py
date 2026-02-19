#!/usr/bin/env python3
"""
Test Suite for Security Testing Suite v4.0 Extensions

Tests:
- CausalResponseAnalyzer (Module 1)
- CausalVulnerabilityAnalyzer (Module 2)
- SelfLearningTaxonomy (Module 3)

Run with: python -m unittest tests.test_extensions -v
"""

import sys
from pathlib import Path

# Add parent path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import unittest


def mock_response(status_code=200, text="", headers=None, cookies=None, elapsed=0.1):
    """Helper to create mock response dictionaries"""
    return {
        'status_code': status_code,
        'text': text,
        'content': text.encode() if isinstance(text, str) else text,
        'headers': headers or {},
        'cookies': cookies or {},
        'elapsed': elapsed
    }


# =============================================================================
# MODULE 1 TESTS: CausalResponseAnalyzer
# =============================================================================

class TestCausalResponseAnalyzer(unittest.TestCase):
    """Tests for CausalResponseAnalyzer"""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures"""
        from extensions.response import (
            CausalResponseAnalyzer,
            ContentClassifier,
            LayerIdentifier,
            BehavioralAnalyzer,
            ContentType
        )
        cls.CausalResponseAnalyzer = CausalResponseAnalyzer
        cls.ContentClassifier = ContentClassifier
        cls.LayerIdentifier = LayerIdentifier
        cls.BehavioralAnalyzer = BehavioralAnalyzer
        cls.ContentType = ContentType

    def setUp(self):
        """Set up for each test"""
        self.analyzer = self.CausalResponseAnalyzer()

    def test_true_bypass_detection(self):
        """Test detection of true bypass"""
        baseline = mock_response(
            status_code=403,
            text="<html>Access Denied - WAF Blocked</html>",
            headers={'x-waf': 'blocked'}
        )

        test = mock_response(
            status_code=200,
            text='<html>Admin Panel<form>User Management</form></html>',
            headers={'x-powered-by': 'PHP/7.4'},
            cookies={'PHPSESSID': 'abc123'}
        )

        result = self.analyzer.verify_bypass(
            baseline_response=baseline,
            test_response=test,
            bypass_info={
                'type': 'Header Confusion',
                'test_name': 'X-Original-URL Test',
                'target_layers': ['WAF']
            }
        )

        self.assertTrue(result.is_true_bypass)
        self.assertGreater(result.confidence, 0.75)
        self.assertIn('admin_interface', result.protected_indicators)

    def test_false_positive_detection(self):
        """Test detection of false positive"""
        baseline = mock_response(
            status_code=403,
            text="<html>Access Denied</html>",
            headers={'x-waf': 'blocked'}
        )

        test = mock_response(
            status_code=403,
            text="<html>Request Blocked by Firewall</html>",
            headers={'x-waf': 'blocked'}
        )

        result = self.analyzer.verify_bypass(
            baseline_response=baseline,
            test_response=test,
            bypass_info={
                'type': 'Header Confusion',
                'test_name': 'Failed Test',
                'target_layers': ['WAF']
            }
        )

        self.assertFalse(result.is_true_bypass)
        self.assertIn('same_status_code', result.false_positive_indicators)

    def test_content_classifier(self):
        """Test content classification"""
        classifier = self.ContentClassifier()

        # Test error page
        error_response = mock_response(
            status_code=403,
            text="Access Denied - You are not authorized"
        )
        result = classifier.classify(error_response)
        self.assertEqual(result, self.ContentType.ERROR_PAGE)

        # Test API response
        api_response = mock_response(
            status_code=200,
            text='{"users": [{"id": 1}]}',
            headers={'content-type': 'application/json'}
        )
        result = classifier.classify(api_response)
        self.assertEqual(result, self.ContentType.API_RESPONSE)

    def test_layer_identifier(self):
        """Test infrastructure layer identification"""
        identifier = self.LayerIdentifier()

        # Test Cloudflare detection
        cf_response = mock_response(
            status_code=200,
            text="OK",
            headers={
                'cf-ray': '123abc',
                'cf-cache-status': 'HIT',
                'server': 'cloudflare'
            }
        )

        layers = identifier.identify_layers(cf_response)
        self.assertIn('CDN', layers)

    def test_behavioral_analyzer(self):
        """Test behavioral analysis"""
        analyzer = self.BehavioralAnalyzer()

        baseline = mock_response(
            status_code=403,
            text="Blocked",
            elapsed=0.1
        )

        test = mock_response(
            status_code=200,
            text="Welcome to Admin Panel " * 100,
            elapsed=0.5,
            cookies={'session': 'new_session'}
        )

        diff = analyzer.analyze_differential(baseline, test)

        self.assertTrue(diff.significant_change)
        self.assertGreater(diff.size_diff, 100)


# =============================================================================
# MODULE 2 TESTS: CausalVulnerabilityAnalyzer
# =============================================================================

class TestCausalVulnerabilityAnalyzer(unittest.TestCase):
    """Tests for CausalVulnerabilityAnalyzer"""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures"""
        from extensions.vulnerability import (
            CausalVulnerabilityAnalyzer,
            SQLiAnalyzer,
            XSSAnalyzer,
            LFIAnalyzer,
            DatabaseType,
            XSSContext
        )
        cls.CausalVulnerabilityAnalyzer = CausalVulnerabilityAnalyzer
        cls.SQLiAnalyzer = SQLiAnalyzer
        cls.XSSAnalyzer = XSSAnalyzer
        cls.LFIAnalyzer = LFIAnalyzer
        cls.DatabaseType = DatabaseType
        cls.XSSContext = XSSContext

    def setUp(self):
        """Set up for each test"""
        self.analyzer = self.CausalVulnerabilityAnalyzer()

    def test_sqli_error_detection(self):
        """Test SQL injection error-based detection"""
        response = mock_response(
            status_code=500,
            text="You have an error in your SQL syntax near 'test' at line 1"
        )

        result = self.analyzer.analyze(
            endpoint="http://example.com/search",
            param="q",
            payload="' OR 1=1-- -",
            response=response,
            vuln_type="sqli"
        )

        self.assertTrue(result.is_vulnerable)
        self.assertGreater(result.confidence, 0.75)
        self.assertEqual(result.database_type, 'MySQL')

    def test_sqli_postgresql_detection(self):
        """Test PostgreSQL error detection"""
        response_text = "PostgreSQL ERROR: syntax error at or near"

        sqli_analyzer = self.SQLiAnalyzer()
        errors, db_type = sqli_analyzer.detect_errors(response_text)

        self.assertTrue(len(errors) > 0)
        self.assertEqual(db_type, self.DatabaseType.POSTGRESQL)

    def test_xss_reflected_detection(self):
        """Test XSS reflected detection"""
        response = mock_response(
            status_code=200,
            text='<html><body><div><script>alert(1)</script></div></body></html>'
        )

        result = self.analyzer.analyze(
            endpoint="http://example.com/page",
            param="name",
            payload="<script>alert(1)</script>",
            response=response,
            vuln_type="xss"
        )

        self.assertTrue(result.is_vulnerable)
        self.assertGreater(result.confidence, 0.5)

    def test_xss_context_detection(self):
        """Test XSS context detection"""
        xss_analyzer = self.XSSAnalyzer()

        # JavaScript context
        response = '<script>var x = "test<script>alert(1)</script>";</script>'
        result = xss_analyzer.analyze(response, '<script>alert(1)</script>')

        self.assertEqual(result.context, self.XSSContext.JAVASCRIPT)

    def test_lfi_detection(self):
        """Test LFI detection"""
        response = mock_response(
            status_code=200,
            text='root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent'
        )

        result = self.analyzer.analyze(
            endpoint="http://example.com/file",
            param="path",
            payload="../../../../etc/passwd",
            response=response,
            vuln_type="lfi"
        )

        self.assertTrue(result.is_vulnerable)
        self.assertGreater(result.confidence, 0.75)

    def test_lfi_windows_detection(self):
        """Test Windows LFI detection"""
        lfi_analyzer = self.LFIAnalyzer()

        response = "[boot loader]\ntimeout=30\n[operating systems]"
        result = lfi_analyzer.analyze(response, "..\\..\\boot.ini")

        self.assertTrue(result.is_vulnerable)
        self.assertEqual(result.file_accessed, 'boot.ini')

    def test_no_vulnerability(self):
        """Test clean response detection"""
        response = mock_response(
            status_code=200,
            text="<html><body>Normal page content</body></html>"
        )

        result = self.analyzer.analyze(
            endpoint="http://example.com/page",
            param="id",
            payload="' OR 1=1-- -",
            response=response,
            vuln_type="sqli"
        )

        self.assertFalse(result.is_vulnerable)


# =============================================================================
# MODULE 3 TESTS: SelfLearningTaxonomy
# =============================================================================

class TestSelfLearningTaxonomy(unittest.TestCase):
    """Tests for SelfLearningTaxonomy"""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures"""
        from extensions.taxonomy import (
            SelfLearningTaxonomy,
            TaxonomyDatabase,
            PatternLearner,
            AttackChainAnalyzer
        )
        cls.SelfLearningTaxonomy = SelfLearningTaxonomy
        cls.TaxonomyDatabase = TaxonomyDatabase
        cls.PatternLearner = PatternLearner
        cls.AttackChainAnalyzer = AttackChainAnalyzer

    def setUp(self):
        """Set up for each test"""
        self.taxonomy = self.SelfLearningTaxonomy()

    def test_sqli_classification(self):
        """Test SQL injection classification"""
        result = self.taxonomy.classify(
            vuln_type='sqli',
            evidence=[{'type': 'error', 'strength': 0.95}],
            context={'internet_facing': True}
        )

        self.assertEqual(result.primary_category, 'injection')
        self.assertIn('CWE-89', result.cwe_ids)
        self.assertEqual(result.severity, 'CRITICAL')
        self.assertGreaterEqual(result.cvss_score, 9.0)

    def test_xss_classification(self):
        """Test XSS classification"""
        result = self.taxonomy.classify(vuln_type='xss')

        self.assertEqual(result.primary_category, 'xss')
        self.assertIn('CWE-79', result.cwe_ids)
        self.assertIn('A03:2021', result.owasp_categories)

    def test_pattern_learning(self):
        """Test pattern learning from vulnerabilities"""
        pattern = self.taxonomy.learn(
            vuln_type='sqli',
            payload="' OR 1=1-- -",
            response="MySQL syntax error",
            is_confirmed=True
        )

        self.assertIsNotNone(pattern)
        self.assertEqual(pattern.vuln_type, 'sqli')
        self.assertGreater(pattern.confidence, 0.5)

    def test_pattern_learning_incremental(self):
        """Test incremental pattern learning"""
        pattern1 = self.taxonomy.learn(
            vuln_type='sqli',
            payload="' OR 1=1-- -",
            response="MySQL syntax error",
            is_confirmed=True
        )

        pattern2 = self.taxonomy.learn(
            vuln_type='sqli',
            payload="' OR 1=1-- -",
            response="Another MySQL error",
            is_confirmed=True
        )

        self.assertEqual(pattern2.occurrences, 2)

    def test_attack_chain_analysis(self):
        """Test attack chain analysis"""
        chain_analyzer = self.AttackChainAnalyzer()

        chain_analyzer.add_vulnerability('ssrf')
        chains = chain_analyzer.analyze_chains()

        self.assertGreater(len(chains), 0)

        ssrf_chain = next(
            (c for c in chains if 'ssrf' in c['chain_name']),
            None
        )
        self.assertIsNotNone(ssrf_chain)

    def test_remediation_guidance(self):
        """Test remediation guidance retrieval"""
        fixes = self.taxonomy.get_remediation('sqli')

        self.assertGreater(len(fixes), 0)
        self.assertTrue(any('parameterized' in f.lower() for f in fixes))

    def test_cwe_info(self):
        """Test CWE information retrieval"""
        info = self.taxonomy.get_cwe_info('CWE-89')

        self.assertIsNotNone(info)
        self.assertEqual(info['cwe_id'], 'CWE-89')
        self.assertEqual(info['vulnerability_type'], 'sqli')

    def test_severity_adjustment(self):
        """Test context-based severity adjustment"""
        # Internet facing, high sensitivity
        result1 = self.taxonomy.classify(
            vuln_type='sqli',
            context={'internet_facing': True, 'data_sensitivity': 'high'}
        )

        # Internal, low sensitivity
        result2 = self.taxonomy.classify(
            vuln_type='sqli',
            context={'internet_facing': False, 'data_sensitivity': 'low', 'requires_auth': True}
        )

        self.assertGreater(result1.cvss_score, result2.cvss_score)

    def test_export_import_state(self):
        """Test state export and import"""
        # Learn some patterns
        self.taxonomy.learn('sqli', "' OR 1=1", "error", True)
        self.taxonomy.learn('xss', '<script>', "reflected", True)

        # Export
        state = self.taxonomy.export_state()

        # Create new taxonomy and import
        new_taxonomy = self.SelfLearningTaxonomy()
        new_taxonomy.import_state(state)

        # Verify imported patterns
        patterns = new_taxonomy.pattern_learner.learned_patterns
        self.assertEqual(len(patterns), 2)


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestIntegration(unittest.TestCase):
    """Integration tests for all modules working together"""

    def test_full_analysis_pipeline(self):
        """Test complete analysis pipeline"""
        from extensions.response import CausalResponseAnalyzer
        from extensions.vulnerability import CausalVulnerabilityAnalyzer
        from extensions.taxonomy import SelfLearningTaxonomy

        # 1. Create mock responses
        baseline = mock_response(status_code=403, text="Access Denied")

        bypass_response = mock_response(
            status_code=200,
            text="<html>Admin: Users<table>user data</table></html>",
            headers={'x-powered-by': 'PHP'}
        )

        vuln_response = mock_response(
            status_code=500,
            text="You have an error in your SQL syntax"
        )

        # 2. Verify bypass
        response_analyzer = CausalResponseAnalyzer()
        bypass_result = response_analyzer.verify_bypass(
            baseline_response=baseline,
            test_response=bypass_response,
            bypass_info={'type': 'test', 'test_name': 'test', 'target_layers': []}
        )

        self.assertTrue(bypass_result.is_true_bypass)

        # 3. Analyze vulnerability
        vuln_analyzer = CausalVulnerabilityAnalyzer()
        vuln_result = vuln_analyzer.analyze(
            endpoint="http://test.com/admin",
            param="id",
            payload="' OR 1=1",
            response=vuln_response,
            vuln_type="sqli"
        )

        self.assertTrue(vuln_result.is_vulnerable)

        # 4. Classify with taxonomy
        taxonomy = SelfLearningTaxonomy()
        classification = taxonomy.classify(
            vuln_type='sqli',
            evidence=vuln_result.evidence
        )

        self.assertEqual(classification.severity, 'CRITICAL')

        # 5. Learn from finding
        taxonomy.learn(
            vuln_type='sqli',
            payload="' OR 1=1",
            response=vuln_response['text'],
            is_confirmed=True
        )

        stats = taxonomy.get_statistics()
        self.assertEqual(stats['learnings'], 1)


# =============================================================================
<<<<<<< HEAD
# MODULE 4 TESTS: Extended Analyzer Routing
# =============================================================================

class TestExtendedAnalyzerRouting(unittest.TestCase):
    """Tests for CausalVulnerabilityAnalyzer routing to extended analyzers"""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures"""
        from extensions.vulnerability import CausalVulnerabilityAnalyzer
        cls.CausalVulnerabilityAnalyzer = CausalVulnerabilityAnalyzer

    def setUp(self):
        """Set up for each test"""
        self.analyzer = self.CausalVulnerabilityAnalyzer()

    def test_ssti_detection(self):
        """Test SSTI detection via extended analyzer routing"""
        response = mock_response(
            status_code=200,
            text='Hello 49!'
        )

        result = self.analyzer.analyze(
            endpoint="http://example.com/greet",
            param="name",
            payload="{{7*7}}",
            response=response,
            vuln_type="ssti"
        )

        self.assertTrue(result.is_vulnerable)
        self.assertGreater(result.confidence, 0.75)
        self.assertEqual(result.vulnerability_type, 'ssti')

    def test_xxe_detection(self):
        """Test XXE detection via extended analyzer routing"""
        response = mock_response(
            status_code=200,
            text='root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534'
        )

        result = self.analyzer.analyze(
            endpoint="http://example.com/xml",
            param="data",
            payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            response=response,
            vuln_type="xxe"
        )

        self.assertTrue(result.is_vulnerable)
        self.assertGreater(result.confidence, 0.75)
        self.assertEqual(result.vulnerability_type, 'xxe')

    def test_nosqli_detection(self):
        """Test NoSQL injection detection via extended analyzer routing"""
        response = mock_response(
            status_code=500,
            text='MongoError: command failed with error 2'
        )

        result = self.analyzer.analyze(
            endpoint="http://example.com/api/users",
            param="id",
            payload='{"$ne": null}',
            response=response,
            vuln_type="nosqli"
        )

        self.assertTrue(result.is_vulnerable)
        self.assertGreater(result.confidence, 0.75)
        self.assertEqual(result.vulnerability_type, 'nosqli')

    def test_xpath_detection(self):
        """Test XPath injection detection via extended analyzer routing"""
        response = mock_response(
            status_code=500,
            text='XPath error: Invalid XPath expression supplied'
        )

        result = self.analyzer.analyze(
            endpoint="http://example.com/search",
            param="query",
            payload="' or '1'='1",
            response=response,
            vuln_type="xpath"
        )

        self.assertTrue(result.is_vulnerable)
        self.assertGreater(result.confidence, 0.75)
        self.assertEqual(result.vulnerability_type, 'xpath')

    def test_ssti_no_vulnerability(self):
        """Test SSTI with clean response returns not vulnerable"""
        response = mock_response(
            status_code=200,
            text='Hello {{7*7}}!'
        )

        result = self.analyzer.analyze(
            endpoint="http://example.com/greet",
            param="name",
            payload="{{7*7}}",
            response=response,
            vuln_type="ssti"
        )

        # Template expression was NOT evaluated (echoed back literally)
        self.assertFalse(result.is_vulnerable)

    def test_unknown_type_returns_generic(self):
        """Test unknown vuln type falls through to generic handler"""
        response = mock_response(
            status_code=200,
            text='Normal page content'
        )

        result = self.analyzer.analyze(
            endpoint="http://example.com/page",
            param="id",
            payload="test",
            response=response,
            vuln_type="unknown_type"
        )

        self.assertFalse(result.is_vulnerable)


class TestXSSFalsePositiveFixes(unittest.TestCase):
    """Tests for XSS false positive reduction"""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures"""
        from extensions.vulnerability import XSSAnalyzer, XSSContext
        cls.XSSAnalyzer = XSSAnalyzer
        cls.XSSContext = XSSContext

    def setUp(self):
        """Set up for each test"""
        self.analyzer = self.XSSAnalyzer()

    def test_no_false_positive_from_distant_event_handler(self):
        """Event handlers far from reflected payload should not trigger bypass detection"""
        # Payload is reflected in a div, but legitimate onclick is elsewhere on page
        response_text = (
            '<html><body>'
            '<button onclick="save()">Save</button>'  # Legitimate handler
            '<div>Some content here</div>'
            '<p>Your search: test_value</p>'  # Reflected payload (safe)
            '</body></html>'
        )

        result = self.analyzer.analyze(response_text, 'test_value')

        # Should detect reflection but NOT flag as filter_bypassed
        # because the event handler is far from the reflected payload
        self.assertFalse(result.filter_bypassed)

    def test_true_positive_reflected_xss(self):
        """Actual XSS payload reflected in executable context"""
        response_text = (
            '<html><body>'
            '<div><script>alert(1)</script></div>'
            '</body></html>'
        )

        result = self.analyzer.analyze(response_text, '<script>alert(1)</script>')

        self.assertTrue(result.is_vulnerable)
        self.assertGreater(result.confidence, 0.8)


class TestRCEFalsePositiveFixes(unittest.TestCase):
    """Tests for RCE hostname pattern false positive reduction"""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures"""
        from extensions.vulnerability import CausalVulnerabilityAnalyzer
        cls.CausalVulnerabilityAnalyzer = CausalVulnerabilityAnalyzer

    def setUp(self):
        """Set up for each test"""
        self.analyzer = self.CausalVulnerabilityAnalyzer()

    def test_no_false_positive_from_normal_text(self):
        """Normal page text should not trigger RCE hostname detection"""
        response = mock_response(
            status_code=200,
            text='<html><body>Welcome to our website</body></html>'
        )

        result = self.analyzer.analyze(
            endpoint="http://example.com/page",
            param="cmd",
            payload="; whoami",
            response=response,
            vuln_type="rce"
        )

        self.assertFalse(result.is_vulnerable)

    def test_true_positive_id_command(self):
        """Actual id command output should be detected"""
        response = mock_response(
            status_code=200,
            text='uid=33(www-data) gid=33(www-data) groups=33(www-data)'
        )

        result = self.analyzer.analyze(
            endpoint="http://example.com/exec",
            param="cmd",
            payload="; id",
            response=response,
            vuln_type="rce"
        )

        self.assertTrue(result.is_vulnerable)
        self.assertGreater(result.confidence, 0.75)


# =============================================================================
=======
>>>>>>> e71c17c (Risolti conflitti merge)
# MAIN
# =============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("Security Testing Suite v4.0 - Extension Tests")
    print("=" * 60)

    # Run tests
    unittest.main(verbosity=2)
