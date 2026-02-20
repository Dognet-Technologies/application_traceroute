#!/usr/bin/env python3
"""
Causal Response Analyzer v4.0
Enhanced response verification with multi-level causal analysis

This module provides sophisticated verification of bypass attempts
using multi-level analysis including:
- Content semantic classification
- Protected content detection
- Causal layer analysis
- Behavioral fingerprinting
- Bayesian confidence scoring

Author: Security Testing Suite
License: Authorized security research only
"""

import re
import time
import hashlib
import math
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import Counter

try:
    import requests
except ImportError:
    requests = None

# Import from core engines (optional - fallback implementations provided)
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from core.engines.advanced_bypass_engine import (
        BayesianBypassInference,
        BypassEvidence,
        BypassConfidence
    )
    CORE_ENGINES_AVAILABLE = True
except ImportError:
    CORE_ENGINES_AVAILABLE = False

    # Fallback implementations
    class BypassConfidence(Enum):
        """Bypass confidence levels"""
        CRITICAL = "critical"
        HIGH = "high"
        MEDIUM = "medium"
        LOW = "low"
        MINIMAL = "minimal"

    @dataclass
    class BypassEvidence:
        """Evidence for bypass success"""
        evidence_type: str
        strength: float
        description: str
        likelihood_ratio: float

    class BayesianBypassInference:
        """Fallback Bayesian inference for bypass confidence"""
        def __init__(self, prior_probability: float = 0.05):
            self.prior_probability = prior_probability
            self.evidence_collected: List[Any] = []

        def add_evidence(self, evidence: BypassEvidence):
            self.evidence_collected.append(evidence)

        def get_posterior_probability(self) -> float:
            if not self.evidence_collected:
                return self.prior_probability
            prior_odds = self.prior_probability / (1 - self.prior_probability)
            log_odds = math.log(prior_odds)
            for ev in self.evidence_collected:
                lr = ev.likelihood_ratio if ev.likelihood_ratio > 0 else 10.0
                weighted_lr = 1 + (lr - 1) * ev.strength
                log_odds += math.log(max(0.001, weighted_lr))
            odds = math.exp(min(log_odds, 20))  # Prevent overflow
            return min(0.99, max(0.01, odds / (1 + odds)))

        def get_confidence_level(self) -> BypassConfidence:
            prob = self.get_posterior_probability()
            if prob >= 0.95: return BypassConfidence.CRITICAL
            elif prob >= 0.85: return BypassConfidence.HIGH
            elif prob >= 0.70: return BypassConfidence.MEDIUM
            elif prob >= 0.50: return BypassConfidence.LOW
            return BypassConfidence.MINIMAL

        def explain_reasoning(self) -> str:
            prob = self.get_posterior_probability()
            return f"Confidence: {prob:.1%} based on {len(self.evidence_collected)} evidence items"


# =============================================================================
# ENUMS AND DATA CLASSES
# =============================================================================

class ContentType(Enum):
    """Content type classification for HTTP responses"""
    ERROR_PAGE = "error_page"
    PROTECTED_CONTENT = "protected_content"
    DIFFERENT_ERROR_PAGE = "different_error_page"
    REDIRECT = "redirect"
    EMPTY = "empty"
    LOGIN_PAGE = "login_page"
    API_RESPONSE = "api_response"
    STATIC_CONTENT = "static_content"
    UNKNOWN = "unknown"


class LayerType(Enum):
    """Infrastructure layer types"""
    CDN = "CDN"
    WAF = "WAF"
    PROXY = "Proxy"
    LOAD_BALANCER = "LoadBalancer"
    BACKEND = "Backend"
    CACHE = "Cache"
    API_GATEWAY = "APIGateway"
    UNKNOWN = "Unknown"


@dataclass
class VerificationResult:
    """Result of bypass verification"""
    is_true_bypass: bool
    confidence: float
    confidence_level: str
    content_transition: str
    protected_indicators: List[str]
    reached_layers: List[str]
    evidence: List[Dict]
    reasoning: str

    # Additional analysis fields
    baseline_content_type: str = ""
    test_content_type: str = ""
    behavioral_changes: Dict = field(default_factory=dict)
    causal_chain: List[str] = field(default_factory=list)
    false_positive_indicators: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'is_true_bypass': self.is_true_bypass,
            'confidence': self.confidence,
            'confidence_level': self.confidence_level,
            'content_transition': self.content_transition,
            'protected_indicators': self.protected_indicators,
            'reached_layers': self.reached_layers,
            'evidence': self.evidence,
            'reasoning': self.reasoning,
            'baseline_content_type': self.baseline_content_type,
            'test_content_type': self.test_content_type,
            'behavioral_changes': self.behavioral_changes,
            'causal_chain': self.causal_chain,
            'false_positive_indicators': self.false_positive_indicators
        }


@dataclass
class ContentAnalysisResult:
    """Result of content analysis"""
    content_type: ContentType
    indicators_found: List[str]
    confidence: float
    raw_features: Dict = field(default_factory=dict)


@dataclass
class BehavioralDifferential:
    """Behavioral differences between responses"""
    significant_change: bool
    strength: float
    description: str
    likelihood_ratio: float
    timing_diff: float = 0.0
    entropy_diff: float = 0.0
    size_diff: int = 0
    new_cookies: Set[str] = field(default_factory=set)
    new_headers: Set[str] = field(default_factory=set)


# =============================================================================
# CONTENT CLASSIFIER
# =============================================================================

class ContentClassifier:
    """
    Advanced content classifier for HTTP responses.

    Uses multi-pattern matching to classify response types:
    - Error pages (WAF blocks, 403, 401, etc.)
    - Protected content (admin panels, API data, user content)
    - Login pages
    - API responses
    - Static content
    """

    # Error page indicators - compiled for performance
    ERROR_PATTERNS = [
        # WAF/Security blocks
        re.compile(r'access\s+denied', re.IGNORECASE),
        re.compile(r'forbidden', re.IGNORECASE),
        re.compile(r'not\s+authorized', re.IGNORECASE),
        re.compile(r'permission\s+denied', re.IGNORECASE),
        re.compile(r'blocked', re.IGNORECASE),
        re.compile(r'waf|firewall|security\s+block', re.IGNORECASE),
        re.compile(r'error\s+40[13]', re.IGNORECASE),
        re.compile(r'unauthorized\s+access', re.IGNORECASE),
        re.compile(r'restricted\s+area', re.IGNORECASE),
        re.compile(r'request\s+blocked', re.IGNORECASE),
        re.compile(r'access\s+control', re.IGNORECASE),
        # Generic errors
        re.compile(r'error\s+occurred', re.IGNORECASE),
        re.compile(r'something\s+went\s+wrong', re.IGNORECASE),
        re.compile(r'page\s+not\s+found', re.IGNORECASE),
        # Cloudflare specific
        re.compile(r'cloudflare.*ray\s+id', re.IGNORECASE),
        re.compile(r'attention\s+required', re.IGNORECASE),
        # AWS/Azure
        re.compile(r'accessdeniedexception', re.IGNORECASE),
        re.compile(r'request\s+has\s+been\s+blocked', re.IGNORECASE),
    ]

    # Protected content indicators by category
    PROTECTED_INDICATORS = {
        'admin_interface': [
            re.compile(r'admin\s*(panel|area|dashboard|console)', re.IGNORECASE),
            re.compile(r'administration', re.IGNORECASE),
            re.compile(r'control\s+panel', re.IGNORECASE),
            re.compile(r'management\s+console', re.IGNORECASE),
            re.compile(r'settings\s*</h[1-3]>', re.IGNORECASE),
            re.compile(r'user\s+management', re.IGNORECASE),
            re.compile(r'system\s+configuration', re.IGNORECASE),
        ],
        'api_data_response': [
            re.compile(r'"users"\s*:', re.IGNORECASE),
            re.compile(r'"data"\s*:\s*\[', re.IGNORECASE),
            re.compile(r'"items"\s*:\s*\[', re.IGNORECASE),
            re.compile(r'"results"\s*:\s*\[', re.IGNORECASE),
            re.compile(r'"records"\s*:', re.IGNORECASE),
            re.compile(r'"entities"\s*:', re.IGNORECASE),
            re.compile(r'"response"\s*:\s*\{', re.IGNORECASE),
            re.compile(r'"pagination"\s*:', re.IGNORECASE),
            re.compile(r'"total"\s*:\s*\d+', re.IGNORECASE),
        ],
        'user_authenticated_content': [
            re.compile(r'welcome\s+back', re.IGNORECASE),
            re.compile(r'logout|sign\s*out', re.IGNORECASE),
            re.compile(r'my\s+account', re.IGNORECASE),
            re.compile(r'user\s+profile', re.IGNORECASE),
            re.compile(r'my\s+settings', re.IGNORECASE),
            re.compile(r'profile\s+settings', re.IGNORECASE),
            re.compile(r'account\s+settings', re.IGNORECASE),
            re.compile(r'dashboard</title>', re.IGNORECASE),
            re.compile(r'hello,?\s+\w+', re.IGNORECASE),
        ],
        'interactive_forms': [
            re.compile(r'<form[^>]*method\s*=\s*["\']?post', re.IGNORECASE),
            re.compile(r'<input[^>]*type\s*=\s*["\']?password', re.IGNORECASE),
            re.compile(r'<button[^>]*type\s*=\s*["\']?submit', re.IGNORECASE),
            re.compile(r'save\s+changes', re.IGNORECASE),
            re.compile(r'delete\s+account', re.IGNORECASE),
            re.compile(r'update\s+profile', re.IGNORECASE),
            re.compile(r'create\s+new', re.IGNORECASE),
            re.compile(r'edit\s+', re.IGNORECASE),
        ],
        'database_content': [
            re.compile(r'<table[^>]*class\s*=\s*["\']?data', re.IGNORECASE),
            re.compile(r'showing\s+\d+\s+to\s+\d+', re.IGNORECASE),
            re.compile(r'total\s+records?:', re.IGNORECASE),
            re.compile(r'query\s+results?', re.IGNORECASE),
            re.compile(r'search\s+results?:\s*\d+', re.IGNORECASE),
            re.compile(r'<td[^>]*>\d{4}-\d{2}-\d{2}', re.IGNORECASE),  # Date in table
        ],
        'sensitive_data': [
            re.compile(r'api[_-]?key\s*[=:]', re.IGNORECASE),
            re.compile(r'secret[_-]?key\s*[=:]', re.IGNORECASE),
            re.compile(r'password\s*[=:]', re.IGNORECASE),
            re.compile(r'access[_-]?token\s*[=:]', re.IGNORECASE),
            re.compile(r'bearer\s+[a-zA-Z0-9._-]+', re.IGNORECASE),
            re.compile(r'private[_-]?key', re.IGNORECASE),
        ],
        'file_content': [
            re.compile(r'root:x:0:0:', re.IGNORECASE),  # /etc/passwd
            re.compile(r'\[boot\s+loader\]', re.IGNORECASE),  # boot.ini
            re.compile(r'<\?php', re.IGNORECASE),  # PHP source
            re.compile(r'#!/bin/(ba)?sh', re.IGNORECASE),  # Shell scripts
            re.compile(r'define\s*\(\s*[\'"]DB_', re.IGNORECASE),  # Config
        ],
    }

    # Login page indicators
    LOGIN_PATTERNS = [
        re.compile(r'<form[^>]*login', re.IGNORECASE),
        re.compile(r'sign\s*in</button>', re.IGNORECASE),
        re.compile(r'username|email[^>]*input', re.IGNORECASE),
        re.compile(r'password[^>]*input', re.IGNORECASE),
        re.compile(r'forgot\s+(your\s+)?password', re.IGNORECASE),
        re.compile(r'remember\s+me', re.IGNORECASE),
        re.compile(r'login\s*</title>', re.IGNORECASE),
    ]

    def __init__(self):
        """Initialize content classifier"""
        self._classification_cache = {}

    def classify(self, response: Any) -> ContentType:
        """
        Classify response content type

        Args:
            response: HTTP response object (requests.Response or similar)

        Returns:
            ContentType enum
        """
        # Handle mock responses for testing
        if hasattr(response, 'text'):
            content = response.text.lower() if response.text else ""
            status = getattr(response, 'status_code', 200)
        elif isinstance(response, dict):
            content = response.get('text', '').lower()
            status = response.get('status_code', 200)
        else:
            return ContentType.UNKNOWN

        # Check cache
        content_hash = hashlib.md5(content.encode()).hexdigest()[:16]
        if content_hash in self._classification_cache:
            return self._classification_cache[content_hash]

        # Check redirect first
        if status in [301, 302, 303, 307, 308]:
            result = ContentType.REDIRECT
        # Check error page BEFORE empty (status code takes precedence)
        elif self._is_error_page(content, status):
            result = ContentType.ERROR_PAGE
        # Check API response BEFORE empty (JSON content-type takes precedence)
        elif self._is_api_response(response):
            result = ContentType.API_RESPONSE
        # Check empty AFTER error page and API response checks
        elif len(content.strip()) < 50:
            result = ContentType.EMPTY
        # Check login page
        elif self._is_login_page(content):
            result = ContentType.LOGIN_PAGE
        # Check protected content
        elif self._has_protected_content(content, response):
            result = ContentType.PROTECTED_CONTENT
        # Check static content
        elif self._is_static_content(response):
            result = ContentType.STATIC_CONTENT
        else:
            result = ContentType.DIFFERENT_ERROR_PAGE

        # Cache result
        self._classification_cache[content_hash] = result
        return result

    def _is_error_page(self, content: str, status: int) -> bool:
        """Check if content is an error page"""
        # Status code indicates error
        if status in [400, 401, 403, 404, 405, 429, 500, 502, 503]:
            return True

        # Pattern matching
        error_score = 0
        for pattern in self.ERROR_PATTERNS:
            if pattern.search(content):
                error_score += 1
                if error_score >= 2:  # Multiple error indicators
                    return True

        return False

    def _is_login_page(self, content: str) -> bool:
        """Check if content is a login page"""
        login_score = 0
        for pattern in self.LOGIN_PATTERNS:
            if pattern.search(content):
                login_score += 1
                if login_score >= 2:
                    return True
        return False

    def _is_api_response(self, response: Any) -> bool:
        """Check if response is API data"""
        headers = {}
        if hasattr(response, 'headers'):
            headers = {k.lower(): v for k, v in response.headers.items()}
        elif isinstance(response, dict):
            headers = {k.lower(): v for k, v in response.get('headers', {}).items()}

        content_type = headers.get('content-type', '')

        if 'application/json' in content_type:
            return True
        if 'application/xml' in content_type:
            return True
        if 'text/xml' in content_type:
            return True

        return False

    def _has_protected_content(self, content: str, response: Any) -> bool:
        """Check if response contains protected content"""
        for category, patterns in self.PROTECTED_INDICATORS.items():
            matches = 0
            for pattern in patterns:
                if pattern.search(content):
                    matches += 1
                    if matches >= 1:  # At least one match in category
                        return True
        return False

    def _is_static_content(self, response: Any) -> bool:
        """Check if response is static content"""
        headers = {}
        if hasattr(response, 'headers'):
            headers = {k.lower(): v for k, v in response.headers.items()}
        elif isinstance(response, dict):
            headers = {k.lower(): v for k, v in response.get('headers', {}).items()}

        content_type = headers.get('content-type', '')

        static_types = ['image/', 'text/css', 'text/javascript',
                        'application/javascript', 'font/', 'video/', 'audio/']

        return any(t in content_type for t in static_types)

    def detect_protected_indicators(self, response: Any) -> List[str]:
        """
        Detect specific protected content indicators

        Returns:
            List of indicator category names found
        """
        indicators_found = []

        content = ""
        headers = {}

        if hasattr(response, 'text'):
            content = response.text.lower() if response.text else ""
            headers = {k.lower(): v for k, v in response.headers.items()}
        elif isinstance(response, dict):
            content = response.get('text', '').lower()
            headers = {k.lower(): v for k, v in response.get('headers', {}).items()}

        # Check each category
        for category, patterns in self.PROTECTED_INDICATORS.items():
            for pattern in patterns:
                if pattern.search(content):
                    if category not in indicators_found:
                        indicators_found.append(category)
                    break

        # Special check for JSON API responses with data
        if 'application/json' in headers.get('content-type', ''):
            try:
                if hasattr(response, 'json'):
                    json_data = response.json()
                elif isinstance(response, dict) and 'json' in response:
                    json_data = response['json']
                else:
                    json_data = None

                if json_data:
                    if any(k in json_data for k in ['users', 'data', 'items',
                                                     'results', 'records']):
                        if 'api_data_response' not in indicators_found:
                            indicators_found.append('api_data_response')
            except:
                pass

        return indicators_found

    def analyze_content(self, response: Any) -> ContentAnalysisResult:
        """
        Comprehensive content analysis

        Returns:
            ContentAnalysisResult with type, indicators, and confidence
        """
        content_type = self.classify(response)
        indicators = self.detect_protected_indicators(response)

        # Calculate confidence based on matches
        if content_type == ContentType.PROTECTED_CONTENT:
            confidence = min(0.5 + len(indicators) * 0.15, 0.95)
        elif content_type == ContentType.ERROR_PAGE:
            confidence = 0.85
        elif content_type == ContentType.API_RESPONSE:
            confidence = 0.90
        else:
            confidence = 0.70

        return ContentAnalysisResult(
            content_type=content_type,
            indicators_found=indicators,
            confidence=confidence,
            raw_features={'indicator_count': len(indicators)}
        )


# =============================================================================
# LAYER IDENTIFIER
# =============================================================================

class LayerIdentifier:
    """
    Identifies which infrastructure layers were reached based on response headers.

    Analyzes headers to detect:
    - CDN layers (Cloudflare, Akamai, AWS CloudFront, etc.)
    - WAF presence
    - Proxy servers
    - Load balancers
    - Backend application servers
    - Caching layers
    """

    # Layer signatures from headers
    LAYER_SIGNATURES = {
        LayerType.CDN: {
            'headers': [
                'cf-ray', 'cf-cache-status', 'cf-request-id',  # Cloudflare
                'x-amz-cf-id', 'x-amz-cf-pop',  # AWS CloudFront
                'x-cache', 'x-cdn',  # Generic CDN
                'x-akamai-request-id', 'akamai-origin-hop',  # Akamai
                'x-fastly-request-id', 'fastly-io-info',  # Fastly
                'x-azure-ref',  # Azure CDN
                'x-edge-', 'x-served-by',  # Edge servers
            ],
            'header_values': {
                'server': ['cloudflare', 'akamaighost', 'cloudfront', 'fastly']
            }
        },
        LayerType.WAF: {
            'headers': [
                'x-waf', 'x-firewall', 'x-security',
                'x-sucuri-id', 'x-sucuri-cache',  # Sucuri
                'x-mod-security', 'x-modsecurity',  # ModSecurity
                'x-imperva-',  # Imperva
                'x-aws-waf-',  # AWS WAF
            ],
            'header_values': {
                'server': ['awselb/2.0', 'bigip', 'f5']
            }
        },
        LayerType.PROXY: {
            'headers': [
                'via', 'x-proxy', 'x-forwarded-for', 'x-forwarded-host',
                'x-forwarded-proto', 'forwarded', 'x-real-ip',
                'x-original-url', 'x-rewrite-url',
            ],
            'header_values': {}
        },
        LayerType.LOAD_BALANCER: {
            'headers': [
                'x-lb-', 'x-loadbalancer', 'x-backend-server',
                'x-upstream-', 'x-served-from',
            ],
            'header_values': {
                'server': ['nginx', 'haproxy', 'traefik', 'envoy']
            }
        },
        LayerType.BACKEND: {
            'headers': [
                'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version',
                'x-runtime', 'x-backend', 'x-request-id',
                'x-rack-cache', 'x-rails-',  # Ruby/Rails
                'x-django-', 'x-flask-',  # Python
                'x-generator', 'x-drupal-cache',  # CMS
                'x-wp-', 'x-wordpress',  # WordPress
            ],
            'header_values': {
                'x-powered-by': ['php', 'asp.net', 'express', 'django', 'flask',
                                'rails', 'spring', 'laravel'],
                'server': ['apache', 'nginx', 'iis', 'tomcat', 'jetty',
                          'gunicorn', 'uvicorn', 'waitress']
            }
        },
        LayerType.CACHE: {
            'headers': [
                'x-cache', 'x-cache-hit', 'x-cache-status',
                'x-varnish', 'age', 'x-proxy-cache',
                'x-rack-cache', 'x-drupal-cache',
            ],
            'header_values': {
                'x-cache': ['hit', 'miss', 'stale']
            }
        },
        LayerType.API_GATEWAY: {
            'headers': [
                'x-amzn-requestid', 'x-amzn-trace-id',  # AWS API Gateway
                'x-kong-', 'kong-request-id',  # Kong
                'x-apigw-',  # Generic API Gateway
            ],
            'header_values': {}
        }
    }

    def __init__(self):
        """Initialize layer identifier"""
        self._signature_cache = {}

    def identify_layers(self, response: Any) -> List[str]:
        """
        Identify which layers were reached based on headers

        Args:
            response: HTTP response object

        Returns:
            List of layer names reached
        """
        headers = self._extract_headers(response)
        if not headers:
            return []

        # Create cache key
        header_key = hashlib.md5(str(sorted(headers.items())).encode()).hexdigest()[:16]
        if header_key in self._signature_cache:
            return self._signature_cache[header_key]

        reached = []
        headers_lower = {k.lower(): v.lower() if isinstance(v, str) else str(v).lower()
                        for k, v in headers.items()}
        header_names = ' '.join(headers_lower.keys())

        for layer_type, signatures in self.LAYER_SIGNATURES.items():
            # Check header names
            for sig_header in signatures['headers']:
                if sig_header.lower() in header_names:
                    if layer_type.value not in reached:
                        reached.append(layer_type.value)
                    break

            # Check header values
            for header_name, value_patterns in signatures.get('header_values', {}).items():
                header_value = headers_lower.get(header_name, '')
                for pattern in value_patterns:
                    if pattern.lower() in header_value:
                        if layer_type.value not in reached:
                            reached.append(layer_type.value)
                        break

        self._signature_cache[header_key] = reached
        return reached

    def _extract_headers(self, response: Any) -> Dict[str, str]:
        """Extract headers from response"""
        if hasattr(response, 'headers'):
            return dict(response.headers)
        elif isinstance(response, dict):
            return response.get('headers', {})
        return {}

    def get_layer_details(self, response: Any) -> Dict[str, Any]:
        """
        Get detailed layer analysis

        Returns:
            Dictionary with layer details and evidence
        """
        headers = self._extract_headers(response)
        layers = self.identify_layers(response)

        details = {
            'layers_reached': layers,
            'layer_count': len(layers),
            'evidence': {},
            'backend_technology': None,
            'cdn_provider': None,
            'waf_detected': 'WAF' in layers
        }

        # Extract specific evidence
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # CDN provider detection
        if 'cf-ray' in headers_lower:
            details['cdn_provider'] = 'Cloudflare'
        elif 'x-amz-cf-id' in headers_lower:
            details['cdn_provider'] = 'AWS CloudFront'
        elif 'x-akamai-request-id' in headers_lower:
            details['cdn_provider'] = 'Akamai'
        elif 'x-fastly-request-id' in headers_lower:
            details['cdn_provider'] = 'Fastly'

        # Backend technology
        if 'x-powered-by' in headers_lower:
            details['backend_technology'] = headers_lower['x-powered-by']
        elif 'server' in headers_lower:
            details['backend_technology'] = headers_lower['server']

        return details


# =============================================================================
# BEHAVIORAL ANALYZER
# =============================================================================

class BehavioralAnalyzer:
    """
    Analyzes behavioral differences between baseline and test responses.

    Metrics analyzed:
    - Response timing differential
    - Content entropy differential
    - Response size differential
    - Cookie changes
    - Header changes
    - Redirect behavior
    """

    def __init__(self):
        """Initialize behavioral analyzer"""
        self._entropy_cache = {}

    def analyze_differential(
        self,
        baseline: Any,
        test: Any
    ) -> BehavioralDifferential:
        """
        Analyze behavioral differences between responses

        Args:
            baseline: Baseline response (blocked)
            test: Test response (with bypass attempt)

        Returns:
            BehavioralDifferential with analysis results
        """
        # Initialize result values
        timing_diff = 0.0
        entropy_diff = 0.0
        size_diff = 0
        new_cookies = set()
        new_headers = set()

        # Timing differential
        baseline_timing = self._get_timing(baseline)
        test_timing = self._get_timing(test)
        timing_diff = abs(test_timing - baseline_timing)

        # Content differential
        baseline_content = self._get_content(baseline)
        test_content = self._get_content(test)

        baseline_entropy = self._calculate_entropy(baseline_content)
        test_entropy = self._calculate_entropy(test_content)
        entropy_diff = abs(test_entropy - baseline_entropy)

        size_diff = abs(len(test_content) - len(baseline_content))

        # Cookie differential
        baseline_cookies = self._get_cookies(baseline)
        test_cookies = self._get_cookies(test)
        new_cookies = test_cookies - baseline_cookies

        # Header differential
        baseline_headers = set(self._get_headers(baseline).keys())
        test_headers = set(self._get_headers(test).keys())
        new_headers = test_headers - baseline_headers

        # Evaluate significance
        significant = False
        strength = 0.0
        description_parts = []
        likelihood_ratio = 1.0

        # Timing significance (>500ms)
        if timing_diff > 0.5:
            significant = True
            strength += min(timing_diff / 2.0, 0.4)  # Cap at 0.4
            description_parts.append(f"Timing: +{timing_diff:.2f}s")
            likelihood_ratio *= 5.0 + min(timing_diff * 2, 10.0)

        # Entropy significance
        if entropy_diff > 1.0:
            significant = True
            strength += min(entropy_diff / 4.0, 0.4)  # Cap at 0.4
            description_parts.append(f"Entropy: Δ{entropy_diff:.2f}")
            likelihood_ratio *= 10.0 + min(entropy_diff * 3, 20.0)

        # Size significance (>20% or >1KB)
        baseline_size = len(baseline_content)
        if baseline_size > 0:
            size_pct_diff = size_diff / baseline_size
            if size_pct_diff > 0.2 or size_diff > 1024:
                significant = True
                strength += min(size_pct_diff / 2.0, 0.3)
                description_parts.append(f"Size: Δ{size_diff}B ({size_pct_diff*100:.1f}%)")
                likelihood_ratio *= 8.0

        # New cookies (strong signal)
        if new_cookies:
            significant = True
            strength += min(len(new_cookies) * 0.15, 0.5)
            description_parts.append(f"New cookies: {len(new_cookies)}")
            likelihood_ratio *= 15.0 * len(new_cookies)

        # New headers
        if len(new_headers) > 2:  # More than 2 new headers
            significant = True
            strength += min(len(new_headers) * 0.05, 0.2)
            description_parts.append(f"New headers: {len(new_headers)}")
            likelihood_ratio *= 3.0

        return BehavioralDifferential(
            significant_change=significant,
            strength=min(strength, 1.0),
            description=', '.join(description_parts) if description_parts else 'No significant change',
            likelihood_ratio=likelihood_ratio,
            timing_diff=timing_diff,
            entropy_diff=entropy_diff,
            size_diff=size_diff,
            new_cookies=new_cookies,
            new_headers=new_headers
        )

    def _get_timing(self, response: Any) -> float:
        """Extract timing from response"""
        if hasattr(response, 'elapsed'):
            return response.elapsed.total_seconds()
        elif isinstance(response, dict):
            return response.get('elapsed', 0.0)
        return 0.0

    def _get_content(self, response: Any) -> bytes:
        """Extract content bytes from response"""
        if hasattr(response, 'content'):
            return response.content or b''
        elif hasattr(response, 'text'):
            return (response.text or '').encode()
        elif isinstance(response, dict):
            text = response.get('text', response.get('content', ''))
            if isinstance(text, bytes):
                return text
            return text.encode() if text else b''
        return b''

    def _get_cookies(self, response: Any) -> Set[str]:
        """Extract cookie names from response"""
        if hasattr(response, 'cookies'):
            return set(response.cookies.keys())
        elif isinstance(response, dict):
            cookies = response.get('cookies', {})
            if isinstance(cookies, dict):
                return set(cookies.keys())
        return set()

    def _get_headers(self, response: Any) -> Dict[str, str]:
        """Extract headers from response"""
        if hasattr(response, 'headers'):
            return dict(response.headers)
        elif isinstance(response, dict):
            return response.get('headers', {})
        return {}

    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data

        Returns:
            Entropy value (0 to 8 for byte data)
        """
        if not data:
            return 0.0

        # Check cache
        data_hash = hashlib.md5(data[:1024]).hexdigest()[:16]  # Sample first 1KB
        if data_hash in self._entropy_cache:
            return self._entropy_cache[data_hash]

        counts = Counter(data)
        total = len(data)

        entropy = 0.0
        for count in counts.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)

        self._entropy_cache[data_hash] = entropy
        return entropy


# =============================================================================
# CAUSAL RESPONSE ANALYZER (MAIN)
# =============================================================================

class CausalResponseAnalyzer:
    """
    Main analyzer - verifies if bypass is REALLY a bypass using multi-level analysis.

    Multi-level verification:
    1. Status code analysis
    2. Content semantic analysis
    3. Protected content detection
    4. Causal layer analysis
    5. Behavioral fingerprinting

    Uses Bayesian inference to combine evidence and calculate confidence.
    """

    def __init__(self, prior_probability: float = 0.05):
        """
        Initialize Causal Response Analyzer

        Args:
            prior_probability: Prior probability of true bypass (default 5%)
        """
        self.prior_probability = prior_probability
        self.content_classifier = ContentClassifier()
        self.layer_identifier = LayerIdentifier()
        self.behavioral_analyzer = BehavioralAnalyzer()

        # Verification statistics
        self._verification_count = 0
        self._true_bypass_count = 0
        self._false_positive_count = 0

    def verify_bypass(
        self,
        baseline_response: Any,
        test_response: Any,
        bypass_info: Dict
    ) -> VerificationResult:
        """
        Verify if test response represents a TRUE bypass

        Multi-level verification process:
        1. Status code analysis
        2. Content semantic analysis
        3. Protected content detection
        4. Causal layer analysis
        5. Behavioral fingerprinting

        Args:
            baseline_response: Response without bypass (403/401)
            test_response: Response with bypass applied
            bypass_info: {
                'type': str,
                'test_name': str,
                'headers': dict,
                'method': str,
                'target_layers': List[str]
            }

        Returns:
            VerificationResult with confidence and reasoning
        """
        self._verification_count += 1

        # Initialize Bayesian engine
        bayesian = BayesianBypassInference(prior_probability=self.prior_probability)

        # Track false positive indicators
        false_positive_indicators = []
        causal_chain = []

        # Get status codes
        baseline_status = self._get_status_code(baseline_response)
        test_status = self._get_status_code(test_response)

        # === LEVEL 1: Status Code Analysis ===
        causal_chain.append("L1:StatusCode")

        if test_status == 200 and baseline_status in [401, 403, 429]:
            bayesian.add_evidence(BypassEvidence(
                evidence_type="Status Code Change",
                strength=0.6,
                description=f"Status: {baseline_status} → {test_status}",
                likelihood_ratio=20.0
            ))
        elif test_status == baseline_status:
            # Same status - likely false positive
            false_positive_indicators.append("same_status_code")
            bayesian.add_evidence(BypassEvidence(
                evidence_type="Same Status Code",
                strength=0.5,
                description=f"No status change: {baseline_status}",
                likelihood_ratio=0.3  # Evidence against bypass
            ))
        elif test_status in [400, 404, 500, 502, 503]:
            # Error response - likely false positive
            false_positive_indicators.append("error_response")
            bayesian.add_evidence(BypassEvidence(
                evidence_type="Error Response",
                strength=0.7,
                description=f"Got error: {test_status}",
                likelihood_ratio=0.1  # Strong evidence against
            ))

        # === LEVEL 2: Content Semantic Analysis ===
        causal_chain.append("L2:ContentSemantic")

        baseline_type = self.content_classifier.classify(baseline_response)
        test_type = self.content_classifier.classify(test_response)

        content_transition = f"{baseline_type.value} → {test_type.value}"

        if baseline_type == ContentType.ERROR_PAGE:
            if test_type == ContentType.PROTECTED_CONTENT:
                # STRONGEST SIGNAL - Error page → Protected content
                bayesian.add_evidence(BypassEvidence(
                    evidence_type="Content Type Transition",
                    strength=0.95,
                    description=f"Transition: {content_transition}",
                    likelihood_ratio=100.0
                ))
            elif test_type == ContentType.API_RESPONSE:
                # Strong signal - Error page → API data
                bayesian.add_evidence(BypassEvidence(
                    evidence_type="API Response Access",
                    strength=0.90,
                    description="Accessed API endpoint",
                    likelihood_ratio=80.0
                ))
            elif test_type == ContentType.DIFFERENT_ERROR_PAGE:
                # FALSE POSITIVE - Just different error
                false_positive_indicators.append("different_error_page")
                bayesian.add_evidence(BypassEvidence(
                    evidence_type="Different Error Page",
                    strength=0.85,
                    description="Different error page, not real bypass",
                    likelihood_ratio=0.05  # Strong evidence AGAINST bypass
                ))
            elif test_type == ContentType.ERROR_PAGE:
                # Same type - likely false positive
                false_positive_indicators.append("still_error_page")
                bayesian.add_evidence(BypassEvidence(
                    evidence_type="Still Error Page",
                    strength=0.7,
                    description="Still blocked, different message",
                    likelihood_ratio=0.2
                ))
            elif test_type == ContentType.LOGIN_PAGE:
                # Redirected to login - partial bypass at best
                bayesian.add_evidence(BypassEvidence(
                    evidence_type="Login Page Redirect",
                    strength=0.5,
                    description="Redirected to login",
                    likelihood_ratio=5.0  # Weak positive
                ))
            elif test_type == ContentType.REDIRECT:
                # Just a redirect - not necessarily a bypass
                bayesian.add_evidence(BypassEvidence(
                    evidence_type="Redirect Response",
                    strength=0.4,
                    description="Got redirect",
                    likelihood_ratio=2.0  # Weak positive
                ))

        # === LEVEL 3: Protected Content Indicators ===
        causal_chain.append("L3:ProtectedIndicators")

        protected_indicators = self.content_classifier.detect_protected_indicators(
            test_response
        )

        if protected_indicators:
            # Strong evidence of accessing protected content
            indicator_str = ', '.join(protected_indicators)
            lr = 30.0 + (len(protected_indicators) * 20.0)  # More indicators = stronger

            bayesian.add_evidence(BypassEvidence(
                evidence_type="Protected Content Indicators",
                strength=0.85,
                description=f"Found: {indicator_str}",
                likelihood_ratio=min(lr, 150.0)
            ))

            # Extra strong evidence for sensitive data
            if 'sensitive_data' in protected_indicators:
                bayesian.add_evidence(BypassEvidence(
                    evidence_type="Sensitive Data Exposed",
                    strength=0.95,
                    description="API keys, passwords, or tokens exposed",
                    likelihood_ratio=200.0
                ))

            if 'file_content' in protected_indicators:
                bayesian.add_evidence(BypassEvidence(
                    evidence_type="File Content Exposed",
                    strength=0.95,
                    description="System files or source code exposed",
                    likelihood_ratio=200.0
                ))

        # === LEVEL 4: Causal Layer Analysis ===
        causal_chain.append("L4:LayerAnalysis")

        reached_layers = self.layer_identifier.identify_layers(test_response)
        target_layers = bypass_info.get('target_layers', [])

        if target_layers and reached_layers:
            # Check if bypass targeted layer was actually bypassed
            if 'Backend' in reached_layers and 'WAF' in target_layers:
                # WAF bypassed, backend reached!
                bayesian.add_evidence(BypassEvidence(
                    evidence_type="Causal Layer Bypass",
                    strength=0.9,
                    description="WAF bypassed, backend reached",
                    likelihood_ratio=80.0
                ))
            elif 'Backend' in reached_layers:
                # Backend reached (generic)
                bayesian.add_evidence(BypassEvidence(
                    evidence_type="Backend Reached",
                    strength=0.7,
                    description=f"Layers: {', '.join(reached_layers)}",
                    likelihood_ratio=40.0
                ))

            # Check for proxy/CDN only (not backend)
            if reached_layers and 'Backend' not in reached_layers:
                # Might be cached or edge response
                if 'CDN' in reached_layers or 'Cache' in reached_layers:
                    false_positive_indicators.append("edge_response_only")
                    bayesian.add_evidence(BypassEvidence(
                        evidence_type="Edge Response Only",
                        strength=0.5,
                        description="Response from CDN/cache, not backend",
                        likelihood_ratio=0.5  # Weak evidence against
                    ))

        # === LEVEL 5: Behavioral Fingerprinting ===
        causal_chain.append("L5:Behavioral")

        behavioral_diff = self.behavioral_analyzer.analyze_differential(
            baseline_response,
            test_response
        )

        if behavioral_diff.significant_change:
            bayesian.add_evidence(BypassEvidence(
                evidence_type="Behavioral Differential",
                strength=behavioral_diff.strength,
                description=behavioral_diff.description,
                likelihood_ratio=behavioral_diff.likelihood_ratio
            ))

            # New cookies is especially strong (session established)
            if behavioral_diff.new_cookies:
                bayesian.add_evidence(BypassEvidence(
                    evidence_type="New Session Cookies",
                    strength=0.8,
                    description=f"Session cookies: {', '.join(list(behavioral_diff.new_cookies)[:3])}",
                    likelihood_ratio=25.0
                ))
        else:
            # No behavioral change - suspicious
            false_positive_indicators.append("no_behavioral_change")

        # === FINAL VERDICT ===
        posterior = bayesian.get_posterior_probability()
        confidence_level = bayesian.get_confidence_level()

        is_true_bypass = posterior > 0.75

        # Update statistics
        if is_true_bypass:
            self._true_bypass_count += 1
        elif false_positive_indicators:
            self._false_positive_count += 1

        # Build reasoning
        reasoning = bayesian.explain_reasoning()
        if false_positive_indicators:
            reasoning += f"\n\nFalse Positive Indicators: {', '.join(false_positive_indicators)}"

        return VerificationResult(
            is_true_bypass=is_true_bypass,
            confidence=posterior,
            confidence_level=confidence_level.name,
            content_transition=content_transition,
            protected_indicators=protected_indicators,
            reached_layers=reached_layers,
            evidence=[{
                'type': e.evidence_type,
                'strength': e.strength,
                'description': e.description,
                'likelihood_ratio': e.likelihood_ratio
            } for e in bayesian.evidence_collected],
            reasoning=reasoning,
            baseline_content_type=baseline_type.value,
            test_content_type=test_type.value,
            behavioral_changes={
                'significant': behavioral_diff.significant_change,
                'timing_diff': behavioral_diff.timing_diff,
                'entropy_diff': behavioral_diff.entropy_diff,
                'size_diff': behavioral_diff.size_diff,
                'new_cookies': list(behavioral_diff.new_cookies),
                'new_headers': list(behavioral_diff.new_headers)
            },
            causal_chain=causal_chain,
            false_positive_indicators=false_positive_indicators
        )

    def _get_status_code(self, response: Any) -> int:
        """Extract status code from response"""
        if hasattr(response, 'status_code'):
            return response.status_code
        elif isinstance(response, dict):
            return response.get('status_code', 0)
        return 0

    def get_statistics(self) -> Dict[str, Any]:
        """Get verification statistics"""
        return {
            'total_verifications': self._verification_count,
            'true_bypasses': self._true_bypass_count,
            'false_positives': self._false_positive_count,
            'true_bypass_rate': (
                self._true_bypass_count / self._verification_count
                if self._verification_count > 0 else 0.0
            ),
            'false_positive_rate': (
                self._false_positive_count / self._verification_count
                if self._verification_count > 0 else 0.0
            )
        }


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def create_mock_response(
    status_code: int = 200,
    text: str = "",
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    elapsed_seconds: float = 0.1
) -> Dict:
    """
    Create a mock response for testing

    Args:
        status_code: HTTP status code
        text: Response body text
        headers: Response headers
        cookies: Response cookies
        elapsed_seconds: Response time in seconds

    Returns:
        Mock response dictionary
    """
    return {
        'status_code': status_code,
        'text': text,
        'content': text.encode(),
        'headers': headers or {},
        'cookies': cookies or {},
        'elapsed': elapsed_seconds
    }


# =============================================================================
# INTEGRATION EXAMPLE
# =============================================================================

def example_integration():
    """
    Example of how to integrate in application_traceroute_v3_5.py

    BEFORE (in test_header_confusion):

        if status not in [400, 401, 403, 429]:
            self.discrepancies.append({
                'type': 'Header Confusion Bypass',
                ...
            })

    AFTER:

        # Get baseline
        baseline_response = self.session.get(self.forbidden_endpoint)

        # Test with bypass
        response = self.session.get(
            self.forbidden_endpoint,
            headers=test['headers']
        )

        # VERIFY with CausalResponseAnalyzer
        analyzer = CausalResponseAnalyzer()
        verification = analyzer.verify_bypass(
            baseline_response=baseline_response,
            test_response=response,
            bypass_info={
                'type': 'Header Confusion',
                'test_name': test['name'],
                'headers': test['headers'],
                'method': 'GET',
                'target_layers': ['WAF', 'Proxy']
            }
        )

        # Only add if TRUE bypass
        if verification.is_true_bypass:
            self.discrepancies.append({
                'type': 'Header Confusion Bypass',
                'test_name': test['name'],
                'response_code': response.status_code,
                'severity': 'CRITICAL' if verification.confidence > 0.9 else 'HIGH',
                'confidence': verification.confidence,
                'confidence_level': verification.confidence_level,
                'content_transition': verification.content_transition,
                'protected_indicators': verification.protected_indicators,
                'reached_layers': verification.reached_layers,
                'evidence': verification.evidence,
                'reasoning': verification.reasoning
            })

            print(f"    [!] TRUE BYPASS: {test['name']} "
                  f"(confidence: {verification.confidence:.2%})")

        else:
            # Filtered false positive
            print(f"    [~] False positive filtered: {test['name']}")
            print(f"        Reason: {verification.false_positive_indicators}")
    """
    pass


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print("""
    CausalResponseAnalyzer v4.0 - Multi-Level Bypass Verification

    Features:
    - Content semantic classification
    - Protected content detection
    - Causal layer analysis
    - Behavioral fingerprinting
    - Bayesian confidence scoring

    Classes:
    - CausalResponseAnalyzer: Main analyzer
    - ContentClassifier: Content type classification
    - LayerIdentifier: Infrastructure layer detection
    - BehavioralAnalyzer: Response behavior analysis

    Usage: See example_integration() for application_traceroute integration
    """)

    # Quick self-test
    print("\n[*] Running self-test...")

    analyzer = CausalResponseAnalyzer()

    # Test 1: True bypass scenario
    baseline = create_mock_response(
        status_code=403,
        text="<html>Access Denied - WAF Blocked</html>",
        headers={'x-waf': 'blocked'}
    )

    test = create_mock_response(
        status_code=200,
        text='<html>Admin Panel<form>User Management</form></html>',
        headers={'x-powered-by': 'PHP/7.4'},
        cookies={'PHPSESSID': 'abc123'}
    )

    result = analyzer.verify_bypass(
        baseline_response=baseline,
        test_response=test,
        bypass_info={
            'type': 'Header Confusion',
            'test_name': 'X-Original-URL Test',
            'target_layers': ['WAF']
        }
    )

    print(f"\n[Test 1] True Bypass Scenario:")
    print(f"  Is True Bypass: {result.is_true_bypass}")
    print(f"  Confidence: {result.confidence:.2%}")
    print(f"  Content Transition: {result.content_transition}")
    print(f"  Protected Indicators: {result.protected_indicators}")

    # Test 2: False positive scenario
    baseline2 = create_mock_response(
        status_code=403,
        text="<html>Access Denied</html>",
        headers={'x-waf': 'blocked'}
    )

    test2 = create_mock_response(
        status_code=403,
        text="<html>Request Blocked by Firewall</html>",
        headers={'x-waf': 'blocked'}
    )

    result2 = analyzer.verify_bypass(
        baseline_response=baseline2,
        test_response=test2,
        bypass_info={
            'type': 'Header Confusion',
            'test_name': 'Failed Test',
            'target_layers': ['WAF']
        }
    )

    print(f"\n[Test 2] False Positive Scenario:")
    print(f"  Is True Bypass: {result2.is_true_bypass}")
    print(f"  Confidence: {result2.confidence:.2%}")
    print(f"  False Positive Indicators: {result2.false_positive_indicators}")

    print("\n[+] Self-test completed!")
    print(f"\nStatistics: {analyzer.get_statistics()}")
