#!/usr/bin/env python3
"""
Active Scanner v4.0 - Burp Suite-level Intelligent Vulnerability Detection

Advanced active scanning capabilities:
- Response Differential Analysis
- Reflection Detection & Context Analysis
- Intelligent Behavior Probing
- Timing-based Detection
- Error Pattern Analysis
- Technology-specific Probes
- Input Transformation Tracking

Inspired by Burp Suite Active Scanner methodology.

Author: Security Testing Suite
License: Authorized security research only
"""

import re
import time
import hashlib
import difflib
import statistics
from typing import Dict, List, Optional, Tuple, Set, Any, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict
from urllib.parse import quote, unquote, urlparse
import logging
import html
import json

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS AND CONSTANTS
# =============================================================================

class InjectionContext(Enum):
    """Context where input is reflected/processed"""
    HTML_TEXT = "html_text"
    HTML_ATTRIBUTE = "html_attribute"
    HTML_ATTRIBUTE_UNQUOTED = "html_attribute_unquoted"
    HTML_ATTRIBUTE_SINGLE_QUOTED = "html_attribute_single_quoted"
    HTML_ATTRIBUTE_DOUBLE_QUOTED = "html_attribute_double_quoted"
    HTML_COMMENT = "html_comment"
    JAVASCRIPT_STRING = "javascript_string"
    JAVASCRIPT_STRING_SINGLE = "javascript_string_single"
    JAVASCRIPT_STRING_DOUBLE = "javascript_string_double"
    JAVASCRIPT_STRING_TEMPLATE = "javascript_string_template"
    JAVASCRIPT_CODE = "javascript_code"
    CSS_VALUE = "css_value"
    CSS_URL = "css_url"
    URL_PATH = "url_path"
    URL_PARAMETER = "url_parameter"
    JSON_VALUE = "json_value"
    XML_TEXT = "xml_text"
    XML_ATTRIBUTE = "xml_attribute"
    XML_CDATA = "xml_cdata"
    SQL_STRING = "sql_string"
    SQL_NUMERIC = "sql_numeric"
    SQL_IDENTIFIER = "sql_identifier"
    HEADER_VALUE = "header_value"
    UNKNOWN = "unknown"


class TransformationType(Enum):
    """How input was transformed"""
    NONE = "none"
    HTML_ENCODED = "html_encoded"
    URL_ENCODED = "url_encoded"
    DOUBLE_URL_ENCODED = "double_url_encoded"
    UNICODE_ESCAPED = "unicode_escaped"
    HEX_ENCODED = "hex_encoded"
    BASE64_ENCODED = "base64_encoded"
    CASE_MODIFIED = "case_modified"
    TRUNCATED = "truncated"
    FILTERED = "filtered"
    STRIPPED = "stripped"
    REPLACED = "replaced"
    NORMALIZED = "normalized"


class VulnSusceptibility(Enum):
    """Susceptibility level"""
    CONFIRMED = "confirmed"       # Definitely vulnerable
    HIGH = "high"                 # Very likely vulnerable
    MEDIUM = "medium"             # Possibly vulnerable
    LOW = "low"                   # Unlikely but worth testing
    NONE = "none"                 # Not susceptible


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ReflectionPoint:
    """Where and how input is reflected"""
    context: InjectionContext
    position: int
    surrounding_code: str
    transformations: List[TransformationType]
    breakout_chars: List[str]  # Characters needed to break out of context
    is_encoded: bool
    encoding_type: Optional[str]
    can_break_out: bool


@dataclass
class ProbeResult:
    """Result of a single probe"""
    probe_payload: str
    response_code: int
    response_body: str
    response_headers: Dict[str, str]
    response_time: float
    reflected: bool
    reflection_points: List[ReflectionPoint]
    error_triggered: bool
    error_pattern: Optional[str]
    behavior_change: bool
    differential_score: float  # 0.0-1.0


@dataclass
class VulnerabilitySusceptibility:
    """Assessment of vulnerability susceptibility for an injection point"""
    vuln_type: str
    susceptibility: VulnSusceptibility
    confidence: float  # 0.0-1.0
    evidence: List[str]
    recommended_payloads: List[str]
    detection_technique: str
    context: Optional[InjectionContext]
    requires_blind_testing: bool


@dataclass
class InjectionPointAnalysis:
    """Complete analysis of an injection point"""
    parameter_name: str
    parameter_value: str
    location: str  # query, body, header, cookie, path
    baseline_response: 'ResponseFingerprint'
    reflections: List[ReflectionPoint]
    susceptibilities: List[VulnerabilitySusceptibility]
    detected_technologies: List[str]
    waf_detected: bool
    waf_name: Optional[str]
    recommended_test_order: List[str]


@dataclass
class ResponseFingerprint:
    """Fingerprint of a response for comparison"""
    status_code: int
    content_length: int
    content_hash: str
    word_count: int
    line_count: int
    tag_count: int
    headers_hash: str
    response_time: float
    error_keywords: List[str]
    significant_strings: Set[str]


# =============================================================================
# RESPONSE DIFFERENTIAL ANALYZER
# =============================================================================

class ResponseDifferentialAnalyzer:
    """
    Analyzes differences between baseline and probe responses.
    Core technique for detecting vulnerabilities through behavior changes.
    """

    # Significant keywords that indicate interesting behavior
    ERROR_KEYWORDS = {
        'sql': ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle', 'mssql', 'syntax', 'query',
                'ORA-', 'PLS-', 'SP2-', 'SQL Server', 'ODBC', 'JDBC', 'MariaDB'],
        'path': ['No such file', 'cannot find', 'not found', 'failed to open', 'include(',
                 'require(', 'fopen(', 'file_get_contents', 'Permission denied', 'ENOENT'],
        'xml': ['XML', 'parsing', 'entity', 'DTD', 'PCDATA', 'xmlns', 'CDATA'],
        'command': ['sh:', 'bash:', 'cmd.exe', 'command not found', '/bin/', 'Permission denied',
                    'syntax error', 'unexpected token'],
        'template': ['Jinja2', 'Twig', 'Smarty', 'FreeMarker', 'Velocity', 'template', 'render'],
        'generic': ['exception', 'error', 'warning', 'fatal', 'undefined', 'null', 'nil',
                    'stack trace', 'traceback', 'at line', 'debug'],
    }

    def __init__(self):
        self.baseline_cache: Dict[str, ResponseFingerprint] = {}

    def fingerprint_response(self, status_code: int, body: str,
                            headers: Dict[str, str], response_time: float) -> ResponseFingerprint:
        """Create a fingerprint of a response"""
        # Extract error keywords found
        error_keywords = []
        body_lower = body.lower()
        for category, keywords in self.ERROR_KEYWORDS.items():
            for kw in keywords:
                if kw.lower() in body_lower:
                    error_keywords.append(f"{category}:{kw}")

        # Extract significant strings (potential tokens, IDs, etc.)
        significant = set()
        # Look for quoted strings
        for match in re.finditer(r'["\']([^"\']{8,64})["\']', body):
            significant.add(match.group(1))
        # Look for numbers that might be IDs
        for match in re.finditer(r'\b\d{4,12}\b', body):
            significant.add(match.group())

        # Count HTML tags
        tag_count = len(re.findall(r'<[a-zA-Z][^>]*>', body))

        return ResponseFingerprint(
            status_code=status_code,
            content_length=len(body),
            content_hash=hashlib.md5(body.encode()).hexdigest(),
            word_count=len(body.split()),
            line_count=body.count('\n') + 1,
            tag_count=tag_count,
            headers_hash=hashlib.md5(str(sorted(headers.items())).encode()).hexdigest(),
            response_time=response_time,
            error_keywords=error_keywords,
            significant_strings=significant
        )

    def calculate_differential(self, baseline: ResponseFingerprint,
                              probe: ResponseFingerprint) -> Tuple[float, Dict[str, Any]]:
        """
        Calculate differential score between baseline and probe.
        Returns (score, details) where score is 0.0-1.0 (higher = more different)
        """
        details = {
            'status_changed': baseline.status_code != probe.status_code,
            'length_diff': abs(baseline.content_length - probe.content_length),
            'length_diff_percent': 0.0,
            'content_changed': baseline.content_hash != probe.content_hash,
            'word_diff': abs(baseline.word_count - probe.word_count),
            'line_diff': abs(baseline.line_count - probe.line_count),
            'tag_diff': abs(baseline.tag_count - probe.tag_count),
            'headers_changed': baseline.headers_hash != probe.headers_hash,
            'time_diff': probe.response_time - baseline.response_time,
            'new_errors': [e for e in probe.error_keywords if e not in baseline.error_keywords],
            'new_strings': probe.significant_strings - baseline.significant_strings,
        }

        # Calculate length diff percent
        if baseline.content_length > 0:
            details['length_diff_percent'] = details['length_diff'] / baseline.content_length

        # Calculate overall score
        score = 0.0

        # Status code change is very significant
        if details['status_changed']:
            score += 0.3
            # Error status even more significant
            if probe.status_code >= 500:
                score += 0.2
            elif probe.status_code >= 400:
                score += 0.1

        # Content changes
        if details['content_changed']:
            size_pct_diff = details['length_diff_percent']
            size_diff = details['length_diff']
            # Soglie abbassate per applicazioni di test (DVWA, phpvuln)
            if size_pct_diff > 0.10 or size_diff > 200:
                score += 0.2
            elif size_pct_diff > 0.05 or size_diff > 50:
                score += 0.1
            elif size_pct_diff > 0.02:
                score += 0.05

        # New error keywords are very interesting
        if details['new_errors']:
            score += min(0.3, len(details['new_errors']) * 0.1)

        # Timing anomalies (potential blind injection)
        if details['time_diff'] > 5.0:
            score += 0.3
        elif details['time_diff'] > 2.0:
            score += 0.15
        elif details['time_diff'] > 1.0:
            score += 0.05

        # New significant strings
        if details['new_strings']:
            score += min(0.1, len(details['new_strings']) * 0.02)

        return min(1.0, score), details

    def analyze_error_patterns(self, response_body: str) -> Dict[str, List[str]]:
        """Analyze response for error patterns by category"""
        found = defaultdict(list)
        body_lower = response_body.lower()

        for category, keywords in self.ERROR_KEYWORDS.items():
            for kw in keywords:
                if kw.lower() in body_lower:
                    # Extract context around the keyword
                    idx = body_lower.find(kw.lower())
                    start = max(0, idx - 50)
                    end = min(len(response_body), idx + len(kw) + 50)
                    context = response_body[start:end]
                    found[category].append({
                        'keyword': kw,
                        'context': context
                    })

        return dict(found)


# =============================================================================
# REFLECTION DETECTOR
# =============================================================================

class ReflectionDetector:
    """
    Detects where and how input is reflected in the response.
    Determines the context and what transformations were applied.
    """

    # Canary strings for different tests
    CANARIES = {
        'basic': 'xss1337test',
        'html': '<xss1337>',
        'js': 'xss1337"\'',
        'special': 'xss<>"\'&1337',
        'numeric': '1337.7331',
        'boundary': 'xss\x00\x0a\x0d1337',
    }

    def __init__(self):
        pass

    def detect_reflections(self, original_value: str, response_body: str,
                          test_canary: str = None) -> List[ReflectionPoint]:
        """
        Detect all reflection points of the input in the response.
        """
        reflections = []
        search_value = test_canary or original_value

        if not search_value or search_value not in response_body:
            # Try common transformations
            transformed = self._detect_transformed_reflection(search_value, response_body)
            if transformed:
                return transformed
            return []

        # Find all occurrences
        pos = 0
        while True:
            idx = response_body.find(search_value, pos)
            if idx == -1:
                break

            # Analyze context at this position
            context = self._analyze_context(response_body, idx, len(search_value))
            transformations = self._detect_transformations(original_value, search_value, response_body, idx)
            breakout = self._get_breakout_chars(context)

            reflections.append(ReflectionPoint(
                context=context,
                position=idx,
                surrounding_code=response_body[max(0, idx-100):idx+len(search_value)+100],
                transformations=transformations,
                breakout_chars=breakout,
                is_encoded=any(t != TransformationType.NONE for t in transformations),
                encoding_type=self._get_encoding_type(transformations),
                can_break_out=self._can_break_context(context, response_body, idx)
            ))

            pos = idx + 1

        return reflections

    def _detect_transformed_reflection(self, original: str, body: str) -> List[ReflectionPoint]:
        """Detect reflection with transformations applied"""
        reflections = []

        # HTML encoded
        html_encoded = html.escape(original)
        if html_encoded != original and html_encoded in body:
            idx = body.find(html_encoded)
            reflections.append(ReflectionPoint(
                context=self._analyze_context(body, idx, len(html_encoded)),
                position=idx,
                surrounding_code=body[max(0, idx-100):idx+len(html_encoded)+100],
                transformations=[TransformationType.HTML_ENCODED],
                breakout_chars=[],
                is_encoded=True,
                encoding_type='html',
                can_break_out=False
            ))

        # URL encoded
        url_encoded = quote(original, safe='')
        if url_encoded != original and url_encoded in body:
            idx = body.find(url_encoded)
            reflections.append(ReflectionPoint(
                context=self._analyze_context(body, idx, len(url_encoded)),
                position=idx,
                surrounding_code=body[max(0, idx-100):idx+len(url_encoded)+100],
                transformations=[TransformationType.URL_ENCODED],
                breakout_chars=[],
                is_encoded=True,
                encoding_type='url',
                can_break_out=False
            ))

        # Case modified
        if original.lower() in body.lower() and original not in body:
            idx = body.lower().find(original.lower())
            reflections.append(ReflectionPoint(
                context=self._analyze_context(body, idx, len(original)),
                position=idx,
                surrounding_code=body[max(0, idx-100):idx+len(original)+100],
                transformations=[TransformationType.CASE_MODIFIED],
                breakout_chars=[],
                is_encoded=False,
                encoding_type=None,
                can_break_out=True  # Case change usually doesn't prevent breakout
            ))

        # Stripped (common chars removed)
        stripped = re.sub(r'[<>"\'&;]', '', original)
        if stripped != original and len(stripped) > 3 and stripped in body:
            idx = body.find(stripped)
            reflections.append(ReflectionPoint(
                context=self._analyze_context(body, idx, len(stripped)),
                position=idx,
                surrounding_code=body[max(0, idx-100):idx+len(stripped)+100],
                transformations=[TransformationType.STRIPPED],
                breakout_chars=['<', '>', '"', "'", '&', ';'],
                is_encoded=False,
                encoding_type=None,
                can_break_out=False
            ))

        return reflections

    def _analyze_context(self, body: str, position: int, length: int) -> InjectionContext:
        """Determine the context where reflection occurs"""
        # Get surrounding content
        start = max(0, position - 500)
        prefix = body[start:position]
        suffix = body[position + length:position + length + 200]

        # Check JavaScript context
        if self._is_in_script_block(body, position):
            return self._analyze_js_context(prefix, suffix)

        # Check HTML attribute context
        attr_context = self._check_attribute_context(prefix, suffix)
        if attr_context:
            return attr_context

        # Check CSS context
        if self._is_in_style_block(body, position) or self._is_in_style_attribute(prefix):
            return InjectionContext.CSS_VALUE

        # Check HTML comment
        if '<!--' in prefix and '-->' not in prefix[prefix.rfind('<!--'):]:
            return InjectionContext.HTML_COMMENT

        # Check XML context
        if '<?xml' in body[:100].lower():
            if self._is_in_attribute(prefix):
                return InjectionContext.XML_ATTRIBUTE
            return InjectionContext.XML_TEXT

        # Check JSON context
        if self._looks_like_json(body):
            return InjectionContext.JSON_VALUE

        # Default: HTML text
        return InjectionContext.HTML_TEXT

    def _is_in_script_block(self, body: str, position: int) -> bool:
        """Check if position is inside a <script> block"""
        # Find last <script before position
        last_script_open = body.rfind('<script', 0, position)
        if last_script_open == -1:
            return False

        # Check if there's a </script> between that and position
        last_script_close = body.rfind('</script>', last_script_open, position)
        return last_script_close == -1

    def _is_in_style_block(self, body: str, position: int) -> bool:
        """Check if position is inside a <style> block"""
        last_style_open = body.rfind('<style', 0, position)
        if last_style_open == -1:
            return False
        last_style_close = body.rfind('</style>', last_style_open, position)
        return last_style_close == -1

    def _is_in_style_attribute(self, prefix: str) -> bool:
        """Check if we're in a style attribute"""
        # Look for style=" pattern
        match = re.search(r'style\s*=\s*["\'][^"\']*$', prefix, re.I)
        return match is not None

    def _analyze_js_context(self, prefix: str, suffix: str) -> InjectionContext:
        """Analyze JavaScript-specific context"""
        # Check for string literals
        # Count unescaped quotes before position
        single_quotes = len(re.findall(r"(?<!\\)'", prefix))
        double_quotes = len(re.findall(r'(?<!\\)"', prefix))
        backticks = len(re.findall(r'(?<!\\)`', prefix))

        if single_quotes % 2 == 1:
            return InjectionContext.JAVASCRIPT_STRING_SINGLE
        if double_quotes % 2 == 1:
            return InjectionContext.JAVASCRIPT_STRING_DOUBLE
        if backticks % 2 == 1:
            return InjectionContext.JAVASCRIPT_STRING_TEMPLATE

        return InjectionContext.JAVASCRIPT_CODE

    def _check_attribute_context(self, prefix: str, suffix: str) -> Optional[InjectionContext]:
        """Check if we're in an HTML attribute"""
        # Pattern: attribute="...VALUE or attribute='...VALUE
        double_attr = re.search(r'(\w+)\s*=\s*"[^"]*$', prefix)
        single_attr = re.search(r"(\w+)\s*=\s*'[^']*$", prefix)
        unquoted_attr = re.search(r'(\w+)\s*=\s*[^\s"\'<>]+$', prefix)

        if double_attr:
            return InjectionContext.HTML_ATTRIBUTE_DOUBLE_QUOTED
        if single_attr:
            return InjectionContext.HTML_ATTRIBUTE_SINGLE_QUOTED
        if unquoted_attr:
            return InjectionContext.HTML_ATTRIBUTE_UNQUOTED

        return None

    def _is_in_attribute(self, prefix: str) -> bool:
        """Generic check for being in any attribute"""
        return bool(re.search(r'(\w+)\s*=\s*["\'][^"\']*$', prefix))

    def _looks_like_json(self, body: str) -> bool:
        """Check if response looks like JSON"""
        stripped = body.strip()
        return (stripped.startswith('{') and stripped.endswith('}')) or \
               (stripped.startswith('[') and stripped.endswith(']'))

    def _detect_transformations(self, original: str, found: str,
                               body: str, position: int) -> List[TransformationType]:
        """Detect what transformations were applied"""
        transformations = []

        if original == found:
            return [TransformationType.NONE]

        if html.escape(original) == found:
            transformations.append(TransformationType.HTML_ENCODED)

        if quote(original, safe='') == found:
            transformations.append(TransformationType.URL_ENCODED)

        if quote(quote(original, safe=''), safe='') == found:
            transformations.append(TransformationType.DOUBLE_URL_ENCODED)

        if original.lower() == found.lower() and original != found:
            transformations.append(TransformationType.CASE_MODIFIED)

        if len(found) < len(original):
            transformations.append(TransformationType.TRUNCATED)

        return transformations if transformations else [TransformationType.NONE]

    def _get_breakout_chars(self, context: InjectionContext) -> List[str]:
        """Get characters needed to break out of context"""
        breakout_map = {
            InjectionContext.HTML_TEXT: ['<'],
            InjectionContext.HTML_ATTRIBUTE_DOUBLE_QUOTED: ['"', '>'],
            InjectionContext.HTML_ATTRIBUTE_SINGLE_QUOTED: ["'", '>'],
            InjectionContext.HTML_ATTRIBUTE_UNQUOTED: [' ', '>', '/'],
            InjectionContext.HTML_COMMENT: ['-->'],
            InjectionContext.JAVASCRIPT_STRING_SINGLE: ["'"],
            InjectionContext.JAVASCRIPT_STRING_DOUBLE: ['"'],
            InjectionContext.JAVASCRIPT_STRING_TEMPLATE: ['`', '${'],
            InjectionContext.JAVASCRIPT_CODE: ['</script>'],
            InjectionContext.CSS_VALUE: ['}', '</style>'],
            InjectionContext.JSON_VALUE: ['"', '}'],
            InjectionContext.XML_TEXT: ['<'],
            InjectionContext.XML_ATTRIBUTE: ['"', "'"],
            InjectionContext.SQL_STRING: ["'", '"'],
            InjectionContext.SQL_NUMERIC: [' ', ';', '--'],
        }
        return breakout_map.get(context, [])

    def _get_encoding_type(self, transformations: List[TransformationType]) -> Optional[str]:
        """Get the primary encoding type"""
        for t in transformations:
            if t == TransformationType.HTML_ENCODED:
                return 'html'
            if t == TransformationType.URL_ENCODED:
                return 'url'
            if t == TransformationType.DOUBLE_URL_ENCODED:
                return 'double_url'
        return None

    def _can_break_context(self, context: InjectionContext, body: str, position: int) -> bool:
        """Determine if context can likely be broken"""
        # If in HTML text, we can usually inject tags
        if context == InjectionContext.HTML_TEXT:
            return True

        # In unquoted attributes, very easy to break
        if context == InjectionContext.HTML_ATTRIBUTE_UNQUOTED:
            return True

        # In JS code (not string), we have full control
        if context == InjectionContext.JAVASCRIPT_CODE:
            return True

        # In quoted contexts, depends on filtering
        # (This would need to be tested with actual breakout chars)
        return False


# =============================================================================
# BEHAVIOR PROBER
# =============================================================================

class BehaviorProber:
    """
    Sends intelligent probes to understand application behavior.
    Uses technology-aware probes based on detected stack.
    """

    # Lightweight probes that are unlikely to cause harm but reveal behavior
    BEHAVIOR_PROBES = {
        # SQL probes
        'sqli_basic': {
            'probes': ["'", "''", '"', '\\', "'--", "' OR '1", "1 OR 1=1", "-1 OR 1=1"],
            'indicators': ['sql', 'syntax', 'query', 'mysql', 'sqlite', 'oracle', 'postgres', 'ORA-', 'error'],
            'type': 'sqli'
        },
        'sqli_timing': {
            'probes': ["'; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--", "'; SELECT pg_sleep(5)--"],
            'timing_threshold': 4.5,
            'type': 'sqli'
        },
        'sqli_math': {
            'probes': ['1', '1+1', '2-1', '1*1'],  # Math operations
            'expect_same': [(0, 1), (1, 3)],  # Indices that should give same result
            'type': 'sqli'
        },

        # XSS probes
        'xss_reflection': {
            'probes': ['xss<test>', 'xss"test', "xss'test", 'xss`test', 'xss${7*7}'],
            'reflection_check': True,
            'type': 'xss'
        },
        'xss_event': {
            'probes': ['"><svg onload=alert(1)>', "'-alert(1)-'", '<img src=x onerror=alert(1)>'],
            'indicators': ['<svg', '<img', 'onerror', 'onload'],
            'type': 'xss'
        },

        # LFI probes
        'lfi_basic': {
            'probes': ['....//....//etc/passwd', '/etc/passwd', '..\\..\\windows\\win.ini',
                      'php://filter/convert.base64-encode/resource=index', '....//....//....//etc/passwd'],
            'indicators': ['root:', 'daemon:', 'bin:', '[extensions]', 'PD9waHA'],  # base64 of <?php
            'type': 'lfi'
        },
        'lfi_wrapper': {
            'probes': ['php://input', 'php://filter/read=string.rot13/resource=index.php',
                      'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=='],
            'indicators': ['<?php', 'phpinfo', 'allow_url_'],
            'type': 'lfi'
        },

        # RCE probes
        'rce_basic': {
            'probes': ['; id', '| id', '`id`', '$(id)', '; whoami', '| whoami'],
            'indicators': ['uid=', 'gid=', 'groups=', 'root', 'www-data', 'apache', 'nginx'],
            'type': 'rce'
        },
        'rce_blind': {
            'probes': ['; sleep 5', '| sleep 5', '`sleep 5`', '$(sleep 5)'],
            'timing_threshold': 4.5,
            'type': 'rce'
        },

        # SSRF probes
        'ssrf_basic': {
            'probes': ['http://127.0.0.1', 'http://localhost', 'http://[::1]',
                      'http://169.254.169.254/latest/meta-data/', 'file:///etc/passwd'],
            'indicators': ['root:', 'localhost', '127.0.0.1', 'ami-id', 'instance-id'],
            'type': 'ssrf'
        },

        # XXE probes
        'xxe_basic': {
            'probes': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1">]><foo>&xxe;</foo>',
            ],
            'indicators': ['root:', 'daemon:', 'ENTITY', 'DOCTYPE'],
            'type': 'xxe'
        },

        # SSTI probes
        'ssti_basic': {
            'probes': ['{{7*7}}', '${7*7}', '<%= 7*7 %>', '#{7*7}', '*{7*7}', '@(7*7)'],
            'indicators': ['49'],  # 7*7 = 49
            'type': 'ssti'
        },
        'ssti_advanced': {
            'probes': [
                "{{config}}", "{{self}}", "{{request}}",
                "${class.getResource('').getPath()}",
                "<%= system('id') %>"
            ],
            'indicators': ['SECRET', 'DEBUG', 'config', 'uid='],
            'type': 'ssti'
        },

        # NoSQLi probes
        'nosqli_basic': {
            'probes': ["{'$gt': ''}", '{"$ne": null}', '[$ne]=1', '{"$where": "1==1"}'],
            'indicators': ['mongo', 'bson', 'ObjectId', 'undefined'],
            'type': 'nosqli'
        },

        # Path traversal probes
        'traversal_basic': {
            'probes': ['../../../etc/passwd', '..\\..\\..\\windows\\win.ini',
                      '....//....//etc/passwd', '..%252f..%252f..%252fetc/passwd'],
            'indicators': ['root:', 'daemon:', '[extensions]'],
            'type': 'path_traversal'
        },

        # CRLF probes
        'crlf_basic': {
            'probes': ['%0d%0aX-Injected: true', '\r\nX-Injected: true', '%0aX-Injected: true'],
            'header_check': 'X-Injected',
            'type': 'crlf'
        },

        # Open redirect probes
        'redirect_basic': {
            'probes': ['//evil.com', 'https://evil.com', '/\\evil.com', '//evil.com/%2f..'],
            'redirect_check': True,
            'type': 'open_redirect'
        },
    }

    # Technology-specific probe configurations
    TECH_PROBES = {
        'php': ['sqli_basic', 'lfi_basic', 'lfi_wrapper', 'rce_basic', 'xss_reflection'],
        'java': ['sqli_basic', 'xxe_basic', 'ssti_advanced', 'traversal_basic'],
        'python': ['sqli_basic', 'ssti_basic', 'rce_basic'],
        'nodejs': ['nosqli_basic', 'ssti_basic', 'rce_basic', 'xss_reflection'],
        'ruby': ['sqli_basic', 'ssti_basic', 'rce_basic'],
        'asp.net': ['sqli_basic', 'traversal_basic', 'xss_reflection'],
        'wordpress': ['sqli_basic', 'lfi_basic', 'xss_reflection'],
        'default': ['sqli_basic', 'xss_reflection', 'traversal_basic', 'ssti_basic'],
    }

    def __init__(self):
        self.differential_analyzer = ResponseDifferentialAnalyzer()
        self.reflection_detector = ReflectionDetector()

    def get_probes_for_technology(self, technologies: List[str]) -> List[str]:
        """Get appropriate probes based on detected technologies"""
        probe_sets = set()

        for tech in technologies:
            tech_lower = tech.lower()
            if tech_lower in self.TECH_PROBES:
                probe_sets.update(self.TECH_PROBES[tech_lower])

        # Always include default probes
        probe_sets.update(self.TECH_PROBES['default'])

        return list(probe_sets)

    def create_probe_payloads(self, probe_type: str) -> List[Dict[str, Any]]:
        """Create probe payloads with metadata"""
        if probe_type not in self.BEHAVIOR_PROBES:
            return []

        config = self.BEHAVIOR_PROBES[probe_type]
        payloads = []

        for probe in config['probes']:
            payloads.append({
                'payload': probe,
                'type': config.get('type', 'unknown'),
                'probe_type': probe_type,
                'indicators': config.get('indicators', []),
                'timing_threshold': config.get('timing_threshold'),
                'reflection_check': config.get('reflection_check', False),
                'header_check': config.get('header_check'),
                'redirect_check': config.get('redirect_check', False),
            })

        return payloads


# =============================================================================
# TIMING ANALYZER
# =============================================================================

class TimingAnalyzer:
    """
    Analyzes response timing for blind injection detection.
    Uses statistical methods to detect meaningful time differences.
    """

    def __init__(self, baseline_samples: int = 3):
        self.baseline_samples = baseline_samples
        self.timing_history: Dict[str, List[float]] = defaultdict(list)

    def establish_baseline(self, endpoint: str, times: List[float]) -> Dict[str, float]:
        """Establish baseline timing statistics"""
        if not times:
            return {'mean': 0, 'std': 0, 'max': 0, 'min': 0}

        self.timing_history[endpoint].extend(times)

        return {
            'mean': statistics.mean(times),
            'std': statistics.stdev(times) if len(times) > 1 else 0,
            'max': max(times),
            'min': min(times),
        }

    def is_timing_anomaly(self, endpoint: str, probe_time: float,
                         expected_delay: float = 5.0) -> Tuple[bool, Dict]:
        """
        Check if response time indicates a timing-based vulnerability.
        """
        history = self.timing_history.get(endpoint, [])

        if not history:
            # No baseline, use simple threshold
            is_anomaly = probe_time >= expected_delay * 0.9
            return is_anomaly, {
                'probe_time': probe_time,
                'expected_delay': expected_delay,
                'no_baseline': True,
                'confidence': 0.5 if is_anomaly else 0.0
            }

        baseline_mean = statistics.mean(history)
        baseline_std = statistics.stdev(history) if len(history) > 1 else baseline_mean * 0.1

        # Calculate z-score
        if baseline_std > 0:
            z_score = (probe_time - baseline_mean) / baseline_std
        else:
            z_score = (probe_time - baseline_mean) / (baseline_mean * 0.1 + 0.001)

        # Check if significantly higher than baseline AND close to expected delay
        time_diff = probe_time - baseline_mean
        is_timing_injection = (
            z_score > 3.0 and  # Statistically significant
            time_diff > expected_delay * 0.8  # Close to expected delay
        )

        confidence = 0.0
        if is_timing_injection:
            # Higher confidence if very close to expected delay
            delay_accuracy = 1 - abs(time_diff - expected_delay) / expected_delay
            confidence = min(1.0, 0.5 + delay_accuracy * 0.5)

        return is_timing_injection, {
            'probe_time': probe_time,
            'baseline_mean': baseline_mean,
            'baseline_std': baseline_std,
            'z_score': z_score,
            'time_diff': time_diff,
            'expected_delay': expected_delay,
            'confidence': confidence
        }


# =============================================================================
# ACTIVE SCANNER (Main Class)
# =============================================================================

class ActiveScanner:
    """
    Main Active Scanner - Burp Suite-level vulnerability detection.

    Combines all analysis techniques:
    - Response differential analysis
    - Reflection detection
    - Context analysis
    - Behavior probing
    - Timing analysis
    - Technology-specific tests
    """

    def __init__(self, stack_info: Dict = None):
        """
        Initialize Active Scanner.

        Args:
            stack_info: Technology stack from ProgressiveStackAnalyzer
        """
        self.differential_analyzer = ResponseDifferentialAnalyzer()
        self.reflection_detector = ReflectionDetector()
        self.behavior_prober = BehaviorProber()
        self.timing_analyzer = TimingAnalyzer()

        # Technology stack
        self.stack_info = stack_info or {}
        self.detected_technologies = self._extract_technologies()

        # WAF detection
        self.waf_detected = False
        self.waf_name = None
        self._detect_waf()

        # Results cache
        self.analysis_cache: Dict[str, InjectionPointAnalysis] = {}

    def _extract_technologies(self) -> List[str]:
        """Extract technology list from stack info"""
        technologies = []

        if 'layers' in self.stack_info:
            for layer in self.stack_info['layers']:
                if layer.get('type') == 'backend':
                    tech = layer.get('name', '').lower()
                    if tech:
                        technologies.append(tech)
                    # Also check evidence
                    evidence = layer.get('evidence', '')
                    if 'php' in evidence.lower():
                        technologies.append('php')
                    elif 'asp' in evidence.lower():
                        technologies.append('asp.net')
                    elif 'java' in evidence.lower():
                        technologies.append('java')

        # Default if nothing detected
        if not technologies:
            technologies = ['default']

        return list(set(technologies))

    def _detect_waf(self):
        """Check if WAF is present in stack"""
        if 'layers' in self.stack_info:
            for layer in self.stack_info['layers']:
                if layer.get('type') == 'waf':
                    self.waf_detected = True
                    self.waf_name = layer.get('name')
                    break

    def analyze_injection_point(
        self,
        parameter_name: str,
        parameter_value: str,
        location: str,  # query, body, header, cookie, path
        send_request: Callable[[str], Tuple[int, str, Dict, float]],
        baseline_response: Tuple[int, str, Dict, float] = None
    ) -> InjectionPointAnalysis:
        """
        Perform deep analysis of an injection point.

        Args:
            parameter_name: Name of the parameter
            parameter_value: Current value
            location: Where parameter is (query, body, header, cookie, path)
            send_request: Function that sends request with modified value
                          Returns (status_code, body, headers, response_time)
            baseline_response: Optional pre-captured baseline

        Returns:
            Complete analysis of the injection point
        """
        # Get baseline if not provided
        if baseline_response is None:
            baseline_response = send_request(parameter_value)

        status, body, headers, resp_time = baseline_response
        baseline_fp = self.differential_analyzer.fingerprint_response(
            status, body, headers, resp_time
        )

        # Establish timing baseline
        timing_samples = [resp_time]
        for _ in range(2):  # Get 2 more samples
            _, _, _, t = send_request(parameter_value)
            timing_samples.append(t)
        self.timing_analyzer.establish_baseline(parameter_name, timing_samples)

        # Phase 1: Reflection Analysis
        reflections = self._analyze_reflections(
            parameter_value, body, send_request
        )

        # Phase 2: Behavior Probing
        susceptibilities = self._probe_vulnerabilities(
            parameter_name, parameter_value, location,
            send_request, baseline_fp
        )

        # Phase 3: Determine test order
        test_order = self._determine_test_order(susceptibilities, reflections)

        return InjectionPointAnalysis(
            parameter_name=parameter_name,
            parameter_value=parameter_value,
            location=location,
            baseline_response=baseline_fp,
            reflections=reflections,
            susceptibilities=susceptibilities,
            detected_technologies=self.detected_technologies,
            waf_detected=self.waf_detected,
            waf_name=self.waf_name,
            recommended_test_order=test_order
        )

    def _analyze_reflections(
        self,
        original_value: str,
        baseline_body: str,
        send_request: Callable
    ) -> List[ReflectionPoint]:
        """Analyze how input is reflected"""
        all_reflections = []

        # Check basic reflection
        reflections = self.reflection_detector.detect_reflections(
            original_value, baseline_body
        )
        all_reflections.extend(reflections)

        # Test with canary to understand transformations
        canary = 'xss7331test'
        status, body, _, _ = send_request(canary)
        canary_reflections = self.reflection_detector.detect_reflections(
            canary, body, canary
        )
        all_reflections.extend(canary_reflections)

        # Test special characters
        special_canary = 'zz<>"\'&zz'
        status, body, _, _ = send_request(special_canary)
        special_reflections = self.reflection_detector.detect_reflections(
            special_canary, body, special_canary
        )
        all_reflections.extend(special_reflections)

        return all_reflections

    def _probe_vulnerabilities(
        self,
        param_name: str,
        param_value: str,
        location: str,
        send_request: Callable,
        baseline_fp: ResponseFingerprint
    ) -> List[VulnerabilitySusceptibility]:
        """Probe for vulnerability susceptibility"""
        susceptibilities = []

        # Get probes for detected technologies
        probe_types = self.behavior_prober.get_probes_for_technology(
            self.detected_technologies
        )

        for probe_type in probe_types:
            probes = self.behavior_prober.create_probe_payloads(probe_type)

            for probe_config in probes:
                payload = probe_config['payload']
                vuln_type = probe_config['type']

                # Send probe
                status, body, headers, resp_time = send_request(payload)
                probe_fp = self.differential_analyzer.fingerprint_response(
                    status, body, headers, resp_time
                )

                # Calculate differential
                diff_score, diff_details = self.differential_analyzer.calculate_differential(
                    baseline_fp, probe_fp
                )

                # Check for indicators
                indicators_found = []
                for indicator in probe_config.get('indicators', []):
                    if indicator.lower() in body.lower():
                        indicators_found.append(indicator)

                # Check timing (for timing-based probes)
                timing_result = None
                if probe_config.get('timing_threshold'):
                    is_timing, timing_details = self.timing_analyzer.is_timing_anomaly(
                        param_name, resp_time, probe_config['timing_threshold']
                    )
                    if is_timing:
                        timing_result = timing_details

                # Check reflection (for XSS probes)
                reflection_result = None
                if probe_config.get('reflection_check'):
                    reflections = self.reflection_detector.detect_reflections(
                        payload, body
                    )
                    if reflections:
                        reflection_result = reflections

                # Determine susceptibility
                susceptibility = self._evaluate_susceptibility(
                    vuln_type=vuln_type,
                    diff_score=diff_score,
                    diff_details=diff_details,
                    indicators_found=indicators_found,
                    timing_result=timing_result,
                    reflection_result=reflection_result,
                    probe_config=probe_config
                )

                if susceptibility.susceptibility != VulnSusceptibility.NONE:
                    susceptibilities.append(susceptibility)

        # Deduplicate and sort by confidence
        return self._dedupe_susceptibilities(susceptibilities)

    def _evaluate_susceptibility(
        self,
        vuln_type: str,
        diff_score: float,
        diff_details: Dict,
        indicators_found: List[str],
        timing_result: Optional[Dict],
        reflection_result: Optional[List[ReflectionPoint]],
        probe_config: Dict
    ) -> VulnerabilitySusceptibility:
        """Evaluate susceptibility based on probe results"""
        evidence = []
        confidence = 0.0
        susceptibility = VulnSusceptibility.NONE
        detection_technique = "differential"
        requires_blind = False
        context = None

        # Strong indicators found
        if indicators_found:
            evidence.append(f"Indicators found: {', '.join(indicators_found)}")
            confidence += 0.4
            susceptibility = VulnSusceptibility.HIGH

        # Timing-based detection
        if timing_result:
            evidence.append(f"Timing anomaly detected: {timing_result['probe_time']:.2f}s")
            confidence += timing_result.get('confidence', 0.3)
            susceptibility = VulnSusceptibility.HIGH
            detection_technique = "timing"
            requires_blind = True

        # Reflection-based (XSS)
        if reflection_result:
            for ref in reflection_result:
                if ref.can_break_out:
                    evidence.append(f"Breakable reflection in {ref.context.value}")
                    confidence += 0.5
                    susceptibility = VulnSusceptibility.HIGH
                    context = ref.context
                elif not ref.is_encoded:
                    evidence.append(f"Unencoded reflection in {ref.context.value}")
                    confidence += 0.3
                    susceptibility = VulnSusceptibility.MEDIUM
                    context = ref.context
                else:
                    evidence.append(f"Encoded reflection in {ref.context.value}")
                    confidence += 0.1
                    susceptibility = VulnSusceptibility.LOW
            detection_technique = "reflection"

        # Differential analysis
        if diff_score > 0.5:
            evidence.append(f"High differential score: {diff_score:.2f}")
            if susceptibility == VulnSusceptibility.NONE:
                susceptibility = VulnSusceptibility.MEDIUM
            confidence += 0.2

        # New errors
        if diff_details.get('new_errors'):
            evidence.append(f"New errors: {diff_details['new_errors']}")
            confidence += 0.3
            if susceptibility == VulnSusceptibility.NONE:
                susceptibility = VulnSusceptibility.MEDIUM

        # Status code change to error
        if diff_details.get('status_changed') and diff_details.get('new_errors'):
            confidence += 0.1

        # Cap confidence at 1.0
        confidence = min(1.0, confidence)

        # Get recommended payloads
        recommended = self._get_recommended_payloads(vuln_type, context)

        return VulnerabilitySusceptibility(
            vuln_type=vuln_type,
            susceptibility=susceptibility,
            confidence=confidence,
            evidence=evidence,
            recommended_payloads=recommended,
            detection_technique=detection_technique,
            context=context,
            requires_blind_testing=requires_blind
        )

    def _get_recommended_payloads(self, vuln_type: str,
                                  context: InjectionContext = None) -> List[str]:
        """Get recommended payloads based on vuln type and context"""
        payloads = []

        if vuln_type == 'xss':
            if context == InjectionContext.HTML_TEXT:
                payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>']
            elif context in [InjectionContext.HTML_ATTRIBUTE_DOUBLE_QUOTED]:
                payloads = ['"><script>alert(1)</script>', '" onmouseover=alert(1) x="']
            elif context == InjectionContext.JAVASCRIPT_STRING_SINGLE:
                payloads = ["'-alert(1)-'", "';alert(1)//"]
            elif context == InjectionContext.JAVASCRIPT_STRING_DOUBLE:
                payloads = ['"-alert(1)-"', '";alert(1)//']
            else:
                payloads = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>']

        elif vuln_type == 'sqli':
            payloads = ["' OR '1'='1", "' UNION SELECT NULL--", "1' AND '1'='1", "1 OR 1=1"]

        elif vuln_type == 'lfi':
            payloads = ['../../../etc/passwd', 'php://filter/convert.base64-encode/resource=index.php']

        elif vuln_type == 'rce':
            payloads = ['; id', '| id', '`id`', '$(id)']

        elif vuln_type == 'ssti':
            payloads = ['{{7*7}}', '${7*7}', '<%= 7*7 %>']

        return payloads

    def _dedupe_susceptibilities(
        self,
        susceptibilities: List[VulnerabilitySusceptibility]
    ) -> List[VulnerabilitySusceptibility]:
        """Deduplicate and merge susceptibilities by vuln type"""
        by_type = defaultdict(list)
        for s in susceptibilities:
            by_type[s.vuln_type].append(s)

        merged = []
        for vuln_type, items in by_type.items():
            # Take highest confidence
            best = max(items, key=lambda x: x.confidence)

            # Merge evidence
            all_evidence = []
            all_payloads = []
            for item in items:
                all_evidence.extend(item.evidence)
                all_payloads.extend(item.recommended_payloads)

            best.evidence = list(set(all_evidence))
            best.recommended_payloads = list(set(all_payloads))[:5]
            merged.append(best)

        # Sort by confidence
        merged.sort(key=lambda x: x.confidence, reverse=True)
        return merged

    def _determine_test_order(
        self,
        susceptibilities: List[VulnerabilitySusceptibility],
        reflections: List[ReflectionPoint]
    ) -> List[str]:
        """Determine optimal test order based on analysis"""
        order = []

        # First: high susceptibility vulns
        for s in susceptibilities:
            if s.susceptibility in [VulnSusceptibility.CONFIRMED, VulnSusceptibility.HIGH]:
                if s.vuln_type not in order:
                    order.append(s.vuln_type)

        # Second: reflected XSS if we have unencoded reflection
        if any(r.can_break_out or not r.is_encoded for r in reflections):
            if 'xss' not in order:
                order.insert(0, 'xss')

        # Third: medium susceptibility
        for s in susceptibilities:
            if s.susceptibility == VulnSusceptibility.MEDIUM:
                if s.vuln_type not in order:
                    order.append(s.vuln_type)

        # Fourth: technology-based recommendations
        tech_vulns = {
            'php': ['sqli', 'lfi', 'rce'],
            'java': ['sqli', 'xxe', 'ssti'],
            'nodejs': ['nosqli', 'ssti', 'rce'],
            'python': ['sqli', 'ssti', 'rce'],
        }
        for tech in self.detected_technologies:
            for vuln in tech_vulns.get(tech.lower(), []):
                if vuln not in order:
                    order.append(vuln)

        # Fifth: common vulns
        common = ['sqli', 'xss', 'lfi', 'path_traversal']
        for vuln in common:
            if vuln not in order:
                order.append(vuln)

        return order

    def get_summary(self, analysis: InjectionPointAnalysis) -> Dict:
        """Get summary of analysis for reporting"""
        return {
            'parameter': analysis.parameter_name,
            'location': analysis.location,
            'technologies': analysis.detected_technologies,
            'waf_detected': analysis.waf_detected,
            'waf_name': analysis.waf_name,
            'reflection_count': len(analysis.reflections),
            'reflections': [
                {
                    'context': r.context.value,
                    'can_break_out': r.can_break_out,
                    'is_encoded': r.is_encoded,
                    'encoding': r.encoding_type,
                }
                for r in analysis.reflections
            ],
            'susceptibilities': [
                {
                    'vuln_type': s.vuln_type,
                    'level': s.susceptibility.value,
                    'confidence': f"{s.confidence:.0%}",
                    'evidence': s.evidence,
                    'detection': s.detection_technique,
                    'requires_blind': s.requires_blind_testing,
                }
                for s in analysis.susceptibilities
            ],
            'recommended_test_order': analysis.recommended_test_order,
        }


# =============================================================================
# MAIN / SELF-TEST
# =============================================================================

if __name__ == "__main__":
    print("""
    Active Scanner v4.0 - Burp Suite-level Vulnerability Detection

    Components:
    - ResponseDifferentialAnalyzer: Compare baseline vs probe responses
    - ReflectionDetector: Find where/how input is reflected
    - BehaviorProber: Technology-aware intelligent probing
    - TimingAnalyzer: Detect timing-based vulnerabilities
    - ActiveScanner: Main orchestrator

    This module analyzes injection points to determine:
    1. What vulnerabilities the point is susceptible to
    2. What context the input appears in (HTML, JS, SQL, etc.)
    3. What transformations are applied to input
    4. What payloads are most likely to work
    """)

    # Self-test
    print("\n[*] Running self-test...")

    # Test 1: Reflection Detection
    print("\n[Test 1] Reflection Detection:")
    detector = ReflectionDetector()

    test_body = '''
    <html>
    <body>
        <h1>Search Results for: xss1337test</h1>
        <script>
            var query = "xss1337test";
            console.log(query);
        </script>
        <input type="hidden" value="xss1337test">
    </body>
    </html>
    '''

    reflections = detector.detect_reflections('xss1337test', test_body)
    print(f"  Found {len(reflections)} reflection points:")
    for r in reflections:
        print(f"    - Context: {r.context.value}, Can break: {r.can_break_out}")

    # Test 2: Differential Analysis
    print("\n[Test 2] Differential Analysis:")
    diff_analyzer = ResponseDifferentialAnalyzer()

    baseline_fp = diff_analyzer.fingerprint_response(
        200, '<html><body>Normal page</body></html>', {}, 0.1
    )
    probe_fp = diff_analyzer.fingerprint_response(
        500, '<html><body>SQL error: syntax near</body></html>', {}, 0.15
    )

    score, details = diff_analyzer.calculate_differential(baseline_fp, probe_fp)
    print(f"  Differential score: {score:.2f}")
    print(f"  Status changed: {details['status_changed']}")
    print(f"  New errors: {details['new_errors']}")

    # Test 3: Context Analysis
    print("\n[Test 3] Context Analysis:")
    test_contexts = [
        ('<div>MARKER</div>', InjectionContext.HTML_TEXT),
        ('<input value="MARKER">', InjectionContext.HTML_ATTRIBUTE_DOUBLE_QUOTED),
        ("<script>var x = 'MARKER';</script>", InjectionContext.JAVASCRIPT_STRING_SINGLE),
        ('<script>var x = "MARKER";</script>', InjectionContext.JAVASCRIPT_STRING_DOUBLE),
    ]

    for html, expected in test_contexts:
        reflections = detector.detect_reflections('MARKER', html)
        if reflections:
            actual = reflections[0].context
            status = "✓" if actual == expected else "✗"
            print(f"  {status} Expected {expected.value}, got {actual.value}")

    # Test 4: Behavior Probes
    print("\n[Test 4] Behavior Probes:")
    prober = BehaviorProber()
    probes = prober.get_probes_for_technology(['php', 'mysql'])
    print(f"  Probes for PHP/MySQL: {probes}")

    print("\n[+] Self-test completed!")
