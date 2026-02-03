#!/usr/bin/env python3
"""
Intelligent Payload Manager v4.0
Orchestrates wordlist loading, vulnerability inference, and analyzer integration

Features:
- Automatic vulnerability type inference from endpoint/parameter
- Smart wordlist selection based on inferred vulnerabilities
- Integration with all analyzers (SQLi, XSS, LFI, XXE, SSTI, etc.)
- Payload prioritization and deduplication
- Adaptive payload selection based on technology stack
- Results validation with Bayesian confidence

Author: Security Testing Suite
License: Authorized security research only
"""

import os
import re
import hashlib
import itertools
from typing import Dict, List, Optional, Tuple, Set, Any, Generator, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging

# Import analyzers
from .vulnerability.causal_vulnerability_analyzer import (
    CausalVulnerabilityAnalyzer,
    SQLiAnalyzer,
    XSSAnalyzer,
    LFIAnalyzer,
    RCEAnalyzer,
    SSRFAnalyzer
)
from .vulnerability.extended_analyzers import ExtendedAnalyzerRegistry
from .taxonomy import SelfLearningTaxonomy

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS AND DATA CLASSES
# =============================================================================

class ParameterContext(Enum):
    """Parameter context types"""
    URL_PATH = "url_path"
    QUERY_PARAM = "query_param"
    POST_BODY = "post_body"
    HEADER = "header"
    COOKIE = "cookie"
    JSON_FIELD = "json_field"
    XML_ELEMENT = "xml_element"
    FILE_UPLOAD = "file_upload"


@dataclass
class VulnerabilityInference:
    """Inferred vulnerability from parameter analysis"""
    vuln_type: str
    confidence: float
    reason: str
    priority: int  # 1=highest
    wordlist_category: str


@dataclass
class PayloadResult:
    """Result of payload testing"""
    payload: str
    vuln_type: str
    is_vulnerable: bool
    confidence: float
    technique: str
    evidence: str
    analyzer_result: Dict = field(default_factory=dict)
    wordlist_source: str = ""


@dataclass
class TestingPlan:
    """Complete testing plan for an endpoint/parameter"""
    endpoint: str
    parameter: str
    context: ParameterContext
    inferred_vulns: List[VulnerabilityInference]
    payloads_by_type: Dict[str, List[str]]
    total_payloads: int
    estimated_requests: int


# =============================================================================
# VULNERABILITY INFERENCER
# =============================================================================

class VulnerabilityInferencer:
    """
    Infers likely vulnerabilities from parameter name, context, and value.

    Uses pattern matching and heuristics to determine which vulnerability
    types are most likely for a given injection point.
    """

    # Parameter name patterns → vulnerability types
    PARAM_PATTERNS = {
        'sqli': [
            re.compile(r'^(id|uid|user_id|userid|item|product|category|cat|page|article|news|post|order|sort|column|col|table|db|query|select|where|limit|offset)$', re.I),
            re.compile(r'_id$|Id$|ID$', re.I),
            re.compile(r'(search|find|filter|lookup|fetch)', re.I),
        ],
        'xss': [
            re.compile(r'^(name|title|comment|message|text|content|body|description|bio|about|note|feedback|review|q|query|search|keyword|term|input|value|data|field|param|label)$', re.I),
            re.compile(r'(name|title|text|msg|comment|content)$', re.I),
        ],
        'lfi': [
            re.compile(r'^(file|path|filepath|filename|name|doc|document|folder|root|dir|directory|pg|page|view|template|tpl|include|inc|load|read|cat|download|attachment|pdf|img|image|src)$', re.I),
            re.compile(r'(file|path|template|page|lang|language|locale)$', re.I),
        ],
        'rce': [
            re.compile(r'^(cmd|command|exec|run|execute|system|shell|bash|ping|ip|host|hostname|address|daemon|upload|process|task|job|action|do)$', re.I),
        ],
        'ssrf': [
            re.compile(r'^(url|uri|link|href|src|source|dest|destination|target|site|website|domain|host|fetch|load|read|open|callback|webhook|api|endpoint|proxy|forward|redirect|redir|next|return|continue|goto)$', re.I),
        ],
        'xxe': [
            re.compile(r'^(xml|data|content|body|payload|request|input|doc|document|soap)$', re.I),
        ],
        'ssti': [
            re.compile(r'^(template|tpl|theme|layout|view|render|page|email|message|subject|greeting|welcome|banner|header|footer|content)$', re.I),
        ],
        'open_redirect': [
            re.compile(r'^(url|uri|link|redirect|redir|next|return|returnUrl|return_url|continue|goto|dest|destination|target|out|forward|ref|callback|success|error|login|logout)$', re.I),
        ],
        'ldapi': [
            re.compile(r'^(user|username|login|uid|cn|dn|search|filter|query|ldap|auth|name|group|ou)$', re.I),
        ],
        'nosqli': [
            re.compile(r'^(id|_id|user|username|email|query|filter|search|find|where|match|lookup)$', re.I),
        ],
        'path_traversal': [
            re.compile(r'^(file|path|filepath|dir|directory|folder|name|doc|download|attachment|template|include|page|lang|locale)$', re.I),
        ],
    }

    # Content-Type patterns → vulnerability types
    CONTENT_TYPE_VULNS = {
        'application/xml': ['xxe', 'xpath'],
        'text/xml': ['xxe', 'xpath'],
        'application/json': ['nosqli', 'sqli'],
        'application/x-www-form-urlencoded': ['sqli', 'xss', 'lfi', 'rce'],
        'multipart/form-data': ['file_upload', 'rce', 'xss'],
    }

    # Technology stack → vulnerability types
    TECHNOLOGY_VULNS = {
        'php': ['sqli', 'lfi', 'rce', 'xss', 'xxe', 'ssti'],
        'java': ['sqli', 'xxe', 'ssti', 'insecure_deser'],
        'python': ['sqli', 'ssti', 'insecure_deser', 'rce'],
        'nodejs': ['nosqli', 'ssti', 'prototype_pollution', 'rce'],
        'ruby': ['sqli', 'ssti', 'insecure_deser', 'rce'],
        'asp.net': ['sqli', 'xss', 'insecure_deser', 'path_traversal'],
        'wordpress': ['sqli', 'xss', 'lfi', 'file_upload'],
        'mongodb': ['nosqli'],
        'nginx': ['path_traversal', 'ssrf'],
        'apache': ['path_traversal', 'ssrf'],
    }

    def __init__(self):
        """Initialize vulnerability inferencer"""
        pass

    def infer_vulnerabilities(
        self,
        parameter_name: str,
        parameter_value: str = "",
        context: Union[ParameterContext, str] = ParameterContext.QUERY_PARAM,
        content_type: str = "",
        technologies: List[str] = None
    ) -> List[VulnerabilityInference]:
        """
        Infer likely vulnerabilities for a parameter

        Args:
            parameter_name: Name of the parameter
            parameter_value: Current value (if known)
            context: Parameter context (enum or string)
            content_type: Request content-type
            technologies: Detected technologies

        Returns:
            List of VulnerabilityInference sorted by priority
        """
        # Convert string context to enum if needed
        if isinstance(context, str):
            context_map = {
                'query': ParameterContext.QUERY_PARAM,
                'query_param': ParameterContext.QUERY_PARAM,
                'body': ParameterContext.POST_BODY,
                'post_body': ParameterContext.POST_BODY,
                'header': ParameterContext.HEADER,
                'cookie': ParameterContext.COOKIE,
                'path': ParameterContext.URL_PATH,
                'url_path': ParameterContext.URL_PATH,
                'json': ParameterContext.JSON_FIELD,
                'json_field': ParameterContext.JSON_FIELD,
                'xml': ParameterContext.XML_ELEMENT,
                'xml_element': ParameterContext.XML_ELEMENT,
                'file': ParameterContext.FILE_UPLOAD,
                'file_upload': ParameterContext.FILE_UPLOAD,
            }
            context = context_map.get(context.lower(), ParameterContext.QUERY_PARAM)

        inferences = []
        seen_types = set()

        # 1. Check parameter name patterns
        for vuln_type, patterns in self.PARAM_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(parameter_name):
                    if vuln_type not in seen_types:
                        inferences.append(VulnerabilityInference(
                            vuln_type=vuln_type,
                            confidence=0.75,
                            reason=f"Parameter name '{parameter_name}' matches {vuln_type} pattern",
                            priority=2,
                            wordlist_category=vuln_type
                        ))
                        seen_types.add(vuln_type)
                    break

        # 2. Check content-type
        if content_type:
            for ct_pattern, vulns in self.CONTENT_TYPE_VULNS.items():
                if ct_pattern in content_type.lower():
                    for vuln_type in vulns:
                        if vuln_type not in seen_types:
                            inferences.append(VulnerabilityInference(
                                vuln_type=vuln_type,
                                confidence=0.65,
                                reason=f"Content-Type '{content_type}' suggests {vuln_type}",
                                priority=3,
                                wordlist_category=vuln_type
                            ))
                            seen_types.add(vuln_type)

        # 3. Check technologies
        if technologies:
            for tech in technologies:
                tech_lower = tech.lower()
                if tech_lower in self.TECHNOLOGY_VULNS:
                    for vuln_type in self.TECHNOLOGY_VULNS[tech_lower]:
                        if vuln_type not in seen_types:
                            inferences.append(VulnerabilityInference(
                                vuln_type=vuln_type,
                                confidence=0.60,
                                reason=f"Technology '{tech}' commonly vulnerable to {vuln_type}",
                                priority=4,
                                wordlist_category=vuln_type
                            ))
                            seen_types.add(vuln_type)

        # 4. Context-based inference
        context_vulns = self._get_context_vulnerabilities(context)
        for vuln_type in context_vulns:
            if vuln_type not in seen_types:
                inferences.append(VulnerabilityInference(
                    vuln_type=vuln_type,
                    confidence=0.50,
                    reason=f"Context '{context.value}' may be vulnerable to {vuln_type}",
                    priority=5,
                    wordlist_category=vuln_type
                ))
                seen_types.add(vuln_type)

        # 5. Value-based inference
        if parameter_value:
            value_vulns = self._analyze_value(parameter_value)
            for vuln_type, confidence in value_vulns:
                if vuln_type not in seen_types:
                    inferences.append(VulnerabilityInference(
                        vuln_type=vuln_type,
                        confidence=confidence,
                        reason=f"Parameter value suggests {vuln_type}",
                        priority=3,
                        wordlist_category=vuln_type
                    ))
                    seen_types.add(vuln_type)

        # Sort by priority then confidence
        inferences.sort(key=lambda x: (x.priority, -x.confidence))

        # Always add generic tests with low priority
        generic_tests = ['sqli', 'xss']
        for gt in generic_tests:
            if gt not in seen_types:
                inferences.append(VulnerabilityInference(
                    vuln_type=gt,
                    confidence=0.30,
                    reason="Generic test",
                    priority=10,
                    wordlist_category=gt
                ))

        return inferences

    def _get_context_vulnerabilities(self, context: ParameterContext) -> List[str]:
        """Get vulnerabilities based on context"""
        context_map = {
            ParameterContext.URL_PATH: ['path_traversal', 'lfi', 'sqli'],
            ParameterContext.QUERY_PARAM: ['sqli', 'xss', 'lfi', 'ssrf'],
            ParameterContext.POST_BODY: ['sqli', 'xss', 'rce', 'xxe'],
            ParameterContext.HEADER: ['crlf', 'ssrf', 'xss'],
            ParameterContext.COOKIE: ['sqli', 'xss', 'insecure_deser'],
            ParameterContext.JSON_FIELD: ['nosqli', 'sqli', 'ssti'],
            ParameterContext.XML_ELEMENT: ['xxe', 'xpath', 'sqli'],
            ParameterContext.FILE_UPLOAD: ['file_upload', 'rce', 'xxe'],
        }
        return context_map.get(context, ['sqli', 'xss'])

    def _analyze_value(self, value: str) -> List[Tuple[str, float]]:
        """Analyze parameter value for vulnerability hints"""
        vulns = []

        # Numeric value → likely SQL ID
        if value.isdigit():
            vulns.append(('sqli', 0.70))
            vulns.append(('idor', 0.60))

        # URL value → SSRF/redirect
        if value.startswith(('http://', 'https://', '//')):
            vulns.append(('ssrf', 0.80))
            vulns.append(('open_redirect', 0.75))

        # Path-like value → LFI
        if '/' in value or '\\' in value or value.endswith(('.php', '.html', '.jsp', '.asp')):
            vulns.append(('lfi', 0.75))
            vulns.append(('path_traversal', 0.70))

        # JSON-like → NoSQL
        if value.startswith(('{', '[')):
            vulns.append(('nosqli', 0.70))

        # Base64-like → Deserialization
        if re.match(r'^[A-Za-z0-9+/=]{20,}$', value):
            vulns.append(('insecure_deser', 0.60))

        return vulns


# =============================================================================
# WORDLIST LOADER
# =============================================================================

class WordlistLoader:
    """
    Loads and manages payloads from wordlist files.

    Supports:
    - PayloadsAllTheThings
    - FuzzDB
    - SecLists
    - Custom wordlists
    """

    # Default base paths
    DEFAULT_PATHS = {
        'payloads_all_the_things': '/usr/share/wordlists/PayloadsAllTheThings',
        'fuzzdb': '/usr/share/wordlists/fuzzdb',
        'seclists': '/usr/share/wordlists/SecLists',
    }

    # Wordlist mapping: vuln_type → list of paths
    WORDLIST_MAP = {
        'sqli': {
            'payloads_all_the_things': [
                'SQL Injection/Intruder/Auth_Bypass.txt',
                'SQL Injection/Intruder/Generic_Fuzz.txt',
                'SQL Injection/Intruder/SQLi_Polyglots.txt',
            ],
            'fuzzdb': [
                'attack/sql-injection/detect/Generic_SQLI.txt',
                'attack/sql-injection/detect/MySQL.txt',
                'attack/sql-injection/detect/MSSQL.txt',
                'attack/sql-injection/detect/oracle.txt',
                'attack/sql-injection/detect/PostgreSQL.txt',
            ],
            'seclists': [
                'Fuzzing/SQLi/Generic-SQLi.txt',
                'Fuzzing/SQLi/quick-SQLi.txt',
            ],
        },
        'xss': {
            'payloads_all_the_things': [
                'XSS Injection/Intruders/XSS_Polyglots.txt',
                'XSS Injection/Intruders/JHADDIX_XSS.txt',
                'XSS Injection/Intruders/BRUTELOGIC-XSS-STRINGS.txt',
            ],
            'fuzzdb': [
                'attack/xss/xss-rsnake.txt',
                'attack/xss/xss-other.txt',
            ],
            'seclists': [
                'Fuzzing/XSS/XSS-Jhaddix.txt',
                'Fuzzing/XSS/XSS-BruteLogic.txt',
            ],
        },
        'lfi': {
            'payloads_all_the_things': [
                'File Inclusion/Intruders/JHADDIX_LFI.txt',
                'File Inclusion/Intruders/LFI-WindowsFileCheck.txt',
                'File Inclusion/Intruders/Wrapper-PHP.txt',
            ],
            'fuzzdb': [
                'attack/lfi/JHADDIX_LFI.txt',
            ],
            'seclists': [
                'Fuzzing/LFI/LFI-Jhaddix.txt',
                'Fuzzing/LFI/LFI-gracefulsecurity-linux.txt',
                'Fuzzing/LFI/LFI-gracefulsecurity-windows.txt',
            ],
        },
        'path_traversal': {
            'payloads_all_the_things': [
                'Directory Traversal/Intruder/directory_traversal.txt',
                'Directory Traversal/Intruder/deep_traversal.txt',
            ],
            'fuzzdb': [
                'attack/path-traversal/traversals-8-deep-exotic-encoding.txt',
            ],
            'seclists': [
                'Fuzzing/LFI/LFI-gracefulsecurity-linux.txt',
            ],
        },
        'rce': {
            'payloads_all_the_things': [
                'Command Injection/Intruder/command_exec.txt',
            ],
            'fuzzdb': [
                'attack/os-cmd-execution/command-execution-unix.txt',
                'attack/os-cmd-execution/Commands-Windows.txt',
            ],
            'seclists': [
                'Fuzzing/command-injection-commix.txt',
            ],
        },
        'ssrf': {
            'payloads_all_the_things': [
                'Server Side Request Forgery/Intruders/SSRF_Payloads.txt',
            ],
            'seclists': [
                'Fuzzing/SSRF/SSRF.txt',
            ],
        },
        'xxe': {
            'payloads_all_the_things': [
                'XXE Injection/Intruders/XXE_Fuzzing.txt',
            ],
            'fuzzdb': [
                'attack/xml/xml-attacks.txt',
            ],
            'seclists': [
                'Fuzzing/XXE-Fuzzing.txt',
            ],
        },
        'ssti': {
            'payloads_all_the_things': [
                'Server Side Template Injection/Intruder/ssti.fuzz',
            ],
            'seclists': [
                'Fuzzing/template-engines-expression.txt',
                'Fuzzing/template-engines-special-vars.txt',
            ],
        },
        'nosqli': {
            'payloads_all_the_things': [
                'NoSQL Injection/Intruders/NoSQL.txt',
            ],
            'fuzzdb': [
                'attack/no-sql-injection/mongodb.txt',
            ],
        },
        'ldapi': {
            'payloads_all_the_things': [
                'LDAP Injection/Intruder/LDAP_FUZZ.txt',
            ],
            'fuzzdb': [
                'attack/ldap/ldap-injection.txt',
            ],
            'seclists': [
                'Fuzzing/LDAP.Fuzzing.txt',
            ],
        },
        'open_redirect': {
            'payloads_all_the_things': [
                'Open Redirect/Intruder/Open-Redirect-payloads.txt',
            ],
        },
        'crlf': {
            'payloads_all_the_things': [
                'CRLF Injection/Intruder/CRLF_Injection.txt',
            ],
        },
        'xpath': {
            'fuzzdb': [
                'attack/xpath/xpath-injection.txt',
            ],
        },
        'insecure_deser': {
            'payloads_all_the_things': [
                'Insecure Deserialization/Java/',
                'Insecure Deserialization/PHP/',
            ],
        },
    }

    def __init__(self, base_paths: Dict[str, str] = None):
        """Initialize wordlist loader"""
        self.base_paths = base_paths or self.DEFAULT_PATHS
        self._cache = {}  # Cache loaded payloads
        self._available_paths = self._check_available_paths()

    def _check_available_paths(self) -> Dict[str, str]:
        """Check which wordlist paths are available"""
        available = {}
        for name, path in self.base_paths.items():
            if os.path.exists(path):
                available[name] = path
                logger.info(f"Wordlist path available: {name} -> {path}")
            else:
                logger.warning(f"Wordlist path not found: {path}")
        return available

    def get_payloads(
        self,
        vuln_type: str,
        max_payloads: int = 50,
        sources: List[str] = None
    ) -> Generator[str, None, None]:
        """
        Get payloads for a vulnerability type (generator for memory efficiency)

        Args:
            vuln_type: Vulnerability type
            max_payloads: Maximum payloads to return
            sources: Specific sources to use (None = all available)

        Yields:
            Payload strings
        """
        if vuln_type not in self.WORDLIST_MAP:
            logger.warning(f"No wordlists configured for {vuln_type}")
            return

        yielded = 0
        seen = set()

        wordlist_config = self.WORDLIST_MAP[vuln_type]

        for source_name, paths in wordlist_config.items():
            if sources and source_name not in sources:
                continue

            if source_name not in self._available_paths:
                continue

            base_path = self._available_paths[source_name]

            for relative_path in paths:
                full_path = os.path.join(base_path, relative_path)

                if not os.path.exists(full_path):
                    continue

                try:
                    for payload in self._read_wordlist(full_path):
                        if payload in seen:
                            continue

                        seen.add(payload)
                        yield payload
                        yielded += 1

                        if yielded >= max_payloads:
                            return

                except Exception as e:
                    logger.error(f"Error reading {full_path}: {e}")

    def _read_wordlist(self, path: str) -> Generator[str, None, None]:
        """Read payloads from wordlist file"""
        # Check cache
        cache_key = hashlib.md5(path.encode()).hexdigest()[:12]
        if cache_key in self._cache:
            for payload in self._cache[cache_key]:
                yield payload
            return

        payloads = []

        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()

                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue

                    # Basic validation
                    if len(line) > 2000:  # Skip extremely long payloads
                        continue

                    payloads.append(line)
                    yield line

            # Cache for future use (limit cache size)
            if len(payloads) < 1000:
                self._cache[cache_key] = payloads

        except Exception as e:
            logger.error(f"Error reading wordlist {path}: {e}")

    def get_payload_count(self, vuln_type: str) -> int:
        """Get estimated payload count for vulnerability type"""
        count = 0

        if vuln_type not in self.WORDLIST_MAP:
            return 0

        for source_name, paths in self.WORDLIST_MAP[vuln_type].items():
            if source_name not in self._available_paths:
                continue

            base_path = self._available_paths[source_name]

            for relative_path in paths:
                full_path = os.path.join(base_path, relative_path)
                if os.path.exists(full_path):
                    try:
                        with open(full_path, 'r', errors='ignore') as f:
                            count += sum(1 for line in f if line.strip() and not line.startswith('#'))
                    except:
                        pass

        return count

    def get_available_sources(self) -> List[str]:
        """Get list of available wordlist sources"""
        return list(self._available_paths.keys())


# =============================================================================
# PAYLOAD MANAGER (MAIN ORCHESTRATOR)
# =============================================================================

class PayloadManager:
    """
    Main orchestrator that combines:
    - Vulnerability inference
    - Wordlist loading
    - Analyzer integration
    - Result validation

    This is the central component that implements the intelligent
    payload testing workflow.
    """

    def __init__(
        self,
        wordlist_paths: Dict[str, str] = None,
        max_payloads_per_type: int = 30
    ):
        """
        Initialize Payload Manager

        Args:
            wordlist_paths: Custom wordlist paths
            max_payloads_per_type: Max payloads per vulnerability type
        """
        self.inferencer = VulnerabilityInferencer()
        self.wordlist_loader = WordlistLoader(wordlist_paths)
        self.main_analyzer = CausalVulnerabilityAnalyzer()
        self.extended_analyzer = ExtendedAnalyzerRegistry()
        self.taxonomy = SelfLearningTaxonomy()
        self.max_payloads = max_payloads_per_type

        # Statistics
        self._total_tests = 0
        self._vulnerabilities_found = 0

    def create_testing_plan(
        self,
        endpoint: str,
        parameter: str,
        parameter_value: str = "",
        context: ParameterContext = ParameterContext.QUERY_PARAM,
        content_type: str = "",
        technologies: List[str] = None
    ) -> TestingPlan:
        """
        Create a complete testing plan for an endpoint/parameter

        Args:
            endpoint: Target URL
            parameter: Parameter name
            parameter_value: Current value
            context: Parameter context
            content_type: Request content-type
            technologies: Detected technologies

        Returns:
            TestingPlan with prioritized vulnerabilities and payloads
        """
        # Infer vulnerabilities
        inferred = self.inferencer.infer_vulnerabilities(
            parameter_name=parameter,
            parameter_value=parameter_value,
            context=context,
            content_type=content_type,
            technologies=technologies or []
        )

        # Load payloads for each inferred vulnerability
        payloads_by_type = {}
        total_payloads = 0

        for inference in inferred[:5]:  # Top 5 vulnerability types
            payloads = list(self.wordlist_loader.get_payloads(
                inference.vuln_type,
                max_payloads=self.max_payloads
            ))

            if payloads:
                payloads_by_type[inference.vuln_type] = payloads
                total_payloads += len(payloads)

        return TestingPlan(
            endpoint=endpoint,
            parameter=parameter,
            context=context,
            inferred_vulns=inferred,
            payloads_by_type=payloads_by_type,
            total_payloads=total_payloads,
            estimated_requests=total_payloads
        )

    def test_payload(
        self,
        vuln_type: str,
        payload: str,
        response_text: str,
        response_headers: Dict[str, str] = None,
        status_code: int = 200,
        response_time: float = 0.0,
        baseline_response: str = "",
        baseline_time: float = 0.0
    ) -> PayloadResult:
        """
        Test a single payload and validate with analyzer

        Args:
            vuln_type: Vulnerability type
            payload: Test payload
            response_text: HTTP response body
            response_headers: Response headers
            status_code: HTTP status code
            response_time: Response time
            baseline_response: Normal response for comparison
            baseline_time: Baseline response time

        Returns:
            PayloadResult with validation
        """
        self._total_tests += 1

        # Choose appropriate analyzer
        result = None

        # Main analyzers (SQLi, XSS, LFI, RCE, SSRF)
        main_types = ['sqli', 'xss', 'lfi', 'rce', 'ssrf']

        if vuln_type.lower() in main_types:
            # Use CausalVulnerabilityAnalyzer
            mock_response = {
                'status_code': status_code,
                'text': response_text,
                'headers': response_headers or {},
                'elapsed': response_time
            }
            mock_baseline = {
                'text': baseline_response,
                'elapsed': baseline_time
            } if baseline_response else None

            analysis = self.main_analyzer.analyze(
                endpoint="",
                param="",
                payload=payload,
                response=mock_response,
                vuln_type=vuln_type,
                baseline_response=mock_baseline
            )

            result = PayloadResult(
                payload=payload,
                vuln_type=vuln_type,
                is_vulnerable=analysis.is_vulnerable,
                confidence=analysis.confidence,
                technique=analysis.technique_used,
                evidence=analysis.recommendation if analysis.is_vulnerable else "",
                analyzer_result=analysis.to_dict()
            )

        else:
            # Use extended analyzers
            analysis = self.extended_analyzer.analyze(
                vuln_type=vuln_type,
                response_text=response_text,
                payload=payload,
                response_headers=response_headers or {},
                status_code=status_code,
                baseline_response=baseline_response
            )

            result = PayloadResult(
                payload=payload,
                vuln_type=vuln_type,
                is_vulnerable=analysis.is_vulnerable,
                confidence=analysis.confidence,
                technique=analysis.technique,
                evidence=analysis.evidence,
                analyzer_result=analysis.to_dict()
            )

        # Learn from result
        if result.is_vulnerable:
            self._vulnerabilities_found += 1
            self.taxonomy.learn(
                vuln_type=vuln_type,
                payload=payload,
                response=response_text[:500],
                is_confirmed=True
            )

        return result

    def get_classification(self, vuln_type: str, evidence: List[Dict] = None) -> Dict:
        """
        Get full classification for a vulnerability

        Args:
            vuln_type: Vulnerability type
            evidence: Detection evidence

        Returns:
            Classification with CWE, OWASP, severity
        """
        classification = self.taxonomy.classify(
            vuln_type=vuln_type,
            evidence=evidence
        )
        return classification.to_dict()

    def get_statistics(self) -> Dict:
        """Get testing statistics"""
        return {
            'total_tests': self._total_tests,
            'vulnerabilities_found': self._vulnerabilities_found,
            'success_rate': (
                self._vulnerabilities_found / self._total_tests
                if self._total_tests > 0 else 0.0
            ),
            'available_sources': self.wordlist_loader.get_available_sources(),
            'learned_patterns': len(self.taxonomy.pattern_learner.learned_patterns)
        }


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print("""
    Intelligent Payload Manager v4.0

    Features:
    - Automatic vulnerability inference from parameter context
    - Smart wordlist selection (PayloadsAllTheThings, FuzzDB, SecLists)
    - Integration with all analyzers
    - Bayesian result validation
    - Adaptive learning

    Flow:
    1. Analyze parameter → infer vulnerabilities
    2. Load appropriate payloads from wordlists
    3. Test payloads
    4. Validate results with analyzers
    5. Classify with CWE/OWASP taxonomy
    6. Learn for future tests
    """)

    # Quick self-test
    print("\n[*] Running self-test...")

    manager = PayloadManager()

    # Test vulnerability inference
    print("\n[Test 1] Vulnerability Inference:")
    inferences = manager.inferencer.infer_vulnerabilities(
        parameter_name="id",
        parameter_value="123",
        context=ParameterContext.QUERY_PARAM
    )
    for inf in inferences[:5]:
        print(f"  - {inf.vuln_type}: {inf.confidence:.0%} ({inf.reason})")

    # Test inference for file parameter
    print("\n[Test 2] File Parameter Inference:")
    inferences2 = manager.inferencer.infer_vulnerabilities(
        parameter_name="file",
        parameter_value="report.pdf"
    )
    for inf in inferences2[:5]:
        print(f"  - {inf.vuln_type}: {inf.confidence:.0%} ({inf.reason})")

    # Test inference for URL parameter
    print("\n[Test 3] URL Parameter Inference:")
    inferences3 = manager.inferencer.infer_vulnerabilities(
        parameter_name="redirect",
        parameter_value="https://example.com"
    )
    for inf in inferences3[:5]:
        print(f"  - {inf.vuln_type}: {inf.confidence:.0%} ({inf.reason})")

    # Test payload loading
    print("\n[Test 4] Wordlist Loading:")
    print(f"  Available sources: {manager.wordlist_loader.get_available_sources()}")

    for vuln_type in ['sqli', 'xss', 'lfi']:
        count = manager.wordlist_loader.get_payload_count(vuln_type)
        print(f"  {vuln_type}: {count} payloads available")

    # Test payload validation
    print("\n[Test 5] Payload Validation:")
    result = manager.test_payload(
        vuln_type='sqli',
        payload="' OR 1=1-- -",
        response_text="You have an error in your SQL syntax near 'test'",
        status_code=500
    )
    print(f"  Vulnerable: {result.is_vulnerable}")
    print(f"  Confidence: {result.confidence:.2%}")
    print(f"  Technique: {result.technique}")

    print("\n[+] Self-test completed!")
    print(f"\nStatistics: {manager.get_statistics()}")
