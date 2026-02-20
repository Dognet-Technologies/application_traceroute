#!/usr/bin/env python3
"""
Self-Learning Taxonomy v4.0
Dynamic vulnerability classification with adaptive learning

This module provides intelligent vulnerability classification using:
- Hierarchical taxonomy (CWE/OWASP mapping)
- Pattern learning from confirmed vulnerabilities
- Automatic pattern refinement
- Severity scoring with context awareness
- Attack chain correlation

Author: Security Testing Suite
License: Authorized security research only
"""

import re
import json
import math
import hashlib
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from datetime import datetime


# =============================================================================
# ENUMS AND DATA CLASSES
# =============================================================================

class TaxonomyCategory(Enum):
    """Top-level vulnerability categories"""
    INJECTION = "injection"
    BROKEN_AUTH = "broken_authentication"
    SENSITIVE_DATA = "sensitive_data_exposure"
    XXE = "xxe"
    BROKEN_ACCESS = "broken_access_control"
    MISCONFIG = "security_misconfiguration"
    XSS = "xss"
    INSECURE_DESER = "insecure_deserialization"
    VULN_COMPONENTS = "vulnerable_components"
    LOGGING = "insufficient_logging"
    SSRF = "ssrf"
    BUSINESS_LOGIC = "business_logic"


class SeverityLevel(Enum):
    """CVSS-aligned severity levels"""
    CRITICAL = (9.0, 10.0)
    HIGH = (7.0, 8.9)
    MEDIUM = (4.0, 6.9)
    LOW = (0.1, 3.9)
    INFO = (0.0, 0.0)


@dataclass
class VulnerabilityTaxon:
    """Individual vulnerability classification"""
    vuln_id: str
    name: str
    category: TaxonomyCategory
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss_base: float = 5.0
    description: str = ""
    patterns: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    related_vulns: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'vuln_id': self.vuln_id,
            'name': self.name,
            'category': self.category.value,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'cvss_base': self.cvss_base,
            'description': self.description,
            'patterns': self.patterns,
            'mitigations': self.mitigations,
            'related_vulns': self.related_vulns,
            'attack_vectors': self.attack_vectors
        }


@dataclass
class LearnedPattern:
    """Pattern learned from confirmed vulnerabilities"""
    pattern_id: str
    pattern_regex: str
    vuln_type: str
    confidence: float
    occurrences: int = 1
    last_seen: str = ""
    false_positive_rate: float = 0.0
    contexts: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'pattern_id': self.pattern_id,
            'pattern_regex': self.pattern_regex,
            'vuln_type': self.vuln_type,
            'confidence': self.confidence,
            'occurrences': self.occurrences,
            'last_seen': self.last_seen,
            'false_positive_rate': self.false_positive_rate,
            'contexts': self.contexts
        }


@dataclass
class ClassificationResult:
    """Result of vulnerability classification"""
    primary_category: str
    subcategory: str
    cwe_ids: List[str]
    owasp_categories: List[str]
    severity: str
    cvss_score: float
    confidence: float
    related_vulnerabilities: List[str]
    attack_chain_potential: List[str]
    remediation_priority: int

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'primary_category': self.primary_category,
            'subcategory': self.subcategory,
            'cwe_ids': self.cwe_ids,
            'owasp_categories': self.owasp_categories,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'confidence': self.confidence,
            'related_vulnerabilities': self.related_vulnerabilities,
            'attack_chain_potential': self.attack_chain_potential,
            'remediation_priority': self.remediation_priority
        }


# =============================================================================
# TAXONOMY DATABASE
# =============================================================================

class TaxonomyDatabase:
    """
    Pre-built taxonomy database with CWE/OWASP mappings.

    Contains comprehensive vulnerability definitions with:
    - CWE (Common Weakness Enumeration) IDs
    - OWASP Top 10 categories
    - CVSS base scores
    - Detection patterns
    - Remediation guidance
    """

    # Core vulnerability definitions
    VULNERABILITY_DEFINITIONS: Dict[str, VulnerabilityTaxon] = {}

    # CWE to vulnerability type mapping
    CWE_MAPPING = {
        # Injection
        'CWE-89': ('sqli', 'SQL Injection'),
        'CWE-564': ('sqli_hibernate', 'Hibernate Injection'),
        'CWE-943': ('nosql_injection', 'NoSQL Injection'),

        # XSS
        'CWE-79': ('xss', 'Cross-Site Scripting'),
        'CWE-80': ('xss_basic', 'Basic XSS'),
        'CWE-83': ('xss_attribute', 'XSS in Attribute'),
        'CWE-87': ('xss_alternate', 'Alternate XSS Syntax'),

        # Path Traversal / LFI
        'CWE-22': ('path_traversal', 'Path Traversal'),
        'CWE-23': ('relative_path', 'Relative Path Traversal'),
        'CWE-36': ('absolute_path', 'Absolute Path Traversal'),
        'CWE-98': ('lfi', 'Local File Inclusion'),
        'CWE-99': ('rfi', 'Remote File Inclusion'),

        # Command Injection / RCE
        'CWE-78': ('os_command', 'OS Command Injection'),
        'CWE-77': ('command_injection', 'Command Injection'),
        'CWE-94': ('code_injection', 'Code Injection'),
        'CWE-95': ('eval_injection', 'Eval Injection'),

        # XXE
        'CWE-611': ('xxe', 'XML External Entity'),
        'CWE-776': ('xxe_recursive', 'Recursive XXE'),

        # SSRF
        'CWE-918': ('ssrf', 'Server-Side Request Forgery'),

        # Authentication
        'CWE-287': ('auth_bypass', 'Authentication Bypass'),
        'CWE-288': ('auth_alternate', 'Alternate Path Auth Bypass'),
        'CWE-290': ('auth_spoofing', 'Authentication Spoofing'),
        'CWE-306': ('missing_auth', 'Missing Authentication'),
        'CWE-307': ('brute_force', 'Brute Force'),

        # Authorization
        'CWE-285': ('improper_authz', 'Improper Authorization'),
        'CWE-639': ('idor', 'Insecure Direct Object Reference'),
        'CWE-863': ('incorrect_authz', 'Incorrect Authorization'),

        # Session
        'CWE-384': ('session_fixation', 'Session Fixation'),
        'CWE-613': ('session_expiration', 'Session Expiration'),
        'CWE-614': ('session_https', 'Session Not Over HTTPS'),

        # Information Disclosure
        'CWE-200': ('info_disclosure', 'Information Exposure'),
        'CWE-209': ('error_info', 'Error Information Disclosure'),
        'CWE-215': ('debug_info', 'Debug Information Disclosure'),
        'CWE-497': ('system_info', 'System Information Disclosure'),

        # CSRF
        'CWE-352': ('csrf', 'Cross-Site Request Forgery'),

        # Open Redirect
        'CWE-601': ('open_redirect', 'Open Redirect'),

        # Deserialization
        'CWE-502': ('insecure_deser', 'Insecure Deserialization'),

        # SSTI
        'CWE-1336': ('ssti', 'Server-Side Template Injection'),
    }

    # OWASP Top 10 2021 mapping
    OWASP_MAPPING = {
        'A01:2021': ['broken_access_control', 'idor', 'path_traversal', 'auth_bypass'],
        'A02:2021': ['weak_crypto', 'sensitive_data', 'cleartext'],
        'A03:2021': ['sqli', 'xss', 'command_injection', 'xxe', 'lfi', 'ssti'],
        'A04:2021': ['insecure_design', 'business_logic'],
        'A05:2021': ['misconfig', 'default_creds', 'verbose_errors'],
        'A06:2021': ['vuln_components', 'outdated_lib'],
        'A07:2021': ['auth_failure', 'session_mgmt', 'brute_force'],
        'A08:2021': ['insecure_deser', 'ssrf'],
        'A09:2021': ['logging_failure', 'monitoring'],
        'A10:2021': ['ssrf'],
    }

    # Severity scores by vulnerability type
    SEVERITY_SCORES = {
        'sqli': 9.8,
        'rce': 10.0,
        'command_injection': 9.8,
        'code_injection': 9.5,
        'xxe': 8.5,
        'ssrf': 8.0,
        'lfi': 8.0,
        'rfi': 9.0,
        'path_traversal': 7.5,
        'insecure_deser': 9.0,
        'auth_bypass': 9.0,
        'idor': 7.0,
        'xss': 6.5,
        'csrf': 6.0,
        'open_redirect': 5.0,
        'info_disclosure': 5.0,
        'session_fixation': 6.5,
        'ssti': 9.0,
    }

    @classmethod
    def initialize(cls):
        """Initialize the taxonomy database"""
        # Build vulnerability definitions from CWE mapping
        for cwe_id, (vuln_type, vuln_name) in cls.CWE_MAPPING.items():
            category = cls._determine_category(vuln_type)
            cvss = cls.SEVERITY_SCORES.get(vuln_type, 5.0)
            owasp = cls._find_owasp_category(vuln_type)

            cls.VULNERABILITY_DEFINITIONS[vuln_type] = VulnerabilityTaxon(
                vuln_id=vuln_type,
                name=vuln_name,
                category=category,
                cwe_id=cwe_id,
                owasp_category=owasp,
                cvss_base=cvss,
                description=f"{vuln_name} vulnerability",
                patterns=[],
                mitigations=cls._get_mitigations(vuln_type),
                related_vulns=cls._get_related(vuln_type),
                attack_vectors=cls._get_attack_vectors(vuln_type)
            )

    @classmethod
    def _determine_category(cls, vuln_type: str) -> TaxonomyCategory:
        """Determine category from vulnerability type"""
        injection_types = ['sqli', 'nosql', 'command', 'code', 'eval', 'lfi', 'rfi', 'ssti']
        if any(t in vuln_type for t in injection_types):
            return TaxonomyCategory.INJECTION

        if 'xss' in vuln_type:
            return TaxonomyCategory.XSS
        if 'xxe' in vuln_type:
            return TaxonomyCategory.XXE
        if 'ssrf' in vuln_type:
            return TaxonomyCategory.SSRF
        if 'auth' in vuln_type or 'session' in vuln_type:
            return TaxonomyCategory.BROKEN_AUTH
        if 'idor' in vuln_type or 'authz' in vuln_type or 'path' in vuln_type:
            return TaxonomyCategory.BROKEN_ACCESS
        if 'deser' in vuln_type:
            return TaxonomyCategory.INSECURE_DESER
        if 'info' in vuln_type or 'disclosure' in vuln_type:
            return TaxonomyCategory.SENSITIVE_DATA

        return TaxonomyCategory.MISCONFIG

    @classmethod
    def _find_owasp_category(cls, vuln_type: str) -> Optional[str]:
        """Find OWASP category for vulnerability type"""
        for owasp_id, vuln_types in cls.OWASP_MAPPING.items():
            if vuln_type in vuln_types or any(vuln_type.startswith(vt) for vt in vuln_types):
                return owasp_id
        return None

    @classmethod
    def _get_mitigations(cls, vuln_type: str) -> List[str]:
        """Get remediation guidance"""
        mitigations = {
            'sqli': [
                'Use parameterized queries/prepared statements',
                'Implement input validation with whitelist',
                'Apply principle of least privilege to database accounts',
                'Use stored procedures where appropriate'
            ],
            'xss': [
                'Implement context-aware output encoding',
                'Use Content-Security-Policy headers',
                'Enable HttpOnly and Secure cookie flags',
                'Validate and sanitize input on server-side'
            ],
            'lfi': [
                'Validate and sanitize file paths',
                'Use whitelist for allowed files',
                'Implement chroot or jail environments',
                'Disable dangerous PHP functions'
            ],
            'rce': [
                'Avoid system calls with user input',
                'Use safe APIs instead of shell commands',
                'Implement strict input validation',
                'Run application with minimal privileges'
            ],
            'ssrf': [
                'Whitelist allowed URLs/IP ranges',
                'Block internal network access',
                'Disable unnecessary URL schemes',
                'Use network-level controls'
            ],
            'xxe': [
                'Disable external entity processing',
                'Use JSON instead of XML where possible',
                'Update XML parsers to latest versions',
                'Implement input validation for XML'
            ],
        }

        # Find matching mitigations
        for key, value in mitigations.items():
            if key in vuln_type:
                return value

        return ['Implement input validation', 'Apply security best practices']

    @classmethod
    def _get_related(cls, vuln_type: str) -> List[str]:
        """Get related vulnerability types"""
        relations = {
            'sqli': ['nosql_injection', 'hibernate_injection'],
            'xss': ['xss_stored', 'xss_dom', 'html_injection'],
            'lfi': ['rfi', 'path_traversal'],
            'rce': ['command_injection', 'code_injection'],
            'ssrf': ['xxe', 'rfi'],
            'auth_bypass': ['idor', 'session_fixation'],
        }

        for key, value in relations.items():
            if key in vuln_type:
                return value

        return []

    @classmethod
    def _get_attack_vectors(cls, vuln_type: str) -> List[str]:
        """Get common attack vectors"""
        vectors = {
            'sqli': ['GET parameters', 'POST body', 'HTTP headers', 'Cookies'],
            'xss': ['URL parameters', 'Form inputs', 'HTTP headers', 'File uploads'],
            'lfi': ['File parameters', 'Include parameters', 'Template paths'],
            'ssrf': ['URL parameters', 'Webhook URLs', 'File fetching'],
            'xxe': ['XML body', 'File uploads', 'SOAP requests'],
        }

        for key, value in vectors.items():
            if key in vuln_type:
                return value

        return ['HTTP parameters', 'Request body']


# Initialize database on module load
TaxonomyDatabase.initialize()


# =============================================================================
# PATTERN LEARNER
# =============================================================================

class PatternLearner:
    """
    Learns patterns from confirmed vulnerabilities.

    Features:
    - Pattern extraction from successful exploits
    - Confidence scoring based on occurrence frequency
    - False positive rate tracking
    - Pattern refinement over time
    """

    def __init__(self):
        """Initialize pattern learner"""
        self.learned_patterns: Dict[str, LearnedPattern] = {}
        self.pattern_stats: Dict[str, Dict] = defaultdict(lambda: {
            'true_positives': 0,
            'false_positives': 0,
            'total_matches': 0
        })

    def learn_from_vulnerability(
        self,
        vuln_type: str,
        payload: str,
        response_content: str,
        is_confirmed: bool = True
    ) -> Optional[LearnedPattern]:
        """
        Learn pattern from confirmed vulnerability

        Args:
            vuln_type: Type of vulnerability
            payload: Successful payload
            response_content: Response that confirmed vulnerability
            is_confirmed: Whether vulnerability is confirmed

        Returns:
            LearnedPattern if new pattern learned
        """
        # Extract pattern from payload
        pattern = self._extract_pattern(payload, vuln_type)

        if not pattern:
            return None

        pattern_id = hashlib.md5(pattern.encode()).hexdigest()[:12]

        if pattern_id in self.learned_patterns:
            # Update existing pattern
            existing = self.learned_patterns[pattern_id]
            existing.occurrences += 1
            existing.last_seen = datetime.now().isoformat()

            # Update confidence based on confirmation
            if is_confirmed:
                existing.confidence = min(1.0, existing.confidence + 0.05)
                self.pattern_stats[pattern_id]['true_positives'] += 1
            else:
                existing.confidence = max(0.1, existing.confidence - 0.1)
                self.pattern_stats[pattern_id]['false_positives'] += 1

            # Update false positive rate
            stats = self.pattern_stats[pattern_id]
            total = stats['true_positives'] + stats['false_positives']
            if total > 0:
                existing.false_positive_rate = stats['false_positives'] / total

            return existing
        else:
            # Create new pattern
            new_pattern = LearnedPattern(
                pattern_id=pattern_id,
                pattern_regex=pattern,
                vuln_type=vuln_type,
                confidence=0.7 if is_confirmed else 0.3,
                occurrences=1,
                last_seen=datetime.now().isoformat(),
                false_positive_rate=0.0 if is_confirmed else 0.5,
                contexts=[self._extract_context(response_content)]
            )

            self.learned_patterns[pattern_id] = new_pattern
            self.pattern_stats[pattern_id]['true_positives' if is_confirmed else 'false_positives'] = 1

            return new_pattern

    def _extract_pattern(self, payload: str, vuln_type: str) -> Optional[str]:
        """Extract regex pattern from payload"""
        # Escape special characters but preserve structure
        escaped = re.escape(payload)

        # Replace common variable parts with regex groups
        pattern = escaped

        # Replace numbers with digit patterns
        pattern = re.sub(r'\\d+', r'\\d+', pattern)

        # Replace quoted strings with flexible patterns
        pattern = re.sub(r"'[^']*'", r"'[^']*'", pattern)
        pattern = re.sub(r'"[^"]*"', r'"[^"]*"', pattern)

        # Vulnerability-specific patterns
        if vuln_type in ['sqli', 'nosql']:
            # Make SQL keywords case-insensitive
            for keyword in ['SELECT', 'UNION', 'WHERE', 'AND', 'OR', 'FROM']:
                pattern = re.sub(
                    re.escape(keyword),
                    f'(?i){keyword}',
                    pattern,
                    flags=re.IGNORECASE
                )

        return pattern if len(pattern) > 5 else None

    def _extract_context(self, response: str) -> str:
        """Extract context from response"""
        if len(response) > 200:
            return response[:200] + "..."
        return response

    def get_patterns_for_type(self, vuln_type: str) -> List[LearnedPattern]:
        """Get all learned patterns for a vulnerability type"""
        return [
            p for p in self.learned_patterns.values()
            if p.vuln_type == vuln_type and p.confidence > 0.5
        ]

    def get_high_confidence_patterns(self, min_confidence: float = 0.8) -> List[LearnedPattern]:
        """Get patterns with high confidence"""
        return [
            p for p in self.learned_patterns.values()
            if p.confidence >= min_confidence
        ]

    def export_patterns(self) -> Dict:
        """Export learned patterns"""
        return {
            'patterns': [p.to_dict() for p in self.learned_patterns.values()],
            'stats': dict(self.pattern_stats)
        }

    def import_patterns(self, data: Dict):
        """Import patterns from exported data"""
        for p_data in data.get('patterns', []):
            pattern = LearnedPattern(
                pattern_id=p_data['pattern_id'],
                pattern_regex=p_data['pattern_regex'],
                vuln_type=p_data['vuln_type'],
                confidence=p_data['confidence'],
                occurrences=p_data.get('occurrences', 1),
                last_seen=p_data.get('last_seen', ''),
                false_positive_rate=p_data.get('false_positive_rate', 0.0),
                contexts=p_data.get('contexts', [])
            )
            self.learned_patterns[pattern.pattern_id] = pattern

        for pattern_id, stats in data.get('stats', {}).items():
            self.pattern_stats[pattern_id].update(stats)


# =============================================================================
# ATTACK CHAIN ANALYZER
# =============================================================================

class AttackChainAnalyzer:
    """
    Analyzes potential attack chains from discovered vulnerabilities.

    Identifies how vulnerabilities can be chained together for
    more impactful attacks.
    """

    # Attack chain definitions
    CHAIN_DEFINITIONS = {
        'ssrf_to_rce': {
            'steps': ['ssrf', 'internal_service', 'rce'],
            'description': 'SSRF to access internal service leading to RCE',
            'severity_multiplier': 1.5
        },
        'sqli_to_rce': {
            'steps': ['sqli', 'file_write', 'rce'],
            'description': 'SQLi with file write privileges leading to RCE',
            'severity_multiplier': 1.3
        },
        'lfi_to_rce': {
            'steps': ['lfi', 'log_poisoning', 'rce'],
            'description': 'LFI with log poisoning leading to RCE',
            'severity_multiplier': 1.4
        },
        'xss_to_account_takeover': {
            'steps': ['xss', 'session_hijack', 'account_takeover'],
            'description': 'XSS leading to session hijacking and account takeover',
            'severity_multiplier': 1.3
        },
        'idor_to_data_breach': {
            'steps': ['idor', 'mass_enumeration', 'data_breach'],
            'description': 'IDOR allowing mass data enumeration',
            'severity_multiplier': 1.4
        },
        'auth_bypass_to_admin': {
            'steps': ['auth_bypass', 'privilege_escalation', 'admin_access'],
            'description': 'Authentication bypass leading to admin access',
            'severity_multiplier': 1.5
        },
        'xxe_to_ssrf': {
            'steps': ['xxe', 'ssrf', 'internal_scan'],
            'description': 'XXE used for SSRF to scan internal network',
            'severity_multiplier': 1.2
        },
    }

    def __init__(self):
        """Initialize attack chain analyzer"""
        self.discovered_vulns: List[str] = []

    def add_vulnerability(self, vuln_type: str):
        """Add discovered vulnerability"""
        if vuln_type not in self.discovered_vulns:
            self.discovered_vulns.append(vuln_type)

    def analyze_chains(self) -> List[Dict]:
        """
        Analyze potential attack chains

        Returns:
            List of potential attack chains
        """
        potential_chains = []

        for chain_name, chain_def in self.CHAIN_DEFINITIONS.items():
            # Check if first step vulnerability exists
            first_step = chain_def['steps'][0]

            for vuln in self.discovered_vulns:
                if first_step in vuln or vuln in first_step:
                    potential_chains.append({
                        'chain_name': chain_name,
                        'description': chain_def['description'],
                        'starting_vulnerability': vuln,
                        'steps': chain_def['steps'],
                        'severity_multiplier': chain_def['severity_multiplier'],
                        'exploitability': self._calculate_exploitability(chain_def['steps'])
                    })
                    break

        return potential_chains

    def _calculate_exploitability(self, steps: List[str]) -> str:
        """Calculate chain exploitability"""
        # More steps = harder to exploit
        if len(steps) <= 2:
            return 'HIGH'
        elif len(steps) == 3:
            return 'MEDIUM'
        else:
            return 'LOW'

    def get_chain_recommendations(self) -> List[str]:
        """Get recommendations based on potential chains"""
        chains = self.analyze_chains()
        recommendations = []

        for chain in chains:
            rec = f"PRIORITY: Address {chain['starting_vulnerability']} to prevent {chain['chain_name']} attack chain"
            recommendations.append(rec)

        return recommendations


# =============================================================================
# SELF-LEARNING TAXONOMY (MAIN)
# =============================================================================

class SelfLearningTaxonomy:
    """
    Main taxonomy class with self-learning capabilities.

    Features:
    - Vulnerability classification with CWE/OWASP mapping
    - Pattern learning from confirmed vulnerabilities
    - Attack chain analysis
    - Severity scoring with context awareness
    """

    def __init__(self):
        """Initialize Self-Learning Taxonomy"""
        self.database = TaxonomyDatabase
        self.pattern_learner = PatternLearner()
        self.chain_analyzer = AttackChainAnalyzer()

        # Statistics
        self._classification_count = 0
        self._learning_count = 0

    def classify(
        self,
        vuln_type: str,
        evidence: Optional[List[Dict]] = None,
        context: Optional[Dict] = None
    ) -> ClassificationResult:
        """
        Classify a vulnerability with full taxonomy information

        Args:
            vuln_type: Vulnerability type string
            evidence: Evidence from detection
            context: Additional context (endpoint, technology, etc.)

        Returns:
            ClassificationResult with full classification
        """
        self._classification_count += 1

        # Normalize vuln_type
        vuln_type_lower = vuln_type.lower().replace('-', '_').replace(' ', '_')

        # Get base definition
        base_def = self.database.VULNERABILITY_DEFINITIONS.get(vuln_type_lower)

        if not base_def:
            # Try to find partial match
            for key, definition in self.database.VULNERABILITY_DEFINITIONS.items():
                if key in vuln_type_lower or vuln_type_lower in key:
                    base_def = definition
                    break

        # Build CWE list
        cwe_ids = []
        for cwe, (vtype, _) in self.database.CWE_MAPPING.items():
            if vtype == vuln_type_lower or vuln_type_lower in vtype:
                cwe_ids.append(cwe)

        # Build OWASP list
        owasp_cats = []
        for owasp_id, vtypes in self.database.OWASP_MAPPING.items():
            if vuln_type_lower in vtypes or any(vuln_type_lower in vt for vt in vtypes):
                owasp_cats.append(owasp_id)

        # Calculate severity
        cvss_score = self.database.SEVERITY_SCORES.get(vuln_type_lower, 5.0)

        # Adjust based on context
        if context:
            cvss_score = self._adjust_severity(cvss_score, context)

        severity = self._score_to_severity(cvss_score)

        # Calculate confidence
        confidence = self._calculate_confidence(evidence)

        # Get related vulnerabilities
        related = base_def.related_vulns if base_def else []

        # Analyze attack chains
        self.chain_analyzer.add_vulnerability(vuln_type_lower)
        chains = self.chain_analyzer.analyze_chains()
        chain_potential = [c['chain_name'] for c in chains]

        # Calculate remediation priority
        priority = self._calculate_priority(cvss_score, confidence, len(chain_potential))

        # Determine category
        if base_def:
            category = base_def.category.value
            subcategory = base_def.name
        else:
            category = self._infer_category(vuln_type_lower)
            subcategory = vuln_type

        return ClassificationResult(
            primary_category=category,
            subcategory=subcategory,
            cwe_ids=cwe_ids,
            owasp_categories=owasp_cats,
            severity=severity,
            cvss_score=cvss_score,
            confidence=confidence,
            related_vulnerabilities=related,
            attack_chain_potential=chain_potential,
            remediation_priority=priority
        )

    def learn(
        self,
        vuln_type: str,
        payload: str,
        response: str,
        is_confirmed: bool = True
    ) -> Optional[LearnedPattern]:
        """
        Learn from a vulnerability finding

        Args:
            vuln_type: Type of vulnerability
            payload: Payload used
            response: Response content
            is_confirmed: Whether confirmed as true positive

        Returns:
            LearnedPattern if pattern was learned
        """
        self._learning_count += 1

        return self.pattern_learner.learn_from_vulnerability(
            vuln_type=vuln_type,
            payload=payload,
            response_content=response,
            is_confirmed=is_confirmed
        )

    def get_patterns(self, vuln_type: str) -> List[LearnedPattern]:
        """Get learned patterns for vulnerability type"""
        return self.pattern_learner.get_patterns_for_type(vuln_type)

    def get_remediation(self, vuln_type: str) -> List[str]:
        """Get remediation guidance for vulnerability type"""
        vuln_type_lower = vuln_type.lower().replace('-', '_')

        base_def = self.database.VULNERABILITY_DEFINITIONS.get(vuln_type_lower)

        if base_def:
            return base_def.mitigations

        # Try partial match
        for key, definition in self.database.VULNERABILITY_DEFINITIONS.items():
            if key in vuln_type_lower or vuln_type_lower in key:
                return definition.mitigations

        return ['Implement security best practices', 'Validate all user input']

    def get_cwe_info(self, cwe_id: str) -> Optional[Dict]:
        """Get information for a CWE ID"""
        if cwe_id in self.database.CWE_MAPPING:
            vuln_type, name = self.database.CWE_MAPPING[cwe_id]
            return {
                'cwe_id': cwe_id,
                'vulnerability_type': vuln_type,
                'name': name,
                'cvss_base': self.database.SEVERITY_SCORES.get(vuln_type, 5.0)
            }
        return None

    def _adjust_severity(self, base_score: float, context: Dict) -> float:
        """Adjust severity based on context"""
        score = base_score

        # Adjust for authentication state
        if context.get('requires_auth', False):
            score -= 0.5

        # Adjust for network exposure
        if context.get('internet_facing', True):
            score += 0.5

        # Adjust for data sensitivity
        sensitivity = context.get('data_sensitivity', 'medium')
        if sensitivity == 'high':
            score += 0.5
        elif sensitivity == 'low':
            score -= 0.5

        # Clamp to valid range
        return max(0.0, min(10.0, score))

    def _score_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity string"""
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        elif score >= 0.1:
            return 'LOW'
        return 'INFO'

    def _calculate_confidence(self, evidence: Optional[List[Dict]]) -> float:
        """Calculate classification confidence"""
        if not evidence:
            return 0.5

        # Average evidence strength
        strengths = [e.get('strength', 0.5) for e in evidence]
        return sum(strengths) / len(strengths) if strengths else 0.5

    def _calculate_priority(
        self,
        cvss: float,
        confidence: float,
        chain_count: int
    ) -> int:
        """
        Calculate remediation priority (1-5, 1 being highest)
        """
        # Base priority from CVSS
        if cvss >= 9.0:
            priority = 1
        elif cvss >= 7.0:
            priority = 2
        elif cvss >= 4.0:
            priority = 3
        else:
            priority = 4

        # Adjust for confidence
        if confidence < 0.5:
            priority += 1

        # Adjust for attack chains
        if chain_count > 0:
            priority = max(1, priority - 1)

        return min(5, priority)

    def _infer_category(self, vuln_type: str) -> str:
        """Infer category from vulnerability type string"""
        if 'inject' in vuln_type or 'sqli' in vuln_type:
            return 'injection'
        if 'xss' in vuln_type:
            return 'xss'
        if 'auth' in vuln_type:
            return 'broken_authentication'
        if 'access' in vuln_type or 'idor' in vuln_type:
            return 'broken_access_control'
        return 'security_misconfiguration'

    def export_state(self) -> Dict:
        """Export taxonomy state for persistence"""
        return {
            'patterns': self.pattern_learner.export_patterns(),
            'discovered_vulns': self.chain_analyzer.discovered_vulns,
            'stats': {
                'classifications': self._classification_count,
                'learnings': self._learning_count
            }
        }

    def import_state(self, state: Dict):
        """Import taxonomy state"""
        if 'patterns' in state:
            self.pattern_learner.import_patterns(state['patterns'])
        if 'discovered_vulns' in state:
            self.chain_analyzer.discovered_vulns = state['discovered_vulns']

    def get_statistics(self) -> Dict:
        """Get taxonomy statistics"""
        return {
            'classifications': self._classification_count,
            'learnings': self._learning_count,
            'patterns_learned': len(self.pattern_learner.learned_patterns),
            'vulns_discovered': len(self.chain_analyzer.discovered_vulns),
            'potential_chains': len(self.chain_analyzer.analyze_chains())
        }


# =============================================================================
# INTEGRATION EXAMPLE
# =============================================================================

def example_integration():
    """
    How to integrate in smart_vuln_crawler2.py

    USAGE:

        from extensions.taxonomy import SelfLearningTaxonomy

        taxonomy = SelfLearningTaxonomy()

        # When vulnerability is detected:
        classification = taxonomy.classify(
            vuln_type='sqli',
            evidence=[{'type': 'error', 'strength': 0.95}],
            context={'internet_facing': True, 'data_sensitivity': 'high'}
        )

        print(f"CWE: {classification.cwe_ids}")
        print(f"OWASP: {classification.owasp_categories}")
        print(f"Severity: {classification.severity}")
        print(f"Priority: {classification.remediation_priority}")

        # Learn from confirmed vulnerability:
        taxonomy.learn(
            vuln_type='sqli',
            payload="' OR 1=1-- -",
            response="MySQL syntax error",
            is_confirmed=True
        )

        # Get remediation:
        fixes = taxonomy.get_remediation('sqli')
        for fix in fixes:
            print(f"  - {fix}")
    """
    pass


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print("""
    SelfLearningTaxonomy v4.0 - Dynamic Vulnerability Classification

    Features:
    - CWE/OWASP mapping
    - Pattern learning
    - Attack chain analysis
    - Context-aware severity

    Classes:
    - SelfLearningTaxonomy: Main taxonomy
    - TaxonomyDatabase: Vulnerability definitions
    - PatternLearner: Learning engine
    - AttackChainAnalyzer: Chain detection
    """)

    # Quick self-test
    print("\n[*] Running self-test...")

    taxonomy = SelfLearningTaxonomy()

    # Test 1: SQLi Classification
    print("\n[Test 1] SQLi Classification:")
    result = taxonomy.classify(
        vuln_type='sqli',
        evidence=[{'type': 'error', 'strength': 0.95}],
        context={'internet_facing': True}
    )

    print(f"  Category: {result.primary_category}")
    print(f"  CWE IDs: {result.cwe_ids}")
    print(f"  OWASP: {result.owasp_categories}")
    print(f"  Severity: {result.severity} (CVSS: {result.cvss_score})")
    print(f"  Priority: {result.remediation_priority}")

    # Test 2: XSS Classification
    print("\n[Test 2] XSS Classification:")
    result2 = taxonomy.classify(vuln_type='xss')

    print(f"  Category: {result2.primary_category}")
    print(f"  CWE IDs: {result2.cwe_ids}")
    print(f"  Severity: {result2.severity}")

    # Test 3: Pattern Learning
    print("\n[Test 3] Pattern Learning:")
    pattern = taxonomy.learn(
        vuln_type='sqli',
        payload="' OR 1=1-- -",
        response="MySQL syntax error near ''",
        is_confirmed=True
    )

    if pattern:
        print(f"  Pattern ID: {pattern.pattern_id}")
        print(f"  Confidence: {pattern.confidence:.2f}")
        print(f"  Occurrences: {pattern.occurrences}")

    # Test 4: Attack Chain
    print("\n[Test 4] Attack Chain Analysis:")
    taxonomy.chain_analyzer.add_vulnerability('ssrf')
    chains = taxonomy.chain_analyzer.analyze_chains()

    for chain in chains:
        print(f"  Chain: {chain['chain_name']}")
        print(f"    Description: {chain['description']}")
        print(f"    Exploitability: {chain['exploitability']}")

    # Test 5: Remediation
    print("\n[Test 5] Remediation Guidance:")
    fixes = taxonomy.get_remediation('sqli')
    for fix in fixes[:3]:
        print(f"  - {fix}")

    print("\n[+] Self-test completed!")
    print(f"\nStatistics: {taxonomy.get_statistics()}")
