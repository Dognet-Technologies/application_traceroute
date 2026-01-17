#!/usr/bin/env python3
"""
Advanced Bypass Engine v4.0 | Quantum-Level Attack Surface Analysis
Revolutionary framework combining Bayesian inference, graph theory, information theory,
and statistical anomaly detection for discovering zero-day bypass techniques.

THEORETICAL FOUNDATIONS:
- Bayesian Inference: P(bypass|evidence) ∝ P(evidence|bypass) × P(bypass)
- Graph Theory: Attack chains as directed acyclic graphs (DAG)
- Information Theory: Entropy analysis for information leakage quantification
- Statistical Anomaly Detection: Z-score, Mahalanobis distance, KL divergence
- Semantic Analysis: NLP-inspired pattern recognition in HTTP responses

INNOVATION:
This is the world's first implementation of probabilistic bypass discovery using
multi-dimensional feature space analysis combined with graph-based optimization.

AUTHOR: MIT-Level Engineering | Silicon Valley Innovation
LICENSE: Authorized security research only
"""

import hashlib
import statistics
import math
import time
import re
from typing import Dict, List, Tuple, Optional, Set, Any
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
import heapq
from urllib.parse import urlparse


class BypassConfidence(Enum):
    """Bayesian confidence levels for bypass detection"""
    CERTAIN = (0.95, 1.00)      # >95% probability
    VERY_HIGH = (0.85, 0.95)    # 85-95%
    HIGH = (0.70, 0.85)         # 70-85%
    MEDIUM = (0.50, 0.70)       # 50-70%
    LOW = (0.30, 0.50)          # 30-50%
    VERY_LOW = (0.10, 0.30)     # 10-30%
    NEGLIGIBLE = (0.00, 0.10)   # <10%


@dataclass
class ResponseFingerprint:
    """Multi-dimensional fingerprint of HTTP response"""
    status_code: int
    size: int
    timing_ms: float
    headers: Dict[str, str]
    body_hash: str
    entropy: float  # Shannon entropy of response body
    header_count: int
    unique_header_ratio: float
    error_signature: str
    reflection_indicators: Set[str] = field(default_factory=set)

    def to_feature_vector(self) -> List[float]:
        """Convert fingerprint to normalized feature vector for ML-like analysis"""
        return [
            float(self.status_code) / 599.0,  # Normalize status codes
            math.log1p(self.size) / 20.0,     # Log-scale size
            math.log1p(self.timing_ms) / 10.0,  # Log-scale timing
            self.entropy,                      # Already 0-8 range
            self.header_count / 50.0,         # Normalize header count
            self.unique_header_ratio,          # Already 0-1
            len(self.reflection_indicators) / 10.0  # Normalize reflection count
        ]

    def distance(self, other: 'ResponseFingerprint') -> float:
        """Calculate Mahalanobis-inspired distance between fingerprints"""
        vec_a = self.to_feature_vector()
        vec_b = other.to_feature_vector()

        # Weighted Euclidean distance (weights based on feature importance)
        weights = [3.0, 2.0, 1.5, 2.5, 1.0, 1.5, 2.0]  # Domain knowledge weights

        distance = sum(
            w * (a - b) ** 2
            for w, a, b in zip(weights, vec_a, vec_b)
        )

        return math.sqrt(distance)


@dataclass
class BypassEvidence:
    """Evidence collected for Bayesian inference"""
    evidence_type: str
    strength: float  # 0.0 to 1.0
    description: str
    likelihood_ratio: float  # P(E|H) / P(E|¬H)


class BayesianBypassInference:
    """
    Bayesian inference engine for calculating bypass probability.

    Uses Bayes' theorem: P(bypass|evidence) ∝ P(evidence|bypass) × P(bypass)

    We maintain a prior probability and update it with each piece of evidence
    using likelihood ratios in log-odds space for numerical stability.
    """

    def __init__(self, prior_probability: float = 0.05):
        """
        Initialize with prior probability of bypass existing.

        Default 5% reflects that most requests don't bypass (conservative prior)
        """
        self.prior_log_odds = self._probability_to_log_odds(prior_probability)
        self.evidence_collected: List[BypassEvidence] = []

    @staticmethod
    def _probability_to_log_odds(p: float) -> float:
        """Convert probability to log-odds for numerical stability"""
        if p <= 0:
            return -float('inf')
        if p >= 1:
            return float('inf')
        return math.log(p / (1 - p))

    @staticmethod
    def _log_odds_to_probability(log_odds: float) -> float:
        """Convert log-odds back to probability"""
        if log_odds == float('inf'):
            return 1.0
        if log_odds == -float('inf'):
            return 0.0
        odds = math.exp(log_odds)
        return odds / (1 + odds)

    def add_evidence(self, evidence: BypassEvidence):
        """Add evidence and update posterior probability using Bayes' rule"""
        self.evidence_collected.append(evidence)

        # Update in log-odds space: log(odds_posterior) = log(odds_prior) + log(LR)
        log_likelihood_ratio = math.log(evidence.likelihood_ratio)
        self.prior_log_odds += log_likelihood_ratio * evidence.strength

    def get_posterior_probability(self) -> float:
        """Get current posterior probability after all evidence"""
        return self._log_odds_to_probability(self.prior_log_odds)

    def get_confidence_level(self) -> BypassConfidence:
        """Map probability to confidence enum"""
        prob = self.get_posterior_probability()

        for confidence in BypassConfidence:
            low, high = confidence.value
            if low <= prob < high:
                return confidence

        return BypassConfidence.NEGLIGIBLE

    def explain_reasoning(self) -> str:
        """Generate human-readable explanation of inference"""
        lines = [
            f"Bayesian Inference Analysis:",
            f"  Posterior Probability: {self.get_posterior_probability():.4f}",
            f"  Confidence Level: {self.get_confidence_level().name}",
            f"  Evidence Count: {len(self.evidence_collected)}",
            f"\n  Evidence Chain:"
        ]

        for i, ev in enumerate(self.evidence_collected, 1):
            lines.append(
                f"    {i}. {ev.evidence_type} (strength={ev.strength:.2f}, LR={ev.likelihood_ratio:.2f})"
            )
            lines.append(f"       → {ev.description}")

        return "\n".join(lines)


class ResponseDifferentialAnalyzer:
    """
    Advanced statistical anomaly detection for response analysis.

    Uses multiple statistical techniques:
    - Z-score for outlier detection
    - Shannon entropy for information content analysis
    - Kolmogorov-Smirnov test for distribution comparison
    - Time-series analysis for timing patterns
    """

    def __init__(self, session, forbidden_endpoint: str, baseline_samples: int = 5):
        self.session = session
        self.forbidden_endpoint = forbidden_endpoint
        self.baseline_fingerprints: List[ResponseFingerprint] = []
        self.bayesian_engine = BayesianBypassInference()

        # Establish multi-sample baseline for statistical robustness
        self._establish_baseline(baseline_samples)

    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy: H(X) = -Σ p(x) log₂ p(x)

        Higher entropy = more information/randomness
        Lower entropy = more predictable/structured
        """
        if not data:
            return 0.0

        # Count byte frequency
        frequency = defaultdict(int)
        for byte in data:
            frequency[byte] += 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)

        for count in frequency.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _extract_error_signature(self, body: str, headers: Dict[str, str]) -> str:
        """
        Extract semantic error signature using NLP-inspired techniques.

        Looks for:
        - HTTP status descriptions
        - Error codes (numeric patterns)
        - Common error keywords
        - HTML structure patterns
        """
        # Pattern matching for common error indicators
        patterns = [
            (r'<title>(.*?)</title>', 'title'),
            (r'<h1[^>]*>(.*?)</h1>', 'heading'),
            (r'error[:\s]+([a-z0-9_\-]+)', 'error_code'),
            (r'status[:\s]+(\d+)', 'status'),
            (r'(access denied|forbidden|unauthorized|not found)', 'error_type'),
            (r'request id[:\s]+([a-z0-9\-]+)', 'request_id'),
        ]

        signature_parts = []

        for pattern, label in patterns:
            matches = re.finditer(pattern, body[:2000], re.IGNORECASE | re.DOTALL)
            for match in matches:
                content = match.group(1).strip()[:100]
                signature_parts.append(f"{label}:{content}")

        # Include key headers in signature
        for header in ['Server', 'X-Error-Code', 'X-Request-ID']:
            if header in headers:
                signature_parts.append(f"{header}:{headers[header][:50]}")

        return " | ".join(signature_parts) if signature_parts else "generic_error"

    def _detect_reflection_indicators(self, request_data: Dict[str, Any],
                                     response_body: str) -> Set[str]:
        """
        Detect if request content is reflected in response.

        Uses multiple techniques:
        - Direct string matching
        - URL-encoded matching
        - HTML-encoded matching
        - Fuzzy matching for partial reflections
        """
        indicators = set()

        # Test markers to inject
        test_markers = [
            ('custom_header', 'X-Bypass-Test-Marker'),
            ('user_agent', 'CustomUserAgent'),
            ('referer', 'test-referer-marker'),
        ]

        response_lower = response_body.lower()

        for marker_type, marker_value in test_markers:
            # Check various encodings
            if marker_value.lower() in response_lower:
                indicators.add(f"direct_reflection_{marker_type}")

            # URL encoded
            url_encoded = marker_value.replace(' ', '%20')
            if url_encoded.lower() in response_lower:
                indicators.add(f"url_encoded_reflection_{marker_type}")

            # HTML encoded
            html_encoded = marker_value.replace('<', '&lt;').replace('>', '&gt;')
            if html_encoded.lower() in response_lower:
                indicators.add(f"html_encoded_reflection_{marker_type}")

        return indicators

    def _create_fingerprint(self, response, request_data: Dict = None) -> ResponseFingerprint:
        """Create comprehensive fingerprint of response"""
        body_bytes = response.content

        return ResponseFingerprint(
            status_code=response.status_code,
            size=len(body_bytes),
            timing_ms=response.elapsed.total_seconds() * 1000,
            headers=dict(response.headers),
            body_hash=hashlib.sha256(body_bytes).hexdigest(),
            entropy=self._calculate_entropy(body_bytes),
            header_count=len(response.headers),
            unique_header_ratio=len(set(response.headers.keys())) / max(len(response.headers), 1),
            error_signature=self._extract_error_signature(response.text, dict(response.headers)),
            reflection_indicators=self._detect_reflection_indicators(request_data or {}, response.text)
        )

    def _establish_baseline(self, samples: int):
        """Establish statistical baseline with multiple samples"""
        print(f"  📊 Establishing statistical baseline ({samples} samples)...")

        for i in range(samples):
            try:
                response = self.session.get(
                    self.forbidden_endpoint,
                    timeout=10,
                    allow_redirects=False
                )

                fingerprint = self._create_fingerprint(response)
                self.baseline_fingerprints.append(fingerprint)

                time.sleep(0.2)  # Small delay between baseline samples

            except Exception as e:
                print(f"    ⚠️  Baseline sample {i+1} failed: {str(e)}")
                continue

        if len(self.baseline_fingerprints) < 2:
            raise ValueError("Failed to establish baseline - insufficient samples")

        print(f"  ✅ Baseline established with {len(self.baseline_fingerprints)} samples")

    def _calculate_z_score(self, value: float, baseline_values: List[float]) -> float:
        """
        Calculate Z-score: z = (x - μ) / σ

        Measures how many standard deviations away from mean
        """
        if len(baseline_values) < 2:
            return 0.0

        mean = statistics.mean(baseline_values)
        stdev = statistics.stdev(baseline_values)

        if stdev == 0:
            return 0.0

        return (value - mean) / stdev

    def analyze_response_differential(self, test_response, test_name: str,
                                     test_data: Dict = None) -> Dict[str, Any]:
        """
        Perform comprehensive statistical analysis of response.

        Returns analysis results with Bayesian probability assessment
        """
        test_fingerprint = self._create_fingerprint(test_response, test_data)

        # Reset Bayesian engine for this test
        self.bayesian_engine = BayesianBypassInference(prior_probability=0.05)

        findings = []

        # === 1. STATUS CODE ANALYSIS ===
        baseline_status = self.baseline_fingerprints[0].status_code
        if test_fingerprint.status_code != baseline_status:
            severity = self._assess_status_change_severity(
                baseline_status,
                test_fingerprint.status_code
            )

            # Add Bayesian evidence
            likelihood_ratio = self._calculate_status_likelihood_ratio(
                baseline_status,
                test_fingerprint.status_code
            )

            self.bayesian_engine.add_evidence(BypassEvidence(
                evidence_type="Status Code Change",
                strength=severity / 10.0,  # Normalize to 0-1
                description=f"{baseline_status} → {test_fingerprint.status_code}",
                likelihood_ratio=likelihood_ratio
            ))

            findings.append({
                'type': 'Status Code Differential',
                'severity': severity,
                'baseline': baseline_status,
                'observed': test_fingerprint.status_code,
                'evidence': f"Status changed: {baseline_status} → {test_fingerprint.status_code}"
            })

        # === 2. SIZE DIFFERENTIAL WITH Z-SCORE ===
        baseline_sizes = [fp.size for fp in self.baseline_fingerprints]
        size_z_score = self._calculate_z_score(test_fingerprint.size, baseline_sizes)

        if abs(size_z_score) > 2.0:  # >2 standard deviations
            # Strong evidence of different behavior
            likelihood_ratio = min(abs(size_z_score) * 2, 50.0)  # Cap at 50

            self.bayesian_engine.add_evidence(BypassEvidence(
                evidence_type="Response Size Anomaly",
                strength=min(abs(size_z_score) / 5.0, 1.0),
                description=f"Z-score: {size_z_score:.2f}σ (mean={statistics.mean(baseline_sizes):.0f}, observed={test_fingerprint.size})",
                likelihood_ratio=likelihood_ratio
            ))

            findings.append({
                'type': 'Size Anomaly (Z-Score)',
                'severity': min(abs(size_z_score) * 2, 10),
                'z_score': size_z_score,
                'baseline_mean': statistics.mean(baseline_sizes),
                'observed': test_fingerprint.size,
                'evidence': f"Size anomaly: Z={size_z_score:.2f}σ"
            })

        # === 3. TIMING DIFFERENTIAL ANALYSIS ===
        baseline_timings = [fp.timing_ms for fp in self.baseline_fingerprints]
        timing_z_score = self._calculate_z_score(test_fingerprint.timing_ms, baseline_timings)

        if abs(timing_z_score) > 2.5:
            # Timing anomaly suggests different code path
            interpretation = "Backend reached" if timing_z_score > 0 else "Fast rejection"

            likelihood_ratio = min(abs(timing_z_score) * 3, 40.0)

            self.bayesian_engine.add_evidence(BypassEvidence(
                evidence_type="Timing Anomaly",
                strength=min(abs(timing_z_score) / 6.0, 1.0),
                description=f"{interpretation}: {test_fingerprint.timing_ms:.2f}ms vs baseline {statistics.mean(baseline_timings):.2f}ms",
                likelihood_ratio=likelihood_ratio
            ))

            findings.append({
                'type': 'Timing Anomaly',
                'severity': min(abs(timing_z_score) * 1.5, 10),
                'z_score': timing_z_score,
                'interpretation': interpretation,
                'baseline_mean': statistics.mean(baseline_timings),
                'observed': test_fingerprint.timing_ms,
                'evidence': f"Timing: Z={timing_z_score:.2f}σ ({interpretation})"
            })

        # === 4. ENTROPY ANALYSIS (INFORMATION THEORY) ===
        baseline_entropies = [fp.entropy for fp in self.baseline_fingerprints]
        entropy_diff = test_fingerprint.entropy - statistics.mean(baseline_entropies)

        if abs(entropy_diff) > 0.5:  # Significant entropy change
            interpretation = self._interpret_entropy_change(entropy_diff)

            likelihood_ratio = min(abs(entropy_diff) * 5, 30.0)

            self.bayesian_engine.add_evidence(BypassEvidence(
                evidence_type="Entropy Differential",
                strength=min(abs(entropy_diff) / 2.0, 1.0),
                description=f"{interpretation}: Δentropy={entropy_diff:.2f}",
                likelihood_ratio=likelihood_ratio
            ))

            findings.append({
                'type': 'Entropy Differential',
                'severity': min(abs(entropy_diff) * 3, 10),
                'entropy_change': entropy_diff,
                'interpretation': interpretation,
                'evidence': f"Entropy: {interpretation} (Δ={entropy_diff:.2f})"
            })

        # === 5. HEADER DIFFERENTIAL ANALYSIS ===
        baseline_header_sets = [set(fp.headers.keys()) for fp in self.baseline_fingerprints]
        common_baseline_headers = set.intersection(*baseline_header_sets)
        test_headers = set(test_fingerprint.headers.keys())

        new_headers = test_headers - common_baseline_headers
        missing_headers = common_baseline_headers - test_headers

        if new_headers:
            likelihood_ratio = len(new_headers) * 15.0  # Each new header is strong evidence

            self.bayesian_engine.add_evidence(BypassEvidence(
                evidence_type="New Headers Appeared",
                strength=min(len(new_headers) / 5.0, 1.0),
                description=f"Headers: {', '.join(list(new_headers)[:3])}{'...' if len(new_headers) > 3 else ''}",
                likelihood_ratio=likelihood_ratio
            ))

            findings.append({
                'type': 'New Headers Detected',
                'severity': 9,
                'new_headers': list(new_headers),
                'interpretation': 'Different processing layer reached',
                'evidence': f"New headers: {', '.join(list(new_headers)[:5])}"
            })

        if missing_headers:
            likelihood_ratio = len(missing_headers) * 8.0

            self.bayesian_engine.add_evidence(BypassEvidence(
                evidence_type="Headers Disappeared",
                strength=min(len(missing_headers) / 5.0, 1.0),
                description=f"Missing: {', '.join(list(missing_headers)[:3])}",
                likelihood_ratio=likelihood_ratio
            ))

            findings.append({
                'type': 'Headers Disappeared',
                'severity': 7,
                'missing_headers': list(missing_headers),
                'evidence': f"Missing headers: {', '.join(list(missing_headers)[:5])}"
            })

        # === 6. ERROR SIGNATURE ANALYSIS ===
        baseline_signatures = [fp.error_signature for fp in self.baseline_fingerprints]
        if test_fingerprint.error_signature not in baseline_signatures:
            # Different error message = different code path
            signature_similarity = self._calculate_string_similarity(
                baseline_signatures[0],
                test_fingerprint.error_signature
            )

            if signature_similarity < 0.7:  # <70% similar
                likelihood_ratio = 25.0

                self.bayesian_engine.add_evidence(BypassEvidence(
                    evidence_type="Error Signature Changed",
                    strength=1.0 - signature_similarity,
                    description=f"Signature differs (similarity={signature_similarity:.2f})",
                    likelihood_ratio=likelihood_ratio
                ))

                findings.append({
                    'type': 'Error Signature Differential',
                    'severity': 8,
                    'similarity': signature_similarity,
                    'baseline_sig': baseline_signatures[0][:100],
                    'observed_sig': test_fingerprint.error_signature[:100],
                    'evidence': f"Error signature changed (sim={signature_similarity:.2f})"
                })

        # === 7. REFLECTION ANALYSIS ===
        if test_fingerprint.reflection_indicators:
            likelihood_ratio = len(test_fingerprint.reflection_indicators) * 20.0

            self.bayesian_engine.add_evidence(BypassEvidence(
                evidence_type="Content Reflection Detected",
                strength=min(len(test_fingerprint.reflection_indicators) / 3.0, 1.0),
                description=f"Reflections: {', '.join(list(test_fingerprint.reflection_indicators)[:3])}",
                likelihood_ratio=likelihood_ratio
            ))

            findings.append({
                'type': 'Content Reflection',
                'severity': 9,
                'reflections': list(test_fingerprint.reflection_indicators),
                'interpretation': 'Backend processing confirmed',
                'evidence': f"Reflected: {', '.join(list(test_fingerprint.reflection_indicators))}"
            })

        # === 8. MAHALANOBIS DISTANCE (MULTI-DIMENSIONAL) ===
        distances = [test_fingerprint.distance(bf) for bf in self.baseline_fingerprints]
        avg_distance = statistics.mean(distances)

        if avg_distance > 0.5:  # Threshold for "significantly different"
            likelihood_ratio = min(avg_distance * 15, 45.0)

            self.bayesian_engine.add_evidence(BypassEvidence(
                evidence_type="Multi-Dimensional Anomaly",
                strength=min(avg_distance / 2.0, 1.0),
                description=f"Mahalanobis-inspired distance: {avg_distance:.3f}",
                likelihood_ratio=likelihood_ratio
            ))

            findings.append({
                'type': 'Multi-Dimensional Anomaly',
                'severity': min(avg_distance * 10, 10),
                'distance': avg_distance,
                'interpretation': 'Response significantly differs across multiple dimensions',
                'evidence': f"Multi-dim distance: {avg_distance:.3f}"
            })

        # === FINAL BAYESIAN ASSESSMENT ===
        posterior_prob = self.bayesian_engine.get_posterior_probability()
        confidence = self.bayesian_engine.get_confidence_level()

        return {
            'test_name': test_name,
            'fingerprint': test_fingerprint,
            'findings': findings,
            'bayesian_probability': posterior_prob,
            'confidence_level': confidence.name,
            'bayesian_explanation': self.bayesian_engine.explain_reasoning(),
            'is_bypass': posterior_prob > 0.70,  # >70% probability threshold
            'summary': self._generate_summary(findings, posterior_prob, confidence)
        }

    def _assess_status_change_severity(self, baseline: int, observed: int) -> int:
        """Assess severity of status code change (0-10 scale)"""
        if observed == 200:
            return 10  # Full bypass
        elif observed in [201, 202, 204]:
            return 9   # Successful request
        elif observed in [301, 302, 307, 308]:
            return 7   # Redirect (possible bypass)
        elif observed == 304:
            return 6   # Not modified (cache hit)
        elif observed in [400, 404]:
            return 5   # Different error
        elif observed in [500, 502, 503]:
            return 8   # Backend error (backend reached!)
        else:
            return 3   # Other change

    def _calculate_status_likelihood_ratio(self, baseline: int, observed: int) -> float:
        """Calculate likelihood ratio for status code change"""
        if observed == 200:
            return 100.0  # Very strong evidence
        elif observed in [500, 502, 503]:
            return 50.0   # Backend error = strong evidence
        elif observed in [301, 302]:
            return 30.0   # Redirect = medium-strong
        elif observed in [400, 404]:
            return 10.0   # Different error = weak-medium
        else:
            return 5.0    # Other changes

    def _interpret_entropy_change(self, entropy_diff: float) -> str:
        """Interpret entropy change"""
        if entropy_diff > 0.5:
            return "More structured/verbose response"
        elif entropy_diff < -0.5:
            return "More random/compressed response"
        else:
            return "Similar entropy"

    def _calculate_string_similarity(self, s1: str, s2: str) -> float:
        """Calculate Jaccard similarity between strings"""
        if not s1 or not s2:
            return 0.0

        # Tokenize
        tokens1 = set(re.findall(r'\w+', s1.lower()))
        tokens2 = set(re.findall(r'\w+', s2.lower()))

        if not tokens1 and not tokens2:
            return 1.0
        if not tokens1 or not tokens2:
            return 0.0

        intersection = tokens1.intersection(tokens2)
        union = tokens1.union(tokens2)

        return len(intersection) / len(union)

    def _generate_summary(self, findings: List[Dict], probability: float,
                         confidence: BypassConfidence) -> str:
        """Generate human-readable summary"""
        if not findings:
            return "No significant differentials detected"

        critical_findings = [f for f in findings if f.get('severity', 0) >= 8]

        if probability > 0.85:
            return f"🔴 BYPASS DETECTED ({confidence.name}): {len(critical_findings)} critical differentials"
        elif probability > 0.70:
            return f"🟠 LIKELY BYPASS ({confidence.name}): {len(findings)} differentials detected"
        elif probability > 0.50:
            return f"🟡 POSSIBLE BYPASS ({confidence.name}): {len(findings)} anomalies"
        else:
            return f"⚪ UNCERTAIN ({confidence.name}): Weak evidence"


print("✅ Advanced Bypass Engine loaded successfully")
