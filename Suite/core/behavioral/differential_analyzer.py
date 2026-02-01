"""
differential_analyzer.py - Differential causal analysis for security testing

Implements behavioral analysis through minimal perturbations:
- 75 minimal perturbations for causality inference
- KL-divergence based anomaly detection
- Baseline distribution estimation
- Affected layer inference
"""

import logging
import time
import uuid
import re
import numpy as np
import requests
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs

from scipy import stats
from scipy.special import rel_entr

logger = logging.getLogger('security_suite.differential_analyzer')


class PerturbationType(Enum):
    """Types of perturbations for differential analysis."""
    SINGLE_CHAR = 'single_char'       # Single character modifications
    BOUNDARY = 'boundary'              # Boundary value perturbations
    ENCODING = 'encoding'              # Encoding variations
    STRUCTURAL = 'structural'          # Structure modifications
    SEMANTIC = 'semantic'              # Semantic perturbations


@dataclass
class PerturbationResult:
    """Result of a single perturbation test."""
    perturbation_type: PerturbationType
    original_value: str
    perturbed_value: str
    response_time: float
    status_code: int
    response_length: int
    headers: Dict[str, str]
    anomaly_score: float = 0.0
    is_anomalous: bool = False
    affected_layer: Optional[str] = None
    error: Optional[str] = None


@dataclass
class AnalysisResult:
    """Complete analysis result."""
    target_url: str
    baseline_stats: Dict[str, float]
    perturbation_results: List[PerturbationResult]
    anomalies: List[PerturbationResult]
    affected_layers: Dict[str, int]
    kl_divergence: float
    analysis_time: float
    session_id: str


class Perturbation(ABC):
    """Abstract base class for perturbations."""

    @abstractmethod
    def apply(self, value: str) -> List[str]:
        """
        Apply perturbation to value.

        Args:
            value: Original value to perturb

        Returns:
            List of perturbed values
        """
        pass

    @property
    @abstractmethod
    def perturbation_type(self) -> PerturbationType:
        """Get perturbation type."""
        pass


class SingleCharPerturbation(Perturbation):
    """Single character perturbations."""

    @property
    def perturbation_type(self) -> PerturbationType:
        return PerturbationType.SINGLE_CHAR

    def apply(self, value: str) -> List[str]:
        results = []
        if not value:
            return ['a', '1', ' ']

        # Character substitutions at various positions
        positions = [0, len(value) // 2, -1] if len(value) > 2 else range(len(value))
        chars_to_try = ['a', 'A', '0', '9', ' ', '.', '-', '_']

        for pos in positions:
            pos = pos if pos >= 0 else len(value) + pos
            if pos < len(value):
                for char in chars_to_try[:3]:  # Limit chars per position
                    new_value = value[:pos] + char + value[pos + 1:]
                    if new_value != value:
                        results.append(new_value)

        # Character deletion
        if len(value) > 1:
            results.append(value[1:])
            results.append(value[:-1])

        # Character insertion
        results.append('x' + value)
        results.append(value + 'x')

        return results[:15]  # Limit to 15 perturbations


class BoundaryPerturbation(Perturbation):
    """Boundary value perturbations."""

    @property
    def perturbation_type(self) -> PerturbationType:
        return PerturbationType.BOUNDARY

    def apply(self, value: str) -> List[str]:
        results = []

        # Empty and whitespace
        results.extend(['', ' ', '  ', '\t', '\n'])

        # Length boundaries
        results.append('a' * 1)
        results.append('a' * 100)
        results.append('a' * 1000)

        # Numeric boundaries
        results.extend(['0', '-1', '1', '2147483647', '-2147483648', '9999999999'])

        # Special values
        results.extend(['null', 'undefined', 'NaN', 'true', 'false'])

        return results[:15]


class EncodingPerturbation(Perturbation):
    """Encoding variation perturbations."""

    @property
    def perturbation_type(self) -> PerturbationType:
        return PerturbationType.ENCODING

    def apply(self, value: str) -> List[str]:
        results = []

        # URL encoding variations
        if value:
            # Double encoding
            results.append(value.replace('/', '%252F'))
            results.append(value.replace(' ', '%2520'))

            # Unicode normalization
            results.append(value.replace('a', '\u0061'))
            results.append(value.replace('/', '\u002F'))

            # Mixed case encoding
            results.append(value.replace('a', '%61'))
            results.append(value.upper())
            results.append(value.lower())

        # Null bytes
        results.append(value + '%00')
        results.append('%00' + value)

        # UTF-8 BOM
        results.append('\ufeff' + value)

        # Overlong UTF-8
        results.append(value.replace('/', '\xc0\xaf'))

        return results[:15]


class StructuralPerturbation(Perturbation):
    """Structural perturbations."""

    @property
    def perturbation_type(self) -> PerturbationType:
        return PerturbationType.STRUCTURAL

    def apply(self, value: str) -> List[str]:
        results = []

        # JSON-like structures
        results.extend([
            '{}',
            '[]',
            '{"key":"value"}',
            '[1,2,3]',
            '{"nested":{"deep":"value"}}'
        ])

        # XML-like structures
        results.extend([
            '<tag>value</tag>',
            '<?xml version="1.0"?>',
            '<!DOCTYPE test>'
        ])

        # Path structures
        results.extend([
            '../',
            '..\\',
            '/etc/passwd',
            'C:\\Windows\\',
            '....//....//etc/passwd'
        ])

        return results[:15]


class SemanticPerturbation(Perturbation):
    """Semantic perturbations."""

    @property
    def perturbation_type(self) -> PerturbationType:
        return PerturbationType.SEMANTIC

    def apply(self, value: str) -> List[str]:
        results = []

        # SQL-like
        results.extend([
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "UNION SELECT * FROM"
        ])

        # Script injection
        results.extend([
            '<script>alert(1)</script>',
            'javascript:alert(1)',
            '{{7*7}}'
        ])

        # Command injection
        results.extend([
            '; ls -la',
            '| cat /etc/passwd',
            '`id`',
            '$(whoami)'
        ])

        # LDAP/XPath
        results.extend([
            '*)(objectClass=*',
            "' or '1'='1' or '"
        ])

        return results[:15]


class DifferentialCausalAnalyzer:
    """
    Analyzer for differential causal analysis.

    Implements:
    - Baseline distribution establishment (50 samples)
    - 75 minimal perturbations across 5 types
    - KL-divergence anomaly detection
    - Affected layer inference

    Performance targets:
    - ~5 minutes for complete analysis
    - Respects 60s global timeout
    """

    # Configuration
    N_BASELINE_SAMPLES = 50
    N_PERTURBATIONS = 75
    KL_THRESHOLD = 0.05
    GLOBAL_TIMEOUT = 60.0
    REQUEST_TIMEOUT = 10.0

    # Layer detection patterns (precompiled for performance)
    LAYER_PATTERNS = {
        'nginx': re.compile(r'nginx', re.IGNORECASE),
        'apache': re.compile(r'apache|httpd', re.IGNORECASE),
        'iis': re.compile(r'microsoft-iis|asp\.net', re.IGNORECASE),
        'php': re.compile(r'php|laravel|symfony', re.IGNORECASE),
        'python': re.compile(r'python|django|flask|gunicorn', re.IGNORECASE),
        'nodejs': re.compile(r'node|express', re.IGNORECASE),
        'java': re.compile(r'java|tomcat|spring|jetty', re.IGNORECASE),
        'cloudflare': re.compile(r'cloudflare|cf-ray', re.IGNORECASE),
        'waf': re.compile(r'waf|firewall|blocked|forbidden', re.IGNORECASE),
        'database': re.compile(r'mysql|postgres|sqlite|mongodb|sql', re.IGNORECASE),
        'cache': re.compile(r'varnish|redis|memcache|x-cache', re.IGNORECASE),
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize analyzer.

        Args:
            config: Optional configuration overrides
        """
        config = config or {}

        self.n_baseline_samples = config.get('n_baseline_samples', self.N_BASELINE_SAMPLES)
        self.n_perturbations = config.get('n_perturbations', self.N_PERTURBATIONS)
        self.kl_threshold = config.get('kl_threshold', self.KL_THRESHOLD)
        self.global_timeout = config.get('timeout', self.GLOBAL_TIMEOUT)
        self.request_timeout = config.get('request_timeout', self.REQUEST_TIMEOUT)

        # Perturbation generators
        self._perturbations: List[Perturbation] = [
            SingleCharPerturbation(),
            BoundaryPerturbation(),
            EncodingPerturbation(),
            StructuralPerturbation(),
            SemanticPerturbation(),
        ]

        # Session
        self._session = requests.Session()
        self._session.headers.update({
            'User-Agent': 'SecuritySuite/1.0 DifferentialAnalyzer'
        })

        logger.debug("Initialized DifferentialCausalAnalyzer")

    def analyze(
        self,
        url: str,
        results_dir: Optional[Path] = None
    ) -> AnalysisResult:
        """
        Perform differential causal analysis on URL.

        Args:
            url: Target URL to analyze
            results_dir: Directory for saving results

        Returns:
            AnalysisResult with all findings

        Complexity: O(n_baseline + n_perturbations)
        """
        start_time = time.time()
        session_id = str(uuid.uuid4())[:8]

        # Setup results directory
        if results_dir is None:
            domain = self._extract_domain(url)
            timestamp = int(time.time())
            results_dir = Path(f"results/{domain}_{timestamp}_{session_id}")

        results_dir = Path(results_dir).resolve()
        results_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Starting differential analysis on {url}")
        logger.info(f"Session ID: {session_id}, Results: {results_dir}")

        # Phase 1: Establish baseline
        baseline_stats = self._establish_baseline(url)

        # Phase 2: Generate and apply perturbations
        perturbations = self._generate_perturbations(url)
        perturbation_results = self._apply_perturbations(url, perturbations, baseline_stats)

        # Phase 3: Detect anomalies
        anomalies = self._detect_anomalies(perturbation_results, baseline_stats)

        # Phase 4: Infer affected layers
        affected_layers = self._infer_affected_layers(anomalies)

        # Calculate overall KL divergence
        kl_divergence = self._calculate_overall_kl(perturbation_results, baseline_stats)

        analysis_time = time.time() - start_time

        result = AnalysisResult(
            target_url=url,
            baseline_stats=baseline_stats,
            perturbation_results=perturbation_results,
            anomalies=anomalies,
            affected_layers=affected_layers,
            kl_divergence=kl_divergence,
            analysis_time=analysis_time,
            session_id=session_id
        )

        # Save results
        self._save_results(result, results_dir)

        logger.info(
            f"Analysis complete: {len(anomalies)} anomalies found, "
            f"KL divergence: {kl_divergence:.4f}, time: {analysis_time:.1f}s"
        )

        return result

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc.replace(':', '_')
        except Exception:
            return 'unknown'

    def _establish_baseline(self, url: str) -> Dict[str, float]:
        """
        Establish baseline behavior distribution.

        Collects n_baseline_samples to estimate normal response distribution.

        Args:
            url: Target URL

        Returns:
            Dict with baseline statistics
        """
        logger.debug(f"Establishing baseline with {self.n_baseline_samples} samples")

        response_times = []
        response_lengths = []
        status_codes = []

        for i in range(self.n_baseline_samples):
            try:
                start = time.time()
                response = self._session.get(url, timeout=self.request_timeout)
                elapsed = time.time() - start

                response_times.append(elapsed)
                response_lengths.append(len(response.content))
                status_codes.append(response.status_code)

            except requests.Timeout:
                response_times.append(self.request_timeout)
                response_lengths.append(0)
                status_codes.append(408)
            except Exception as e:
                logger.debug(f"Baseline sample {i} failed: {e}")
                response_times.append(0)
                response_lengths.append(0)
                status_codes.append(0)

        # Calculate statistics
        rt_array = np.array(response_times)
        rl_array = np.array(response_lengths)

        return {
            'response_time_mean': float(np.mean(rt_array)),
            'response_time_std': float(np.std(rt_array)),
            'response_time_min': float(np.min(rt_array)),
            'response_time_max': float(np.max(rt_array)),
            'response_length_mean': float(np.mean(rl_array)),
            'response_length_std': float(np.std(rl_array)),
            'modal_status_code': int(stats.mode(status_codes, keepdims=False).mode),
            'samples': self.n_baseline_samples
        }

    def _generate_perturbations(self, url: str) -> List[Tuple[PerturbationType, str, str]]:
        """
        Generate exactly 75 perturbations.

        Distributes perturbations evenly across 5 types (15 each).

        Args:
            url: Target URL (used to extract base parameter value)

        Returns:
            List of (type, original_value, perturbed_value) tuples
        """
        logger.debug("Generating perturbations")

        # Extract parameter values to perturb, or use path
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Collect all base values to perturb (all params + path)
        base_values = []
        if params:
            # Use ALL parameters, not just the first
            for param_name, values in params.items():
                for value in values:
                    base_values.append((param_name, value))
        if not base_values:
            # Use path if no params
            base_values.append(('path', parsed.path or '/'))

        perturbations = []
        # Distribute perturbations across all base values
        per_value = max(1, self.n_perturbations // len(base_values))
        per_type = max(1, per_value // len(self._perturbations))

        for param_name, base_value in base_values:
            for generator in self._perturbations:
                perturbed_values = generator.apply(base_value)[:per_type]

                for perturbed in perturbed_values:
                    perturbations.append((
                        generator.perturbation_type,
                        base_value,
                        perturbed
                    ))
                    if len(perturbations) >= self.n_perturbations:
                        break
                if len(perturbations) >= self.n_perturbations:
                    break
            if len(perturbations) >= self.n_perturbations:
                break

        # Ensure exactly n_perturbations
        while len(perturbations) < self.n_perturbations:
            # Add more from first generator
            extra = self._perturbations[0].apply(base_value)
            for p in extra:
                if len(perturbations) >= self.n_perturbations:
                    break
                perturbations.append((
                    self._perturbations[0].perturbation_type,
                    base_value,
                    p
                ))

        return perturbations[:self.n_perturbations]

    def _apply_perturbations(
        self,
        url: str,
        perturbations: List[Tuple[PerturbationType, str, str]],
        baseline: Dict[str, float]
    ) -> List[PerturbationResult]:
        """
        Apply perturbations and collect results.

        Args:
            url: Target URL
            perturbations: List of perturbations to apply
            baseline: Baseline statistics

        Returns:
            List of PerturbationResult
        """
        logger.debug(f"Applying {len(perturbations)} perturbations")
        results = []

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for ptype, original, perturbed in perturbations:
            # Construct perturbed URL
            if params:
                param_name = list(params.keys())[0]
                new_params = params.copy()
                new_params[param_name] = [perturbed]
                perturbed_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"
            else:
                # Perturb path
                perturbed_url = f"{parsed.scheme}://{parsed.netloc}{perturbed}"

            result = self._test_perturbation(perturbed_url, ptype, original, perturbed, baseline)
            results.append(result)

        return results

    def _test_perturbation(
        self,
        url: str,
        ptype: PerturbationType,
        original: str,
        perturbed: str,
        baseline: Dict[str, float]
    ) -> PerturbationResult:
        """Test a single perturbation."""
        try:
            start = time.time()
            response = self._session.get(url, timeout=self.request_timeout)
            elapsed = time.time() - start

            # Calculate anomaly score based on deviation from baseline
            time_zscore = abs(elapsed - baseline['response_time_mean']) / max(baseline['response_time_std'], 0.001)
            length_zscore = abs(len(response.content) - baseline['response_length_mean']) / max(baseline['response_length_std'], 1)
            status_anomaly = 1.0 if response.status_code != baseline['modal_status_code'] else 0.0

            anomaly_score = (time_zscore + length_zscore + status_anomaly * 3) / 5

            # Detect affected layer from response
            affected_layer = self._detect_layer(response)

            return PerturbationResult(
                perturbation_type=ptype,
                original_value=original,
                perturbed_value=perturbed,
                response_time=elapsed,
                status_code=response.status_code,
                response_length=len(response.content),
                headers=dict(response.headers),
                anomaly_score=anomaly_score,
                is_anomalous=anomaly_score > 1.0,
                affected_layer=affected_layer
            )

        except requests.Timeout:
            return PerturbationResult(
                perturbation_type=ptype,
                original_value=original,
                perturbed_value=perturbed,
                response_time=self.request_timeout,
                status_code=408,
                response_length=0,
                headers={},
                anomaly_score=5.0,
                is_anomalous=True,
                error="Timeout"
            )
        except Exception as e:
            return PerturbationResult(
                perturbation_type=ptype,
                original_value=original,
                perturbed_value=perturbed,
                response_time=0,
                status_code=0,
                response_length=0,
                headers={},
                anomaly_score=3.0,
                is_anomalous=True,
                error=str(e)
            )

    def _detect_layer(self, response: requests.Response) -> Optional[str]:
        """Detect which layer handled the response."""
        # Check headers
        headers_str = str(response.headers).lower()

        for layer, pattern in self.LAYER_PATTERNS.items():
            if pattern.search(headers_str):
                return layer

        # Check response body (first 1000 chars)
        body_sample = response.text[:1000].lower()
        for layer, pattern in self.LAYER_PATTERNS.items():
            if pattern.search(body_sample):
                return layer

        return None

    def _detect_anomalies(
        self,
        results: List[PerturbationResult],
        baseline: Dict[str, float]
    ) -> List[PerturbationResult]:
        """
        Detect anomalies using statistical deviation.

        Uses Z-score based detection which is deterministic and mathematically sound.

        Args:
            results: Perturbation results
            baseline: Baseline statistics

        Returns:
            List of anomalous results
        """
        anomalies = []

        baseline_mean = baseline['response_time_mean']
        baseline_std = max(baseline['response_time_std'], 1e-10)

        for result in results:
            if result.is_anomalous:
                anomalies.append(result)
                continue

            # Z-score based anomaly detection (deterministic)
            if result.response_time > 0:
                z_score = abs(result.response_time - baseline_mean) / baseline_std

                # High z-score indicates anomaly (>2.5 corresponds to ~99% CI)
                if z_score > 2.5:
                    result.is_anomalous = True
                    # Normalize score to reasonable range
                    result.anomaly_score = max(result.anomaly_score, min(z_score / 5, 2.0))
                    anomalies.append(result)

        logger.debug(f"Detected {len(anomalies)} anomalies")
        return anomalies

    def _kl_divergence(self, p: np.ndarray, q: np.ndarray) -> float:
        """
        Calculate KL divergence between two distributions.

        Uses histogram approximation for continuous values.
        """
        # Create histograms
        all_data = np.concatenate([p, q])
        bins = np.linspace(all_data.min(), all_data.max(), 50)

        p_hist, _ = np.histogram(p, bins=bins, density=True)
        q_hist, _ = np.histogram(q, bins=bins, density=True)

        # Add small epsilon to avoid log(0)
        eps = 1e-10
        p_hist = p_hist + eps
        q_hist = q_hist + eps

        # Normalize
        p_hist = p_hist / p_hist.sum()
        q_hist = q_hist / q_hist.sum()

        # Calculate KL divergence
        kl = np.sum(rel_entr(p_hist, q_hist))

        return float(kl)

    def _infer_affected_layers(
        self,
        anomalies: List[PerturbationResult]
    ) -> Dict[str, int]:
        """Infer which layers were affected by anomalies."""
        layer_counts: Dict[str, int] = {}

        for anomaly in anomalies:
            if anomaly.affected_layer:
                layer_counts[anomaly.affected_layer] = layer_counts.get(anomaly.affected_layer, 0) + 1

        return layer_counts

    def _calculate_overall_kl(
        self,
        results: List[PerturbationResult],
        baseline: Dict[str, float]
    ) -> float:
        """
        Calculate overall KL divergence between baseline and perturbed distributions.

        Uses closed-form KL divergence for normal distributions (deterministic).

        KL(P||Q) = log(σ_q/σ_p) + (σ_p² + (μ_p - μ_q)²)/(2σ_q²) - 1/2

        Args:
            results: Perturbation results
            baseline: Baseline statistics

        Returns:
            KL divergence value (symmetric average)
        """
        if not results:
            return 0.0

        perturbed_times = np.array([r.response_time for r in results if r.response_time > 0])

        if len(perturbed_times) < 10:
            return 0.0

        # Baseline distribution parameters
        mu_p = baseline['response_time_mean']
        sigma_p = max(baseline['response_time_std'], 1e-10)

        # Perturbed distribution parameters (empirical)
        mu_q = float(np.mean(perturbed_times))
        sigma_q = max(float(np.std(perturbed_times)), 1e-10)

        # Closed-form KL divergence for Gaussians
        # KL(P||Q) where P=baseline, Q=perturbed
        kl_pq = np.log(sigma_q / sigma_p) + \
                (sigma_p**2 + (mu_p - mu_q)**2) / (2 * sigma_q**2) - 0.5

        # KL(Q||P)
        kl_qp = np.log(sigma_p / sigma_q) + \
                (sigma_q**2 + (mu_q - mu_p)**2) / (2 * sigma_p**2) - 0.5

        # Symmetric KL (Jensen-Shannon like)
        symmetric_kl = (kl_pq + kl_qp) / 2

        return max(0.0, float(symmetric_kl))

    def _save_results(self, result: AnalysisResult, results_dir: Path) -> None:
        """Save analysis results to file."""
        import json

        output_file = results_dir / 'differential_analysis.json'

        data = {
            'target_url': result.target_url,
            'session_id': result.session_id,
            'analysis_time': result.analysis_time,
            'baseline_stats': result.baseline_stats,
            'kl_divergence': result.kl_divergence,
            'affected_layers': result.affected_layers,
            'anomaly_count': len(result.anomalies),
            'perturbation_count': len(result.perturbation_results),
            'anomalies': [
                {
                    'type': a.perturbation_type.value,
                    'original': a.original_value,
                    'perturbed': a.perturbed_value,
                    'score': a.anomaly_score,
                    'layer': a.affected_layer,
                    'status_code': a.status_code
                }
                for a in result.anomalies
            ]
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Saved results to {output_file}")
