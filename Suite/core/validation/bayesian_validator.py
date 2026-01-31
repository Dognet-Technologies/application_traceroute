"""
bayesian_validator.py - Bayesian bypass validation

Implements intelligent validation using:
- Thompson Sampling for exploit selection
- UCB algorithm for exploration/exploitation balance
- Bayesian prior updates based on results
- Adaptive confidence estimation
"""

import logging
import time
import numpy as np
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict

logger = logging.getLogger('security_suite.bayesian_validator')


class ValidationResult(Enum):
    """Result of a validation attempt."""
    SUCCESS = 'success'       # Bypass succeeded
    FAILURE = 'failure'       # Bypass blocked
    PARTIAL = 'partial'       # Partial bypass
    ERROR = 'error'           # Test error
    TIMEOUT = 'timeout'       # Timeout occurred


@dataclass
class ExploitCandidate:
    """
    Candidate exploit for validation.

    Attributes:
        exploit_id: Unique identifier
        category: Exploit category (sqli, xss, etc.)
        payload: Exploit payload
        alpha: Beta distribution alpha parameter
        beta: Beta distribution beta parameter
        successes: Number of successful validations
        failures: Number of failed validations
        last_tested: Last test timestamp
    """
    exploit_id: str
    category: str
    payload: str
    alpha: float = 1.0
    beta: float = 1.0
    successes: float = 0.0  # Float to support partial successes
    failures: float = 0.0   # Float for consistency
    last_tested: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def mean_success_rate(self) -> float:
        """Expected success rate (posterior mean)."""
        return self.alpha / (self.alpha + self.beta)

    @property
    def variance(self) -> float:
        """Posterior variance."""
        total = self.alpha + self.beta
        return (self.alpha * self.beta) / (total ** 2 * (total + 1))

    @property
    def confidence(self) -> float:
        """Confidence in estimate (inverse of variance)."""
        return 1.0 / (1.0 + self.variance * 10)

    def sample(self) -> float:
        """Sample from posterior (Thompson Sampling)."""
        return np.random.beta(self.alpha, self.beta)

    def ucb_score(self, total_trials: int, exploration_weight: float = 2.0) -> float:
        """
        Calculate UCB score.

        UCB = mean + c * sqrt(ln(N) / n)

        Args:
            total_trials: Total number of trials across all candidates
            exploration_weight: Exploration constant (c)

        Returns:
            UCB score
        """
        n = self.successes + self.failures
        if n == 0:
            return float('inf')  # Explore untested candidates

        exploitation = self.mean_success_rate
        exploration = exploration_weight * np.sqrt(np.log(total_trials + 1) / n)

        return exploitation + exploration

    def update(self, success: bool) -> None:
        """
        Update posterior based on result.

        Args:
            success: Whether the validation succeeded
        """
        if success:
            self.alpha += 1
            self.successes += 1
        else:
            self.beta += 1
            self.failures += 1

        self.last_tested = time.time()


@dataclass
class ValidationAttempt:
    """Record of a validation attempt."""
    exploit_id: str
    target: str
    result: ValidationResult
    response_code: int
    response_time: float
    timestamp: float = field(default_factory=time.time)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationSummary:
    """Summary of validation results."""
    total_attempts: int
    successful: int
    failed: int
    partial: int
    errors: int
    success_rate: float
    best_exploits: List[str]
    vulnerable_endpoints: List[str]
    confidence: float


class BayesianBypassValidator:
    """
    Validator for security bypass testing using Bayesian methods.

    Implements:
    - Thompson Sampling for exploit selection
    - UCB algorithm for exploration/exploitation
    - Adaptive prior updates
    - Confidence-based stopping

    Performance targets:
    - Efficient exploit selection: O(n) per selection
    - Minimal redundant testing through Bayesian updates
    """

    # Configuration
    MIN_TRIALS_FOR_CONFIDENCE = 5
    CONFIDENCE_THRESHOLD = 0.8
    EXPLORATION_WEIGHT = 2.0
    DECAY_FACTOR = 0.95
    MAX_ATTEMPTS_PER_EXPLOIT = 10

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize validator.

        Args:
            config: Optional configuration overrides
        """
        config = config or {}

        self.min_trials = config.get('min_trials', self.MIN_TRIALS_FOR_CONFIDENCE)
        self.confidence_threshold = config.get('confidence_threshold', self.CONFIDENCE_THRESHOLD)
        self.exploration_weight = config.get('exploration_weight', self.EXPLORATION_WEIGHT)
        self.decay_factor = config.get('decay_factor', self.DECAY_FACTOR)
        self.max_attempts = config.get('max_attempts_per_exploit', self.MAX_ATTEMPTS_PER_EXPLOIT)

        # Storage
        self._candidates: Dict[str, ExploitCandidate] = {}
        self._attempts: List[ValidationAttempt] = []
        self._endpoint_results: Dict[str, Dict[str, ValidationResult]] = defaultdict(dict)

        # Category priors (learned from history)
        self._category_priors: Dict[str, Tuple[float, float]] = {
            'sqli': (2.0, 3.0),
            'xss': (2.0, 4.0),
            'path_traversal': (1.5, 3.0),
            'command_injection': (1.0, 5.0),
            'ssrf': (1.0, 4.0),
            'xxe': (1.0, 5.0),
            'default': (1.0, 1.0)
        }

        logger.debug("Initialized BayesianBypassValidator")

    def add_candidate(
        self,
        exploit_id: str,
        category: str,
        payload: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ExploitCandidate:
        """
        Add an exploit candidate for validation.

        Args:
            exploit_id: Unique identifier
            category: Exploit category
            payload: Exploit payload
            metadata: Additional metadata

        Returns:
            The created ExploitCandidate
        """
        # Get category prior
        alpha, beta = self._category_priors.get(category, self._category_priors['default'])

        candidate = ExploitCandidate(
            exploit_id=exploit_id,
            category=category,
            payload=payload,
            alpha=alpha,
            beta=beta,
            metadata=metadata or {}
        )

        self._candidates[exploit_id] = candidate
        logger.debug(f"Added candidate: {exploit_id} ({category})")

        return candidate

    def select_next_exploit_thompson(self) -> Optional[ExploitCandidate]:
        """
        Select next exploit using Thompson Sampling.

        Samples from each candidate's posterior and selects the highest.

        Returns:
            Selected ExploitCandidate or None if no candidates
        """
        if not self._candidates:
            return None

        # Filter candidates that haven't been tested too many times
        eligible = [
            c for c in self._candidates.values()
            if c.successes + c.failures < self.max_attempts
        ]

        if not eligible:
            eligible = list(self._candidates.values())

        # Thompson Sampling: sample from each posterior
        best_candidate = None
        best_sample = -1

        for candidate in eligible:
            sample = candidate.sample()
            if sample > best_sample:
                best_sample = sample
                best_candidate = candidate

        return best_candidate

    def select_next_exploit_ucb(self) -> Optional[ExploitCandidate]:
        """
        Select next exploit using UCB algorithm.

        Balances exploitation (high success rate) with exploration (uncertainty).

        Returns:
            Selected ExploitCandidate or None if no candidates
        """
        if not self._candidates:
            return None

        total_trials = sum(c.successes + c.failures for c in self._candidates.values())

        best_candidate = None
        best_score = -float('inf')

        for candidate in self._candidates.values():
            if candidate.successes + candidate.failures >= self.max_attempts:
                continue

            score = candidate.ucb_score(total_trials, self.exploration_weight)
            if score > best_score:
                best_score = score
                best_candidate = candidate

        return best_candidate

    def record_result(
        self,
        exploit_id: str,
        target: str,
        result: ValidationResult,
        response_code: int = 0,
        response_time: float = 0.0,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Record validation result and update posteriors.

        Args:
            exploit_id: Exploit identifier
            target: Target endpoint
            result: Validation result
            response_code: HTTP response code
            response_time: Response time in seconds
            details: Additional details
        """
        candidate = self._candidates.get(exploit_id)
        if candidate is None:
            logger.warning(f"Unknown exploit: {exploit_id}")
            return

        # Update candidate posterior
        success = result == ValidationResult.SUCCESS
        partial = result == ValidationResult.PARTIAL

        if success:
            candidate.update(True)
        elif partial:
            # Partial success: smaller update
            candidate.alpha += 0.5
            candidate.successes += 0.5
        else:
            candidate.update(False)

        # Record attempt
        attempt = ValidationAttempt(
            exploit_id=exploit_id,
            target=target,
            result=result,
            response_code=response_code,
            response_time=response_time,
            details=details or {}
        )
        self._attempts.append(attempt)

        # Update endpoint results
        self._endpoint_results[target][exploit_id] = result

        # Update category prior based on results
        self._update_category_prior(candidate.category, success or partial)

        logger.debug(
            f"Recorded {result.value} for {exploit_id} on {target}, "
            f"new success rate: {candidate.mean_success_rate:.3f}"
        )

    def _update_category_prior(self, category: str, success: bool) -> None:
        """Update category prior based on observed results."""
        if category not in self._category_priors:
            return

        alpha, beta = self._category_priors[category]

        # Weighted update with decay
        if success:
            alpha = alpha * self.decay_factor + 1
        else:
            beta = beta * self.decay_factor + 1

        self._category_priors[category] = (alpha, beta)

    def get_top_exploits(self, n: int = 10) -> List[ExploitCandidate]:
        """
        Get top N exploits by success rate.

        Args:
            n: Number of exploits to return

        Returns:
            List of top candidates sorted by mean success rate
        """
        candidates = list(self._candidates.values())
        # Sort by mean success rate, with confidence as tiebreaker
        candidates.sort(
            key=lambda c: (c.mean_success_rate, c.confidence),
            reverse=True
        )
        return candidates[:n]

    def get_vulnerable_endpoints(
        self,
        min_confidence: Optional[float] = None
    ) -> List[Tuple[str, List[str]]]:
        """
        Get endpoints with successful bypasses.

        Args:
            min_confidence: Minimum confidence threshold

        Returns:
            List of (endpoint, successful_exploits) tuples
        """
        min_confidence = min_confidence or self.confidence_threshold
        vulnerable = []

        for endpoint, results in self._endpoint_results.items():
            successful = [
                eid for eid, result in results.items()
                if result == ValidationResult.SUCCESS
            ]

            if successful:
                # Check confidence
                confidences = [
                    self._candidates[eid].confidence
                    for eid in successful
                    if eid in self._candidates
                ]

                if confidences and np.mean(confidences) >= min_confidence:
                    vulnerable.append((endpoint, successful))

        return sorted(vulnerable, key=lambda x: len(x[1]), reverse=True)

    def should_stop_testing(
        self,
        exploit_id: str,
        min_trials: Optional[int] = None,
        confidence_threshold: Optional[float] = None
    ) -> bool:
        """
        Determine if we should stop testing an exploit.

        Stops when:
        - Enough trials for confident estimate
        - Success rate is clearly high or low

        Args:
            exploit_id: Exploit to check
            min_trials: Minimum trials required
            confidence_threshold: Confidence threshold

        Returns:
            True if testing should stop
        """
        candidate = self._candidates.get(exploit_id)
        if candidate is None:
            return True

        min_trials = min_trials or self.min_trials
        confidence_threshold = confidence_threshold or self.confidence_threshold

        total = candidate.successes + candidate.failures

        # Not enough trials
        if total < min_trials:
            return False

        # High confidence in estimate
        if candidate.confidence >= confidence_threshold:
            # Clear success or clear failure
            if candidate.mean_success_rate > 0.7 or candidate.mean_success_rate < 0.1:
                return True

        # Max attempts reached
        if total >= self.max_attempts:
            return True

        return False

    def get_summary(self) -> ValidationSummary:
        """Get validation summary."""
        if not self._attempts:
            return ValidationSummary(
                total_attempts=0,
                successful=0,
                failed=0,
                partial=0,
                errors=0,
                success_rate=0.0,
                best_exploits=[],
                vulnerable_endpoints=[],
                confidence=0.0
            )

        result_counts = defaultdict(int)
        for attempt in self._attempts:
            result_counts[attempt.result] += 1

        total = len(self._attempts)
        successful = result_counts[ValidationResult.SUCCESS]

        # Best exploits
        top_exploits = self.get_top_exploits(5)
        best_exploit_ids = [e.exploit_id for e in top_exploits if e.mean_success_rate > 0.5]

        # Vulnerable endpoints
        vulnerable = self.get_vulnerable_endpoints()
        vulnerable_endpoints = [e[0] for e in vulnerable]

        # Overall confidence
        if self._candidates:
            avg_confidence = np.mean([c.confidence for c in self._candidates.values()])
        else:
            avg_confidence = 0.0

        return ValidationSummary(
            total_attempts=total,
            successful=successful,
            failed=result_counts[ValidationResult.FAILURE],
            partial=result_counts[ValidationResult.PARTIAL],
            errors=result_counts[ValidationResult.ERROR] + result_counts[ValidationResult.TIMEOUT],
            success_rate=successful / total if total > 0 else 0.0,
            best_exploits=best_exploit_ids,
            vulnerable_endpoints=vulnerable_endpoints,
            confidence=float(avg_confidence)
        )

    def get_category_statistics(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics by exploit category."""
        stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'count': 0,
            'successes': 0,
            'failures': 0,
            'avg_success_rate': 0.0
        })

        for candidate in self._candidates.values():
            cat_stats = stats[candidate.category]
            cat_stats['count'] += 1
            cat_stats['successes'] += candidate.successes
            cat_stats['failures'] += candidate.failures

        for category, cat_stats in stats.items():
            total = cat_stats['successes'] + cat_stats['failures']
            if total > 0:
                cat_stats['avg_success_rate'] = cat_stats['successes'] / total

        return dict(stats)

    def export_results(self) -> Dict[str, Any]:
        """Export all results."""
        return {
            'summary': {
                'total_attempts': len(self._attempts),
                'candidates': len(self._candidates),
                'vulnerable_endpoints': len(self.get_vulnerable_endpoints())
            },
            'candidates': {
                cid: {
                    'category': c.category,
                    'success_rate': c.mean_success_rate,
                    'confidence': c.confidence,
                    'successes': c.successes,
                    'failures': c.failures
                }
                for cid, c in self._candidates.items()
            },
            'category_stats': self.get_category_statistics(),
            'vulnerable_endpoints': [
                {'endpoint': e, 'exploits': exps}
                for e, exps in self.get_vulnerable_endpoints()
            ]
        }

    def reset(self) -> None:
        """Reset validator state."""
        self._candidates.clear()
        self._attempts.clear()
        self._endpoint_results.clear()
        logger.info("Validator reset")
