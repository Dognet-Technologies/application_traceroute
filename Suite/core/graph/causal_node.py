"""
causal_node.py - Causal node implementation with KDE-based behavior distribution

Implements nodes in the causal security graph with:
- KDE-based behavior distribution estimation
- Entropy calculation for uncertainty quantification
- Anomaly detection via CDF-based analysis
- Observation tracking and statistical summaries
"""

import logging
import numpy as np
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from scipy import stats

logger = logging.getLogger('security_suite.causal_node')


class NodeType(Enum):
    """Types of nodes in the causal security graph."""
    STACK_LAYER = 'stack_layer'      # e.g., nginx, php, mysql
    DATA_FLOW = 'data_flow'          # e.g., request, response, header
    STATE = 'state'                   # e.g., authenticated, blocked
    TIME = 'time'                     # temporal ordering nodes
    ENDPOINT = 'endpoint'            # Web endpoint
    PARAMETER = 'parameter'          # Request parameter
    BEHAVIOR = 'behavior'            # Observable behavior
    VULNERABILITY = 'vulnerability'  # Detected vulnerability
    INFRASTRUCTURE = 'infrastructure'  # Infrastructure component


@dataclass
class ObservationData:
    """
    Single observation for a causal node.

    Attributes:
        value: Numeric value of observation
        timestamp: When observation was recorded
        context: Additional context (optional)
        source: Where observation originated
    """
    value: float
    timestamp: float
    context: Optional[Dict[str, Any]] = None
    source: str = 'unknown'


@dataclass
class NodeStatistics:
    """Statistical summary of node observations."""
    count: int = 0
    mean: float = 0.0
    std: float = 0.0
    min_val: float = float('inf')
    max_val: float = float('-inf')
    last_updated: float = 0.0


class CausalNode:
    """
    Node in the causal security graph.

    Implements KDE-based behavior distribution with:
    - Gaussian KDE for smooth density estimation
    - Entropy calculation for uncertainty measurement
    - CDF-based anomaly detection
    - Efficient observation tracking

    Complexity:
    - add_observation: O(1)
    - update_distribution: O(n log n)
    - calculate_entropy: O(k) where k=integration points
    - is_anomalous: O(n) for CDF calculation
    """

    # KDE parameters
    MIN_OBSERVATIONS_FOR_KDE = 5
    DEFAULT_BANDWIDTH = 'scott'
    ENTROPY_INTEGRATION_POINTS = 1000
    ANOMALY_TAIL_THRESHOLD = 0.05  # 5% tail probability

    def __init__(
        self,
        node_id: str,
        node_type: NodeType,
        name: str = '',
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize causal node.

        Args:
            node_id: Unique identifier for the node
            node_type: Type of node (STACK_LAYER, DATA_FLOW, STATE, TIME)
            name: Human-readable name
            metadata: Additional metadata
        """
        self.node_id = node_id
        self.node_type = node_type
        self.name = name or node_id
        self.metadata = metadata or {}

        # Observations storage
        self._observations: List[ObservationData] = []
        self._values: List[float] = []

        # Statistics
        self._stats = NodeStatistics()

        # KDE-related
        self._kde: Optional[stats.gaussian_kde] = None
        self._distribution_valid = False

        # Cache
        self._entropy_cache: Optional[float] = None

        logger.debug(f"Created CausalNode: {node_id} ({node_type.value})")

    def add_observation(
        self,
        value: float,
        timestamp: float,
        context: Optional[Dict[str, Any]] = None,
        source: str = 'unknown'
    ) -> None:
        """
        Add an observation to the node.

        Args:
            value: Numeric observation value
            timestamp: Observation timestamp
            context: Additional context
            source: Observation source

        Complexity: O(1) amortized
        """
        observation = ObservationData(
            value=value,
            timestamp=timestamp,
            context=context,
            source=source
        )

        self._observations.append(observation)
        self._values.append(value)

        # Update running statistics
        self._update_statistics(value, timestamp)

        # Invalidate caches
        self._distribution_valid = False
        self._entropy_cache = None

        logger.debug(f"Node {self.node_id}: added observation {value}")

    def _update_statistics(self, value: float, timestamp: float) -> None:
        """Update running statistics with new observation."""
        n = self._stats.count
        old_mean = self._stats.mean

        # Welford's online algorithm for mean and variance
        self._stats.count = n + 1
        delta = value - old_mean
        self._stats.mean = old_mean + delta / (n + 1)

        if n > 0:
            # Update variance using Welford's method
            delta2 = value - self._stats.mean
            m2 = (self._stats.std ** 2) * n + delta * delta2
            self._stats.std = np.sqrt(m2 / (n + 1))
        else:
            self._stats.std = 0.0

        self._stats.min_val = min(self._stats.min_val, value)
        self._stats.max_val = max(self._stats.max_val, value)
        self._stats.last_updated = timestamp

    def update_distribution(self, bandwidth: str = 'scott') -> bool:
        """
        Update KDE distribution from observations.

        Args:
            bandwidth: KDE bandwidth estimation method ('scott' or 'silverman')

        Returns:
            True if distribution was updated, False if insufficient data

        Complexity: O(n log n) for KDE fitting
        """
        if len(self._values) < self.MIN_OBSERVATIONS_FOR_KDE:
            logger.debug(
                f"Node {self.node_id}: insufficient observations "
                f"({len(self._values)} < {self.MIN_OBSERVATIONS_FOR_KDE})"
            )
            return False

        try:
            values_array = np.array(self._values)

            # Check for constant values (would cause singular matrix)
            if np.std(values_array) < 1e-10:
                logger.warning(f"Node {self.node_id}: constant values, using normal approximation")
                self._kde = None
                self._distribution_valid = True
                return True

            self._kde = stats.gaussian_kde(values_array, bw_method=bandwidth)
            self._distribution_valid = True
            self._entropy_cache = None

            logger.debug(f"Node {self.node_id}: updated KDE distribution")
            return True

        except Exception as e:
            logger.error(f"Node {self.node_id}: KDE fitting failed: {e}")
            self._kde = None
            self._distribution_valid = False
            return False

    def calculate_entropy(self) -> float:
        """
        Calculate entropy of the behavior distribution.

        Uses numerical integration over the KDE.
        Higher entropy indicates more uncertain/variable behavior.

        Returns:
            Entropy in nats (natural logarithm base)

        Complexity: O(k) where k=ENTROPY_INTEGRATION_POINTS
        """
        # Return cached value if available
        if self._entropy_cache is not None:
            return self._entropy_cache

        # Edge case: no or few observations
        if len(self._values) < self.MIN_OBSERVATIONS_FOR_KDE:
            # Return maximum entropy estimate based on observed range
            if self._stats.max_val > self._stats.min_val:
                # Uniform distribution entropy over observed range
                range_val = self._stats.max_val - self._stats.min_val
                return np.log(range_val) if range_val > 0 else 0.0
            return 0.0

        # Edge case: constant values
        if self._kde is None and self._distribution_valid:
            return 0.0  # Zero entropy for constant distribution

        if self._kde is None:
            self.update_distribution()
            if self._kde is None:
                return 0.0

        try:
            # Integration bounds (extend slightly beyond observed range)
            margin = 0.1 * (self._stats.max_val - self._stats.min_val + 1)
            x_min = self._stats.min_val - margin
            x_max = self._stats.max_val + margin

            # Integration points
            x = np.linspace(x_min, x_max, self.ENTROPY_INTEGRATION_POINTS)
            dx = x[1] - x[0]

            # Evaluate PDF
            pdf = self._kde(x)

            # Calculate entropy: -∫ p(x) log(p(x)) dx
            # Avoid log(0) by filtering near-zero values
            mask = pdf > 1e-10
            entropy = -np.sum(pdf[mask] * np.log(pdf[mask])) * dx

            # Ensure non-negative (numerical errors can cause small negatives)
            entropy = max(0.0, entropy)

            self._entropy_cache = entropy
            return entropy

        except Exception as e:
            logger.error(f"Node {self.node_id}: entropy calculation failed: {e}")
            return 0.0

    def is_anomalous(
        self,
        value: float,
        threshold: Optional[float] = None
    ) -> Tuple[bool, float]:
        """
        Check if a value is anomalous based on the distribution.

        Uses CDF to determine if value falls in distribution tails.

        Args:
            value: Value to check
            threshold: Tail probability threshold (default: 5%)

        Returns:
            Tuple of (is_anomalous, tail_probability)

        Complexity: O(n) for CDF calculation
        """
        if threshold is None:
            threshold = self.ANOMALY_TAIL_THRESHOLD

        # Edge case: insufficient observations
        if len(self._values) < self.MIN_OBSERVATIONS_FOR_KDE:
            # Use simple z-score if we have at least 2 observations
            if len(self._values) >= 2 and self._stats.std > 0:
                z_score = abs(value - self._stats.mean) / self._stats.std
                # Convert z-score to approximate tail probability
                tail_prob = 2 * (1 - stats.norm.cdf(abs(z_score)))
                return (tail_prob < threshold, tail_prob)
            return (False, 0.5)  # Not enough data to determine

        # Ensure distribution is valid
        if not self._distribution_valid:
            self.update_distribution()

        # Handle constant values case
        if self._kde is None:
            # Anomalous if different from constant value
            is_different = abs(value - self._stats.mean) > 1e-10
            return (is_different, 0.0 if is_different else 1.0)

        try:
            # Calculate CDF using numerical integration
            # CDF(x) = P(X <= x)
            x_min = min(self._stats.min_val, value) - 1
            x_points = np.linspace(x_min, value, 500)
            dx = x_points[1] - x_points[0]
            cdf = np.sum(self._kde(x_points)) * dx

            # Clamp CDF to [0, 1]
            cdf = max(0.0, min(1.0, cdf))

            # Tail probability is min(CDF, 1-CDF)
            tail_prob = min(cdf, 1 - cdf)

            is_anomalous = tail_prob < threshold

            logger.debug(
                f"Node {self.node_id}: value={value}, "
                f"tail_prob={tail_prob:.4f}, anomalous={is_anomalous}"
            )

            return (is_anomalous, tail_prob)

        except Exception as e:
            logger.error(f"Node {self.node_id}: anomaly detection failed: {e}")
            return (False, 0.5)

    def get_probability_density(self, value: float) -> float:
        """
        Get probability density at a given value.

        Args:
            value: Value to evaluate

        Returns:
            Probability density (not probability!)
        """
        if self._kde is None:
            if not self._distribution_valid or len(self._values) < self.MIN_OBSERVATIONS_FOR_KDE:
                return 0.0
            self.update_distribution()
            if self._kde is None:
                # Constant value case
                if abs(value - self._stats.mean) < 1e-10:
                    return float('inf')
                return 0.0

        return float(self._kde(value)[0])

    def get_statistics(self) -> NodeStatistics:
        """Get current statistics."""
        return self._stats

    def get_observations(
        self,
        limit: Optional[int] = None,
        since: Optional[float] = None
    ) -> List[ObservationData]:
        """
        Get observations, optionally filtered.

        Args:
            limit: Maximum number of observations to return (most recent)
            since: Only return observations after this timestamp

        Returns:
            List of observations
        """
        obs = self._observations

        if since is not None:
            obs = [o for o in obs if o.timestamp >= since]

        if limit is not None:
            obs = obs[-limit:]

        return obs

    def clear_observations(self) -> None:
        """Clear all observations and reset state."""
        self._observations.clear()
        self._values.clear()
        self._stats = NodeStatistics()
        self._kde = None
        self._distribution_valid = False
        self._entropy_cache = None

        logger.debug(f"Node {self.node_id}: cleared observations")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize node to dictionary."""
        return {
            'node_id': self.node_id,
            'node_type': self.node_type.value,
            'name': self.name,
            'metadata': self.metadata,
            'statistics': {
                'count': self._stats.count,
                'mean': self._stats.mean,
                'std': self._stats.std,
                'min': self._stats.min_val if self._stats.min_val != float('inf') else None,
                'max': self._stats.max_val if self._stats.max_val != float('-inf') else None
            },
            'entropy': self.calculate_entropy() if self._stats.count > 0 else None
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CausalNode':
        """Deserialize node from dictionary."""
        node = cls(
            node_id=data['node_id'],
            node_type=NodeType(data['node_type']),
            name=data.get('name', ''),
            metadata=data.get('metadata', {})
        )
        return node

    def __repr__(self) -> str:
        return (
            f"CausalNode(id={self.node_id}, type={self.node_type.value}, "
            f"observations={len(self._values)})"
        )

    def __hash__(self) -> int:
        return hash(self.node_id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CausalNode):
            return False
        return self.node_id == other.node_id
