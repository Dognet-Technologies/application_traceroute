"""
causal_edge.py - Causal edge implementation for security graph

Implements edges representing causal relationships between nodes with:
- Causality strength tracking
- Evidence accumulation
- Conditional probability estimation
- Bayesian updates for strength refinement
"""

import logging
import time
import numpy as np
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger('security_suite.causal_edge')


class CausalityType(Enum):
    """Types of causal relationships."""
    DIRECT = 'direct'           # A directly causes B
    INDIRECT = 'indirect'       # A causes B through intermediate nodes
    CONDITIONAL = 'conditional'  # A causes B given conditions C


@dataclass
class CausalEvidence:
    """
    Evidence supporting a causal relationship.

    Attributes:
        timestamp: When evidence was observed
        source_value: Value observed at source node
        target_value: Value observed at target node
        time_delta: Time difference between observations
        strength_contribution: How much this evidence supports causation
        context: Additional context information
    """
    timestamp: float
    source_value: float
    target_value: float
    time_delta: float
    strength_contribution: float = 0.5
    context: Dict[str, Any] = field(default_factory=dict)


class CausalEdge:
    """
    Edge representing causal relationship between two nodes.

    Implements:
    - Exponential moving average for strength updates
    - Evidence accumulation with decay
    - Conditional probability estimation
    - Bayesian strength updates

    The edge tracks evidence of causation and maintains an
    estimate of causal strength (probability that source causes target).
    """

    # Parameters
    EMA_ALPHA = 0.1  # Exponential moving average decay
    EVIDENCE_DECAY = 0.95  # Evidence importance decay over time
    MIN_EVIDENCE_FOR_ESTIMATE = 3
    MAX_EVIDENCE_HISTORY = 1000

    def __init__(
        self,
        source_id: str,
        target_id: str,
        causality_type: CausalityType = CausalityType.DIRECT,
        initial_strength: float = 0.5,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize causal edge.

        Args:
            source_id: ID of source node (cause)
            target_id: ID of target node (effect)
            causality_type: Type of causal relationship
            initial_strength: Initial causality strength [0, 1]
            metadata: Additional metadata

        Raises:
            ValueError: If source and target are the same (self-loop)
            ValueError: If initial_strength not in [0, 1]
        """
        # Validate no self-loops
        if source_id == target_id:
            raise ValueError(f"Self-loops not allowed: {source_id}")

        # Validate strength range
        if not 0 <= initial_strength <= 1:
            raise ValueError(f"Strength must be in [0, 1], got {initial_strength}")

        self.source_id = source_id
        self.target_id = target_id
        self.causality_type = causality_type
        self.metadata = metadata or {}

        # Strength tracking
        self._strength = initial_strength
        self._confidence = 0.0  # Confidence in strength estimate

        # Evidence storage
        self._evidence: List[CausalEvidence] = []
        self._evidence_count = 0

        # Conditional tracking
        self._conditions: Set[str] = set()

        # Bayesian prior (Beta distribution parameters)
        self._alpha = 1.0  # Prior successes
        self._beta = 1.0   # Prior failures

        # Timestamps
        self._created_at = time.time()
        self._updated_at = self._created_at

        logger.debug(f"Created CausalEdge: {source_id} -> {target_id}")

    @property
    def strength(self) -> float:
        """Get current causality strength."""
        return self._strength

    @property
    def confidence(self) -> float:
        """Get confidence in strength estimate."""
        return self._confidence

    @property
    def edge_id(self) -> str:
        """Unique edge identifier."""
        return f"{self.source_id}->{self.target_id}"

    def add_evidence(
        self,
        source_value: float,
        target_value: float,
        time_delta: float,
        strength_contribution: Optional[float] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Add evidence of causal relationship.

        Args:
            source_value: Value observed at source
            target_value: Value observed at target
            time_delta: Time between source and target observations
            strength_contribution: Strength of this evidence [0, 1]
            context: Additional context

        Complexity: O(1) amortized
        """
        # Estimate strength contribution if not provided
        if strength_contribution is None:
            # Positive time delta suggests causation
            # Shorter delta suggests stronger causation
            if time_delta > 0:
                strength_contribution = 1.0 / (1.0 + time_delta)
            else:
                strength_contribution = 0.1  # Unlikely causation if target before source

        # Clamp strength contribution
        strength_contribution = max(0.0, min(1.0, strength_contribution))

        evidence = CausalEvidence(
            timestamp=time.time(),
            source_value=source_value,
            target_value=target_value,
            time_delta=time_delta,
            strength_contribution=strength_contribution,
            context=context or {}
        )

        self._evidence.append(evidence)
        self._evidence_count += 1

        # Trim old evidence if needed
        if len(self._evidence) > self.MAX_EVIDENCE_HISTORY:
            self._evidence = self._evidence[-self.MAX_EVIDENCE_HISTORY:]

        # Update strength using EMA
        self._update_strength_ema(strength_contribution)

        # Update Bayesian posterior
        self._update_bayesian(strength_contribution)

        self._updated_at = time.time()

        logger.debug(
            f"Edge {self.edge_id}: added evidence, "
            f"strength={self._strength:.3f}, confidence={self._confidence:.3f}"
        )

    def _update_strength_ema(self, new_contribution: float) -> None:
        """Update strength using exponential moving average."""
        self._strength = (
            self.EMA_ALPHA * new_contribution +
            (1 - self.EMA_ALPHA) * self._strength
        )

        # Update confidence based on evidence count
        max_confidence_evidence = 100
        self._confidence = min(1.0, self._evidence_count / max_confidence_evidence)

    def _update_bayesian(self, contribution: float) -> None:
        """
        Update Bayesian posterior for strength.

        Uses Beta-Bernoulli conjugate model with binary outcomes.
        Contribution > 0.5 is treated as success, otherwise failure.
        This follows standard Bayesian inference: alpha += 1 or beta += 1.
        """
        # Binary Bayesian update (standard Beta-Bernoulli)
        if contribution > 0.5:
            self._alpha += 1.0  # Success observation
        else:
            self._beta += 1.0  # Failure observation

    def update_strength(self) -> float:
        """
        Recalculate strength from all evidence with decay.

        Returns:
            Updated strength value

        Complexity: O(n) where n = evidence count
        """
        if not self._evidence:
            return self._strength

        current_time = time.time()
        weighted_sum = 0.0
        weight_total = 0.0

        for evidence in self._evidence:
            # Calculate time-based decay
            age = current_time - evidence.timestamp
            decay = self.EVIDENCE_DECAY ** (age / 3600)  # Decay per hour

            weight = decay
            weighted_sum += weight * evidence.strength_contribution
            weight_total += weight

        if weight_total > 0:
            self._strength = weighted_sum / weight_total

        return self._strength

    def get_conditional_probability(
        self,
        given_nodes: Optional[Set[str]] = None
    ) -> float:
        """
        Get conditional probability P(target | source, given_nodes).

        For CONDITIONAL edges, this considers the conditioning set.
        For DIRECT edges, returns the strength.

        Args:
            given_nodes: Set of node IDs to condition on

        Returns:
            Conditional probability estimate
        """
        if self.causality_type != CausalityType.CONDITIONAL:
            return self._strength

        if given_nodes is None:
            return self._strength

        # Check if all conditions are met
        if not self._conditions.issubset(given_nodes):
            # Missing conditions, reduce probability
            missing_ratio = 1 - len(self._conditions & given_nodes) / max(1, len(self._conditions))
            return self._strength * (1 - missing_ratio * 0.5)

        return self._strength

    def add_condition(self, node_id: str) -> None:
        """
        Add a conditioning node for CONDITIONAL edges.

        Args:
            node_id: Node ID to add as condition
        """
        self._conditions.add(node_id)
        if self.causality_type == CausalityType.DIRECT:
            self.causality_type = CausalityType.CONDITIONAL

    def get_bayesian_estimate(self) -> tuple[float, float, float]:
        """
        Get Bayesian strength estimate with credible interval.

        Returns:
            Tuple of (mean, lower_95, upper_95)
        """
        from scipy import stats

        # Beta distribution parameters
        mean = self._alpha / (self._alpha + self._beta)

        # 95% credible interval
        lower = stats.beta.ppf(0.025, self._alpha, self._beta)
        upper = stats.beta.ppf(0.975, self._alpha, self._beta)

        return (mean, lower, upper)

    def get_evidence_count(self) -> int:
        """Get total evidence count."""
        return self._evidence_count

    def get_recent_evidence(self, limit: int = 10) -> List[CausalEvidence]:
        """Get most recent evidence."""
        return self._evidence[-limit:]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize edge to dictionary."""
        return {
            'source_id': self.source_id,
            'target_id': self.target_id,
            'causality_type': self.causality_type.value,
            'strength': self._strength,
            'confidence': self._confidence,
            'evidence_count': self._evidence_count,
            'conditions': list(self._conditions),
            'bayesian': {
                'alpha': self._alpha,
                'beta': self._beta
            },
            'metadata': self.metadata,
            'created_at': self._created_at,
            'updated_at': self._updated_at
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CausalEdge':
        """Deserialize edge from dictionary."""
        edge = cls(
            source_id=data['source_id'],
            target_id=data['target_id'],
            causality_type=CausalityType(data['causality_type']),
            initial_strength=data['strength'],
            metadata=data.get('metadata', {})
        )

        edge._confidence = data.get('confidence', 0.0)
        edge._evidence_count = data.get('evidence_count', 0)
        edge._conditions = set(data.get('conditions', []))

        bayesian = data.get('bayesian', {})
        edge._alpha = bayesian.get('alpha', 1.0)
        edge._beta = bayesian.get('beta', 1.0)

        edge._created_at = data.get('created_at', time.time())
        edge._updated_at = data.get('updated_at', time.time())

        return edge

    def __repr__(self) -> str:
        return (
            f"CausalEdge({self.source_id} -> {self.target_id}, "
            f"strength={self._strength:.3f}, type={self.causality_type.value})"
        )

    def __hash__(self) -> int:
        return hash((self.source_id, self.target_id))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CausalEdge):
            return False
        return self.source_id == other.source_id and self.target_id == other.target_id
