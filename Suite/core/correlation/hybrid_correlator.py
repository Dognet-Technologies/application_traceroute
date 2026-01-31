"""
hybrid_correlator.py - Hybrid correlation engine for security analysis

Implements correlation analysis combining:
- Graph-based causal reasoning
- Cosine similarity for vector comparisons
- Temporal correlation analysis
- Cross-layer correlation
"""

import logging
import time
import numpy as np
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from scipy.spatial.distance import cosine
from scipy.stats import pearsonr, spearmanr

logger = logging.getLogger('security_suite.hybrid_correlator')


class CorrelationType(Enum):
    """Types of correlations detected."""
    CAUSAL = 'causal'           # Direct causal relationship
    TEMPORAL = 'temporal'       # Time-based correlation
    STRUCTURAL = 'structural'   # Structure similarity
    BEHAVIORAL = 'behavioral'   # Behavior similarity
    SEMANTIC = 'semantic'       # Semantic similarity


@dataclass
class CorrelationEvidence:
    """Evidence supporting a correlation."""
    evidence_type: str
    description: str
    strength: float
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Correlation:
    """
    Represents a correlation between two entities.

    Attributes:
        source_id: Source entity identifier
        target_id: Target entity identifier
        correlation_type: Type of correlation
        strength: Correlation strength (0-1)
        confidence: Confidence in the correlation
        evidence: Supporting evidence
    """
    source_id: str
    target_id: str
    correlation_type: CorrelationType
    strength: float
    confidence: float
    evidence: List[CorrelationEvidence] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def add_evidence(self, evidence: CorrelationEvidence) -> None:
        """Add supporting evidence."""
        self.evidence.append(evidence)
        self.updated_at = time.time()
        # Update confidence based on evidence
        self.confidence = min(1.0, self.confidence + evidence.strength * 0.1)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'source_id': self.source_id,
            'target_id': self.target_id,
            'type': self.correlation_type.value,
            'strength': self.strength,
            'confidence': self.confidence,
            'evidence_count': len(self.evidence),
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }


@dataclass
class CorrelationCluster:
    """Cluster of correlated entities."""
    cluster_id: str
    entities: Set[str]
    correlations: List[Correlation]
    coherence_score: float
    dominant_type: CorrelationType


class HybridCorrelationEngine:
    """
    Engine for hybrid correlation analysis.

    Combines multiple correlation techniques:
    - Graph-based causal analysis
    - Cosine similarity for feature vectors
    - Temporal pattern matching
    - Cross-layer correlation

    Performance targets:
    - O(n²) for pairwise correlations
    - Configurable sampling for large datasets
    """

    # Configuration
    MIN_CORRELATION_STRENGTH = 0.3
    MIN_CONFIDENCE = 0.5
    COSINE_THRESHOLD = 0.7
    TEMPORAL_WINDOW = 1.0  # seconds
    MAX_CORRELATIONS = 10000

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize correlation engine.

        Args:
            config: Optional configuration overrides
        """
        config = config or {}

        self.min_strength = config.get('min_correlation_strength', self.MIN_CORRELATION_STRENGTH)
        self.min_confidence = config.get('min_confidence', self.MIN_CONFIDENCE)
        self.cosine_threshold = config.get('cosine_threshold', self.COSINE_THRESHOLD)
        self.temporal_window = config.get('temporal_window', self.TEMPORAL_WINDOW)
        self.max_correlations = config.get('max_correlations', self.MAX_CORRELATIONS)

        # Storage
        self._correlations: Dict[str, Correlation] = {}
        self._entity_vectors: Dict[str, np.ndarray] = {}
        self._entity_timestamps: Dict[str, List[float]] = defaultdict(list)
        self._entity_features: Dict[str, Dict[str, Any]] = {}

        # Index for fast lookup
        self._source_index: Dict[str, Set[str]] = defaultdict(set)
        self._target_index: Dict[str, Set[str]] = defaultdict(set)

        logger.debug("Initialized HybridCorrelationEngine")

    def _correlation_id(self, source_id: str, target_id: str) -> str:
        """Generate unique correlation ID."""
        return f"{source_id}::{target_id}"

    def register_entity(
        self,
        entity_id: str,
        features: Optional[Dict[str, Any]] = None,
        vector: Optional[np.ndarray] = None,
        timestamp: Optional[float] = None
    ) -> None:
        """
        Register an entity for correlation analysis.

        Args:
            entity_id: Unique entity identifier
            features: Feature dictionary
            vector: Feature vector for similarity calculations
            timestamp: Event timestamp
        """
        if features:
            self._entity_features[entity_id] = features

        if vector is not None:
            self._entity_vectors[entity_id] = np.array(vector)

        if timestamp is not None:
            self._entity_timestamps[entity_id].append(timestamp)

    def add_correlation(
        self,
        source_id: str,
        target_id: str,
        correlation_type: CorrelationType,
        strength: float,
        confidence: float = 0.5,
        evidence: Optional[List[CorrelationEvidence]] = None
    ) -> Optional[Correlation]:
        """
        Add or update a correlation.

        Args:
            source_id: Source entity ID
            target_id: Target entity ID
            correlation_type: Type of correlation
            strength: Correlation strength (0-1)
            confidence: Confidence level
            evidence: Supporting evidence

        Returns:
            The created or updated Correlation
        """
        if strength < self.min_strength:
            return None

        if len(self._correlations) >= self.max_correlations:
            logger.warning("Max correlations reached, pruning weak correlations")
            self._prune_weak_correlations()

        corr_id = self._correlation_id(source_id, target_id)

        if corr_id in self._correlations:
            # Update existing
            corr = self._correlations[corr_id]
            corr.strength = max(corr.strength, strength)
            corr.confidence = max(corr.confidence, confidence)
            if evidence:
                for e in evidence:
                    corr.add_evidence(e)
            corr.updated_at = time.time()
        else:
            # Create new
            corr = Correlation(
                source_id=source_id,
                target_id=target_id,
                correlation_type=correlation_type,
                strength=strength,
                confidence=confidence,
                evidence=evidence or []
            )
            self._correlations[corr_id] = corr
            self._source_index[source_id].add(corr_id)
            self._target_index[target_id].add(corr_id)

        return corr

    def get_correlation(
        self,
        source_id: str,
        target_id: str
    ) -> Optional[Correlation]:
        """Get correlation between two entities."""
        corr_id = self._correlation_id(source_id, target_id)
        return self._correlations.get(corr_id)

    def get_correlations_for_entity(
        self,
        entity_id: str,
        as_source: bool = True,
        as_target: bool = True,
        min_strength: Optional[float] = None
    ) -> List[Correlation]:
        """Get all correlations involving an entity."""
        corr_ids = set()

        if as_source:
            corr_ids.update(self._source_index.get(entity_id, set()))
        if as_target:
            corr_ids.update(self._target_index.get(entity_id, set()))

        min_strength = min_strength or self.min_strength
        correlations = [
            self._correlations[cid]
            for cid in corr_ids
            if cid in self._correlations and self._correlations[cid].strength >= min_strength
        ]

        return sorted(correlations, key=lambda c: c.strength, reverse=True)

    def compute_cosine_similarity(
        self,
        entity1_id: str,
        entity2_id: str
    ) -> Optional[float]:
        """
        Compute cosine similarity between two entity vectors.

        Returns:
            Similarity score (0-1) or None if vectors not available
        """
        vec1 = self._entity_vectors.get(entity1_id)
        vec2 = self._entity_vectors.get(entity2_id)

        if vec1 is None or vec2 is None:
            return None

        # Handle zero vectors
        if np.allclose(vec1, 0) or np.allclose(vec2, 0):
            return 0.0

        similarity = 1 - cosine(vec1, vec2)
        return float(similarity)

    def compute_temporal_correlation(
        self,
        entity1_id: str,
        entity2_id: str
    ) -> Optional[float]:
        """
        Compute temporal correlation between entities.

        Measures how often events occur within temporal_window.

        Returns:
            Correlation score (0-1) or None if no timestamps
        """
        times1 = self._entity_timestamps.get(entity1_id, [])
        times2 = self._entity_timestamps.get(entity2_id, [])

        if not times1 or not times2:
            return None

        # Count co-occurrences within window
        co_occurrences = 0
        total_events = len(times1) + len(times2)

        for t1 in times1:
            for t2 in times2:
                if abs(t1 - t2) <= self.temporal_window:
                    co_occurrences += 1
                    break

        if total_events == 0:
            return 0.0

        return co_occurrences / (len(times1) + 0.001)

    def find_all_correlations(
        self,
        entity_ids: Optional[List[str]] = None,
        correlation_types: Optional[List[CorrelationType]] = None
    ) -> List[Correlation]:
        """
        Find correlations between all registered entities.

        Args:
            entity_ids: Specific entities to analyze (or all if None)
            correlation_types: Types of correlations to compute

        Returns:
            List of discovered correlations

        Complexity: O(n²) where n = number of entities
        """
        if entity_ids is None:
            entity_ids = list(set(
                list(self._entity_vectors.keys()) +
                list(self._entity_features.keys()) +
                list(self._entity_timestamps.keys())
            ))

        if correlation_types is None:
            correlation_types = list(CorrelationType)

        discovered = []
        n = len(entity_ids)

        logger.debug(f"Computing correlations for {n} entities")

        for i in range(n):
            for j in range(i + 1, n):
                e1, e2 = entity_ids[i], entity_ids[j]

                # Cosine similarity
                if CorrelationType.STRUCTURAL in correlation_types:
                    sim = self.compute_cosine_similarity(e1, e2)
                    if sim and sim >= self.cosine_threshold:
                        corr = self.add_correlation(
                            e1, e2,
                            CorrelationType.STRUCTURAL,
                            strength=sim,
                            confidence=0.7,
                            evidence=[CorrelationEvidence(
                                evidence_type='cosine_similarity',
                                description=f'Cosine similarity: {sim:.3f}',
                                strength=sim
                            )]
                        )
                        if corr:
                            discovered.append(corr)

                # Temporal correlation
                if CorrelationType.TEMPORAL in correlation_types:
                    temp_corr = self.compute_temporal_correlation(e1, e2)
                    if temp_corr and temp_corr >= self.min_strength:
                        corr = self.add_correlation(
                            e1, e2,
                            CorrelationType.TEMPORAL,
                            strength=temp_corr,
                            confidence=0.6,
                            evidence=[CorrelationEvidence(
                                evidence_type='temporal_proximity',
                                description=f'Temporal correlation: {temp_corr:.3f}',
                                strength=temp_corr
                            )]
                        )
                        if corr:
                            discovered.append(corr)

                # Feature-based behavioral correlation
                if CorrelationType.BEHAVIORAL in correlation_types:
                    f1 = self._entity_features.get(e1, {})
                    f2 = self._entity_features.get(e2, {})
                    if f1 and f2:
                        behav_sim = self._compute_feature_similarity(f1, f2)
                        if behav_sim >= self.min_strength:
                            corr = self.add_correlation(
                                e1, e2,
                                CorrelationType.BEHAVIORAL,
                                strength=behav_sim,
                                confidence=0.5,
                                evidence=[CorrelationEvidence(
                                    evidence_type='feature_match',
                                    description=f'Feature similarity: {behav_sim:.3f}',
                                    strength=behav_sim
                                )]
                            )
                            if corr:
                                discovered.append(corr)

        logger.info(f"Found {len(discovered)} correlations among {n} entities")
        return discovered

    def _compute_feature_similarity(
        self,
        features1: Dict[str, Any],
        features2: Dict[str, Any]
    ) -> float:
        """Compute similarity between feature dictionaries."""
        common_keys = set(features1.keys()) & set(features2.keys())
        if not common_keys:
            return 0.0

        matches = 0
        for key in common_keys:
            if features1[key] == features2[key]:
                matches += 1
            elif isinstance(features1[key], (int, float)) and isinstance(features2[key], (int, float)):
                # Numeric similarity
                max_val = max(abs(features1[key]), abs(features2[key]), 1)
                similarity = 1 - abs(features1[key] - features2[key]) / max_val
                matches += max(0, similarity)

        return matches / len(common_keys)

    def find_correlation_clusters(
        self,
        min_cluster_size: int = 2,
        min_coherence: float = 0.5
    ) -> List[CorrelationCluster]:
        """
        Find clusters of highly correlated entities.

        Uses connected components in correlation graph.

        Args:
            min_cluster_size: Minimum entities in cluster
            min_coherence: Minimum cluster coherence

        Returns:
            List of correlation clusters
        """
        # Build adjacency for strong correlations
        adjacency: Dict[str, Set[str]] = defaultdict(set)

        for corr in self._correlations.values():
            if corr.strength >= self.min_strength and corr.confidence >= self.min_confidence:
                adjacency[corr.source_id].add(corr.target_id)
                adjacency[corr.target_id].add(corr.source_id)

        # Find connected components (DFS)
        visited = set()
        clusters = []

        def dfs(node: str, component: Set[str]) -> None:
            if node in visited:
                return
            visited.add(node)
            component.add(node)
            for neighbor in adjacency.get(node, set()):
                dfs(neighbor, component)

        for entity_id in adjacency:
            if entity_id not in visited:
                component: Set[str] = set()
                dfs(entity_id, component)

                if len(component) >= min_cluster_size:
                    # Calculate cluster coherence and find correlations
                    cluster_corrs = []
                    type_counts: Dict[CorrelationType, int] = defaultdict(int)

                    for e1 in component:
                        for e2 in component:
                            if e1 < e2:
                                corr = self.get_correlation(e1, e2)
                                if corr:
                                    cluster_corrs.append(corr)
                                    type_counts[corr.correlation_type] += 1

                    if cluster_corrs:
                        coherence = np.mean([c.strength for c in cluster_corrs])
                        dominant_type = max(type_counts, key=type_counts.get) if type_counts else CorrelationType.BEHAVIORAL

                        if coherence >= min_coherence:
                            clusters.append(CorrelationCluster(
                                cluster_id=f"cluster_{len(clusters)}",
                                entities=component,
                                correlations=cluster_corrs,
                                coherence_score=float(coherence),
                                dominant_type=dominant_type
                            ))

        logger.info(f"Found {len(clusters)} correlation clusters")
        return sorted(clusters, key=lambda c: c.coherence_score, reverse=True)

    def compute_correlation_matrix(
        self,
        entity_ids: List[str]
    ) -> Tuple[np.ndarray, List[str]]:
        """
        Compute correlation matrix for entities.

        Args:
            entity_ids: List of entity IDs

        Returns:
            Tuple of (correlation matrix, entity IDs in order)
        """
        n = len(entity_ids)
        matrix = np.zeros((n, n))

        for i, e1 in enumerate(entity_ids):
            matrix[i, i] = 1.0  # Self-correlation
            for j, e2 in enumerate(entity_ids[i + 1:], i + 1):
                corr = self.get_correlation(e1, e2)
                if corr:
                    matrix[i, j] = corr.strength
                    matrix[j, i] = corr.strength

        return matrix, entity_ids

    def _prune_weak_correlations(self) -> int:
        """Remove weak correlations to free space."""
        threshold = self.min_strength * 1.5
        to_remove = [
            cid for cid, corr in self._correlations.items()
            if corr.strength < threshold
        ]

        for cid in to_remove:
            corr = self._correlations.pop(cid, None)
            if corr:
                self._source_index[corr.source_id].discard(cid)
                self._target_index[corr.target_id].discard(cid)

        logger.info(f"Pruned {len(to_remove)} weak correlations")
        return len(to_remove)

    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics."""
        correlations = list(self._correlations.values())
        strengths = [c.strength for c in correlations]

        type_counts = defaultdict(int)
        for c in correlations:
            type_counts[c.correlation_type.value] += 1

        return {
            'total_correlations': len(correlations),
            'total_entities': len(set(self._entity_vectors.keys()) |
                                  set(self._entity_features.keys()) |
                                  set(self._entity_timestamps.keys())),
            'avg_strength': float(np.mean(strengths)) if strengths else 0.0,
            'max_strength': float(max(strengths)) if strengths else 0.0,
            'min_strength': float(min(strengths)) if strengths else 0.0,
            'type_distribution': dict(type_counts)
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize engine state."""
        return {
            'correlations': {
                cid: corr.to_dict()
                for cid, corr in self._correlations.items()
            },
            'statistics': self.get_statistics()
        }
