"""
core.correlation - Hybrid correlation engine

This module provides correlation analysis combining graph-based causal
reasoning with cosine similarity and temporal analysis.
"""

from .hybrid_correlator import (
    HybridCorrelationEngine,
    Correlation,
    CorrelationType,
    CorrelationEvidence,
    CorrelationCluster,
)

__all__ = [
    'HybridCorrelationEngine',
    'Correlation',
    'CorrelationType',
    'CorrelationEvidence',
    'CorrelationCluster',
]
