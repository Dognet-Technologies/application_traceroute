"""
core.behavioral - Behavioral analysis components

This module provides differential causal analysis for security testing.
"""

from .differential_analyzer import (
    DifferentialCausalAnalyzer,
    PerturbationType,
    PerturbationResult,
    AnalysisResult,
)

__all__ = [
    'DifferentialCausalAnalyzer',
    'PerturbationType',
    'PerturbationResult',
    'AnalysisResult',
]
