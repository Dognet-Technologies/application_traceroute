"""
extensions/response/__init__.py

Response analysis package for Security Testing Suite v4.0.1

Provides multi-level bypass verification with:
- Content semantic classification
- Protected content detection
- Causal layer analysis
- Behavioral fingerprinting
- Bayesian confidence scoring
"""

from .causal_response_analyzer import (
    CausalResponseAnalyzer,
    ContentClassifier,
    LayerIdentifier,
    BehavioralAnalyzer,
    ContentType,
    LayerType,
    VerificationResult,
    ContentAnalysisResult,
    BehavioralDifferential,
    create_mock_response
)

__all__ = [
    # Main analyzer
    'CausalResponseAnalyzer',

    # Sub-analyzers
    'ContentClassifier',
    'LayerIdentifier',
    'BehavioralAnalyzer',

    # Enums
    'ContentType',
    'LayerType',

    # Data classes
    'VerificationResult',
    'ContentAnalysisResult',
    'BehavioralDifferential',

    # Helpers
    'create_mock_response'
]

__version__ = "4.0.1"
