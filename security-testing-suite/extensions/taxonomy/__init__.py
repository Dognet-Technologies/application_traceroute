"""
extensions/taxonomy/__init__.py

Self-learning taxonomy package for Security Testing Suite v4.0

Provides intelligent vulnerability classification with:
- CWE/OWASP mapping
- Pattern learning from confirmed vulnerabilities
- Attack chain analysis
- Context-aware severity scoring
"""

from .self_learning_taxonomy import (
    SelfLearningTaxonomy,
    TaxonomyDatabase,
    PatternLearner,
    AttackChainAnalyzer,
    TaxonomyCategory,
    SeverityLevel,
    VulnerabilityTaxon,
    LearnedPattern,
    ClassificationResult
)

__all__ = [
    # Main class
    'SelfLearningTaxonomy',

    # Supporting classes
    'TaxonomyDatabase',
    'PatternLearner',
    'AttackChainAnalyzer',

    # Enums
    'TaxonomyCategory',
    'SeverityLevel',

    # Data classes
    'VulnerabilityTaxon',
    'LearnedPattern',
    'ClassificationResult'
]

__version__ = "4.0.0"
