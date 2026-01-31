"""
modules.taxonomy - Self-learning vulnerability taxonomy

This module provides adaptive categorization using clustering and pattern learning.
"""

from .adaptive_taxonomy import (
    SelfLearningTaxonomy,
    TaxonomyNode,
    TaxonomyLevel,
    ClassificationResult,
)

__all__ = [
    'SelfLearningTaxonomy',
    'TaxonomyNode',
    'TaxonomyLevel',
    'ClassificationResult',
]
