"""
Extensions module - Enhanced analysis capabilities for Security Testing Suite v4.0

Packages:
- response: CausalResponseAnalyzer for bypass verification
- vulnerability: CausalVulnerabilityAnalyzer + ExtendedAnalyzers
- taxonomy: SelfLearningTaxonomy for CWE/OWASP mapping
- payload_manager: Intelligent wordlist + analyzer integration
"""

from .response import CausalResponseAnalyzer
from .vulnerability import CausalVulnerabilityAnalyzer
from .vulnerability.extended_analyzers import ExtendedAnalyzerRegistry
from .taxonomy import SelfLearningTaxonomy

# PayloadManager import may fail if dependencies missing
try:
    from .payload_manager import (
        PayloadManager,
        VulnerabilityInferencer,
        WordlistLoader,
        ParameterContext,
        TestingPlan,
        PayloadResult
    )
    PAYLOAD_MANAGER_AVAILABLE = True
except ImportError:
    PAYLOAD_MANAGER_AVAILABLE = False

__all__ = [
    # Core analyzers
    'CausalResponseAnalyzer',
    'CausalVulnerabilityAnalyzer',
    'ExtendedAnalyzerRegistry',
    'SelfLearningTaxonomy',

    # Payload manager (if available)
    'PayloadManager',
    'VulnerabilityInferencer',
    'WordlistLoader',
    'ParameterContext',
    'TestingPlan',
    'PayloadResult',

    # Availability flag
    'PAYLOAD_MANAGER_AVAILABLE'
]

__version__ = "4.0.0"
