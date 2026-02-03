"""
Extensions module - Enhanced analysis capabilities for Security Testing Suite v4.0

Packages:
- response: CausalResponseAnalyzer for bypass verification
- vulnerability: CausalVulnerabilityAnalyzer + ExtendedAnalyzers
- taxonomy: SelfLearningTaxonomy for CWE/OWASP mapping
- payload_manager: Intelligent wordlist + analyzer integration
- internal_wordlist: Self-learning persistent wordlist with mutations
- active_scanner: Burp Suite-level intelligent vulnerability detection
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

# InternalWordlistManager import
try:
    from .internal_wordlist import (
        InternalWordlistManager,
        CombinedWordlistProvider,
        PayloadMutationEngine,
        LearnedPayload,
        MutationResult
    )
    INTERNAL_WORDLIST_AVAILABLE = True
except ImportError:
    INTERNAL_WORDLIST_AVAILABLE = False

# ActiveScanner import
try:
    from .active_scanner import (
        ActiveScanner,
        ResponseDifferentialAnalyzer,
        ReflectionDetector,
        BehaviorProber,
        TimingAnalyzer,
        InjectionContext,
        VulnSusceptibility,
        InjectionPointAnalysis,
        VulnerabilitySusceptibility,
        ReflectionPoint
    )
    ACTIVE_SCANNER_AVAILABLE = True
except ImportError:
    ACTIVE_SCANNER_AVAILABLE = False

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

    # Internal wordlist (if available)
    'InternalWordlistManager',
    'CombinedWordlistProvider',
    'PayloadMutationEngine',
    'LearnedPayload',
    'MutationResult',

    # Active Scanner (if available)
    'ActiveScanner',
    'ResponseDifferentialAnalyzer',
    'ReflectionDetector',
    'BehaviorProber',
    'TimingAnalyzer',
    'InjectionContext',
    'VulnSusceptibility',
    'InjectionPointAnalysis',
    'VulnerabilitySusceptibility',
    'ReflectionPoint',

    # Availability flags
    'PAYLOAD_MANAGER_AVAILABLE',
    'INTERNAL_WORDLIST_AVAILABLE',
    'ACTIVE_SCANNER_AVAILABLE'
]

__version__ = "4.0.0"
