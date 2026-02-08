"""
Security Testing Tools

This module provides vulnerability detection capabilities:

1. Native Detection (pure Python - no external tools):
   - VulnDetector: Unified detector for SQLi, XSS, etc.
   - SQLiDetector: SQL injection with time-based, boolean-based, error-based
   - XSSDetector: XSS with reflection and context analysis

2. External Tool Wrappers (optional - if tools installed):
   - SqlmapWrapper: sqlmap integration
   - XSStrikeWrapper: XSStrike integration
   - CommixWrapper: commix integration
   - VulnOrchestrator: Coordinates all tools

Native detection is preferred as it requires no external dependencies.
"""

# Native detection (pure Python)
from .native_detector import (
    VulnDetector,
    SQLiDetector,
    XSSDetector,
    DetectionResult,
    DetectionTechnique,
    VulnType,
    PayloadDB,
)

# External tool wrappers (optional)
from .base_wrapper import ToolWrapper, ToolResult, ToolNotFoundError, VulnSeverity
from .sqlmap_wrapper import SqlmapWrapper
from .xsstrike_wrapper import XSStrikeWrapper
from .commix_wrapper import CommixWrapper
from .orchestrator import VulnOrchestrator

__all__ = [
    # Native (recommended)
    'VulnDetector',
    'SQLiDetector',
    'XSSDetector',
    'DetectionResult',
    'DetectionTechnique',
    'VulnType',
    'PayloadDB',
    # External wrappers
    'ToolWrapper',
    'ToolResult',
    'ToolNotFoundError',
    'VulnSeverity',
    'SqlmapWrapper',
    'XSStrikeWrapper',
    'CommixWrapper',
    'VulnOrchestrator',
]
