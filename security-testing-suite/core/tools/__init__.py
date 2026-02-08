"""
External Security Tools Integration

This module provides wrappers for external security testing tools:
- sqlmap: SQL Injection detection and exploitation
- commix: Command Injection detection
- XSStrike: XSS detection
- tplmap: SSTI detection

Each wrapper provides:
- Automatic tool detection and installation check
- Unified interface for vulnerability testing
- Result parsing and normalization
- Session/cookie forwarding from crawler
"""

from .base_wrapper import ToolWrapper, ToolResult, ToolNotFoundError, VulnSeverity
from .sqlmap_wrapper import SqlmapWrapper
from .xsstrike_wrapper import XSStrikeWrapper
from .commix_wrapper import CommixWrapper
from .orchestrator import VulnOrchestrator

__all__ = [
    'ToolWrapper',
    'ToolResult',
    'ToolNotFoundError',
    'VulnSeverity',
    'SqlmapWrapper',
    'XSStrikeWrapper',
    'CommixWrapper',
    'VulnOrchestrator',
]
