"""
Application Stack Traceroute module
"""

__all__ = ['ProgressiveStackAnalyzer']


def __getattr__(name):
    """Lazy import to avoid circular/double-import issues with -m execution."""
    if name == 'ProgressiveStackAnalyzer':
        from .application_traceroute_v3_5 import ProgressiveStackAnalyzer
        return ProgressiveStackAnalyzer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
