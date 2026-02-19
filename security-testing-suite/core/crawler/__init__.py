"""
Smart Vulnerability Crawler module
"""

__all__ = ['SmartCrawler', 'SmartVulnerabilityCrawler']


def __getattr__(name):
    """Lazy import to avoid circular/double-import issues with -m execution."""
    if name in ('SmartCrawler', 'SmartVulnerabilityCrawler'):
        from .smart_vuln_crawler2 import SmartCrawler
        return SmartCrawler
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")