"""
Smart Vulnerability Crawler module
"""
from .smart_vuln_crawler2 import SmartCrawler

# Alias per backward compatibility
SmartVulnerabilityCrawler = SmartCrawler

__all__ = ['SmartCrawler', 'SmartVulnerabilityCrawler']