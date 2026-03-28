"""
Vulnerability Testing Orchestrator

Coordinates multiple security tools to test discovered parameters.

Flow:
1. Receives endpoints with predicted vulnerabilities from crawler
2. Routes each parameter to the appropriate specialized tool
3. Collects and normalizes results
4. Returns unified vulnerability report

Usage:
    from core.tools import VulnOrchestrator

    orchestrator = VulnOrchestrator(
        cookies={'PHPSESSID': 'xxx'},
        verbose=True
    )

    # Test endpoints discovered by crawler
    results = orchestrator.test_endpoints(endpoints)

    for result in results:
        if result.is_vulnerable:
            print(f"[{result.tool_name}] {result.vulnerability_type} on {result.parameter}")
"""

import logging
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from .base_wrapper import ToolResult, ToolNotFoundError, VulnSeverity
from .sqlmap_wrapper import SqlmapWrapper
from .xsstrike_wrapper import XSStrikeWrapper
from .commix_wrapper import CommixWrapper

logger = logging.getLogger(__name__)


@dataclass
class ToolConfig:
    """Configuration for a specific tool"""
    enabled: bool = True
    timeout: int = 300
    extra_args: Dict[str, Any] = None


class VulnOrchestrator:
    """
    Orchestrates vulnerability testing using specialized tools.

    Maps vulnerability types to the most appropriate tool:
    - sqli → sqlmap
    - xss → XSStrike (or custom)
    - rce → commix
    - lfi/ssti/xxe → custom detection
    """

    VULN_TO_TOOL = {
        'sqli': 'sqlmap',
        'xss': 'xsstrike',
        'rce': 'commix',
        # These use custom detection (no specialized tool)
        'lfi': 'custom',
        'ssti': 'custom',
        'xxe': 'custom',
        'open_redirect': 'custom',
        'ldapi': 'custom',
    }

    def __init__(self,
                 cookies: Optional[Dict[str, str]] = None,
                 headers: Optional[Dict[str, str]] = None,
                 proxy: Optional[str] = None,
                 verbose: bool = False,
                 max_workers: int = 3,
                 tool_configs: Optional[Dict[str, ToolConfig]] = None):
        """
        Initialize orchestrator with shared configuration.

        Args:
            cookies: Session cookies to forward to all tools
            headers: Custom headers
            proxy: Proxy URL
            verbose: Enable verbose output
            max_workers: Max concurrent tool executions
            tool_configs: Per-tool configuration overrides
        """
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.proxy = proxy
        self.verbose = verbose
        self.max_workers = max_workers
        self.tool_configs = tool_configs or {}

        # Initialize tool wrappers
        self._tools: Dict[str, Any] = {}
        self._init_tools()

        # Statistics
        self.stats = {
            'total_tests': 0,
            'vulnerabilities_found': 0,
            'by_tool': {},
            'by_type': {},
        }

    def _init_tools(self):
        """Initialize available tool wrappers"""
        # SQLMap
        try:
            config = self.tool_configs.get('sqlmap', ToolConfig())
            if config.enabled:
                self._tools['sqlmap'] = SqlmapWrapper(
                    cookies=self.cookies,
                    headers=self.headers,
                    proxy=self.proxy,
                    timeout=config.timeout,
                    verbose=self.verbose,
                    **(config.extra_args or {})
                )
                if self._tools['sqlmap'].is_available():
                    logger.info("✓ sqlmap available")
                else:
                    logger.warning("✗ sqlmap not installed")
                    del self._tools['sqlmap']
        except Exception as e:
            logger.error(f"Failed to initialize sqlmap: {e}")

        # XSStrike
        try:
            config = self.tool_configs.get('xsstrike', ToolConfig())
            if config.enabled:
                self._tools['xsstrike'] = XSStrikeWrapper(
                    cookies=self.cookies,
                    headers=self.headers,
                    proxy=self.proxy,
                    timeout=config.timeout,
                    verbose=self.verbose,
                    **(config.extra_args or {})
                )
                if self._tools['xsstrike'].is_available():
                    logger.info("✓ xsstrike available")
                else:
                    logger.warning("✗ xsstrike not installed")
                    del self._tools['xsstrike']
        except Exception as e:
            logger.error(f"Failed to initialize xsstrike: {e}")

        # Commix
        try:
            config = self.tool_configs.get('commix', ToolConfig())
            if config.enabled:
                self._tools['commix'] = CommixWrapper(
                    cookies=self.cookies,
                    headers=self.headers,
                    proxy=self.proxy,
                    timeout=config.timeout,
                    verbose=self.verbose,
                    **(config.extra_args or {})
                )
                if self._tools['commix'].is_available():
                    logger.info("✓ commix available")
                else:
                    logger.warning("✗ commix not installed")
                    del self._tools['commix']
        except Exception as e:
            logger.error(f"Failed to initialize commix: {e}")

    def get_available_tools(self) -> List[str]:
        """Return list of available tool names"""
        return list(self._tools.keys())

    def test_parameter(self,
                       url: str,
                       parameter: str,
                       vuln_type: str,
                       method: str = "GET",
                       data: Optional[Dict[str, str]] = None) -> Optional[ToolResult]:
        """
        Test a single parameter for a specific vulnerability type.

        Args:
            url: Target URL
            parameter: Parameter name
            vuln_type: Vulnerability type (sqli, xss, rce, etc.)
            method: HTTP method
            data: POST data if applicable

        Returns:
            ToolResult if tested, None if no tool available
        """
        tool_name = self.VULN_TO_TOOL.get(vuln_type, 'custom')

        if tool_name == 'custom':
            # Custom detection handled by crawler
            return None

        tool = self._tools.get(tool_name)
        if not tool:
            logger.debug(f"Tool {tool_name} not available for {vuln_type}")
            return None

        self.stats['total_tests'] += 1

        try:
            result = tool.scan(url, parameter, method, data)

            # Update statistics
            tool_stats = self.stats['by_tool'].setdefault(tool_name, {'tests': 0, 'vulns': 0})
            tool_stats['tests'] += 1

            type_stats = self.stats['by_type'].setdefault(vuln_type, {'tests': 0, 'vulns': 0})
            type_stats['tests'] += 1

            if result.is_vulnerable:
                self.stats['vulnerabilities_found'] += 1
                tool_stats['vulns'] += 1
                type_stats['vulns'] += 1

            return result

        except Exception as e:
            logger.error(f"Error testing {parameter} with {tool_name}: {e}")
            return None

    def test_endpoints(self,
                       endpoints: List[Dict[str, Any]],
                       parallel: bool = True) -> List[ToolResult]:
        """
        Test all parameters in discovered endpoints.

        Args:
            endpoints: List of endpoint dicts from crawler with format:
                {
                    'url': 'http://...',
                    'method': 'GET',
                    'parameters': [
                        {
                            'name': 'id',
                            'location': 'query',
                            'predicted_vulns': [
                                {'type': 'sqli', 'confidence': 70},
                                ...
                            ]
                        }
                    ]
                }
            parallel: Run tests in parallel

        Returns:
            List of ToolResult for all tests
        """
        results = []
        test_queue = []

        # Build queue of tests to run
        for endpoint in endpoints:
            url = endpoint.get('url', '')
            method = endpoint.get('method', 'GET')

            for param in endpoint.get('parameters', []):
                param_name = param.get('name', '')
                predicted_vulns = param.get('predicted_vulns', [])

                for vuln in predicted_vulns:
                    vuln_type = vuln.get('type', '')
                    confidence = vuln.get('confidence', 0)

                    # Only test high-confidence predictions with external tools
                    # (to avoid wasting time on unlikely vulns)
                    if confidence >= 50:
                        test_queue.append({
                            'url': url,
                            'parameter': param_name,
                            'vuln_type': vuln_type,
                            'method': method,
                            'data': None,
                        })

        logger.info(f"Testing {len(test_queue)} parameter/vulnerability combinations")

        if parallel and len(test_queue) > 1:
            results = self._test_parallel(test_queue)
        else:
            results = self._test_sequential(test_queue)

        return results

    def _test_sequential(self, test_queue: List[Dict]) -> List[ToolResult]:
        """Run tests sequentially"""
        results = []
        for test in test_queue:
            result = self.test_parameter(
                url=test['url'],
                parameter=test['parameter'],
                vuln_type=test['vuln_type'],
                method=test['method'],
                data=test['data']
            )
            if result:
                results.append(result)

                if self.verbose and result.is_vulnerable:
                    print(f"  🎯 [{result.tool_name}] {result.vulnerability_type.upper()} "
                          f"on {result.parameter}: {result.technique}")

        return results

    def _test_parallel(self, test_queue: List[Dict]) -> List[ToolResult]:
        """Run tests in parallel"""
        results = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for test in test_queue:
                future = executor.submit(
                    self.test_parameter,
                    url=test['url'],
                    parameter=test['parameter'],
                    vuln_type=test['vuln_type'],
                    method=test['method'],
                    data=test['data']
                )
                futures[future] = test

            for future in as_completed(futures):
                test = futures[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)

                        if self.verbose and result.is_vulnerable:
                            print(f"  🎯 [{result.tool_name}] {result.vulnerability_type.upper()} "
                                  f"on {test['parameter']}: {result.technique}")

                except Exception as e:
                    logger.error(f"Test failed for {test['parameter']}: {e}")

        return results

    def get_statistics(self) -> Dict:
        """Return testing statistics"""
        return self.stats

    def print_summary(self):
        """Print summary of testing results"""
        print("\n" + "=" * 50)
        print("VULNERABILITY TESTING SUMMARY")
        print("=" * 50)
        print(f"Total tests: {self.stats['total_tests']}")
        print(f"Vulnerabilities found: {self.stats['vulnerabilities_found']}")

        if self.stats['by_tool']:
            print("\nBy Tool:")
            for tool, stats in self.stats['by_tool'].items():
                print(f"  {tool}: {stats['vulns']}/{stats['tests']} "
                      f"({100*stats['vulns']/max(1,stats['tests']):.1f}%)")

        if self.stats['by_type']:
            print("\nBy Type:")
            for vtype, stats in self.stats['by_type'].items():
                print(f"  {vtype}: {stats['vulns']}/{stats['tests']} "
                      f"({100*stats['vulns']/max(1,stats['tests']):.1f}%)")

        print("=" * 50)
