"""
SQLMap Wrapper

Integrates sqlmap for professional SQL injection detection.

Features:
- Automatic technique detection (boolean, time-based, UNION, error-based)
- Database fingerprinting
- Session/cookie forwarding
- Risk/level configuration
- Output parsing into normalized format

Usage:
    wrapper = SqlmapWrapper(cookies={'PHPSESSID': 'xxx'})
    result = wrapper.scan(
        url='http://target/page.php?id=1',
        parameter='id'
    )
    if result.is_vulnerable:
        print(f"SQLi found: {result.technique}")
"""

import os
import json
import re
import tempfile
from typing import Dict, List, Optional, Any
from .base_wrapper import ToolWrapper, ToolResult, VulnSeverity, logger


class SqlmapWrapper(ToolWrapper):
    """
    Wrapper for sqlmap SQL injection scanner.

    Sqlmap is the de-facto standard for SQL injection detection and exploitation.
    This wrapper provides a clean interface for integration with the crawler.
    """

    tool_name = "sqlmap"
    tool_commands = ["sqlmap", "sqlmap.py", "python3 -m sqlmap"]

    def __init__(self,
                 cookies: Optional[Dict[str, str]] = None,
                 headers: Optional[Dict[str, str]] = None,
                 proxy: Optional[str] = None,
                 timeout: int = 300,
                 verbose: bool = False,
                 level: int = 1,
                 risk: int = 1,
                 threads: int = 1,
                 technique: str = "BEUSTQ",
                 tamper: Optional[List[str]] = None):
        """
        Initialize SQLMap wrapper.

        Args:
            level: Level of tests (1-5, higher = more tests)
            risk: Risk of tests (1-3, higher = more aggressive)
            threads: Number of concurrent requests
            technique: SQLi techniques to test:
                B = Boolean-based blind
                E = Error-based
                U = UNION query-based
                S = Stacked queries
                T = Time-based blind
                Q = Inline queries
            tamper: List of tamper scripts to use
        """
        super().__init__(cookies, headers, proxy, timeout, verbose)
        self.level = min(5, max(1, level))
        self.risk = min(3, max(1, risk))
        self.threads = threads
        self.technique = technique
        self.tamper = tamper or []

    def get_install_instructions(self) -> str:
        return """
SQLMap Installation:

Option 1 - pip:
    pip install sqlmap

Option 2 - apt (Debian/Ubuntu):
    sudo apt install sqlmap

Option 3 - git:
    git clone https://github.com/sqlmapproject/sqlmap.git
    cd sqlmap
    python3 sqlmap.py --version

Official site: https://sqlmap.org/
"""

    def _run_scan(self,
                  url: str,
                  parameter: str,
                  method: str,
                  data: Optional[Dict[str, str]]) -> ToolResult:
        """
        Run sqlmap scan on target parameter.
        """
        tool_path = self.get_tool_path()
        output_file = os.path.join(self._temp_dir, "sqlmap_output.json")

        # Build command
        args = [tool_path]

        # Target
        if method.upper() == "POST" and data:
            args.extend(["-u", url])
            args.extend(["--data", "&".join(f"{k}={v}" for k, v in data.items())])
        else:
            # Ensure parameter is in URL for GET
            if parameter not in url:
                separator = "&" if "?" in url else "?"
                args.extend(["-u", f"{url}{separator}{parameter}=test"])
            else:
                args.extend(["-u", url])

        # Specify parameter to test
        args.extend(["-p", parameter])

        # Configuration
        args.extend(["--level", str(self.level)])
        args.extend(["--risk", str(self.risk)])
        args.extend(["--threads", str(self.threads)])
        args.extend(["--technique", self.technique])

        # Cookies
        if self.cookies:
            args.extend(["--cookie", self._build_cookie_string()])

        # Headers
        args.extend(self._build_header_args())

        # Proxy
        if self.proxy:
            args.extend(["--proxy", self.proxy])

        # Tamper scripts
        for tamper in self.tamper:
            args.extend(["--tamper", tamper])

        # Output format
        args.extend(["--batch"])  # Non-interactive
        args.extend(["--output-dir", self._temp_dir])

        # Fingerprint database
        args.extend(["--fingerprint"])

        # Don't ask for further exploitation
        args.extend(["--answers", "follow=N,crack=N,dict=N,continue=N"])

        # Timeout per request
        args.extend(["--timeout", "10"])

        if self.verbose:
            args.extend(["-v", "2"])
        else:
            args.extend(["-v", "0"])

        # Run sqlmap
        result = self._run_process(args)

        # Parse output
        return self._parse_output(
            result.stdout + result.stderr,
            url,
            parameter
        )

    def _parse_output(self, output: str, url: str, parameter: str) -> ToolResult:
        """
        Parse sqlmap output to extract vulnerability information.
        """
        is_vulnerable = False
        technique = ""
        payload = ""
        evidence = ""
        db_type = ""
        confidence = 0.0

        # Check for vulnerability confirmation
        vuln_patterns = [
            (r"Parameter:\s*['\"]?(\w+)['\"]?\s*\((.*?)\)", "technique"),
            (r"Type:\s*(.*)", "type"),
            (r"Payload:\s*(.*)", "payload"),
        ]

        # Check if vulnerable
        if "is vulnerable" in output.lower() or "sqlmap identified the following injection" in output.lower():
            is_vulnerable = True
            confidence = 0.95

        # Extract technique
        technique_match = re.search(r"Type:\s*(\w+[\w\s\-]*)", output)
        if technique_match:
            technique = technique_match.group(1).strip()

        # Extract payload
        payload_match = re.search(r"Payload:\s*(.+?)(?:\n|$)", output)
        if payload_match:
            payload = payload_match.group(1).strip()

        # Extract database type
        db_patterns = [
            (r"back-end DBMS:\s*([\w\s]+)", "dbms"),
            (r"web server operating system:\s*([\w\s]+)", "os"),
            (r"web application technology:\s*([\w\s,]+)", "tech"),
        ]

        extra_data = {}
        for pattern, key in db_patterns:
            match = re.search(pattern, output, re.I)
            if match:
                extra_data[key] = match.group(1).strip()

        if "dbms" in extra_data:
            db_type = extra_data["dbms"]
            evidence = f"Database: {db_type}"

        # Determine severity based on technique
        severity = VulnSeverity.HIGH
        if "time-based" in technique.lower():
            severity = VulnSeverity.HIGH
        elif "union" in technique.lower():
            severity = VulnSeverity.CRITICAL
        elif "error-based" in technique.lower():
            severity = VulnSeverity.HIGH
        elif "boolean" in technique.lower():
            severity = VulnSeverity.MEDIUM

        # Check for errors
        if "connection timed out" in output.lower():
            evidence = "Connection timed out"
            confidence = 0.0
        elif "all tested parameters do not appear to be injectable" in output.lower():
            is_vulnerable = False
            confidence = 0.1
            evidence = "Parameter tested - not injectable"

        return ToolResult(
            tool_name=self.tool_name,
            vulnerability_type="sqli",
            is_vulnerable=is_vulnerable,
            confidence=confidence,
            severity=severity if is_vulnerable else VulnSeverity.INFO,
            url=url,
            parameter=parameter,
            method="GET",  # Will be updated by caller
            payload=payload,
            evidence=evidence or technique,
            technique=technique,
            raw_output=output[-2000:] if len(output) > 2000 else output,  # Last 2000 chars
            extra_data=extra_data,
            exploitable=is_vulnerable and "union" in technique.lower(),
        )

    def scan_batch(self, targets: List[Dict[str, Any]]) -> List[ToolResult]:
        """
        Scan multiple targets efficiently.

        Args:
            targets: List of dicts with 'url', 'parameter', 'method', 'data'

        Returns:
            List of ToolResult
        """
        results = []
        for target in targets:
            result = self.scan(
                url=target['url'],
                parameter=target['parameter'],
                method=target.get('method', 'GET'),
                data=target.get('data')
            )
            results.append(result)
        return results

    def quick_check(self, url: str, parameter: str) -> bool:
        """
        Quick check if parameter is injectable (level 1, risk 1).

        Returns True if likely vulnerable, False otherwise.
        """
        original_level = self.level
        original_risk = self.risk

        self.level = 1
        self.risk = 1
        self.timeout = 60  # Quick timeout

        result = self.scan(url, parameter)

        self.level = original_level
        self.risk = original_risk

        return result.is_vulnerable
