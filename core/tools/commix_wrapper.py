"""
Commix Wrapper

Integrates Commix for command injection detection and exploitation.

Features:
- Multiple injection techniques (classic, eval-based, time-based, file-based)
- OS command execution
- Reverse shell capabilities
- Tamper script support
- WAF bypass

Usage:
    wrapper = CommixWrapper(cookies={'PHPSESSID': 'xxx'})
    result = wrapper.scan(
        url='http://target/ping.php?ip=127.0.0.1',
        parameter='ip'
    )
    if result.is_vulnerable:
        print(f"Command Injection found: {result.technique}")
"""

import os
import re
from typing import Dict, List, Optional, Any
from .base_wrapper import ToolWrapper, ToolResult, VulnSeverity, logger


class CommixWrapper(ToolWrapper):
    """
    Wrapper for Commix command injection scanner.

    Commix is designed to detect and exploit command injection vulnerabilities.
    """

    tool_name = "commix"
    tool_commands = ["commix", "commix.py", "python3 -m commix"]

    def __init__(self,
                 cookies: Optional[Dict[str, str]] = None,
                 headers: Optional[Dict[str, str]] = None,
                 proxy: Optional[str] = None,
                 timeout: int = 300,
                 verbose: bool = False,
                 level: int = 1,
                 technique: str = "classic,eval-based,time-based,file-based",
                 os_type: Optional[str] = None):
        """
        Initialize Commix wrapper.

        Args:
            level: Level of tests (1-3)
            technique: Injection techniques to test
            os_type: Target OS (unix, windows) - auto-detected if None
        """
        super().__init__(cookies, headers, proxy, timeout, verbose)
        self.level = min(3, max(1, level))
        self.technique = technique
        self.os_type = os_type

    def get_install_instructions(self) -> str:
        return """
Commix Installation:

Option 1 - pip:
    pip install commix

Option 2 - apt (Kali/Debian):
    sudo apt install commix

Option 3 - git:
    git clone https://github.com/commixproject/commix.git
    cd commix
    python3 commix.py --help

Official repo: https://github.com/commixproject/commix
"""

    def _run_scan(self,
                  url: str,
                  parameter: str,
                  method: str,
                  data: Optional[Dict[str, str]]) -> ToolResult:
        """
        Run Commix scan on target parameter.
        """
        tool_path = self.get_tool_path()

        # Build command
        args = [tool_path]

        # Target
        if method.upper() == "POST" and data:
            args.extend(["-u", url])
            args.extend(["--data", "&".join(f"{k}={v}" for k, v in data.items())])
        else:
            if parameter not in url:
                separator = "&" if "?" in url else "?"
                args.extend(["-u", f"{url}{separator}{parameter}=test"])
            else:
                args.extend(["-u", url])

        # Parameter to test
        args.extend(["-p", parameter])

        # Level
        args.extend(["--level", str(self.level)])

        # Techniques
        args.extend(["--technique", self.technique])

        # OS type
        if self.os_type:
            args.extend(["--os", self.os_type])

        # Cookies
        if self.cookies:
            args.extend(["--cookie", self._build_cookie_string()])

        # Headers
        for key, value in self.headers.items():
            args.extend(["--header", f"{key}: {value}"])

        # Proxy
        if self.proxy:
            args.extend(["--proxy", self.proxy])

        # Batch mode (non-interactive)
        args.append("--batch")

        # Timeout
        args.extend(["--timeout", str(min(30, self.timeout // 10))])

        if self.verbose:
            args.extend(["-v", "2"])

        # Run
        result = self._run_process(args)

        return self._parse_output(
            result.stdout + result.stderr,
            url,
            parameter
        )

    def _parse_output(self, output: str, url: str, parameter: str) -> ToolResult:
        """
        Parse Commix output to extract vulnerability information.
        """
        is_vulnerable = False
        technique = ""
        payload = ""
        evidence = ""
        os_detected = ""
        confidence = 0.0
        extra_data = {}

        # Check for vulnerability confirmation
        vuln_patterns = [
            r"is vulnerable",
            r"injection point",
            r"\[\+\].*injectable",
            r"The parameter.*appears to be injectable",
        ]

        for pattern in vuln_patterns:
            if re.search(pattern, output, re.I):
                is_vulnerable = True
                confidence = 0.90
                break

        # Extract technique
        technique_patterns = [
            (r"classic.*injection", "classic"),
            (r"eval-based.*injection", "eval-based"),
            (r"time-based.*injection", "time-based"),
            (r"file-based.*injection", "file-based"),
        ]

        techniques_found = []
        for pattern, tech_name in technique_patterns:
            if re.search(pattern, output, re.I):
                techniques_found.append(tech_name)

        technique = ", ".join(techniques_found) if techniques_found else ""

        # Extract payload
        payload_match = re.search(r"Payload:\s*(.+?)(?:\n|$)", output, re.I)
        if payload_match:
            payload = payload_match.group(1).strip()

        # Extract OS information
        os_patterns = [
            (r"Target operating system:\s*(\w+)", "os"),
            (r"Current user:\s*(\w+)", "user"),
            (r"Hostname:\s*(\S+)", "hostname"),
        ]

        for pattern, key in os_patterns:
            match = re.search(pattern, output, re.I)
            if match:
                extra_data[key] = match.group(1)
                if key == "os":
                    os_detected = match.group(1)

        if os_detected:
            evidence = f"OS detected: {os_detected}"

        # Determine severity
        severity = VulnSeverity.CRITICAL  # Command injection is always critical
        if not is_vulnerable:
            severity = VulnSeverity.INFO

        # Check for errors
        if "no parameter appears to be injectable" in output.lower():
            is_vulnerable = False
            confidence = 0.1
            evidence = "No command injection found"

        if "connection timed out" in output.lower():
            evidence = "Connection timed out"
            confidence = 0.0

        return ToolResult(
            tool_name=self.tool_name,
            vulnerability_type="rce",
            is_vulnerable=is_vulnerable,
            confidence=confidence,
            severity=severity,
            url=url,
            parameter=parameter,
            method="GET",
            payload=payload,
            evidence=evidence or technique,
            technique=technique,
            raw_output=output[-2000:] if len(output) > 2000 else output,
            extra_data=extra_data,
            exploitable=is_vulnerable,  # Command injection is exploitable by definition
        )

    def execute_command(self, url: str, parameter: str, command: str) -> str:
        """
        Execute a command on a confirmed vulnerable target.

        WARNING: Only use on authorized targets!

        Returns:
            Command output
        """
        tool_path = self.get_tool_path()

        args = [
            tool_path,
            "-u", url,
            "-p", parameter,
            "--batch",
            "--os-cmd", command,
        ]

        if self.cookies:
            args.extend(["--cookie", self._build_cookie_string()])

        result = self._run_process(args, timeout=60)

        # Extract command output
        output_match = re.search(
            r"command output[:\s]*\n(.+?)(?:\n\n|\Z)",
            result.stdout,
            re.I | re.S
        )

        if output_match:
            return output_match.group(1).strip()

        return result.stdout
