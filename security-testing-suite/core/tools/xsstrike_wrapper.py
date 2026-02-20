"""
XSStrike Wrapper

Integrates XSStrike for advanced XSS detection.

Features:
- Context-aware payload generation
- WAF bypass techniques
- DOM XSS detection
- Reflected and Stored XSS
- Fuzzing mode

Usage:
    wrapper = XSStrikeWrapper(cookies={'PHPSESSID': 'xxx'})
    result = wrapper.scan(
        url='http://target/search.php?q=test',
        parameter='q'
    )
    if result.is_vulnerable:
        print(f"XSS found: {result.payload}")
"""

import os
import re
from typing import Dict, List, Optional, Any
from .base_wrapper import ToolWrapper, ToolResult, VulnSeverity, logger


class XSStrikeWrapper(ToolWrapper):
    """
    Wrapper for XSStrike XSS scanner.

    XSStrike is a powerful XSS detection tool with:
    - Intelligent payload generation
    - Context analysis
    - WAF detection and bypass
    """

    tool_name = "xsstrike"
    tool_commands = ["xsstrike", "xsstrike.py", "python3 -m xsstrike"]

    def __init__(self,
                 cookies: Optional[Dict[str, str]] = None,
                 headers: Optional[Dict[str, str]] = None,
                 proxy: Optional[str] = None,
                 timeout: int = 120,
                 verbose: bool = False,
                 skip_dom: bool = False,
                 blind: bool = False,
                 fuzzer: bool = False):
        """
        Initialize XSStrike wrapper.

        Args:
            skip_dom: Skip DOM XSS scanning
            blind: Enable blind XSS mode
            fuzzer: Enable fuzzing mode
        """
        super().__init__(cookies, headers, proxy, timeout, verbose)
        self.skip_dom = skip_dom
        self.blind = blind
        self.fuzzer = fuzzer

    def get_install_instructions(self) -> str:
        return """
XSStrike Installation:

Option 1 - pip:
    pip install xsstrike

Option 2 - git:
    git clone https://github.com/s0md3v/XSStrike.git
    cd XSStrike
    pip install -r requirements.txt
    python3 xsstrike.py --help

Official repo: https://github.com/s0md3v/XSStrike
"""

    def _run_scan(self,
                  url: str,
                  parameter: str,
                  method: str,
                  data: Optional[Dict[str, str]]) -> ToolResult:
        """
        Run XSStrike scan on target parameter.
        """
        tool_path = self.get_tool_path()

        # Build command
        args = [tool_path]

        # Target URL
        if method.upper() == "POST" and data:
            args.extend(["-u", url])
            args.extend(["--data", "&".join(f"{k}={v}" for k, v in data.items())])
        else:
            # Ensure parameter is in URL
            if parameter not in url:
                separator = "&" if "?" in url else "?"
                args.extend(["-u", f"{url}{separator}{parameter}=test"])
            else:
                args.extend(["-u", url])

        # Cookies
        if self.cookies:
            cookie_file = os.path.join(self._temp_dir, "cookies.txt")
            with open(cookie_file, 'w') as f:
                for k, v in self.cookies.items():
                    f.write(f"{k}={v}\n")
            args.extend(["--cookies", cookie_file])

        # Headers
        if self.headers:
            header_file = os.path.join(self._temp_dir, "headers.txt")
            with open(header_file, 'w') as f:
                for k, v in self.headers.items():
                    f.write(f"{k}: {v}\n")
            args.extend(["--headers", header_file])

        # Proxy
        if self.proxy:
            args.extend(["--proxy", self.proxy])

        # Options
        if self.skip_dom:
            args.append("--skip-dom")

        if self.blind:
            args.append("--blind")

        if self.fuzzer:
            args.append("--fuzzer")

        # Timeout
        args.extend(["--timeout", str(min(30, self.timeout))])

        # Run
        result = self._run_process(args)

        return self._parse_output(
            result.stdout + result.stderr,
            url,
            parameter
        )

    def _parse_output(self, output: str, url: str, parameter: str) -> ToolResult:
        """
        Parse XSStrike output to extract vulnerability information.
        """
        is_vulnerable = False
        payload = ""
        evidence = ""
        context = ""
        confidence = 0.0
        extra_data = {}

        # Check for vulnerability confirmation
        vuln_indicators = [
            "Payload:",
            "XSS vulnerability found",
            "[+]",
            "Vulnerable",
        ]

        for indicator in vuln_indicators:
            if indicator.lower() in output.lower():
                is_vulnerable = True
                confidence = 0.85
                break

        # Extract payload
        payload_patterns = [
            r"Payload:\s*(.+?)(?:\n|$)",
            r"\[PAYLOAD\]\s*(.+?)(?:\n|$)",
            r"Vector:\s*(.+?)(?:\n|$)",
        ]

        for pattern in payload_patterns:
            match = re.search(pattern, output, re.I)
            if match:
                payload = match.group(1).strip()
                break

        # Extract context
        context_match = re.search(r"Context:\s*(\w+)", output, re.I)
        if context_match:
            context = context_match.group(1)
            extra_data['context'] = context

        # Check for WAF detection
        if "WAF" in output.upper() or "firewall" in output.lower():
            extra_data['waf_detected'] = True
            evidence = "WAF detected"

        # Check for DOM XSS
        if "DOM" in output.upper():
            extra_data['dom_xss'] = True
            evidence = "DOM-based XSS"

        # Reflection analysis
        reflection_match = re.search(r"Reflection:\s*(\d+)", output, re.I)
        if reflection_match:
            extra_data['reflection_count'] = int(reflection_match.group(1))

        # Determine severity
        severity = VulnSeverity.MEDIUM
        if is_vulnerable:
            if extra_data.get('dom_xss'):
                severity = VulnSeverity.HIGH
            elif "script" in payload.lower():
                severity = VulnSeverity.HIGH
            else:
                severity = VulnSeverity.MEDIUM

        # Check for errors
        if "error" in output.lower() and not is_vulnerable:
            evidence = "Scan completed with errors"

        if "no vulnerability found" in output.lower():
            is_vulnerable = False
            confidence = 0.1
            evidence = "No XSS vulnerability found"

        return ToolResult(
            tool_name=self.tool_name,
            vulnerability_type="xss",
            is_vulnerable=is_vulnerable,
            confidence=confidence,
            severity=severity if is_vulnerable else VulnSeverity.INFO,
            url=url,
            parameter=parameter,
            method="GET",
            payload=payload,
            evidence=evidence or f"Context: {context}" if context else "",
            technique="reflected" if not extra_data.get('dom_xss') else "dom",
            raw_output=output[-2000:] if len(output) > 2000 else output,
            extra_data=extra_data,
            exploitable=is_vulnerable,
        )

    def scan_dom(self, url: str) -> ToolResult:
        """
        Specifically scan for DOM-based XSS.
        """
        tool_path = self.get_tool_path()

        args = [tool_path, "-u", url, "--dom"]

        if self.cookies:
            args.extend(["--cookie", self._build_cookie_string()])

        result = self._run_process(args)

        return self._parse_output(result.stdout + result.stderr, url, "DOM")
