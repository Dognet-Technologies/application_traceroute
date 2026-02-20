"""
Base Wrapper for External Security Tools

Provides common functionality for all tool wrappers:
- Tool availability checking
- Process management
- Output parsing
- Result normalization
"""

import subprocess
import shutil
import json
import os
import tempfile
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum

logger = logging.getLogger(__name__)


class ToolNotFoundError(Exception):
    """Raised when a required tool is not installed"""
    pass


class VulnSeverity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ToolResult:
    """
    Normalized result from any security tool.

    Provides a common format regardless of which tool detected the vulnerability.
    """
    tool_name: str
    vulnerability_type: str
    is_vulnerable: bool
    confidence: float  # 0.0 - 1.0
    severity: VulnSeverity

    # Target info
    url: str
    parameter: str
    method: str = "GET"

    # Detection details
    payload: str = ""
    evidence: str = ""
    technique: str = ""  # e.g., "time-based blind", "error-based", "UNION"

    # Additional data from tool
    raw_output: str = ""
    extra_data: Dict[str, Any] = field(default_factory=dict)

    # Exploitation info (if available)
    exploitable: bool = False
    exploitation_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'tool_name': self.tool_name,
            'vulnerability_type': self.vulnerability_type,
            'is_vulnerable': self.is_vulnerable,
            'confidence': self.confidence,
            'severity': self.severity.value,
            'url': self.url,
            'parameter': self.parameter,
            'method': self.method,
            'payload': self.payload,
            'evidence': self.evidence,
            'technique': self.technique,
            'exploitable': self.exploitable,
            'exploitation_info': self.exploitation_info,
            'extra_data': self.extra_data,
        }


class ToolWrapper(ABC):
    """
    Abstract base class for security tool wrappers.

    Subclasses must implement:
    - tool_name: Name of the tool
    - tool_commands: List of possible command names (e.g., ['sqlmap', 'sqlmap.py'])
    - _run_scan(): Execute the actual scan
    - _parse_output(): Parse tool output into ToolResult
    """

    tool_name: str = "base"
    tool_commands: List[str] = []

    def __init__(self,
                 cookies: Optional[Dict[str, str]] = None,
                 headers: Optional[Dict[str, str]] = None,
                 proxy: Optional[str] = None,
                 timeout: int = 300,
                 verbose: bool = False):
        """
        Initialize tool wrapper.

        Args:
            cookies: Session cookies to forward to the tool
            headers: Custom headers to include
            proxy: Proxy URL (e.g., http://127.0.0.1:8080)
            timeout: Maximum time for scan in seconds
            verbose: Enable verbose output
        """
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.proxy = proxy
        self.timeout = timeout
        self.verbose = verbose
        self._tool_path: Optional[str] = None
        self._temp_dir = tempfile.mkdtemp(prefix=f"{self.tool_name}_")

    def __del__(self):
        """Cleanup temp directory"""
        try:
            import shutil
            if hasattr(self, '_temp_dir') and os.path.exists(self._temp_dir):
                shutil.rmtree(self._temp_dir)
        except Exception:
            pass

    def is_available(self) -> bool:
        """Check if the tool is installed and accessible"""
        return self.get_tool_path() is not None

    def get_tool_path(self) -> Optional[str]:
        """Find the tool executable path"""
        if self._tool_path:
            return self._tool_path

        for cmd in self.tool_commands:
            path = shutil.which(cmd)
            if path:
                self._tool_path = path
                return path

        # Check common installation paths
        common_paths = [
            f"/usr/bin/{self.tool_commands[0]}",
            f"/usr/local/bin/{self.tool_commands[0]}",
            f"/opt/{self.tool_name}/{self.tool_commands[0]}",
            os.path.expanduser(f"~/.local/bin/{self.tool_commands[0]}"),
        ]

        for path in common_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                self._tool_path = path
                return path

        return None

    def get_install_instructions(self) -> str:
        """Return installation instructions for the tool"""
        return f"Please install {self.tool_name}. Visit the official documentation for installation instructions."

    def _build_cookie_string(self) -> str:
        """Build cookie string for command line"""
        if not self.cookies:
            return ""
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def _build_header_args(self) -> List[str]:
        """Build header arguments for command line"""
        args = []
        for key, value in self.headers.items():
            args.extend(["--header", f"{key}: {value}"])
        return args

    def _run_process(self,
                     args: List[str],
                     timeout: Optional[int] = None) -> subprocess.CompletedProcess:
        """
        Run a subprocess with proper error handling.

        Args:
            args: Command arguments
            timeout: Override default timeout

        Returns:
            CompletedProcess result
        """
        timeout = timeout or self.timeout

        if self.verbose:
            logger.info(f"Running: {' '.join(args)}")

        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self._temp_dir
            )
            return result
        except subprocess.TimeoutExpired:
            logger.warning(f"{self.tool_name} timed out after {timeout}s")
            raise
        except Exception as e:
            logger.error(f"{self.tool_name} execution failed: {e}")
            raise

    def scan(self,
             url: str,
             parameter: str,
             method: str = "GET",
             data: Optional[Dict[str, str]] = None) -> ToolResult:
        """
        Scan a specific parameter for vulnerabilities.

        Args:
            url: Target URL
            parameter: Parameter to test
            method: HTTP method (GET/POST)
            data: POST data if applicable

        Returns:
            ToolResult with scan findings
        """
        if not self.is_available():
            raise ToolNotFoundError(
                f"{self.tool_name} not found. {self.get_install_instructions()}"
            )

        try:
            return self._run_scan(url, parameter, method, data)
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=self.tool_name,
                vulnerability_type="unknown",
                is_vulnerable=False,
                confidence=0.0,
                severity=VulnSeverity.INFO,
                url=url,
                parameter=parameter,
                method=method,
                evidence="Scan timed out",
            )
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return ToolResult(
                tool_name=self.tool_name,
                vulnerability_type="error",
                is_vulnerable=False,
                confidence=0.0,
                severity=VulnSeverity.INFO,
                url=url,
                parameter=parameter,
                method=method,
                evidence=f"Scan error: {str(e)}",
            )

    @abstractmethod
    def _run_scan(self,
                  url: str,
                  parameter: str,
                  method: str,
                  data: Optional[Dict[str, str]]) -> ToolResult:
        """
        Execute the actual scan. Must be implemented by subclasses.
        """
        pass

    @abstractmethod
    def _parse_output(self, output: str, url: str, parameter: str) -> ToolResult:
        """
        Parse tool output into ToolResult. Must be implemented by subclasses.
        """
        pass
