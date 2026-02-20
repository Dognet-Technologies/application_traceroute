#!/usr/bin/env python3
"""
Debug Logger v4.0 - Comprehensive Debug System for Security Testing Suite

Features:
- Request/Response logging with full headers and body
- Data flow tracking
- Performance metrics
- Authentication debugging
- Session state tracking
- Error context capture
- Structured JSON output for analysis

Usage:
    python3 crawler.py --debug https://target.com
    # Creates: debug_YYYYMMDD_HHMMSS.json

Author: Security Testing Suite
License: Authorized security research only
"""

import json
import time
import hashlib
import traceback
import threading
import sys
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from pathlib import Path
import logging
from io import StringIO
from contextlib import contextmanager


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class RequestLog:
    """Logged HTTP request"""
    id: str
    timestamp: str
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str]
    body_size: int
    cookies: Dict[str, str]
    auth_type: Optional[str]

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ResponseLog:
    """Logged HTTP response"""
    request_id: str
    timestamp: str
    status_code: int
    reason: str
    headers: Dict[str, str]
    body_preview: str  # First N chars
    body_size: int
    body_hash: str
    response_time: float
    redirects: List[str]
    cookies_set: Dict[str, str]

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class AuthEvent:
    """Authentication event log"""
    timestamp: str
    auth_type: str
    action: str  # setup, login_attempt, login_success, login_failure, session_check
    details: Dict[str, Any]
    success: bool
    error: Optional[str]

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ErrorLog:
    """Error event log"""
    timestamp: str
    error_type: str
    message: str
    traceback: str
    context: Dict[str, Any]
    request_id: Optional[str]

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class DataFlowEvent:
    """Data flow tracking event"""
    timestamp: str
    flow_type: str  # injection_point, reflection, transformation, validation
    source: str
    destination: str
    data_preview: str
    data_size: int
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class PerformanceMetric:
    """Performance measurement"""
    timestamp: str
    operation: str
    duration: float
    memory_before: Optional[int]
    memory_after: Optional[int]
    details: Dict[str, Any]

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class StepLog:
    """Generic step logging event"""
    timestamp: str
    step_name: str
    details: Dict[str, Any]
    success: bool

    def to_dict(self) -> Dict:
        return asdict(self)


# =============================================================================
# DEBUG LOGGER
# =============================================================================

class DebugLogger:
    """
    Comprehensive debug logger for security testing.
    Captures all I/O, data flows, and errors for analysis.
    """

    MAX_BODY_PREVIEW = 2000  # Max chars for body preview
    MAX_LOG_ENTRIES = 10000  # Max entries before auto-rotation

    def __init__(self, output_dir: str = None, enabled: bool = True):
        """
        Initialize debug logger.

        Args:
            output_dir: Directory for debug files (default: current dir)
            enabled: Whether debug logging is enabled
        """
        self.enabled = enabled
        self.output_dir = Path(output_dir) if output_dir else Path.cwd()
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.session_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_file = self.output_dir / f"debug_{self.session_id}.json"

        # Log storage
        self.requests: List[RequestLog] = []
        self.responses: List[ResponseLog] = []
        self.auth_events: List[AuthEvent] = []
        self.errors: List[ErrorLog] = []
        self.data_flows: List[DataFlowEvent] = []
        self.performance: List[PerformanceMetric] = []
        self.steps: List[StepLog] = []

        # State tracking
        self.session_state: Dict[str, Any] = {
            'authenticated': False,
            'auth_type': None,
            'cookies': {},
            'headers': {},
            'technologies': [],
        }

        # Metadata
        self.metadata: Dict[str, Any] = {
            'session_id': self.session_id,
            'start_time': datetime.now().isoformat(),
            'python_version': sys.version,
            'platform': sys.platform,
            'cwd': str(Path.cwd()),
        }

        # Request ID counter
        self._request_counter = 0
        self._lock = threading.Lock()

        # Console logging capture
        self._console_logs: List[str] = []
        self._original_stdout = None
        self._original_stderr = None

        if self.enabled:
            logging.info(f"Debug mode enabled. Output: {self.output_file}")

    def _generate_request_id(self) -> str:
        """Generate unique request ID"""
        with self._lock:
            self._request_counter += 1
            return f"REQ-{self.session_id}-{self._request_counter:05d}"

    def _truncate(self, text: str, max_len: int = None) -> str:
        """Truncate text to max length"""
        max_len = max_len or self.MAX_BODY_PREVIEW
        if text and len(text) > max_len:
            return text[:max_len] + f"... [TRUNCATED, total: {len(text)} chars]"
        return text or ""

    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Sanitize sensitive headers for logging"""
        sanitized = dict(headers) if headers else {}
        sensitive_patterns = ['authorization', 'cookie', 'x-api-key', 'api-key',
                             'token', 'secret', 'password', 'auth']

        for key in list(sanitized.keys()):
            key_lower = key.lower()
            for pattern in sensitive_patterns:
                if pattern in key_lower:
                    value = sanitized[key]
                    if len(value) > 20:
                        sanitized[key] = value[:10] + '...[REDACTED]...' + value[-5:]
                    else:
                        sanitized[key] = '[REDACTED]'
                    break

        return sanitized

    # -------------------------------------------------------------------------
    # REQUEST/RESPONSE LOGGING
    # -------------------------------------------------------------------------

    def log_request(self, method: str, url: str, headers: Dict = None,
                   body: Any = None, cookies: Dict = None,
                   auth_type: str = None) -> str:
        """
        Log an outgoing HTTP request.

        Returns:
            Request ID for correlation
        """
        if not self.enabled:
            return ""

        request_id = self._generate_request_id()

        # Process body
        body_str = None
        body_size = 0
        if body:
            if isinstance(body, bytes):
                body_str = body.decode('utf-8', errors='replace')
            elif isinstance(body, dict):
                body_str = json.dumps(body, default=str)
            else:
                body_str = str(body)
            body_size = len(body_str)
            body_str = self._truncate(body_str)

        log = RequestLog(
            id=request_id,
            timestamp=datetime.now().isoformat(),
            method=method.upper(),
            url=url,
            headers=self._sanitize_headers(headers or {}),
            body=body_str,
            body_size=body_size,
            cookies=self._sanitize_headers(cookies or {}),
            auth_type=auth_type
        )

        with self._lock:
            self.requests.append(log)

        return request_id

    def log_response(self, request_id: str, response, response_time: float = 0.0):
        """
        Log an HTTP response.

        Args:
            request_id: Correlating request ID
            response: requests.Response object
            response_time: Time taken for request
        """
        if not self.enabled:
            return

        # Get response body
        try:
            body = response.text
        except:
            body = "[BINARY OR DECODE ERROR]"

        body_hash = hashlib.md5(body.encode()).hexdigest() if body else ""

        # Get redirects
        redirects = [r.url for r in response.history] if hasattr(response, 'history') else []

        # Get cookies set by response
        cookies_set = {}
        if hasattr(response, 'cookies'):
            cookies_set = {k: self._truncate(v, 50) for k, v in response.cookies.items()}

        log = ResponseLog(
            request_id=request_id,
            timestamp=datetime.now().isoformat(),
            status_code=response.status_code,
            reason=response.reason if hasattr(response, 'reason') else "",
            headers=self._sanitize_headers(dict(response.headers)),
            body_preview=self._truncate(body),
            body_size=len(body) if body else 0,
            body_hash=body_hash,
            response_time=response_time,
            redirects=redirects,
            cookies_set=cookies_set
        )

        with self._lock:
            self.responses.append(log)

    # -------------------------------------------------------------------------
    # AUTHENTICATION LOGGING
    # -------------------------------------------------------------------------

    def log_auth_event(self, auth_type: str, action: str,
                      details: Dict = None, success: bool = True,
                      error: str = None):
        """Log an authentication event"""
        if not self.enabled:
            return

        event = AuthEvent(
            timestamp=datetime.now().isoformat(),
            auth_type=auth_type,
            action=action,
            details=details or {},
            success=success,
            error=error
        )

        with self._lock:
            self.auth_events.append(event)

            # Update session state
            if action == 'login_success':
                self.session_state['authenticated'] = True
                self.session_state['auth_type'] = auth_type
            elif action == 'login_failure':
                self.session_state['authenticated'] = False

    # -------------------------------------------------------------------------
    # ERROR LOGGING
    # -------------------------------------------------------------------------

    def log_error(self, error_type: str, message: str,
                 context: Dict = None, request_id: str = None,
                 exception: Exception = None):
        """Log an error event"""
        if not self.enabled:
            return

        tb = ""
        if exception:
            tb = traceback.format_exc()

        error = ErrorLog(
            timestamp=datetime.now().isoformat(),
            error_type=error_type,
            message=message,
            traceback=tb,
            context=context or {},
            request_id=request_id
        )

        with self._lock:
            self.errors.append(error)

    # -------------------------------------------------------------------------
    # DATA FLOW LOGGING
    # -------------------------------------------------------------------------

    def log_data_flow(self, flow_type: str, source: str, destination: str,
                     data: Any, metadata: Dict = None):
        """Log a data flow event"""
        if not self.enabled:
            return

        data_str = str(data) if data else ""

        event = DataFlowEvent(
            timestamp=datetime.now().isoformat(),
            flow_type=flow_type,
            source=source,
            destination=destination,
            data_preview=self._truncate(data_str, 500),
            data_size=len(data_str),
            metadata=metadata or {}
        )

        with self._lock:
            self.data_flows.append(event)

    # -------------------------------------------------------------------------
    # STEP LOGGING
    # -------------------------------------------------------------------------

    def log_step(self, step_name: str, details: Dict = None, success: bool = True):
        """Log a generic step event"""
        if not self.enabled:
            return

        step = StepLog(
            timestamp=datetime.now().isoformat(),
            step_name=step_name,
            details=details or {},
            success=success
        )

        with self._lock:
            self.steps.append(step)

    # -------------------------------------------------------------------------
    # PERFORMANCE LOGGING
    # -------------------------------------------------------------------------

    @contextmanager
    def measure_performance(self, operation: str, details: Dict = None):
        """Context manager to measure operation performance"""
        if not self.enabled:
            yield
            return

        start_time = time.time()
        memory_before = self._get_memory_usage()

        try:
            yield
        finally:
            end_time = time.time()
            memory_after = self._get_memory_usage()

            metric = PerformanceMetric(
                timestamp=datetime.now().isoformat(),
                operation=operation,
                duration=end_time - start_time,
                memory_before=memory_before,
                memory_after=memory_after,
                details=details or {}
            )

            with self._lock:
                self.performance.append(metric)

    def _get_memory_usage(self) -> Optional[int]:
        """Get current memory usage in bytes"""
        try:
            import psutil
            process = psutil.Process(os.getpid())
            return process.memory_info().rss
        except ImportError:
            return None

    # -------------------------------------------------------------------------
    # SESSION STATE
    # -------------------------------------------------------------------------

    def update_session_state(self, key: str, value: Any):
        """Update session state"""
        if not self.enabled:
            return

        with self._lock:
            self.session_state[key] = value

    def add_technology(self, tech: str):
        """Add detected technology"""
        if not self.enabled:
            return

        with self._lock:
            if tech not in self.session_state['technologies']:
                self.session_state['technologies'].append(tech)

    # -------------------------------------------------------------------------
    # OUTPUT
    # -------------------------------------------------------------------------

    def save(self):
        """Save all logs to JSON file"""
        if not self.enabled:
            return

        output = {
            'metadata': self.metadata,
            'session_state': self.session_state,
            'summary': {
                'total_requests': len(self.requests),
                'total_responses': len(self.responses),
                'total_errors': len(self.errors),
                'auth_events': len(self.auth_events),
                'data_flows': len(self.data_flows),
                'performance_metrics': len(self.performance),
                'steps': len(self.steps),
            },
            'requests': [r.to_dict() for r in self.requests[-self.MAX_LOG_ENTRIES:]],
            'responses': [r.to_dict() for r in self.responses[-self.MAX_LOG_ENTRIES:]],
            'auth_events': [e.to_dict() for e in self.auth_events],
            'errors': [e.to_dict() for e in self.errors],
            'data_flows': [f.to_dict() for f in self.data_flows[-self.MAX_LOG_ENTRIES:]],
            'performance': [p.to_dict() for p in self.performance],
            'steps': [s.to_dict() for s in self.steps[-self.MAX_LOG_ENTRIES:]],
            'end_time': datetime.now().isoformat(),
        }

        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False, default=str)

        logging.info(f"Debug log saved to: {self.output_file}")
        return str(self.output_file)

    def get_summary(self) -> Dict:
        """Get summary of logged data"""
        return {
            'output_file': str(self.output_file),
            'total_requests': len(self.requests),
            'total_responses': len(self.responses),
            'total_errors': len(self.errors),
            'session_state': self.session_state,
            'error_types': list(set(e.error_type for e in self.errors)),
        }


# =============================================================================
# DEBUG SESSION WRAPPER
# =============================================================================

class DebugSession:
    """
    Wrapper around requests.Session that automatically logs all I/O.
    """

    def __init__(self, session, debug_logger: DebugLogger):
        """
        Wrap a requests session with debug logging.

        Args:
            session: requests.Session to wrap
            debug_logger: DebugLogger instance
        """
        self._session = session
        self._logger = debug_logger

    def __getattr__(self, name):
        """Proxy attribute access to wrapped session"""
        return getattr(self._session, name)

    def _make_request(self, method: str, url: str, **kwargs) -> 'requests.Response':
        """Make request with logging"""
        # Log request
        request_id = self._logger.log_request(
            method=method,
            url=url,
            headers=kwargs.get('headers', self._session.headers),
            body=kwargs.get('data') or kwargs.get('json'),
            cookies={c.name: c.value for c in self._session.cookies},
            auth_type=self._logger.session_state.get('auth_type')
        )

        # Make actual request
        start_time = time.time()
        try:
            method_func = getattr(self._session, method.lower())
            response = method_func(url, **kwargs)
            response_time = time.time() - start_time

            # Log response
            self._logger.log_response(request_id, response, response_time)

            return response

        except Exception as e:
            self._logger.log_error(
                error_type='request_error',
                message=str(e),
                context={'url': url, 'method': method},
                request_id=request_id,
                exception=e
            )
            raise

    def get(self, url: str, **kwargs):
        return self._make_request('GET', url, **kwargs)

    def post(self, url: str, **kwargs):
        return self._make_request('POST', url, **kwargs)

    def put(self, url: str, **kwargs):
        return self._make_request('PUT', url, **kwargs)

    def delete(self, url: str, **kwargs):
        return self._make_request('DELETE', url, **kwargs)

    def head(self, url: str, **kwargs):
        return self._make_request('HEAD', url, **kwargs)

    def options(self, url: str, **kwargs):
        return self._make_request('OPTIONS', url, **kwargs)

    def patch(self, url: str, **kwargs):
        return self._make_request('PATCH', url, **kwargs)


# =============================================================================
# GLOBAL INSTANCE
# =============================================================================

# Global debug logger instance (can be imported and used anywhere)
_global_debug_logger: Optional[DebugLogger] = None


def init_debug_logger(output_dir: str = None, enabled: bool = True) -> DebugLogger:
    """Initialize global debug logger"""
    global _global_debug_logger
    _global_debug_logger = DebugLogger(output_dir=output_dir, enabled=enabled)
    return _global_debug_logger


def get_debug_logger() -> Optional[DebugLogger]:
    """Get global debug logger"""
    return _global_debug_logger


def wrap_session(session) -> Union['DebugSession', Any]:
    """Wrap a session with debug logging if enabled"""
    if _global_debug_logger and _global_debug_logger.enabled:
        return DebugSession(session, _global_debug_logger)
    return session


# =============================================================================
# MAIN / SELF-TEST
# =============================================================================

if __name__ == "__main__":
    print("""
    Debug Logger v4.0 - Comprehensive Debug System

    Features:
    - Request/Response logging with headers and body
    - Authentication event tracking
    - Data flow logging
    - Error capture with context
    - Performance metrics
    - JSON output for analysis

    Usage:
        from debug_logger import init_debug_logger, wrap_session

        # Initialize
        logger = init_debug_logger(enabled=True)

        # Wrap session
        session = wrap_session(requests.Session())

        # Use session normally - all I/O is logged
        response = session.get('https://example.com')

        # Save logs
        logger.save()
    """)

    # Self-test
    print("\n[*] Running self-test...")

    import tempfile
    temp_dir = tempfile.mkdtemp()

    logger = DebugLogger(output_dir=temp_dir, enabled=True)

    # Test request logging
    req_id = logger.log_request(
        method='GET',
        url='https://example.com/api/users?id=123',
        headers={'User-Agent': 'Test', 'Authorization': 'Bearer secret-token-12345'},
        body=None
    )
    print(f"  Request logged: {req_id}")

    # Test auth event
    logger.log_auth_event(
        auth_type='form',
        action='login_attempt',
        details={'username': 'admin', 'url': 'https://example.com/login'},
        success=True
    )
    print("  Auth event logged")

    # Test error logging
    logger.log_error(
        error_type='connection_error',
        message='Connection refused',
        context={'url': 'https://example.com'},
        request_id=req_id
    )
    print("  Error logged")

    # Test data flow
    logger.log_data_flow(
        flow_type='injection_point',
        source='parameter:id',
        destination='sql_query',
        data="' OR 1=1--",
        metadata={'vuln_type': 'sqli'}
    )
    print("  Data flow logged")

    # Test performance
    with logger.measure_performance('test_operation'):
        time.sleep(0.1)
    print("  Performance measured")

    # Save
    output_file = logger.save()
    print(f"\n  Debug log saved to: {output_file}")

    # Verify
    with open(output_file, 'r') as f:
        data = json.load(f)
        print(f"  Total requests: {data['summary']['total_requests']}")
        print(f"  Total errors: {data['summary']['total_errors']}")

    # Cleanup
    import shutil
    shutil.rmtree(temp_dir)

    print("\n[+] Self-test completed!")
