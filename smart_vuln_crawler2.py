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

# Disabilita SSL warnings per security testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class BehavioralContextEngine:
    """Deduce vulnerabilities through behavioral analysis, not assumptions"""
    
    def __init__(self):
        self.cache = {}  # Cache results per evitare test ripetuti
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
    
    def fingerprint_endpoint(self, session, url, param_name):
        """Send smart probes to understand endpoint behavior"""
        cache_key = self.get_cache_key(url, param_name)
        
        # Check cache
        if cache_key in self.cache:
            logger.info(f"Using cached behavioral results for {param_name}")
            return self.cache[cache_key]
        
        results = {}
        logger.info(f"Starting behavioral fingerprinting for {param_name}")
        
        for context, probes in self.context_probes.items():
            context_results = {}
            
            for probe in probes:
                time.sleep(self.rate_limit_delay)  # Rate limiting
                
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
                        probe_result['timing_anomaly'] = elapsed > 1.5  # >1.5s suggests sleep worked
                    
                    context_results[probe.get('response_key', 'probe')] = probe_result
                    
                except Exception as e:
                    logger.debug(f"Probe failed for {probe['param']}: {e}")
                    context_results[probe.get('response_key', 'probe')] = {'error': str(e)}
            
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
    """Handle various authentication methods"""
    
    def __init__(self):
        self.auth_types = {
            'basic': self.setup_basic_auth,
            'bearer': self.setup_bearer_auth,
            'cookie': self.setup_cookie_auth,
            'form': self.setup_form_auth,
            'custom_header': self.setup_custom_header_auth
        }
        self.session = None
        self.auth_config = None
    
    def setup_authentication(self, session, auth_config):
        """Configure authentication for the session"""
        self.session = session
        self.auth_config = auth_config
        
        auth_type = auth_config.get('type', '').lower()
        
        if auth_type in self.auth_types:
            return self.auth_types[auth_type](auth_config)
        else:
            logger.error(f"Unknown authentication type: {auth_type}")
            return False
    
    def setup_basic_auth(self, config):
        """Setup HTTP Basic Authentication"""
        username = config.get('username')
        password = config.get('password')
        
        if username and password:
            self.session.auth = (username, password)
            logger.info(f"Basic auth configured for user: {username}")
            return True
        return False
    
    def setup_bearer_auth(self, config):
        """Setup Bearer token authentication"""
        token = config.get('token')
        
        if token:
            self.session.headers.update({
                'Authorization': f'Bearer {token}'
            })
            logger.info("Bearer token authentication configured")
            return True
        return False
    
    def setup_cookie_auth(self, config):
        """Setup cookie-based authentication"""
        cookies = config.get('cookies', {})
        
        for name, value in cookies.items():
            self.session.cookies.set(name, value)
        
        logger.info(f"Cookie authentication configured with {len(cookies)} cookies")
        return True
    
    def setup_custom_header_auth(self, config):
        """Setup custom header authentication"""
        headers = config.get('headers', {})
        
        self.session.headers.update(headers)
        logger.info(f"Custom header authentication configured with {len(headers)} headers")
        return True
    
    def setup_form_auth(self, config):
        """Setup form-based authentication with login"""
        login_url = config.get('login_url')
        username_field = config.get('username_field', 'username')
        password_field = config.get('password_field', 'password')
        username = config.get('username')
        password = config.get('password')
        
        if not all([login_url, username, password]):
            logger.error("Missing required form auth parameters")
            return False
        
        try:
            # Perform login
            login_data = {
                username_field: username,
                password_field: password
            }
            
            # Add any additional fields
            extra_fields = config.get('extra_fields', {})
            login_data.update(extra_fields)
            
            response = self.session.post(login_url, data=login_data, timeout=30)
            
            # Check login success
            success_indicators = config.get('success_indicators', [])
            if success_indicators:
                success = any(indicator in response.text for indicator in success_indicators)
            else:
                success = response.status_code in [200, 302]
            
            if success:
                logger.info(f"Form authentication successful for user: {username}")
                
                # Check if we need to handle 2FA
                if config.get('2fa_required'):
                    self.handle_2fa(config, response)
                
                return True
            else:
                logger.error("Form authentication failed")
                return False
                
        except Exception as e:
            logger.error(f"Form authentication error: {e}")
            return False
    
    def handle_2fa(self, config, login_response):
        """Handle two-factor authentication"""
        twofa_url = config.get('2fa_url')
        twofa_field = config.get('2fa_field', 'code')
        twofa_code = config.get('2fa_code')
        
        if twofa_url and twofa_code:
            try:
                twofa_data = {twofa_field: twofa_code}
                response = self.session.post(twofa_url, data=twofa_data, timeout=30)
                
                if response.status_code in [200, 302]:
                    logger.info("2FA authentication successful")
                else:
                    logger.error("2FA authentication failed")
                    
            except Exception as e:
                logger.error(f"2FA error: {e}")


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
        self.sql_params = ['id', 'user_id', 'product_id', 'cat', 'category', 'item', 'page', 
                          'sort', 'order', 'limit', 'offset', 'search', 'q', 'query']
        self.file_params = ['file', 'path', 'document', 'folder', 'name', 'page', 'include',
                           'template', 'view', 'module', 'load']
        self.cmd_params = ['cmd', 'exec', 'command', 'execute', 'ping', 'system', 'do', 'func']
        self.xxe_params = ['xml', 'data', 'input', 'payload', 'doc', 'document']
        
    def analyze_parameter(self, param_name, param_value, response_text, content_type=""):
        """Analyze a parameter for vulnerability indicators"""
        vulnerabilities = []
        param_name_lower = param_name.lower()
        
        # Check for reflection (XSS indicator)
        if param_value and response_text and str(param_value) in response_text:
            context = self._get_reflection_context(str(param_value), response_text)
            if context:
                vulnerabilities.append({
                    'type': 'xss',
                    'confidence': 85 if context in ['html', 'attribute'] else 60,
                    'context': context,
                    'evidence': 'Parameter value reflected in response'
                })
        
        # SQL Injection indicators
        if param_name_lower in self.sql_params or re.search(r'(id|ID|Id)$', param_name):
            vulnerabilities.append({
                'type': 'sqli',
                'confidence': 60,
                'context': 'database_parameter',
                'evidence': f'Parameter name suggests database query: {param_name}'
            })
        
        # File Inclusion indicators
        if param_name_lower in self.file_params:
            vulnerabilities.append({
                'type': 'lfi',
                'confidence': 60,
                'context': 'file_parameter',
                'evidence': f'Parameter name suggests file operation: {param_name}'
            })
        
        # Command Injection indicators
        if param_name_lower in self.cmd_params:
            vulnerabilities.append({
                'type': 'rce',
                'confidence': 60,
                'context': 'command_parameter',
                'evidence': f'Parameter name suggests command execution: {param_name}'
            })
        
        # XXE indicators
        if param_name_lower in self.xxe_params or 'xml' in content_type.lower():
            vulnerabilities.append({
                'type': 'xxe',
                'confidence': 60,
                'context': 'xml_parameter',
                'evidence': f'Parameter appears to accept XML data: {param_name}'
            })
        
        # SSTI indicators
        if param_name_lower in ['template', 'name', 'view', 'page'] and '{{' not in str(param_value):
            vulnerabilities.append({
                'type': 'ssti',
                'confidence': 35,
                'context': 'template_parameter',
                'evidence': f'Parameter name suggests template usage: {param_name}'
            })
        
        # Open Redirect indicators
        if param_name_lower in ['url', 'link', 'redirect', 'return', 'next', 'callback', 'goto']:
            vulnerabilities.append({
                'type': 'open_redirect',
                'confidence': 60,
                'context': 'redirect_parameter',
                'evidence': f'Parameter name suggests redirection: {param_name}'
            })
        
        # LDAP Injection indicators
        if param_name_lower in ['username', 'user', 'name', 'uid', 'cn', 'dn']:
            vulnerabilities.append({
                'type': 'ldapi',
                'confidence': 35,
                'context': 'authentication_parameter',
                'evidence': f'Parameter used for authentication: {param_name}'
            })
        
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
    
    def __init__(self, target_url, max_depth=3, max_pages=1000, verbose=False, auth_config=None):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(target_url)
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.verbose = verbose
        self.visited_urls = set()
        self.url_queue = queue.Queue()
        self.endpoints = []
        self.forms = []
        
        # Setup session with retry strategy
        self.session = requests.Session()
        
        # Retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
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
        
        # Initialize authentication
        self.auth_manager = AuthenticationManager()
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
            js_content = ""
            for script in soup.find_all('script'):
                src = script.get('src')
                if src:
                    js_url = urljoin(url, src)
                    self.results['javascript_files'].append(js_url)
                    
                    # Analyze external JS
                    try:
                        js_response = self.session.get(js_url, timeout=5)
                        js_content += js_response.text + "\n"
                        js_urls = self.extract_urls_from_js(js_response.text, url)
                        for js_url_found in js_urls:
                            if self.is_valid_url(js_url_found):
                                self.url_queue.put((js_url_found, depth + 1))
                                if '/api/' in js_url_found or '/v1/' in js_url_found:
                                    self.results['api_endpoints'].append(js_url_found)
                    except:
                        pass
                
                # Analyze inline JS
                if script.string:
                    js_content += script.string + "\n"
                    js_urls = self.extract_urls_from_js(script.string, url)
                    for js_url_found in js_urls:
                        if self.is_valid_url(js_url_found):
                            self.url_queue.put((js_url_found, depth + 1))
                            if '/api/' in js_url_found or '/v1/' in js_url_found:
                                self.results['api_endpoints'].append(js_url_found)
            
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
                param_name
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
        
        if not injectable_segments:
            return
        
        if self.verbose:
            print(f"  📍 Injectable path segments found: {len(injectable_segments)}")
            for seg in injectable_segments:
                print(f"    - {seg['name']}: {seg['value']} ({seg['type']})")
        
        # Create endpoint for path segments
        endpoint = {
            'url': url,
            'method': 'GET', 
            'parameters': [],
            'form': False,
            'source': 'path_segments'
        }
        
        for segment_info in injectable_segments:
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
        
        if not dynamic_params:
            return
        
        if self.verbose:
            print(f"  📍 Dynamic JavaScript parameters found: {len(dynamic_params)}")
            for param in dynamic_params:
                print(f"    - {param['name']} (source: {param['source']})")
        
        # Create endpoint for JavaScript parameters
        endpoint = {
            'url': url,
            'method': 'POST',  # Most dynamic params are POST
            'parameters': [],
            'form': False,
            'source': 'javascript_dynamic'
        }
        
        for param_info in dynamic_params:
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
                
                if input_data['type'] == 'hidden':
                    vulns.append({
                        'type': 'hidden_param_manipulation',
                        'confidence': 60,
                        'context': 'hidden_form_field',
                        'evidence': f'Hidden field manipulation: {input_data["name"]}'
                    })
                
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
        
        if self.verbose:
            print(f"\n🎯 IMMEDIATE TESTING: {endpoint['url']} parameter '{param['name']}'")
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', vuln.get('vulnerability', 'unknown'))
            confidence = vuln.get('confidence', 'unknown')
            
            if self.verbose:
                print(f"  🔍 Testing {vuln_type.upper()} (confidence: {confidence})")
            
            # Get appropriate wordlists
            wordlists = self.wordlist_mapper.get_wordlists_for_vulnerability(
                vuln_type, self.results['technologies']
            )
            
            if not wordlists:
                if self.verbose:
                    print(f"    ⚠️ No wordlists found for {vuln_type}")
                continue
            
            # Test with payloads from wordlists
            self.test_with_wordlists(endpoint, param, vuln_type, wordlists)
    
    def test_with_wordlists(self, endpoint, param, vuln_type, wordlists):
        """Test vulnerability using wordlists and bypasses"""
        tested_payloads = set()  # Per evitare duplicati
        max_payloads_per_list = 10  # Limit for immediate testing
        
        # Collect all payloads first (cat)
        all_payloads = []
        for wordlist in wordlists[:3]:  # Limit to first 3 wordlists
            if not os.path.exists(wordlist['path']):
                continue
            
            try:
                with open(wordlist['path'], 'r', encoding='utf-8', errors='ignore') as f:
                    payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    all_payloads.extend(payloads[:max_payloads_per_list])
                
                if self.verbose:
                    print(f"    📚 Loading from: {wordlist['source']}/{wordlist['relative_path']} ({len(payloads)} payloads)")
                
            except Exception as e:
                if self.verbose:
                    print(f"    ❌ Error reading wordlist {wordlist['path']}: {e}")
                continue
        
        # Sort and unique (sort | uniq)
        unique_payloads = sorted(list(set(all_payloads)))
        
        if self.verbose:
            print(f"    📊 Total unique payloads: {len(unique_payloads)} (from {len(all_payloads)} total)")
        
        # Test unique payloads
        tested_count = 0
        for payload in unique_payloads[:max_payloads_per_list * 2]:  # Total limit
            if tested_count >= max_payloads_per_list * 2:
                break
            
            # Test without bypass first
            success = self.test_single_payload(endpoint, param, payload, vuln_type, None)
            
            if not success and self.bypass_manager and self.bypass_manager.validated_bypasses:
                # Test with each validated bypass
                for bypass in self.bypass_manager.validated_bypasses:
                    if self.verbose:
                        print(f"      🔧 Applying bypass: {bypass['type']}")
                    
                    success = self.test_single_payload(endpoint, param, payload, vuln_type, bypass)
                    if success:
                        break  # Stop trying bypasses once one works
            
            tested_count += 1
            tested_payloads.add(payload)
            
            # Small delay between requests
            time.sleep(0.1)
        
        if self.verbose:
            print(f"    ✅ Tested {tested_count} unique payloads for {vuln_type}")
    
    def test_single_payload(self, endpoint, param, payload, vuln_type, bypass=None):
        """Test a single payload against an endpoint"""
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
            
            # Make request
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
            
            # Analyze response for vulnerability indicators
            vulnerability_detected = self.analyze_response_for_vulnerability(
                response, payload, vuln_type, bypass
            )
            
            if vulnerability_detected:
                # Record successful test
                test_result = {
                    'endpoint': endpoint['url'],
                    'parameter': param_name,
                    'vulnerability_type': vuln_type,
                    'payload': payload,
                    'bypass_used': bypass['type'] if bypass else None,
                    'response_status': response.status_code,
                    'response_length': len(response.content),
                    'timestamp': time.strftime('%H:%M:%S'),
                    'confidence': 85 if bypass else 75
                }
                
                self.results['vulnerability_test_results'].append(test_result)
                
                if self.verbose:
                    bypass_info = f" with {bypass['type']}" if bypass else ""
                    print(f"      🚨 VULNERABILITY DETECTED{bypass_info}!")
                    print(f"         Payload: {payload[:50]}{'...' if len(payload) > 50 else ''}")
                    print(f"         Status: {response.status_code}, Length: {len(response.content)}")
                
                return True
            
            elif self.verbose:
                bypass_info = f" + {bypass['type']}" if bypass else ""
                print(f"      ⚪ {payload[:30]}{'...' if len(payload) > 30 else ''}{bypass_info} → {response.status_code}")
            
            return False
            
        except Exception as e:
            if self.verbose:
                print(f"      ❌ Error testing payload: {e}")
            return False
    
    def analyze_response_for_vulnerability(self, response, payload, vuln_type, bypass):
        """Enhanced response analysis with behavioral verification"""
        status_code = response.status_code
        response_text = response.text.lower() if response.text else ""
        payload_lower = payload.lower()
        
        # First check: is payload even in response?
        if payload_lower not in response_text and payload not in response.text:
            # Special case for blind vulnerabilities
            if vuln_type in ['sqli', 'xxe', 'ssti'] and status_code in [500, 503]:
                # Server error might indicate vulnerability
                return True
            return False
        
        # Enhanced vulnerability-specific detection
        if vuln_type == 'xss':
            # Check if dangerous patterns are preserved (not escaped)
            dangerous_patterns = [
                (r'<script[^>]*>', r'&lt;script'),
                (r'javascript:', r'javascript&#58;|javascript%3A'),
                (r'on\w+\s*=', r'on\w+\s*&#61;'),
                (r'<img[^>]*>', r'&lt;img'),
                (r'<svg[^>]*>', r'&lt;svg'),
                (r'<iframe[^>]*>', r'&lt;iframe')
            ]
            
            for pattern, escaped_pattern in dangerous_patterns:
                if re.search(pattern, payload, re.I):
                    # Check if pattern exists unescaped in response
                    if re.search(pattern, response.text, re.I):
                        # Make sure it's not in a comment or CDATA
                        if not re.search(f'<!--.*{pattern}.*-->', response.text, re.I | re.S):
                            return True
        
        elif vuln_type == 'sqli':
            # Enhanced SQL error detection
            sql_errors = [
                # MySQL
                r'SQL syntax.*MySQL',
                r'Warning.*mysql_',
                r'MySQLSyntaxErrorException',
                r'valid MySQL result',
                r'mysqldump',
                
                # PostgreSQL
                r'PostgreSQL.*ERROR',
                r'Warning.*\Wpg_',
                r'valid PostgreSQL result',
                r'PSQLException',
                
                # MSSQL
                r'Driver.*SQL[\s\-\_]*Server',
                r'OLE DB.*SQL Server',
                r'SQLServer JDBC Driver',
                r'SqlException',
                r'Unclosed quotation mark',
                
                # Oracle
                r'Oracle.*Driver',
                r'Warning.*oci_',
                r'Oracle.*Parser',
                r'OracleException',
                
                # SQLite
                r'SQLite.*Exception',
                r'System.Data.SQLite.SQLiteException',
                r'Warning.*sqlite_',
                
                # Generic
                r'SQL\s*command\s*not\s*properly\s*ended',
                r'Query\s*failed',
                r'mysql_fetch_array\(\)',
                r'mysqli::query\(\)',
                r'pg_exec\(\)',
                r'unrecognized token'
            ]
            
            for error in sql_errors:
                if re.search(error, response.text, re.I):
                    return True
        
        elif vuln_type == 'lfi':
            # Enhanced LFI detection
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
                r'<?php',
                r'<%',
                
                # Error messages
                r'failed to open stream',
                r'Failed opening',
                r'Warning.*include',
                r'Warning.*file_get_contents'
            ]
            
            for indicator in lfi_indicators:
                if re.search(indicator, response.text, re.I | re.M):
                    return True
        
        elif vuln_type == 'rce':
            # Enhanced RCE detection
            rce_indicators = [
                # Command outputs
                r'uid=\d+.*gid=\d+.*groups=',
                r'Linux\s+\w+\s+\d+\.\d+',
                r'Microsoft\s+Windows',
                r'Volume\s+in\s+drive',
                r'Directory\s+of',
                
                # Shell prompts
                r'[\w\-]+@[\w\-]+:',
                r'[\w\-]+\$',
                r'[\w\-]+#',
                r'C:\\.*>',
                
                # Common commands
                r'/bin/\w+',
                r'/usr/bin/\w+',
                r'command not found',
                r'is not recognized as',
                
                # Process listings
                r'PID\s+TTY\s+TIME\s+CMD',
                r'UID\s+PID\s+PPID'
            ]
            
            for indicator in rce_indicators:
                if re.search(indicator, response.text, re.I | re.M):
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
    
    def discover_hidden_endpoints(self, max_paths=1000):
        """Smart endpoint discovery using technology-specific wordlists"""
        print("  🔍 Smart Endpoint Discovery...")
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
                        if result['status'] == 200:
                            # Add to crawl queue if accessible
                            self.url_queue.put((result['url'], 0))
                except Exception as e:
                    logger.error(f"Error checking {path}: {e}")
        
        logger.info(f"Discovered {discovered_count} new endpoints")
    
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
        """Export results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        logger.info(f"Results exported to {filename}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Smart Vulnerability Crawler with Bypass Integration and Behavioral Analysis')
    parser.add_argument('target', help='Target URL to crawl')
    parser.add_argument('--depth', type=int, default=3, help='Maximum crawl depth (default: 3)')
    parser.add_argument('--max-pages', type=int, default=1000, help='Maximum pages to crawl (default: 1000)')
    parser.add_argument('--output', default='attack_surface.json', help='Output JSON file')
    parser.add_argument('--wordlist-base', help='Base path for wordlists')
    parser.add_argument('--discovery-limit', type=int, default=1000, help='Max paths to test')
    parser.add_argument('--skip-discovery', action='store_true', help='Skip wordlist discovery')
    parser.add_argument('--bypass-file', help='JSON file with bypasses')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
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
    
    # Build auth configuration
    auth_config = None
    if args.auth_type:
        auth_config = {'type': args.auth_type}
        
        if args.auth_config:
            # Load from JSON file
            with open(args.auth_config, 'r') as f:
                auth_config = json.load(f)
        else:
            # Build from command line
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
    
    # Initialize bypass manager
    bypass_manager = None
    if args.bypass_file:
        bypass_manager = BypassManager(args.bypass_file)
    
    # Create crawler instance with auth
    crawler = SmartCrawler(
        args.target, 
        max_depth=args.depth, 
        max_pages=args.max_pages, 
        verbose=args.verbose,
        auth_config=auth_config
    )
    
    # Set bypass manager
    if bypass_manager:
        crawler.set_bypass_manager(bypass_manager)
    
    # Set custom wordlist base path if provided
    if args.wordlist_base:
        crawler.wordlist_mapper.base_paths = {
            'fuzzdb': f"{args.wordlist_base}/fuzzdb",
            'payloads': f"{args.wordlist_base}/PayloadsAllTheThings",
            'seclists': f"{args.wordlist_base}/SecLists"
        }
        crawler.discovery_mapper.base_paths = {
            'fuzzdb': f"{args.wordlist_base}/fuzzdb",
            'payloads': f"{args.wordlist_base}/PayloadsAllTheThings",
            'seclists': f"{args.wordlist_base}/SecLists"
        }
    
    # Run crawler
    results = crawler.run(discovery_limit=args.discovery_limit, skip_discovery=args.skip_discovery)
    
    # Export results
    crawler.export_results(args.output)
    
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
    
    print("\n" + "="*60)
    print(f"Full results saved to: {args.output}")
    print("="*60)


if __name__ == "__main__":
    main()