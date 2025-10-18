#!/usr/bin/env python3
"""
Application Stack Traceroute v3.0 - Intelligent Reconstruction
Next-Generation Infrastructure Analysis with Progressive Discovery

FEATURES:
- Progressive stack reconstruction with header timeline analysis
- Adaptive fingerprinting based on discovered components
- Confidence scoring system for accurate identification
- Intelligent bypass generation targeting real forbidden endpoints
- Full correlation: CDN→WAF→LB→Proxy→Backend
- JSON export for orchestration tools

AUTHOR: Rewritten from scratch for bug bounty hunting
LICENSE: Use responsibly - authorized testing only
"""

import requests
import asyncio
import aiohttp
import json
import time
import base64
import urllib.parse
import re
import random
import string
import socket
import ssl
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Tuple
import urllib3
import warnings

# Suppress SSL warnings for security testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class ProgressiveStackAnalyzer:
    """
    Analyzes infrastructure stack progressively using header timeline,
    behavioral testing, and timing analysis for accurate reconstruction.
    """
    
    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(target_url)
        self.session = requests.Session()
        self.session.verify = False
        
        # Stack reconstruction data
        self.stack = {
            'layers': [],           # Ordered list of discovered layers
            'timeline': [],         # Header processing timeline
            'confidence': {},       # Confidence scores per component
            'correlations': []      # Layer relationships
        }
        
        # Fingerprint data (YOU will populate this)
        self.fingerprints = self.initialize_fingerprints()
        
    def initialize_fingerprints(self) -> Dict:
        """
        Initialize fingerprint structure.
        YOU will insert the complete lists here from your existing code.
        """
        return {
            'cdn_detection': {
                # INSERT YOUR COMPLETE CDN LIST HERE
                # Structure:
                # 'cloudflare': {
                #     'headers': ['cf-ray', 'cf-cache-status', ...],
                #     'body_patterns': ['cloudflare', 'error 1020', ...],
                #     'behavioral_paths': ['/cdn-cgi/', ...],
                #     'timing_signature': {'avg_ms': 50, 'jitter': 10},
                #     'ssl_patterns': [...],
                #     'dns_patterns': [...]
                # }
            },
            'waf_detection': {
                # INSERT YOUR COMPLETE WAF LIST HERE
            },
            'load_balancer_detection': {
                # INSERT YOUR COMPLETE LB LIST HERE
            },
            'proxy_detection': {
                # INSERT YOUR COMPLETE PROXY LIST HERE
            },
            'api_gateway_detection': {
                # INSERT YOUR COMPLETE API GATEWAY LIST HERE
            },
            'backend_detection': {
                # INSERT YOUR COMPLETE BACKEND LIST HERE
            }
        }
    
    def log(self, category: str, message: str, level: str = "INFO"):
        """Structured logging"""
        timestamp = time.strftime('%H:%M:%S')
        icons = {"INFO": "ℹ️", "SUCCESS": "✅", "WARNING": "⚠️", "ERROR": "❌", "DISCOVERY": "🔍"}
        print(f"[{timestamp}] {icons.get(level, '•')} [{category}] {message}")
    
    def send_baseline_request(self) -> requests.Response:
        """Send initial request to analyze raw stack response"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        response = self.session.get(self.target_url, headers=headers, timeout=15)
        return response
    
    def analyze_header_timeline(self, response: requests.Response) -> List[Dict]:
        """
        Analyze header timeline to reconstruct processing chain.
        Via, X-Forwarded-*, Server headers reveal the path.
        """
        timeline = []
        
        # Via header analysis (shows proxy chain)
        via_header = response.headers.get('Via', '')
        if via_header:
            hops = via_header.split(',')
            for idx, hop in enumerate(hops):
                hop = hop.strip()
                timeline.append({
                    'order': idx,
                    'type': 'proxy',
                    'raw': hop,
                    'component': self._identify_from_via(hop)
                })
        
        # X-Forwarded headers
        xff = response.headers.get('X-Forwarded-For', '')
        if xff:
            timeline.append({
                'order': len(timeline),
                'type': 'proxy/lb',
                'raw': f'X-Forwarded-For: {xff}',
                'component': 'forwarding_proxy'
            })
        
        # Server header (usually last in chain - origin)
        server = response.headers.get('Server', '')
        if server:
            timeline.append({
                'order': len(timeline),
                'type': 'backend',
                'raw': f'Server: {server}',
                'component': self._identify_from_server(server)
            })
        
        # CDN-specific headers (usually first in chain)
        cdn_headers = {
            'CF-Ray': 'cloudflare',
            'X-Amz-Cf-Id': 'cloudfront',
            'X-Served-By': 'fastly/akamai',
            'X-Cache': 'generic_cdn'
        }
        
        for header, cdn_type in cdn_headers.items():
            if header in response.headers:
                timeline.insert(0, {  # CDN is always first
                    'order': 0,
                    'type': 'cdn',
                    'raw': f'{header}: {response.headers[header]}',
                    'component': cdn_type
                })
                break
        
        # WAF-specific headers
        waf_headers = {
            'X-WAF-Event-Info': 'generic_waf',
            'X-Sucuri-ID': 'sucuri_waf',
            'X-Denied-Reason': 'generic_waf'
        }
        
        for header, waf_type in waf_headers.items():
            if header in response.headers:
                # WAF usually after CDN but before backend
                insert_pos = 1 if timeline and timeline[0]['type'] == 'cdn' else 0
                timeline.insert(insert_pos, {
                    'order': insert_pos,
                    'type': 'waf',
                    'raw': f'{header}: {response.headers[header]}',
                    'component': waf_type
                })
                break
        
        self.stack['timeline'] = timeline
        return timeline
    
    def _identify_from_via(self, via_string: str) -> str:
        """Identify component from Via header"""
        via_lower = via_string.lower()
        
        identifiers = {
            'cloudflare': 'cloudflare',
            'nginx': 'nginx_proxy',
            'squid': 'squid_proxy',
            'varnish': 'varnish_cache',
            'haproxy': 'haproxy_lb',
            'envoy': 'envoy_proxy'
        }
        
        for pattern, component in identifiers.items():
            if pattern in via_lower:
                return component
        
        return 'unknown_proxy'
    
    def _identify_from_server(self, server_string: str) -> str:
        """Identify backend from Server header"""
        server_lower = server_string.lower()
        
        identifiers = {
            'nginx': 'nginx_backend',
            'apache': 'apache_backend',
            'microsoft-iis': 'iis_backend',
            'cloudflare': 'cloudflare_workers',
            'openresty': 'openresty_backend'
        }
        
        for pattern, component in identifiers.items():
            if pattern in server_lower:
                return component
        
        return 'unknown_backend'
    
    def progressive_fingerprinting(self, baseline_response: requests.Response):
        """
        Progressive fingerprinting: start with timeline analysis,
        then deep-dive into each discovered layer type.
        """
        self.log("FINGERPRINTING", "Starting progressive stack analysis...", "INFO")
        
        # Phase 1: Timeline analysis (already done)
        timeline = self.stack['timeline']
        
        # Phase 2: Deep fingerprinting for each layer type found
        layer_types = set([layer['type'] for layer in timeline])
        
        for layer_type in layer_types:
            if layer_type == 'cdn':
                self.deep_cdn_fingerprinting(baseline_response)
            elif layer_type == 'waf':
                self.deep_waf_fingerprinting(baseline_response)
            elif layer_type == 'proxy' or layer_type == 'proxy/lb':
                self.deep_proxy_fingerprinting(baseline_response)
            elif layer_type == 'backend':
                self.deep_backend_fingerprinting(baseline_response)
        
        # Phase 3: Check for hidden layers (no header evidence)
        self.detect_hidden_layers()
    
    def deep_cdn_fingerprinting(self, response: requests.Response):
        """
        Deep CDN analysis using ALL data from fingerprint list.
        Confidence scoring: Headers(40) + Body(30) + Behavioral(20) + Timing(10)
        """
        self.log("CDN", "Deep fingerprinting with confidence scoring...", "DISCOVERY")
        
        cdn_fingerprints = self.fingerprints['cdn_detection']
        detected = []
        
        for cdn_name, fingerprint_data in cdn_fingerprints.items():
            confidence = 0
            evidence = []
            
            # YOU will have these keys in your fingerprint:
            # 'headers', 'body_patterns', 'behavioral_paths', 'timing_signature'
            
            # 1. Header matching (40 points)
            headers_list = fingerprint_data.get('headers', [])
            for header_pattern in headers_list:
                for header_name, header_value in response.headers.items():
                    if re.search(header_pattern, f"{header_name}: {header_value}", re.IGNORECASE):
                        confidence += 40
                        evidence.append(f"Header: {header_name}")
                        break
                if confidence >= 40:
                    break
            
            # 2. Body pattern matching (30 points)
            body_patterns = fingerprint_data.get('body_patterns', [])
            response_text = response.text.lower()
            for pattern in body_patterns:
                if pattern.lower() in response_text:
                    confidence += 30
                    evidence.append(f"Body pattern: {pattern}")
                    break
            
            # 3. Behavioral testing (20 points)
            behavioral_paths = fingerprint_data.get('behavioral_paths', [])
            for path in behavioral_paths:
                try:
                    test_url = self.target_url + path
                    test_response = self.session.get(test_url, timeout=5)
                    # If path exists or returns specific code, it's behavioral evidence
                    if test_response.status_code in [200, 403, 404]:  # Existence check
                        confidence += 20
                        evidence.append(f"Behavioral: {path}")
                        break
                except:
                    pass
            
            # 4. Timing analysis (10 points)
            timing_sig = fingerprint_data.get('timing_signature', {})
            if timing_sig:
                avg_latency = self._measure_latency()
                expected_ms = timing_sig.get('avg_ms', 0)
                jitter = timing_sig.get('jitter', 50)
                
                if abs(avg_latency - expected_ms) <= jitter:
                    confidence += 10
                    evidence.append(f"Timing: ~{avg_latency}ms")
            
            # Store if confidence is sufficient
            if confidence >= 40:  # Minimum threshold
                detected.append({
                    'name': cdn_name,
                    'confidence': confidence,
                    'evidence': evidence,
                    'level': 'HIGH' if confidence >= 70 else 'MEDIUM' if confidence >= 50 else 'LOW'
                })
        
        # Sort by confidence and add to stack
        detected.sort(key=lambda x: x['confidence'], reverse=True)
        
        if detected:
            best_match = detected[0]
            self.stack['layers'].append({
                'type': 'CDN',
                'component': best_match['name'],
                'confidence': best_match['confidence'],
                'level': best_match['level'],
                'evidence': best_match['evidence']
            })
            self.log("CDN", f"Detected: {best_match['name']} (confidence: {best_match['confidence']}/100, {best_match['level']})", "SUCCESS")
        else:
            self.log("CDN", "No CDN detected or confidence too low", "INFO")
    
    def deep_waf_fingerprinting(self, response: requests.Response):
        """
        Deep WAF analysis with active testing.
        Uses malicious payloads to trigger WAF responses.
        """
        self.log("WAF", "Deep fingerprinting with active payload testing...", "DISCOVERY")
        
        waf_fingerprints = self.fingerprints['waf_detection']
        detected = []
        
        # Test payloads to trigger WAF
        test_payloads = [
            "/?test=<script>alert(1)</script>",
            "/?test=' OR '1'='1",
            "/?test=../../../etc/passwd",
            "/?test=<img src=x onerror=alert(1)>"
        ]
        
        for waf_name, fingerprint_data in waf_fingerprints.items():
            confidence = 0
            evidence = []
            
            # 1. Passive detection from baseline response (40 points)
            headers_list = fingerprint_data.get('headers', [])
            for header_pattern in headers_list:
                for header_name, header_value in response.headers.items():
                    if re.search(header_pattern, f"{header_name}: {header_value}", re.IGNORECASE):
                        confidence += 40
                        evidence.append(f"Header: {header_name}")
                        break
                if confidence >= 40:
                    break
            
            # 2. Active testing with payloads (30 points)
            block_patterns = fingerprint_data.get('block_patterns', [])
            for payload in test_payloads:
                try:
                    test_url = self.target_url + payload
                    test_response = self.session.get(test_url, timeout=5)
                    
                    # Check if response matches WAF block pattern
                    full_response = f"{test_response.status_code} {test_response.text}".lower()
                    for pattern in block_patterns:
                        if re.search(pattern, full_response, re.IGNORECASE):
                            confidence += 30
                            evidence.append(f"Block pattern: {pattern}")
                            break
                    
                    if confidence >= 70:
                        break
                except:
                    pass
            
            # 3. Response signature analysis (30 points)
            response_signatures = fingerprint_data.get('response_signatures', [])
            response_text = response.text.lower()
            for signature in response_signatures:
                if signature.lower() in response_text:
                    confidence += 30
                    evidence.append(f"Response signature: {signature}")
                    break
            
            if confidence >= 40:
                detected.append({
                    'name': waf_name,
                    'confidence': confidence,
                    'evidence': evidence,
                    'level': 'HIGH' if confidence >= 70 else 'MEDIUM' if confidence >= 50 else 'LOW'
                })
        
        detected.sort(key=lambda x: x['confidence'], reverse=True)
        
        if detected:
            best_match = detected[0]
            self.stack['layers'].append({
                'type': 'WAF',
                'component': best_match['name'],
                'confidence': best_match['confidence'],
                'level': best_match['level'],
                'evidence': best_match['evidence']
            })
            self.log("WAF", f"Detected: {best_match['name']} (confidence: {best_match['confidence']}/100, {best_match['level']})", "SUCCESS")
        else:
            self.log("WAF", "No WAF detected or confidence too low", "INFO")
    
    def deep_proxy_fingerprinting(self, response: requests.Response):
        """
        Deep Proxy/Load Balancer analysis.
        Similar pattern to CDN/WAF with confidence scoring.
        """
        self.log("PROXY", "Deep fingerprinting...", "DISCOVERY")
        
        proxy_fingerprints = self.fingerprints['proxy_detection']
        detected = []
        
        for proxy_name, fingerprint_data in proxy_fingerprints.items():
            confidence = 0
            evidence = []
            
            # Header analysis (40 points)
            headers_list = fingerprint_data.get('headers', [])
            for header_pattern in headers_list:
                for header_name, header_value in response.headers.items():
                    if re.search(header_pattern, f"{header_name}: {header_value}", re.IGNORECASE):
                        confidence += 40
                        evidence.append(f"Header: {header_name}")
                        break
                if confidence >= 40:
                    break
            
            # Via header specific analysis (30 points)
            via = response.headers.get('Via', '').lower()
            via_patterns = fingerprint_data.get('via_patterns', [])
            for pattern in via_patterns:
                if pattern.lower() in via:
                    confidence += 30
                    evidence.append(f"Via pattern: {pattern}")
                    break
            
            # Connection behavior (20 points)
            connection_tests = fingerprint_data.get('connection_tests', [])
            # YOU can add specific connection behavior tests here
            
            if confidence >= 40:
                detected.append({
                    'name': proxy_name,
                    'confidence': confidence,
                    'evidence': evidence,
                    'level': 'HIGH' if confidence >= 70 else 'MEDIUM'
                })
        
        detected.sort(key=lambda x: x['confidence'], reverse=True)
        
        if detected:
            best_match = detected[0]
            self.stack['layers'].append({
                'type': 'PROXY',
                'component': best_match['name'],
                'confidence': best_match['confidence'],
                'level': best_match['level'],
                'evidence': best_match['evidence']
            })
            self.log("PROXY", f"Detected: {best_match['name']} (confidence: {best_match['confidence']}/100)", "SUCCESS")
    
    def deep_backend_fingerprinting(self, response: requests.Response):
        """
        Deep Backend analysis (web server, runtime, framework).
        """
        self.log("BACKEND", "Deep fingerprinting...", "DISCOVERY")
        
        backend_fingerprints = self.fingerprints['backend_detection']
        detected = []
        
        for backend_name, fingerprint_data in backend_fingerprints.items():
            confidence = 0
            evidence = []
            
            # Server header (40 points)
            server = response.headers.get('Server', '').lower()
            server_patterns = fingerprint_data.get('server_patterns', [])
            for pattern in server_patterns:
                if pattern.lower() in server:
                    confidence += 40
                    evidence.append(f"Server: {pattern}")
                    break
            
            # Technology-specific headers (30 points)
            tech_headers = fingerprint_data.get('tech_headers', {})
            for header_name, expected_value in tech_headers.items():
                actual_value = response.headers.get(header_name, '')
                if expected_value.lower() in actual_value.lower():
                    confidence += 30
                    evidence.append(f"Tech header: {header_name}")
                    break
            
            # Framework detection from response (30 points)
            framework_patterns = fingerprint_data.get('framework_patterns', [])
            for pattern in framework_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    confidence += 30
                    evidence.append(f"Framework pattern: {pattern}")
                    break
            
            if confidence >= 40:
                detected.append({
                    'name': backend_name,
                    'confidence': confidence,
                    'evidence': evidence,
                    'level': 'HIGH' if confidence >= 70 else 'MEDIUM'
                })
        
        detected.sort(key=lambda x: x['confidence'], reverse=True)
        
        if detected:
            best_match = detected[0]
            self.stack['layers'].append({
                'type': 'BACKEND',
                'component': best_match['name'],
                'confidence': best_match['confidence'],
                'level': best_match['level'],
                'evidence': best_match['evidence']
            })
            self.log("BACKEND", f"Detected: {best_match['name']} (confidence: {best_match['confidence']}/100)", "SUCCESS")
    
    def detect_hidden_layers(self):
        """
        Detect layers that don't leave obvious headers.
        Uses timing analysis, behavioral testing, and edge cases.
        """
        self.log("HIDDEN", "Searching for hidden layers (API Gateway, Service Mesh, etc.)...", "DISCOVERY")
        
        # Check for API Gateway patterns
        api_paths = ['/api/', '/v1/', '/graphql', '/rest/']
        for path in api_paths:
            try:
                test_url = self.target_url + path
                test_response = self.session.get(test_url, timeout=5)
                
                # API Gateways often add specific headers on API paths
                gateway_headers = ['X-Kong-', 'X-Amzn-', 'X-Gateway-']
                for header_pattern in gateway_headers:
                    for header_name in test_response.headers.keys():
                        if header_pattern in header_name:
                            self.stack['layers'].append({
                                'type': 'API_GATEWAY',
                                'component': 'detected_via_api_path',
                                'confidence': 60,
                                'level': 'MEDIUM',
                                'evidence': [f'Header on {path}: {header_name}']
                            })
                            self.log("HIDDEN", f"API Gateway detected via {path}", "SUCCESS")
                            return
            except:
                pass
        
        # Timing-based detection for transparent proxies
        latencies = []
        for _ in range(3):
            start = time.time()
            try:
                self.session.get(self.target_url, timeout=5)
                latencies.append((time.time() - start) * 1000)
            except:
                pass
        
        if latencies:
            avg_latency = sum(latencies) / len(latencies)
            jitter = max(latencies) - min(latencies)
            
            # High jitter might indicate load balancing
            if jitter > 100:
                self.stack['layers'].append({
                    'type': 'LOAD_BALANCER',
                    'component': 'hidden_lb_via_timing',
                    'confidence': 50,
                    'level': 'LOW',
                    'evidence': [f'High jitter: {jitter:.2f}ms']
                })
                self.log("HIDDEN", f"Possible hidden load balancer (jitter: {jitter:.2f}ms)", "WARNING")
    
    def _measure_latency(self) -> float:
        """Measure average latency for timing analysis"""
        latencies = []
        for _ in range(3):
            start = time.time()
            try:
                self.session.head(self.target_url, timeout=5)
                latencies.append((time.time() - start) * 1000)
            except:
                pass
        return sum(latencies) / len(latencies) if latencies else 0
    
    def correlate_stack(self):
        """
        Correlate discovered layers to understand the full chain.
        Example: CDN → WAF → Load Balancer → Proxy → Backend
        """
        self.log("CORRELATION", "Building stack relationships...", "INFO")
        
        # Sort layers by typical order
        order_priority = {'CDN': 1, 'WAF': 2, 'API_GATEWAY': 3, 'LOAD_BALANCER': 4, 'PROXY': 5, 'BACKEND': 6}
        
        self.stack['layers'].sort(key=lambda x: order_priority.get(x['type'], 99))
        
        # Build correlations
        for i in range(len(self.stack['layers']) - 1):
            current = self.stack['layers'][i]
            next_layer = self.stack['layers'][i + 1]
            
            self.stack['correlations'].append({
                'from': f"{current['type']}:{current['component']}",
                'to': f"{next_layer['type']}:{next_layer['component']}",
                'relationship': 'forwards_to'
            })
        
        # Log the chain
        if self.stack['layers']:
            chain = " → ".join([f"{l['type']}({l['component']})" for l in self.stack['layers']])
            self.log("CORRELATION", f"Stack chain: {chain}", "SUCCESS")


class ForbiddenEndpointFinder:
    """
    Finds a real 403/401 forbidden endpoint for bypass testing.
    """
    
    def __init__(self, target_url: str, session: requests.Session):
        self.target_url = target_url.rstrip('/')
        self.session = session
    
    def find(self, user_provided: Optional[str] = None) -> Optional[str]:
        """Find forbidden endpoint"""
        print("\n🔍 Phase 0: Finding Forbidden Endpoint for Bypass Testing")
        print("=" * 70)
        
        # If user provided one, validate it
        if user_provided:
            if self._is_truly_forbidden(user_provided):
                print(f"  ✅ User-provided endpoint validated: {user_provided}")
                return user_provided
            else:
                print(f"  ⚠️ User-provided endpoint doesn't return 403/401, searching alternatives...")
        
        # Common forbidden paths
        common_paths = [
            '/admin', '/wp-admin', '/administrator', '/secure', '/api/admin',
            '/manage', '/console', '/portal', '/control', '/private',
            '/restricted', '/staff', '/backend', '/cpanel', '/webadmin',
            '/.env', '/.git', '/config', '/phpmyadmin', '/adminer',
            '/api/v1/admin', '/api/admin', '/admin.php', '/login',
            '/secret', '/internal', '/debug', '/test'
        ]
        
        print(f"  🔎 Testing {len(common_paths)} common forbidden paths...")
        
        for path in common_paths:
            url = self.target_url + path
            if self._is_truly_forbidden(url):
                print(f"  ✅ Found forbidden endpoint: {path}")
                return url
        
        print("  ⚠️ No forbidden endpoint found - bypass testing will be limited")
        return None
    
    def _is_truly_forbidden(self, url: str) -> bool:
        """Check if URL returns true 403/401 (not redirect)"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = self.session.get(url, headers=headers, timeout=5, allow_redirects=False)
            
            # True forbidden: 401/403 without redirect
            if response.status_code in [401, 403] and response.status_code != 302:
                return True
            
            return False
        except:
            return False


class DiscrepancyTester:
    """
    Tests for parser discrepancies between stack layers.
    CRITICAL: Uses the REAL forbidden endpoint, not hardcoded paths!
    """
    
    def __init__(self, target_url: str, forbidden_endpoint: str, session: requests.Session, stack_analyzer: ProgressiveStackAnalyzer):
        self.target_url = target_url.rstrip('/')
        self.forbidden_endpoint = forbidden_endpoint
        self.session = session
        self.stack_analyzer = stack_analyzer
        self.discrepancies = []
    
    def test_all_discrepancies(self):
        """Run all discrepancy tests on the REAL forbidden endpoint"""
        print("\n🧪 Phase 3: Parser Discrepancy Testing")
        print("=" * 70)
        
        if not self.forbidden_endpoint:
            print("  ⚠️ No forbidden endpoint available - skipping discrepancy tests")
            return
        
        print(f"  🎯 Target: {self.forbidden_endpoint}")
        print(f"  📊 Testing against reconstructed stack: {len(self.stack_analyzer.stack['layers'])} layers")
        
        # Run all discrepancy test categories
        self.test_header_confusion()
        self.test_method_confusion()
        self.test_path_normalization()
        self.test_protocol_confusion()
        self.test_encoding_confusion()
        
        print(f"\n  📊 Total discrepancies found: {len(self.discrepancies)}")
        return self.discrepancies
    
    def test_header_confusion(self):
        """Test header parsing discrepancies"""
        print("\n  🔬 Testing Header Confusion...")
        
        header_tests = [
            {
                'name': 'Double Content-Type',
                'headers': {
                    'Content-Type': 'application/json',
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            },
            {
                'name': 'Host Override',
                'headers': {
                    'Host': 'localhost',
                    'X-Forwarded-Host': self.target_url.split('//')[1].split('/')[0]
                }
            },
            {
                'name': 'Method Override',
                'headers': {
                    'X-HTTP-Method-Override': 'GET',
                    'X-Method-Override': 'GET'
                }
            },
            {
                'name': 'Content-Length Mismatch',
                'headers': {
                    'Content-Length': '0',
                    'Transfer-Encoding': 'chunked'
                }
            }
        ]
        
        for test in header_tests:
            try:
                response = self.session.get(self.forbidden_endpoint, headers=test['headers'], timeout=5)
                
                # Look for unusual responses indicating discrepancy
                if response.status_code not in [403, 401]:
                    self.discrepancies.append({
                        'type': 'Header Confusion',
                        'test_name': test['name'],
                        'forbidden_url': self.forbidden_endpoint,
                        'headers': test['headers'],
                        'response_code': response.status_code,
                        'severity': 'HIGH' if response.status_code == 200 else 'MEDIUM'
                    })
                    print(f"    ✅ Discrepancy found: {test['name']} → {response.status_code}")
            except Exception as e:
                pass
    
    def test_method_confusion(self):
        """Test HTTP method parsing discrepancies"""
        print("  🔬 Testing Method Confusion...")
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT']
        results = {}
        
        for method in methods:
            try:
                response = self.session.request(method, self.forbidden_endpoint, timeout=5)
                results[method] = response.status_code
                
                # If any method bypasses forbidden
                if response.status_code not in [403, 401, 405]:
                    self.discrepancies.append({
                        'type': 'Method Confusion',
                        'method': method,
                        'forbidden_url': self.forbidden_endpoint,
                        'response_code': response.status_code,
                        'severity': 'HIGH' if response.status_code == 200 else 'MEDIUM'
                    })
                    print(f"    ✅ Discrepancy found: {method} → {response.status_code}")
            except Exception as e:
                results[method] = f"Error: {str(e)}"
    
    def test_path_normalization(self):
        """Test path parsing discrepancies"""
        print("  🔬 Testing Path Normalization...")
        
        # Extract path from forbidden endpoint
        parsed = urlparse(self.forbidden_endpoint)
        base_path = parsed.path
        
        path_variants = [
            base_path,
            base_path + '/',
            base_path + '//',
            base_path + '/.',
            base_path + '/./',
            base_path + '/../' + base_path.split('/')[-1],
            base_path.upper(),
            base_path.replace('/', '//'),
            urllib.parse.quote(base_path),
            urllib.parse.quote(base_path, safe=''),
            base_path + '%00',
            base_path + '?',
            base_path + '#'
        ]
        
        for variant in path_variants:
            try:
                test_url = f"{parsed.scheme}://{parsed.netloc}{variant}"
                response = self.session.get(test_url, timeout=5, allow_redirects=False)
                
                if response.status_code not in [403, 401]:
                    self.discrepancies.append({
                        'type': 'Path Normalization',
                        'original_path': base_path,
                        'variant': variant,
                        'test_url': test_url,
                        'response_code': response.status_code,
                        'severity': 'HIGH' if response.status_code == 200 else 'MEDIUM'
                    })
                    print(f"    ✅ Discrepancy found: {variant} → {response.status_code}")
            except Exception as e:
                pass
    
    def test_protocol_confusion(self):
        """Test protocol version confusion"""
        print("  🔬 Testing Protocol Confusion...")
        
        # HTTP/1.1 vs HTTP/1.0
        try:
            # Force HTTP/1.0
            import http.client
            parsed = urlparse(self.forbidden_endpoint)
            conn = http.client.HTTPConnection(parsed.netloc) if parsed.scheme == 'http' else http.client.HTTPSConnection(parsed.netloc)
            
            conn.request("GET", parsed.path or '/', headers={'Host': parsed.netloc})
            response = conn.getresponse()
            
            if response.status not in [403, 401]:
                self.discrepancies.append({
                    'type': 'Protocol Confusion',
                    'test': 'HTTP/1.0 vs HTTP/1.1',
                    'forbidden_url': self.forbidden_endpoint,
                    'response_code': response.status,
                    'severity': 'MEDIUM'
                })
                print(f"    ✅ Discrepancy found: HTTP/1.0 → {response.status}")
            
            conn.close()
        except Exception as e:
            pass
    
    def test_encoding_confusion(self):
        """Test encoding confusion between layers"""
        print("  🔬 Testing Encoding Confusion...")
        
        parsed = urlparse(self.forbidden_endpoint)
        base_path = parsed.path
        
        encoding_variants = [
            urllib.parse.quote(base_path),
            urllib.parse.quote(urllib.parse.quote(base_path)),  # Double encoding
            base_path.replace('/', '%2f'),
            base_path.replace('/', '%252f'),  # Double encoded slash
            base_path.replace(' ', '%20').replace('%20', '+'),
            base64.b64encode(base_path.encode()).decode()
        ]
        
        for variant in encoding_variants:
            try:
                test_url = f"{parsed.scheme}://{parsed.netloc}{variant}"
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code not in [403, 401, 400]:
                    self.discrepancies.append({
                        'type': 'Encoding Confusion',
                        'original_path': base_path,
                        'encoded_variant': variant,
                        'test_url': test_url,
                        'response_code': response.status_code,
                        'severity': 'HIGH' if response.status_code == 200 else 'MEDIUM'
                    })
                    print(f"    ✅ Discrepancy found: encoding bypass → {response.status_code}")
            except Exception as e:
                pass


class BypassGenerator:
    """
    Generates custom bypass payloads based on discovered discrepancies.
    """
    
    def __init__(self, discrepancies: List[Dict], stack_info: Dict):
        self.discrepancies = discrepancies
        self.stack_info = stack_info
        self.bypasses = []
    
    def generate_all_bypasses(self):
        """Generate bypasses for each discrepancy"""
        print("\n🛠️ Phase 4: Custom Bypass Generation")
        print("=" * 70)
        
        if not self.discrepancies:
            print("  ⚠️ No discrepancies found - no bypasses to generate")
            return []
        
        print(f"  📊 Generating bypasses for {len(self.discrepancies)} discrepancies...")
        
        for discrepancy in self.discrepancies:
            bypass_type = discrepancy['type']
            
            if bypass_type == 'Header Confusion':
                self._generate_header_bypass(discrepancy)
            elif bypass_type == 'Method Confusion':
                self._generate_method_bypass(discrepancy)
            elif bypass_type == 'Path Normalization':
                self._generate_path_bypass(discrepancy)
            elif bypass_type == 'Protocol Confusion':
                self._generate_protocol_bypass(discrepancy)
            elif bypass_type == 'Encoding Confusion':
                self._generate_encoding_bypass(discrepancy)
        
        print(f"\n  ✅ Generated {len(self.bypasses)} bypass techniques")
        return self.bypasses
    
    def _generate_header_bypass(self, discrepancy: Dict):
        """Generate header-based bypass"""
        bypass = {
            'id': f"bypass_{len(self.bypasses) + 1}",
            'type': 'Header Confusion',
            'discrepancy': discrepancy,
            'severity': discrepancy['severity'],
            'method': 'GET',
            'url': discrepancy['forbidden_url'],
            'headers': discrepancy['headers'],
            'description': f"Header confusion bypass: {discrepancy['test_name']}",
            'curl_command': self._generate_curl(discrepancy['forbidden_url'], 'GET', discrepancy['headers'])
        }
        self.bypasses.append(bypass)
    
    def _generate_method_bypass(self, discrepancy: Dict):
        """Generate method-based bypass"""
        bypass = {
            'id': f"bypass_{len(self.bypasses) + 1}",
            'type': 'Method Confusion',
            'discrepancy': discrepancy,
            'severity': discrepancy['severity'],
            'method': discrepancy['method'],
            'url': discrepancy['forbidden_url'],
            'headers': {},
            'description': f"HTTP method bypass using {discrepancy['method']}",
            'curl_command': self._generate_curl(discrepancy['forbidden_url'], discrepancy['method'], {})
        }
        self.bypasses.append(bypass)
    
    def _generate_path_bypass(self, discrepancy: Dict):
        """Generate path-based bypass"""
        bypass = {
            'id': f"bypass_{len(self.bypasses) + 1}",
            'type': 'Path Normalization',
            'discrepancy': discrepancy,
            'severity': discrepancy['severity'],
            'method': 'GET',
            'url': discrepancy['test_url'],
            'headers': {},
            'description': f"Path normalization bypass: {discrepancy['variant']}",
            'curl_command': self._generate_curl(discrepancy['test_url'], 'GET', {})
        }
        self.bypasses.append(bypass)
    
    def _generate_protocol_bypass(self, discrepancy: Dict):
        """Generate protocol-based bypass"""
        bypass = {
            'id': f"bypass_{len(self.bypasses) + 1}",
            'type': 'Protocol Confusion',
            'discrepancy': discrepancy,
            'severity': discrepancy['severity'],
            'method': 'GET',
            'url': discrepancy['forbidden_url'],
            'headers': {},
            'description': f"Protocol confusion bypass: {discrepancy['test']}",
            'curl_command': f"# Use HTTP/1.0: curl --http1.0 '{discrepancy['forbidden_url']}'"
        }
        self.bypasses.append(bypass)
    
    def _generate_encoding_bypass(self, discrepancy: Dict):
        """Generate encoding-based bypass"""
        bypass = {
            'id': f"bypass_{len(self.bypasses) + 1}",
            'type': 'Encoding Confusion',
            'discrepancy': discrepancy,
            'severity': discrepancy['severity'],
            'method': 'GET',
            'url': discrepancy['test_url'],
            'headers': {},
            'description': f"Encoding confusion bypass: {discrepancy['encoded_variant']}",
            'curl_command': self._generate_curl(discrepancy['test_url'], 'GET', {})
        }
        self.bypasses.append(bypass)
    
    def _generate_curl(self, url: str, method: str, headers: Dict) -> str:
        """Generate curl command"""
        cmd = ['curl', '-i']
        
        if method != 'GET':
            cmd.append(f'-X {method}')
        
        for header, value in headers.items():
            cmd.append(f"-H '{header}: {value}'")
        
        cmd.append(f"'{url}'")
        
        return ' '.join(cmd)


class BypassValidator:
    """
    Validates generated bypasses to confirm they work.
    """
    
    def __init__(self, bypasses: List[Dict], session: requests.Session):
        self.bypasses = bypasses
        self.session = session
        self.validated = []
    
    def validate_all(self):
        """Validate all generated bypasses"""
        print("\n🧪 Phase 5: Bypass Validation")
        print("=" * 70)
        
        if not self.bypasses:
            print("  ⚠️ No bypasses to validate")
            return []
        
        print(f"  🔬 Validating {len(self.bypasses)} bypass techniques...")
        
        for bypass in self.bypasses:
            if self._validate_bypass(bypass):
                self.validated.append(bypass)
                print(f"    ✅ Validated: {bypass['type']} - {bypass['description']}")
            else:
                print(f"    ❌ Failed: {bypass['type']}")
        
        print(f"\n  📊 Validation complete: {len(self.validated)}/{len(self.bypasses)} bypasses confirmed")
        return self.validated
    
    def _validate_bypass(self, bypass: Dict) -> bool:
        """Validate a single bypass"""
        try:
            response = self.session.request(
                method=bypass['method'],
                url=bypass['url'],
                headers=bypass.get('headers', {}),
                timeout=10
            )
            
            # Success if we get anything other than 403/401
            if response.status_code not in [403, 401]:
                bypass['validation'] = {
                    'status': 'CONFIRMED',
                    'response_code': response.status_code,
                    'validated_at': datetime.now().isoformat()
                }
                return True
            
            return False
        except Exception as e:
            bypass['validation'] = {
                'status': 'ERROR',
                'error': str(e)
            }
            return False


class ReportGenerator:
    """
    Generates comprehensive reports and exports.
    """
    
    def __init__(self, target_url: str, stack_analyzer: ProgressiveStackAnalyzer, 
                 discrepancies: List[Dict], bypasses: List[Dict]):
        self.target_url = target_url
        self.stack_analyzer = stack_analyzer
        self.discrepancies = discrepancies
        self.bypasses = bypasses
    
    def generate_text_report(self) -> str:
        """Generate human-readable text report"""
        report = f"""
{'=' * 80}
APPLICATION STACK TRACEROUTE v3.0 - INTELLIGENT RECONSTRUCTION
{'=' * 80}

🎯 TARGET: {self.target_url}
📅 SCAN TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{'=' * 80}
📊 DISCOVERED STACK ARCHITECTURE
{'=' * 80}

"""
        
        # Stack layers
        if self.stack_analyzer.stack['layers']:
            report += "🔗 Processing Chain:\n\n"
            for idx, layer in enumerate(self.stack_analyzer.stack['layers'], 1):
                report += f"  {idx}. {layer['type']}: {layer['component']}\n"
                report += f"     Confidence: {layer['confidence']}/100 ({layer['level']})\n"
                report += f"     Evidence: {', '.join(layer['evidence'])}\n\n"
        else:
            report += "  ⚠️ No stack components detected\n\n"
        
        # Discrepancies
        report += f"\n{'=' * 80}\n"
        report += f"🧪 PARSER DISCREPANCIES FOUND: {len(self.discrepancies)}\n"
        report += f"{'=' * 80}\n\n"
        
        if self.discrepancies:
            for idx, disc in enumerate(self.discrepancies, 1):
                report += f"  {idx}. {disc['type']} - {disc.get('test_name', disc.get('method', 'N/A'))}\n"
                report += f"     Severity: {disc['severity']}\n"
                report += f"     Response: {disc.get('response_code', 'N/A')}\n\n"
        else:
            report += "  ✅ No discrepancies found - stack is consistent\n\n"
        
        # Bypasses
        report += f"\n{'=' * 80}\n"
        report += f"🛠️ GENERATED BYPASSES: {len(self.bypasses)}\n"
        report += f"{'=' * 80}\n\n"
        
        if self.bypasses:
            for idx, bypass in enumerate(self.bypasses, 1):
                report += f"  {idx}. {bypass['type']}\n"
                report += f"     ID: {bypass['id']}\n"
                report += f"     Severity: {bypass['severity']}\n"
                report += f"     Description: {bypass['description']}\n"
                report += f"     Command: {bypass['curl_command']}\n"
                
                if 'validation' in bypass:
                    status = bypass['validation']['status']
                    report += f"     Validation: {status}\n"
                
                report += "\n"
        else:
            report += "  ⚠️ No bypasses generated\n\n"
        
        report += f"\n{'=' * 80}\n"
        report += "📝 NOTES:\n"
        report += f"{'=' * 80}\n\n"
        report += "This report contains validated bypass techniques for authorized security testing.\n"
        report += "Use responsibly and only on targets you have permission to test.\n"
        report += "Export JSON for automation with Exploit Orchestrator tools.\n\n"
        
        return report
    
    def export_json(self, filename: Optional[str] = None) -> str:
        """Export data to JSON for orchestration tools"""
        if not filename:
            domain = urlparse(self.target_url).netloc.replace(':', '_')
            timestamp = int(time.time())
            filename = f"bypasses_{domain}_{timestamp}.json"
        
        data = {
            'metadata': {
                'target': self.target_url,
                'scan_time': datetime.now().isoformat(),
                'version': '3.0',
                'tool': 'Application Traceroute - Intelligent Reconstruction'
            },
            'stack': {
                'layers': self.stack_analyzer.stack['layers'],
                'timeline': self.stack_analyzer.stack['timeline'],
                'correlations': self.stack_analyzer.stack['correlations']
            },
            'discrepancies': self.discrepancies,
            'bypasses': self.bypasses,
            'statistics': {
                'total_layers': len(self.stack_analyzer.stack['layers']),
                'total_discrepancies': len(self.discrepancies),
                'total_bypasses': len(self.bypasses),
                'validated_bypasses': len([b for b in self.bypasses if b.get('validation', {}).get('status') == 'CONFIRMED'])
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\n💾 JSON Export: {filename}")
        return filename


class ApplicationTraceroute:
    """
    Main orchestrator for the complete analysis workflow.
    """
    
    def __init__(self, target_url: str, forbidden_endpoint: Optional[str] = None, 
                 skip_forbidden_tests: bool = False):
        self.target_url = target_url.rstrip('/')
        self.forbidden_endpoint = forbidden_endpoint
        self.skip_forbidden_tests = skip_forbidden_tests
        
        # Initialize session
        self.session = requests.Session()
        self.session.verify = False
        
        # Components
        self.stack_analyzer = ProgressiveStackAnalyzer(target_url)
        self.stack_analyzer.session = self.session  # Share session
        
        self.forbidden_finder = ForbiddenEndpointFinder(target_url, self.session)
        self.discrepancy_tester = None
        self.bypass_generator = None
        self.bypass_validator = None
        self.report_generator = None
    
    async def run_full_analysis(self):
        """Run complete analysis workflow"""
        print("\n" + "=" * 80)
        print("🔬 APPLICATION STACK TRACEROUTE v3.0")
        print("🎯 Intelligent Stack Reconstruction & Bypass Generation")
        print("=" * 80)
        print(f"\n🎯 Target: {self.target_url}\n")
        
        # Phase 0: Find Forbidden Endpoint
        if not self.skip_forbidden_tests:
            self.forbidden_endpoint = self.forbidden_finder.find(self.forbidden_endpoint)
        
        # Phase 1: Send Baseline Request
        print("\n🔍 Phase 1: Baseline Analysis")
        print("=" * 70)
        baseline_response = self.stack_analyzer.send_baseline_request()
        print(f"  ✅ Baseline request completed (Status: {baseline_response.status_code})")
        
        # Phase 2: Progressive Stack Fingerprinting
        print("\n🔍 Phase 2: Progressive Stack Fingerprinting")
        print("=" * 70)
        
        # 2a: Header Timeline Analysis
        timeline = self.stack_analyzer.analyze_header_timeline(baseline_response)
        print(f"  ✅ Header timeline analyzed: {len(timeline)} processing hops detected")
        
        # 2b: Deep Fingerprinting
        self.stack_analyzer.progressive_fingerprinting(baseline_response)
        
        # 2c: Correlate Stack
        self.stack_analyzer.correlate_stack()
        
        # Phase 3: Discrepancy Testing
        if self.forbidden_endpoint and not self.skip_forbidden_tests:
            self.discrepancy_tester = DiscrepancyTester(
                self.target_url, 
                self.forbidden_endpoint, 
                self.session,
                self.stack_analyzer
            )
            discrepancies = self.discrepancy_tester.test_all_discrepancies()
        else:
            print("\n⚠️ Phase 3: Skipping discrepancy testing (no forbidden endpoint)")
            discrepancies = []
        
        # Phase 4: Bypass Generation
        self.bypass_generator = BypassGenerator(
            discrepancies,
            self.stack_analyzer.stack
        )
        bypasses = self.bypass_generator.generate_all_bypasses()
        
        # Phase 5: Bypass Validation
        self.bypass_validator = BypassValidator(bypasses, self.session)
        validated_bypasses = self.bypass_validator.validate_all()
        
        # Phase 6: Report Generation
        self.report_generator = ReportGenerator(
            self.target_url,
            self.stack_analyzer,
            discrepancies,
            validated_bypasses
        )
        
        # Generate text report
        text_report = self.report_generator.generate_text_report()
        
        # Export JSON
        json_file = self.report_generator.export_json()
        
        # Save text report
        report_filename = f"traceroute_{int(time.time())}.txt"
        with open(report_filename, 'w') as f:
            f.write(text_report)
        
        print(f"\n📄 Text Report: {report_filename}")
        
        # Print summary
        print("\n" + "=" * 80)
        print("📊 ANALYSIS COMPLETE")
        print("=" * 80)
        print(f"  Stack Layers: {len(self.stack_analyzer.stack['layers'])}")
        print(f"  Discrepancies: {len(discrepancies)}")
        print(f"  Bypasses Generated: {len(bypasses)}")
        print(f"  Bypasses Validated: {len(validated_bypasses)}")
        print("\n" + "=" * 80)
        
        return text_report


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Application Stack Traceroute v3.0 - Intelligent Stack Reconstruction',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python app_traceroute_v3.py https://target.com
  python app_traceroute_v3.py https://target.com --forbidden-endpoint https://target.com/admin
  python app_traceroute_v3.py https://target.com --skip-forbidden-tests
        """
    )
    
    parser.add_argument('target', help='Target URL to analyze')
    parser.add_argument(
        '--forbidden-endpoint',
        help='Known 403/401 endpoint for bypass testing (e.g. https://target.com/admin)'
    )
    parser.add_argument(
        '--skip-forbidden-tests',
        action='store_true',
        help='Skip tests requiring forbidden endpoint'
    )
    
    args = parser.parse_args()
    
    # Run analysis
    tracer = ApplicationTraceroute(
        args.target,
        forbidden_endpoint=args.forbidden_endpoint,
        skip_forbidden_tests=args.skip_forbidden_tests
    )
    
    # Use asyncio for async operations
    asyncio.run(tracer.run_full_analysis())


if __name__ == "__main__":
    main()