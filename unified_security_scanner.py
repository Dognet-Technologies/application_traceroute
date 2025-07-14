#!/usr/bin/env python3
"""
Unified Security Scanner
Combines Application Stack Traceroute + Smart Vulnerability Crawler
With authentication support and optimized bypass usage
"""

import json
import time
import logging
import argparse
import signal
import sys
from urllib.parse import urlparse, urljoin
import requests
from collections import defaultdict

# Import core components from existing scripts
# Assuming they're in the same directory
try:
    from application_traceroute import ApplicationTraceroute
    from smart_vuln_crawler import (
        SmartCrawler, TechnologyDetector, ParameterAnalyzer, 
        WordlistMapper, DiscoveryWordlistMapper
    )
except ImportError:
    print("Error: Make sure application_traceroute.py and smart_vuln_crawler.py are in the same directory")
    exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class GracefulInterrupt:
    """Handle Ctrl+C gracefully"""
    def __init__(self):
        self.interrupted = False
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        print("\n\n⏸️  Crawling interrupted by user (Ctrl+C)")
        print("⏩ Skipping to vulnerability analysis phase...")
        self.interrupted = True


class AuthenticationHandler:
    """Handle various authentication methods"""
    
    def __init__(self, session):
        self.session = session
        self.auth_type = None
        self.is_authenticated = False
    
    def authenticate(self, auth_config):
        """Authenticate based on config"""
        if not auth_config:
            return True
        
        auth_type = auth_config.get('type', '').lower()
        
        if auth_type == 'form':
            return self.form_auth(auth_config)
        elif auth_type == 'header':
            return self.header_auth(auth_config)
        elif auth_type == 'basic':
            return self.basic_auth(auth_config)
        elif auth_type == 'bearer':
            return self.bearer_auth(auth_config)
        elif auth_type == 'cookie':
            return self.cookie_auth(auth_config)
        else:
            logger.error(f"Unknown auth type: {auth_type}")
            return False
    
    def form_auth(self, config):
        """Handle form-based authentication"""
        try:
            login_url = config.get('login_url')
            username_field = config.get('username_field', 'username')
            password_field = config.get('password_field', 'password')
            
            # Check for additional fields (CSRF tokens, etc)
            additional_fields = config.get('additional_fields', {})
            
            # Build login data
            login_data = {
                username_field: config.get('username'),
                password_field: config.get('password')
            }
            login_data.update(additional_fields)
            
            # Get login page first (for CSRF tokens)
            if config.get('csrf_token'):
                login_page = self.session.get(login_url)
                csrf_token = self._extract_csrf_token(login_page.text, config.get('csrf_token'))
                if csrf_token:
                    login_data[config.get('csrf_field', 'csrf_token')] = csrf_token
            
            # Submit login
            response = self.session.post(login_url, data=login_data, allow_redirects=True)
            
            # Check success indicators
            success_indicators = config.get('success_indicators', ['dashboard', 'logout', 'profile'])
            success = any(indicator in response.text.lower() or indicator in response.url.lower() 
                         for indicator in success_indicators)
            
            if success:
                logger.info("Form authentication successful")
                self.is_authenticated = True
                self.auth_type = 'form'
                return True
            else:
                logger.error("Form authentication failed")
                return False
                
        except Exception as e:
            logger.error(f"Form auth error: {e}")
            return False
    
    def header_auth(self, config):
        """Handle header-based authentication"""
        try:
            header_name = config.get('header_name', 'Authorization')
            header_value = config.get('header_value')
            
            self.session.headers[header_name] = header_value
            
            # Test auth
            test_url = config.get('test_url', config.get('target'))
            response = self.session.get(test_url)
            
            if response.status_code != 401:
                logger.info("Header authentication successful")
                self.is_authenticated = True
                self.auth_type = 'header'
                return True
            else:
                logger.error("Header authentication failed")
                return False
                
        except Exception as e:
            logger.error(f"Header auth error: {e}")
            return False
    
    def basic_auth(self, config):
        """Handle HTTP Basic authentication"""
        try:
            username = config.get('username')
            password = config.get('password')
            
            self.session.auth = (username, password)
            
            # Test auth
            test_url = config.get('test_url', config.get('target'))
            response = self.session.get(test_url)
            
            if response.status_code != 401:
                logger.info("Basic authentication successful")
                self.is_authenticated = True
                self.auth_type = 'basic'
                return True
            else:
                logger.error("Basic authentication failed")
                return False
                
        except Exception as e:
            logger.error(f"Basic auth error: {e}")
            return False
    
    def bearer_auth(self, config):
        """Handle Bearer token authentication"""
        try:
            token = config.get('token')
            self.session.headers['Authorization'] = f'Bearer {token}'
            
            # Test auth
            test_url = config.get('test_url', config.get('target'))
            response = self.session.get(test_url)
            
            if response.status_code != 401:
                logger.info("Bearer authentication successful")
                self.is_authenticated = True
                self.auth_type = 'bearer'
                return True
            else:
                logger.error("Bearer authentication failed")
                return False
                
        except Exception as e:
            logger.error(f"Bearer auth error: {e}")
            return False
    
    def cookie_auth(self, config):
        """Handle cookie-based authentication"""
        try:
            cookies = config.get('cookies', {})
            
            for name, value in cookies.items():
                self.session.cookies.set(name, value)
            
            # Test auth
            test_url = config.get('test_url', config.get('target'))
            response = self.session.get(test_url)
            
            if response.status_code != 401:
                logger.info("Cookie authentication successful")
                self.is_authenticated = True
                self.auth_type = 'cookie'
                return True
            else:
                logger.error("Cookie authentication failed")
                return False
                
        except Exception as e:
            logger.error(f"Cookie auth error: {e}")
            return False
    
    def _extract_csrf_token(self, html, token_pattern):
        """Extract CSRF token from HTML"""
        import re
        from bs4 import BeautifulSoup
        
        # Try regex pattern first
        if token_pattern.startswith('regex:'):
            pattern = token_pattern[6:]
            match = re.search(pattern, html)
            if match:
                return match.group(1)
        
        # Try CSS selector
        elif token_pattern.startswith('css:'):
            selector = token_pattern[4:]
            soup = BeautifulSoup(html, 'html.parser')
            element = soup.select_one(selector)
            if element:
                return element.get('value') or element.text
        
        # Default: look for common CSRF patterns
        else:
            patterns = [
                r'csrf[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'<input[^>]+name=["\']csrf[_-]?token["\'][^>]+value=["\']([^"\']+)["\']',
                r'<meta[^>]+name=["\']csrf[_-]?token["\'][^>]+content=["\']([^"\']+)["\']'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, html, re.I)
                if match:
                    return match.group(1)
        
        return None


class UnifiedSecurityScanner:
    """Unified scanner combining traceroute + crawler with optimizations"""
    
    def __init__(self, target_url, auth_config=None, wordlist_base=None):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        
        # Graceful interrupt handler
        self.interrupt_handler = GracefulInterrupt()
        
        # Shared session for all components
        self.session = requests.Session()
        
        # Authentication
        self.auth_handler = AuthenticationHandler(self.session)
        if auth_config:
            if not self.auth_handler.authenticate(auth_config):
                logger.error("Authentication failed, continuing without auth")
        
        # Results storage
        self.results = {
            'target': target_url,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'authenticated': self.auth_handler.is_authenticated,
            'infrastructure': {},
            'bypasses': [],
            'endpoints': [],
            'vulnerabilities': defaultdict(list)
        }
        
        # Initialize components with shared session
        self._init_components(wordlist_base)
        
        # Initialize empty bypasses
        self.all_bypasses = []
    
    def _init_components(self, wordlist_base):
        """Initialize scanner components"""
        # Application traceroute for bypass detection
        self.traceroute = ApplicationTraceroute(self.target_url)
        # Share the session
        self.traceroute.session = self.session
        
        # Smart crawler
        self.crawler = SmartCrawler(self.target_url)
        # Share the session and auth
        self.crawler.session = self.session
        
        # Set wordlist paths if provided
        if wordlist_base:
            base_paths = {
                'fuzzdb': f"{wordlist_base}/fuzzdb",
                'payloads': f"{wordlist_base}/PayloadsAllTheThings",
                'seclists': f"{wordlist_base}/SecLists"
            }
            self.crawler.wordlist_mapper.base_paths = base_paths
            self.crawler.discovery_mapper.base_paths = base_paths
    
    def run(self, discovery_limit=1000, skip_discovery=False):
        """Run unified security scan"""
        print("🚀 Starting Unified Security Scan")
        print("=" * 60)
        print("💡 Tip: Press Ctrl+C during crawling to skip to vulnerability analysis")
        
        try:
            # Phase 1: Infrastructure Analysis (run once)
            print("\n🔍 Phase 1: Infrastructure Analysis")
            self.analyze_infrastructure()
            
            # Phase 2: Bypass Detection (run once on base URL)
            print("\n🔍 Phase 2: Bypass Detection")
            self.detect_bypasses()
            
            # Phase 3: Smart Crawling with Bypasses (interruptible)
            print("\n🔍 Phase 3: Smart Crawling with Bypass Application")
            print("   (Press Ctrl+C to skip remaining crawling and analyze found endpoints)")
            self.crawl_with_bypasses(discovery_limit, skip_discovery)
            
            if self.interrupt_handler.interrupted:
                print("\n⏩ Crawling interrupted - Moving to vulnerability analysis")
            
            # Phase 4: Vulnerability Analysis (always run on found endpoints)
            print("\n🔍 Phase 4: Vulnerability Analysis")
            self.analyze_vulnerabilities()
            
        except Exception as e:
            logger.error(f"Error during scan: {e}")
        
        # Phase 5: Generate Report (always run)
        print("\n📊 Phase 5: Generating Report")
        return self.generate_report()
    
    def analyze_infrastructure(self):
        """Run infrastructure fingerprinting once"""
        # Use traceroute's infrastructure fingerprinting
        self.traceroute.infrastructure_fingerprinting()
        
        # Store results
        self.results['infrastructure'] = {
            'chain': self.traceroute.chain_map['layers'],
            'technologies': self.traceroute.chain_map['fingerprints'],
            'protocols': self.traceroute.protocols
        }
        
        print(f"✅ Infrastructure chain: {' → '.join(self.results['infrastructure']['chain'])}")
    
    def detect_bypasses(self):
        """Detect bypasses using traceroute's discrepancy testing"""
        # Override the traceroute methods to check for interruption
        original_test = self.traceroute.parser_discrepancy_testing
        
        def interruptible_test():
            # Run only essential tests if interrupted
            if self.interrupt_handler.interrupted:
                logger.info("Skipping remaining discrepancy tests due to interruption")
                return
            original_test()
        
        self.traceroute.parser_discrepancy_testing = interruptible_test
        
        # Run parser discrepancy testing
        self.traceroute.parser_discrepancy_testing()
        
        # Restore original
        self.traceroute.parser_discrepancy_testing = original_test
        
        # Generate bypasses
        self.traceroute.generate_custom_bypasses()
        
        # Store validated bypasses
        self.results['bypasses'] = [
            bypass for bypass in self.traceroute.chain_map['bypasses']
            if bypass.get('validated', False)
        ]
        
        # Also keep all bypasses for testing
        self.all_bypasses = self.traceroute.chain_map['bypasses']
        
        print(f"✅ Found {len(self.results['bypasses'])} validated bypasses")
        print(f"📋 Total bypasses available: {len(self.all_bypasses)}")
    
    def crawl_with_bypasses(self, discovery_limit, skip_discovery):
        """Run crawler with bypass support for 403/401 endpoints"""
        # Modified crawler that uses bypasses
        self.crawler.bypasses = getattr(self, 'all_bypasses', [])
        
        # Override the crawler's run method to check for interruption
        original_run = self.crawler.run
        
        def interruptible_run(discovery_limit, skip_discovery):
            # Modified run that checks for interruption
            self.crawler.url_queue.put((self.crawler.target_url, 0))
            
            # Crawl with interruption check
            while not self.crawler.url_queue.empty() and len(self.crawler.visited_urls) < self.crawler.max_pages:
                if self.interrupt_handler.interrupted:
                    logger.info("Crawling interrupted by user")
                    break
                    
                url, depth = self.crawler.url_queue.get()
                crawl_page_with_bypass(url, depth)
                
                # Small delay between requests
                import random
                time.sleep(random.uniform(0.5, 1.5))
            
            # Process results
            self.crawler.results['endpoints'] = self.crawler.endpoints
            return self.crawler.results
        
        # Override crawler's request method to try bypasses on 403/401
        original_crawl_page = self.crawler.crawl_page
        
        def crawl_page_with_bypass(url, depth=0):
            """Modified crawl_page that tries bypasses on protected resources"""
            # Check for interruption
            if hasattr(self, 'interrupt_handler') and self.interrupt_handler.interrupted:
                return
            
            # First try normal request
            normalized_url = self.crawler.normalize_url(url)
            if normalized_url in self.crawler.visited_urls:
                return
            
            self.crawler.visited_urls.add(normalized_url)
            logger.info(f"Crawling: {url} (depth: {depth})")
            
            try:
                self.crawler._rotate_user_agent()
                response = self.crawler.session.get(url, timeout=10, verify=False)
                
                # If 403/401, try bypasses
                if response.status_code in [401, 403]:
                    logger.info(f"Protected resource detected: {url} ({response.status_code})")
                    
                    for bypass in self.all_bypasses:
                        if self.interrupt_handler.interrupted:
                            break
                        if self.try_bypass_on_url(url, bypass):
                            logger.info(f"✅ Bypass successful: {bypass['type']} on {url}")
                            # Re-crawl with bypass applied
                            response = self.crawler.session.get(url, timeout=10, verify=False)
                            break
                
                # Continue normal crawling logic
                if response.status_code == 200:
                    # Process the page normally
                    # Check content type to avoid XML parsing warnings
                    content_type = response.headers.get('Content-Type', '').lower()
                    
                    if 'xml' not in content_type and response.text and len(response.text) > 10:
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(response.text, 'html.parser')
                        
                        # Extract URLs
                        for tag in soup.find_all(['a', 'link']):
                            href = tag.get('href')
                            if href:
                                absolute_url = urljoin(url, href)
                                if self.crawler.is_valid_url(absolute_url):
                                    self.crawler.url_queue.put((absolute_url, depth + 1))
                
            except Exception as e:
                logger.error(f"Error crawling {url}: {e}")
        
        # Replace method temporarily
        self.crawler.crawl_page = crawl_page_with_bypass
        self.crawler.run = lambda dl, sd: interruptible_run(dl, sd)
        
        # Run crawler
        crawler_results = self.crawler.run(discovery_limit, skip_discovery)
        
        # Restore original methods
        self.crawler.crawl_page = original_crawl_page
        self.crawler.run = original_run
        
        # Store results
        self.results['endpoints'] = crawler_results.get('endpoints', [])
        self.results['technologies'].update(crawler_results.get('technologies', {}))
        
        print(f"✅ Found {len(self.results['endpoints'])} endpoints")
    
    def analyze_vulnerabilities(self):
        """Analyze found endpoints for injection points and vulnerabilities"""
        print(f"  🔍 Analyzing {len(self.results['endpoints'])} endpoints for vulnerabilities...")
        
        # Initialize analyzer if not already done
        if not hasattr(self.crawler, 'param_analyzer'):
            from smart_vuln_crawler import ParameterAnalyzer, WordlistMapper
            self.crawler.param_analyzer = ParameterAnalyzer()
        
        if not hasattr(self.crawler, 'wordlist_mapper'):
            from smart_vuln_crawler import WordlistMapper
            self.crawler.wordlist_mapper = WordlistMapper()
        
        analyzed_count = 0
        vuln_count = 0
        
        # Analyze each endpoint
        for endpoint in self.results['endpoints']:
            if self.interrupt_handler.interrupted:
                print("  ⏩ Vulnerability analysis interrupted")
                break
            
            # Skip if already has parameters analyzed
            if endpoint.get('parameters'):
                for param in endpoint['parameters']:
                    if param.get('predicted_vulns'):
                        vuln_count += len(param['predicted_vulns'])
                continue
            
            # Analyze endpoint for parameters
            url = endpoint['url']
            method = endpoint.get('method', 'GET')
            
            try:
                # Make request to get response for analysis
                response = self.session.get(url, timeout=5, verify=False)
                
                # Extract parameters from URL
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                
                if params:
                    endpoint['parameters'] = []
                    
                    for param_name, values in params.items():
                        param_value = values[0] if values else ''
                        
                        # Analyze parameter
                        vulns = self.crawler.param_analyzer.analyze_parameter(
                            param_name, param_value, response.text
                        )
                        
                        if vulns:
                            param_data = {
                                'name': param_name,
                                'location': 'query',
                                'type': 'string',
                                'value_sample': param_value,
                                'predicted_vulns': vulns
                            }
                            
                            # Add wordlists for each vulnerability
                            for vuln in vulns:
                                vuln['wordlists'] = self.crawler.wordlist_mapper.get_wordlists_for_vulnerability(
                                    vuln['type'], self.results.get('technologies', {})
                                )
                            
                            endpoint['parameters'].append(param_data)
                            vuln_count += len(vulns)
                    
                    analyzed_count += 1
                
                # Also check for forms in the response
                if response.status_code == 200 and 'html' in response.headers.get('Content-Type', ''):
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Use crawler's extract_forms method
                    forms = []
                    for form in soup.find_all('form'):
                        form_data = {
                            'action': urljoin(url, form.get('action', url)),
                            'method': form.get('method', 'get').upper(),
                            'inputs': []
                        }
                        
                        # Extract all inputs
                        for input_tag in form.find_all(['input', 'textarea', 'select']):
                            input_data = {
                                'name': input_tag.get('name', ''),
                                'type': input_tag.get('type', 'text'),
                                'value': input_tag.get('value', ''),
                                'required': input_tag.get('required') is not None
                            }
                            
                            if input_data['name']:
                                form_data['inputs'].append(input_data)
                        
                        if form_data['inputs']:
                            forms.append(form_data)
                    if forms:
                        for form in forms:
                            # Analyze form inputs
                            form_endpoint = {
                                'url': form['action'],
                                'method': form['method'],
                                'parameters': [],
                                'form': True
                            }
                            
                            for input_field in form['inputs']:
                                param = {
                                    'name': input_field['name'],
                                    'location': 'body',
                                    'type': input_field['type'],
                                    'required': input_field.get('required', False),
                                    'predicted_vulns': []
                                }
                                
                                # Special handling for file upload
                                if input_field['type'] == 'file':
                                    param['predicted_vulns'].append({
                                        'type': 'file_upload',
                                        'confidence': 'high',
                                        'wordlists': self.crawler.wordlist_mapper.get_wordlists_for_vulnerability(
                                            'file_upload', self.results.get('technologies', {})
                                        )
                                    })
                                    vuln_count += 1
                                
                                form_endpoint['parameters'].append(param)
                            
                            if form_endpoint['parameters']:
                                self.results['endpoints'].append(form_endpoint)
                                self.results.setdefault('forms', []).append(form_data)
                                analyzed_count += 1
                
            except Exception as e:
                logger.debug(f"Error analyzing {url}: {e}")
                continue
        
        # Re-calculate priorities with vulnerability data
        for endpoint in self.results['endpoints']:
            # Calculate priority based on vulnerabilities
            score = 0
            
            # Status code based scoring
            status = endpoint.get('status', 200)
            if status == 403:
                score += 15
            elif status in [301, 302]:
                score += 10
            elif status == 401:
                score += 8
            
            # Sensitive files/paths
            sensitive_patterns = ['.git', '.env', 'config', 'backup', '.sql', '.zip', '.tar']
            for pattern in sensitive_patterns:
                if pattern in endpoint['url'].lower():
                    score += 20
            
            # High value endpoints
            high_value_paths = ['/admin', '/api', '/upload', '/login', '/register']
            for path in high_value_paths:
                if path in endpoint['url'].lower():
                    score += 10
            
            # Number of parameters
            score += len(endpoint.get('parameters', [])) * 2
            
            # Vulnerabilities
            for param in endpoint.get('parameters', []):
                for vuln in param.get('predicted_vulns', []):
                    if vuln['confidence'] == 'high':
                        score += 8
                    elif vuln['confidence'] == 'medium':
                        score += 5
                    else:
                        score += 2
            
            endpoint['priority'] = score
        
        # Sort by priority
        self.results['endpoints'].sort(key=lambda x: x.get('priority', 0), reverse=True)
        
        print(f"  ✅ Analyzed {analyzed_count} endpoints")
        print(f"  🎯 Found {vuln_count} potential vulnerabilities")
    
    def try_bypass_on_url(self, url, bypass):
        """Try a specific bypass on a URL"""
        try:
            parsed = urlparse(url)
            
            # Apply bypass based on type
            if bypass['type'] == 'Header Bypass':
                # Temporarily add bypass headers
                original_headers = dict(self.session.headers)
                self.session.headers.update(bypass['payload'])
                
                response = self.session.get(url, timeout=5, verify=False)
                
                # Restore headers
                self.session.headers = original_headers
                
                return response.status_code not in [401, 403]
            
            elif bypass['type'] in ['Path Bypass', 'Unicode Bypass', 'Encoding Bypass']:
                # Modify the URL
                bypass_url = url.replace(parsed.path, bypass['payload'])
                response = self.session.get(bypass_url, timeout=5, verify=False)
                return response.status_code not in [401, 403]
            
            # Add more bypass types as needed
            
        except Exception:
            return False
        
        return False
    
    def generate_report(self):
        """Generate comprehensive report"""
        # Count vulnerabilities
        vuln_summary = defaultdict(int)
        for endpoint in self.results['endpoints']:
            for param in endpoint.get('parameters', []):
                for vuln in param.get('predicted_vulns', []):
                    vuln_summary[vuln['type']] += 1
        
        report = {
            'summary': {
                'target': self.target_url,
                'scan_time': self.results['scan_time'],
                'authenticated': self.results['authenticated'],
                'scan_completed': not self.interrupt_handler.interrupted,
                'total_endpoints': len(self.results['endpoints']),
                'total_bypasses': len(self.results['bypasses']),
                'total_vulnerabilities': sum(vuln_summary.values()),
                'vulnerability_types': dict(vuln_summary),
                'infrastructure_chain': ' → '.join(self.results['infrastructure']['chain']) if self.results['infrastructure'].get('chain') else 'Not analyzed'
            },
            'infrastructure': self.results['infrastructure'],
            'bypasses': self.results['bypasses'],
            'endpoints': self.results['endpoints'],
            'technologies': self.results.get('technologies', {}),
            'recommendations': self.generate_recommendations()
        }
        
        if self.interrupt_handler.interrupted:
            report['summary']['note'] = 'Crawling was interrupted by user. Vulnerability analysis completed on found endpoints.'
        
        return report
    
    def generate_recommendations(self):
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Check for exposed sensitive files
        sensitive_endpoints = [
            ep for ep in self.results['endpoints'] 
            if any(pattern in ep['url'].lower() 
                   for pattern in ['.git', '.env', 'config', 'backup'])
        ]
        
        if sensitive_endpoints:
            recommendations.append({
                'severity': 'HIGH',
                'title': 'Exposed Sensitive Files',
                'description': f'Found {len(sensitive_endpoints)} potentially sensitive endpoints',
                'endpoints': [ep['url'] for ep in sensitive_endpoints[:5]]
            })
        
        # Check for successful bypasses
        if self.results['bypasses']:
            recommendations.append({
                'severity': 'HIGH',
                'title': 'WAF/Security Bypass Possible',
                'description': f'Found {len(self.results["bypasses"])} working bypass techniques',
                'bypass_types': list(set(b['type'] for b in self.results['bypasses']))
            })
        
        # Check for vulnerabilities by type
        vuln_summary = defaultdict(list)
        for endpoint in self.results['endpoints']:
            for param in endpoint.get('parameters', []):
                for vuln in param.get('predicted_vulns', []):
                    vuln_summary[vuln['type']].append({
                        'endpoint': endpoint['url'],
                        'parameter': param['name'],
                        'confidence': vuln['confidence']
                    })
        
        # SQL Injection
        if 'sqli' in vuln_summary:
            recommendations.append({
                'severity': 'CRITICAL',
                'title': 'Potential SQL Injection',
                'description': f'Found {len(vuln_summary["sqli"])} potential SQL injection points',
                'examples': vuln_summary['sqli'][:3]
            })
        
        # XSS
        if 'xss' in vuln_summary:
            recommendations.append({
                'severity': 'HIGH',
                'title': 'Potential Cross-Site Scripting (XSS)',
                'description': f'Found {len(vuln_summary["xss"])} potential XSS injection points',
                'examples': vuln_summary['xss'][:3]
            })
        
        # File Upload
        if 'file_upload' in vuln_summary:
            recommendations.append({
                'severity': 'HIGH',
                'title': 'File Upload Functionality',
                'description': f'Found {len(vuln_summary["file_upload"])} file upload endpoints',
                'examples': vuln_summary['file_upload'][:3]
            })
        
        # RCE
        if 'rce' in vuln_summary:
            recommendations.append({
                'severity': 'CRITICAL',
                'title': 'Potential Remote Code Execution',
                'description': f'Found {len(vuln_summary["rce"])} potential RCE injection points',
                'examples': vuln_summary['rce'][:3]
            })
        
        return recommendations
    
    def export_results(self, filename='unified_scan_results.json'):
        """Export results to JSON file"""
        report = self.generate_report()
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Results exported to {filename}")
        return filename


def main():
    parser = argparse.ArgumentParser(description='Unified Security Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('--auth-config', help='Path to authentication config JSON')
    parser.add_argument('--wordlist-base', help='Base path for wordlists')
    parser.add_argument('--discovery-limit', type=int, default=1000,
                       help='Max paths to test from wordlists (default: 1000)')
    parser.add_argument('--skip-discovery', action='store_true',
                       help='Skip wordlist-based discovery')
    parser.add_argument('--output', default='unified_scan_results.json',
                       help='Output JSON file (default: unified_scan_results.json)')
    
    args = parser.parse_args()
    
    # Load auth config if provided
    auth_config = None
    if args.auth_config:
        try:
            with open(args.auth_config, 'r') as f:
                auth_config = json.load(f)
                auth_config['target'] = args.target  # Add target to config
        except Exception as e:
            logger.error(f"Failed to load auth config: {e}")
    
    # Create scanner
    scanner = UnifiedSecurityScanner(
        args.target,
        auth_config=auth_config,
        wordlist_base=args.wordlist_base
    )
    
    # Run scan
    scanner.run(
        discovery_limit=args.discovery_limit,
        skip_discovery=args.skip_discovery
    )
    
    # Export results
    output_file = scanner.export_results(args.output)
    
    # Print summary
    print("\n" + "="*60)
    print("SCAN COMPLETE")
    print("="*60)
    
    report = scanner.generate_report()
    summary = report['summary']
    
    print(f"Target: {summary['target']}")
    print(f"Authenticated: {summary['authenticated']}")
    print(f"Scan Status: {'INTERRUPTED (crawling)' if not summary['scan_completed'] else 'COMPLETED'}")
    print(f"Infrastructure: {summary['infrastructure_chain']}")
    print(f"Total Endpoints: {summary['total_endpoints']}")
    print(f"Working Bypasses: {summary['total_bypasses']}")
    print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
    
    # Show vulnerability breakdown
    if summary.get('vulnerability_types'):
        print("\n🎯 VULNERABILITIES FOUND:")
        for vuln_type, count in summary['vulnerability_types'].items():
            print(f"  - {vuln_type.upper()}: {count}")
    
    # Show top vulnerable endpoints
    vulnerable_endpoints = [ep for ep in report['endpoints'] if any(p.get('predicted_vulns') for p in ep.get('parameters', []))]
    if vulnerable_endpoints:
        print("\n🔝 TOP VULNERABLE ENDPOINTS:")
        for endpoint in vulnerable_endpoints[:5]:
            print(f"  [{endpoint.get('priority', 0)}] {endpoint.get('method', 'GET')} {endpoint['url']}")
            for param in endpoint.get('parameters', [])[:2]:
                if param.get('predicted_vulns'):
                    vulns = ', '.join([v['type'] for v in param['predicted_vulns']])
                    print(f"    └─ {param['name']}: {vulns}")
    
    # Show recommendations
    if report['recommendations']:
        print("\n🚨 SECURITY RECOMMENDATIONS:")
        for rec in report['recommendations']:
            print(f"\n[{rec['severity']}] {rec['title']}")
            print(f"  {rec['description']}")
    
    print(f"\nFull results saved to: {output_file}")
    print("="*60)


if __name__ == "__main__":
    main()