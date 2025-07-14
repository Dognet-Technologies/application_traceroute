#!/usr/bin/env python3
"""
Smart Vulnerability Crawler & Predictor
Advanced Web Application Security Analysis Tool

Features:
- Intelligent crawling with JavaScript analysis
- Technology fingerprinting
- Context-aware vulnerability prediction
- Automatic wordlist mapping
- Priority scoring for attack vectors
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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


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
                    'confidence': 'high' if context in ['html', 'attribute'] else 'medium',
                    'context': context,
                    'evidence': 'Parameter value reflected in response'
                })
        
        # SQL Injection indicators
        if param_name_lower in self.sql_params or re.search(r'(id|ID|Id)$', param_name):
            vulnerabilities.append({
                'type': 'sqli',
                'confidence': 'medium',
                'context': 'database_parameter',
                'evidence': f'Parameter name suggests database query: {param_name}'
            })
        
        # File Inclusion indicators
        if param_name_lower in self.file_params:
            vulnerabilities.append({
                'type': 'lfi',
                'confidence': 'medium',
                'context': 'file_parameter',
                'evidence': f'Parameter name suggests file operation: {param_name}'
            })
        
        # Command Injection indicators
        if param_name_lower in self.cmd_params:
            vulnerabilities.append({
                'type': 'rce',
                'confidence': 'medium',
                'context': 'command_parameter',
                'evidence': f'Parameter name suggests command execution: {param_name}'
            })
        
        # XXE indicators
        if param_name_lower in self.xxe_params or 'xml' in content_type.lower():
            vulnerabilities.append({
                'type': 'xxe',
                'confidence': 'medium',
                'context': 'xml_parameter',
                'evidence': f'Parameter appears to accept XML data: {param_name}'
            })
        
        # SSTI indicators
        if param_name_lower in ['template', 'name', 'view', 'page'] and '{{' not in str(param_value):
            vulnerabilities.append({
                'type': 'ssti',
                'confidence': 'low',
                'context': 'template_parameter',
                'evidence': f'Parameter name suggests template usage: {param_name}'
            })
        
        # Open Redirect indicators
        if param_name_lower in ['url', 'link', 'redirect', 'return', 'next', 'callback', 'goto']:
            vulnerabilities.append({
                'type': 'open_redirect',
                'confidence': 'medium',
                'context': 'redirect_parameter',
                'evidence': f'Parameter name suggests redirection: {param_name}'
            })
        
        # LDAP Injection indicators
        if param_name_lower in ['username', 'user', 'name', 'uid', 'cn', 'dn']:
            vulnerabilities.append({
                'type': 'ldapi',
                'confidence': 'low',
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
            }
        }
    
    def get_wordlists_for_vulnerability(self, vuln_type, technology=None):
        """Get appropriate wordlists for a vulnerability type"""
        wordlists = []
        
        if vuln_type not in self.wordlist_map:
            return wordlists
        
        vuln_lists = self.wordlist_map[vuln_type]
        
        # Add technology-specific wordlists
        if technology:
            if vuln_type == 'sqli':
                if technology.get('database') == 'mysql':
                    vuln_lists['fuzzdb'].append('attack/sql-injection/detect/MySQL.txt')
                elif technology.get('database') == 'mssql':
                    vuln_lists['fuzzdb'].append('attack/sql-injection/detect/MSSQL.txt')
            
            elif vuln_type == 'file_upload' and technology.get('language'):
                lang = technology['language'].lower()
                if lang == 'php':
                    vuln_lists['fuzzdb'].append('attack/file-upload/alt-extensions-php.txt')
                elif lang == 'asp.net':
                    vuln_lists['fuzzdb'].append('attack/file-upload/alt-extensions-asp.txt')
        
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
                'SecLists/Discovery/Web-Content/raft-small-files.txt',
                'fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-small-directories.txt'
            ],
            'wordpress': [
                'SecLists/Discovery/Web-Content/CMS/wordpress.txt',
                'SecLists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt',
                'SecLists/Discovery/Web-Content/CMS/wp-themes.fuzz.txt',
                'fuzzdb/discovery/predictable-filepaths/cms/wordpress.txt',
                'PayloadsAllTheThings/CMS/wordpress-all-levels.txt'
            ],
            'drupal': [
                'SecLists/Discovery/Web-Content/CMS/drupal-themes.fuzz.txt',
                'SecLists/Discovery/Web-Content/CMS/Drupal.txt',
                'PayloadsAllTheThings/CMS/drupal-all-levels.txt'
            ],
            'joomla': [
                'SecLists/Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt',
                'SecLists/Discovery/Web-Content/CMS/joomla-themes.fuzz.txt',
                'PayloadsAllTheThings/CMS/joomla-all-levels.txt'
            ],
            'php': [
                'SecLists/Discovery/Web-Content/PHP.fuzz.txt',
                'SecLists/Discovery/Web-Content/Common-PHP-Filenames.txt',
                'SecLists/Discovery/Web-Content/CommonBackdoors-PHP.fuzz.txt',
                'fuzzdb/discovery/predictable-filepaths/php/PHP.txt',
                'fuzzdb/discovery/predictable-filepaths/php/PHP_CommonBackdoors.txt'
            ],
            'asp.net': [
                'SecLists/Discovery/Web-Content/IIS.fuzz.txt',
                'SecLists/Discovery/Web-Content/iis-systemweb.txt',
                'SecLists/Discovery/Web-Content/SharePoint.fuzz.txt',
                'fuzzdb/discovery/predictable-filepaths/webservers-appservers/IIS.txt',
                'fuzzdb/discovery/predictable-filepaths/webservers-appservers/Sharepoint.txt'
            ],
            'java': [
                'SecLists/Discovery/Web-Content/tomcat.txt',
                'SecLists/Discovery/Web-Content/JavaServlets-Common.fuzz.txt',
                'SecLists/Discovery/Web-Content/jboss.txt',
                'fuzzdb/discovery/predictable-filepaths/webservers-appservers/ApacheTomcat.txt',
                'fuzzdb/discovery/predictable-filepaths/webservers-appservers/JBoss.txt'
            ],
            'python': [
                'SecLists/Discovery/Web-Content/django.txt',
                'SecLists/Discovery/Web-Content/ror.txt',
                'PayloadsAllTheThings/CMS/django-cms-all-levels.txt'
            ],
            'api': [
                'SecLists/Discovery/Web-Content/api/api-endpoints.txt',
                'SecLists/Discovery/Web-Content/api/api-endpoints-res.txt',
                'SecLists/Discovery/Web-Content/swagger.txt',
                'SecLists/Discovery/Web-Content/graphql.txt'
            ],
            'nginx': [
                'SecLists/Discovery/Web-Content/nginx.txt'
            ],
            'apache': [
                'SecLists/Discovery/Web-Content/apache.txt',
                'SecLists/Discovery/Web-Content/Apache.fuzz.txt',
                'fuzzdb/discovery/predictable-filepaths/webservers-appservers/Apache.txt'
            ],
            'git': [
                'SecLists/Discovery/Web-Content/Common-DB-Backups.txt',
                'SecLists/Discovery/Web-Content/versioning_metafiles.txt'
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
                    elif base_name == 'payloads':
                        wordlist_path = wordlist_path.replace('PayloadsAllTheThings/', '')
                    elif base_name == 'fuzzdb':
                        wordlist_path = wordlist_path.replace('fuzzdb/', '')
                    
                    full_path = os.path.join(base_path, wordlist_path)
                    if os.path.exists(full_path):
                        wordlists.append({
                            'path': full_path,
                            'source': base_name,
                            'technology': technology
                        })
                        break
        
        return wordlists


class SmartCrawler:
    """Advanced web crawler with JS analysis and smart endpoint discovery"""
    
    def __init__(self, target_url, max_depth=3, max_pages=1000):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(target_url)
        self.max_depth = max_depth
        self.max_pages = max_pages
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
            'potential_vulnerabilities': defaultdict(list)
        }
    
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
    
    def extract_forms(self, soup, current_url):
        """Extract and analyze forms from HTML"""
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(current_url, form.get('action', current_url)),
                'method': form.get('method', 'get').upper(),
                'inputs': [],
                'url': current_url
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
                self.analyze_form(form_data)
        
        return forms
    
    def analyze_form(self, form_data):
        """Analyze form for potential vulnerabilities"""
        endpoint = {
            'url': form_data['action'],
            'method': form_data['method'],
            'parameters': [],
            'form': True
        }
        
        for input_field in form_data['inputs']:
            param = {
                'name': input_field['name'],
                'location': 'body',
                'type': input_field['type'],
                'required': input_field['required'],
                'predicted_vulns': []
            }
            
            # Special handling for file upload
            if input_field['type'] == 'file':
                param['predicted_vulns'].append({
                    'vulnerability': 'file_upload',
                    'confidence': 'high',
                    'wordlists': self.wordlist_mapper.get_wordlists_for_vulnerability(
                        'file_upload', self.results['technologies']
                    )
                })
            
            endpoint['parameters'].append(param)
        
        self.endpoints.append(endpoint)
    
    def crawl_page(self, url, depth=0):
        """Crawl a single page and extract information"""
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
            # Allow redirects for the main page
            allow_redirects = (depth == 0)
            response = self.session.get(url, timeout=timeout, verify=False, allow_redirects=allow_redirects)
            response.raise_for_status()
            
            # Detect technologies
            if not self.results['technologies']:
                self.results['technologies'] = self.tech_detector.detect(response, url)
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract forms
            forms = self.extract_forms(soup, url)
            self.results['forms'].extend(forms)
            
            # Extract URLs
            for tag in soup.find_all(['a', 'link']):
                href = tag.get('href')
                if href:
                    absolute_url = urljoin(url, href)
                    if self.is_valid_url(absolute_url):
                        self.url_queue.put((absolute_url, depth + 1))
            
            # Extract JavaScript files
            for script in soup.find_all('script'):
                src = script.get('src')
                if src:
                    js_url = urljoin(url, src)
                    self.results['javascript_files'].append(js_url)
                    
                    # Analyze external JS
                    try:
                        js_response = self.session.get(js_url, timeout=5)
                        js_urls = self.extract_urls_from_js(js_response.text, url)
                        for js_url in js_urls:
                            if self.is_valid_url(js_url):
                                self.url_queue.put((js_url, depth + 1))
                                if '/api/' in js_url or '/v1/' in js_url:
                                    self.results['api_endpoints'].append(js_url)
                    except:
                        pass
                
                # Analyze inline JS
                if script.string:
                    js_urls = self.extract_urls_from_js(script.string, url)
                    for js_url in js_urls:
                        if self.is_valid_url(js_url):
                            self.url_queue.put((js_url, depth + 1))
                            if '/api/' in js_url or '/v1/' in js_url:
                                self.results['api_endpoints'].append(js_url)
            
            # Extract comments
            comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text)
            for comment in comments:
                if any(keyword in comment.lower() for keyword in ['todo', 'fixme', 'hack', 'bug', 'debug']):
                    self.results['comments'].append(comment.strip())
            
            # Extract emails
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response.text)
            self.results['emails'].extend(list(set(emails)))
            
            # Analyze parameters in URL
            parsed = urlparse(url)
            if parsed.query:
                self.analyze_url_parameters(url, response.text)
            
        except requests.RequestException as e:
            logger.error(f"Error crawling {url}: {e}")
            # Se è un errore di timeout o connessione sulla prima pagina, proviamo con un timeout maggiore
            if depth == 0 and 'timeout' in str(e).lower():
                try:
                    logger.info(f"Retrying {url} with longer timeout...")
                    response = self.session.get(url, timeout=30, verify=False)
                    self.crawl_page(url, depth)
                except:
                    pass
    
    def analyze_url_parameters(self, url, response_text):
        """Analyze URL parameters for vulnerabilities"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        endpoint = {
            'url': url.split('?')[0],
            'method': 'GET',
            'parameters': [],
            'form': False
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
            
            # Analyze parameter
            vulns = self.param_analyzer.analyze_parameter(
                param_name, param_value, response_text
            )
            
            for vuln in vulns:
                vuln['wordlists'] = self.wordlist_mapper.get_wordlists_for_vulnerability(
                    vuln['type'], self.results['technologies']
                )
                param_data['predicted_vulns'].append(vuln)
            
            endpoint['parameters'].append(param_data)
        
        if endpoint['parameters']:
            self.endpoints.append(endpoint)
    
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
        
        # Add server-specific wordlists
        if self.results['technologies'].get('server'):
            server = self.results['technologies']['server'].lower()
            server_lists = self.discovery_mapper.get_wordlists(server)
            for wl in server_lists:
                if wl['path'] not in added_sources:
                    wordlists.append(wl)
                    added_sources.add(wl['path'])
        
        # Check for API indicators
        if any(api in str(self.visited_urls) for api in ['/api/', '/v1/', '/v2/', '/graphql']):
            api_lists = self.discovery_mapper.get_wordlists('api')
            for wl in api_lists:
                if wl['path'] not in added_sources:
                    wordlists.append(wl)
                    added_sources.add(wl['path'])
        
        # Add git/version control if no specific tech detected
        if not self.results['technologies'].get('cms'):
            git_lists = self.discovery_mapper.get_wordlists('git')
            for wl in git_lists:
                if wl['path'] not in added_sources:
                    wordlists.append(wl)
                    added_sources.add(wl['path'])
        
        logger.info(f"Selected {len(wordlists)} wordlists for discovery")
        return wordlists
    
    def check_endpoint(self, path):
        """Check if an endpoint exists"""
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
                if vuln['confidence'] == 'high':
                    score += 8
                elif vuln['confidence'] == 'medium':
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
        
        # Disable SSL warnings for testing
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
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
    
    parser = argparse.ArgumentParser(description='Smart Vulnerability Crawler')
    parser.add_argument('target', help='Target URL to crawl')
    parser.add_argument('--depth', type=int, default=3, help='Maximum crawl depth (default: 3)')
    parser.add_argument('--max-pages', type=int, default=1000, help='Maximum pages to crawl (default: 1000)')
    parser.add_argument('--output', default='attack_surface.json', help='Output JSON file (default: attack_surface.json)')
    parser.add_argument('--wordlist-base', help='Base path for wordlists')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--discovery-limit', type=int, default=1000, 
                       help='Max paths to test from wordlists (default: 1000)')
    parser.add_argument('--skip-discovery', action='store_true',
                       help='Skip wordlist-based discovery')
    
    args = parser.parse_args()
    
    # Create crawler instance
    crawler = SmartCrawler(args.target, max_depth=args.depth, max_pages=args.max_pages)
    
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
    
    # Technology summary
    print("\nDETECTED TECHNOLOGIES:")
    for key, value in results['technologies'].items():
        if value and key not in ['headers', 'cookies', 'javascript_libs']:
            print(f"  {key.capitalize()}: {value}")
    if results['technologies'].get('javascript_libs'):
        print(f"  JS Libraries: {', '.join(results['technologies']['javascript_libs'])}")
    
    # Show wordlists used
    if not args.skip_discovery:
        print("\nWORDLISTS USED FOR DISCOVERY:")
        used_wordlists = set()
        for wl in crawler.get_discovery_wordlists():
            tech = wl['technology']
            if tech not in used_wordlists:
                print(f"  - {tech} wordlists")
                used_wordlists.add(tech)
    
    # Top vulnerabilities
    vuln_count = defaultdict(int)
    for endpoint in results['endpoints']:
        for param in endpoint.get('parameters', []):
            for vuln in param.get('predicted_vulns', []):
                vuln_count[vuln['type']] += 1
    
    if vuln_count:
        print("\nPOTENTIAL VULNERABILITIES:")
        for vuln_type, count in sorted(vuln_count.items(), key=lambda x: x[1], reverse=True):
            print(f"  {vuln_type.upper()}: {count} parameters")
    
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