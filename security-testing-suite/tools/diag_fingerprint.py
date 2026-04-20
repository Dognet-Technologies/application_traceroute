#!/usr/bin/env python3
"""
Diagnostic script: traces the fingerprinting pipeline step by step.

Usage:
    python tools/diag_fingerprint.py https://dashboard.visme.co/v2/login
"""

import sys
import os
import json
import warnings
warnings.filterwarnings('ignore')

# Make the package importable from the security-testing-suite directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
requests.packages.urllib3.disable_warnings()

from core.traceroute.application_traceroute_v4 import ProgressiveStackAnalyzer


def _hr(title: str = '', width: int = 70):
    if title:
        print(f"\n{'─' * 3} {title} {'─' * (width - len(title) - 5)}")
    else:
        print('─' * width)


def diag(target_url: str):
    print(f"\n🔬 FINGERPRINTING DIAGNOSTIC — {target_url}\n")

    analyzer = ProgressiveStackAnalyzer(target_url)

    # ── Step 1: Baseline request ──────────────────────────────────────────
    _hr("Step 1: Baseline request")
    try:
        resp = analyzer.session.get(target_url, timeout=10)
        print(f"  Status : {resp.status_code}")
        print(f"  Headers ({len(resp.headers)}):")
        for k, v in sorted(resp.headers.items()):
            print(f"    {k}: {v}")
    except Exception as e:
        print(f"  ❌ Request failed: {e}")
        return

    # ── Step 2: analyze_header_timeline ──────────────────────────────────
    _hr("Step 2: analyze_header_timeline")
    analyzer.analyze_header_timeline(resp)
    timeline = analyzer.stack['timeline']
    print(f"  Timeline hops: {len(timeline)}")
    for hop in timeline:
        print(f"    type={hop.get('type')} component={hop.get('component')} "
              f"evidence={hop.get('raw') or hop.get('evidence')}")

    # ── Step 3: Build methods_to_call (replica of progressive_fingerprinting logic) ──
    _hr("Step 3: methods_to_call from timeline")
    _type_to_method = {
        'cdn': 'cdn', 'waf': 'waf', 'proxy': 'proxy', 'backend': 'backend',
        'load_balancer': 'load_balancer', 'api_gateway': 'api_gateway',
        'service_mesh': 'service_mesh', 'cache': 'cache',
        'microservice': 'framework', 'container_orchestration': 'load_balancer',
        'serverless': 'backend', 'cms': 'cms',
        'cdn/lb': 'load_balancer', 'cdn/waf': 'waf', 'proxy/lb': 'load_balancer',
        'forwarding': 'load_balancer', 'infrastructure': 'load_balancer',
        'framework': 'framework',
    }
    methods_to_call = {_type_to_method[h['type']] for h in timeline
                       if h.get('type') in _type_to_method}
    print(f"  Methods triggered: {sorted(methods_to_call)}")
    print(f"  API_GW in methods_to_call: {'api_gateway' in methods_to_call}")

    # ── Step 4: Run each deep fingerprinting method ───────────────────────
    _hr("Step 4: Deep fingerprinting methods")

    method_dispatch = {
        'cdn':          analyzer.deep_cdn_fingerprinting,
        'waf':          analyzer.deep_waf_fingerprinting,
        'proxy':        analyzer.deep_proxy_fingerprinting,
        'backend':      analyzer.deep_backend_fingerprinting,
        'load_balancer': analyzer.deep_load_balancer_fingerprinting,
        'cache':        analyzer.deep_cache_fingerprinting,
        'framework':    analyzer.deep_framework_fingerprinting,
        'cms':          analyzer.deep_cms_fingerprinting,
        'api_gateway':  analyzer.deep_api_gateway_fingerprinting,
        'service_mesh': analyzer.deep_service_mesh_fingerprinting,
    }

    layers_before = len(analyzer.stack['layers'])
    for key in sorted(methods_to_call):
        n_before = len(analyzer.stack['layers'])
        method_dispatch[key](resp)
        n_after = len(analyzer.stack['layers'])
        added = analyzer.stack['layers'][n_before:]
        if added:
            for lyr in added:
                print(f"  ✅ [{key}] added: {lyr['component']} "
                      f"(type={lyr['type']}, conf={lyr.get('confidence')})")
        else:
            print(f"  ─  [{key}] nothing added (below threshold)")

    # CMS always runs
    if 'cms' not in methods_to_call:
        n_before = len(analyzer.stack['layers'])
        analyzer.deep_cms_fingerprinting(resp)
        added = analyzer.stack['layers'][n_before:]
        if added:
            for lyr in added:
                print(f"  ✅ [cms] added: {lyr['component']}")

    # ── Step 5: _promote_timeline_hops_to_layers ─────────────────────────
    _hr("Step 5: _promote_timeline_hops_to_layers")
    n_before = len(analyzer.stack['layers'])
    analyzer._promote_timeline_hops_to_layers(timeline)
    promoted = analyzer.stack['layers'][n_before:]
    deep_covered = {lyr['type'] for lyr in analyzer.stack['layers'][:n_before]
                    if lyr.get('source') != 'timeline'}
    print(f"  Types already covered by deep: {sorted(deep_covered)}")
    if promoted:
        for lyr in promoted:
            print(f"  ✅ Promoted: {lyr['component']} (type={lyr['type']}, conf={lyr.get('confidence')})")
    else:
        print("  ─  Nothing promoted (all types covered or no new families)")

    # ── Step 6: detect_hidden_layers ─────────────────────────────────────
    _hr("Step 6: detect_hidden_layers (API_GW + Service Mesh)")
    existing_types_before = {lyr['type'] for lyr in analyzer.stack['layers']}
    print(f"  Existing types before hidden detection: {sorted(existing_types_before)}")
    print(f"  API_GATEWAY present: {'API_GATEWAY' in existing_types_before}")
    n_before = len(analyzer.stack['layers'])
    analyzer.detect_hidden_layers()
    added = analyzer.stack['layers'][n_before:]
    if added:
        for lyr in added:
            print(f"  ✅ Hidden: {lyr['component']} (type={lyr['type']}, conf={lyr.get('confidence')})")
    else:
        print("  ─  No hidden layers added")

    # ── Step 7: _deduplicate_layers ───────────────────────────────────────
    _hr("Step 7: _deduplicate_layers")
    layers_before_dedup = list(analyzer.stack['layers'])
    analyzer._deduplicate_layers()
    kept = {lyr['component'] for lyr in analyzer.stack['layers']}
    removed = [lyr for lyr in layers_before_dedup if lyr['component'] not in kept]
    if removed:
        for lyr in removed:
            family = analyzer._TECH_FAMILY.get(lyr['component'], lyr['component'])
            print(f"  🗑️  Removed: {lyr['component']} "
                  f"(family={family}, conf={lyr.get('confidence')}) — "
                  f"superseded by higher-conf entry in same family")
    else:
        print("  ─  No duplicates removed")

    # ── Final stack ───────────────────────────────────────────────────────
    _hr("Final Stack")
    layers = analyzer.stack['layers']
    print(f"  Total layers: {len(layers)}")
    for i, lyr in enumerate(layers, 1):
        print(f"  {i:2d}. {lyr['type']:20s} {lyr['component']:30s} "
              f"conf={lyr.get('confidence', '?'):3} "
              f"level={lyr.get('level', '?'):8} "
              f"source={lyr.get('source', 'deep')}")

    # ── Kong-specific debug ───────────────────────────────────────────────
    _hr("Kong confidence breakdown (re-computed manually)")
    fp = analyzer.fingerprints.get('api_gateway_detection', {}).get('kong', {})
    conf = 0
    print(f"  Kong headers to match: {fp.get('headers')}")
    print(f"  Kong via_patterns: {fp.get('via_patterns', [])}")
    print(f"  Kong body_patterns: {fp.get('body_patterns')}")
    print(f"  Kong behavioral_paths: {fp.get('behavioral_paths')}")
    print()
    # Header check
    for h_pattern in fp.get('headers', []):
        for h_name, h_val in resp.headers.items():
            import re
            if re.search(h_pattern, f"{h_name}: {h_val}", re.IGNORECASE):
                conf += 40
                print(f"  ✅ Header match: {h_name} (+40 pts)")
                break
    # Via patterns
    via_val = resp.headers.get('via', '') or resp.headers.get('Via', '')
    print(f"  Via header value: {via_val!r}")
    for pat in fp.get('via_patterns', []):
        if pat.lower() in via_val.lower():
            conf += 20
            print(f"  ✅ Via match: {pat!r} (+20 pts)")
    # Body patterns
    body = resp.text.lower()
    for pat in fp.get('body_patterns', []):
        if pat.lower() in body:
            conf += 20
            print(f"  ✅ Body match: {pat!r} (+20 pts)")
            break
    # Behavioral (quick, just /)
    try:
        r = requests.get(target_url.split('/v2')[0] + '/', timeout=5, verify=False)
        if r.status_code in [200, 401, 403, 404]:
            conf += 30
            print(f"  ✅ Behavioral / ({r.status_code}) (+30 pts)")
    except Exception:
        pass
    print(f"\n  Kong total confidence: {conf}/100  (threshold: 40)")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python tools/diag_fingerprint.py <target_url>")
        sys.exit(1)
    diag(sys.argv[1])
