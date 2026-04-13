#!/usr/bin/env python3
"""
Step-by-step traceroute test against OWASP Juice Shop (or any real target).

Each PHASE is independent: set the corresponding RUN_PHASE_* flag to False
to skip it. Intermediate results are stored in plain dicts so you can
inspect them between runs.

Usage:
    cd /path/to/application_traceroute
    python -m tests.test_traceroute_juiceshop

    # or run directly (sets sys.path automatically):
    python tests/test_traceroute_juiceshop.py
"""

import sys
import os
import json
import pprint
import asyncio
import requests

# ---------------------------------------------------------------------------
# PATH SETUP  (makes "from core.xxx import ..." work from any working dir)
# ---------------------------------------------------------------------------
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_SUITE_ROOT = os.path.join(_REPO_ROOT, "security-testing-suite")
if _SUITE_ROOT not in sys.path:
    sys.path.insert(0, _SUITE_ROOT)

# Silence SSL warnings for self-signed / http targets
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# TARGET CONFIG  — edit here
# ---------------------------------------------------------------------------
TARGET_URL        = "https://juice-shop.herokuapp.com"  # OWASP Juice Shop public instance
FORBIDDEN_PATH    = "/api/Users/"                      # 401 JWT-protected, verified manually
DEBUG_MODE        = True                      # Write raw HTTP log to results/
REQUESTS_PER_SEC  = 2.0                       # Rate limiter — lower = safer for target

# ---------------------------------------------------------------------------
# PHASE FLAGS  — set to False to skip a phase
# ---------------------------------------------------------------------------
RUN_PHASE_0_FORBIDDEN  = False   # Skip: forbidden endpoint already known (FORBIDDEN_PATH set above)
RUN_PHASE_1_BASELINE   = True    # Baseline HTTP request
RUN_PHASE_2_STACK      = True    # Header timeline + deep fingerprinting
RUN_PHASE_3_DISCREPANCY = True   # Parser discrepancy tests (needs forbidden endpoint)
RUN_PHASE_4_BYPASS_GEN = True    # Generate bypass payloads
RUN_PHASE_5_BYPASS_VAL = True    # Validate bypasses against live target
RUN_PHASE_6_REPORT     = True    # Generate text + JSON report

# ---------------------------------------------------------------------------
# IMPORTS  (done after sys.path is set)
# ---------------------------------------------------------------------------
print("📦 Importing core modules…")

from core.traceroute.application_traceroute_v4 import (
    RateLimiter,
    ProgressiveStackAnalyzer,
    ForbiddenEndpointFinder,
    DiscrepancyTester,
    BypassGenerator,
    BypassValidator,
    ReportGenerator,
    ADVANCED_MODULES_AVAILABLE,
    LEARNING_DB_AVAILABLE,
)
from core.paths import RESULTS_BASE_STR, ensure_results_base

print(f"  ✅ Core modules loaded")
print(f"  {'✅' if ADVANCED_MODULES_AVAILABLE else '⚠️ '} Advanced engines: {'available' if ADVANCED_MODULES_AVAILABLE else 'NOT available'}")
print(f"  {'✅' if LEARNING_DB_AVAILABLE else '⚠️ '} SQLite learning DB: {'available' if LEARNING_DB_AVAILABLE else 'NOT available'}")


# ---------------------------------------------------------------------------
# SHARED STATE  — populated phase by phase, inspectable at any point
# ---------------------------------------------------------------------------
state = {
    "target_url":          TARGET_URL,
    "session":             None,
    "stack_analyzer":      None,
    "baseline_response":   None,
    "timeline":            None,
    "forbidden_endpoint":  FORBIDDEN_PATH,
    "discrepancy_tester":  None,
    "discrepancies":       [],
    "bypass_generator":    None,
    "bypasses":            [],
    "bypass_validator":    None,
    "validated_bypasses":  [],
    "report_generator":    None,
    "results_dir":         None,
}


def _make_session() -> requests.Session:
    """Create a shared requests.Session (SSL disabled for http targets)."""
    s = requests.Session()
    s.verify = False
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; SecurityTracer/4.1)",
    })
    return s


def _section(title: str):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


# ===========================================================================
# PHASE 0 — Find a forbidden endpoint
# ===========================================================================
if RUN_PHASE_0_FORBIDDEN:
    _section("PHASE 0 — Forbidden Endpoint Discovery")

    session = _make_session()
    state["session"] = session

    finder = ForbiddenEndpointFinder(TARGET_URL, session)
    found = finder.find(user_provided=FORBIDDEN_PATH)
    state["forbidden_endpoint"] = found

    if found:
        print(f"\n  🔒 Forbidden endpoint: {found}")
    else:
        print("\n  ⚠️  No forbidden endpoint found — discrepancy tests will be skipped")
else:
    print("\n⏭  PHASE 0 skipped")
    state["session"] = _make_session()


# ===========================================================================
# PHASE 1 — Baseline request
# ===========================================================================
if RUN_PHASE_1_BASELINE:
    _section("PHASE 1 — Baseline Request")

    stack_analyzer = ProgressiveStackAnalyzer(TARGET_URL)
    stack_analyzer.session = state["session"]
    stack_analyzer.rate_limiter = RateLimiter(requests_per_second=REQUESTS_PER_SEC)
    state["stack_analyzer"] = stack_analyzer

    baseline = stack_analyzer.send_baseline_request()
    state["baseline_response"] = baseline

    print(f"\n  Status : {baseline.status_code}")
    print(f"  Server : {baseline.headers.get('Server', '(none)')}")
    print(f"  Headers: {dict(baseline.headers)}")
else:
    print("\n⏭  PHASE 1 skipped")
    if state["stack_analyzer"] is None:
        state["stack_analyzer"] = ProgressiveStackAnalyzer(TARGET_URL)
        state["stack_analyzer"].session = state["session"]


# ===========================================================================
# PHASE 2 — Stack fingerprinting (header timeline + deep modules)
# ===========================================================================
if RUN_PHASE_2_STACK:
    _section("PHASE 2 — Stack Fingerprinting")

    sa = state["stack_analyzer"]
    baseline = state["baseline_response"]

    if baseline is None:
        print("  ⚠️  No baseline response — run PHASE 1 first")
    else:
        # 2a — Header timeline
        print("\n  [2a] Header timeline analysis…")
        timeline = sa.analyze_header_timeline(baseline)
        state["timeline"] = timeline
        print(f"       {len(timeline)} processing hops detected")
        for hop in timeline:
            print(f"       → {hop}")

        # 2b — Progressive fingerprinting (CDN / WAF / backend / DB…)
        print("\n  [2b] Progressive fingerprinting…")
        sa.progressive_fingerprinting(baseline)

        # 2c — Correlate the full stack
        print("\n  [2c] Stack correlation…")
        sa.correlate_stack()

        print("\n  Detected layers:")
        for layer in sa.stack.get("layers", []):
            print(f"       {layer}")

        print("\n  Confidence scores:")
        pprint.pprint(sa.stack.get("confidence", {}), indent=6)
else:
    print("\n⏭  PHASE 2 skipped")


# ===========================================================================
# PHASE 3 — Parser discrepancy testing
# ===========================================================================
if RUN_PHASE_3_DISCREPANCY:
    _section("PHASE 3 — Discrepancy Testing")

    forbidden = state["forbidden_endpoint"]
    sa        = state["stack_analyzer"]
    session   = state["session"]

    if not forbidden:
        print("  ⚠️  No forbidden endpoint — skipping discrepancy tests")
        state["discrepancies"] = []
    else:
        dt = DiscrepancyTester(TARGET_URL, forbidden, session, sa)
        state["discrepancy_tester"] = dt

        discrepancies = dt.test_all_discrepancies()
        state["discrepancies"] = discrepancies

        print(f"\n  Found {len(discrepancies)} discrepancies:")
        for d in discrepancies:
            print(f"    [{d.get('type','?')}]  {d.get('description','')}")
            if d.get("payload"):
                print(f"       payload: {d['payload']}")
else:
    print("\n⏭  PHASE 3 skipped")


# ===========================================================================
# PHASE 4 — Bypass generation
# ===========================================================================
if RUN_PHASE_4_BYPASS_GEN:
    _section("PHASE 4 — Bypass Generation")

    sa   = state["stack_analyzer"]
    disc = state["discrepancies"]

    if not disc:
        print("  ⚠️  No discrepancies — no bypass payloads to generate")
        state["bypasses"] = []
    else:
        bg = BypassGenerator(disc, sa.stack)
        state["bypass_generator"] = bg

        bypasses = bg.generate_all_bypasses()
        state["bypasses"] = bypasses

        print(f"\n  Generated {len(bypasses)} bypass candidates:")
        for bp in bypasses:
            print(f"    [{bp.get('type','?')}]  {bp.get('url','?')}")
            if bp.get("headers"):
                print(f"       headers: {bp['headers']}")
else:
    print("\n⏭  PHASE 4 skipped")


# ===========================================================================
# PHASE 5 — Bypass validation
# ===========================================================================
if RUN_PHASE_5_BYPASS_VAL:
    _section("PHASE 5 — Bypass Validation")

    bypasses = state["bypasses"]
    session  = state["session"]

    if not bypasses:
        print("  ⚠️  No bypasses to validate")
        state["validated_bypasses"] = []
    else:
        bv = BypassValidator(bypasses, session)
        state["bypass_validator"] = bv

        validated = bv.validate_all()
        state["validated_bypasses"] = validated

        print(f"\n  ✅ Validated: {len(validated)} / {len(bypasses)} bypasses succeeded")
        for bp in validated:
            print(f"    [{bp.get('type','?')}]  {bp.get('url','?')}")
else:
    print("\n⏭  PHASE 5 skipped")


# ===========================================================================
# PHASE 6 — Report
# ===========================================================================
if RUN_PHASE_6_REPORT:
    _section("PHASE 6 — Report Generation")

    sa        = state["stack_analyzer"]
    disc      = state["discrepancies"]
    validated = state["validated_bypasses"]

    ensure_results_base()
    rg = ReportGenerator(TARGET_URL, sa, disc, validated)
    state["report_generator"] = rg

    text_report = rg.generate_text_report()
    json_path   = rg.export_json()

    results_dir = os.path.dirname(json_path)
    state["results_dir"] = results_dir

    txt_path = json_path.replace(".json", ".txt")
    with open(txt_path, "w") as f:
        f.write(text_report)

    print(f"\n  📄 Text report : {txt_path}")
    print(f"  📊 JSON export  : {json_path}")
    print(f"\n{text_report[:2000]}{'…' if len(text_report) > 2000 else ''}")
else:
    print("\n⏭  PHASE 6 skipped")


# ===========================================================================
# FINAL SUMMARY
# ===========================================================================
_section("SUMMARY")
print(f"  Target              : {state['target_url']}")
print(f"  Forbidden endpoint  : {state['forbidden_endpoint']}")
layers = state["stack_analyzer"].stack.get("layers", []) if state["stack_analyzer"] else []
print(f"  Stack layers found  : {len(layers)}")
print(f"  Discrepancies       : {len(state['discrepancies'])}")
print(f"  Bypass candidates   : {len(state['bypasses'])}")
print(f"  Validated bypasses  : {len(state['validated_bypasses'])}")
if state["results_dir"]:
    print(f"  Results dir         : {state['results_dir']}")
print()
