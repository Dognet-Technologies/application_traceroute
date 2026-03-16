"""
Project-wide path constants.

Single source of truth for all filesystem paths used by the suite.
Import from here instead of hardcoding relative paths in individual modules.

Layout (anchored to project root, not to CWD):

    application_traceroute/          ← PROJECT_ROOT
    ├── security-testing-suite/      ← SUITE_ROOT
    │   ├── cli/
    │   ├── core/
    │   └── extensions/
    ├── results/                     ← RESULTS_BASE  (all tool output goes here)
    └── tests/
"""

from pathlib import Path

# Absolute path to the project root (two levels up from this file:
#   this file   → core/paths.py
#   core/       → security-testing-suite/core
#   suite root  → security-testing-suite/
#   project root→ application_traceroute/
SUITE_ROOT: Path = Path(__file__).resolve().parent.parent   # .../security-testing-suite
PROJECT_ROOT: Path = SUITE_ROOT.parent                      # .../application_traceroute

# Single canonical output directory for all tools.
# Created on first use; never relative to CWD.
RESULTS_BASE: Path = PROJECT_ROOT / "results"

# Convenience string for code that still uses os.path / str concatenation
RESULTS_BASE_STR: str = str(RESULTS_BASE)


def ensure_results_base() -> Path:
    """Create RESULTS_BASE if it does not exist and return it."""
    RESULTS_BASE.mkdir(parents=True, exist_ok=True)
    return RESULTS_BASE
