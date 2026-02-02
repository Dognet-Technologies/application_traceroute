# Import Fixes Guide

After migration, you need to update imports in existing files.

## In application_traceroute_v3_5.py

### BEFORE (old imports):
```python
from advanced_bypass_engine import (
    ResponseDifferentialAnalyzer,
    BayesianBypassInference
)
from semantic_bypass_engine import (
    SemanticBypassEngine,
    EvolutionaryMutationEngine
)
from graph_attack_planner import GraphAttackPlanner
```

### AFTER (new imports):
```python
from core.engines.advanced_bypass_engine import (
    ResponseDifferentialAnalyzer,
    BayesianBypassInference
)
from core.engines.semantic_bypass_engine import (
    SemanticBypassEngine,
    EvolutionaryMutationEngine
)
from core.engines.graph_attack_planner import GraphAttackPlanner
```

## In smart_vuln_crawler2.py

### BEFORE:
```python
from smart_crawler_advanced_engine import (
    BayesianVulnerabilityScorer,
    AttackGraphEngine
)
```

### AFTER:
```python
from core.engines.smart_crawler_advanced_engine import (
    BayesianVulnerabilityScorer,
    AttackGraphEngine
)
```

## Running the automated fix:

```bash
cd security-testing-suite

# Fix traceroute imports
python fix_imports.py core/traceroute/application_traceroute_v3_5.py

# Fix crawler imports
python fix_imports.py core/crawler/smart_vuln_crawler2.py
```

## Manual verification:

After running the fix script, test that imports work:

```bash
python -c "from core.traceroute import ProgressiveStackAnalyzer; print('✓ Traceroute OK')"
python -c "from core.crawler import SmartVulnerabilityCrawler; print('✓ Crawler OK')"
```
