#!/bin/bash

###############################################################################
# migrate_structure.sh
# 
# Script di migrazione automatica per riorganizzare il progetto
# security-testing-suite
#
# Usage: bash migrate_structure.sh
###############################################################################

set -e  # Exit on error

echo "=================================================="
echo "  Security Testing Suite - Structure Migration"
echo "=================================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if we're in the right directory
if [ ! -f "application_traceroute_v3_5.py" ]; then
    echo -e "${RED}ERROR: application_traceroute_v3_5.py not found!${NC}"
    echo "Please run this script from the directory containing your Python files."
    exit 1
fi

echo -e "${YELLOW}[1/6] Creating new directory structure...${NC}"

# Create main directories
mkdir -p security-testing-suite/core/{traceroute,crawler,engines,exporters}
mkdir -p security-testing-suite/extensions/{response,vulnerability,taxonomy}
mkdir -p security-testing-suite/cli
mkdir -p security-testing-suite/tests
mkdir -p security-testing-suite/results
mkdir -p security-testing-suite/wordlists

echo -e "${GREEN}✓ Directory structure created${NC}"

echo ""
echo -e "${YELLOW}[2/6] Moving existing files...${NC}"

# Move traceroute
if [ -f "application_traceroute_v3_5.py" ]; then
    mv application_traceroute_v3_5.py security-testing-suite/core/traceroute/
    echo -e "${GREEN}✓ Moved application_traceroute_v3_5.py${NC}"
fi

# Move crawler
if [ -f "smart_vuln_crawler2.py" ]; then
    mv smart_vuln_crawler2.py security-testing-suite/core/crawler/
    echo -e "${GREEN}✓ Moved smart_vuln_crawler2.py${NC}"
fi

# Move engines
for file in advanced_bypass_engine.py semantic_bypass_engine.py graph_attack_planner.py intelligent_bypass_validator.py smart_crawler_advanced_engine.py; do
    if [ -f "$file" ]; then
        mv "$file" security-testing-suite/core/engines/
        echo -e "${GREEN}✓ Moved $file${NC}"
    fi
done

# Move exporter
if [ -f "enhanced_json_exporter.py" ]; then
    mv enhanced_json_exporter.py security-testing-suite/core/exporters/
    echo -e "${GREEN}✓ Moved enhanced_json_exporter.py${NC}"
fi

# Move wordlists if they exist
if [ -d "wordlists" ]; then
    cp -r wordlists/* security-testing-suite/wordlists/ 2>/dev/null || true
    echo -e "${GREEN}✓ Copied wordlists${NC}"
fi

echo ""
echo -e "${YELLOW}[3/6] Creating __init__.py files...${NC}"

# Core __init__.py
cat > security-testing-suite/core/__init__.py << 'EOF'
"""
Core security testing modules
"""

__version__ = "4.0.0"
EOF

# Traceroute __init__.py
cat > security-testing-suite/core/traceroute/__init__.py << 'EOF'
"""
Application Stack Traceroute module
"""
from .application_traceroute_v3_5 import ProgressiveStackAnalyzer

__all__ = ['ProgressiveStackAnalyzer']
EOF

# Crawler __init__.py
cat > security-testing-suite/core/crawler/__init__.py << 'EOF'
"""
Smart Vulnerability Crawler module
"""
from .smart_vuln_crawler2 import SmartVulnerabilityCrawler

__all__ = ['SmartVulnerabilityCrawler']
EOF

# Engines __init__.py
cat > security-testing-suite/core/engines/__init__.py << 'EOF'
"""
Advanced engines module
"""
from .advanced_bypass_engine import (
    ResponseDifferentialAnalyzer,
    BayesianBypassInference
)
from .semantic_bypass_engine import (
    SemanticBypassEngine,
    EvolutionaryMutationEngine
)
from .graph_attack_planner import GraphAttackPlanner
from .intelligent_bypass_validator import IntelligentBypassValidator
from .smart_crawler_advanced_engine import (
    BayesianVulnerabilityScorer,
    AttackGraphEngine
)

__all__ = [
    'ResponseDifferentialAnalyzer',
    'BayesianBypassInference',
    'SemanticBypassEngine',
    'EvolutionaryMutationEngine',
    'GraphAttackPlanner',
    'IntelligentBypassValidator',
    'BayesianVulnerabilityScorer',
    'AttackGraphEngine'
]
EOF

# Exporters __init__.py
cat > security-testing-suite/core/exporters/__init__.py << 'EOF'
"""
JSON exporters module
"""
from .enhanced_json_exporter import EnhancedJSONExporter

__all__ = ['EnhancedJSONExporter']
EOF

# Extensions __init__.py files
cat > security-testing-suite/extensions/__init__.py << 'EOF'
"""
Extensions module - Enhanced analysis capabilities
"""
EOF

cat > security-testing-suite/extensions/response/__init__.py << 'EOF'
"""
Response analysis extensions
"""
from .causal_response_analyzer import CausalResponseAnalyzer

__all__ = ['CausalResponseAnalyzer']
EOF

cat > security-testing-suite/extensions/vulnerability/__init__.py << 'EOF'
"""
Vulnerability analysis extensions
"""
from .causal_vulnerability_analyzer import CausalVulnerabilityAnalyzer

__all__ = ['CausalVulnerabilityAnalyzer']
EOF

cat > security-testing-suite/extensions/taxonomy/__init__.py << 'EOF'
"""
Self-learning taxonomy extensions
"""
from .adaptive_taxonomy import SelfLearningTaxonomy

__all__ = ['SelfLearningTaxonomy']
EOF

# CLI __init__.py
cat > security-testing-suite/cli/__init__.py << 'EOF'
"""
Command-line interface
"""
EOF

# Tests __init__.py
cat > security-testing-suite/tests/__init__.py << 'EOF'
"""
Test suite
"""
EOF

echo -e "${GREEN}✓ Created all __init__.py files${NC}"

echo ""
echo -e "${YELLOW}[4/6] Creating setup.py...${NC}"

cat > security-testing-suite/setup.py << 'EOF'
"""
setup.py

Installation script for security-testing-suite
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="security-testing-suite",
    version="4.0.0",
    description="Advanced Security Testing Suite with Causal Inference",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Simone",
    packages=find_packages(),
    install_requires=[
        'requests>=2.31.0',
        'beautifulsoup4>=4.12.0',
        'numpy>=1.24.0',
        'scipy>=1.10.0',
        'scikit-learn>=1.3.0',
        'hdbscan>=0.8.33',
        'lxml>=4.9.0',
        'urllib3>=2.0.0',
    ],
    python_requires='>=3.10',
    entry_points={
        'console_scripts': [
            'security-traceroute=core.traceroute.application_traceroute_v3_5:main',
            'security-crawler=core.crawler.smart_vuln_crawler2:main',
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
EOF

echo -e "${GREEN}✓ Created setup.py${NC}"

echo ""
echo -e "${YELLOW}[5/6] Creating requirements.txt...${NC}"

cat > security-testing-suite/requirements.txt << 'EOF'
# Core dependencies
requests>=2.31.0
beautifulsoup4>=4.12.0
lxml>=4.9.0
urllib3>=2.0.0

# Scientific computing
numpy>=1.24.0
scipy>=1.10.0

# Machine learning
scikit-learn>=1.3.0
hdbscan>=0.8.33

# Optional (for advanced features)
matplotlib>=3.7.0
networkx>=3.1
EOF

echo -e "${GREEN}✓ Created requirements.txt${NC}"

echo ""
echo -e "${YELLOW}[6/6] Creating .gitignore...${NC}"

cat > security-testing-suite/.gitignore << 'EOF'
# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# C extensions
*.so

# Distribution / packaging
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# PyInstaller
*.manifest
*.spec

# Installer logs
pip-log.txt
pip-delete-this-directory.txt

# Unit test / coverage reports
htmlcov/
.tox/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
.hypothesis/
.pytest_cache/

# Environments
.env
.venv
env/
venv/
ENV/
env.bak/
venv.bak/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# Project specific
results/
*.log
*.json.bak

# OS
.DS_Store
Thumbs.db
EOF

echo -e "${GREEN}✓ Created .gitignore${NC}"

echo ""
echo "=================================================="
echo -e "${GREEN}✓ Migration completed successfully!${NC}"
echo "=================================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Review the new structure:"
echo "   cd security-testing-suite"
echo "   tree -L 3"
echo ""
echo "2. Install the package:"
echo "   pip install -e ."
echo ""
echo "3. The new modules will be created in extensions/ directory"
echo ""
echo "4. Fix imports in existing files (see IMPORT_FIXES.md)"
echo ""

# Create IMPORT_FIXES.md guide
cat > security-testing-suite/IMPORT_FIXES.md << 'EOF'
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
EOF

echo -e "${GREEN}✓ Created IMPORT_FIXES.md guide${NC}"

echo ""
echo "Migration complete! Check IMPORT_FIXES.md for next steps."
