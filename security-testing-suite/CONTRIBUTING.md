# Contributing to Application Stack Traceroute

First off, thank you for considering contributing! 🎉

This project is made better by the security community, and we welcome contributions of all kinds.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)

---

## 🤝 Code of Conduct

### Our Pledge

We are committed to making participation in this project a harassment-free experience for everyone.

### Our Standards

**Positive behavior includes:**
- Being respectful and inclusive
- Providing constructive feedback
- Focusing on what's best for the community
- Showing empathy towards others

**Unacceptable behavior includes:**
- Harassment, trolling, or derogatory comments
- Publishing others' private information
- Other conduct which could reasonably be considered inappropriate

---

## 💡 How Can I Contribute?

### Reporting Bugs

**Before submitting a bug report:**
- Check existing issues to avoid duplicates
- Verify the bug on the latest version
- Collect relevant information (logs, steps to reproduce)

**When submitting a bug report, include:**
1. **Title**: Clear, specific description
2. **Environment**: Python version, OS, dependencies
3. **Steps to reproduce**: Detailed, numbered steps
4. **Expected behavior**: What should happen
5. **Actual behavior**: What actually happens
6. **Logs**: Relevant error messages or debug output
7. **Screenshots**: If applicable

**Template:**
```markdown
### Bug Description
[Clear description of the bug]

### Environment
- Python version: 3.10.5
- OS: Ubuntu 22.04
- Tool version: 4.0.0

### Steps to Reproduce
1. Run command: `python3 smart_vuln_crawler2.py ...`
2. [Next step]
3. [Next step]

### Expected Behavior
[What should happen]

### Actual Behavior
[What actually happens]

### Logs
```
[Paste relevant logs here]
```

### Screenshots
[If applicable]
```

### Suggesting Enhancements

**Before suggesting an enhancement:**
- Check if it already exists
- Search closed issues for previous discussions
- Consider if it fits the project's scope

**Enhancement proposals should include:**
1. **Problem**: What problem does this solve?
2. **Solution**: How would you solve it?
3. **Alternatives**: What alternatives did you consider?
4. **Examples**: Real-world use cases
5. **Implementation**: High-level implementation ideas

### Adding New Vulnerability Checks

We're always interested in new vulnerability detection techniques!

**To add a new check:**

1. **Create an issue first** describing:
   - Vulnerability type
   - Detection method
   - Example vulnerable code
   - PoC payloads

2. **Implement following the pattern**:
   ```python
   # In ParameterAnalyzer
   def _analyze_new_vuln(self, param_name, context):
       """Detect new vulnerability type"""
       # Pattern matching
       # Behavioral analysis
       # Return vulnerability dict
   ```

3. **Add payloads**:
   ```python
   # In native_detector.py
   NEW_VULN_PAYLOADS = [
       'payload1',
       'payload2',
       # ... with comments explaining each
   ]
   ```

4. **Add detection logic**:
   ```python
   # In analyze_response_for_vulnerability
   elif vuln_type == 'new_vuln':
       # Detection logic
       # Evidence collection
       # Return True/False
   ```

5. **Add tests** (see Testing Guidelines)

### Improving Documentation

Documentation improvements are always welcome!

**Areas needing help:**
- Clarifying complex sections
- Adding examples
- Fixing typos/grammar
- Translating to other languages
- Creating tutorials/guides

---

## 🛠️ Development Setup

### Prerequisites

- Python 3.8+
- Git
- Virtual environment tool (venv, virtualenv, conda)

### Setup Steps

```bash
# 1. Fork and clone
git clone https://github.com/yourusername/application_traceroute.git
cd application_traceroute

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies

# 4. Install pre-commit hooks (optional but recommended)
pre-commit install

# 5. Verify installation
python3 smart_vuln_crawler2.py --version
python3 -m pytest tests/  # Run tests
```

### Development Dependencies

```bash
# requirements-dev.txt
pytest>=7.4.0
pytest-cov>=4.1.0
black>=23.0.0
flake8>=6.0.0
mypy>=1.5.0
isort>=5.12.0
```

---

## 🔀 Pull Request Process

### Before Submitting

1. **Create an issue first** (for significant changes)
2. **Fork the repository**
3. **Create a feature branch**: `git checkout -b feature/amazing-feature`
4. **Make your changes**
5. **Test thoroughly** (see Testing Guidelines)
6. **Update documentation** if needed
7. **Commit with clear messages** (see Commit Messages)

### PR Guidelines

**Title Format:**
```
[Type] Brief description

Examples:
[Feature] Add XPath injection detection
[Fix] Resolve authentication timeout bug
[Docs] Update installation guide
[Refactor] Improve pattern matching performance
```

**Description Template:**
```markdown
## Description
[Clear description of changes]

## Motivation
[Why is this change needed?]

## Changes Made
- [ ] Added new feature X
- [ ] Fixed bug Y
- [ ] Updated documentation

## Testing
- [ ] Tested on DVWA
- [ ] Tested on testphp.vulnweb.com
- [ ] Unit tests pass
- [ ] Manual testing completed

## Screenshots
[If applicable]

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-reviewed code
- [ ] Commented complex logic
- [ ] Updated documentation
- [ ] No breaking changes (or documented)
- [ ] Tests added/updated
```

### Review Process

1. **Automated checks**: Must pass (linting, tests)
2. **Code review**: At least one maintainer approval
3. **Testing**: Verified on real targets
4. **Documentation**: Updated if needed

### After Approval

- Maintainers will merge your PR
- Your contribution will be credited in CHANGELOG
- Thank you! 🎉

---

## 📝 Coding Standards

### Python Style

**Follow PEP 8** with these specifics:

```python
# Line length: 100 characters (not 79)
# Indentation: 4 spaces (no tabs)
# Quotes: Single quotes for strings, double for docstrings

# Good:
def analyze_parameter(self, param_name: str, context: dict) -> list:
    """
    Analyze parameter for vulnerability indicators.
    
    Args:
        param_name: Name of the parameter
        context: Context dictionary with metadata
        
    Returns:
        List of detected vulnerabilities
    """
    if not param_name:
        return []
    
    vulnerabilities = []
    # ... implementation
    return vulnerabilities

# Bad:
def analyze(p,c):
    if not p: return []
    v=[]
    # ... implementation
    return v
```

### Naming Conventions

```python
# Classes: PascalCase
class ParameterAnalyzer:
    pass

# Functions/Methods: snake_case
def analyze_parameter():
    pass

# Constants: UPPER_SNAKE_CASE
MAX_PAYLOADS = 150

# Private methods: _leading_underscore
def _internal_helper():
    pass

# Variables: snake_case
param_name = 'user_id'
```

### Type Hints

**Always use type hints** for public APIs:

```python
def test_payload(
    self,
    endpoint: dict,
    param: dict,
    payload: str,
    vuln_type: str
) -> bool:
    """Type hints make code self-documenting"""
    pass
```

### Documentation

**Docstrings for all public functions**:

```python
def analyze_parameter(self, param_name: str) -> list:
    """
    Analyze parameter for vulnerability indicators.
    
    Uses pattern matching, behavioral analysis, and contextual
    information to predict vulnerabilities.
    
    Args:
        param_name: Name of the parameter to analyze
        
    Returns:
        List of vulnerability dictionaries with:
        - type: Vulnerability type (sqli, xss, etc.)
        - confidence: Confidence score (0-100)
        - context: Detection context
        - evidence: Evidence for detection
        
    Example:
        >>> analyzer.analyze_parameter('user_id')
        [{'type': 'sqli', 'confidence': 70, ...}]
    """
    pass
```

### Error Handling

```python
# Good: Specific exceptions with context
try:
    result = self._test_payload(payload)
except ConnectionError as e:
    logger.error(f"Connection failed for {endpoint}: {e}")
    return False
except ValueError as e:
    logger.warning(f"Invalid payload format: {e}")
    return False

# Bad: Bare except
try:
    result = self._test_payload(payload)
except:
    return False
```

### Logging

```python
# Use appropriate levels
logger.debug("Detailed diagnostic info")
logger.info("Important milestones")
logger.warning("Recoverable issues")
logger.error("Serious problems")

# Include context
logger.error(f"Failed to test {vuln_type} on {endpoint}: {error}")
```

---

## 🧪 Testing Guidelines

### Test Structure

```
tests/
├── unit/
│   ├── test_parameter_analyzer.py
│   ├── test_vulnerability_verifier.py
│   └── test_mutation_engine.py
├── integration/
│   ├── test_full_scan.py
│   └── test_authentication.py
└── fixtures/
    ├── sample_responses.py
    └── mock_targets.py
```

### Writing Tests

```python
import pytest
from smart_vuln_crawler2 import ParameterAnalyzer

class TestParameterAnalyzer:
    """Test parameter analysis functionality"""
    
    def setup_method(self):
        """Run before each test"""
        self.analyzer = ParameterAnalyzer()
    
    def test_sql_injection_detection(self):
        """Should detect SQLi in parameter names"""
        # Arrange
        param_name = 'user_id'
        
        # Act
        vulns = self.analyzer.analyze_parameter(param_name, '', '')
        
        # Assert
        assert any(v['type'] == 'sqli' for v in vulns)
        assert vulns[0]['confidence'] >= 70
    
    def test_empty_parameter(self):
        """Should handle empty parameter gracefully"""
        vulns = self.analyzer.analyze_parameter('', '', '')
        assert vulns == []
    
    @pytest.mark.parametrize("param_name,expected_type", [
        ('user_id', 'sqli'),
        ('file_path', 'lfi'),
        ('search', 'xss'),
    ])
    def test_pattern_matching(self, param_name, expected_type):
        """Should match various parameter patterns"""
        vulns = self.analyzer.analyze_parameter(param_name, '', '')
        types = [v['type'] for v in vulns]
        assert expected_type in types
```

### Running Tests

```bash
# All tests
pytest

# Specific test file
pytest tests/unit/test_parameter_analyzer.py

# Specific test
pytest tests/unit/test_parameter_analyzer.py::TestParameterAnalyzer::test_sql_injection_detection

# With coverage
pytest --cov=smart_vuln_crawler2 --cov-report=html

# Verbose
pytest -v

# Stop on first failure
pytest -x
```

### Test Coverage Goals

- **Unit tests**: > 80% coverage
- **Integration tests**: Critical workflows
- **Edge cases**: Documented in tests

---

## 🎯 Commit Messages

### Format

```
[Type] Brief description (50 chars or less)

More detailed explanation if needed (wrap at 72 chars).
Include motivation for change and contrast with previous behavior.

- Bullet points for multiple changes
- Reference issues: Fixes #123, Closes #456
```

### Types

- `[Feature]`: New functionality
- `[Fix]`: Bug fixes
- `[Docs]`: Documentation changes
- `[Refactor]`: Code restructuring (no behavior change)
- `[Test]`: Test additions/changes
- `[Perf]`: Performance improvements
- `[Style]`: Code style changes (formatting, etc.)
- `[Chore]`: Build/tooling changes

### Examples

```
[Feature] Add SSTI detection with Jinja2 payloads

Implements server-side template injection detection for
Jinja2, Twig, and Velocity engines.

- Added 40+ SSTI payloads
- Detection based on mathematical evaluation (7*7=49)
- Template error pattern matching

Closes #234
```

```
[Fix] Resolve authentication timeout on slow connections

Increased timeout from 5s to 15s for initial auth request.
Added retry logic with exponential backoff.

Fixes #567
```

---

## 📞 Getting Help

- **Questions**: [GitHub Discussions](https://github.com/yourusername/application_traceroute/discussions)
- **Bugs**: [GitHub Issues](https://github.com/yourusername/application_traceroute/issues)
- **Security**: Email security@yourdomain.com (not public issues!)

---

## 🏆 Recognition

Contributors will be:
- Listed in CHANGELOG
- Mentioned in release notes
- Credited in README (for significant contributions)

---

**Thank you for contributing to the security community!** 🙏
