# Installation Guide - Security Testing Suite

## Prerequisites

- Python 3.10 or higher
- pip (Python package manager)
- Virtual environment (recommended)

## Installation Steps

### 1. Extract Archive

```bash
unzip security-suite-complete.zip
cd security-suite-complete
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows
```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Install Package

```bash
# Development mode (recommended for testing)
pip install -e .

# Or production install
pip install .
```

### 5. Verify Installation

```bash
security-suite --help
```

You should see the help message.

## File Structure

```
security-suite-complete/
├── cli/                    # Command-line interface
├── core/                   # Core algorithms
│   ├── graph/             # Causal graph
│   ├── behavioral/        # Differential analysis
│   ├── correlation/       # Hybrid correlator
│   └── validation/        # Bayesian validator
├── modules/               # High-level modules
│   └── taxonomy/          # Self-learning taxonomy
├── utils/                 # Utilities
├── tests/                 # Unit tests
├── data/                  # Data storage
├── results/               # Analysis results
├── setup.py               # Installation script
├── requirements.txt       # Dependencies
└── README.md             # Documentation
```

## Configuration

1. Copy example config:
```bash
cp config.example.json config.json
```

2. Edit config.json with your preferences

## Usage

### Basic Analysis

```bash
security-suite analyze https://example.com
```

### With Options

```bash
# Non-interactive mode
security-suite analyze https://example.com --no-interactive

# Skip crawler
security-suite analyze https://example.com --no-crawler

# Custom output
security-suite analyze https://example.com --output ./my-results
```

## Troubleshooting

### Import Errors

If you get import errors:
```bash
# Reinstall in development mode
pip install -e .
```

### Missing Dependencies

```bash
# Install all dependencies including optional ones
pip install -r requirements.txt
```

### hdbscan Installation Issues

On some systems, hdbscan requires compilation:
```bash
# Install build tools first
# Ubuntu/Debian:
sudo apt-get install python3-dev build-essential

# Then install hdbscan
pip install hdbscan
```

## Next Steps

1. Read README.md for architecture overview
2. Check examples in `/examples` directory
3. Run tests: `pytest tests/`
4. Start analyzing: `security-suite analyze <target>`

## Support

For issues and questions:
- GitHub Issues: [project-url]/issues
- Documentation: See /docs directory
- Email: security@example.com
