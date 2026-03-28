# Application Stack Traceroute & Smart Vulnerability Scanner

<div align="center">

![Version](https://img.shields.io/badge/version-4.0.1-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![Status](https://img.shields.io/badge/status-stable-success.svg)

**Advanced Web Application Security Testing Suite for Bug Bounty Hunters**

[Features](#features) • [Installation](#installation) • [Quick Start](#quick-start) • [License Management](#license-management) • [Documentation](#documentation) • [Examples](#examples)

</div>

---

## 🎯 Overview

**Application Stack Traceroute** is a comprehensive security testing suite designed for professional bug bounty hunters and security researchers. It combines infrastructure fingerprinting, intelligent vulnerability scanning, and automated bypass generation into a unified workflow.

### What Makes It Unique?

- **🔍 Infrastructure Mapping**: Traces the complete application stack (CDN → WAF → Proxy → Backend)
- **🧠 Intelligent Scanning**: Behavioral analysis + pattern matching for accurate vulnerability prediction
- **🛡️ Bypass Generation**: Automatically discovers and validates WAF/CDN bypass techniques
- **📊 High Coverage**: Tests 10+ vulnerability categories with 150+ payloads per type
- **⚡ Production Ready**: Stable, fast, and battle-tested on real bug bounty targets

---

## 🚀 Features

### Application Stack Traceroute (`security-traceroute`)
- **Infrastructure Fingerprinting**: Identifies CDN, WAF, Load Balancers, Proxies, Backend servers
- **Parser Discrepancy Detection**: Finds inconsistencies between layers (22+ advanced techniques)
- **Automated Bypass Generation**: Creates and validates custom bypasses for discovered infrastructure
- **Semantic Bypass Engine**: NLP-inspired classification + evolutionary mutation of bypass candidates
- **Graph-Optimized Attack Chains**: A* search + Game Theory to find optimal technique sequences
- **JSON Export**: Structured output saved to `results/` for integration with other tools

### Smart Vulnerability Scanner (`security-crawler`)
- **Multi-Category Detection**: XSS, SQLi, RCE, LFI, SSTI, XXE, CSRF, CRLF, XPath, and more
- **Intelligent Crawling**: Discovers hidden endpoints, parameters, and attack surface
- **Behavioral Analysis**: Identifies parameter behavior (database interaction, file ops, reflection)
- **Advanced Pattern Matching**: Parameter normalization, compound patterns, typo detection
- **Wordlist Intelligence**: Recursive scanning of fuzzdb, SecLists, PayloadsAllTheThings
- **Mutation Engine**: Generates payload variations for filter bypasses
- **Technology Detection**: Adapts payloads based on detected stack (PHP, MySQL, etc.)

---

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/yourusername/application_traceroute.git
cd application_traceroute/security-testing-suite

# Create and activate virtual environment (required on Python 3.13+ / Debian/Ubuntu)
python3 -m venv .venv
source .venv/bin/activate

# Install package and dependencies
pip install -e .

# Verify installation
security-traceroute --version
security-crawler --version
```

### Requirements

- Python 3.10+
- Linux / macOS (Windows with WSL)
- 2 GB RAM minimum

---

## 🎬 Quick Start

### 1. Infrastructure Analysis

Map the complete application stack and discover bypass techniques:

```bash
security-traceroute https://target.com
```

**Output**: `results/target_com_<timestamp>/bypasses_target_com_<timestamp>.json`

### 2. Vulnerability Scanning

Scan for vulnerabilities with intelligent crawling:

```bash
security-crawler https://target.com \
    --max-pages 100 \
    --verbose
```

**Output**: `results/target_com_<timestamp>/vulnerabilities_target_com_<timestamp>.json`

### 3. Authenticated Scanning (form login)

```bash
security-crawler https://target.com \
    --auth-type form \
    --auth-login-url "https://target.com/login" \
    --auth-username admin \
    --auth-password secret \
    --max-pages 200 \
    --verbose
```

### 4. Combined Workflow (Recommended)

```bash
# Step 1: Discover infrastructure and bypass techniques
security-traceroute https://target.com

# Step 2: Scan using the discovered bypasses
security-crawler https://target.com \
    --bypass-file results/target_com_<timestamp>/bypasses_target_com_<timestamp>.json \
    --max-pages 500 \
    --verbose
```

---

## 🔑 License Management

Both tools share a **single license file** stored at `~/.application_traceroute/license.json`.
Activating or deactivating a license from either tool affects both.

### License Types

| Type | Key Format | Duration |
|---|---|---|
| Free Trial | `DOGNETDA3-DAD-B3Dfree` | 30 days |
| Monthly | `ATXXX_XXX_XXX_XXXmo` | 30 days |
| Annual | `ATXXX_XXX_XXX_XXXyr` | 365 days |

> `X` = character from `ABCDEFGHILMENOPQRSTUVZXWYJK1234567890`

Licenses are validated online against **dognet.tech**. An activation token is returned by the server and stored locally. Each subsequent run performs an online token validation; on network failure the tool falls back to the locally cached expiration date.

### Check Current License

```bash
security-traceroute --license-status
# or
security-crawler --license-status
```

Output:
```
License: ANNUAL [online]
  Key:       ATABC_DEF_GHI_JKLyr
  Expires:   2027-03-10
  Remaining: 365 days
```

### Activate or Renew a License

```bash
security-traceroute --activate-license YOUR_LICENSE_KEY
# or
security-crawler --activate-license YOUR_LICENSE_KEY
```

If a license is already active its **online activation slot is released automatically** before the new key is registered. You can renew mid-subscription without manual steps.

```bash
# Renew before expiry — old slot released, new one registered
security-traceroute --activate-license ATNEW_KEY_HEREyr
# License activated: annual (expires 2027-03-10)
```

### Deactivate a License

Use this before moving the tool to a different machine so the activation slot is freed on the server:

```bash
security-traceroute --deactivate-license
# or
security-crawler --deactivate-license
```

Output:
```
License deactivated successfully.
```

### First Run Without a License

If no valid license is found the tool prompts interactively:

```
============================================================
  SECURITY TESTING SUITE v4.0 - LICENSE REQUIRED
============================================================

  License types:
    - Free trial (30 days)
    - Monthly   (30 days)  - suffix 'mo'
    - Annual    (365 days) - suffix 'yr'

  Enter license key: _
```

---

## 📖 Documentation

### Command Line Options

#### Application Traceroute

```
security-traceroute <target> [options]

Required:
  target                      Target URL

Options:
  --forbidden-endpoint URL    Known 403/401 endpoint for bypass testing
  --skip-forbidden-tests      Skip tests requiring a forbidden endpoint
  --verbose                   Detailed output
  --debug                     Log all I/O, headers and data flows to debug_*.json

License:
  --license-status            Show current license status and exit
  --activate-license KEY      Activate or renew a license key and exit
  --deactivate-license        Deactivate the current license and exit
```

#### Smart Vulnerability Scanner

```
security-crawler <target> [options]

Required:
  target                Target URL (http://example.com)

Scanning Options:
  --max-pages N         Maximum pages to crawl (default: 1000)
  --depth N             Maximum crawl depth (default: 3)
  --discovery-limit N   Endpoint discovery limit (default: 1000)

Authentication:
  --auth-type TYPE      Authentication type: form, basic, bearer, cookie, custom_header
  --auth-username USER  Username for authentication
  --auth-password PASS  Password for authentication
  --auth-token TOKEN    Bearer token
  --auth-login-url URL  Login URL for form authentication (--auth-type form)
  --auth-cookies STR    Cookies: name1=value1;name2=value2
  --auth-headers STR    Headers: Header1:Value1;Header2:Value2
  --auth-config FILE    JSON file with auth configuration

Wordlists:
  --wordlist-base PATH  Base directory for wordlists (REQUIRED for payload scanning)
                        e.g. /usr/share/wordlists or ~/wordlists

Discovery:
  --skip-discovery      Skip wordlist-based endpoint discovery (crawled pages only)

Bypass:
  --bypass-file FILE    Load bypasses from security-traceroute output

Output:
  --output FILE         Output JSON filename (saved inside results/<scan_dir>/)
  --verbose             Enable detailed logging
  --debug               Log all I/O, headers and data flows to debug_*.json

License:
  --license-status      Show current license status and exit
  --activate-license KEY  Activate or renew a license key and exit
  --deactivate-license  Deactivate the current license and exit
```

---

## 🔬 Examples

### Example 1: Quick scan, no auth

```bash
security-crawler https://target.com --verbose
```

---

### Example 2: Infrastructure analysis with a known 403 endpoint

Map the stack and run full bypass discovery on a specific protected path:

```bash
security-traceroute https://target.com \
    --forbidden-endpoint https://target.com/admin/dashboard
```

Results in `results/target_com_<timestamp>/bypasses_*.json`.

---

### Example 3: Infrastructure analysis only — skip bypass tests

Useful when you only want stack fingerprinting and have no 403 endpoint, or want a fast run:

```bash
security-traceroute https://target.com --skip-forbidden-tests
```

---

### Example 4: Form authentication

```bash
security-crawler https://app.example.com \
    --auth-type form \
    --auth-login-url "https://app.example.com/login" \
    --auth-username "pentester@example.com" \
    --auth-password "MyPassword123" \
    --max-pages 500 \
    --verbose
```

---

### Example 5: Bearer token (API or JWT)

```bash
security-crawler https://api.example.com \
    --auth-type bearer \
    --auth-token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
    --max-pages 200 \
    --verbose
```

---

### Example 6: Basic HTTP authentication

```bash
security-crawler https://staging.example.com \
    --auth-type basic \
    --auth-username admin \
    --auth-password admin123 \
    --verbose
```

---

### Example 7: Cookie-based authentication

Paste the session cookie directly from your browser after logging in:

```bash
security-crawler https://app.example.com \
    --auth-type cookie \
    --auth-cookies "session=abc123def456; csrftoken=xyz789; _ga=GA1.2.111" \
    --max-pages 300 \
    --verbose
```

---

### Example 8: Custom header authentication (API key, X-Auth-Token, etc.)

```bash
security-crawler https://api.example.com \
    --auth-type custom_header \
    --auth-headers "X-API-Key:sk-live-abc123;X-Tenant-ID:acme-corp" \
    --max-pages 100 \
    --verbose
```

---

### Example 9: Auth from a JSON config file

Useful when the auth setup is complex or reused across multiple runs. Create `auth.json`:

```json
{
    "type": "form",
    "login_url": "https://app.example.com/login",
    "username": "pentester",
    "password": "secret",
    "cookies": "remember_me=1"
}
```

Then run:

```bash
security-crawler https://app.example.com \
    --auth-config auth.json \
    --max-pages 500 \
    --verbose
```

---

### Example 10: Targeted scan with custom wordlists (specific vuln type + vendor)

Point `--wordlist-base` at your wordlist root. The scanner automatically picks the right
files based on detected technology. To target a specific vendor directory structure:

```bash
# Focused SQLi scan against a WordPress/MySQL target
security-crawler https://wp-site.example.com \
    --wordlist-base ~/wordlists \
    --max-pages 200 \
    --verbose
```

Matching wordlist paths (auto-discovered under `--wordlist-base`):
```
~/wordlists/
├── SecLists/Fuzzing/SQLi/             ← picked for sqli
├── PayloadsAllTheThings/SQL Injection/ ← picked for sqli
├── fuzzdb/attack/xss/                 ← picked for xss
└── custom/wordpress/sqli.txt          ← picked if path contains 'sqli'
```

Output includes:
```
📚 Found 27 wordlist files for sqli (tech: mysql)
Collected 147 MySQL-specific payloads
```

---

### Example 11: Skip wordlist endpoint discovery

Skip the path discovery phase and scan only crawled pages (faster, less noise):

```bash
security-crawler https://target.com \
    --skip-discovery \
    --max-pages 100 \
    --verbose
```

---

### Example 12: Debug mode — full HTTP I/O trace

Saves every request/response (headers, body, timings) to `debug_<session_id>.json`
in the results directory. Use to diagnose false positives or inspect exactly what was sent:

```bash
security-crawler https://target.com \
    --auth-type cookie \
    --auth-cookies "session=abc123" \
    --debug \
    --verbose
```

---

### Example 13: Full workflow — traceroute → bypass → scan

```bash
# Step 1: fingerprint the stack, find bypass techniques for the admin panel
security-traceroute https://target.com \
    --forbidden-endpoint https://target.com/admin

# Step 2: use the discovered bypasses in the full vulnerability scan
security-crawler https://target.com \
    --auth-type cookie \
    --auth-cookies "session=abc123" \
    --bypass-file results/target_com_<timestamp>/bypasses_target_com_<timestamp>.json \
    --wordlist-base ~/wordlists \
    --max-pages 1000 \
    --verbose
```

---

### Example 14: Bug bounty recon — full unauthenticated sweep

Large scope, deep crawl, all default payload sets, no wordlist (uses internal payloads):

```bash
security-traceroute https://target.com --skip-forbidden-tests

security-crawler https://target.com \
    --depth 5 \
    --max-pages 1000 \
    --discovery-limit 2000 \
    --verbose
```

---

## 📊 Output Formats

All output is saved under `results/<domain>_<timestamp>/` at the project root,
regardless of where the tool is invoked from.

### Vulnerability Report (JSON)

```json
{
  "target": "https://target.com",
  "scan_time": "2026-02-18T17:42:56",
  "vulnerabilities": [
    {
      "type": "xss",
      "severity": "high",
      "url": "https://target.com/search.php",
      "parameter": "q",
      "payload": "<script>alert(1)</script>",
      "method": "GET",
      "confidence": 100,
      "evidence": "Unencoded script tag reflected"
    }
  ],
  "statistics": {
    "pages_crawled": 42,
    "vulnerabilities_found": 27,
    "payloads_tested": 1270
  }
}
```

### Bypass Techniques (JSON)

```json
{
  "target": "https://target.com",
  "infrastructure": {
    "cdn": "Cloudflare",
    "waf": "ModSecurity",
    "backend": "Nginx"
  },
  "bypasses": [
    {
      "type": "unicode_confusion",
      "technique": "Unicode normalization bypass",
      "payload": "%u003cscript%u003e",
      "validated": true,
      "success_rate": 0.95
    }
  ]
}
```

---

## 🎯 Use Cases

### Bug Bounty Hunting
- Automated reconnaissance and vulnerability discovery
- High coverage with intelligent payload selection
- Technology-aware testing for better results
- Export results for integration with reporting tools

### Penetration Testing
- Comprehensive web application security assessment
- Infrastructure mapping for attack surface analysis
- Authenticated scanning for internal applications
- Detailed reporting with evidence and PoCs

### Security Research
- Advanced bypass technique discovery
- WAF/CDN evasion research
- Vulnerability pattern analysis
- Custom wordlist and payload testing

---

## 🔧 Advanced Configuration

### Custom Wordlists

Place your wordlists in the following structure and pass the root with `--wordlist-base`:

```
/path/to/wordlists/
├── fuzzdb/
│   └── attack/
│       ├── sql-injection/
│       ├── xss/
│       └── ...
├── SecLists/
│   └── Fuzzing/
│       ├── SQLi/
│       └── XSS/
└── PayloadsAllTheThings/
    ├── SQL Injection/
    └── XSS Injection/
```

The scanner automatically discovers and uses all relevant files.

### Technology Detection

The scanner automatically detects and adapts to:
- **Languages**: PHP, Python, Java, Node.js, Ruby, ASP.NET
- **Databases**: MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MongoDB
- **Frameworks**: Laravel, Django, Spring, Express, Rails
- **Servers**: Apache, Nginx, IIS, Tomcat

---

## 🧪 Testing

```bash
# Test on DVWA (Damn Vulnerable Web Application)
docker run --rm -p 8080:80 vulnerables/web-dvwa

security-crawler http://localhost:8080 \
    --auth-type form \
    --auth-login-url "http://localhost:8080/login.php" \
    --auth-username admin \
    --auth-password password \
    --verbose

# Expected: 15-20 vulnerabilities detected
```

---

## 📈 Performance

### Benchmarks (testphp.vulnweb.com)

| Metric | Value |
|--------|-------|
| Pages Crawled | 42 |
| Vulnerabilities Found | 27 |
| Time Elapsed | 21.7 minutes |
| HTTP Requests | 1269 |
| Request Rate | 1.0 req/s |
| Memory Usage | 76 MB |
| Success Rate | 99.9% |

### Scalability

- **Small target** (< 50 pages): 10–20 minutes
- **Medium target** (50–200 pages): 30–60 minutes
- **Large target** (200–500 pages): 1–3 hours
- **Very large target** (500+ pages): 3–6 hours

---

## 🛡️ Security & Ethics

### Responsible Use

⚠️ **This tool is for authorized security testing only.**

- ✅ **DO**: Use on bug bounty programs, penetration tests, your own applications
- ❌ **DON'T**: Use on systems without explicit permission
- ✅ **DO**: Follow responsible disclosure practices
- ❌ **DON'T**: Use for malicious purposes or illegal activities

### Legal Disclaimer

Users are responsible for compliance with applicable laws. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/yourusername/application_traceroute.git
cd application_traceroute/security-testing-suite
pip install -e ".[dev]"
```

---

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full history of decisions, fixes, and features.

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/application_traceroute/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/application_traceroute/discussions)
- **Email**: info@dognet.tech

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Wordlists**: fuzzdb, SecLists, PayloadsAllTheThings
- **Testing**: DVWA, testphp.vulnweb.com
- **Community**: Bug bounty hunters and security researchers worldwide

---

<div align="center">

**Built with ❤️ for the Security Community**

[Report Bug](https://github.com/yourusername/application_traceroute/issues) • [Request Feature](https://github.com/yourusername/application_traceroute/issues) • [Documentation](https://github.com/yourusername/application_traceroute/wiki)

</div>
