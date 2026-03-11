# Application Traceroute Suite v3.5.5

Suite di tool per la fase di discovery e vulnerability assessment di applicazioni web.

---

## Workflow consigliato

### Step 1 — Stack Fingerprinting & Bypass Generation

```bash
python Application_tracereout_3.5/application_traceroute_v3.5.py https://target.com \
  --forbidden-endpoint https://target.com/admin
```

Ricostruisce lo stack tecnologico, individua discrepanze tra layer e genera bypass verificati.
Output in `results/<target>/`:
- `bypasses_<target>_<ts>.json` — bypass confermati (input per gli step successivi)
- `traceroute_<target>_<ts>.txt` — report testuale

### Step 2 — Bypass Validation (opzionale)

```bash
python Application_tracereout_3.5/intelligent_bypass_validator.py \
  results/<target>/bypasses_<target>_<ts>.json \
  --baseline-url https://target.com
```

Ri-valida i bypass con analisi Bayesiana su un baseline fresco. Utile per target con WAF dinamici.

### Step 3 — Vulnerability Crawling

```bash
python SmartCrawler/smart_vuln_crawler2.py https://target.com \
  --bypass-file results/<target>/bypasses_<target>_<ts>.json \
  --wordlist-base /usr/share/wordlists \
  --depth 3 --max-pages 200 -v
```

Crawla il target, testa i parametri per SQLi/XSS/RCE/LFI/SSTI/CSRF e applica i bypass generati dallo Step 1.

---

## Tool reference

### `application_traceroute_v3.5.py`

```
usage: application_traceroute_v3.5.py [-h]
                                      [--forbidden-endpoint FORBIDDEN_ENDPOINT]
                                      [--skip-forbidden-tests]
                                      target

Application Stack Traceroute v3.5.5 - Intelligent Stack Reconstruction

positional arguments:
  target                Target URL to analyze

options:
  --forbidden-endpoint  Known 403/401 endpoint for bypass testing
  --skip-forbidden-tests  Skip bypass discovery phase
```

### `intelligent_bypass_validator.py`

```
usage: intelligent_bypass_validator.py [-h]
                                       --baseline-url BASELINE_URL
                                       [--rate-limit RATE_LIMIT]
                                       [--output OUTPUT]
                                       json_file

Intelligent Bypass Validator v5.0 - Bayesian validation system
```

### `smart_vuln_crawler2.py`

```
usage: smart_vuln_crawler2.py [-h]
                              [--depth DEPTH] [--max-pages MAX_PAGES]
                              [--output OUTPUT]
                              [--wordlist-base WORDLIST_BASE]
                              [--discovery-limit DISCOVERY_LIMIT]
                              [--skip-discovery]
                              [--bypass-file BYPASS_FILE] [-v]
                              [--auth-type {basic,bearer,cookie,form,custom_header}]
                              [--auth-username AUTH_USERNAME]
                              [--auth-password AUTH_PASSWORD]
                              [--auth-token AUTH_TOKEN]
                              [--auth-login-url AUTH_LOGIN_URL]
                              [--auth-cookies AUTH_COOKIES]
                              [--auth-headers AUTH_HEADERS]
                              [--auth-config AUTH_CONFIG]
                              target

Smart Vulnerability Crawler v3.5.5 - Bypass Integration, Behavioral Analysis & Extended Detection
```

---

## Architettura

```
┌─────────────────────────────────────────────────────────────────┐
│              Application Traceroute Suite v3.5.5                │
└────────────────────────────┬────────────────────────────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│   Differential   │ │    Semantic      │ │  Graph Attack    │
│    Analyzer      │ │     Engine       │ │    Planner       │
│  (Bayesian AI)   │ │  (NLP + GA)      │ │ (A* + Nash)      │
└──────────────────┘ └──────────────────┘ └──────────────────┘
        │                    │                    │
        └────────────────────┴────────────────────┘
                             │
        ┌────────────────────▼────────────────────┐
        │          SmartVulnCrawler v3.5.5         │
        │  ┌─────────────┐  ┌────────────────────┐│
        │  │ RateLimiter │  │ SemanticDiffer      ││
        │  │ (WAF jitter)│  │ (token-aware diff)  ││
        │  └─────────────┘  └────────────────────┘│
        │  ┌─────────────┐  ┌────────────────────┐│
        │  │ LRU Dedup   │  │ VulnLogger w/ CWE  ││
        │  │ (param cache│  │ OWASP/CVSS/hints   ││
        │  └─────────────┘  └────────────────────┘│
        └─────────────────────────────────────────┘
```

---

## Moduli (Application_tracereout_3.5/)

| File | Funzione |
|---|---|
| `application_traceroute_v3.5.py` | Stack fingerprinting, bypass generation, export JSON |
| `intelligent_bypass_validator.py` | Ri-validazione bypass con Bayesian inference |
| `advanced_bypass_engine.py` | Parser discrepancy testing (smuggling, encoding, path normalization) |
| `semantic_bypass_engine.py` | NLP error classification + evolutionary payload mutation |
| `graph_attack_planner.py` | A* attack chain optimization con Nash equilibrium |
| `smart_crawler_advanced_engine.py` | Engine ausiliario per SmartCrawler |

---

## Novità in v3.5.5

- **SemanticResponseDiffer** — diff che ignora CSRF token, session ID e timestamp dinamici
- **RateLimiter** — token bucket con jitter randomico per WAF evasion
- **PerformanceMonitor** — stats a fine scan: req/s, payload/s, memoria
- **LRU parameter deduplication** — evita di ritestare lo stesso (endpoint, param, tipo) più volte
- **VulnerabilityLogger enriched** — CWE, OWASP category, CVSS, severity icon, hint per sqlmap/dalfox/commix
- **Bug fix** — rimossi 3 metodi duplicati in VulnerabilityLogger

---

## Requisiti

```
requests>=2.31.0
beautifulsoup4>=4.12.0
urllib3>=2.0.0
aiohttp>=3.9.0
numpy>=1.24.0
networkx>=3.1
psutil>=5.9.0        # opzionale, per memory monitoring
```

---

**Licenza**: Authorized security research only — Dognet Technologies srl
Vedere `LICENSE` per i termini completi.
