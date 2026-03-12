# Changelog

Tutte le modifiche rilevanti al progetto sono documentate in questo file.
Formato: [Semantic Versioning](https://semver.org/) — `MAJOR.MINOR.PATCH`

---

## [3.5.5] — 2026-03-11

### SmartCrawler (`SmartCrawler/smart_vuln_crawler2.py`)

#### Aggiunto
- **`SemanticResponseDiffer`** — confronto semantico delle risposte HTTP che normalizza
  CSRF token, session ID, timestamp e cache buster prima del diff. Riduce i falsi positivi
  causati da contenuto dinamico della pagina.
- **`RateLimiter`** — token bucket thread-safe con jitter randomico (default 30%) per
  distribuire le richieste in modo da evitare pattern detection da WAF.
- **`PerformanceMonitor`** — traccia richieste HTTP, payload testati, vulnerabilità trovate
  e utilizzo memoria (psutil opzionale). Stats loggate a fine scansione.
- **`LRUCache`** — cache con limite di dimensione (default 5000 entry) per evitare memory
  leak su scansioni lunghe.
- **`SmartCrawler.should_test_parameter()` / `mark_parameter_tested()`** — deduplication
  basata su LRU: evita di ritestare lo stesso (endpoint, param, vuln_type) su pagine diverse.
- **`VulnerabilityLogger.VULN_METADATA`** — mapping completo vuln_type → CWE ID, OWASP
  category, CVSS score, severity per SQLi/XSS/RCE/LFI/RFI/SSTI/XXE/SSRF/IDOR/OPEN_REDIRECT/CSRF.
- **`VulnerabilityLogger.SEVERITY_ICONS`** — icone colorate (🔴🟠🟡🟢) per output terminale.
- **`VulnerabilityLogger.confidence_bar()`** — barra visuale di confidenza `[████████░░] 80%`.
- **`VulnerabilityLogger.detect_false_positive_indicators()`** — segnala 403/404/redirect
  come possibili falsi positivi nel JSON di output.
- **`VulnerabilityLogger.generate_verification_hint()`** — genera comandi sqlmap/dalfox/
  commix/tplmap/curl pronti all'uso per ogni finding.
- **`__version__ = "3.5.5"`** nel modulo.
- Epilog argparse con esempi di utilizzo e workflow tipico.

#### Modificato
- `log_vulnerability()` — ora include severity, CVSS, CWE, OWASP, false positive indicators
  e verification hint nel JSON. Log line arricchita con severity icon e CVSS score.
- `SmartCrawler.__init__` — inizializza `perf_monitor`, `rate_limiter`, `_tested_params`.
- `test_vulnerability_immediately()` — controlla deduplication prima di ogni test.
- Argparse `description` aggiornata a `v3.5.5`.

#### Corretto
- Rimossi 3 metodi `get_output_dir()` / `get_summary()` duplicati in `VulnerabilityLogger`
  (bug preesistente).
- Spaziatura e whitespace irregolari nel corpo di `VulnerabilityLogger` (accessi
  `self. vuln_file`, `method. upper()`, etc.).

### Application Traceroute (`Application_tracereout_3.5/application_traceroute_v3.5.py`)

#### Modificato
- Versione aggiornata da `v3.5-dev` a `v3.5.5` nel docstring, nel banner di avvio,
  nel report testuale e nella descrizione argparse.

### Documentazione

#### Aggiunto
- **`CHANGELOG.md`** — questo file.

#### Modificato
- **`README.md`** — riscritto: workflow a 3 step, reference dei 3 tool con usage completo,
  diagramma architetturale aggiornato, tabella moduli, sezione "Novità in v3.5.5",
  requisiti aggiornati (rimossi scipy/scikit-learn/rich/click/matplotlib non usati).

---

## [3.5.0] — 2026-01-xx

### Aggiunto
- Application Traceroute con Bayesian bypass inference
- Semantic bypass engine con algoritmo genetico (7 operatori di mutazione)
- Graph attack planner con A* search e Nash equilibrium
- SmartCrawler con BehavioralContextEngine e multi-type authentication
- Intelligent Bypass Validator v5.0

---

## [3.0.0] — 2025-xx-xx

### Aggiunto
- Prima release pubblica
- Stack fingerprinting base
- Bypass generation senza validazione statistica
