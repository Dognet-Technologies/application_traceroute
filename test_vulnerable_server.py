#!/usr/bin/env python3
"""
Test Vulnerable Server per validare la Suite di Security Testing.
Questo server contiene vulnerabilità INTENZIONALI per testare la capacità
della Suite di rilevare bypass e vulnerabilità.

WARNING: NON usare in produzione! Solo per testing locale.
"""

from flask import Flask, request, Response, redirect, abort
import re
import hashlib
import time

app = Flask(__name__)

# Simula diversi layer dello stack
STACK_HEADERS = {
    'X-Powered-By': 'PHP/7.4.3',
    'Server': 'nginx/1.18.0',
    'X-Cache': 'HIT from proxy-layer',
    'X-Backend': 'apache-backend-01',
}

# Path "protetti" - ma con bypass intenzionali
PROTECTED_PATHS = ['/admin', '/api/internal', '/config', '/debug', '/private']


def add_stack_headers(response):
    """Aggiunge header che rivelano lo stack."""
    for key, value in STACK_HEADERS.items():
        response.headers[key] = value
    response.headers['X-Request-ID'] = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    return response


def check_waf_rules(path, headers):
    """
    WAF simulato con VULNERABILITÀ INTENZIONALI per bypass testing.
    """
    normalized_path = path.lower()

    # VULNERABILITÀ 1: Path Traversal Bypass
    # Il WAF non normalizza ../ correttamente
    if '/../' in path or path.startswith('../'):
        # Bug: non controlla tutte le varianti
        pass  # Dovrebbe bloccare ma non lo fa

    # VULNERABILITÀ 2: Case Sensitivity Bypass
    # nginx è case-sensitive, ma il backend potrebbe non esserlo
    for protected in PROTECTED_PATHS:
        if normalized_path.startswith(protected):
            # BYPASS: /Admin, /ADMIN, /AdMiN passano se il backend è case-insensitive
            if path != normalized_path:  # Case diversa = possibile bypass
                return None  # Lascia passare (vulnerabilità!)
            return "blocked_by_waf"

    # VULNERABILITÀ 3: URL Encoding Bypass
    # Il WAF non decodifica completamente
    if '%2f' in path.lower() or '%2F' in path:  # /
        # Non controlla double encoding (%252f)
        pass

    # VULNERABILITÀ 4: Header Injection per bypass
    # X-Original-URL e X-Rewrite-URL non sono filtrati
    if 'X-Original-URL' in headers or 'X-Rewrite-URL' in headers:
        return None  # Bypass tramite header!

    # VULNERABILITÀ 5: Null Byte Injection (legacy)
    if '%00' in path:
        # Tronca il path al null byte
        return None

    return None  # Permesso


def check_backend_auth(path, headers):
    """
    Controllo di autenticazione backend con VULNERABILITÀ.
    """
    # VULNERABILITÀ 6: Path Normalization Discrepancy
    # Backend normalizza in modo diverso dal WAF
    clean_path = path.replace('//', '/').rstrip('/')

    # Rimuove dot-segments (../) - ma dopo il WAF ha già controllato!
    while '/./' in clean_path:
        clean_path = clean_path.replace('/./', '/')

    # Controlla percorsi protetti
    for protected in PROTECTED_PATHS:
        if clean_path.lower().startswith(protected):
            # Richiede auth
            auth = headers.get('Authorization')
            if not auth or auth != 'Bearer valid-token-12345':
                return False

    return True


@app.route('/')
def index():
    """Pagina principale."""
    resp = Response("""
    <html>
    <head><title>Test Vulnerable Server</title></head>
    <body>
        <h1>Test Server for Security Suite Validation</h1>
        <p>Endpoints disponibili:</p>
        <ul>
            <li><a href="/public">Public</a> - Accessibile a tutti</li>
            <li><a href="/admin">Admin</a> - Protetto (richiede auth)</li>
            <li><a href="/api/internal">API Internal</a> - API interna protetta</li>
            <li><a href="/config">Config</a> - Configurazione protetta</li>
            <li><a href="/debug">Debug</a> - Debug info protetta</li>
            <li><a href="/private">Private</a> - Area privata</li>
        </ul>
        <p><strong>Test form vulnerabile:</strong></p>
        <form action="/search" method="GET">
            <input type="text" name="q" placeholder="Search...">
            <input type="hidden" name="debug" value="false">
            <button type="submit">Search</button>
        </form>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
        <p><strong>Bypass intenzionali per testing:</strong></p>
        <ul>
            <li><a href="/Admin">Case bypass: /Admin</a></li>
            <li><a href="/admin/">Trailing slash: /admin/</a></li>
            <li><a href="//admin">Double slash: //admin</a></li>
        </ul>
        <!-- TODO: remove debug endpoint before production -->
        <!-- DEBUG: admin password is admin123 -->
    </body>
    </html>
    """, mimetype='text/html')
    return add_stack_headers(resp)


@app.route('/public')
def public():
    """Endpoint pubblico."""
    resp = Response('{"status": "ok", "public": true}', mimetype='application/json')
    return add_stack_headers(resp)


@app.route('/search')
def search():
    """Search endpoint - VULNERABILE a XSS e SQL injection (intenzionale)."""
    query = request.args.get('q', '')
    debug = request.args.get('debug', 'false')

    # VULNERABILITA XSS: riflette input non sanitizzato
    resp = Response(f"""
    <html>
    <head><title>Search Results</title></head>
    <body>
        <h1>Search Results for: {query}</h1>
        <p>Debug mode: {debug}</p>
        <p>No results found for your query.</p>
        <a href="/">Back to home</a>
    </body>
    </html>
    """, mimetype='text/html')
    return add_stack_headers(resp)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login endpoint - VULNERABILE a SQL injection (intenzionale)."""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # VULNERABILITA: SQL injection simulation
        # In un vero scenario: SELECT * FROM users WHERE username='{username}' AND password='{password}'
        if "'" in username or "'" in password or "OR" in username.upper():
            # Simula bypass SQL injection
            resp = Response(f"""
            <html>
            <body>
                <h1>SQL Injection Detected!</h1>
                <p>Your payload: {username}</p>
                <p>In a real scenario, you would have bypassed authentication!</p>
                <p>Secret data: DATABASE_PASSWORD=supersecret123</p>
            </body>
            </html>
            """, mimetype='text/html')
            resp.headers['X-Vulnerability'] = 'SQL-Injection'
            return add_stack_headers(resp)

        if username == 'admin' and password == 'admin123':
            resp = Response('{"status": "success", "token": "secret-admin-token-xyz"}',
                          mimetype='application/json')
            return add_stack_headers(resp)

        resp = Response('{"status": "error", "message": "Invalid credentials"}',
                       status=401, mimetype='application/json')
        return add_stack_headers(resp)

    # GET request - show login form
    resp = Response("""
    <html>
    <body>
        <h1>Login</h1>
        <form method="POST">
            <input type="text" name="username" placeholder="Username"><br>
            <input type="password" name="password" placeholder="Password"><br>
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """, mimetype='text/html')
    return add_stack_headers(resp)


@app.route('/admin', defaults={'subpath': ''})
@app.route('/admin/<path:subpath>')
def admin(subpath):
    """Admin endpoint - protetto ma con bypass."""
    # Simula il check del WAF
    waf_result = check_waf_rules(request.path, dict(request.headers))
    if waf_result == "blocked_by_waf":
        resp = Response('403 Forbidden - WAF Block', status=403)
        resp.headers['X-Blocked-By'] = 'WAF-Layer'
        return add_stack_headers(resp)

    # Check backend auth
    if not check_backend_auth(request.path, dict(request.headers)):
        resp = Response('401 Unauthorized - Auth Required', status=401)
        resp.headers['X-Blocked-By'] = 'Backend-Auth'
        return add_stack_headers(resp)

    # Accesso concesso!
    resp = Response(f"""
    <html>
    <head><title>Admin Panel</title></head>
    <body>
        <h1>🔓 ADMIN ACCESS GRANTED</h1>
        <p>Path: {request.path}</p>
        <p>Subpath: {subpath}</p>
        <p>This is sensitive admin content!</p>
        <p>Secret: ADMIN_SECRET_KEY_12345</p>
    </body>
    </html>
    """, mimetype='text/html')
    resp.headers['X-Access'] = 'granted'
    return add_stack_headers(resp)


@app.route('/Admin', defaults={'subpath': ''})
@app.route('/Admin/<path:subpath>')
def admin_case_bypass(subpath):
    """Admin con case diversa - BYPASS!"""
    # Questo bypass funziona perché Flask route /Admin != /admin
    # ma la logica di business potrebbe trattarli come uguali
    resp = Response(f"""
    <html>
    <head><title>Admin Panel (Case Bypass)</title></head>
    <body>
        <h1>🔓 ADMIN ACCESS via CASE BYPASS!</h1>
        <p>Path: {request.path}</p>
        <p>Il WAF non ha bloccato perché /Admin != /admin</p>
        <p>Secret: ADMIN_SECRET_KEY_12345</p>
    </body>
    </html>
    """, mimetype='text/html')
    resp.headers['X-Access'] = 'granted'
    resp.headers['X-Bypass-Type'] = 'case-sensitivity'
    return add_stack_headers(resp)


@app.route('/api/internal', defaults={'subpath': ''})
@app.route('/api/internal/<path:subpath>')
def api_internal(subpath):
    """API interna protetta."""
    waf_result = check_waf_rules(request.path, dict(request.headers))
    if waf_result == "blocked_by_waf":
        resp = Response('{"error": "forbidden"}', status=403, mimetype='application/json')
        return add_stack_headers(resp)

    if not check_backend_auth(request.path, dict(request.headers)):
        resp = Response('{"error": "unauthorized"}', status=401, mimetype='application/json')
        return add_stack_headers(resp)

    resp = Response('{"internal_data": "sensitive_api_response", "secret": "API_KEY_SECRET"}',
                    mimetype='application/json')
    return add_stack_headers(resp)


@app.route('/config')
def config():
    """Configurazione - protetta."""
    waf_result = check_waf_rules(request.path, dict(request.headers))
    if waf_result == "blocked_by_waf":
        return add_stack_headers(Response('Forbidden', status=403))

    if not check_backend_auth(request.path, dict(request.headers)):
        return add_stack_headers(Response('Unauthorized', status=401))

    resp = Response("""
    {
        "db_host": "internal-db.local",
        "db_password": "super_secret_password",
        "api_keys": ["key1", "key2", "key3"]
    }
    """, mimetype='application/json')
    return add_stack_headers(resp)


@app.route('/debug')
def debug():
    """Debug info - protetta."""
    waf_result = check_waf_rules(request.path, dict(request.headers))
    if waf_result == "blocked_by_waf":
        return add_stack_headers(Response('Forbidden', status=403))

    if not check_backend_auth(request.path, dict(request.headers)):
        return add_stack_headers(Response('Unauthorized', status=401))

    resp = Response(f"""
    Debug Information:
    - Request Path: {request.path}
    - Headers: {dict(request.headers)}
    - Stack Trace: [simulated]
    - Environment: PRODUCTION
    """)
    return add_stack_headers(resp)


@app.route('/private')
def private():
    """Area privata."""
    waf_result = check_waf_rules(request.path, dict(request.headers))
    if waf_result == "blocked_by_waf":
        return add_stack_headers(Response('Forbidden', status=403))

    if not check_backend_auth(request.path, dict(request.headers)):
        return add_stack_headers(Response('Unauthorized', status=401))

    resp = Response('Private area content - you should not see this!')
    return add_stack_headers(resp)


# Catch-all per path con bypass
@app.route('/<path:path>')
def catch_all(path):
    """Catch-all handler per testare bypass."""
    full_path = '/' + path

    # Check se è un tentativo di bypass verso path protetti
    normalized = full_path.lower().replace('//', '/').replace('/./', '/')

    # Rimuovi trailing slash per normalizzazione
    while normalized.endswith('/') and len(normalized) > 1:
        normalized = normalized[:-1]

    # Check X-Original-URL header bypass
    original_url = request.headers.get('X-Original-URL')
    if original_url:
        # VULNERABILITÀ: segue X-Original-URL senza validazione!
        for protected in PROTECTED_PATHS:
            if protected in original_url.lower():
                resp = Response(f"""
                <html>
                <body>
                    <h1>🔓 ACCESS via X-Original-URL BYPASS!</h1>
                    <p>Original URL: {original_url}</p>
                    <p>Actual Path: {full_path}</p>
                    <p>Secret content accessed!</p>
                </body>
                </html>
                """, mimetype='text/html')
                resp.headers['X-Bypass-Type'] = 'header-injection'
                return add_stack_headers(resp)

    # Check se path normalizzato è protetto
    for protected in PROTECTED_PATHS:
        if normalized.startswith(protected):
            # Path normalization bypass check
            if full_path != normalized:
                # BYPASS RILEVATO!
                resp = Response(f"""
                <html>
                <body>
                    <h1>🔓 ACCESS via PATH NORMALIZATION BYPASS!</h1>
                    <p>Requested: {full_path}</p>
                    <p>Normalized: {normalized}</p>
                    <p>Secret content accessed via bypass!</p>
                </body>
                </html>
                """, mimetype='text/html')
                resp.headers['X-Bypass-Type'] = 'path-normalization'
                return add_stack_headers(resp)
            else:
                # Path protetto richiesto direttamente
                return add_stack_headers(Response('Unauthorized', status=401))

    # Path non protetto
    resp = Response(f'Path {full_path} not found', status=404)
    return add_stack_headers(resp)


if __name__ == '__main__':
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║     TEST VULNERABLE SERVER - Security Suite Validation            ║
╠═══════════════════════════════════════════════════════════════════╣
║  WARNING: This server contains INTENTIONAL vulnerabilities!       ║
║  DO NOT use in production - testing purposes only!                ║
╠═══════════════════════════════════════════════════════════════════╣
║  Bypass types implemented:                                        ║
║  1. Case Sensitivity    (/Admin vs /admin)                        ║
║  2. Path Normalization  (//admin, /./admin)                       ║
║  3. Header Injection    (X-Original-URL)                          ║
║  4. URL Encoding        (%2fadmin)                                ║
║  5. Double Slash        (//admin)                                 ║
╚═══════════════════════════════════════════════════════════════════╝
    """)
    app.run(host='127.0.0.1', port=8888, debug=False, threaded=True)
