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
            <li>/public - Accessibile a tutti</li>
            <li>/admin - Protetto (richiede auth)</li>
            <li>/api/internal - API interna protetta</li>
            <li>/config - Configurazione protetta</li>
            <li>/debug - Debug info protetta</li>
            <li>/private - Area privata</li>
        </ul>
        <p><strong>Bypass intenzionali per testing:</strong></p>
        <ul>
            <li>Case sensitivity bypass (/Admin vs /admin)</li>
            <li>Path normalization (//admin, /./admin)</li>
            <li>Header injection (X-Original-URL)</li>
            <li>URL encoding (%2fadmin)</li>
        </ul>
    </body>
    </html>
    """, mimetype='text/html')
    return add_stack_headers(resp)


@app.route('/public')
def public():
    """Endpoint pubblico."""
    resp = Response('{"status": "ok", "public": true}', mimetype='application/json')
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
