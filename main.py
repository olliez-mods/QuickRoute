from flask import Flask, request, Response, redirect, send_from_directory
from quick_ini import QuickIni
from werkzeug.serving import make_server
import requests
import os
import ssl
import threading

# INI file =============================================================
if(not QuickIni.load_file("config.ini")):
    print(f"Could not load config: {QuickIni.get_last_error()}\nFalling back to default settings")
port = QuickIni.get_value("port", 80, int)
use_https = QuickIni.get_value("use_https", False, bool)
https_port = QuickIni.get_value("https_port", 443, int)
acme_webroot = QuickIni.get_value("acme_webroot", "/var/www/acme")
cert_dir = QuickIni.get_value("cert_dir", "/etc/letsencrypt/live")
# A prefix matches whole path segments only: '/phex' matches /phex and /phex/..., not /phexfoo.
# The bare prefix (/phex) redirects to /phex/ so relative URLs in pages resolve under it.
ROUTES = QuickIni.get_all("routes")
DOMAIN_ROUTES = QuickIni.get_all("domains")
# ======================================================================

app = Flask(__name__)

# Longest first, so a nested prefix wins over a shorter one it starts with
SORTED_ROUTES = sorted(((r.strip('/'), t) for r, t in ROUTES.items()), key=lambda rt: len(rt[0]), reverse=True)

# HTTPS certificates ===================================================
# Each new connection picks its domain's certbot certificate (SNI), and a renewed certificate
# is loaded on the next connection, so renewals never need a restart
cert_cache = {}  # cert name -> (mtime, SSLContext)
cert_lock = threading.Lock()
missing_certs = set()

def cert_files(host):
    # The host's own certificate, or for www.x the certificate of x (certbot -d x -d www.x)
    names = [host, host[4:]] if host.startswith('www.') else [host]
    for name in names:
        chain = os.path.join(cert_dir, name, 'fullchain.pem')
        key = os.path.join(cert_dir, name, 'privkey.pem')
        if os.path.exists(chain) and os.path.exists(key):
            return name, chain, key
    return None

def context_for(host):
    found = cert_files(host)
    if not found:
        return None
    name, chain, key = found
    mtime = os.path.getmtime(chain)
    with cert_lock:
        cached = cert_cache.get(name)
        if cached and cached[0] == mtime:
            return cached[1]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(chain, key)
        cert_cache[name] = (mtime, context)
        print(f"Loaded certificate for {name}")
        return context

def pick_certificate(ssl_socket, server_name, base_context):
    if not server_name:
        return
    try:
        context = context_for(server_name.lower())
    except (OSError, ssl.SSLError) as e:
        # e.g. caught mid-renewal; not cached, so the next connection tries again
        print(f"Could not load certificate for {server_name}: {e}")
        return
    if context:
        ssl_socket.context = context
    elif server_name not in missing_certs:
        # Logged once per name; without a certificate the browser shows ERR_SSL_VERSION_OR_CIPHER_MISMATCH
        missing_certs.add(server_name)
        print(f"No certificate for {server_name} in {cert_dir} (missing, or not readable by this user)")

https_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
https_context.sni_callback = pick_certificate
# ======================================================================

#@app.route('/')
def default_route():
    return """NOT VALID LOL"""

# certbot --webroot puts its challenge files here; served for every host, over plain http
@app.route('/.well-known/acme-challenge/<token>')
def acme_challenge(token):
    return send_from_directory(os.path.join(acme_webroot, '.well-known', 'acme-challenge'), token)

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(path):

    host = request.host.split(':')[0]  # strip port if present
    query_string = request.query_string.decode('utf-8')

    # Plain http for a domain that has a certificate goes to https (308 keeps the method and body)
    if(use_https and request.scheme == 'http' and cert_files(host)):
        https_host = host if https_port == 443 else f"{host}:{https_port}"
        return redirect(f"https://{https_host}/{path}" + ('?' + query_string if query_string else ''), 308)

    # --- 1. Check domain-based routing ---
    if host in DOMAIN_ROUTES:
        target = DOMAIN_ROUTES[host]
        target_url = target + path
    else:
        # --- 2. Fall back to path-based routing ---
        for route, target in SORTED_ROUTES:
            if path == route:
                # 308 keeps the method and body
                return redirect('/' + route + '/' + ('?' + query_string if query_string else ''), 308)
            if path.startswith(route + '/'):
                target_url = target + path[len(route) + 1:]
                break
        else:
            return Response('Not Found', status=404)

    # Append query parameters
    if query_string:
        target_url = f"{target_url}?{query_string}"

    # Tell the service who really connected (werkzeug's ProxyFix reads these)
    headers = {key: value for key, value in request.headers if key != 'Host'}
    forwarded_for = request.headers.get('X-Forwarded-For')
    headers['X-Forwarded-For'] = f"{forwarded_for}, {request.remote_addr}" if forwarded_for else request.remote_addr
    headers['X-Forwarded-Proto'] = request.scheme
    headers['X-Forwarded-Host'] = request.host

    # Forward the request
    try:
        response = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False
        )
    except requests.exceptions.ConnectionError: return Response('Service Unreachable', status=503)
    except requests.exceptions.Timeout: return Response('Service Timeout', status=504)
    except requests.exceptions.RequestException: return Response('Bad Gateway', status=502)

    # Build response
    proxy_response = Response(response.content, response.status_code)
    for key, value in response.headers.items():
        proxy_response.headers[key] = value
    return proxy_response

if __name__ == '__main__':
    if(use_https):
        https_server = make_server('0.0.0.0', https_port, app, threaded=True, ssl_context=https_context)
        threading.Thread(target=https_server.serve_forever, daemon=True).start()
        print(f"HTTPS on port {https_port}, certificates from {cert_dir}")
    app.run(debug=False, port=port, host='0.0.0.0')
