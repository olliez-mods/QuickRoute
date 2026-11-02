from flask import Flask, request, Response, redirect, send_from_directory
from quick_ini import QuickIni
from werkzeug.serving import make_server, WSGIRequestHandler
from werkzeug.datastructures import EnvironHeaders
from urllib.parse import urlsplit
import requests
import os
import socket
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

# No static folder: Flask's built-in /static route would answer /static/... itself instead of forwarding it
app = Flask(__name__, static_folder=None)

# Longest first, so a nested prefix wins over a shorter one it starts with
SORTED_ROUTES = sorted(((r.strip('/'), t) for r, t in ROUTES.items()), key=lambda rt: len(rt[0]), reverse=True)

# These describe a single connection, so they're never passed through in either direction
HOP_BY_HOP = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
              'te', 'trailers', 'transfer-encoding', 'upgrade'}

def find_target(host, path):
    # The service URL for host and path, or None when nothing matches (a bare prefix doesn't)
    if host in DOMAIN_ROUTES:
        return DOMAIN_ROUTES[host] + path
    for route, target in SORTED_ROUTES:
        if path.startswith(route + '/'):
            return target + path[len(route) + 1:]
    return None

def forwarded_headers(incoming, remote_addr, scheme, host):
    # Tell the service who really connected (werkzeug's ProxyFix reads these)
    headers = {key: value for key, value in incoming
               if key.lower() not in HOP_BY_HOP and key.lower() not in ('host', 'content-length')}
    forwarded_for = incoming.get('X-Forwarded-For')
    headers['X-Forwarded-For'] = f"{forwarded_for}, {remote_addr}" if forwarded_for else remote_addr
    headers['X-Forwarded-Proto'] = scheme
    headers['X-Forwarded-Host'] = host
    return headers

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

    # A bare path prefix redirects to prefix/ (308 keeps the method and body)
    if host not in DOMAIN_ROUTES:
        for route, _ in SORTED_ROUTES:
            if path == route:
                return redirect('/' + route + '/' + ('?' + query_string if query_string else ''), 308)

    target_url = find_target(host, path)
    if target_url is None:
        return Response('Not Found', status=404)

    # Append query parameters
    if query_string:
        target_url = f"{target_url}?{query_string}"

    headers = forwarded_headers(request.headers, request.remote_addr, request.scheme, request.host)

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

    # Build response. requests has already un-chunked and decompressed the body, so the service's
    # framing headers no longer apply (werkzeug sets Content-Length). raw.headers keeps each
    # Set-Cookie separate, where response.headers would join them into one.
    excluded = HOP_BY_HOP | {'content-length', 'content-encoding'}
    response_headers = [(key, value) for key, value in response.raw.headers.items() if key.lower() not in excluded]
    return Response(response.content, response.status_code, headers=response_headers)

# WebSockets ===========================================================
# requests can't do an HTTP Upgrade, so a WebSocket request (e.g. Cockpit's /cockpit/socket) is
# tunnelled instead: the request goes to the service over a raw socket, then bytes are copied both
# ways untouched until either side closes. This sits outside Flask because it takes over werkzeug's
# client socket, which Flask would otherwise write a second response onto.
def pipe(source, destination):
    try:
        while data := source.recv(65536):
            destination.sendall(data)
    except OSError:
        pass
    finally:
        # Wake the other direction. socket.socket.shutdown on purpose: SSLSocket.shutdown drops its
        # TLS state, which the other thread may still be using.
        for sock in (source, destination):
            try:
                socket.socket.shutdown(sock, socket.SHUT_RDWR)
            except OSError:
                pass

class WebSocketTunnel:
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        client = environ.get('werkzeug.socket')
        if environ.get('HTTP_UPGRADE', '').lower() != 'websocket' or client is None:
            return self.wsgi_app(environ, start_response)

        host_header = environ.get('HTTP_HOST', '')
        host = host_header.split(':')[0]
        scheme = environ['wsgi.url_scheme']
        # RAW_URI keeps the path as the client encoded it, so it can go straight into the request line
        path = urlsplit(environ.get('RAW_URI', '/')).path.lstrip('/')
        target_url = find_target(host, path)
        # Left to Flask, whose router turns down WebSocket requests to its plain routes with a 400
        if target_url is None or (use_https and scheme == 'http' and cert_files(host)):
            return self.wsgi_app(environ, start_response)

        target = urlsplit(target_url)
        query_string = environ.get('QUERY_STRING', '')
        try:
            upstream = socket.create_connection((target.hostname, target.port or (443 if target.scheme == 'https' else 80)), timeout=10)
            if target.scheme == 'https':
                # A local service, usually with a self-signed certificate
                tls = ssl.create_default_context()
                tls.check_hostname = False
                tls.verify_mode = ssl.CERT_NONE
                upstream = tls.wrap_socket(upstream, server_hostname=target.hostname)
            upstream.settimeout(None)
        except OSError:
            return Response('Service Unreachable', status=503)(environ, start_response)

        headers = forwarded_headers(EnvironHeaders(environ), environ.get('REMOTE_ADDR', ''), scheme, host_header)
        headers['Connection'] = 'Upgrade'
        headers['Upgrade'] = environ['HTTP_UPGRADE']
        lines = [f"{environ['REQUEST_METHOD']} {target.path or '/'}{'?' + query_string if query_string else ''} HTTP/1.1",
                 f"Host: {target.netloc}"]
        lines += [f"{key}: {value}" for key, value in headers.items()]
        # The client sends nothing more until it sees the service's 101, so werkzeug hasn't buffered
        # anything past the headers and the client socket can be read directly
        client.settimeout(None)
        try:
            upstream.sendall(('\r\n'.join(lines) + '\r\n\r\n').encode('latin-1'))
        except OSError:
            upstream.close()
            return Response('Bad Gateway', status=502)(environ, start_response)

        to_upstream = threading.Thread(target=pipe, args=(client, upstream), daemon=True)
        to_upstream.start()
        pipe(upstream, client)
        to_upstream.join()
        upstream.close()
        # Werkzeug treats this as a dropped connection, so it writes nothing more to the client
        raise ConnectionResetError('WebSocket closed')

app.wsgi_app = WebSocketTunnel(app.wsgi_app)
# ======================================================================

if __name__ == '__main__':
    if(use_https):
        # Werkzeug's ssl_context would do the TLS handshake inside accept(), on the one thread that takes
        # every connection, so a single client that connects and sends nothing (port scanners do this)
        # stalls all of HTTPS. Wrapped like this, the handshake happens on the connection's own thread
        # instead, and the timeout drops connections that go quiet.
        class TimeoutHandler(WSGIRequestHandler):
            timeout = 60
        https_server = make_server('0.0.0.0', https_port, app, threaded=True, request_handler=TimeoutHandler)
        https_server.socket = https_context.wrap_socket(https_server.socket, server_side=True, do_handshake_on_connect=False)
        https_server.ssl_context = https_context  # werkzeug reads this for wsgi.url_scheme
        threading.Thread(target=https_server.serve_forever, daemon=True).start()
        print(f"HTTPS on port {https_port}, certificates from {cert_dir}")
    app.run(debug=False, port=port, host='0.0.0.0')
