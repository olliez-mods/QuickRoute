from flask import Flask, request, Response, redirect
from quick_ini import QuickIni
import requests

# INI file =============================================================
if(not QuickIni.load_file("config.ini")):
    print(f"Could not load config: {QuickIni.get_last_error()}\nFalling back to default settings")
port = QuickIni.get_value("port", 80, int)
# A prefix matches whole path segments only: '/phex' matches /phex and /phex/..., not /phexfoo.
# The bare prefix (/phex) redirects to /phex/ so relative URLs in pages resolve under it.
ROUTES = QuickIni.get_all("routes")
DOMAIN_ROUTES = QuickIni.get_all("domains")
# ======================================================================

app = Flask(__name__)

# Longest first, so a nested prefix wins over a shorter one it starts with
SORTED_ROUTES = sorted(((r.strip('/'), t) for r, t in ROUTES.items()), key=lambda rt: len(rt[0]), reverse=True)

#@app.route('/')
def default_route():
    return """NOT VALID LOL"""

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(path):

    host = request.host.split(':')[0]  # strip port if present
    query_string = request.query_string.decode('utf-8')

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

    # Forward the request
    try:
        response = requests.request(
            method=request.method,
            url=target_url,
            headers={key: value for key, value in request.headers if key != 'Host'},
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
    app.run(debug=False, port=port, host='0.0.0.0')
