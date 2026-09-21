"""Local HokieFlow UI + authentication server. Run: python3 serve.py

Account DB: runtime/hokieday.sqlite3 (ignored by Git). Campus data is fetched from BT services and VT location references.
For deployment, port accounts.py to the team's production Python framework; this
stdlib HTTP server is for local development, not an internet-facing deployment.
"""
from argparse import ArgumentParser
from collections import defaultdict, deque
from functools import partial
from http import cookies
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
from threading import Lock
import time
from urllib.parse import urlsplit, parse_qs
from hokieday import transit, dining_places
from hokieday.accounts import Accounts, AccountError, SESSION_SECONDS


class AppServer(ThreadingHTTPServer):
    def __init__(self, address, root, db_path, secure=False):
        self.accounts = Accounts(db_path)
        self.secure = secure
        self.attempts = defaultdict(deque)
        self.rate_lock = Lock()
        super().__init__(address, partial(Handler, directory=str(root)))
        port = self.server_address[1]
        self.allowed_hosts = {f'127.0.0.1:{port}', f'localhost:{port}'}


class Handler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('X-Frame-Options', 'DENY')
        super().end_headers()

    def json_response(self, status, body, cookie=None):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(payload)))
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(payload)

    def cookie(self, token='', clear=False):
        return f'hokieday_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={0 if clear else SESSION_SECONDS}' + ('; Secure' if self.server.secure else '')

    def token(self):
        jar = cookies.SimpleCookie()
        try:
            jar.load(self.headers.get('Cookie', ''))
            return jar['hokieday_session'].value if 'hokieday_session' in jar else ''
        except cookies.CookieError:
            return ''

    def check_host(self):
        if self.headers.get('Host') not in self.server.allowed_hosts:
            raise AccountError('Unrecognized host.', 403)

    def write_body(self):
        self.check_host()
        origin = self.headers.get('Origin')
        expected = ('https' if self.server.secure else 'http') + '://' + self.headers['Host']
        if origin and origin != expected:
            raise AccountError('Cross-origin writes are not allowed.', 403)
        if self.headers.get('X-HokieFlow-Request') != '1' or self.headers.get_content_type() != 'application/json':
            raise AccountError('Use the same-origin JSON API.', 403)
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 200_000:
                raise AccountError('Request is too large or empty.', 413)
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError()
            return body
        except (ValueError, UnicodeDecodeError):
            raise AccountError('Invalid JSON request.')

    def rate_limit(self):
        # Per-client throttling shared by login/register; no forwarded IP trust.
        now = time.monotonic()
        with self.server.rate_lock:
            for key in list(self.server.attempts):
                queue = self.server.attempts[key]
                while queue and queue[0] < now - 900:
                    queue.popleft()
                if not queue:
                    del self.server.attempts[key]
            queue = self.server.attempts[self.client_address[0]]
            if len(queue) >= 12:
                raise AccountError('Too many attempts. Try again in 15 minutes.', 429)
            queue.append(now)

    def do_GET(self):
        try:
            self.check_host()
            if urlsplit(self.path).path == '/api/auth/me':
                try:
                    result = self.server.accounts.session(self.token())
                except AccountError:
                    result = {'user': None}
                return self.json_response(200, result)
            if urlsplit(self.path).path in ('/api/transit/stops','/api/transit/departures'):
                try:
                    if urlsplit(self.path).path.endswith('/stops'):
                        result = transit.stops()
                    else:
                        stop = parse_qs(urlsplit(self.path).query).get('stop',[''])[0]
                        if not stop.isdigit() or len(stop)>8:
                            return self.json_response(400, {'error':'Invalid stop code.'})
                        result = transit.departures(stop)
                    return self.json_response(200,result)
                except Exception:
                    return self.json_response(503,{'error':'Transit times are temporarily unavailable.'})
            if urlsplit(self.path).path == '/api/dining/places':
                return self.json_response(200, dining_places.dining())
            if self.path.startswith('/api/'):
                return self.json_response(404, {'error':'This campus endpoint is not connected.'})
            return super().do_GET()
        except AccountError as error:
            self.json_response(error.status, {'error':str(error)})

    def do_POST(self):
        try:
            body = self.write_body()
            path = urlsplit(self.path).path
            if path in ('/api/auth/register', '/api/auth/login'):
                self.rate_limit()
                method = self.server.accounts.register if path.endswith('register') else self.server.accounts.login
                token = method(body)
                self.server.accounts.logout(self.token())
                return self.json_response(200, self.server.accounts.session(token), self.cookie(token))
            if path == '/api/auth/logout':
                self.server.accounts.logout(self.token())
                return self.json_response(200, {'user':None}, self.cookie(clear=True))
            return self.json_response(404, {'error':'Endpoint not found.'})
        except AccountError as error:
            self.json_response(error.status, {'error':str(error)})

    def do_PUT(self):
        try:
            body = self.write_body()
            if urlsplit(self.path).path != '/api/account/data':
                return self.json_response(404, {'error':'Endpoint not found.'})
            self.json_response(200, self.server.accounts.save(self.token(), body))
        except (AccountError, ValueError) as error:
            self.json_response(getattr(error, 'status', 400), {'error':str(error)})


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=3001)
    parser.add_argument('--db', default=str(Path(__file__).resolve().parent / 'runtime' / 'hokieday.sqlite3'))
    args = parser.parse_args()
    server = AppServer(('0.0.0.0', args.port), Path(__file__).resolve().parent / 'ui', args.db, secure=os.getenv('HOKIEDAY_SECURE_COOKIE') == '1')
    print(f'HokieFlow: http://127.0.0.1:{args.port}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
