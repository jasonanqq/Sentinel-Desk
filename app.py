import base64
import binascii
import csv
import io
import json
import mimetypes
import os
import re
import secrets
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import engine
import email_threat
import search_lab
from collectors import CollectorManager
from parsers import parse_fortigate_line

ROOT = Path(__file__).resolve().parent
HOST = '127.0.0.1'
PORT = int(os.environ.get('MONITOR_PORT', '8765'))
KEY_FILE = ROOT / '.ingest_key'


def load_key():
    supplied = os.environ.get('MONITOR_INGEST_KEY')
    if supplied:
        return supplied
    if KEY_FILE.exists():
        return KEY_FILE.read_text(encoding='utf-8').strip()
    key = secrets.token_urlsafe(32)
    KEY_FILE.write_text(key, encoding='utf-8')
    try:
        KEY_FILE.chmod(0o600)
    except OSError:
        pass
    return key


INGEST_KEY = load_key()
COLLECTORS = CollectorManager()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stdout.write('%s %s\n' % (self.log_date_time_string(), fmt % args))

    def headers_default(self, content_type, length):
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(length))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")

    def send_bytes(self, code, body, content_type):
        self.send_response(code)
        self.headers_default(content_type, len(body))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, code, data):
        self.send_bytes(code, json.dumps(data, ensure_ascii=False).encode('utf-8'), 'application/json; charset=utf-8')

    def read_json(self):
        length = int(self.headers.get('Content-Length', '0'))
        if not 0 < length <= 2_000_000:
            raise ValueError('Request body must be between 1 byte and 2 MB')
        if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
            raise ValueError('Content-Type must be application/json')
        return json.loads(self.rfile.read(length).decode('utf-8'))

    def same_origin(self):
        origin = self.headers.get('Origin')
        if not origin:
            return True
        return origin in {f'http://127.0.0.1:{PORT}', f'http://localhost:{PORT}'}

    def trusted_host(self):
        return self.headers.get('Host', '') in {f'127.0.0.1:{PORT}', f'localhost:{PORT}'}

    def do_GET(self):
        if not self.trusted_host():
            return self.send_json(403, {'error': 'Invalid host'})
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        param = lambda name: query.get(name, [''])[0]
        start, end = param('from'), param('to')
        try:
            if path == '/api/search/run':
                return self.send_json(200, search_lab.execute(param('q'), start, end))
            if path == '/api/search/saved':
                return self.send_json(200, {'items': search_lab.list_saved()})
            if path == '/api/search/facets':
                return self.send_json(200, {'items': search_lab.facets(start, end)})
            if path == '/api/email/stats':
                return self.send_json(200, email_threat.stats(start, end, param('date_field') or 'analysed_at'))
            if path == '/api/email/investigations':
                return self.send_json(200, email_threat.investigations(
                    param('q'), param('sender'), param('ip'), param('category'), param('severity'),
                    param('status'), start, end, param('date_field') or 'analysed_at',
                    param('page') or 1, param('size') or 25))
            match = re.fullmatch(r'/api/email/investigations/(\d+)', path)
            if match:
                detail = email_threat.get_investigation(match.group(1))
                return self.send_json(200 if detail else 404, detail if detail else {'error': 'Investigation not found'})
            if path == '/api/collectors/status':
                return self.send_json(200, COLLECTORS.status())
            if path == '/api/index/status':
                return self.send_json(200, {**engine.index_status(), 'emails': email_threat.index_status()})
            if path == '/api/stats':
                return self.send_json(200, engine.statistics(start, end))
            if path == '/api/events':
                return self.send_json(200, engine.events_page(
                    param('q'), param('source'), param('severity'), param('event_type'),
                    param('page') or 1, param('size') or 30, start, end))
            if path == '/api/alerts':
                return self.send_json(200, {'items': engine.alerts_list(param('status') or 'all', start, end)})
            if path in {'/api/export/events.csv', '/api/export/alerts.csv'}:
                kind = 'alerts' if 'alerts' in path else 'events'
                columns, rows = engine.csv_rows(kind, param('q'), param('source'), param('severity'),
                                                 param('event_type'), param('status') or 'all', start, end)
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(columns)
                for row in rows:
                    writer.writerow(["'" + value if isinstance(value, str) and value[:1] in '=+-@' else value for value in row])
                return self.send_bytes(200, output.getvalue().encode('utf-8-sig'), 'text/csv; charset=utf-8')
            if path == '/':
                filepath = ROOT / 'static' / 'index.html'
            elif path.startswith('/static/') and Path(path).name in {'app.js', 'email.js', 'style.css', 'search.js'}:
                filepath = ROOT / 'static' / Path(path).name
            else:
                return self.send_json(404, {'error': 'Not found'})
            content_type = mimetypes.guess_type(filepath.name)[0] or 'application/octet-stream'
            return self.send_bytes(200, filepath.read_bytes(), content_type + '; charset=utf-8')
        except (TypeError, ValueError) as exc:
            return self.send_json(400, {'error': str(exc)})
        except Exception:
            return self.send_json(500, {'error': 'Unexpected server error'})

    def do_POST(self):
        if not self.trusted_host():
            return self.send_json(403, {'error': 'Invalid host'})
        path = urlparse(self.path).path
        if not self.same_origin():
            return self.send_json(403, {'error': 'Invalid origin'})
        try:
            if path == '/api/search/saved':
                payload = self.read_json()
                if not isinstance(payload, dict):
                    raise ValueError('Invalid saved search')
                return self.send_json(201, {'items': search_lab.save(payload.get('name'), payload.get('query'))})
            if path == '/api/search/saved/delete':
                payload = self.read_json()
                if not isinstance(payload, dict):
                    raise ValueError('Invalid saved search ID')
                return self.send_json(200, {'deleted': search_lab.remove(payload.get('id'))})
            if path == '/api/email/analyse':
                payload = self.read_json()
                if not isinstance(payload, dict):
                    raise ValueError('Expected an email analysis object')
                if payload.get('mode') == 'eml':
                    encoded = payload.get('content', '')
                    if not isinstance(encoded, str) or len(encoded) > 1_400_000:
                        raise ValueError('Invalid .eml file size')
                    try:
                        raw = base64.b64decode(encoded, validate=True)
                    except (binascii.Error, ValueError):
                        raise ValueError('Invalid email encoding')
                    result = email_threat.analyse(raw)
                elif payload.get('mode') == 'headers':
                    headers = payload.get('content', '')
                    if not isinstance(headers, str):
                        raise ValueError('Paste email headers as text')
                    result = email_threat.analyse(headers.encode('utf-8'), header_only=True)
                else:
                    raise ValueError('Choose email file or raw headers')
                return self.send_json(200 if result['duplicate'] else 201, result)
            match = re.fullmatch(r'/api/email/investigations/(\d+)/status', path)
            if match:
                payload = self.read_json()
                if not isinstance(payload, dict):
                    raise ValueError('Expected status object')
                changed = email_threat.update_status(match.group(1), payload.get('status'))
                return self.send_json(200 if changed else 404, {'ok': changed})
            if path == '/api/collectors/test-syslog':
                if not COLLECTORS.status()['collectors']['syslog']['active']:
                    raise ValueError('Start the syslog listener first')
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(b'<189>type=traffic action=deny srcip=203.0.113.100 dstip=10.0.0.2 msg=Sentinel-Desk-collector-test', ('127.0.0.1', COLLECTORS.port))
                return self.send_json(200, {'sent': True})
            if path == '/api/collectors/start':
                payload = self.read_json()
                return self.send_json(200, COLLECTORS.start(payload.get('type')))
            if path == '/api/collectors/stop':
                payload = self.read_json()
                return self.send_json(200, COLLECTORS.stop(payload.get('type')))
            if path == '/api/index/rebuild':
                return self.send_json(200, {**engine.rebuild_index(), 'emails': email_threat.rebuild_index()})
            if path == '/api/demo':
                items = engine.demo_events()
                engine.ingest_batch(items)
                return self.send_json(201, {'inserted': len(items)})
            if path == '/api/reset':
                payload = self.read_json()
                if payload.get('confirm') != 'RESET':
                    raise ValueError('Reset confirmation is required')
                engine.reset()
                return self.send_json(200, {'ok': True})
            if path == '/api/ingest':
                provided = self.headers.get('X-Ingest-Key', '')
                if not secrets.compare_digest(provided, INGEST_KEY):
                    return self.send_json(401, {'error': 'Invalid ingest key'})
                payload = self.read_json()
                if isinstance(payload, dict) and 'fortigate_logs' in payload:
                    lines = payload['fortigate_logs']
                    if not isinstance(lines, list):
                        raise ValueError('fortigate_logs must be an array of strings')
                    ids = engine.ingest_batch([parse_fortigate_line(line) for line in lines])
                    return self.send_json(201, {'inserted': len(ids), 'ids': ids})
                if isinstance(payload, list):
                    ids = engine.ingest_batch(payload)
                    return self.send_json(201, {'inserted': len(ids), 'ids': ids})
                return self.send_json(201, {'id': engine.ingest(payload)})
            if path == '/api/import':
                payload = self.read_json()
                if not isinstance(payload, dict):
                    raise ValueError('Import must be a JSON object')
                if 'fortigate_logs' in payload:
                    lines = payload['fortigate_logs']
                    if not isinstance(lines, list):
                        raise ValueError('fortigate_logs must be an array')
                    items = [parse_fortigate_line(line) for line in lines]
                else:
                    items = payload.get('events')
                ids = engine.ingest_batch(items)
                return self.send_json(201, {'inserted': len(ids)})
            matched = re.fullmatch(r'/api/alerts/(\d+)/status', path)
            if matched:
                payload = self.read_json()
                updated = engine.update_alert(int(matched.group(1)), payload.get('status'))
                return self.send_json(200 if updated else 404, {'ok': updated})
            return self.send_json(404, {'error': 'Not found'})
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return self.send_json(400, {'error': str(exc)})
        except Exception:
            return self.send_json(500, {'error': 'Unexpected server error'})


if __name__ == '__main__':
    engine.initialize()
    email_threat.initialize()
    print(f'Open http://{HOST}:{PORT}')
    print(f'Ingest key: {INGEST_KEY}')
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        COLLECTORS.stop_all()
        server.server_close()
