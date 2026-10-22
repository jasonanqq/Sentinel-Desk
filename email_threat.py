import base64
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path

import engine

MAX_EML_SIZE = 1_000_000
MAX_HEADERS = 64000
MAX_BODY = 120000
STATUSES = {'New', 'Investigating', 'Resolved', 'False Positive'}
CATEGORIES = {'Sextortion', 'Credential Phishing', 'Suspected Spoofing', 'Impersonation / Payment Fraud', 'Suspicious Email', 'No Clear Threat'}
SEVERITIES = {'Low', 'Medium', 'High', 'Critical'}

DEFAULT_WEIGHTS = {
    'spf_fail': 17, 'dkim_fail': 10, 'dkim_missing': 3, 'dmarc_fail': 24,
    'compauth_fail': 10, 'sender_mismatch': 15, 'relay_mismatch': 5,
    'sextortion_threat': 34, 'crypto_demand': 26, 'urgency': 7,
    'spyware_claim': 6, 'credentials_request': 26, 'suspicious_link': 18,
    'brand_impersonation': 10, 'auth_alignment': 14, 'payment_impersonation': 24
}


class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.output = []
        self.hidden = 0
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag in ('style', 'script', 'template', 'svg'):
            self.hidden += 1
        if tag == 'a':
            address = dict(attrs).get('href', '')
            if address and len(self.links) < 60:
                self.links.append(address[:600])

    def handle_endtag(self, tag):
        if tag in ('style', 'script', 'template', 'svg'):
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if not self.hidden and sum(map(len, self.output)) < MAX_BODY:
            self.output.append(data)


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def iso_date(value):
    if not value:
        return ''
    try:
        parsed = parsedate_to_datetime(str(value))
        if not parsed.tzinfo:
            return ''
        return parsed.astimezone(timezone.utc).isoformat(timespec='seconds')
    except (TypeError, ValueError, IndexError, OverflowError):
        return ''


def decode_field(value, limit=500):
    return str(value or '').replace('\x00', '').strip()[:limit]


def extract_ip(received):
    fallback = ''
    for line in received:
        for candidate in re.findall(r'(?<![\w])(?:\[IPv6:)?[A-Fa-f0-9:.]{3,45}(?:\])?', str(line), re.I):
            candidate = candidate.removeprefix('[IPv6:').rstrip(']')
            try:
                ip = ipaddress.ip_address(candidate)
                if ip.is_global:
                    return str(ip)
                if not fallback:
                    fallback = str(ip)
            except ValueError:
                pass
    return fallback


def find_auth(headers):
    names = ('spf', 'dkim', 'dmarc', 'compauth')
    reports = []
    results = {name: 'not_reported' for name in names}
    for header in headers:
        line = str(header)
        reports.append(line[:3000])
        for name in names:
            match = re.search(r'\b' + name + r'\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|bestguesspass)\b', line, re.I)
            if match and results[name] == 'not_reported':
                results[name] = match.group(1).lower()
    return results, reports[:30]


def text_content(message):
    chunks, links = [], []
    for part in message.walk():
        if part.is_multipart() or part.get_content_disposition() == 'attachment':
            continue
        if part.get_content_type() not in ('text/plain', 'text/html'):
            continue
        try:
            content = part.get_content()
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='replace')
            if not isinstance(content, str):
                continue
        except (LookupError, ValueError, TypeError, UnicodeError, AssertionError):
            continue
        content = content[:MAX_BODY]
        if part.get_content_type() == 'text/html':
            parser = TextExtractor()
            try:
                parser.feed(content)
                content = ' '.join(parser.output)
                links.extend(parser.links)
            except (ValueError, OverflowError):
                continue
            if any(p.get_content_type() == 'text/plain' for p in message.walk()):
                continue
        chunks.append(content)
        if sum(map(len, chunks)) >= MAX_BODY:
            break
    return ('\n'.join(chunks))[:MAX_BODY], links[:60]


def parse_email(data, header_only=False):
    if not isinstance(data, bytes) or not data or len(data) > MAX_EML_SIZE:
        raise ValueError('Email input must be between 1 byte and 1 MB')
    if header_only:
        data = data.split(b'\r\n\r\n', 1)[0].split(b'\n\n', 1)[0] + b'\r\n\r\n'
    message = BytesParser(policy=policy.default.clone(raise_on_defect=False)).parsebytes(data)
    header_lines = data.split(b'\r\n\r\n', 1)[0].split(b'\n\n', 1)[0]
    raw_headers = header_lines.decode('utf-8', errors='replace')[:MAX_HEADERS]
    from_addresses = getaddresses([str(v) for v in message.get_all('from', [])])
    to_addresses = getaddresses([str(v) for v in message.get_all('to', [])])
    sender = next((addr.lower() for _, addr in from_addresses if '@' in addr), '')[:254]
    recipient = ', '.join(addr.lower() for _, addr in to_addresses if '@' in addr)[:1500]
    domain = sender.rsplit('@', 1)[-1] if '@' in sender else ''
    received = [decode_field(v, 3500) for v in message.get_all('received', [])][:25]
    auth, reports = find_auth(message.get_all('authentication-results', []) + message.get_all('arc-authentication-results', []))
    for spf_header in message.get_all('received-spf', []):
        line = str(spf_header)
        reports.append('Received-SPF: ' + line[:3000])
        if auth['spf'] == 'not_reported':
            check = re.match(r'\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b', line, re.I)
            if check:
                auth['spf'] = check.group(1).lower()
    sender_ip = ''
    for line in reports:
        match = re.search(r'\b(?:client-ip|sender-ip)\s*=\s*\[?([a-f0-9:.]+)\]?', line, re.I)
        if match:
            try:
                sender_ip = str(ipaddress.ip_address(match.group(1)))
                break
            except ValueError:
                pass
    sender_ip = sender_ip or extract_ip(list(reversed(received)))
    helo = ''
    for line in reports + list(reversed(received)):
        match = re.search(r'\b(?:helo|ehlo)\s*[=:]\s*([a-z0-9._-]+)', line, re.I)
        if match:
            helo = match.group(1).lower()[:253]
            break
    return_path = decode_field(message.get('return-path', ''), 254)
    addresses = getaddresses([return_path])
    envelope_domain = addresses[0][1].lower().rsplit('@', 1)[-1] if addresses and '@' in addresses[0][1] else ''
    reply_addresses = getaddresses([str(message.get('reply-to', ''))])
    reply_domain = reply_addresses[0][1].lower().rsplit('@', 1)[-1] if reply_addresses and '@' in reply_addresses[0][1] else ''
    content, links = ('', []) if header_only else text_content(message)
    urls = re.findall(r'https?://[^\s<>"\']{4,500}', content, re.I)[:60]
    urls.extend(links)
    return {
        'sender': sender, 'recipient': recipient, 'sender_domain': domain,
        'originating_ip': sender_ip, 'helo': helo, 'envelope_domain': envelope_domain,
        'reply_domain': reply_domain, 'subject': decode_field(message.get('subject', ''), 500),
        'received_at': iso_date(message.get('date')), 'authentication': auth,
        'auth_reports': reports, 'routing': received, 'raw_headers': raw_headers,
        'body': content, 'urls': list(dict.fromkeys(urls))[:70],
        'message_id': decode_field(message.get('message-id', ''), 500),
        'header_defects': [type(d).__name__ for d in message.defects][:20]
    }


def load_rules():
    filepath = Path(__file__).resolve().parent / 'email_rules.json'
    if not filepath.exists():
        return DEFAULT_WEIGHTS.copy()
    settings = json.loads(filepath.read_text(encoding='utf-8'))
    if not isinstance(settings, dict) or set(settings) != set(DEFAULT_WEIGHTS):
        raise ValueError('email_rules.json must define all supported rule weights')
    if any(type(value) is not int or value < 0 or value > 60 for value in settings.values()):
        raise ValueError('Email rule weights must be integers between 0 and 60')
    return settings


def add_indicators(metadata, weights=None):
    weights = weights if weights is not None else load_rules()
    evidence = []
    auth = metadata['authentication']

    def emit(key, title, detail, kind='Reported header / unverified'):
        evidence.append({'rule': key, 'title': title, 'explanation': detail, 'points': max(0, int(weights.get(key, 0))), 'basis': kind})

    for name in ('spf', 'dkim', 'dmarc', 'compauth'):
        result = auth[name]
        if result in ('fail', 'softfail', 'permerror'):
            key = name + '_fail'
            emit(key, name.upper() + ' reported ' + result.upper(), f'The supplied message reports {name.upper()}={result}. Authentication-Results headers can be forged in a standalone .eml; verify at the receiving mail provider.', 'Reported authentication result / not independently verified')
        elif name == 'dkim' and result in ('none', 'not_reported'):
            emit('dkim_missing', 'No verified DKIM signature', 'DKIM authentication is missing or not reported; this alone does not establish malicious intent.', 'Reported or missing header')
    sender = metadata['sender_domain']
    envelope = metadata['envelope_domain']
    reply = metadata['reply_domain']
    if sender and (envelope and sender != envelope or reply and reply != sender):
        emit('sender_mismatch', 'Sender domain alignment mismatch', f'Visible From domain {sender} differs from Return-Path ({envelope or "missing"}) or Reply-To ({reply or "missing"}). Legitimate senders sometimes use third-party services.', 'Static header comparison')
    helo = metadata['helo']
    if helo and sender and not (helo == sender or helo.endswith('.' + sender)):
        emit('relay_mismatch', 'Different SMTP host identity', f'The SMTP HELO host ({helo}) differs from the displayed sender domain ({sender}); this can be normal for relays, so treat it as context.', 'Static header comparison')

    text = (metadata['subject'] + '\n' + metadata['body']).lower()
    threat = bool(re.search(r'\b(?:expose|publish|release|send|share|leak)\b.{0,95}\b(?:video|footage|pictures|photos|recordings|contacts|family|friends)\b|\b(?:intimate|private|explicit|adult)\b.{0,75}\b(?:video|footage|pictures|photos)\b', text, re.S))
    payment = bool(re.search(r'\b(?:pay|payment|send|transfer|deposit|wire)\b.{0,70}(?:\$\s?\d+|\b(?:usd|dollars?|money|cash|wallet|bitcoin|litecoin|monero|ethereum|crypto)\b)|(?:\$\s?\d+|\b(?:usd|dollars?|money|cash|wallet|bitcoin|litecoin|monero|ethereum|crypto)\b).{0,70}\b(?:pay|payment|send|transfer|deposit|wire)\b', text, re.S))
    demand = bool(re.search(r'\b(?:bitcoin|litecoin|monero|ethereum|usdt|crypto(?:currency)?|btc|ltc)\b', text)) and payment
    urgency = bool(re.search(r'\b(?:within\s+\d+\s*(?:hours?|days?)|\d+\s*(?:hours?|days?)\s*(?:left|to pay)|immediately|last chance|final warning|urgent|deadline)\b', text))
    spyware = bool(re.search(r'\b(?:pegasus|spyware|keylogger|remote access|infected your device|installed.{0,30}(?:trojan|malware))\b', text))
    credentials = bool(re.search(r'\b(?:verify|confirm|enter|submit|update|reset|provide|share)\b.{0,75}\b(?:password|login credentials|account details|otp|one.time password|security code|sign.in|log.in)\b', text, re.S))
    targets = []
    for url in metadata['urls']:
        if re.match(r'https?://', url, re.I):
            targets.append(url)
    suspicious_link = bool(targets and (credentials or re.search(r'\b(?:click|open|visit|sign in|verify|login)\b.{0,50}\b(?:link|here|account|page|portal)\b', text, re.S)))
    brand = bool(re.search(r'\b(?:microsoft|office\s*365|outlook|paypal|bank(?:ing)?|helpdesk|it support|administrator)\b', text)) and credentials
    claimed_authority = bool(re.search(r'\b(?:this is (?:your|the) (?:ceo|director|manager|boss)|i am (?:your|the) (?:ceo|director|manager)|speaking as (?:your|the) (?:ceo|director))\b', text))
    wire_request = bool(re.search(r'\b(?:wire transfer|bank transfer|send (?:funds|money)|transfer (?:funds|money)|pay (?:the|this) invoice)\b', text))

    if threat:
        emit('sextortion_threat', 'Intimidation involving private material', 'The content threatens to distribute personal or intimate material. This is consistent with sextortion tactics.', 'Static content analysis')
    if demand:
        emit('crypto_demand', 'Cryptocurrency payment demand', 'The text includes cryptocurrency and a request to pay or transfer funds, a common extortion indicator.', 'Static content analysis')
    if urgency:
        emit('urgency', 'Urgent deadline or pressure', 'Time pressure is used to encourage compliance before the recipient verifies the message.', 'Static content analysis')
    if spyware:
        emit('spyware_claim', 'Claim of spyware or device access', 'The sender claims surveillance, spyware or malware. This is an unverified allegation, not proof of infection.', 'Unverified sender claim')
    if credentials:
        emit('credentials_request', 'Request for credentials', 'The message requests authentication details or account verification, a credential-phishing indicator.', 'Static content analysis')
    if suspicious_link:
        emit('suspicious_link', 'Account-action link', f'The message urges a recipient to use an embedded link; {len(targets)} URL(s) were identified but not opened or reputation-checked.', 'Static URL extraction / no reputation check')
    if claimed_authority and wire_request:
        emit('payment_impersonation', 'Executive identity and payment request', 'The message claims senior organisational authority and requests a payment or transfer. The claimed identity is unverified.', 'Static content analysis / unverified identity')
    if brand:
        emit('brand_impersonation', 'Possible organisational impersonation', 'The message invokes a common provider or institution while asking for credentials; the brand identity is not independently verified.', 'Static content analysis')
    if sender and auth['dmarc'] == 'fail' and (auth['spf'] in ('fail', 'softfail') or auth['dkim'] == 'fail'):
        emit('auth_alignment', 'Multiple authentication checks failed', 'Combined SPF/DKIM and DMARC failures increase confidence in suspected sender spoofing, but the supplied results remain unverified.', 'Correlation of reported results')

    sextortion = threat and payment
    spoof = auth['dmarc'] == 'fail' and (auth['spf'] in ('fail', 'softfail') or auth['dkim'] == 'fail')
    credential = credentials and (suspicious_link or brand)
    categories = []
    if sextortion:
        categories.append('Sextortion')
    if claimed_authority and wire_request:
        categories.append('Impersonation / Payment Fraud')
    if credential:
        categories.append('Credential Phishing')
    if spoof:
        categories.append('Suspected Spoofing')
    if not categories:
        categories.append('Suspicious Email' if evidence and sum(v['points'] for v in evidence) >= 20 else 'No Clear Threat')
    score = min(100, sum(item['points'] for item in evidence))
    severity = 'Critical' if score >= 75 else 'High' if score >= 45 else 'Medium' if score >= 20 else 'Low'
    return {'score': score, 'severity': severity, 'categories': categories, 'primary_category': categories[0], 'evidence': evidence,
            'assessment_note': 'Static analysis of user-supplied, potentially forged email content. Authentication headers, server identity, timestamps and IP attribution are unverified. No live DNS, URL visits, malware execution or external reputation checks were performed.'}


def initialize():
    with engine.LOCK, engine.connect() as db:
        db.executescript('''
            CREATE TABLE IF NOT EXISTS email_investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                digest TEXT NOT NULL UNIQUE,
                sender TEXT NOT NULL, recipient TEXT NOT NULL, sender_domain TEXT NOT NULL,
                originating_ip TEXT NOT NULL, helo TEXT NOT NULL, envelope_domain TEXT NOT NULL,
                reply_domain TEXT NOT NULL, subject TEXT NOT NULL, received_at TEXT NOT NULL,
                analysed_at TEXT NOT NULL, score INTEGER NOT NULL, severity TEXT NOT NULL,
                primary_category TEXT NOT NULL, categories_json TEXT NOT NULL,
                auth_json TEXT NOT NULL, evidence_json TEXT NOT NULL, routing_json TEXT NOT NULL,
                auth_reports_json TEXT NOT NULL, raw_headers TEXT NOT NULL, body_excerpt TEXT NOT NULL,
                urls_json TEXT NOT NULL, message_id TEXT NOT NULL, defects_json TEXT NOT NULL,
                assessment_note TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'New'
            );
            CREATE INDEX IF NOT EXISTS email_analysed_idx ON email_investigations(analysed_at DESC);
            CREATE INDEX IF NOT EXISTS email_received_idx ON email_investigations(received_at DESC);
            CREATE INDEX IF NOT EXISTS email_sender_idx ON email_investigations(sender, analysed_at DESC);
            CREATE INDEX IF NOT EXISTS email_ip_idx ON email_investigations(originating_ip, analysed_at DESC);
            CREATE INDEX IF NOT EXISTS email_category_idx ON email_investigations(primary_category, analysed_at DESC);
            CREATE INDEX IF NOT EXISTS email_severity_idx ON email_investigations(severity, analysed_at DESC);
            CREATE INDEX IF NOT EXISTS email_status_idx ON email_investigations(status, analysed_at DESC);
            CREATE TABLE IF NOT EXISTS email_categories (
                investigation_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                PRIMARY KEY(investigation_id, category),
                FOREIGN KEY(investigation_id) REFERENCES email_investigations(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS email_categories_lookup ON email_categories(category, investigation_id);
            CREATE VIRTUAL TABLE IF NOT EXISTS email_fts USING fts5(sender,subject,originating_ip,body_excerpt, tokenize='unicode61');
            CREATE TRIGGER IF NOT EXISTS email_fts_insert AFTER INSERT ON email_investigations BEGIN
                INSERT INTO email_fts(rowid,sender,subject,originating_ip,body_excerpt) VALUES(new.id,new.sender,new.subject,new.originating_ip,new.body_excerpt);
            END;
            CREATE TRIGGER IF NOT EXISTS email_fts_delete AFTER DELETE ON email_investigations BEGIN
                DELETE FROM email_fts WHERE rowid=old.id;
            END;
        ''')
        if db.execute('SELECT COUNT(*) FROM email_fts').fetchone()[0] != db.execute('SELECT COUNT(*) FROM email_investigations').fetchone()[0]:
            db.execute('DELETE FROM email_fts')
            db.execute('INSERT INTO email_fts(rowid,sender,subject,originating_ip,body_excerpt) SELECT id,sender,subject,originating_ip,body_excerpt FROM email_investigations')
        old = db.execute('SELECT id,categories_json FROM email_investigations').fetchall()
        for item in old:
            for category in json.loads(item['categories_json']):
                db.execute('INSERT OR IGNORE INTO email_categories(investigation_id,category) VALUES (?,?)', (item['id'], category))


def analyse(data, header_only=False):
    if not isinstance(data, bytes) or not data or len(data) > MAX_EML_SIZE:
        raise ValueError('Email must be between 1 byte and 1 MB')
    digest = hashlib.sha256(data.replace(b'\r\n', b'\n').strip()).hexdigest()
    with engine.LOCK, engine.connect() as db:
        existing = db.execute('SELECT id FROM email_investigations WHERE digest=?', (digest,)).fetchone()
        if existing:
            return {'id': existing['id'], 'duplicate': True, 'investigation': get_investigation(existing['id'])}
    metadata = parse_email(data, header_only)
    assessment = add_indicators(metadata)
    fields = {
        'digest': digest, 'sender': metadata['sender'], 'recipient': metadata['recipient'], 'sender_domain': metadata['sender_domain'],
        'originating_ip': metadata['originating_ip'], 'helo': metadata['helo'], 'envelope_domain': metadata['envelope_domain'],
        'reply_domain': metadata['reply_domain'], 'subject': metadata['subject'], 'received_at': metadata['received_at'],
        'analysed_at': now(), 'score': assessment['score'], 'severity': assessment['severity'],
        'primary_category': assessment['primary_category'], 'categories_json': json.dumps(assessment['categories']),
        'auth_json': json.dumps(metadata['authentication']), 'evidence_json': json.dumps(assessment['evidence']),
        'routing_json': json.dumps(metadata['routing']), 'auth_reports_json': json.dumps(metadata['auth_reports']),
        'raw_headers': metadata['raw_headers'], 'body_excerpt': metadata['body'][:4000], 'urls_json': json.dumps(metadata['urls']),
        'message_id': metadata['message_id'], 'defects_json': json.dumps(metadata['header_defects']),
        'assessment_note': assessment['assessment_note']
    }
    with engine.LOCK, engine.connect() as db:
        keys = list(fields)
        cursor = db.execute('INSERT OR IGNORE INTO email_investigations (' + ','.join(keys) + ') VALUES (' + ','.join('?' for _ in keys) + ')', list(fields.values()))
        unique_id = cursor.lastrowid if cursor.rowcount else db.execute('SELECT id FROM email_investigations WHERE digest=?', (digest,)).fetchone()['id']
        inserted = cursor.rowcount > 0
        if inserted:
            db.executemany('INSERT OR IGNORE INTO email_categories(investigation_id,category) VALUES (?,?)', [(unique_id, category) for category in assessment['categories']])
    return {'id': unique_id, 'duplicate': not inserted, 'investigation': get_investigation(unique_id)}


def deserialize(row):
    data = dict(row)
    for key in ('categories', 'auth', 'evidence', 'routing', 'auth_reports', 'urls', 'defects'):
        data[key] = json.loads(data.pop({'categories': 'categories_json', 'auth': 'auth_json', 'evidence': 'evidence_json', 'routing': 'routing_json', 'auth_reports': 'auth_reports_json', 'urls': 'urls_json', 'defects': 'defects_json'}[key]))
    data.pop('digest', None)
    return data


def get_investigation(id):
    with engine.connect() as db:
        row = db.execute('SELECT * FROM email_investigations WHERE id=?', (int(id),)).fetchone()
        return deserialize(row) if row else None


def filters(q='', sender='', ip='', category='', severity='', status='', start='', end='', date_field='analysed_at'):
    if date_field not in ('analysed_at', 'received_at'):
        raise ValueError('Invalid date filter field')
    clauses, args = engine.window_sql(date_field, start, end)
    if q:
        clauses.append('id IN (SELECT rowid FROM email_fts WHERE email_fts MATCH ?)')
        args.append(engine.full_text_query(q))
    if sender:
        clauses.append('sender LIKE ? ESCAPE "\\"')
        args.append('%' + sender[:254].replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%')
    if ip:
        clauses.append('originating_ip=?')
        args.append(ip[:45])
    if category in CATEGORIES:
        clauses.append('id IN (SELECT investigation_id FROM email_categories WHERE category=?)')
        args.append(category)
    if severity in SEVERITIES:
        clauses.append('severity=?')
        args.append(severity)
    if status in STATUSES:
        clauses.append('status=?')
        args.append(status)
    return (' WHERE ' + ' AND '.join(clauses)) if clauses else '', args


def investigations(q='', sender='', ip='', category='', severity='', status='', start='', end='', date_field='analysed_at', page=1, size=25):
    page = max(1, int(page))
    size = min(100, max(1, int(size)))
    where, args = filters(q, sender, ip, category, severity, status, start, end, date_field)
    with engine.connect() as db:
        total = db.execute('SELECT COUNT(*) FROM email_investigations' + where, args).fetchone()[0]
        rows = db.execute('SELECT id,sender,recipient,originating_ip,subject,received_at,analysed_at,score,severity,primary_category,categories_json,status FROM email_investigations' + where + ' ORDER BY analysed_at DESC,id DESC LIMIT ? OFFSET ?', args + [size, size * (page - 1)]).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item['categories'] = json.loads(item.pop('categories_json'))
        items.append(item)
    return {'total': total, 'items': items, 'page': page, 'size': size}


def stats(start='', end='', date_field='analysed_at'):
    where, args = filters(start=start, end=end, date_field=date_field)
    with engine.connect() as db:
        rows = db.execute('SELECT analysed_at,received_at,severity,primary_category,categories_json FROM email_investigations' + where + ' ORDER BY analysed_at ASC', args).fetchall()
    category_counts = {}
    day_counts = {}
    suspicious = high_risk = 0
    for row in rows:
        categories = json.loads(row['categories_json'])
        if any(category != 'No Clear Threat' for category in categories):
            suspicious += 1
        if row['severity'] in ('High', 'Critical'):
            high_risk += 1
        for category in categories:
            category_counts[category] = category_counts.get(category, 0) + 1
        stamp = row[date_field][:10] if row[date_field] else 'Unknown'
        day_counts[stamp] = day_counts.get(stamp, 0) + 1
    return {'total': len(rows), 'suspicious': suspicious, 'high_risk': high_risk,
            'categories': [{'name': k, 'value': v} for k,v in sorted(category_counts.items(), key=lambda x: -x[1])],
            'timeline': [{'date': k, 'value': v} for k,v in sorted(day_counts.items())]}


def update_status(identifier, status):
    if status not in STATUSES:
        raise ValueError('Invalid investigation status')
    with engine.LOCK, engine.connect() as db:
        return db.execute('UPDATE email_investigations SET status=? WHERE id=?', (status, int(identifier))).rowcount > 0


def index_status():
    with engine.connect() as db:
        total = db.execute('SELECT COUNT(*) FROM email_investigations').fetchone()[0]
        indexed = db.execute('SELECT COUNT(*) FROM email_fts').fetchone()[0]
        return {'total': total, 'indexed': indexed, 'synced': total == indexed}


def rebuild_index():
    with engine.LOCK, engine.connect() as db:
        db.execute('DELETE FROM email_fts')
        db.execute('INSERT INTO email_fts(rowid,sender,subject,originating_ip,body_excerpt) SELECT id,sender,subject,originating_ip,body_excerpt FROM email_investigations')
    return index_status()
