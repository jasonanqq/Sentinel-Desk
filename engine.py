import ipaddress
from contextlib import contextmanager
import json
import os
import random
import re
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from parsers import normalize_windows_record

LOCK = threading.RLock()
DATABASE = Path(os.environ.get('MONITOR_DB', str(Path(__file__).resolve().parent / 'events.db')))
SOURCES = {'fortigate', 'windows', 'linux', 'application', 'cloud', 'other'}
INDEX_BY_SOURCE = {'fortigate': 'network', 'windows': 'endpoint', 'linux': 'endpoint', 'application': 'application', 'cloud': 'cloud', 'other': 'main'}
TYPE_BY_SOURCE = {'fortigate': 'fortigate:log', 'windows': 'windows:security', 'linux': 'linux:syslog', 'application': 'application:log', 'cloud': 'cloud:event', 'other': 'generic:event'}
INDEXES = {'network', 'endpoint', 'application', 'cloud', 'main'}
RULES = {
    'AUTH-001': ('Repeated failed logins', 'high'),
    'AUTH-002': ('Login success after multiple failures', 'critical'),
    'FW-001': ('Firewall deny burst', 'high'),
    'PROC-001': ('Suspicious command execution', 'critical'),
    'PRIV-001': ('Privilege change detected', 'high')
}


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


@contextmanager
def connect():
    db = sqlite3.connect(DATABASE, timeout=15)
    try:
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA journal_mode=WAL')
        with db:
            yield db
    finally:
        db.close()


def initialize():
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        is_existing = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='events_fts'").fetchone() is not None
        db.executescript('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dest_ip TEXT NOT NULL,
                username TEXT NOT NULL,
                message TEXT NOT NULL,
                details TEXT NOT NULL,
                received_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS events_timestamp_idx ON events(timestamp);
            CREATE INDEX IF NOT EXISTS events_pattern_idx ON events(event_type, src_ip, timestamp);
            CREATE INDEX IF NOT EXISTS events_source_time_idx ON events(source, timestamp DESC);
            CREATE INDEX IF NOT EXISTS events_severity_time_idx ON events(severity, timestamp DESC);
            CREATE INDEX IF NOT EXISTS events_type_time_idx ON events(event_type, timestamp DESC);
            CREATE INDEX IF NOT EXISTS events_ip_time_idx ON events(src_ip, timestamp DESC);
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                entity TEXT NOT NULL,
                summary TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                hits INTEGER NOT NULL DEFAULT 1,
                last_event_id INTEGER NOT NULL,
                FOREIGN KEY(last_event_id) REFERENCES events(id)
            );
            CREATE INDEX IF NOT EXISTS alerts_status_idx ON alerts(status, last_seen);
            CREATE INDEX IF NOT EXISTS alerts_rule_entity_idx ON alerts(rule_id, entity, status, last_seen DESC);
            CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                message, username, src_ip, dest_ip, tokenize='unicode61'
            );
            CREATE TRIGGER IF NOT EXISTS events_fts_insert AFTER INSERT ON events BEGIN
                INSERT INTO events_fts(rowid,message,username,src_ip,dest_ip)
                VALUES(new.id,new.message,new.username,new.src_ip,new.dest_ip);
            END;
            CREATE TRIGGER IF NOT EXISTS events_fts_delete AFTER DELETE ON events BEGIN
                DELETE FROM events_fts WHERE rowid=old.id;
            END;
            CREATE TRIGGER IF NOT EXISTS events_fts_update AFTER UPDATE ON events BEGIN
                DELETE FROM events_fts WHERE rowid=old.id;
                INSERT INTO events_fts(rowid,message,username,src_ip,dest_ip)
                VALUES(new.id,new.message,new.username,new.src_ip,new.dest_ip);
            END;
        ''')
        columns = {row['name'] for row in db.execute('PRAGMA table_info(events)')}
        for name in ('index_name', 'sourcetype', 'host'):
            if name not in columns:
                db.execute(f"ALTER TABLE events ADD COLUMN {name} TEXT NOT NULL DEFAULT ''")
        for source, idx in INDEX_BY_SOURCE.items():
            db.execute("UPDATE events SET index_name=? WHERE source=? AND index_name=''", (idx, source))
            db.execute("UPDATE events SET sourcetype=? WHERE source=? AND sourcetype=''", (TYPE_BY_SOURCE[source], source))
        db.execute("UPDATE events SET index_name='main' WHERE index_name='' ")
        db.execute("UPDATE events SET sourcetype='generic:event' WHERE sourcetype='' ")
        db.execute('CREATE INDEX IF NOT EXISTS events_index_time_idx ON events(index_name, timestamp DESC)')
        db.execute('CREATE INDEX IF NOT EXISTS events_sourcetype_time_idx ON events(sourcetype, timestamp DESC)')
        db.execute('CREATE INDEX IF NOT EXISTS events_host_time_idx ON events(host, timestamp DESC)')
        db.execute('''CREATE TABLE IF NOT EXISTS saved_searches (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE,
          query TEXT NOT NULL,
          created_at TEXT NOT NULL
        )''')
        if not is_existing:
            db.execute('''INSERT INTO events_fts(rowid,message,username,src_ip,dest_ip)
                SELECT id,message,username,src_ip,dest_ip FROM events e
                WHERE NOT EXISTS (SELECT 1 FROM events_fts f WHERE f.rowid=e.id)''')


def clean_text(value, max_length=500):
    return str(value if value is not None else '').strip()[:max_length]


def normalize(raw):
    if not isinstance(raw, dict):
        raise ValueError('Each event must be a JSON object')
    raw = normalize_windows_record(raw)
    event_type = clean_text(raw.get('event_type'), 60).lower()
    if not event_type:
        raise ValueError('event_type is required')
    source = clean_text(raw.get('source', 'other'), 30).lower()
    if source not in SOURCES:
        source = 'other'
    severity = clean_text(raw.get('severity', 'info'), 20).lower()
    if severity not in {'info', 'low', 'medium', 'high', 'critical'}:
        severity = 'info'
    timestamp = raw.get('timestamp') or now_iso()
    try:
        instant = datetime.fromisoformat(str(timestamp).replace('Z', '+00:00'))
        if instant.tzinfo is None:
            instant = instant.replace(tzinfo=timezone.utc)
        timestamp = instant.astimezone(timezone.utc).isoformat(timespec='seconds')
    except (TypeError, ValueError) as exc:
        raise ValueError('timestamp must be a valid ISO 8601 date') from exc
    ips = []
    for field in ('src_ip', 'dest_ip'):
        ip = clean_text(raw.get(field), 45)
        if ip:
            try:
                ipaddress.ip_address(ip)
            except ValueError as exc:
                raise ValueError(f'{field} must be a valid IP address') from exc
        ips.append(ip)
    details = raw.get('details', {})
    if not isinstance(details, dict):
        raise ValueError('details must be a JSON object')
    details_json = json.dumps(details, ensure_ascii=False)
    if len(details_json) > 4000:
        raise ValueError('details exceeds 4000 characters')
    return (timestamp, source, event_type, severity, ips[0], ips[1],
            clean_text(raw.get('username'), 100), clean_text(raw.get('message'), 900),
            details_json, now_iso())


def search_metadata(raw, event):
    source = event[1]
    idx = clean_text(raw.get('index', INDEX_BY_SOURCE[source]), 30).lower() if isinstance(raw, dict) else INDEX_BY_SOURCE[source]
    if idx not in INDEXES:
        raise ValueError('index must be network, endpoint, application, cloud or main')
    sourcetype = clean_text(raw.get('sourcetype', TYPE_BY_SOURCE[source]), 80) if isinstance(raw, dict) else TYPE_BY_SOURCE[source]
    host = clean_text(raw.get('host', ''), 100) if isinstance(raw, dict) else ''
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,80}', sourcetype):
        raise ValueError('sourcetype contains unsupported characters')
    if host and not re.fullmatch(r'[A-Za-z0-9_.:-]{1,100}', host):
        raise ValueError('host contains unsupported characters')
    return idx, sourcetype, host


def record_alert(db, rule_id, entity, summary, timestamp, event_id):
    title, severity = RULES[rule_id]
    cutoff = (datetime.fromisoformat(timestamp) - timedelta(minutes=10)).isoformat(timespec='seconds')
    previous = db.execute('''SELECT id, hits FROM alerts
        WHERE rule_id=? AND entity=? AND status='open' AND last_seen>=?
        ORDER BY last_seen DESC LIMIT 1''', (rule_id, entity, cutoff)).fetchone()
    if previous:
        db.execute('''UPDATE alerts SET last_seen=?, last_event_id=?, hits=hits+1, summary=?
            WHERE id=?''', (timestamp, event_id, summary, previous['id']))
    else:
        db.execute('''INSERT INTO alerts
            (rule_id,title,severity,entity,summary,first_seen,last_seen,last_event_id)
            VALUES (?,?,?,?,?,?,?,?)''',
            (rule_id, title, severity, entity, summary, timestamp, timestamp, event_id))


def detect(db, event, event_id):
    timestamp, source, kind, severity, ip, destination, username, message, details, received = event[:10]
    instant = datetime.fromisoformat(timestamp)
    if kind in {'login_failed', 'login_success'} and ip:
        since = (instant - timedelta(minutes=10)).isoformat(timespec='seconds')
        failures = db.execute('''SELECT COUNT(*) FROM events WHERE event_type='login_failed'
            AND src_ip=? AND timestamp BETWEEN ? AND ?''', (ip, since, timestamp)).fetchone()[0]
        if kind == 'login_failed' and failures >= 5:
            record_alert(db, 'AUTH-001', ip, f'{failures} failed sign-ins from {ip} in 10 minutes', timestamp, event_id)
        if kind == 'login_success' and failures >= 3:
            record_alert(db, 'AUTH-002', ip, f'Successful sign-in for {username or "unknown user"} after {failures} failures', timestamp, event_id)
    if kind == 'firewall_deny' and ip:
        since = (instant - timedelta(minutes=5)).isoformat(timespec='seconds')
        total = db.execute('''SELECT COUNT(*) FROM events WHERE event_type='firewall_deny'
            AND src_ip=? AND timestamp BETWEEN ? AND ?''', (ip, since, timestamp)).fetchone()[0]
        if total >= 8:
            record_alert(db, 'FW-001', ip, f'{total} firewall denies from {ip} in 5 minutes', timestamp, event_id)
    if kind == 'process_start':
        command = f'{message} {details}'.lower()
        indicators = ('-encodedcommand', '-enc ', 'downloadstring', 'frombase64string',
                      'invoke-expression', 'certutil -urlcache')
        if any(indicator in command for indicator in indicators):
            record_alert(db, 'PROC-001', ip or username or source,
                         f'Potentially suspicious command on {source}: {message[:130]}', timestamp, event_id)
    if kind == 'privilege_change':
        record_alert(db, 'PRIV-001', username or ip or source,
                     f'Privilege or group membership change: {message[:160]}', timestamp, event_id)


def ingest(raw):
    event = normalize(raw)
    metadata = search_metadata(raw, event)
    with LOCK, connect() as db:
        cursor = db.execute('''INSERT INTO events
            (timestamp,source,event_type,severity,src_ip,dest_ip,username,message,details,received_at,index_name,sourcetype,host)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''', event + metadata)
        detect(db, event, cursor.lastrowid)
        return cursor.lastrowid


def ingest_batch(items):
    if not isinstance(items, list) or not 1 <= len(items) <= 2000:
        raise ValueError('Provide an events array with 1 to 2000 entries')
    normalized = sorted(((normalize(item), item) for item in items), key=lambda pair: pair[0][0])
    with LOCK, connect() as db:
        ids = []
        for event, raw in normalized:
            metadata = search_metadata(raw, event)
            cursor = db.execute('''INSERT INTO events
                (timestamp,source,event_type,severity,src_ip,dest_ip,username,message,details,received_at,index_name,sourcetype,host)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''', event + metadata)
            detect(db, event, cursor.lastrowid)
            ids.append(cursor.lastrowid)
        return ids


def parse_window(start='', end=''):
    def parse(value, label):
        if not value:
            return ''
        if not isinstance(value, str) or len(value) > 40:
            raise ValueError(f'{label} must be an ISO 8601 timestamp')
        try:
            instant = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError as exc:
            raise ValueError(f'{label} must be an ISO 8601 timestamp') from exc
        if instant.tzinfo is None:
            raise ValueError(f'{label} needs a timezone offset')
        return instant.astimezone(timezone.utc).isoformat(timespec='seconds')
    start, end = parse(start, 'from'), parse(end, 'to')
    if start and end and start >= end:
        raise ValueError('Start date must be before end date')
    return start, end


def window_sql(column, start='', end=''):
    start, end = parse_window(start, end)
    conditions, values = [], []
    if start:
        conditions.append(f'{column} >= ?')
        values.append(start)
    if end:
        conditions.append(f'{column} < ?')
        values.append(end)
    return conditions, values


def full_text_query(query):
    value = str(query).strip()[:100]
    tokens = re.findall(r'\w+', value, flags=re.UNICODE)[:12]
    if not tokens:
        return '"__no_match_token__"'
    if any(character in value for character in '.:@-/'):
        return '"' + ' '.join(tokens) + '"'
    return ' AND '.join('"' + token + '"*' for token in tokens)


def event_filters(query='', source='', severity='', event_type='', start='', end=''):
    conditions, args = window_sql('timestamp', start, end)
    if query:
        conditions.append('id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)')
        args.append(full_text_query(query))
    if source in SOURCES:
        conditions.append('source=?')
        args.append(source)
    if severity in {'info', 'low', 'medium', 'high', 'critical'}:
        conditions.append('severity=?')
        args.append(severity)
    if event_type:
        conditions.append('event_type=?')
        args.append(event_type[:60])
    return (' WHERE ' + ' AND '.join(conditions)) if conditions else '', args


def alert_filters(status='all', start='', end=''):
    conditions, args = window_sql('last_seen', start, end)
    if status in {'open', 'closed'}:
        conditions.append('status=?')
        args.append(status)
    return (' WHERE ' + ' AND '.join(conditions)) if conditions else '', args


def events_page(query='', source='', severity='', event_type='', page=1, size=30, start='', end=''):
    page = max(1, int(page))
    size = min(100, max(1, int(size)))
    where, args = event_filters(query, source, severity, event_type, start, end)
    with connect() as db:
        total = db.execute('SELECT COUNT(*) FROM events' + where, args).fetchone()[0]
        rows = db.execute('SELECT * FROM events' + where + ' ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?',
                          args + [size, (page - 1) * size]).fetchall()
        return {'items': [dict(row) for row in rows], 'total': total, 'page': page, 'size': size}


def alerts_list(status='all', start='', end=''):
    where, args = alert_filters(status, start, end)
    with connect() as db:
        return [dict(row) for row in db.execute('SELECT * FROM alerts' + where + ' ORDER BY last_seen DESC LIMIT 300', args)]


def update_alert(alert_id, status):
    if status not in {'open', 'closed'}:
        raise ValueError('status must be open or closed')
    with LOCK, connect() as db:
        result = db.execute('UPDATE alerts SET status=? WHERE id=?', (status, int(alert_id)))
        return result.rowcount > 0


def statistics(start='', end=''):
    start, end = parse_window(start, end)
    where, args = event_filters(start=start, end=end)
    alert_where, alert_args = alert_filters(start=start, end=end)
    with connect() as db:
        total = db.execute('SELECT COUNT(*) FROM events' + where, args).fetchone()[0]
        denies_where = where + (' AND ' if where else ' WHERE ') + "event_type='firewall_deny'"
        denied = db.execute('SELECT COUNT(*) FROM events' + denies_where, args).fetchone()[0]
        open_cond = alert_where + (' AND ' if alert_where else ' WHERE ') + "status='open'"
        open_alerts = db.execute('SELECT COUNT(*) FROM alerts' + open_cond, alert_args).fetchone()[0]
        critical = db.execute('SELECT COUNT(*) FROM alerts' + open_cond + " AND severity='critical'", alert_args).fetchone()[0]
        sources = [dict(row) for row in db.execute('SELECT source AS label, COUNT(*) AS value FROM events' + where + ' GROUP BY source ORDER BY value DESC', args)]
        types = [dict(row) for row in db.execute('SELECT event_type AS label, COUNT(*) AS value FROM events' + where + ' GROUP BY event_type ORDER BY value DESC LIMIT 6', args)]
        earliest = db.execute('SELECT MIN(timestamp), MAX(timestamp) FROM events' + where, args).fetchone()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        end_time = datetime.fromisoformat(end) if end else max(now, datetime.fromisoformat(earliest[1]) + timedelta(seconds=1)) if earliest[1] else now
        start_time = datetime.fromisoformat(start) if start else (datetime.fromisoformat(earliest[0]) if earliest[0] else end_time - timedelta(hours=24))
        if start_time >= end_time:
            start_time = end_time - timedelta(hours=1)
        seconds = (end_time - start_time).total_seconds()
        if seconds <= 48 * 3600:
            bucket = 3600
        elif seconds <= 10 * 86400:
            bucket = 6 * 3600
        elif seconds <= 90 * 86400:
            bucket = 86400
        elif seconds <= 3 * 365 * 86400:
            bucket = 7 * 86400
        else:
            bucket = max(86400, int(seconds / 48))
        bucket = max(bucket, int(seconds / 60) + 1)
        count = max(1, int((seconds + bucket - 1) // bucket))
        bins = [{'from': (start_time + timedelta(seconds=i * bucket)).isoformat(timespec='seconds'),
                 'to': min(end_time, start_time + timedelta(seconds=(i + 1) * bucket)).isoformat(timespec='seconds'),
                 'count': 0, 'denied': 0, 'failed': 0} for i in range(count)]
        rows = db.execute('SELECT timestamp,event_type FROM events' + where, args)
        for row in rows:
            index = int((datetime.fromisoformat(row['timestamp']) - start_time).total_seconds() // bucket)
            if 0 <= index < count:
                bins[index]['count'] += 1
                if row['event_type'] == 'firewall_deny':
                    bins[index]['denied'] += 1
                if row['event_type'] == 'login_failed':
                    bins[index]['failed'] += 1
        for item in bins:
            stamp = datetime.fromisoformat(item['from'])
            item['hour'] = stamp.strftime('%H:%M') if seconds <= 48 * 3600 else stamp.strftime('%d %b %H:%M') if seconds <= 10 * 86400 else stamp.strftime('%d %b')
        return {'total': total, 'last24': total, 'denied': denied, 'open_alerts': open_alerts,
                'critical': critical, 'sources': sources, 'types': types, 'timeline': bins,
                'range': {'from': start, 'to': end}}


def csv_rows(kind, query='', source='', severity='', event_type='', status='all', start='', end=''):
    with connect() as db:
        if kind == 'alerts':
            columns = ['id', 'rule_id', 'title', 'severity', 'status', 'entity', 'summary', 'first_seen', 'last_seen', 'hits']
            where, args = alert_filters(status, start, end)
            rows = db.execute('SELECT ' + ','.join(columns) + ' FROM alerts' + where + ' ORDER BY last_seen DESC', args).fetchall()
        else:
            columns = ['id', 'timestamp', 'source', 'event_type', 'severity', 'src_ip', 'dest_ip', 'username', 'message']
            where, args = event_filters(query, source, severity, event_type, start, end)
            rows = db.execute('SELECT ' + ','.join(columns) + ' FROM events' + where + ' ORDER BY timestamp DESC', args).fetchall()
        return columns, [tuple(row) for row in rows]


def index_status():
    with connect() as db:
        events = db.execute('SELECT COUNT(*) AS count, MAX(received_at) AS newest FROM events').fetchone()
        indexed = db.execute('SELECT COUNT(*) FROM events_fts').fetchone()[0]
        return {'events': events['count'], 'indexed': indexed,
                'synced': events['count'] == indexed,
                'last_ingested': events['newest'], 'engine': 'SQLite FTS5'}


def rebuild_index():
    with LOCK, connect() as db:
        db.execute('DELETE FROM events_fts')
        db.execute('''INSERT INTO events_fts(rowid,message,username,src_ip,dest_ip)
            SELECT id,message,username,src_ip,dest_ip FROM events''')
    return index_status()


def reset():
    with LOCK, connect() as db:
        db.execute('DELETE FROM alerts')
        db.execute('DELETE FROM events')


def demo_events():
    rng = random.Random(81)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    events = []
    ips = ['10.0.8.21', '10.0.8.34', '10.0.8.65', '192.168.10.12', '203.0.113.24']
    names = ['sarah', 'daniel', 'admin', 'service_account', 'jason']
    for i in range(130):
        stamp = now - timedelta(minutes=rng.randrange(5, 1400))
        source = rng.choice(['fortigate', 'windows', 'linux', 'application'])
        kind = rng.choice(['login_success', 'login_failed', 'firewall_allow', 'firewall_deny', 'file_access'])
        events.append({'timestamp': stamp.isoformat(), 'source': source, 'event_type': kind,
                       'severity': 'medium' if kind in {'login_failed', 'firewall_deny'} else 'info',
                       'src_ip': rng.choice(ips), 'dest_ip': '10.0.1.10',
                       'username': rng.choice(names), 'message': kind.replace('_', ' ').capitalize(),
                       'details': {'environment': 'demo'}})
    attacker = '198.51.100.77'
    for i in range(8):
        events.append({'timestamp': (now - timedelta(minutes=25 - i)).isoformat(), 'source': 'windows',
                       'event_type': 'login_failed', 'severity': 'medium', 'src_ip': attacker,
                       'username': 'admin', 'message': 'Authentication failed', 'details': {'event_id': 4625}})
    events.append({'timestamp': (now - timedelta(minutes=16)).isoformat(), 'source': 'windows',
                   'event_type': 'login_success', 'src_ip': attacker, 'username': 'admin',
                   'message': 'Authentication successful', 'details': {'event_id': 4624}})
    for i in range(11):
        events.append({'timestamp': (now - timedelta(minutes=15 - i)).isoformat(), 'source': 'fortigate',
                       'event_type': 'firewall_deny', 'severity': 'medium', 'src_ip': '203.0.113.90',
                       'dest_ip': '10.0.1.30', 'message': 'Inbound connection denied', 'details': {'service': 'SSH'}})
    events.append({'timestamp': (now - timedelta(minutes=9)).isoformat(), 'source': 'windows',
                   'event_type': 'process_start', 'severity': 'high', 'src_ip': '10.0.8.65',
                   'username': 'service_account', 'message': 'powershell.exe -EncodedCommand [redacted demo payload]',
                   'details': {'event_id': 4688}})
    events.append({'timestamp': (now - timedelta(minutes=4)).isoformat(), 'source': 'windows',
                   'event_type': 'privilege_change', 'severity': 'high', 'src_ip': '10.0.8.34',
                   'username': 'daniel', 'message': 'Account added to local administrators',
                   'details': {'event_id': 4732}})
    return sorted(events, key=lambda item: item['timestamp'])
