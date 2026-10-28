import fnmatch
import json
import re
import shlex
from collections import Counter
from datetime import datetime, timezone

import engine

FIELDS = {'index', 'index_name', 'source', 'sourcetype', 'host', 'severity', 'event_type',
          'src_ip', 'dest_ip', 'username', 'message', 'timestamp', 'received_at', 'id', 'count'}
SQL_FIELDS = {'index': 'index_name', 'index_name': 'index_name', 'source': 'source',
              'sourcetype': 'sourcetype', 'host': 'host', 'severity': 'severity',
              'event_type': 'event_type', 'src_ip': 'src_ip', 'dest_ip': 'dest_ip',
              'username': 'username'}
FILTER = re.compile(r'^([A-Za-z_][\w.]*)(!=|>=|<=|=|>|<)(.+)$')
MAX_SCAN = 15000
MAX_QUERY = 2000


def parse_query(text):
    if not isinstance(text, str) or len(text) > MAX_QUERY:
        raise ValueError('Search query is too long')
    lexer = shlex.shlex(text, posix=True, punctuation_chars='|')
    lexer.whitespace_split = True
    lexer.commenters = ''
    try:
        tokens = list(lexer)
    except ValueError as error:
        raise ValueError(f'Invalid search syntax: {error}') from error
    segments = [[]]
    for token in tokens:
        if token == '|':
            segments.append([])
        else:
            segments[-1].append(token)
    if len(segments) > 7 or any(not segment for segment in segments[1:]):
        raise ValueError('Empty command or too many pipeline stages')
    return segments


def record_dict(row):
    result = dict(row)
    try:
        details = json.loads(result.get('details') or '{}')
    except (TypeError, ValueError):
        details = {}
    result['index'] = result.pop('index_name', 'main')
    result['details'] = details
    for key, value in details.items():
        if isinstance(key, str) and isinstance(value, (str, int, float, bool)) and key not in result:
            result[key] = value
    return result


def resolve(item, field):
    if field == '_time':
        return item.get('timestamp', '')
    if field.startswith('details.'):
        detail = item.get('details', {})
        return detail.get(field[8:], '') if isinstance(detail, dict) else ''
    return item.get(field, '')


def field_valid(field):
    return field in FIELDS or field == '_time' or re.fullmatch(r'details\.[A-Za-z][\w-]{0,60}', field)


def match_term(item, token):
    expression = FILTER.fullmatch(token)
    if expression:
        field, op, value = expression.groups()
        if not field_valid(field):
            raise ValueError(f'Unsupported field: {field}. Use index, source, sourcetype, host, severity, event_type, src_ip, username or details.key')
        actual = resolve(item, field)
        actual = str(actual if actual is not None else '')
        if value == '*' and op == '=':
            return bool(actual)
        if op in ('=', '!='):
            comparison = fnmatch.fnmatchcase(actual.casefold(), value.casefold()) if '*' in value or '?' in value else actual.casefold() == value.casefold()
            return comparison if op == '=' else not comparison
        try:
            a, b = float(actual), float(value)
        except (ValueError, TypeError):
            a, b = actual.casefold(), value.casefold()
        return {'>': lambda: a > b, '<': lambda: a < b, '>=': lambda: a >= b, '<=': lambda: a <= b}[op]()
    text = ' '.join(str(resolve(item, field) or '') for field in ('message', 'username', 'src_ip', 'dest_ip', 'event_type', 'source', 'host'))
    if '*' in token or '?' in token:
        return fnmatch.fnmatchcase(text.casefold(), f'*{token.casefold()}*')
    return token.casefold() in text.casefold()


def match_filters(item, tokens):
    if not tokens:
        return True
    groups = [[]]
    negate = False
    for token in tokens:
        if token.upper() == 'OR':
            if not groups[-1]:
                raise ValueError('OR must join two search expressions')
            groups.append([])
            negate = False
        elif token.upper() == 'AND':
            continue
        elif token.upper() == 'NOT':
            negate = True
        else:
            groups[-1].append((token, negate))
            negate = False
    if not groups[-1] or negate:
        raise ValueError('Search ends with an incomplete expression')
    return any(all((not match_term(item, word)) if neg else match_term(item, word) for word, neg in group) for group in groups)


def prefilter(terms, start, end):
    conditions, args = engine.window_sql('timestamp', start, end)
    if 'OR' in {word.upper() for word in terms} or 'NOT' in {word.upper() for word in terms}:
        return conditions, args
    for token in terms:
        match = FILTER.fullmatch(token)
        if match:
            field, op, value = match.groups()
            if field in SQL_FIELDS and op == '=' and not any(c in value for c in '*?'):
                conditions.append(f'{SQL_FIELDS[field]} = ? COLLATE NOCASE')
                args.append(value)
    return conditions, args


def validate_tokens(terms):
    for token in terms:
        match = FILTER.fullmatch(token)
        if match and not field_valid(match.group(1)):
            raise ValueError(f'Unsupported field: {match.group(1)}')


def execute(query, start='', end=''):
    segments = parse_query(query.strip())
    terms = segments[0]
    validate_tokens(terms)
    conditions, args = prefilter(terms, start, end)
    where = ' WHERE ' + ' AND '.join(conditions) if conditions else ''
    with engine.connect() as db:
        candidates = db.execute('SELECT COUNT(*) FROM events' + where, args).fetchone()[0]
        rows = db.execute('SELECT * FROM events' + where + ' ORDER BY timestamp DESC, id DESC LIMIT ?', args + [MAX_SCAN]).fetchall()
    items = [record_dict(row) for row in rows]
    filtered = [item for item in items if match_filters(item, terms)]
    matched = len(filtered)
    original_fields = ['timestamp', 'index', 'source', 'sourcetype', 'host', 'severity', 'event_type', 'src_ip', 'username', 'message']
    columns = original_fields[:]
    mode = 'events'
    chart = []
    for command_tokens in segments[1:]:
        op = command_tokens[0].lower()
        params = command_tokens[1:]
        if op == 'search' or op == 'where':
            validate_tokens(params)
            filtered = [item for item in filtered if match_filters(item, params)]
        elif op == 'head':
            if len(params) != 1 or not params[0].isdigit() or not 1 <= int(params[0]) <= 5000:
                raise ValueError('Use | head N with N from 1 to 5000')
            filtered = filtered[:int(params[0])]
        elif op == 'sort':
            if len(params) != 1:
                raise ValueError('Use | sort timestamp or | sort -timestamp')
            field = params[0].lstrip('-')
            if not field_valid(field):
                raise ValueError('Unsupported sort field')
            filtered.sort(key=lambda row: str(resolve(row, field)).casefold(), reverse=params[0].startswith('-'))
        elif op == 'table':
            if not params or len(params) > 12 or not all(field_valid(p) for p in params):
                raise ValueError('Use | table timestamp source src_ip message (up to 12 fields)')
            columns = params
            filtered = [{field: resolve(item, field) for field in columns} for item in filtered]
            mode = 'table'
        elif op == 'stats':
            if len(params) != 3 or params[0].lower() != 'count' or params[1].lower() != 'by' or not field_valid(params[2]):
                raise ValueError('Supported syntax: | stats count by source')
            field = params[2]
            counts = Counter(str(resolve(item, field) or '(empty)') for item in filtered)
            filtered = [{field: key, 'count': n} for key, n in counts.most_common()]
            columns = [field, 'count']
            mode = 'stats'
        elif op == 'timechart':
            span = '1h'
            if len(params) == 2 and params[0].startswith('span=') and params[1].lower() == 'count':
                span = params[0][5:].lower()
            elif params != ['count']:
                raise ValueError('Use | timechart span=1h count (supports 1h, 6h, 1d, 1w)')
            seconds = {'1h': 3600, '6h': 21600, '1d': 86400, '1w': 604800}.get(span)
            if not seconds:
                raise ValueError('Supported timechart spans: 1h, 6h, 1d, 1w')
            counts = Counter()
            for item in filtered:
                try:
                    stamp = int(datetime.fromisoformat(str(item['timestamp']).replace('Z', '+00:00')).timestamp())
                except (TypeError, ValueError):
                    continue
                bucket = stamp - stamp % seconds
                counts[bucket] += 1
            filtered = [{'timestamp': datetime.fromtimestamp(key, timezone.utc).isoformat(timespec='seconds'), 'count': counts[key]} for key in sorted(counts)]
            columns = ['timestamp', 'count']
            chart = filtered[:400]
            mode = 'timechart'
        else:
            raise ValueError(f'Unsupported pipeline command: {op}. Try search, head, sort, table, stats or timechart')
    return {'mode': mode, 'columns': columns,
            'items': filtered[:500], 'result_count': len(filtered),
            'matched_events': matched, 'candidates': candidates,
            'truncated': candidates > MAX_SCAN, 'chart': chart,
            'index_facets': facets(start, end), 'field_facets': field_facets(start, end), 'query': query}


def facets(start='', end=''):
    conditions, args = engine.window_sql('timestamp', start, end)
    where = ' WHERE ' + ' AND '.join(conditions) if conditions else ''
    with engine.connect() as db:
        rows = db.execute('SELECT index_name, COUNT(*) AS total FROM events' + where + ' GROUP BY index_name ORDER BY total DESC', args).fetchall()
        return [{'index': row['index_name'], 'count': row['total']} for row in rows]


def field_facets(start='', end=''):
    conditions, args = engine.window_sql('timestamp', start, end)
    where = ' WHERE ' + ' AND '.join(conditions) if conditions else ''
    results = {}
    with engine.connect() as db:
        for field in ('source', 'sourcetype', 'severity'):
            rows = db.execute(f'SELECT {field} AS value, COUNT(*) AS count FROM events' + where +
                              f' GROUP BY {field} ORDER BY count DESC LIMIT 8', args).fetchall()
            results[field] = [{'value': row['value'], 'count': row['count']} for row in rows]
    return results


def list_saved():
    with engine.connect() as db:
        return [dict(row) for row in db.execute('SELECT id,name,query,created_at FROM saved_searches ORDER BY name COLLATE NOCASE')]


def save(name, query):
    name = str(name or '').strip()
    if not 1 <= len(name) <= 70:
        raise ValueError('Name must be 1–70 characters')
    parse_query(query)
    with engine.LOCK, engine.connect() as db:
        db.execute('INSERT INTO saved_searches (name,query,created_at) VALUES (?,?,?) ON CONFLICT(name) DO UPDATE SET query=excluded.query',
                   (name, query, engine.now_iso()))
    return list_saved()


def remove(identifier):
    with engine.LOCK, engine.connect() as db:
        return bool(db.execute('DELETE FROM saved_searches WHERE id=?', (int(identifier),)).rowcount)
