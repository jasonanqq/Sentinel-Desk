import re
from datetime import datetime, timezone

FIELD_PATTERN = re.compile(r'([A-Za-z][A-Za-z0-9_]*)=(?:"([^"]*)"|([^\s]+))')
WINDOWS_EVENT_TYPES = {4624: 'login_success', 4625: 'login_failed',
                       4688: 'process_start', 4732: 'privilege_change',
                       4728: 'privilege_change', 4756: 'privilege_change'}


def parse_fortigate_line(line):
    if not isinstance(line, str) or len(line) > 6000:
        raise ValueError('A FortiGate log line must be text shorter than 6000 characters')
    fields = {key.lower(): quoted or plain for key, quoted, plain in FIELD_PATTERN.findall(line)}
    if not fields or not (fields.get('type') or fields.get('action')):
        raise ValueError('Line does not contain a recognizable FortiGate log record')
    action = fields.get('action', '').lower()
    summary = (fields.get('msg') or fields.get('logdesc') or fields.get('reason') or '').lower()
    if fields.get('type') == 'traffic' or action in {'deny', 'accept', 'allow', 'close'}:
        kind = 'firewall_deny' if action in {'deny', 'drop', 'blocked'} else 'firewall_allow'
    elif 'login' in summary and any(word in summary for word in ('failed', 'failure', 'invalid')):
        kind = 'login_failed'
    elif 'login' in summary and any(word in summary for word in ('success', 'successful')):
        kind = 'login_success'
    else:
        kind = 'system_event'
    level = fields.get('level', '').lower()
    severity = {'alert': 'critical', 'critical': 'critical', 'error': 'high',
                'warning': 'medium', 'notice': 'low', 'information': 'info', 'info': 'info'}.get(level, 'info')
    result = {'source': 'fortigate', 'event_type': kind, 'severity': severity,
              'src_ip': fields.get('srcip', ''), 'dest_ip': fields.get('dstip', ''),
              'username': fields.get('user') or fields.get('srcname', ''),
              'message': fields.get('msg') or fields.get('logdesc') or f'FortiGate {action or "system"} event',
              'details': {key: value for key, value in fields.items()
                          if key in {'action', 'policyid', 'service', 'subtype', 'type', 'devname', 'logid'}}}
    if fields.get('eventtime'):
        try:
            value = int(fields['eventtime'])
            timestamp = value / 1_000_000_000 if value > 100_000_000_000_000 else value
            result['timestamp'] = datetime.fromtimestamp(timestamp,timezone.utc).isoformat(timespec='seconds')
        except (ValueError, OverflowError):
            pass
    elif fields.get('date') and fields.get('time'):
        try:
            timestamp = datetime.fromisoformat(fields['date'] + 'T' + fields['time']).replace(tzinfo=timezone.utc)
            result['timestamp'] = timestamp.isoformat(timespec='seconds')
        except ValueError:
            pass
    return result


def normalize_windows_record(raw):
    if not isinstance(raw, dict) or raw.get('event_type'):
        return raw
    try:
        event_id = int(raw.get('EventID', raw.get('Id', raw.get('event_id', -1))))
    except (ValueError, TypeError):
        return raw
    kind = WINDOWS_EVENT_TYPES.get(event_id, 'windows_event')
    record = {'source': 'windows', 'event_type': kind,
              'severity': 'medium' if kind == 'login_failed' else 'info',
              'src_ip': raw.get('IpAddress') or raw.get('SourceNetworkAddress') or '',
              'username': raw.get('TargetUserName') or raw.get('UserName') or '',
              'message': raw.get('Message') or f'Windows Event {event_id}',
              'details': {'event_id': event_id}}
    stamp = raw.get('TimeCreated') or raw.get('Timestamp')
    if stamp:
        record['timestamp'] = stamp
    return record
