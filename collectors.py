import json
import base64
import os
import platform
import re
import socket
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import engine
from parsers import parse_fortigate_line

ROOT = Path(__file__).resolve().parent
INBOX = ROOT / 'log_inbox'
UDP_HOST = os.environ.get('MONITOR_SYSLOG_HOST', '127.0.0.1')
UDP_PORT = int(os.environ.get('MONITOR_SYSLOG_PORT', '5514'))
STATE_FILE = ROOT / '.collector_state.json'
OFFSETS_FILE = ROOT / '.collector_offsets.json'
SYSLOG_PREFIX = re.compile(r'^<(?P<pri>\d{1,3})>(?:\d\s+)?')
WINDOWS_IDS = (4624, 4625, 4688, 4728, 4732, 4756)


def parse_syslog(text, sender='127.0.0.1'):
    content = str(text).strip('\x00\r\n ')
    if not content or len(content) > 8000:
        raise ValueError('Invalid syslog message')
    prefix = SYSLOG_PREFIX.match(content)
    priority = int(prefix.group('pri')) if prefix else 13
    body = content[prefix.end():].strip() if prefix else content
    if 'type=' in body and ('action=' in body or 'subtype=' in body or 'devname=' in body):
        try:
            item = parse_fortigate_line(body)
            item['details']['syslog_sender'] = sender
            return item
        except ValueError:
            pass
    level = priority % 8
    severity = {0:'critical',1:'critical',2:'critical',3:'high',4:'medium',5:'low',6:'info',7:'info'}[level]
    return {'source': 'linux', 'event_type': 'system_event', 'severity': severity,
            'message': body[:900], 'details': {'syslog_sender': sender, 'facility': priority // 8}}


class CollectorManager:
    def __init__(self, inbox=INBOX, udp_host=UDP_HOST, udp_port=UDP_PORT, state_file=STATE_FILE, offsets_file=OFFSETS_FILE):
        self.inbox = Path(inbox)
        self.host = udp_host
        self.port = int(udp_port)
        self.state_file = Path(state_file)
        self.offsets_file = Path(offsets_file)
        self.lock = threading.RLock()
        self.active = {'syslog': False, 'files': False, 'windows': False}
        self.stops = {}
        self.threads = {}
        self.counts = {'syslog': 0, 'files': 0, 'windows': 0}
        self.errors = {'syslog': '', 'files': '', 'windows': ''}
        self.file_positions = self._read_offsets()
        self.windows_record_id = self._saved_windows_record_id()
        self.sockets = {}

    def _read_offsets(self):
        try:
            saved = json.loads(self.offsets_file.read_text(encoding='utf-8'))
            return {path: (tuple(data['identity']), int(data['position']), base64.b64decode(data['fragment']))
                    for path, data in saved.items() if Path(path).resolve().is_relative_to(self.inbox.resolve())}
        except (OSError, ValueError, TypeError, KeyError):
            return {}

    def _write_offsets(self):
        contents = {path: {'identity': list(identity), 'position': position, 'fragment': base64.b64encode(fragment).decode('ascii')}
                    for path,(identity,position,fragment) in self.file_positions.items()}
        temp = self.offsets_file.with_suffix('.tmp')
        temp.write_text(json.dumps(contents), encoding='utf-8')
        os.replace(temp, self.offsets_file)

    def _saved_windows_record_id(self):
        try:
            return max(0, int(json.loads(self.state_file.read_text(encoding='utf-8')).get('windows_record_id',0)))
        except (OSError, ValueError, TypeError):
            return 0

    def _save_windows_record_id(self):
        temporary = self.state_file.with_suffix('.tmp')
        temporary.write_text(json.dumps({'windows_record_id': self.windows_record_id}), encoding='utf-8')
        os.replace(temporary, self.state_file)

    def status(self):
        with self.lock:
            return {'collectors': {name: {'active': self.active[name], 'events': self.counts[name], 'error': self.errors[name]} for name in self.active},
                    'syslog': {'host': self.host, 'port': self.port, 'local_only': self.host in {'127.0.0.1', '::1'}},
                    'inbox': str(self.inbox), 'windows_supported': platform.system() == 'Windows'}

    def start(self, kind):
        if kind not in self.active:
            raise ValueError('Unknown collector type')
        if kind == 'windows' and platform.system() != 'Windows':
            raise ValueError('Windows Security event collection requires Windows')
        with self.lock:
            if self.active[kind]:
                return self.status()
            self.errors[kind] = ''
            stop = threading.Event()
            self.stops[kind] = stop
            if kind == 'syslog':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.bind((self.host, self.port))
                    sock.settimeout(0.5)
                except OSError as exc:
                    sock.close()
                    raise ValueError(f'Unable to start syslog listener: {exc}') from exc
                self.sockets[kind] = sock
                fn = lambda: self._syslog_loop(stop, sock)
            elif kind == 'files':
                self.inbox.mkdir(parents=True, exist_ok=True)
                fn = lambda: self._files_loop(stop)
            else:
                fn = lambda: self._windows_loop(stop)
            self.active[kind] = True
            thread = threading.Thread(target=self._run, args=(kind, fn), daemon=True, name=f'sentinel-{kind}')
            self.threads[kind] = thread
            thread.start()
            return self.status()

    def _run(self, kind, fn):
        try:
            fn()
        except Exception as exc:
            with self.lock:
                self.errors[kind] = str(exc)[:250]
        finally:
            with self.lock:
                self.active[kind] = False

    def stop(self, kind):
        if kind not in self.active:
            raise ValueError('Unknown collector type')
        with self.lock:
            stop = self.stops.get(kind)
            thread = self.threads.get(kind)
            if stop:
                stop.set()
        if thread and thread is not threading.current_thread():
            thread.join(timeout=4)
        return self.status()

    def stop_all(self):
        for kind in list(self.active):
            self.stop(kind)

    def _store(self, kind, event):
        engine.ingest(event)
        with self.lock:
            self.counts[kind] += 1

    def _syslog_loop(self, stop, sock):
        try:
            while not stop.is_set():
                try:
                    raw, (address, _) = sock.recvfrom(8192)
                except socket.timeout:
                    continue
                except OSError:
                    if stop.is_set():
                        break
                    raise
                try:
                    self._store('syslog', parse_syslog(raw.decode('utf-8', errors='replace'), address))
                except (ValueError, OSError) as exc:
                    with self.lock:
                        self.errors['syslog'] = f'Last skipped message: {str(exc)[:150]}'
        finally:
            sock.close()
            with self.lock:
                self.sockets.pop('syslog', None)

    def _files_loop(self, stop):
        while not stop.is_set():
            for file in self.inbox.iterdir():
                if stop.is_set():
                    break
                if not file.is_file() or file.is_symlink() or file.suffix.lower() not in {'.log', '.jsonl'}:
                    continue
                try:
                    stat = file.stat()
                    if stat.st_size > 50_000_000:
                        continue
                    identity = (stat.st_dev, stat.st_ino)
                    saved_identity, position, fragment = self.file_positions.get(str(file), (identity, 0, b''))
                    if identity != saved_identity or stat.st_size < position:
                        position, fragment = 0, b''
                    with file.open('rb') as handle:
                        handle.seek(position)
                        data = handle.read(250_000)
                        new_position = handle.tell()
                    chunks = (fragment + data).split(b'\n')
                    fragment = chunks.pop()
                    if len(fragment) > 16_000:
                        fragment = b''
                        with self.lock:
                            self.errors['files'] = 'Skipped oversized line'
                    for line in chunks:
                        if not line.strip():
                            continue
                        try:
                            decoded = line.decode('utf-8-sig')
                            item = json.loads(decoded) if file.suffix.lower() == '.jsonl' else parse_syslog(decoded)
                            self._store('files', item)
                        except (ValueError, UnicodeError) as exc:
                            with self.lock:
                                self.errors['files'] = f'Skipped a line in {file.name}: {str(exc)[:100]}'
                    self.file_positions[str(file)] = (identity, new_position, fragment)
                    self._write_offsets()
                except (PermissionError, OSError) as exc:
                    with self.lock:
                        self.errors['files'] = f'{file.name}: {str(exc)[:100]}'
            stop.wait(1.0)

    def _windows_loop(self, stop):
        from parsers import normalize_windows_record
        last_check = datetime.now(timezone.utc) - timedelta(minutes=60)
        while not stop.is_set():
            script = """$ErrorActionPreference='Stop'; $start=[datetime]::Parse($env:SENTINEL_START_UTC, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal); $records=@(); try{$records=Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4688,4728,4732,4756; StartTime=$start} -MaxEvents 1500 -ErrorAction Stop | Sort-Object RecordId}catch{if($_.Exception.Message -notmatch 'No events were found'){throw}}; foreach($e in $records){$fields=@{}; try{$xml=[xml]$e.ToXml(); foreach($field in $xml.Event.EventData.Data){if($field.Name){$fields[$field.Name]=[string]$field.'#text'}}}catch{}; [pscustomobject]@{Id=$e.Id; RecordId=$e.RecordId; TimeCreated=$e.TimeCreated.ToUniversalTime().ToString('o'); Message=[string]$e.Message; IpAddress=[string]$fields['IpAddress']; TargetUserName=[string]$fields['TargetUserName']} | ConvertTo-Json -Compress -Depth 3 }"""
            end_check = datetime.now(timezone.utc)
            result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                                    capture_output=True, text=True, timeout=30,
                                    env={**os.environ, 'SENTINEL_START_UTC': last_check.isoformat()})
            if result.returncode:
                raise RuntimeError(f'Windows Event Log access failed: {result.stderr.strip()[:190]}')
            entries = []
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                entry = json.loads(line)
                record_id = int(entry['RecordId'])
                if record_id <= self.windows_record_id:
                    continue
                entries.append((record_id, normalize_windows_record(entry)))
            for record_id, event in sorted(entries):
                self._store('windows', event)
                self.windows_record_id = record_id
            if entries:
                self._save_windows_record_id()
            last_check = end_check - timedelta(seconds=10)
            stop.wait(12)

