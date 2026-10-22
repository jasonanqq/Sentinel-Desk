import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import engine
from parsers import parse_fortigate_line, normalize_windows_record


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.previous = engine.DATABASE
        engine.DATABASE = Path(self.directory.name) / 'test.db'
        engine.initialize()
        self.start = datetime.now(timezone.utc).replace(microsecond=0)

    def tearDown(self):
        engine.DATABASE = self.previous
        self.directory.cleanup()

    def event(self, kind, offset=0, ip='198.51.100.77', **fields):
        return {'timestamp': (self.start + timedelta(seconds=offset)).isoformat(),
                'source': 'windows', 'event_type': kind, 'src_ip': ip,
                'username': 'admin', 'message': kind, **fields}

    def test_failed_login_burst_and_success(self):
        for i in range(5):
            engine.ingest(self.event('login_failed', i))
        engine.ingest(self.event('login_success', 6))
        titles = {row['rule_id'] for row in engine.alerts_list()}
        self.assertIn('AUTH-001', titles)
        self.assertIn('AUTH-002', titles)

    def test_firewall_deny_burst(self):
        for i in range(8):
            engine.ingest(self.event('firewall_deny', i, source='fortigate'))
        self.assertIn('FW-001', {row['rule_id'] for row in engine.alerts_list()})

    def test_suspicious_process_and_privilege_change(self):
        engine.ingest(self.event('process_start', message='powershell -EncodedCommand DEMO'))
        engine.ingest(self.event('privilege_change', 1))
        rules = {row['rule_id'] for row in engine.alerts_list()}
        self.assertEqual(rules, {'PROC-001', 'PRIV-001'})

    def test_filtering_and_resolution(self):
        engine.ingest(self.event('privilege_change', 1))
        engine.ingest(self.event('login_success', 2, ip='203.0.113.20'))
        result = engine.events_page(query='198.51.100.77')
        self.assertEqual(result['total'], 1)
        alert = engine.alerts_list()[0]
        self.assertTrue(engine.update_alert(alert['id'], 'closed'))
        self.assertEqual(len(engine.alerts_list('open')), 0)
        self.assertEqual(len(engine.alerts_list('closed')), 1)

    def test_batch_atomicity(self):
        valid = self.event('login_failed')
        invalid = self.event('login_failed', 1, src_ip='not an ip')
        with self.assertRaises(ValueError):
            engine.ingest_batch([valid, invalid])
        self.assertEqual(engine.statistics()['total'], 0)

    def test_fortigate_raw_log_parsing(self):
        raw = 'type=traffic action=deny srcip=203.0.113.55 dstip=10.0.0.9 level=warning msg="Blocked SSH"'
        event = parse_fortigate_line(raw)
        self.assertEqual(event['event_type'], 'firewall_deny')
        self.assertEqual(event['src_ip'], '203.0.113.55')
        engine.ingest_batch([event] * 8)
        self.assertIn('FW-001', {row['rule_id'] for row in engine.alerts_list()})

    def test_windows_event_id_normalization(self):
        result = normalize_windows_record({'EventID': 4625, 'IpAddress': '198.51.100.2', 'TargetUserName': 'admin'})
        self.assertEqual(result['event_type'], 'login_failed')
        engine.ingest(result)
        self.assertEqual(engine.events_page()['total'], 1)

    def test_demo_contains_detections(self):
        items = engine.demo_events()
        self.assertGreaterEqual(len(items), 140)
        engine.ingest_batch(items)
        self.assertGreaterEqual(engine.statistics()['open_alerts'], 4)


if __name__ == '__main__':
    unittest.main()
