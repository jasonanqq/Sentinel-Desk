import csv
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import engine


class TimeFilterTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.previous = engine.DATABASE
        engine.DATABASE = Path(self.directory.name) / 'test.db'
        engine.initialize()
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.old = (self.now - timedelta(days=12)).isoformat()
        self.recent = (self.now - timedelta(hours=3)).isoformat()
        engine.ingest_batch([
            {'timestamp': self.old, 'event_type': 'firewall_allow', 'source': 'fortigate', 'src_ip': '203.0.113.1'},
            {'timestamp': self.recent, 'event_type': 'firewall_deny', 'source': 'fortigate', 'src_ip': '203.0.113.2'},
            {'timestamp': self.recent, 'event_type': 'privilege_change', 'source': 'windows', 'username': 'tester'},
        ])

    def tearDown(self):
        engine.DATABASE = self.previous
        self.directory.cleanup()

    def test_date_filter_events_and_alerts(self):
        start = (self.now - timedelta(days=1)).isoformat()
        end = (self.now + timedelta(minutes=1)).isoformat()
        self.assertEqual(engine.events_page(start=start, end=end)['total'], 2)
        self.assertEqual(engine.events_page(start=start, end=end, source='fortigate')['total'], 1)
        self.assertEqual(engine.events_page(start=start, end=end, event_type='firewall_deny')['total'], 1)
        self.assertEqual(engine.events_page(end=start)['total'], 1)
        self.assertEqual(len(engine.alerts_list(start=start, end=end)), 1)
        self.assertEqual(len(engine.alerts_list(end=start)), 0)

    def test_statistics_and_chart_totals(self):
        start = (self.now - timedelta(days=1)).isoformat()
        end = (self.now + timedelta(minutes=1)).isoformat()
        stats = engine.statistics(start, end)
        self.assertEqual(stats['total'], 2)
        self.assertEqual(stats['denied'], 1)
        self.assertEqual(stats['open_alerts'], 1)
        self.assertEqual(sum(bucket['count'] for bucket in stats['timeline']), 2)
        self.assertEqual(sum(bucket['denied'] for bucket in stats['timeline']), 1)
        for bucket in stats['timeline']:
            self.assertLess(bucket['from'], bucket['to'])

    def test_exports_respect_date_and_filters(self):
        start = (self.now - timedelta(days=1)).isoformat()
        columns, rows = engine.csv_rows('events', event_type='firewall_deny', start=start)
        self.assertIn('timestamp', columns)
        self.assertEqual(len(rows), 1)
        columns, rows = engine.csv_rows('alerts', status='open', start=start)
        self.assertEqual(len(rows), 1)

    def test_invalid_time_windows(self):
        with self.assertRaises(ValueError):
            engine.events_page(start='2026-10-21T12:00', end='2026-10-22T12:00Z')
        with self.assertRaises(ValueError):
            engine.alerts_list(start='2026-10-23T12:00Z', end='2026-10-22T12:00Z')
        with self.assertRaises(ValueError):
            engine.statistics(start='yesterday')


if __name__ == '__main__':
    unittest.main()
