import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import engine


class IndexingTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.previous = engine.DATABASE
        engine.DATABASE = Path(self.folder.name) / 'index.db'
        engine.initialize()
        self.now = datetime.now(timezone.utc).replace(microsecond=0)

    def tearDown(self):
        engine.DATABASE = self.previous
        self.folder.cleanup()

    def event(self, message, ip='198.51.100.77', days=0, source='windows'):
        return {'timestamp': (self.now - timedelta(days=days)).isoformat(),
                'source': source, 'event_type': 'process_start', 'src_ip': ip,
                'username': 'jason', 'message': message}

    def test_full_text_search_and_ip_lookup(self):
        engine.ingest(self.event('PowerShell suspicious encoded command'))
        engine.ingest(self.event('Routine heartbeat', '203.0.113.9'))
        self.assertEqual(engine.events_page(query='powershell')['total'], 1)
        self.assertEqual(engine.events_page(query='PowerShell suspicious')['total'], 1)
        self.assertEqual(engine.events_page(query='Power')['total'], 1)
        self.assertEqual(engine.events_page(query='198.51.100.77')['total'], 1)
        self.assertEqual(engine.events_page(query='jason')['total'], 2)
        self.assertEqual(engine.events_page(query='" OR test:') ['total'], 0)

    def test_combined_filters_and_csv(self):
        engine.ingest(self.event('Blocked FortiGate session', source='fortigate'))
        engine.ingest(self.event('Blocked Windows session', source='windows', days=5))
        start = (self.now - timedelta(days=1)).isoformat()
        self.assertEqual(engine.events_page(query='blocked', source='fortigate', start=start)['total'], 1)
        self.assertEqual(engine.events_page(query='blocked', source='windows', start=start)['total'], 0)
        _, rows = engine.csv_rows('events', query='fortigate', source='fortigate')
        self.assertEqual(len(rows), 1)

    def test_index_status_and_reset(self):
        engine.ingest(self.event('Alpha event'))
        engine.ingest(self.event('Beta event'))
        status = engine.index_status()
        self.assertEqual(status['events'], 2)
        self.assertEqual(status['indexed'], 2)
        self.assertTrue(status['synced'])
        engine.reset()
        self.assertEqual(engine.index_status()['indexed'], 0)
        self.assertEqual(engine.events_page(query='Alpha')['total'], 0)

    def test_backfill_preexisting_database(self):
        with engine.connect() as db:
            db.execute('DROP TRIGGER events_fts_insert')
            db.execute('DROP TRIGGER events_fts_delete')
            db.execute('DROP TRIGGER events_fts_update')
            db.execute('DROP TABLE events_fts')
            db.execute('''INSERT INTO events(timestamp,source,event_type,severity,src_ip,dest_ip,username,message,details,received_at)
                          VALUES(?,?,?,?,?,?,?,?,?,?)''',
                       (self.now.isoformat(), 'windows', 'login_failed', 'medium', '198.51.100.77', '', 'jason',
                        'Historic activity', '{}', self.now.isoformat()))
        engine.initialize()
        self.assertEqual(engine.events_page(query='Historic')['total'], 1)
        self.assertEqual(engine.index_status()['indexed'], 1)

    def test_rebuild_fixes_desynchronised_index(self):
        engine.ingest(self.event('Rebuild sample'))
        with engine.connect() as db:
            db.execute('DELETE FROM events_fts')
        self.assertFalse(engine.index_status()['synced'])
        self.assertTrue(engine.rebuild_index()['synced'])
        self.assertEqual(engine.events_page(query='rebuild')['total'], 1)

    def test_index_definitions(self):
        with engine.connect() as db:
            names = {row[1] for row in db.execute('PRAGMA index_list(events)')}
            self.assertIn('events_timestamp_idx', names)
            self.assertIn('events_source_time_idx', names)
            self.assertIn('events_severity_time_idx', names)
            self.assertIn('events_type_time_idx', names)


if __name__ == '__main__':
    unittest.main()
