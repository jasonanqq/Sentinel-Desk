import json
import socket
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import engine
from collectors import CollectorManager, parse_syslog


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_database = engine.DATABASE
        engine.DATABASE = Path(self.temp.name) / 'events.db'
        engine.initialize()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 0))
        self.port = sock.getsockname()[1]
        sock.close()
        self.manager = CollectorManager(inbox=Path(self.temp.name) / 'inbox', udp_port=self.port,
                                        state_file=Path(self.temp.name) / 'state.json',
                                        offsets_file=Path(self.temp.name) / 'offsets.json')

    def tearDown(self):
        self.manager.stop_all()
        engine.DATABASE = self.old_database
        self.temp.cleanup()

    def until(self, predicate, seconds=3):
        deadline = time.time()+seconds
        while time.time()<deadline:
            if predicate():
                return True
            time.sleep(0.05)
        return False

    def test_parses_fortigate_and_generic_syslog(self):
        item = parse_syslog('<189>date=2026-10-22 time=10:00:00 type=traffic subtype=forward action=deny srcip=203.0.113.20 dstip=10.0.0.5 msg="Blocked traffic"', '10.1.1.3')
        self.assertEqual(item['source'], 'fortigate')
        self.assertEqual(item['event_type'], 'firewall_deny')
        self.assertEqual(item['details']['syslog_sender'], '10.1.1.3')
        item = parse_syslog('<11>Oct 22 11:11:11 linuxbox sshd: Failed publickey for root', '127.0.0.1')
        self.assertEqual(item['source'], 'linux')
        self.assertEqual(item['severity'], 'high')
        self.assertIn('sshd', item['message'])

    def test_udp_live_listener_triggers_alert(self):
        self.manager.start('syslog')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            for i in range(9):
                client.sendto(f'<189>type=traffic action=deny srcip=203.0.113.77 dstip=10.0.0.2 msg="Blocked {i}"'.encode(), ('127.0.0.1', self.port))
        self.assertTrue(self.until(lambda: engine.events_page(source='fortigate')['total'] == 9))
        self.assertTrue(any(row['rule_id']=='FW-001' for row in engine.alerts_list()))
        self.assertEqual(self.manager.status()['collectors']['syslog']['events'], 9)
        self.manager.stop('syslog')
        self.assertFalse(self.manager.status()['collectors']['syslog']['active'])

    def test_folder_watcher_tails_new_lines_and_persists_offsets(self):
        inbox=self.manager.inbox
        inbox.mkdir()
        target=inbox/'fortigate.log'
        target.write_text('type=traffic action=deny srcip=203.0.113.22 msg="First"\n',encoding='utf-8')
        self.manager.start('files')
        self.assertTrue(self.until(lambda: engine.events_page()['total']==1))
        with target.open('a',encoding='utf-8') as stream:
            stream.write('type=traffic action=deny srcip=203.0.113.22 msg="Partial')
        time.sleep(1.2)
        self.assertEqual(engine.events_page()['total'],1)
        with target.open('a',encoding='utf-8') as stream:
            stream.write(' message"\n')
        self.assertTrue(self.until(lambda: engine.events_page()['total']==2))
        self.manager.stop('files')
        replacement=CollectorManager(inbox=inbox,udp_port=self.port,state_file=self.manager.state_file,offsets_file=self.manager.offsets_file)
        replacement.start('files')
        time.sleep(1.2)
        self.assertEqual(engine.events_page()['total'],2)
        with (inbox/'other.jsonl').open('w',encoding='utf-8') as stream:
            stream.write(json.dumps({'timestamp':datetime.now(timezone.utc).isoformat(),'source':'windows','event_type':'login_failed','src_ip':'198.51.100.77','message':'Failed authentication'})+'\n')
        self.assertTrue(self.until(lambda: engine.events_page()['total']==3))
        replacement.stop_all()

    def test_validates_collector_types_and_platform(self):
        with self.assertRaises(ValueError):
            self.manager.start('unknown')
        if sys.platform != 'win32':
            with self.assertRaises(ValueError):
                self.manager.start('windows')


if __name__ == '__main__':
    unittest.main()
