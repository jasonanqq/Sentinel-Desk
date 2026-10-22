import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import engine
import email_threat


class EmailThreatTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.previous = engine.DATABASE
        engine.DATABASE = Path(self.folder.name) / 'events.db'
        engine.initialize()
        email_threat.initialize()

    def tearDown(self):
        engine.DATABASE = self.previous
        self.folder.cleanup()

    def sample(self, content='Meeting details for tomorrow.', subject='Meeting tomorrow', authentication='spf=pass dkim=pass dmarc=pass compauth=pass', sender='employee@example.org', extra=''):
        message = (f'From: {sender}\r\nTo: colleague@example.org\r\nSubject: {subject}\r\n'
                   f'Date: Tue, 09 Jul 2024 10:30:00 +0000\r\n'
                   f'Authentication-Results: mx.example.org; {authentication}\r\n'
                   f'Received: from mail.example.org (mail.example.org [8.8.4.4]) by mx.example.org; Tue, 09 Jul 2024 10:30:00 +0000\r\n'
                   f'{extra}MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{content}')
        return message.encode()

    def test_legitimate_email_low_risk(self):
        result = email_threat.analyse(self.sample())['investigation']
        self.assertEqual(result['severity'], 'Low')
        self.assertEqual(result['categories'], ['No Clear Threat'])
        self.assertEqual(result['auth']['spf'], 'pass')
        self.assertEqual(result['originating_ip'], '8.8.4.4')

    def test_sextortion_and_spoofing_distinct_categories(self):
        content = ('I installed Pegasus spyware on your computer. I will release your private videos to your family. '
                   'Pay $1,200 in Litecoin to this wallet within 48 hours.')
        result = email_threat.analyse(self.sample(content, "You've been hacked", 'spf=fail dkim=none dmarc=fail compauth=fail', 'security@hotmail.com', 'Return-Path: <payment@me88.com>\r\n'))['investigation']
        self.assertIn('Sextortion', result['categories'])
        self.assertEqual(email_threat.investigations(category='Sextortion')['total'],1)
        self.assertIn('Suspected Spoofing', result['categories'])
        self.assertNotIn('Credential Phishing', result['categories'])
        self.assertEqual(result['severity'], 'Critical')
        self.assertTrue(any('unverified' in evidence['explanation'].lower() for evidence in result['evidence']))
        self.assertEqual(result['received_at'], '2024-07-09T10:30:00+00:00')

    def test_sextortion_demand_without_crypto(self):
        content = 'I will release your private videos to your family. Pay $500 in dollars by tomorrow.'
        result=email_threat.analyse(self.sample(content, subject='Threatening note'))['investigation']
        self.assertIn('Sextortion', result['categories'])
        self.assertNotIn('Credential Phishing', result['categories'])

    def test_credential_phishing_independent(self):
        payload = self.sample('Urgent: verify your password at https://login-example.invalid/verify', 'Account validation', 'spf=fail dkim=fail dmarc=fail compauth=fail', 'support@example.org')
        detail = email_threat.analyse(payload)['investigation']
        self.assertIn('Credential Phishing', detail['categories'])
        self.assertNotIn('Sextortion', detail['categories'])
        self.assertIn('https://login-example.invalid/verify', detail['urls'])

    def test_single_weak_signal_not_high_risk(self):
        detail = email_threat.analyse(self.sample('Thank you.', authentication='spf=pass dkim=none dmarc=pass compauth=pass'))['investigation']
        self.assertEqual(detail['severity'], 'Low')
        self.assertEqual(detail['primary_category'], 'No Clear Threat')

    def test_duplicate_avoids_new_case(self):
        data = self.sample()
        first = email_threat.analyse(data)
        second = email_threat.analyse(data.replace(b'\r\n',b'\n'))
        self.assertEqual(first['id'],second['id'])
        self.assertTrue(second['duplicate'])
        self.assertEqual(email_threat.stats()['total'], 1)

    def test_malformed_headers_dont_crash(self):
        result = email_threat.analyse(b'\xff\xfebroken\r\n from f\xff\r\n\r\nbody')
        self.assertIn('id',result)
        self.assertGreaterEqual(result['investigation']['score'],0)

    def test_header_only_does_not_invent_body_indicators(self):
        headers = b'From: sender@example.org\r\nSubject: Reminder\r\nAuthentication-Results: mx; spf=fail dkim=none dmarc=fail\r\n\r\n'
        record = email_threat.analyse(headers, header_only=True)['investigation']
        self.assertIn('Suspected Spoofing', record['categories'])
        self.assertNotIn('Sextortion', record['categories'])
        self.assertFalse(record['body_excerpt'])

    def test_search_filters_date_and_status(self):
        first = email_threat.analyse(self.sample('one', subject='Alpha'))
        email_threat.analyse(self.sample('two', subject='Bravo', sender='someone@else.org'))
        self.assertEqual(email_threat.investigations(q='Alpha')['total'],1)
        self.assertEqual(email_threat.investigations(sender='someone@else.org')['total'],1)
        self.assertEqual(email_threat.investigations(ip='8.8.4.4')['total'],2)
        self.assertEqual(email_threat.investigations(start='2026-01-01T00:00:00Z',date_field='received_at')['total'],0)
        self.assertEqual(email_threat.investigations(start='2024-01-01T00:00:00Z',date_field='received_at')['total'],2)
        self.assertTrue(email_threat.update_status(first['id'],'Investigating'))
        self.assertEqual(email_threat.investigations(status='Investigating')['total'],1)

    def test_attachment_html_not_rendered_or_executed(self):
        message=EmailMessage()
        message['From']='team@example.org'
        message['To']='test@example.org'
        message['Subject']='HTML sample'
        message.set_content('Read the weekly report.')
        message.add_alternative('<p>Report</p><script>alert(1)</script><a href="https://example.org">open</a>', subtype='html')
        message.add_attachment(b'fake payload', maintype='application', subtype='octet-stream', filename='report.exe')
        detail=email_threat.analyse(message.as_bytes())['investigation']
        self.assertNotIn('fake payload',detail['body_excerpt'])
        self.assertNotIn('alert(1)',detail['body_excerpt'])

    def test_file_limits_and_status_validation(self):
        with self.assertRaises(ValueError):
            email_threat.analyse(b'a'*(email_threat.MAX_EML_SIZE+1))
        with self.assertRaises(ValueError):
            email_threat.update_status(1,'Destroyed')
        with self.assertRaises(ValueError):
            email_threat.investigations(date_field='invalid')

    def test_received_spf_fallback_and_synthetic_ip(self):
        payload = (b'From: sender@example.org\r\nDate: Tue, 09 Jul 2024 10:30:00 +0000\r\n'
                   b'Received-SPF: fail (client-ip=203.0.113.77)\r\n'
                   b'Received: from relay.example.org [203.0.113.77] by mx.example.org\r\n\r\nHello')
        record=email_threat.analyse(payload)['investigation']
        self.assertEqual(record['auth']['spf'],'fail')
        self.assertEqual(record['originating_ip'],'203.0.113.77')

    def test_payment_impersonation_separate_from_credential_phishing(self):
        payload=self.sample('This is your CEO. Please wire transfer $450 to my bank account today.',subject='Important payment')
        record=email_threat.analyse(payload)['investigation']
        self.assertIn('Impersonation / Payment Fraud',record['categories'])
        self.assertNotIn('Credential Phishing',record['categories'])

    def test_existing_event_index_untouched(self):
        engine.ingest({'source':'windows','event_type':'login_failed','message':'Protected SIEM event'})
        email_threat.analyse(self.sample())
        self.assertEqual(engine.events_page(query='Protected')['total'],1)
        self.assertEqual(engine.index_status()['indexed'],1)


if __name__ == '__main__':
    unittest.main()
