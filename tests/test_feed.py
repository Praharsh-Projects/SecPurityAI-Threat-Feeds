import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import feed


def kev(cve='CVE-2026-1234'):
    return dict(cveID=cve, vulnerabilityName='Example gateway flaw', shortDescription='A public test description.', vendorProject='Example', product='Gateway', dateAdded='2026-09-01', knownRansomwareCampaignUse='Unknown', cwes=['CWE-79'])


def nvd(cve='CVE-2026-1234'):
    return {'cve': {'id': cve, 'descriptions': [{'lang': 'en', 'value': 'NVD test description'}], 'lastModified': '2026-09-02T10:00:00', 'metrics': {'cvssMetricV31': [{'cvssData': {'baseScore': 9.8}}]}}}


class FeedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.db = feed.SQLite(str(Path(self.tmp.name) / 'test.db'))

    def tearDown(self):
        self.db.db.close(); self.tmp.cleanup()

    def test_merge_attribution(self):
        merged = feed.parse_nvd(nvd(), feed.parse_kev(kev()))
        self.assertEqual(merged['sources'], ['cisa-kev', 'nvd']); self.assertTrue(merged['known_exploited'])
        self.assertEqual(merged['severity'], 'critical'); self.assertEqual(merged['ransomware'], 'Unknown')

    def test_malformed(self):
        for raw in [{}, {'cveID': 'not-a-cve'}, {'cveID': 'CVE-2026-1234'}]:
            with self.assertRaises(ValueError): feed.parse_kev(raw)

    def test_304_preserves_dataset(self):
        self.test_publication()
        before = feed.read_catalog(self.db)
        feed.sync_kev(self.db, lambda *_: (304, None, {}))
        self.assertEqual(before, feed.read_catalog(self.db))
        self.assertTrue(self.db.query("SELECT last_success_at FROM feed_state WHERE source='cisa-kev'")[0]['last_success_at'])

    def test_publication(self):
        item = feed.parse_kev(kev()); feed.publish(self.db, {item['cve_id']: item}, {}, 'fixture')
        self.assertEqual(len(feed.read_catalog(self.db)), 1)
        self.assertEqual(self.db.query('SELECT coverage FROM public_state')[0]['coverage'], 'fixture')

    def test_orphan_rows_never_visible(self):
        item = feed.parse_kev(kev())
        original = self.db.query
        def fail_summary(sql, params=()):
            if sql.startswith('INSERT INTO public_summaries'): raise RuntimeError('interrupted')
            return original(sql, params)
        with patch.object(self.db, 'query', fail_summary):
            with self.assertRaises(RuntimeError): feed.publish(self.db, {item['cve_id']: item}, {}, 'interrupted')
        other = feed.parse_kev(kev('CVE-2026-9999')); feed.publish(self.db, {other['cve_id']: other}, {}, 'good')
        self.assertEqual(set(feed.read_catalog(self.db)), {'CVE-2026-9999'})

    def test_deduplicate_and_idempotent(self):
        request = lambda *_: (200, {'vulnerabilities': [kev(), kev()]}, {'ETag': 'one'})
        self.assertEqual(feed.sync_kev(self.db, request), 1)
        self.assertEqual(feed.sync_kev(self.db, request), 0)
        self.assertEqual(len(feed.read_catalog(self.db)), 1)

    def test_nvd_resume_and_overlap(self):
        pages = [dict(totalResults=2, vulnerabilities=[nvd()]), dict(totalResults=2, vulnerabilities=[nvd('CVE-2026-5678')])]
        urls = []
        def request(url, _headers): urls.append(url); return 200, pages.pop(0), {}
        feed.sync_nvd(self.db, request, sleeper=lambda _: None, max_pages=1)
        self.assertEqual(feed.cursor_for(self.db, 'nvd')['index'], 1)
        self.assertIsNone(self.db.query("SELECT last_success_at FROM feed_state WHERE source='nvd'")[0]['last_success_at'])
        feed.sync_nvd(self.db, request, sleeper=lambda _: None, max_pages=1)
        cursor = feed.cursor_for(self.db, 'nvd'); self.assertNotIn('window', cursor)
        self.assertIn('startIndex=1', urls[-1]); self.assertEqual(len(feed.read_catalog(self.db)), 2)
        window = feed.nvd_window(cursor)
        actual = dt.datetime.fromisoformat(window['lastModStartDate'])
        self.assertEqual(actual, dt.datetime.fromisoformat(cursor['last_completed']) - dt.timedelta(hours=2))

    def test_truncated_nvd_preserves_cursor(self):
        with self.assertRaises(ValueError): feed.sync_nvd(self.db, lambda *_: (200, {'totalResults': 10, 'vulnerabilities': []}, {}))
        self.assertEqual(feed.cursor_for(self.db, 'nvd'), {})

    def test_daily_write_budget(self):
        self.db.query('INSERT INTO feed_write_budget(day,used) VALUES(?,60000)', (feed.now()[:10],))
        with self.assertRaisesRegex(RuntimeError, 'daily_write_budget'): feed.publish(self.db, {}, {}, 'full')
        self.assertEqual(feed.read_catalog(self.db), {})

    def test_source_outage_preserves_good_records(self):
        self.test_publication(); before = feed.read_catalog(self.db)
        with patch('feed.sync_kev', side_effect=RuntimeError('upstream_retries_exhausted')):
            self.assertFalse(feed.run(self.db, 'cisa-kev'))
        self.assertEqual(before, feed.read_catalog(self.db))

    def test_quota_statement_is_atomic(self):
        for n in range(10):
            self.db.query('INSERT INTO ai_reservations(id,day,visitor,address,minute) VALUES(?,?,?,?,?)', (str(n), '2026-09-12', 'visitor:one', 'ip:one', str(n)))
        with self.assertRaisesRegex(Exception, 'quota_exhausted'):
            self.db.query('INSERT INTO ai_reservations(id,day,visitor,address,minute) VALUES(?,?,?,?,?)', ('blocked', '2026-09-12', 'visitor:one', 'ip:two', '11'))
        self.db.db.rollback()
        self.assertEqual(self.db.query("SELECT calls FROM ai_quota WHERE subject='global'")[0]['calls'], 10)

    def test_global_cap(self):
        for n in range(100):
            self.db.query('INSERT INTO ai_reservations(id,day,visitor,address,minute) VALUES(?,?,?,?,?)', (str(n), '2026-09-12', f'visitor:{n}', f'ip:{n}', str(n)))
        with self.assertRaisesRegex(Exception, 'quota_exhausted'):
            self.db.query('INSERT INTO ai_reservations(id,day,visitor,address,minute) VALUES(?,?,?,?,?)', ('blocked', '2026-09-12', 'visitor:last', 'ip:last', '101'))
        self.db.db.rollback()
        self.assertEqual(self.db.query("SELECT neurons FROM ai_quota WHERE subject='global'")[0]['neurons'], 8000)


if __name__ == '__main__': unittest.main()
