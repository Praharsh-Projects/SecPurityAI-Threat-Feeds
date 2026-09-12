import datetime as dt
import json
import tempfile
import sqlite3
import urllib.error
from concurrent.futures import ThreadPoolExecutor
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

    def test_kev_refresh_keeps_partial_nvd_coverage_visible(self):
        feed.save_cursor(self.db, 'nvd', {'window': {'pubStartDate': '2026-06-01'}, 'index': 250, 'total': 1000})
        feed.sync_kev(self.db, lambda *_: (200, {'vulnerabilities': [kev()]}, {}))
        self.assertIn('250 of 1000', self.db.query('SELECT coverage FROM public_state')[0]['coverage'])

    def test_wrong_nvd_page_does_not_advance_cursor(self):
        with self.assertRaisesRegex(ValueError, 'unexpected_nvd_page'):
            feed.sync_nvd(self.db, lambda *_: (200, {'startIndex': 250, 'totalResults': 500, 'vulnerabilities': [nvd()]}, {}))
        self.assertEqual(feed.cursor_for(self.db, 'nvd'), {})
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

    def test_parallel_reservations_cannot_exceed_global_cap(self):
        path = str(Path(self.tmp.name) / 'test.db')
        def reserve(n):
            connection = sqlite3.connect(path, timeout=20)
            try:
                connection.execute('INSERT INTO ai_reservations(id,day,visitor,address,minute) VALUES(?,?,?,?,?)', (str(n), '2026-09-12', f'visitor:{n}', f'ip:{n}', str(n)))
                connection.commit(); return True
            except sqlite3.IntegrityError:
                connection.rollback(); return False
            finally:
                connection.close()
        with ThreadPoolExecutor(max_workers=16) as pool:
            self.assertEqual(sum(pool.map(reserve, range(150))), 100)
        quota = self.db.query("SELECT calls,neurons FROM ai_quota WHERE subject='global'")[0]
        self.assertEqual(quota, {'calls': 100, 'neurons': 8000})

    def test_pruning_preserves_current_and_previous(self):
        catalog = {}
        for n in range(4):
            item = {**feed.parse_kev(kev()), 'description': f'version {n}'}
            feed.publish(self.db, {item['cve_id']: item}, catalog, f'gen {n}')
        feed.prune(self.db)
        self.assertEqual(feed.read_catalog(self.db)['CVE-2026-1234']['description'], 'version 3')
        self.assertEqual(self.db.query('SELECT COUNT(*) AS n FROM intel_records')[0]['n'], 2)
        self.assertEqual(self.db.query('SELECT COUNT(*) AS n FROM public_summaries')[0]['n'], 2)

    def test_partial_kev_catalog_does_not_replace_good_data(self):
        self.test_publication(); before = feed.read_catalog(self.db)
        with self.assertRaisesRegex(ValueError, 'truncated_kev_catalog'):
            feed.sync_kev(self.db, lambda *_: (200, {'count': 2, 'vulnerabilities': [kev()]}, {}))
        self.assertEqual(before, feed.read_catalog(self.db))

    def test_429_backoff_is_bounded_and_does_not_publish(self):
        sleeps = []
        with patch('urllib.request.urlopen', side_effect=urllib.error.HTTPError('https://example.test', 429, '', {'Retry-After': '999'}, None)):
            with self.assertRaisesRegex(RuntimeError, 'upstream_retries_exhausted'):
                feed.fetch('https://example.test', sleeper=sleeps.append)
        self.assertEqual(sleeps, [120, 120, 120, 120])

    def test_budget_pause_is_not_reported_as_upstream_outage(self):
        feed.save_cursor(self.db, 'nvd', {'window': {'pubStartDate': '2026-01-01'}, 'index': 250})
        with patch('feed.sync_nvd', side_effect=RuntimeError('daily_write_budget')):
            self.assertTrue(feed.run(self.db, 'nvd'))
        self.assertEqual(feed.cursor_for(self.db, 'nvd')['index'], 250)
        self.assertEqual(self.db.query("SELECT status FROM feed_state WHERE source='nvd'")[0]['status'], 'budget_paused')


if __name__ == '__main__': unittest.main()
