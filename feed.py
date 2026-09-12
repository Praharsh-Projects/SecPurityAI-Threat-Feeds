#!/usr/bin/env python3
"""Public CISA/NVD ingestion only. No application or tenant-data dependencies."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
ATTRIBUTION = {'cisa-kev': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'nvd': 'https://nvd.nist.gov/vuln'}
CVE = re.compile(r'^CVE-\d{4}-\d{4,}$')


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def fetch(url, headers=None, sleeper=time.sleep):
    for attempt in range(5):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'SecPurityAI-Public-Feeds/2.0', 'Accept': 'application/json', **(headers or {})})
            with urllib.request.urlopen(req, timeout=45) as response:
                raw = response.read(25_000_001)
                if len(raw) > 25_000_000:
                    raise ValueError('upstream_payload_too_large')
                return 200, json.loads(raw), dict(response.headers)
        except urllib.error.HTTPError as error:
            if error.code == 304:
                return 304, None, dict(error.headers)
            if error.code != 429 and error.code < 500:
                raise RuntimeError(f'upstream_http_{error.code}') from None
            delay = error.headers.get('Retry-After', '')
            wait = min(float(delay), 120) if delay.isdigit() else min(2 ** attempt * 2, 32)
        except (urllib.error.URLError, TimeoutError):
            wait = min(2 ** attempt * 2, 32)
        if attempt == 4:
            raise RuntimeError('upstream_retries_exhausted')
        sleeper(wait)
    raise RuntimeError('unreachable')


def link(url):
    if not isinstance(url, str):
        return False
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme == 'https' and bool(parsed.hostname) and not parsed.username and not re.match(r'^(localhost|\d|\[)', parsed.hostname)


def base(cve):
    if not isinstance(cve, str) or not CVE.fullmatch(cve):
        raise ValueError('invalid_cve')
    return dict(cve_id=cve, title=cve, description='', vendor='Unknown', product='Unknown', severity='unknown', cvss=None, cwe=[],
                known_exploited=False, ransomware='Unknown', published_at=None, modified_at=None, kev_added_at=None,
                due_date=None, required_action=None, references=[f'https://nvd.nist.gov/vuln/detail/{cve}'], sources=[])


def parse_kev(raw, existing=None):
    item = {**base(raw.get('cveID')), **(existing or {})}
    for field in ('vulnerabilityName', 'shortDescription', 'vendorProject', 'product', 'dateAdded'):
        if not isinstance(raw.get(field), str) or not raw[field]:
            raise ValueError('malformed_kev')
    item.update(title=raw['vulnerabilityName'][:1000], description=raw['shortDescription'][:8000], vendor=raw['vendorProject'][:120],
                product=raw['product'][:300], known_exploited=True, ransomware=raw.get('knownRansomwareCampaignUse', 'Unknown'),
                kev_added_at=raw['dateAdded'], due_date=raw.get('dueDate'), required_action=raw.get('requiredAction'),
                modified_at=max(item.get('modified_at') or '', raw['dateAdded']))
    item['cwe'] = sorted(set(item['cwe'] + raw.get('cwes', [])))
    item['sources'] = sorted(set(item['sources'] + ['cisa-kev']))
    item['references'] = sorted(set(item['references'] + [ATTRIBUTION['cisa-kev']] + [u for u in re.findall(r'https?://[^\s;]+', raw.get('notes', '')) if link(u)]))[:30]
    return item


def parse_nvd(raw, existing=None):
    cve = raw.get('cve', raw)
    item = {**base(cve.get('id')), **(existing or {})}
    descriptions = [r.get('value', '') for r in cve.get('descriptions', []) if r.get('lang') == 'en']
    if not descriptions:
        raise ValueError('missing_nvd_description')
    # KEV wording/vendor names take precedence where both sources are present.
    if not item['known_exploited']:
        item['description'] = descriptions[0][:8000]
        item['title'] = f"{item['cve_id']} - {descriptions[0][:140]}"
    metrics = cve.get('metrics', {})
    ratings = metrics.get('cvssMetricV40') or metrics.get('cvssMetricV31') or metrics.get('cvssMetricV30') or metrics.get('cvssMetricV2') or []
    if ratings:
        rating = ratings[0]; score = rating.get('cvssData', {}).get('baseScore')
        if isinstance(score, (int, float)) and 0 <= score <= 10:
            item['cvss'] = score
            item['severity'] = 'critical' if score >= 9 else 'high' if score >= 7 else 'medium' if score >= 4 else 'low'
    for config in cve.get('configurations', []):
        for node in config.get('nodes', []):
            for match in node.get('cpeMatch', []):
                parts = match.get('criteria', '').split(':')
                if not item['known_exploited'] and match.get('vulnerable') and len(parts) > 4:
                    item['vendor'], item['product'] = parts[3].replace('_', ' ')[:120], parts[4].replace('_', ' ')[:300]
                    break
    item['published_at'] = cve.get('published')
    item['modified_at'] = max(item.get('modified_at') or '', cve.get('lastModified') or '')
    item['sources'] = sorted(set(item['sources'] + ['nvd']))
    item['cwe'] = sorted(set(item['cwe'] + [d['value'] for w in cve.get('weaknesses', []) for d in w.get('description', []) if str(d.get('value', '')).startswith('CWE-')]))
    item['references'] = sorted(set(item['references'] + [r['url'] for r in cve.get('references', []) if link(r.get('url'))]))[:30]
    return item


class SQLite:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(Path(__file__).with_name('schema.sql').read_text())

    def query(self, sql, params=()):
        result = [dict(row) for row in self.db.execute(sql, params).fetchall()]
        self.db.commit()
        return result


class D1:
    def __init__(self):
        account = os.environ['CLOUDFLARE_ACCOUNT_ID']
        database = os.environ['PUBLIC_D1_DATABASE_ID']
        if not re.fullmatch('[a-f0-9]{32}', account) or not re.fullmatch('[a-f0-9-]{36}', database):
            raise ValueError('invalid_database_configuration')
        self.url = f'https://api.cloudflare.com/client/v4/accounts/{account}/d1/database/{database}/query'
        self.token = os.environ['CLOUDFLARE_API_TOKEN']

    def query(self, sql, params=()):
        request = urllib.request.Request(self.url, data=canonical({'sql': sql, 'params': list(params)}).encode(), headers={
            'Content-Type': 'application/json', 'Authorization': f'Bearer {self.token}'})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                value = json.load(response)
            if not value.get('success') or not all(r.get('success') for r in value.get('result', [])):
                raise RuntimeError('d1_query_failed')
            return value['result'][0].get('results', [])
        except urllib.error.HTTPError as error:
            # Do not log SQL, headers, credentials or upstream response bodies.
            raise RuntimeError(f'd1_http_{error.code}') from None


def read_catalog(db):
    output = {}; offset = 0
    while True:
        page = db.query('SELECT payload FROM current_intel ORDER BY cve_id LIMIT 500 OFFSET ?', (offset,))
        for row in page:
            item = json.loads(row['payload']); output[item['cve_id']] = item
        if len(page) < 500:
            return output
        offset += len(page)


def summary(items, coverage):
    values = list(items.values())
    exploited = [r for r in values if r['known_exploited']]
    vendors = Counter(r['vendor'] for r in values)
    trends = Counter((r['kev_added_at'] or '')[:10] for r in exploited)
    return dict(coverage=coverage, totals={'vulnerabilities': len(values), 'known_exploited': len(exploited),
                'known_ransomware': sum(r['ransomware'] == 'Known' for r in values)},
                severity_counts=dict(Counter(r['severity'] for r in values)),
                top_vendors=[{'vendor': k, 'count': v} for k, v in vendors.most_common(10)],
                trends=[{'date': k, 'kev_added': v} for k, v in sorted(trends.items())[-30:] if k],
                recent_kev=sorted(exploited, key=lambda r: (r['kev_added_at'] or '', r['cve_id']), reverse=True)[:12],
                attribution=[{'source': k, 'url': v} for k, v in ATTRIBUTION.items()])


def publish(db, changes, catalog, coverage):
    if getattr(db, 'lease', None):
        lease = db.query("UPDATE feed_lock SET expires_at=datetime('now','+45 minutes') WHERE id=1 AND owner=? AND expires_at>datetime('now') RETURNING owner", (db.lease,))
        if not lease:
            raise RuntimeError('writer_lease_lost')
    changes = {key: item for key, item in changes.items() if canonical(item) != canonical(catalog.get(key))}
    # Reserve conservatively for table/index writes plus publication metadata.
    cost = 8 * len(changes) + 20
    if cost > 60000:
        raise RuntimeError('daily_write_budget')
    budget = db.query('INSERT INTO feed_write_budget(day,used) VALUES(?,?) ON CONFLICT(day) DO UPDATE SET used=used+excluded.used WHERE used+excluded.used<=60000 RETURNING used', (now()[:10], cost))
    if not budget:
        raise RuntimeError('daily_write_budget')
    generation = time.time_ns() // 1000
    for start in range(0, len(changes), 10):
        rows = list(changes.values())[start:start + 10]
        params = []
        for row in rows:
            payload = canonical(row)
            params.extend([row['cve_id'], generation, row['vendor'].lower(), row['severity'], int(row['known_exploited']), row['modified_at'] or '', payload, hashlib.sha256(payload.encode()).hexdigest()])
        db.query('INSERT INTO intel_records(cve_id,generation,vendor,severity,known_exploited,modified_at,payload,checksum) VALUES ' + ','.join(['(?,?,?,?,?,?,?,?)'] * len(rows)), params)
    merged = {**catalog, **changes}
    db.query('INSERT INTO public_summaries(generation,payload) VALUES(?,?)', (generation, canonical(summary(merged, coverage))))
    # The trigger advances the public pointer in the same atomic statement.
    db.query('INSERT INTO published_generations(generation) VALUES(?)', (generation,))
    catalog.update(changes)
    return len(changes)


def cursor_for(db, source):
    rows = db.query('SELECT cursor FROM feed_state WHERE source=?', (source,))
    return json.loads(rows[0]['cursor']) if rows else {}


def save_cursor(db, source, cursor, success=False):
    stamp = now()
    db.query("INSERT INTO feed_state(source,cursor,last_attempt_at,last_success_at,status) VALUES(?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET cursor=excluded.cursor,last_attempt_at=excluded.last_attempt_at,last_success_at=COALESCE(excluded.last_success_at,feed_state.last_success_at),status=excluded.status", (source, canonical(cursor), stamp, stamp if success else None, 'current' if success else 'running'))


def sync_kev(db, request=fetch):
    cursor = cursor_for(db, 'cisa-kev'); headers = {}
    if cursor.get('etag'):
        headers['If-None-Match'] = cursor['etag']
    if cursor.get('last_modified'):
        headers['If-Modified-Since'] = cursor['last_modified']
    status, document, response_headers = request(KEV, headers)
    if status == 304:
        save_cursor(db, 'cisa-kev', cursor, True)
        return 0
    if not isinstance(document, dict) or not isinstance(document.get('vulnerabilities'), list) or len(document['vulnerabilities']) < 1:
        raise ValueError('invalid_kev_catalog')
    catalog = read_catalog(db); changes = {}
    declared_count = document.get('count')
    if declared_count is not None and declared_count != len(document['vulnerabilities']):
        raise ValueError('truncated_kev_catalog')
    previous_count = sum(item['known_exploited'] for item in catalog.values())
    if previous_count > 10 and len(document['vulnerabilities']) < previous_count * 0.9:
        raise ValueError('unexpected_kev_catalog_shrink')
    for raw in document['vulnerabilities']:
        item = parse_kev(raw, catalog.get(raw.get('cveID'))); changes[item['cve_id']] = item
    for key, item in catalog.items():
        if item['known_exploited'] and key not in changes:
            changes[key] = {**item, 'known_exploited': False, 'kev_added_at': None, 'due_date': None, 'required_action': None, 'ransomware': 'Unknown'}
    nvd_cursor = cursor_for(db, 'nvd')
    if nvd_cursor.get('window'):
        coverage = f"Full KEV; NVD bootstrap/catch-up: {nvd_cursor.get('index', 0)} of {nvd_cursor.get('total', 'unknown')} source records imported in the active window."
    elif nvd_cursor.get('last_completed'):
        coverage = f"Full KEV; NVD ingestion completed through {nvd_cursor['last_completed']}."
    else:
        coverage = 'Full KEV catalog; NVD 120-day bootstrap not yet completed.'
    count = publish(db, changes, catalog, coverage)
    save_cursor(db, 'cisa-kev', {'etag': response_headers.get('ETag') or response_headers.get('etag'), 'last_modified': response_headers.get('Last-Modified') or response_headers.get('last-modified'), 'catalog_version': document.get('catalogVersion')}, True)
    return count


def nvd_window(cursor, clock=None):
    end = clock or dt.datetime.now(dt.timezone.utc)
    if cursor.get('window'):
        return cursor['window']
    last = cursor.get('last_completed')
    start = dt.datetime.fromisoformat(last.replace('Z', '+00:00')) - dt.timedelta(hours=2) if last else end - dt.timedelta(days=120)
    # NVD limits date windows to 120 days; long outages catch up in bounded windows.
    end = min(end, start + dt.timedelta(days=120))
    prefix = 'lastMod' if last else 'pub'
    return {f'{prefix}StartDate': start.isoformat(timespec='milliseconds'), f'{prefix}EndDate': end.isoformat(timespec='milliseconds')}


def sync_nvd(db, request=fetch, sleeper=time.sleep, max_pages=30):
    cursor = cursor_for(db, 'nvd'); window = nvd_window(cursor)
    index = cursor.get('index', 0); catalog = read_catalog(db); changed = 0
    for _ in range(max_pages):
        params = {**window, 'startIndex': index, 'resultsPerPage': 250}
        headers = {'apiKey': os.environ['NVD_API_KEY']} if os.environ.get('NVD_API_KEY') else {}
        status, document, _headers = request(NVD + '?' + urllib.parse.urlencode(params), headers)
        if status != 200 or not isinstance(document, dict) or not isinstance(document.get('vulnerabilities'), list):
            raise ValueError('invalid_nvd_page')
        raw = document['vulnerabilities']; total = document.get('totalResults')
        if not isinstance(total, int) or total < 0 or (not raw and index < total):
            raise ValueError('truncated_nvd_page')
        if len(raw) > 250 or document.get('startIndex', index) != index:
            raise ValueError('unexpected_nvd_page')
        changes = {}
        for row in raw:
            cve = row.get('cve', {}).get('id'); item = parse_nvd(row, changes.get(cve) or catalog.get(cve)); changes[item['cve_id']] = item
        next_index = index + len(raw)
        changed += publish(db, changes, catalog, f'Full KEV plus NVD window: {min(next_index, total)} of {total} source records imported. Product/version applicability must be verified.')
        if next_index >= total:
            end = window.get('lastModEndDate') or window['pubEndDate']
            save_cursor(db, 'nvd', {'last_completed': end, 'last_window': window, 'total': total}, True)
            return changed
        cursor.update(window=window, index=next_index, total=total)
        save_cursor(db, 'nvd', cursor)
        index = next_index
        sleeper(0.7 if headers else 6)
    return changed


def run(db, source):
    run_id = time.time_ns() // 1000
    origin = 'cloudflare-cron' if os.environ.get('FEED_DISPATCH_KIND') == 'cloudflare-cron' else 'manual'
    provenance = {'origin': origin, 'scheduled_at': os.environ.get('FEED_SCHEDULED_AT', '')[:40],
                  'github_run_id': re.sub('[^0-9]', '', os.environ.get('GITHUB_RUN_ID', ''))[:30]}
    db.query('INSERT INTO feed_runs(id,source,status,started_at,detail) VALUES(?,?,?,?,?)', (run_id, source, 'running', now(), canonical(provenance)))
    try:
        count = sync_kev(db) if source == 'cisa-kev' else sync_nvd(db)
        cursor = cursor_for(db, source)
        status = 'running' if cursor.get('window') else 'success'
        db.query('UPDATE feed_runs SET status=?,finished_at=?,records_changed=?,cursor=? WHERE id=?', (status, now(), count, canonical(cursor), run_id))
        print(canonical({'source': source, 'status': status, 'records_changed': count}))
        return True
    except (RuntimeError, ValueError) as error:
        # Error messages are fixed codes; never persist a request body or token.
        code = str(error) if re.fullmatch('[a-z0-9_]+', str(error)) else 'sync_failed'
        if code == 'daily_write_budget':
            db.query("UPDATE feed_runs SET status='budget_paused',finished_at=?,detail=? WHERE id=?", (now(), code, run_id))
            db.query("UPDATE feed_state SET status='budget_paused',last_attempt_at=? WHERE source=?", (now(), source))
            print(canonical({'source': source, 'status': 'budget_paused', 'detail': 'Resume after UTC midnight; published data and cursor retained.'}))
            return True
        db.query('UPDATE feed_runs SET status=?,finished_at=?,detail=? WHERE id=?', ('failed', now(), code, run_id))
        db.query("INSERT INTO feed_state(source,last_attempt_at,status) VALUES(?,?,'failed') ON CONFLICT(source) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,status='failed'", (source, now()))
        print(canonical({'source': source, 'status': 'failed', 'detail': code}))
        return False


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--sqlite'); parser.add_argument('--source', choices=['cisa-kev', 'nvd', 'all'], default='all')
    args = parser.parse_args(); db = SQLite(args.sqlite) if args.sqlite else D1()
    import uuid
    db.lease = str(uuid.uuid4())
    lock = db.query("INSERT INTO feed_lock(id,owner,expires_at) VALUES(1,?,datetime('now','+45 minutes')) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at WHERE expires_at<=datetime('now') RETURNING owner", (db.lease,))
    if not lock:
        raise SystemExit('A public feed writer is already active; no data was changed.')
    try:
        results = [run(db, source) for source in (['cisa-kev', 'nvd'] if args.source == 'all' else [args.source])]
        prune(db)
    finally:
        db.query('DELETE FROM feed_lock WHERE id=1 AND owner=?', (db.lease,))
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2)).date().isoformat()
    db.query('DELETE FROM ai_reservations WHERE day<?', (cutoff,)); db.query('DELETE FROM ai_quota WHERE day<?', (cutoff,))
    raise SystemExit(0 if all(results) else 1)


def prune(db):
    budget = db.query('INSERT INTO feed_write_budget(day,used) VALUES(?,2200) ON CONFLICT(day) DO UPDATE SET used=used+2200 WHERE used+2200<=60000 RETURNING used', (now()[:10],))
    if not budget:
        return
    # Keep the current and previous published version of every CVE for rollback.
    db.query('''DELETE FROM intel_records WHERE (cve_id,generation) IN (
      SELECT r.cve_id,r.generation FROM intel_records r,public_state s WHERE s.id=1
      AND r.generation<s.previous_generation AND EXISTS (
        SELECT 1 FROM intel_records n JOIN published_generations p ON p.generation=n.generation
        WHERE n.cve_id=r.cve_id AND n.generation>r.generation AND n.generation<=s.previous_generation)
      LIMIT 200)''')
    db.query('''DELETE FROM public_summaries WHERE generation IN (
      SELECT generation FROM public_summaries,public_state WHERE id=1
      AND generation NOT IN(active_generation,previous_generation) LIMIT 200)''')
    db.query("DELETE FROM feed_runs WHERE id IN (SELECT id FROM feed_runs WHERE started_at<datetime('now','-30 days') LIMIT 100)")


if __name__ == '__main__':
    main()
