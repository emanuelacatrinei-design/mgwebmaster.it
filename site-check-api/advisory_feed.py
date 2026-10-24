"""Bounded refresh of official PHP advisories. No scanned URLs leave the service."""
import json
import logging
import os
from pathlib import Path
import re
import tempfile
import threading
import time

import requests
from advisory_format import normalize

FEED_URL = 'https://api.github.com/repos/php/php-src/security-advisories?per_page=100'
MIRROR_URL = 'https://www.mgwebmaster.it/assets/security/php-advisories.json'
CACHE = Path(tempfile.gettempdir()) / 'mgw-php-advisories-v1.json'
INTERVAL = 6 * 3600
MAX_BYTES = 4 * 1024 * 1024
LOG = logging.getLogger('mgw.sitecheck')




def download(url):
    with requests.Session() as session:
        session.trust_env = False
        with session.get(url, headers={'Accept': 'application/vnd.github+json',
                         'Accept-Encoding': 'identity', 'User-Agent': 'MG-Webmaster-Site-Check'},
                         timeout=(5, 8), stream=True, allow_redirects=False) as response:
            if response.status_code != 200:
                raise ValueError('HTTP_' + str(response.status_code))
            deadline = time.monotonic() + 20
            body = bytearray()
            for chunk in response.iter_content(16384):
                body.extend(chunk)
                if len(body) > MAX_BYTES or time.monotonic() > deadline:
                    raise ValueError('source_limit')
            return json.loads(body), response.headers.get('link', '')


def validate_snapshot(data):
    if (not isinstance(data, dict) or data.get('source') != FEED_URL
            or not isinstance(data.get('checked_at'), int)
            or not 0 < data['checked_at'] <= time.time() + 300
            or not isinstance(data.get('advisories'), list)
            or not 0 < len(data['advisories']) <= 100):
        raise ValueError('snapshot_format')
    for item in data['advisories']:
        if (not re.fullmatch(r'(?:CVE-\d{4}-\d{4,9}|GHSA-[a-z0-9-]{14})', item.get('id', ''))
                or not re.fullmatch(r'GHSA-[a-z0-9-]{14}', item.get('ghsa', ''))
                or item.get('url') != 'https://github.com/php/php-src/security/advisories/' + item['ghsa']
                or not isinstance(item.get('ranges'), list) or len(item['ranges']) > 100):
            raise ValueError('snapshot_record')
        for row in item['ranges']:
            if not isinstance(row.get('range'), str) or len(row['range']) > 512:
                raise ValueError('snapshot_range')
    return data


def refresh():
    """Official API first; own scheduled Pages artifact if API is unavailable."""
    try:
        payload, link = download(FEED_URL)
        data = {'checked_at': int(time.time()), 'source': FEED_URL, 'advisories': normalize(payload),
                'partial': 'rel="next"' in link}
    except Exception as exc:
        reason = str(exc) if isinstance(exc, ValueError) and re.fullmatch(r'HTTP_\d{3}', str(exc)) else type(exc).__name__
        LOG.warning('php_advisories_direct_unavailable reason=%s', reason)
        data, _ = download(MIRROR_URL)
        validate_snapshot(data)
    fd, temporary = tempfile.mkstemp(prefix='mgw-php-', dir=CACHE.parent)
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump(data, handle)
        os.replace(temporary, CACHE)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return data


def snapshot():
    try:
        if CACHE.stat().st_size > MAX_BYTES:
            return None
        data = json.loads(CACHE.read_text())
        validate_snapshot(data)
        return data
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def metadata(data=None, now=None):
    data = snapshot() if data is None else data
    checked = (data or {}).get('checked_at', 0)
    now = time.time() if now is None else now
    return {'checked_at': checked or None, 'stale': not checked or now - checked > 24 * 3600,
            'partial': bool((data or {}).get('partial')), 'source': FEED_URL,
            'count': len((data or {}).get('advisories', []))}


def start_refresh():
    stop = threading.Event()
    def loop():
        while not stop.is_set():
            current = snapshot()
            if not current or time.time() - current.get('checked_at', 0) >= INTERVAL:
                try:
                    data = refresh()
                    LOG.warning('php_advisories_refreshed count=%s partial=%s', len(data['advisories']), data['partial'])
                except Exception as exc:
                    # Keep last successful snapshot. No upstream body/credentials in logs.
                    LOG.warning('php_advisories_refresh_failed category=%s', type(exc).__name__)
            stop.wait(300)
    thread = threading.Thread(target=loop, daemon=True, name='php-advisories')
    thread.start()
    return stop


def affected(version, row):
    """Conservative supported range grammar; None means manual review, never safe.

    PHP publishes branch-specific '< X.Y.Z' rows without a lower bound: scope
    these rows to the fix's branch to avoid attributing 8.4 fixes to PHP 8.3.
    Explicit lower-bound conjunctions retain their stated range.
    """
    value = tuple(map(int, version.split('.')))
    if len(value) != 3:
        return None
    raw = row['range'].strip()
    match = re.fullmatch(r'<\s*(\d+\.\d+\.\d+)', raw)
    if match:
        upper = tuple(map(int, match[1].split('.')))
        return value[:2] == upper[:2] and value < upper
    alternatives = re.split(r'\s*\|\|\s*', raw)
    results = []
    for alternative in alternatives:
        terms = [t.strip() for t in alternative.split(',')]
        outcome = True
        for term in terms:
            match = re.fullmatch(r'(>=|<=|>|<|=)?\s*(\d+\.\d+\.\d+)', term)
            if not match:
                outcome = None
                break
            bound = tuple(map(int, match[2].split('.')))
            op = match[1] or '='
            outcome = outcome and {'>=': value >= bound, '<=': value <= bound,
                                   '>': value > bound, '<': value < bound, '=': value == bound}[op]
        results.append(outcome)
    return True if True in results else (None if None in results else False)


def match_advisories(observations, data):
    matches, unresolved = set(), False
    for observation in observations:
        version = observation.get('version')
        if not version or len(version.split('.')) != 3:
            continue
        for advisory in (data or {}).get('advisories', []):
            if not advisory['ranges']:
                unresolved = True
            for row in advisory['ranges']:
                result = affected(version, row)
                if result is True:
                    matches.add(advisory['id'])
                elif result is None:
                    unresolved = True
    return sorted(matches), unresolved
