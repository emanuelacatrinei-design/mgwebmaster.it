#!/usr/bin/env python3
"""Build a sanitized public PHP advisory snapshot; never print credentials/body."""
import json
import os
from pathlib import Path
import sys
import time
import urllib.request
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'site-check-api'))
from advisory_format import normalize

URL = 'https://api.github.com/repos/php/php-src/security-advisories?per_page=100'
MAX_BYTES = 4 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build():
    opener = urllib.request.build_opener(NoRedirect)
    headers = {'Accept': 'application/vnd.github+json', 'Accept-Encoding': 'identity',
               'User-Agent': 'MG-Webmaster-Advisory-Refresh'}
    token = os.environ.get('GH_TOKEN', '')
    if token:
        headers['Authorization'] = 'Bearer ' + token
    try:
        response = opener.open(urllib.request.Request(URL, headers=headers), timeout=20)
    except urllib.error.HTTPError as exc:
        if not token or exc.code not in (403, 404):
            raise
        # Public notices are also accessible without an integration token.
        headers.pop('Authorization', None)
        response = opener.open(urllib.request.Request(URL, headers=headers), timeout=20)
    with response:
        body = response.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            raise ValueError('advisory_body_limit')
        records = normalize(json.loads(body))
        data = {'source': URL, 'checked_at': int(time.time()), 'advisories': records,
                'partial': 'rel="next"' in response.headers.get('link', '')}
    target = Path(__file__).resolve().parents[1] / 'assets/security/php-advisories.json'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
    print('PHP advisory snapshot:', len(records), 'notices; partial:', data['partial'])


if __name__ == '__main__':
    try:
        build()
    except Exception as exc:
        print('PHP advisory snapshot failed:', type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
