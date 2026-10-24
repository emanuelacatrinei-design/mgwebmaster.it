import json
from unittest.mock import Mock

import pytest
from bs4 import BeautifulSoup

import advisory_feed as feed
from csp_analysis import findings, policies
from passive_security import php_evidence, php_report


def advisory(version='< 8.3.36'):
    return {'state': 'published', 'ghsa_id': 'GHSA-w8hw-w9fx-j79w', 'cve_id': 'CVE-2026-109618',
            'severity': 'critical', 'vulnerabilities': [{'package': {'ecosystem': 'php', 'name': 'php-src'},
            'vulnerable_version_range': version, 'patched_versions': '8.3.36'}]}


def test_normalize_drops_descriptions_and_withdrawn_notices():
    item = advisory()
    item['description'] = 'Untrusted content, never executed or displayed'
    data = feed.normalize([item, {**item, 'withdrawn_at': '2026-10-24'}])
    assert len(data) == 1 and 'description' not in str(data)
    assert data[0]['url'].startswith('https://github.com/php/php-src/security/advisories/')


@pytest.mark.parametrize('value', [[], {}, [{'state': 'published', 'ghsa_id': '../../x'}]])
def test_invalid_feed_does_not_become_clean_result(value):
    with pytest.raises(ValueError):
        feed.normalize(value)


@pytest.mark.parametrize('version,range_,expected', [
    ('8.3.35', '< 8.3.36', True), ('8.3.36', '< 8.3.36', False),
    ('8.2.34', '< 8.3.36', False), ('8.4.0', '< 8.3.36', False),
    ('8.3.4', '>= 8.3.0, < 8.3.5', True), ('8.3.5', '>= 8.3.0, < 8.3.5', False),
    ('8.3.35', '< 8.3.36 || >= 8.4.0, < 8.4.27', True),
    ('8.4.26', '< 8.3.36 || >= 8.4.0, < 8.4.27', True),
    ('8.3.35', '~8.3', None), ('8.3', '<8.3.36', None),
])
def test_supported_ranges_and_unknown_syntax(version, range_, expected):
    assert feed.affected(version, {'range': range_, 'patched': ''}) is expected


def test_live_advisory_can_flag_version_above_bundled_threshold():
    data = {'source': feed.FEED_URL, 'checked_at': 1792861200, 'partial': False,
            'advisories': feed.normalize([advisory('< 8.3.37')])}
    result = php_report(php_evidence({'server': 'PHP/8.3.36'}, 'https://example.com/'), feed=data)
    assert result['status'] == 'potentially_outdated'
    assert result['matched_advisories'] == ['CVE-2026-109618']
    assert 'possibili corrispondenze' in result['message']


def test_stale_and_partial_are_explicit():
    assert feed.metadata({'checked_at': 10, 'advisories': [], 'partial': True}, now=100000)['stale']
    assert feed.metadata({'checked_at': 10, 'advisories': [], 'partial': True}, now=100)['partial']
    assert feed.metadata({'checked_at': 100, 'advisories': []}, now=101)['stale'] is False


def test_failed_refresh_keeps_last_snapshot(tmp_path, monkeypatch):
    cache = tmp_path / 'feed.json'
    cache.write_text('previous')
    monkeypatch.setattr(feed, 'CACHE', cache)
    response = Mock(status_code=429)
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    session = Mock()
    session.get.return_value = response
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(feed.requests, 'Session', lambda: session)
    with pytest.raises(ValueError):
        feed.refresh()
    assert cache.read_text() == 'previous'
    assert session.get.call_args.kwargs['allow_redirects'] is False
    assert session.trust_env is False


def test_successful_refresh_writes_normalized_snapshot_atomically(tmp_path, monkeypatch):
    monkeypatch.setattr(feed, 'CACHE', tmp_path / 'feed.json')
    response = Mock(status_code=200, headers={})
    response.iter_content.return_value = [json.dumps([advisory()]).encode()]
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    session = Mock()
    session.get.return_value = response
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(feed.requests, 'Session', lambda: session)
    assert len(feed.refresh()['advisories']) == 1
    assert feed.snapshot()['advisories'][0]['id'] == 'CVE-2026-109618'
    assert not list(tmp_path.glob('mgw-php-*'))


def csp(header='', meta=''):
    soup = BeautifulSoup('<html><head>' + meta + '</head><body></body></html>', 'html.parser')
    return {i['code'] for i in findings(soup, {'content-security-policy': header}, 'https://example.com/')}


def test_weak_csp_is_not_treated_as_protection_just_because_present():
    assert {'sec_csp_inline', 'sec_csp_eval', 'sec_csp_sources', 'sec_csp_objects', 'sec_csp_base'} <= csp("script-src * 'unsafe-inline' 'unsafe-eval'")


def test_strict_meta_combines_with_permissive_http_header():
    strict = "script-src 'self' 'sha256-YWJj'; script-src-attr 'none'; object-src 'none'; base-uri 'self'"
    assert not csp("script-src * 'unsafe-inline' 'unsafe-eval'", '<meta http-equiv="Content-Security-Policy" content="' + strict + '">')


def test_nonce_overrides_inline_but_not_unsafe_eval():
    codes = csp("script-src 'nonce-YWJj' 'unsafe-inline' 'unsafe-eval'; object-src 'none'; base-uri 'none'")
    assert 'sec_csp_inline' not in codes and 'sec_csp_eval' in codes


def test_duplicate_directives_use_first_and_split_policies_intersect():
    assert 'sec_csp_inline' in csp("script-src 'unsafe-inline'; script-src 'none'")
    assert 'sec_csp_inline' not in csp("script-src 'unsafe-inline', script-src 'none'")


def test_script_element_policy_does_not_cover_event_handlers():
    assert 'sec_csp_inline' in csp("script-src 'unsafe-inline'; script-src-elem 'self'")
    assert 'sec_csp_inline' not in csp("script-src 'unsafe-inline'; script-src-elem 'self'; script-src-attr 'none'")


def test_meta_frame_ancestors_is_not_effective():
    soup = BeautifulSoup('<head><meta http-equiv="Content-Security-Policy" content="frame-ancestors none; script-src none"></head>', 'html.parser')
    assert 'frame-ancestors' not in policies(soup, {})[0]
    assert not policies(BeautifulSoup('<body><meta http-equiv="Content-Security-Policy" content="script-src none"></body>', 'html.parser'), {})


def test_sandbox_and_strict_dynamic_do_not_produce_broad_script_warning():
    assert 'sec_csp_sources' not in csp("script-src https: 'strict-dynamic'")
    assert not {'sec_csp_inline', 'sec_csp_sources', 'sec_csp_eval'} & csp("sandbox; script-src * 'unsafe-inline' 'unsafe-eval'")


def test_engine_accepts_meta_csp_as_enforced_protection(monkeypatch):
    import app
    import requests
    response = requests.Response()
    response.status_code = 200
    response.url = 'https://example.com/'
    response.encoding = 'utf-8'
    engine = app.Engine(app.Budget())
    html = b"<head><meta http-equiv=Content-Security-Policy content=\"script-src 'self'; script-src-attr 'none'; object-src 'none'; base-uri 'self'\"></head><body><h1>Example</h1></body>"
    monkeypatch.setattr(engine, 'fetch', lambda *a, **kw: (response, html, 10))
    result = engine.audit_page(response.url)
    assert not any(i['code'] == 'sec_content-security-policy' or i['code'].startswith('sec_csp_') for i in result['issues'])


def test_late_meta_reports_resources_that_may_precede_protection():
    assert 'sec_csp_late_meta' in csp('', "<script src='/x.js'></script><meta http-equiv='Content-Security-Policy' content=\"script-src 'self'\">")


def test_scheduled_mirror_fallback_preserves_original_download_time(tmp_path, monkeypatch):
    import time
    original = int(time.time()) - 3600
    data = {'source': feed.FEED_URL, 'checked_at': original, 'partial': False,
            'advisories': feed.normalize([advisory()])}
    monkeypatch.setattr(feed, 'CACHE', tmp_path / 'feed.json')
    calls = []
    def download(url):
        calls.append(url)
        if url == feed.FEED_URL:
            raise ValueError('HTTP_403')
        assert url == feed.MIRROR_URL
        return data, ''
    monkeypatch.setattr(feed, 'download', download)
    result = feed.refresh()
    assert result['checked_at'] == original
    assert calls == [feed.FEED_URL, feed.MIRROR_URL]
    assert feed.snapshot() == data


def test_snapshot_rejects_other_sources_and_future_dates():
    import time
    for change in [{'source': 'https://attacker.example/'}, {'checked_at': int(time.time()) + 10000}]:
        data = {'source': feed.FEED_URL, 'checked_at': int(time.time()),
                'advisories': feed.normalize([advisory()]), **change}
        with pytest.raises(ValueError):
            feed.validate_snapshot(data)
