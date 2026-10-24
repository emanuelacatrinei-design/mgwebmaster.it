from datetime import date
from unittest.mock import Mock

import pytest
import requests
from bs4 import BeautifulSoup

import app
from passive_security import php_evidence, php_report, passive_findings, localize_report

TODAY = date(2026, 10, 24)


def report(banner, **kwargs):
    return php_report(php_evidence({'x-powered-by': banner}, 'https://example.com/'), today=TODAY, **kwargs)


@pytest.mark.parametrize('version,status', [
    ('8.2.34', 'potentially_outdated'), ('8.2.35', 'reference_met'),
    ('8.3.35', 'potentially_outdated'), ('8.3.36', 'reference_met'),
    ('8.4.26', 'potentially_outdated'), ('8.4.27', 'reference_met'),
    ('8.5.11', 'potentially_outdated'), ('8.5.12', 'reference_met'),
    ('8.5.13', 'reference_met'), ('7.4.33', 'unsupported'),
    ('8.1.34', 'unsupported'), ('8.6.0RC4', 'review_required'),
    ('8.5.12RC1', 'review_required'), ('8.3', 'review_required'),
    ('9.0.0', 'review_required'), ('8.3.35-1ubuntu99', 'potentially_outdated'),
])
def test_version_boundaries(version, status):
    result = report('PHP/' + version)
    assert result['status'] == status
    assert result['versions'] == [version.split('-')[0].split('RC')[0]]
    assert not result['rules_stale']
    assert 'patch' in result['message']


def test_unknown_is_not_php_absent_or_safe():
    result = php_report([], today=TODAY)
    assert result['status'] == 'not_observable'
    assert result['versions'] == [] and not result['cves']
    assert 'né l’assenza' in result['message']


def test_php_paths_cookies_and_bare_banner_are_only_indirect():
    for headers, url, cookies in [({}, 'https://example.com/index.php', []),
                                  ({}, 'https://example.com/', ['PHPSESSID=secret; Secure']),
                                  ({'x-powered-by': 'PHP'}, 'https://example.com/', [])]:
        result = php_report(php_evidence(headers, url, cookies), today=TODAY)
        assert result['status'] == 'not_observable'
        assert not result['versions']
        assert 'secret' not in str(result)


def test_conflicting_banners_keep_worst_and_evidence():
    obs = php_evidence({'server': 'Apache PHP/8.2.34', 'x-powered-by': 'PHP/8.5.12'}, 'https://example.com/')
    result = php_report(obs, today=TODAY)
    assert result['status'] == 'potentially_outdated'
    assert len(result['versions']) == 2
    assert {o['source'] for o in obs} == {'server', 'x-powered-by'}


def test_old_rules_never_silently_claim_current_security():
    result = php_report(php_evidence({'server': 'PHP/8.5.12'}, 'https://example.com/'), today=date(2026, 12, 1))
    assert result['rules_stale']
    assert 'Regole da aggiornare' in result['message']


def findings(html='', cookies=(), url='https://example.com/'):
    return passive_findings(BeautifulSoup(html, 'html.parser'), {}, url, cookies)


def test_mixed_scripts_and_insecure_forms_resolve_base():
    result = findings('<base href="http://example.com/"><script src="a.js"></script><form action="send"></form>')
    assert {i['code'] for i in result} == {'sec_mixed_active', 'sec_form_http'}
    assert not findings('<script src="//example.com/a.js"></script><form action="/send"></form>')


def test_non_session_cookies_not_accused_and_values_never_retained():
    assert not findings(cookies=['analytics=secret'])
    assert not findings(cookies=['PHPSESSID=secret; Secure; HttpOnly; SameSite=Lax'])
    result = findings(cookies=['PHPSESSID=very-secret; HttpOnly'])
    assert result[0]['code'] == 'sec_session_cookie'
    assert 'very-secret' not in str(result)


def test_error_text_is_evidence_not_confirmed_exploit():
    assert findings('Warning: include() in /var/www/index.php on line 42')[0]['code'] == 'sec_php_errors'
    assert not findings('Aggiorna il tuo sito PHP')


def test_api_localizes_new_php_and_findings_without_touching_old_fields():
    data = {'php': report('PHP/8.3.35'), 'issues': findings('<form action="http://example.com/send"></form>')}
    localized = localize_report(data, 'ro')
    assert 'Versiunea declarată' in localized['php']['message']
    assert localized['issues'][0]['title'] == 'Formular cu destinație HTTP'
    assert 'title_ro' not in str(localized)


def test_engine_integration_includes_php_penalty_and_report(monkeypatch):
    response = requests.Response()
    response.status_code = 200
    response.url = 'https://example.com/'
    response.encoding = 'utf-8'
    response.headers.update({'X-Powered-By': 'PHP/8.3.35'})
    engine = app.Engine(app.Budget())
    monkeypatch.setattr(engine, 'fetch', lambda *a, **kw: (response, b'<h1>Example</h1>', 10))
    monkeypatch.setattr(engine, 'probe', lambda *a: 200)
    result = engine.audit('https://example.com/')
    assert result['php']['status'] == 'potentially_outdated'
    assert result['scores']['security'] < 100
    # PHP remains visible in its dedicated report even with more than eight findings.
    assert '8.3.35' in result['php']['title']


def test_support_expiry_is_checked_at_scan_time():
    observation = php_evidence({'server': 'PHP/8.2.35'}, 'https://example.com/')
    assert php_report(observation, today=date(2027, 1, 1))['status'] == 'unsupported'
