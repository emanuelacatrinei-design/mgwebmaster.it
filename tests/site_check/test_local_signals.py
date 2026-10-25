import json

import pytest
from bs4 import BeautifulSoup

import app
from local_signals import extract, summarize_local
from report_model import summarize
from security import AuditError


def page(html='', url='https://example.com/', status=200):
    return {'url': url, 'status_code': status, 'local': extract(BeautifulSoup(html, 'html.parser'))}


def report(html):
    return summarize_local([page(html)])


@pytest.mark.parametrize('html,key,points', [
    ('<a href="tel:+393715495881">Call</a>', 'phone', 25),
    ('<a href="https://wa.me/393715495881">WhatsApp</a>', 'phone', 25),
    ('<a href="https://api.whatsapp.com/send?phone=%2B40722123456">Contact</a>', 'phone', 25),
    ('<p>Telefon: +40 722 123 456</p>', 'phone', 25),
    ('<p>via Roma 12</p>', 'address', 25),
    ('<p>Strada Ștefan 12</p>', 'address', 25),
    ('<footer>Perugia (PG)</footer>', 'locality', 10),
    ('<p>Oraș: București</p>', 'locality', 10),
    ('<a href="https://www.google.com/maps/place/Perugia">Map</a>', 'maps', 15),
    ('<iframe src="https://www.google.ro/maps/embed?pb=x"></iframe>', 'maps', 15),
    ('<script type="application/ld+json">{"@type":"Organization"}</script>', 'schema', 5),
    ('<script type="application/ld+json">{"@type":"LocalBusiness"}</script>', 'schema', 25),
])
def test_each_observable_signal(html, key, points):
    r = report(html)
    assert r['score'] == points
    assert r['checks'][key]['status'] == 'detected'
    assert r['checks'][key]['evidence'][0]['page'] == 'https://example.com/'
    assert sum(c['status'] == 'detected' for c in r['checks'].values()) == 1


@pytest.mark.parametrize('html', [
    '<p>1234567890 2026-10-25 VAT 12345678901</p>',
    '<p>La strada per migliorare. Invia una richiesta via email. Product (ID)</p>',
    '<a href="https://google.com.evil.example/maps">Map</a>',
    '<a href="https://evil.example/?url=google.com/maps">Map</a>',
    '<a href="https://wa.me/not-a-phone">WhatsApp</a>',
    '<a href="tel:1111111111">Phone</a>',
    '<script type="application/ld+json">{"@type":"Product","sku":"12345678901"}</script>',
])
def test_generic_numbers_words_and_spoofed_links_are_not_evidence(html):
    r = report(html)
    assert r['score'] == 0
    assert all(c['status'] == 'not_detected' for c in r['checks'].values())


def test_graph_multitype_nested_and_referenced_address():
    data = {'@graph': [
        {'@type': ['Organization', 'ProfessionalService'], 'telephone': '+40 722 123 456',
         'address': {'@id': '#address'}},
        {'@id': '#address', '@type': 'PostalAddress', 'streetAddress': 'Strada Ștefan 12',
         'addressLocality': 'București'}]}
    r = report('<script type="application/ld+json">' + json.dumps(data) + '</script><a href="https://maps.app.goo.gl/example">Map</a>')
    assert r['score'] == 100
    assert r['checks']['schema']['points'] == 25  # no double counting Organization
    assert all(c['status'] == 'detected' for c in r['checks'].values())


def test_schema_url_and_root_array():
    r = report('<script type="application/ld+json">[{"nested":{"@type":["https://schema.org/LocalBusiness","Organization"]}}]</script>')
    assert r['score'] == 25


def test_malformed_schema_is_unavailable_not_absent():
    r = report('<script type="application/ld+json">{broken</script>')
    assert r['checks']['schema']['status'] == 'not_evaluated'
    assert r['checks']['schema']['points'] is None
    assert r['partial'] and r['measured_max_points'] == 75
    assert r['score'] == 0


def test_failed_and_partial_scans_distinguish_zero_from_nd():
    broken = page('<a href="tel:+40722123456">Call</a>', status=503)
    r = summarize_local([broken])
    assert r['score'] is None
    assert all(c['status'] == 'not_evaluated' for c in r['checks'].values())
    good = page('', 'https://example.com/contact')
    r = summarize_local([broken, good], ['https://example.com/timeout'])
    assert r['score'] == 0 and r['partial']
    assert r['checked_pages'] == [good['url']]
    assert r['unchecked_pages'] == ['https://example.com/timeout', broken['url']]
    assert summarize_local([])['score'] is None


def test_engine_tracks_failed_urls_and_returns_local_score_in_general_mean(monkeypatch):
    engine = app.Engine(app.Budget())
    good = {**page('<a href="tel:+40722123456">Call</a>'), 'issues': [], 'php': [], 'cta': True,
            'links': ['https://example.com/timeout', 'https://example.com/broken']}
    def audit(url):
        if url.endswith('timeout'):
            raise AuditError('Unavailable')
        if url.endswith('broken'):
            return {**good, 'url': url, 'status_code': 503, 'links': []}
        return good
    monkeypatch.setattr(engine, 'audit_page', audit)
    monkeypatch.setattr(engine, 'probe', lambda *a: 200)
    r = engine.audit(good['url'])
    assert r['scores']['local'] == 25
    assert r['overall_score'] == 85  # (4*100+25)/5
    assert r['local_signals']['partial']
    assert len(r['local_signals']['unchecked_pages']) == 2
    assert r['scoring']['section_weights']['local'] == 1
    assert 'local' not in r['scoring']['excluded_sections']


def test_local_zero_is_included_but_unknown_local_is_excluded():
    assert summarize({'seo': 100, 'security': 100, 'local': 0}, [])['technical_score'] == 67
    assert summarize({'seo': 100, 'security': 100, 'local': None}, [])['technical_score'] == 100
