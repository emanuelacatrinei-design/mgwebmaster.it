"""Generate real API/legacy pairs for the JavaScript presentation contract tests."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'site-check-api'))
import app
from bs4 import BeautifulSoup
from local_signals import extract
from passive_security import localize_report
from report_model import summarize, group_issues


def fixture(html='', status=200):
    url = 'https://example.com/'
    return {'url': url, 'status_code': status, 'issues': [], 'links': [], 'php': [],
            'cta': True, 'local': extract(BeautifulSoup(html, 'html.parser'))}


reports = []
for language in ('it', 'ro'):
    for html, status in [('', 200), ('<a href="tel:+40722123456">Call</a>', 200), ('', 503)]:
        engine = app.Engine(app.Budget())
        p = fixture(html, status)
        engine.audit_page = lambda url: p
        engine.probe = lambda url: 200
        result = localize_report(engine.audit(p['url']), language)
        reports.append({'language': language, 'report': result})

pairs = []
# Deterministic combinations guard against drift of the legacy bridge and API.
for count in range(1, 6):
    for scenario in range(8):
        pages = []
        for n in range(count):
            p = fixture(status=503 if scenario == 7 and n == 0 else 200)
            p['url'] = f'https://example.com/{n}'
            for code, area, severity in [
                ('title_missing', 'SEO tecnica', 'high'),
                ('h1', 'Contenuti', 'medium'),
                ('sec_content-security-policy', 'Sicurezza', 'medium'),
                ('dims', 'Prestazioni', 'medium'),
                ('server', 'Prestazioni', 'high'),
                ('noindex', 'SEO tecnica', 'low'),
            ][:scenario]:
                if n % 2 == 0:
                    p['issues'].append(dict(code=code, area=area, severity=severity,
                                            title=code, message='Evidence', page=p['url']))
            if p['status_code'] >= 400:
                p['issues'].append(dict(code='http_error', area='SEO tecnica', severity='high',
                                        title='HTTP 503', message='Error', page=p['url']))
            pages.append(p)
        issues = group_issues([i for p in pages for i in p['issues']])
        scores = {k: app.Engine.score(a, pages) for k, a in
                  {'seo': 'SEO tecnica', 'performance': 'Prestazioni', 'content': 'Contenuti', 'security': 'Sicurezza'}.items()}
        scores['local'] = None  # v3 has no local evidence: never infer it
        expected = {'scores': scores, **summarize(scores, issues)}
        old = {'score_model': 'basic_checks_v3', 'pages_checked': count,
               'final_url': pages[0]['url'], 'issues': issues, 'basic_checks': expected['basic_checks']}
        pairs.append({'old': old, 'expected': expected})
print(json.dumps({'reports': reports, 'pairs': pairs}))
