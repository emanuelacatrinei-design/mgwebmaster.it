from unittest.mock import Mock

import requests

import app
from passive_security import localize_report
from report_model import summarize, group_issues


def issue(code='h1', severity='high', area='Contenuti', page='https://example.com/a', title='Same finding'):
    return dict(code=code, severity=severity, area=area, page=page, title=title, message='Evidence')


def test_technical_quality_is_not_capped_by_number_of_issues_or_security_score():
    scores={'seo':88, 'performance':86, 'content':90, 'local':80, 'security':26}
    result=summarize(scores,[issue(str(n)) for n in range(6)])
    assert result['technical_score']==87
    assert result['security_priority']=='high'
    assert result['score_model']=='technical_v2'
    assert 'security' not in result['technical_weights']
    assert abs(sum(result['technical_weights'].values())-1)<1e-9


def test_seo_alerts_cannot_raise_security_priority():
    result=summarize({'seo':10, 'performance':100, 'content':10, 'local':None, 'security':100},[issue(str(n)) for n in range(10)])
    assert result['security_priority']=='low'


def test_php_security_alert_stays_high_even_with_perfect_technical_score():
    scores={k:100 for k in ('seo','performance','content','local','security')}
    result=summarize(scores,[issue('sec_php_version',area='Sicurezza')])
    assert result['technical_score']==100
    assert result['security_priority']=='high'


def test_missing_dimensions_are_excluded_and_all_missing_is_unknown():
    assert summarize({'seo':80,'performance':None,'local':None,'content':None},[])['technical_score']==80
    assert summarize({'security':10},[])['technical_score'] is None


def test_group_keeps_every_unique_url_and_different_evidence():
    items=[issue(page='https://example.com/a'),issue(page='https://example.com/b'),issue(page='https://example.com/a'),issue(title='Different version')]
    grouped=group_issues(items)
    assert len(grouped)==2
    assert grouped[0]['pages']==['https://example.com/a','https://example.com/b']
    assert grouped[0]['occurrences']==2


def response(html):
    r=requests.Response();r.status_code=200;r.url='https://example.com/';r.encoding='utf-8'
    r.headers.update({'strict-transport-security':'max-age=31536000','content-security-policy':"script-src 'self'; object-src 'none'; base-uri 'self'",'x-content-type-options':'nosniff','permissions-policy':'camera=()','referrer-policy':'no-referrer'})
    return r,html.encode(),10


def test_h1_medium_and_noindex_contextual_with_no_automatic_penalty(monkeypatch):
    html='<head><title>Example services and support</title><meta name="robots" content="noindex,follow"></head><body>'+('Useful content '*200)+'</body>'
    engine=app.Engine(app.Budget())
    monkeypatch.setattr(engine,'fetch',lambda *a,**kw:response(html))
    page=engine.audit_page('https://example.com/')
    h1=next(i for i in page['issues'] if i['code']=='h1')
    noindex=next(i for i in page['issues'] if i['code']=='noindex')
    assert h1['severity']=='medium' and noindex['severity']=='low'
    assert 'intenzionale' in noindex['message']
    assert app.Engine.score('SEO tecnica',[page])==app.Engine.score('SEO tecnica',[{**page,'issues':[i for i in page['issues'] if i['code']!='noindex']}])
    translated=localize_report({'issues':[h1,noindex]},'ro')
    assert 'intenționată' in translated['issues'][1]['message']


def test_report_preserves_all_groups_beyond_eight(monkeypatch):
    engine=app.Engine(app.Budget())
    page={'url':'https://example.com/','issues':[issue(str(n)) for n in range(12)],'links':[], 'php':[], 'cta':True,'local':{'phone':False,'address':False,'maps':False,'schema':[]}}
    monkeypatch.setattr(engine,'audit_page',lambda *a:page)
    monkeypatch.setattr(engine,'probe',lambda *a:200)
    result=engine.audit(page['url'])
    assert len(result['issues'])==12
    assert all('pages' in i for i in result['issues'])
    assert result['overall_score']==result['technical_score']
