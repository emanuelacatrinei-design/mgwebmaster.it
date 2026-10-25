from unittest.mock import Mock

import requests

import app
from passive_security import localize_report
from report_model import summarize, group_issues


def issue(code='h1', severity='high', area='Contenuti', page='https://example.com/a', title='Same finding'):
    return dict(code=code, severity=severity, area=area, page=page, title=title, message='Evidence')


def test_perfect_measured_sections_and_unavailable_local():
    result=summarize({'seo':100,'performance':100,'content':100,'security':100,'local':None},[])
    assert result['technical_score']==100
    assert result['score_model']=='technical_v4'
    assert result['scoring']['excluded_sections']==['local']
    assert 'core_web_vitals' in result['not_evaluated']


def test_agreed_security_penalty_and_missing_values():
    assert summarize({'seo':80,'performance':70,'security':40},[])['technical_score']==51
    assert summarize({'seo':80,'performance':None,'security':60},[])['technical_score']==62
    result=summarize({'seo':80,'performance':None,'security':None},[])
    assert result['technical_score']==20
    assert result['scoring']['mean']==40
    assert result['scoring']['security_penalty']==20
    assert result['scoring']['security_assumed_zero'] is True
    assert 'security' not in result['scoring']['excluded_sections']
    assert result['basic_checks']['security']['status']=='not_evaluated'


def test_real_zero_is_included_and_all_missing_is_prudential_zero():
    result=summarize({'seo':80,'performance':70,'security':0},[])
    assert result['technical_score']==30
    assert result['scoring']['security_assumed_zero'] is False
    assert summarize({},[])['technical_score']==0
    # Invalid values cannot masquerade as measured scores or produce NaN totals.
    assert summarize({'seo':float('nan'),'security':float('inf')},[])['technical_score']==0


def test_insufficient_or_http_error_pages_do_not_receive_perfect_scores():
    broken={'status_code':503,'issues':[issue('http_error',area='SEO tecnica')]}
    assert app.Engine.score('Sicurezza',[broken]) is None
    assert app.Engine.score('SEO tecnica',[broken]) is None
    assert app.Engine.score('Contenuti',[]) is None


def test_global_findings_are_included_without_diluting_across_pages():
    findings=group_issues([issue('sitemap',area='SEO tecnica'),issue('cta'),issue('h1',page='https://example.com/b')])
    result=summarize({},findings)
    assert result['basic_checks']['seo']['findings']==1
    assert result['basic_checks']['content']['affected_pages']==2


def test_security_priority_uses_security_evidence_only():
    assert summarize({},[issue()])['security_priority']=='low'
    assert summarize({},[issue(area='Sicurezza')])['security_priority']=='high'
    assert summarize({},[issue(area='Sicurezza',severity='medium')])['security_priority']=='medium'


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



def test_global_penalties_are_applied_once_and_local_remains_unavailable(monkeypatch):
    engine=app.Engine(app.Budget())
    page={'url':'https://example.com/','status_code':200,'issues':[], 'links':[], 'php':[], 'cta':False,
          'local':{'phone':False,'address':False,'maps':False,'schema':[]}}
    monkeypatch.setattr(engine,'audit_page',lambda *a:page)
    monkeypatch.setattr(engine,'probe',lambda *a:404)
    result=engine.audit(page['url'])
    assert result['scores']=={'seo':94,'performance':100,'security':100,'content':93,'local':None}
    assert result['overall_score']==97
    assert result['score_model']=='technical_v4'
