"""Explainable report model: technical quality and security remain separate."""
MODEL = 'basic_checks_v3'
AREAS = {'seo': 'SEO tecnica', 'performance': 'Prestazioni',
         'security': 'Sicurezza', 'content': 'Contenuti', 'local': 'Locale'}


def summarize(scores, issues):
    # No numerical quality estimate can be justified by this limited scan.
    security = [i for i in issues if i['area'] == 'Sicurezza']
    priority = ('high' if any(i['severity'] == 'high' for i in security) else
                'medium' if any(i['severity'] == 'medium' for i in security) else 'low')
    areas = {}
    for key, area in AREAS.items():
        findings = [i for i in issues if i['area'] == area]
        areas[key] = {'findings': len(findings),
                      'affected_pages': len({url for i in findings for url in i.get('pages', [i.get('page')]) if url}),
                      'status': 'not_evaluated' if key == 'local' else 'findings' if findings else 'none_detected'}
    return {'technical_score': None, 'security_priority': priority,
            'score_model': MODEL, 'technical_weights': {}, 'basic_checks': areas,
            'not_evaluated': ['content_quality', 'core_web_vitals', 'local_competitiveness', 'ranking_potential']}


def group_issues(issues):
    grouped = {}
    for issue in issues:
        key = (issue['code'], issue['title'], issue['message'])
        if key not in grouped:
            grouped[key] = {**issue, 'pages': []}
        if issue.get('page') and issue['page'] not in grouped[key]['pages']:
            grouped[key]['pages'].append(issue['page'])
    result = list(grouped.values())
    for item in result:
        item['occurrences'] = len(item['pages'])
    order = {'high': 0, 'medium': 1, 'low': 2}
    result.sort(key=lambda i: order.get(i['severity'], 3))
    return result


RO_ISSUES = {
 'title_missing': ('Titlu SEO lipsă', 'Pagina nu are un titlu SEO lizibil.'),
 'title_length': ('Titlul SEO trebuie verificat', 'Lungimea titlului SEO merită verificată.'),
 'description': ('Descriere meta lipsă', 'Nu a fost identificată o descriere meta.'),
 'h1_multiple': ('Mai multe titluri H1 identificate', 'Verifică ierarhia titlurilor H1 din pagină.'),
 'thin': ('Conținut foarte scurt', 'Pagina conține puțin text util în comparație cu o pagină obișnuită de servicii.'),
 'canonical': ('Adresă canonical neidentificată', 'Nu a fost identificată o adresă URL canonical.'),
 'alt': ('Atribute ALT incomplete', 'Mai multe imagini nu au un atribut ALT.'),
 'dims': ('Dimensiuni ale imaginilor nedeclarate', 'Multe imagini nu declară width și height.'),
 'server': ('Răspuns lent al serverului în acest test', 'Răspunsul inițial a fost lent în timpul testului; sunt necesare măsurători repetate pentru confirmare.'),
 'html_weight': ('Document HTML foarte mare', 'Documentul HTML are o dimensiune neobișnuit de mare.'),
 'scripts': ('Numeroase scripturi', 'Pagina încarcă numeroase scripturi.'),
 'styles': ('Numeroase foi de stil', 'Pagina folosește numeroase foi de stil.'),
 'robots_txt': ('robots.txt neidentificat', 'Scanarea nu a identificat un fișier robots.txt accesibil.'),
 'sitemap': ('Sitemap XML neidentificat', 'Nu a fost identificat un fișier sitemap.xml standard; verifică dacă există la o altă adresă.'),
 'cta': ('Contactul nu este evident', 'Paginile verificate nu prezintă un îndemn de contact ușor de recunoscut.'),
 'https': ('HTTPS nu este activ', 'Pagina nu folosește HTTPS.'),
}


def romanian_issue(item):
    if 'title_ro' in item:
        return
    code = item.get('code', '')
    if code in RO_ISSUES:
        item['title_ro'], item['message_ro'] = RO_ISSUES[code]
    elif code == 'http_error':
        item['title_ro'] = item['title']
        item['message_ro'] = 'Pagina returnează o eroare HTTP.'
    elif code.startswith('sec_') and item.get('title', '').endswith(' non rilevato'):
        item['title_ro'] = item['title'].removesuffix(' non rilevato') + ' neidentificat'
        item['message_ro'] = 'O protecție HTTP recomandată nu a fost identificată; configurația trebuie verificată.'
