"""Conservative CSP3 observations, not a complete browser-policy evaluator."""
import re


def policies(soup, headers):
    result = []
    for raw in str(headers.get('content-security-policy', '')).split(','):
        if raw.strip():
            result.append(parse(raw))
    if soup.head:
        for meta in soup.head.find_all('meta'):
            if str(meta.get('http-equiv', '')).lower() == 'content-security-policy':
                policy = parse(meta.get('content', ''))
                for unsupported in ('frame-ancestors', 'sandbox', 'report-uri'):
                    policy.pop(unsupported, None)
                result.append(policy)
    return result


def parse(raw):
    result = {}
    for directive in str(raw)[:65536].split(';'):
        parts = directive.split()
        if parts:
            # Browsers honor the first occurrence; source URL case is retained.
            result.setdefault(parts[0].lower(), parts[1:])
    return result


def sources(policy, kind):
    if "sandbox" in policy and "allow-scripts" not in policy["sandbox"]:
        return []
    for key in ((kind, 'script-src', 'default-src') if kind != 'script-src' else ('script-src', 'default-src')):
        if key in policy:
            return policy[key]
    return None


def trust_token(values):
    return any(re.fullmatch(r"'(?:nonce-[A-Za-z0-9+/_-]+={0,2}|sha(?:256|384|512)-[A-Za-z0-9+/_-]+={0,2})'", v) for v in values or [])


def allows_inline(policy, kind):
    values = sources(policy, kind)
    if values is None:
        return True
    return "'unsafe-inline'" in values and not trust_token(values) and "'strict-dynamic'" not in values


def findings(soup, headers, url):
    enforced = policies(soup, headers)
    if not enforced:
        return []
    issues = []
    def add(code, severity, title, msg, title_ro, msg_ro):
        issues.append(dict(code=code, area='Sicurezza', severity=severity, title=title, message=msg,
                           title_ro=title_ro, message_ro=msg_ro, page=url))
    if soup.head and not str(headers.get('content-security-policy', '')).strip():
        earlier_script = False
        late = False
        for node in soup.head.descendants:
            if getattr(node, 'name', None) == 'script':
                earlier_script = True
            if getattr(node, 'name', None) == 'meta' and str(node.get('http-equiv', '')).lower() == 'content-security-policy' and earlier_script:
                late = True
        if late:
            add('sec_csp_late_meta', 'medium', 'CSP nell’HTML dopo uno script', 'La policy nell’HTML arriva dopo uno script e non è stato rilevato un header CSP. Le risorse precedenti potrebbero non essere coperte: anticipare la policy o configurarla nell’header HTTP.', 'CSP din HTML apare după un script', 'Politica din HTML apare după un script și nu a fost identificat un antet CSP. Resursele anterioare pot rămâne neacoperite: mută politica mai devreme sau configureaz-o în antetul HTTP.')
    if any(all(allows_inline(p, kind) for p in enforced) for kind in ('script-src-elem', 'script-src-attr')):
        add('sec_csp_inline', 'medium', 'CSP: script inline non sufficientemente limitati', 'Le policy rilevate non bloccano tutti gli script inline o i gestori di eventi. Verificare nonce, hash e script-src-attr; il controllo è indicativo e non dimostra una vulnerabilità sfruttabile.', 'CSP: scripturile inline nu sunt limitate suficient', 'Politicile identificate nu blochează toate scripturile inline sau gestionarele de evenimente. Verifică nonce, hash și script-src-attr; acest control este orientativ și nu dovedește o vulnerabilitate exploatabilă.')
    if all(sources(p, 'script-src') is None or "'unsafe-eval'" in sources(p, 'script-src') for p in enforced):
        add('sec_csp_eval', 'medium', 'CSP: esecuzione dinamica del codice non bloccata', 'Le policy rilevate non bloccano eval e funzioni simili. Verificare se unsafe-eval è necessario.', 'CSP: execuția dinamică a codului nu este blocată', 'Politicile identificate nu blochează eval și funcții similare. Verifică dacă unsafe-eval este necesar.')
    def broad(p):
        values = sources(p, 'script-src-elem')
        if values is None:
            return True
        if "'strict-dynamic'" in values:
            return False
        return any(v in {'*', 'http:', 'https:', 'data:'} for v in values)
    if all(broad(p) for p in enforced):
        add('sec_csp_sources', 'medium', 'CSP: origini degli script troppo ampie', 'Nelle policy rilevate manca una restrizione efficace comune sulle origini degli script. Ridurre wildcard e schemi generici dopo aver verificato le risorse necessarie.', 'CSP: surse prea largi pentru scripturi', 'Politicile identificate nu oferă o restricție comună eficientă asupra surselor scripturilor. Limitează wildcard-urile și schemele generale după verificarea resurselor necesare.')
    if not any(p.get('object-src', p.get('default-src')) == ["'none'"] for p in enforced):
        add('sec_csp_objects', 'low', 'CSP: oggetti incorporati da limitare', 'Non è stato rilevato un blocco completo con object-src oppure default-src impostato a none. Valutarlo se il sito non usa oggetti incorporati.', 'CSP: obiectele încorporate trebuie limitate', 'Nu a fost identificată o blocare completă prin object-src sau default-src setat la none. Ia în considerare această protecție dacă site-ul nu folosește obiecte încorporate.')
    if not any(p.get('base-uri') and not any(v in {'*', 'http:', 'https:', 'data:'} for v in p['base-uri']) for p in enforced):
        add('sec_csp_base', 'low', 'CSP: indirizzo base della pagina non limitato', 'Non è stata rilevata una restrizione base-uri. Valutare self o none per limitare la modifica dell’indirizzo base dei collegamenti.', 'CSP: adresa de bază a paginii nu este limitată', 'Nu a fost identificată o restricție base-uri. Ia în considerare self sau none pentru a limita modificarea adresei de bază a legăturilor.')
    return issues
