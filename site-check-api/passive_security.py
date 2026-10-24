"""Passive observations only: no exploit payloads, phpinfo probes or extra requests.

Rules reviewed 2026-10-24 against PHP's advisories/support calendar. Version
banners are untrusted evidence, not proof of the running binary or its patches.
"""
import re
from datetime import date
from http.cookies import SimpleCookie, CookieError
from urllib.parse import urljoin, urlparse

REVIEWED = date(2026, 10, 24)
SOURCES = ['https://www.php.net/archive/2026.php#2026-10-21-5',
           'https://www.php.net/supported-versions.php',
           'https://cert.europa.eu/publications/security-advisories/2026-018/']
FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
SUPPORT_END = {(8, n): date(2024 + n, 12, 31) for n in range(2, 6)}
CVES = ['CVE-2026-109618', 'CVE-2026-109619']
VERSION = re.compile(r'(?i)(?<![\w])PHP\s*/\s*(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)([^\s,;()]*)')


def php_evidence(headers, url, cookie_headers=()):
    observations = []
    for name in ('x-powered-by', 'server'):
        value = str(headers.get(name, ''))[:2048]
        for match in list(VERSION.finditer(value))[:8]:
            observations.append({'version': match[1], 'suffix': match[2][:64], 'source': name, 'page': url})
        if not observations and re.search(r'(?i)\bPHP\b', value):
            observations.append({'version': None, 'suffix': '', 'source': name, 'page': url})
    # Weak clues must never be promoted to a known runtime/version.
    if not observations and (urlparse(url).path.lower().endswith('.php') or
                             any(re.match(r'(?i)\s*PHPSESSID=', c) for c in cookie_headers)):
        observations.append({'version': None, 'suffix': '', 'source': 'indirect', 'page': url})
    return observations


def php_report(observations, today=None):
    today = today or date.today()
    versions = sorted({o['version'] for o in observations if o['version']})
    status = 'not_observable'
    title = 'Versione PHP non rilevabile'
    title_ro = 'Versiunea PHP nu poate fi identificată'
    message = 'Il server non espone una versione PHP verificabile. Questo non dimostra né l’assenza di PHP né la sicurezza del sito.'
    message_ro = 'Serverul nu expune o versiune PHP verificabilă. Acest lucru nu dovedește nici absența PHP, nici securitatea site-ului.'
    ranks = {'reference_met': 0, 'review_required': 1, 'potentially_outdated': 2, 'unsupported': 3}
    states = []
    for o in observations:
        if not o['version']:
            continue
        parts = tuple(map(int, o['version'].split('.')))
        branch = parts[:2]
        if branch < (8, 2) or (branch in SUPPORT_END and today > SUPPORT_END[branch]):
            states.append('unsupported')
        elif branch not in FIXED or len(parts) != 3 or re.search(r'(?i)(?:alpha|beta|RC|dev)', o['suffix']):
            states.append('review_required')
        elif parts[2] < FIXED[branch]:
            states.append('potentially_outdated')
        else:
            states.append('reference_met')
    if states:
        status = max(states, key=ranks.get)
        title, title_ro = 'PHP: ' + ', '.join(versions), 'PHP: ' + ', '.join(versions)
        messages = {
            'unsupported': ('Versione dichiarata fuori dal supporto ufficiale PHP. Chiedere subito all’hosting conferma delle patch del fornitore e pianificare l’aggiornamento.', 'Versiunea declarată nu mai beneficiază de suport oficial PHP. Cere imediat furnizorului de găzduire confirmarea corecțiilor aplicate și planifică actualizarea.'),
            'potentially_outdated': ('Versione dichiarata precedente alle correzioni delle due falle del 21 ottobre 2026: potenzialmente a rischio. Verificare subito le patch con l’hosting e aggiornare se mancanti.', 'Versiunea declarată este anterioară corecțiilor pentru cele două vulnerabilități din 21 octombrie 2026: risc potențial. Verifică imediat corecțiile cu furnizorul de găzduire și actualizează dacă lipsesc.'),
            'review_required': ('Versione parziale, sperimentale o non coperta da queste regole: serve la verifica dell’hosting.', 'Versiune incompletă, experimentală sau neacoperită de aceste reguli: este necesară verificarea de către furnizorul de găzduire.'),
            'reference_met': ('La versione dichiarata raggiunge le correzioni di riferimento per le due falle del 21 ottobre 2026. Non è una certificazione di sicurezza e non esclude altre vulnerabilità.', 'Versiunea declarată atinge nivelul corecțiilor de referință pentru cele două vulnerabilități din 21 octombrie 2026. Nu este o certificare de securitate și nu exclude alte vulnerabilități.')}
        message, message_ro = messages[status]
    if observations:
        message += ' Gli header possono essere nascosti o inesatti; alcune distribuzioni applicano patch mantenendo il numero di versione. La configurazione relativa a CVE-2026-115560 non è verificabile dall’esterno.'
        message_ro += ' Antetele pot fi ascunse sau inexacte; unele distribuții aplică corecții fără să schimbe numărul versiunii. Configurația relevantă pentru CVE-2026-115560 nu poate fi verificată din exterior.'
    stale = (today - REVIEWED).days > 30
    if stale:
        message += ' Regole da aggiornare: ultimo controllo degli avvisi oltre 30 giorni fa.'
        message_ro += ' Regulile trebuie actualizate: ultima verificare a avertizărilor a fost făcută cu peste 30 de zile în urmă.'
    return {'status': status, 'title': title, 'title_ro': title_ro, 'message': message, 'message_ro': message_ro,
            'versions': versions, 'observations': observations[:40], 'rules_reviewed_on': REVIEWED.isoformat(),
            'rules_stale': stale, 'cves': CVES if versions else [], 'sources': SOURCES}


def passive_findings(soup, headers, url, cookie_headers=()):
    findings = []
    def add(code, severity, title, message, title_ro, message_ro):
        findings.append(dict(code=code, area='Sicurezza', severity=severity, title=title,
                             message=message, title_ro=title_ro, message_ro=message_ro, page=url))
    secure = urlparse(url).scheme == 'https'
    base = soup.find('base', href=True)
    base_url = urljoin(url, base['href']) if base else url
    def insecure(raw):
        return bool(raw) and urlparse(urljoin(base_url, raw)).scheme == 'http'
    if secure and any(insecure(n.get('src')) for n in soup.find_all(['script', 'iframe'])):
        add('sec_mixed_active', 'high', 'Script o iframe caricati via HTTP', 'La pagina HTTPS richiama contenuti attivi non cifrati. Il browser potrebbe bloccarli; usare HTTPS per tutte le risorse.', 'Scripturi sau cadre iframe încărcate prin HTTP', 'Pagina HTTPS încarcă resurse active necriptate. Browserul le poate bloca; folosește HTTPS pentru toate resursele.')
    if any(insecure(f.get('action', url)) for f in soup.find_all('form')):
        add('sec_form_http', 'high', 'Modulo con destinazione HTTP', 'Un modulo invia i dati a un indirizzo non cifrato. Correggere la destinazione prima di raccogliere dati.', 'Formular cu destinație HTTP', 'Un formular trimite datele către o adresă necriptată. Corectează destinația înainte de a colecta date.')
    # Inspect attributes only; never retain or output cookie values.
    weak = False
    for raw in cookie_headers:
        try:
            parsed = SimpleCookie()
            parsed.load(raw[:8192])
            for name, morsel in parsed.items():
                if re.search(r'(?i)(?:session|sessid|phpsessid|jsessionid|asp\.net_sessionid)', name):
                    if not morsel['httponly'] or (secure and not morsel['secure']) or not morsel['samesite']:
                        weak = True
        except CookieError:
            continue
    if weak:
        add('sec_session_cookie', 'medium', 'Protezione cookie di sessione da verificare', 'Un cookie con nome riconducibile a una sessione non dichiara tutti gli attributi consigliati Secure, HttpOnly e SameSite. Verificare con lo sviluppatore; il nome non prova la funzione del cookie.', 'Protecția cookie-urilor de sesiune trebuie verificată', 'Un cookie al cărui nume sugerează o sesiune nu declară toate atributele recomandate Secure, HttpOnly și SameSite. Verifică împreună cu dezvoltatorul; numele nu dovedește rolul cookie-ului.')
    visible = soup.get_text(' ', strip=True)
    if re.search(r'(?i)(?:PHP\s+(?:Warning|Fatal error|Parse error)|(?:Warning|Fatal error|Parse error):\s+.{0,300}?\s+in\s+[^\n]{0,200}\.php\s+on\s+line\s+\d+)', visible):
        add('sec_php_errors', 'medium', 'Messaggi di errore PHP visibili', 'La pagina contiene testo compatibile con un errore PHP. Verificare che non sia un esempio didattico; in produzione gli errori tecnici vanno registrati privatamente.', 'Mesaje de eroare PHP vizibile', 'Pagina conține text compatibil cu o eroare PHP. Verifică dacă este doar un exemplu explicativ; în producție, erorile tehnice trebuie înregistrate privat.')
    return findings


def localize_report(result, language):
    """Translate new observations in API, including TXT/print consumers."""
    for item in [*result.get('issues', []), result.get('php', {})]:
        for key in ('title', 'message'):
            translated = item.pop(key + '_ro', None)
            if language == 'ro' and translated:
                item[key] = translated
    return result
