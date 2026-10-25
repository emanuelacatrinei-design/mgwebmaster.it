"""Passive local signals in the fetched HTML; no external lookups or ranking claims."""
import json
import re
from urllib.parse import urlparse, parse_qs, unquote

WEIGHTS = {'phone': 25, 'address': 25, 'locality': 10, 'maps': 15, 'schema': 25}
LOCAL_TYPES = {'LocalBusiness', 'ProfessionalService', 'Restaurant', 'Store', 'Hotel',
               'MedicalBusiness', 'Dentist', 'LegalService', 'RealEstateAgent',
               'AutomotiveBusiness', 'FoodEstablishment', 'LodgingBusiness',
               'FinancialService', 'HomeAndConstructionBusiness', 'HealthAndBeautyBusiness'}


def phone_number(value):
    value = unquote(str(value)).split(';', 1)[0].strip()
    if not re.fullmatch(r'\+?[\d\s().-]+', value):
        return None
    digits = re.sub(r'\D', '', value)
    return value[:120] if 7 <= len(digits) <= 15 and len(set(digits)) > 1 else None


def extract(soup):
    signals = {key: [] for key in WEIGHTS}
    nodes, invalid = [], False

    def add(key, value, source, points=None):
        evidence = {'value': str(value)[:180], 'source': source}
        if points is not None:
            evidence['points'] = points
        if evidence not in signals[key] and len(signals[key]) < 20:
            signals[key].append(evidence)

    def walk(value):
        if isinstance(value, dict):
            nodes.append(value)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    for script in soup.find_all('script', type=re.compile(r'^application/ld\+json\s*$', re.I)):
        try:
            walk(json.loads(script.string or script.get_text()))
        except (ValueError, TypeError, RecursionError):
            invalid = True
    by_id = {n['@id']: n for n in nodes if isinstance(n.get('@id'), str) and len(n) > 1}

    def resolved(value):
        return by_id.get(value.get('@id'), value) if isinstance(value, dict) else value

    def types(node):
        raw = node.get('@type', [])
        return [str(t).rstrip('/').rsplit('/', 1)[-1] for t in (raw if isinstance(raw, list) else [raw])]

    for node in nodes:
        ts = types(node)
        for kind in ts:
            if kind in LOCAL_TYPES:
                add('schema', kind, 'JSON-LD', 25)
            elif kind == 'Organization':
                add('schema', kind, 'JSON-LD', 5)
        # Avoid treating Product identifiers, dates or arbitrary JSON numbers as phones.
        if set(ts) & (LOCAL_TYPES | {'Organization', 'ContactPoint', 'Person'}):
            phone = phone_number(node.get('telephone', ''))
            if phone:
                add('phone', phone, 'JSON-LD telephone')
        address = resolved(node.get('address'))
        if 'PostalAddress' in ts:
            address = node
        if isinstance(address, dict):
            street = address.get('streetAddress')
            locality = address.get('addressLocality')
            if isinstance(street, str) and re.search(r'[A-Za-zÀ-žȘșȚț]{3}', street):
                add('address', street, 'JSON-LD streetAddress')
            if isinstance(locality, str) and re.fullmatch(r'[A-Za-zÀ-žȘșȚț][A-Za-zÀ-žȘșȚț .’\'-]{1,79}', locality.strip()):
                add('locality', locality, 'JSON-LD addressLocality')

    for element in soup.select('[itemprop="telephone"]'):
        value = phone_number(element.get('content') or element.get_text(' ', strip=True))
        if value:
            add('phone', value, 'HTML telephone')
    for key, prop in [('address', 'streetAddress'), ('locality', 'addressLocality')]:
        for element in soup.select(f'[itemprop="{prop}"]'):
            value = element.get('content') or element.get_text(' ', strip=True)
            if re.search(r'[A-Za-zÀ-žȘșȚț]{3}', value):
                add(key, value, 'HTML ' + prop)

    for a in soup.find_all(['a', 'iframe'], href=True) + soup.find_all('iframe', src=True):
        raw = a.get('href') or a.get('src') or ''
        parsed = urlparse(raw)
        host, path = (parsed.hostname or '').lower(), parsed.path.lower()
        if parsed.scheme == 'tel':
            value = phone_number(parsed.path)
            if value:
                add('phone', value, 'tel:')
        if host in {'wa.me', 'api.whatsapp.com', 'web.whatsapp.com'}:
            number = parsed.path.strip('/') if host == 'wa.me' else parse_qs(parsed.query).get('phone', [''])[0]
            value = phone_number(number)
            if value:
                add('phone', value, 'WhatsApp')
        if parsed.scheme in {'https', 'http'} and (
                host in {'maps.app.goo.gl', 'maps.google.com'} or
                (host in {'google.com', 'www.google.com', 'google.it', 'www.google.it', 'google.ro', 'www.google.ro', 'maps.google.it', 'maps.google.ro'} and path.startswith('/maps'))):
            add('maps', raw, 'Google Maps')

    visible = soup.__class__(str(soup), 'html.parser')
    for tag in visible(['script', 'style', 'noscript', 'svg', 'template']):
        tag.decompose()
    text = visible.get_text(' ', strip=True)
    # Explicit phone labels only: generic IDs, dates and VAT numbers are not evidence.
    for match in re.finditer(r'(?i)\b(?:tel(?:efono|efon)?|phone|mobil|cell(?:ulare)?)\s*[:.]\s*(\+?[\d][\d ().-]{5,24}\d)', text):
        value = phone_number(match.group(1))
        if value:
            add('phone', value, 'HTML')
    # A street prefix needs a proper-name token and civic number, not a lone word.
    street_pattern = r'\b(?i:Via|Viale|Piazza|Corso|Strada|Str\.|Bulevardul|Bulevard|Bd\.|Street|Road)\s+[A-ZÀ-ŽȘȚ][\wÀ-žȘșȚț’\'-]*(?:\s+[A-ZÀ-ŽȘȚ][\wÀ-žȘșȚț’\'-]*){0,4}\s*,?\s*(?:nr\.?\s*)?\d{1,5}[A-Za-z]?\b'
    for match in re.finditer(street_pattern, text):
        add('address', match.group(), 'HTML')
    # Conservative locality: city with a province code or explicit city label.
    for pattern in [r'\b([A-ZÀ-ŽȘȚ][A-Za-zÀ-žȘșȚț’\'-]+(?:\s+[A-ZÀ-ŽȘȚ][A-Za-zÀ-žȘșȚț’\'-]+){0,2})\s*\(([A-Z]{2})\)',
                    r'(?i)\b(?:città|località|oraș|oraş|localitate|city)\s*:\s*([A-ZÀ-ŽȘȚ][A-Za-zÀ-žȘșȚț’\'-]+)']:
        for match in re.finditer(pattern, text):
            if len(match.groups()) == 2 and match.group(2) not in {'AG','AL','AN','AO','AP','AQ','AR','AT','AV','BA','BG','BI','BL','BN','BO','BR','BS','BT','BZ','CA','CB','CE','CH','CL','CN','CO','CR','CS','CT','CZ','FC','FE','FG','FI','FM','FR','GE','GO','GR','IM','IS','KR','LC','LE','LI','LO','LT','LU','MB','MC','ME','MI','MN','MO','MS','MT','NA','NO','NU','OR','PA','PC','PD','PE','PG','PI','PN','PO','PR','PT','PU','PV','PZ','RA','RC','RE','RG','RI','RM','RN','SA','SI','SO','SP','SR','SS','SU','SV','TA','TE','TN','TO','TP','TR','TS','TV','UD','VA','VB','VC','VE','VI','VR','VT','VV'}:
                continue
            add('locality', match.group(), 'HTML')
    return {'signals': signals, 'schema_parse_incomplete': invalid}


def summarize_local(pages, failed_pages=()):
    usable = [p for p in pages if p.get('status_code', 200) < 400 and p.get('local', {}).get('signals') is not None]
    unchecked = list(dict.fromkeys([*failed_pages, *(p['url'] for p in pages if p not in usable)]))
    checks = {}
    for key, weight in WEIGHTS.items():
        evidence = [{**e, 'page': p['url']} for p in usable for e in p['local']['signals'][key]]
        incomplete = key == 'schema' and any(p['local'].get('schema_parse_incomplete') for p in usable)
        status = 'detected' if evidence else 'not_evaluated' if not usable or incomplete else 'not_detected'
        points = max((e.get('points', weight) for e in evidence), default=0)
        checks[key] = {'status': status, 'points': points if status != 'not_evaluated' else None,
                       'max_points': weight, 'evidence': evidence,
                       'checked_pages': [p['url'] for p in usable],
                       'incomplete': incomplete}
    # Unknown checks never become fabricated zero evidence. Normalize measured weights only.
    denominator = sum(c['max_points'] for c in checks.values() if c['status'] != 'not_evaluated')
    score = int(100 * sum(c['points'] or 0 for c in checks.values()) / denominator + .5) if denominator else None
    return {'method': 'local_signals_v1', 'score': score, 'checks': checks,
            'checked_pages': [p['url'] for p in usable], 'unchecked_pages': unchecked,
            'partial': bool(unchecked) or any(c['incomplete'] for c in checks.values()),
            'measured_max_points': denominator}
