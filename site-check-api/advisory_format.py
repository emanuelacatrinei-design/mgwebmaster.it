"""Pure validation shared by the backend and the scheduled Pages build."""
import re


def normalize(payload):
    if not isinstance(payload, list) or not payload or len(payload) > 100:
        raise ValueError('Invalid advisory list')
    records = []
    for item in payload:
        if item.get('state') != 'published' or item.get('withdrawn_at'):
            continue
        ghsa = item.get('ghsa_id', '')
        if not re.fullmatch(r'GHSA-[a-z0-9-]{14}', ghsa):
            raise ValueError('Invalid advisory ID')
        rows = []
        for v in item.get('vulnerabilities', [])[:100]:
            package = v.get('package') or {}
            if package.get('ecosystem') != 'php':
                continue
            rows.append({'range': str(v.get('vulnerable_version_range') or '')[:512],
                         'patched': str(v.get('patched_versions') or '')[:128]})
        cve = item.get('cve_id') or ghsa
        if not re.fullmatch(r'(?:CVE-\d{4}-\d{4,9}|GHSA-[a-z0-9-]{14})', cve):
            raise ValueError('Invalid CVE ID')
        records.append({'id': cve, 'ghsa': ghsa, 'severity': item.get('severity', 'unknown'),
                        'ranges': rows, 'url': 'https://github.com/php/php-src/security/advisories/' + ghsa})
    if not records:
        raise ValueError('No published PHP advisories')
    return records

