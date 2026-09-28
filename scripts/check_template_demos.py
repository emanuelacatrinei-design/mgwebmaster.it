#!/usr/bin/env python3
"""Publication gate for every current and future IT/RO template. Standard library only."""
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
ERRORS = []

class Page(HTMLParser):
    def __init__(self, path):
        super().__init__(convert_charrefs=True)
        self.path = path
        self.tags = []
        self.ids = set()
        self.text = []
        self.feed(path.read_text(encoding='utf-8'))
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if 'id' in attrs:
            if attrs['id'] in self.ids:
                fail(self.path, 'duplicate id: ' + attrs['id'])
            self.ids.add(attrs['id'])
    def handle_data(self, data):
        self.text.append(data)
    def find(self, tag, **attrs):
        return [a for t, a in self.tags if t == tag and all(a.get(k) == v for k, v in attrs.items())]

def fail(path, message):
    ERRORS.append(str(path.relative_to(ROOT)) + ': ' + message)

def resolve(source, ref):
    parsed = urlsplit(ref)
    if parsed.scheme or parsed.netloc:
        return None, parsed.fragment
    path = unquote(parsed.path)
    target = ROOT / path.lstrip('/') if path.startswith('/') else source.parent / path
    if not path:
        target = source
    if target.is_dir() or path.endswith('/'):
        target = target / 'index.html'
    return target.resolve(), unquote(parsed.fragment)

cache = {}
def read(path):
    if path not in cache:
        cache[path] = Page(path)
    return cache[path]

def references(path, page):
    for tag, attrs in page.tags:
        for attribute in ('src', 'href', 'data-lightbox'):
            ref = attrs.get(attribute)
            if not ref:
                continue
            target, fragment = resolve(path, ref)
            if target is None:
                if tag in ('script', 'img', 'iframe', 'link') and ref.startswith(('http:', 'https:', '//')):
                    fail(path, 'external runtime dependency: ' + ref)
                continue
            if not target.is_relative_to(ROOT) or not target.is_file() or target.stat().st_size == 0:
                fail(path, 'missing or empty reference: ' + ref)
            elif fragment and target.suffix == '.html' and fragment not in read(target).ids:
                fail(path, 'missing anchor: ' + ref)
            if attrs.get('download') is not None or target.suffix.lower() in ('.zip', '.rar', '.7z', '.bat', '.psd', '.fig'):
                fail(path, 'source package download in demo: ' + ref)
        if tag == 'img':
            if 'alt' not in attrs:
                fail(path, 'image without alt')
            src = attrs.get('src', '')
            if src.lower().endswith(('.png', '.jpg', '.jpeg')):
                fail(path, 'unoptimised raster image: ' + src)
            if src.lower().endswith('.webp'):
                for key in ('width', 'height'):
                    if not str(attrs.get(key, '')).isdigit() or int(attrs[key]) < 1:
                        fail(path, 'image without valid ' + key + ': ' + src)
                if attrs.get('decoding') != 'async':
                    fail(path, 'image without async decoding: ' + src)
        if tag == 'form' and (attrs.get('action') or 'data-demo-form' not in attrs):
            fail(path, 'form not explicitly marked as demonstration')
        if tag == 'button' and attrs.get('type') == 'submit' and 'disabled' not in attrs:
            fail(path, 'demo submit must remain disabled without JavaScript')

manifest = json.loads((ROOT / 'template/demos.json').read_text())
entries = manifest['templates']
for entry in entries:
    if len(entry['pages'].get('it', [])) != len(entry['pages'].get('ro', [])):
        fail(ROOT / 'template/demos.json', entry['slug'] + ': IT/RO page count must match')
slugs = [entry['slug'] for entry in entries]
if len(slugs) != len(set(slugs)):
    fail(ROOT / 'template/demos.json', 'duplicate template slug')
for lang, prefix in [('it', ''), ('ro', '/ro')]:
    catalog_path = ROOT / (prefix.lstrip('/') + '/' if prefix else '') / 'template/index.html'
    catalog = read(catalog_path)
    advertised = set()
    for a in catalog.find('a'):
        match = re.fullmatch(re.escape(prefix) + r'/template/([^/]+)/demo/', a.get('href', ''))
        if match:
            advertised.add(match[1])
    if advertised != set(slugs):
        fail(catalog_path, 'catalog and demo manifest differ: ' + str(advertised ^ set(slugs)))
    details = {p.parent.name for p in catalog_path.parent.glob('*/index.html')}
    if details != set(slugs):
        fail(catalog_path, 'every template detail must have a registered demo: ' + str(details ^ set(slugs)))
    for entry in entries:
        slug = entry['slug']
        pages = entry['pages'].get(lang, [])
        if len(pages) < 2:
            fail(ROOT / 'template/demos.json', f'{slug}/{lang}: complete navigable site required')
        viewer_path = catalog_path.parent / slug / 'demo/index.html'
        if not viewer_path.is_file():
            fail(catalog_path, 'missing viewer ' + slug)
            continue
        viewer = read(viewer_path)
        references(viewer_path, viewer)
        if not viewer.find('html', lang=lang) or not viewer.find('meta', name='robots', content='noindex,follow'):
            fail(viewer_path, 'viewer language/noindex missing')
        if not viewer.find('iframe') or len([a for a in viewer.find('button') if 'data-device' in a]) != 3:
            fail(viewer_path, 'navigable frame and three responsive controls required')
        detail_path = catalog_path.parent / slug / 'index.html'
        detail = read(detail_path)
        if not any(a.get('href') == f'{prefix}/template/{slug}/demo/' for a in detail.find('a')):
            fail(detail_path, 'detail has no direct demo link')
        for p in pages:
            path = ROOT / p['path'].lstrip('/')
            expected = f'{prefix}/template/{slug}/demo/site/'
            if not p['path'].startswith(expected) or not path.is_file():
                fail(ROOT / 'template/demos.json', 'wrong language path or missing page: ' + p['path'])
                continue
            page = read(path)
            if not page.find('html', lang=lang):
                fail(path, 'incorrect document language')
            if not page.find('meta', name='robots', content='noindex,follow'):
                fail(path, 'demo must be excluded from indexing')
            if not page.find('main') or not page.find('h1') or len(' '.join(page.text)) < 400:
                fail(path, 'real page content required, not a screenshot')
            if len([a for a in page.find('a') if '.html' in a.get('href', '')]) < 2:
                fail(path, 'internal navigation required')
            if not any(urlsplit(a.get('src', '')).path == '/template/demo-shared/runtime.js' for a in page.find('script')):
                fail(path, 'shared demo behaviour missing')
            if re.search(r'Lorem ipsum|Contactus|Ministeria|What we do|Our Services', ' '.join(page.text)):
                fail(path, 'untranslated source text')
            for a in page.find('a'):
                href = a.get('href', '')
                if href.startswith('/template/') and lang == 'ro' and not href.startswith('/template/demo-assets/'):
                    fail(path, 'Romanian demo links to an Italian page: ' + href)
            references(path, page)

for path in (ROOT / 'template/demo-assets').rglob('*'):
    if not path.is_file():
        continue
    if path.suffix.lower() in ('.zip', '.rar', '.7z', '.bat', '.psd', '.fig', '.png', '.jpg', '.jpeg'):
        fail(path, 'publish only optimised web assets')
    if not path.stat().st_size:
        fail(path, 'empty asset')
    if path.suffix == '.webp':
        data = path.read_bytes()
        if data[:4] != b'RIFF' or data[8:12] != b'WEBP':
            fail(path, 'invalid WebP header')
for path in (ROOT / 'template').rglob('*.css'):
    for ref in re.findall(r'url\([\s\'"]*([^\)\'"\s]+)', path.read_text()):
        if ref.startswith(('data:', '#')):
            continue
        target, _ = resolve(path, ref)
        if target is None or not target.is_file() or target.stat().st_size == 0:
            fail(path, 'missing or external CSS resource: ' + ref)
if ERRORS:
    print('\n'.join(ERRORS))
    print(f'FAILED: {len(ERRORS)} errors')
    sys.exit(1)
print(f'PASS: {len(slugs)} templates, both languages, {sum(len(e["pages"][l]) for e in entries for l in ("it","ro"))} internal pages; navigation, assets, forms and preview controls.')
