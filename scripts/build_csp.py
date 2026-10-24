"""Add an enforcing script CSP to published HTML without changing page content.

Run LAST, after HTML build transformations. Unknown inline scripts/handlers fail
closed: review them rather than silently extending the allowlist.
"""
import argparse
import base64
import hashlib
import html
import json
import re
from html.parser import HTMLParser
from pathlib import Path

APPROVED = {
 'T/pE0WPkhsnx7JZTx60ih9qOVOq0EaREjdd6FV2O9Zo=',
 '6fOWIWKbMbr5lFWb42hH0Me0XSWZltMtrxi/Xpu1OsU=',
}
SOURCES = ["'self'", 'https://www.googletagmanager.com',
 'https://www.google-analytics.com', 'https://challenges.cloudflare.com',
 'https://static.cloudflareinsights.com']
HANDLERS = {
 'return false': '',
 "event.preventDefault();alert('Demo form — connect this to your email service.');": 'Demo form — connect this to your email service.',
 "event.preventDefault();alert('Forma demonstrationis tantum.');": 'Forma demonstrationis tantum.',
 "event.preventDefault();alert('Modulo dimostrativo: nessun dato viene inviato.');": 'Modulo dimostrativo: nessun dato viene inviato.',
 "event.preventDefault();alert('Modulo demo: collega qui il tuo servizio di contatto.')": 'Modulo demo: collega qui il tuo servizio di contatto.',
}
SCRIPT = re.compile(r'<script\b([^>]*)>(.*?)</script\s*>', re.I | re.S)
TAG = re.compile(r'<[a-zA-Z][^>]*>', re.S)
EVENT = re.compile(r'\s+(on[a-z]+)\s*=\s*([\"\'])(.*?)\2', re.I | re.S)
MARKER = 'data-mgw-script-policy'

class Attributes(HTMLParser):
 def handle_starttag(self, tag, attrs): self.attrs = dict(attrs)

def attrs(tag):
 parser=Attributes();parser.attrs={};parser.feed(tag);return parser.attrs

def digest(code):
 return base64.b64encode(hashlib.sha256(code.replace('\r\n','\n').replace('\r','\n').encode()).digest()).decode()

def transform(text):
 if MARKER in text: raise ValueError('CSP already generated: use clean source files')
 hashes=set()
 for match in SCRIPT.finditer(text):
  attributes=attrs('<script'+match[1]+'>')
  if 'src' in attributes: continue
  kind=attributes.get('type','').lower().strip()
  if kind in {'application/ld+json','application/json'}: continue
  code=match[2]
  if not code.strip(): continue
  value=digest(code)
  if value not in APPROVED: raise ValueError('Unreviewed inline script: '+value)
  hashes.add("'sha256-"+value+"'")
 uses_handler=False
 def rewrite_tag(match):
  nonlocal uses_handler
  tag=match[0]
  for key,value in attrs(tag).items():
   if key.lower().startswith('on') and (key.lower()!='onsubmit' or value not in HANDLERS):
    raise ValueError('Unreviewed inline event handler: '+key)
   if key.lower() in {'href','src','action'} and (value or '').strip().lower().startswith('javascript:'):
    raise ValueError('javascript: URL requires refactoring')
  def rewrite_event(event):
   nonlocal uses_handler
   name=event[1].lower();value=html.unescape(event[3])
   if name!='onsubmit' or value not in HANDLERS: raise ValueError('Unreviewed handler')
   uses_handler=True
   return ' data-mgw-demo-submit="'+html.escape(HANDLERS[value],quote=True)+'"'
  return EVENT.sub(rewrite_event,tag)
 # Do not parse apparent tags inside JavaScript, CSS, comments or JSON-LD.
 chunks=[];last=0
 protected=re.compile(r'<!--.*?-->|<(script|style)\b[^>]*>.*?</\1\s*>',re.I|re.S)
 for match in protected.finditer(text):
  chunks.append(TAG.sub(rewrite_tag,text[last:match.start()]));chunks.append(match[0]);last=match.end()
 chunks.append(TAG.sub(rewrite_tag,text[last:]));text=''.join(chunks)
 policy="script-src "+' '.join(SOURCES+sorted(hashes))+"; script-src-attr 'none'; object-src 'none'; base-uri 'self';"
 meta='<meta '+MARKER+' http-equiv="Content-Security-Policy" content="'+html.escape(policy,quote=True)+'">'
 # Keep the encoding declaration first; policy precedes all executable scripts.
 head=re.search(r'<head\b[^>]*>',text,re.I)
 if not head: raise ValueError('Missing head')
 encoding=re.match(r'\s*<meta\b[^>]*charset\s*=[^>]*>',text[head.end():],re.I)
 position=head.end()+(encoding.end() if encoding else 0)
 text=text[:position]+meta+text[position:]
 if uses_handler:
  text=re.sub(r'</head\s*>','<script defer src="/assets/security/demo-submit.js"></script></head>',text,count=1,flags=re.I)
 return text

def build(root):
 changes=[]
 for path in sorted(root.rglob('*.html')):
  if any(p.startswith('.') for p in path.relative_to(root).parts): continue
  try:changes.append((path,transform(path.read_text(encoding='utf-8'))))
  except ValueError as exc:raise ValueError(str(path)+': '+str(exc)) from exc
 # Validate every page before writing any output.
 for path,text in changes:path.write_text(text,encoding='utf-8')
 target=root/'assets/security/demo-submit.js';target.parent.mkdir(parents=True,exist_ok=True)
 target.write_text('document.addEventListener("submit",function(event){const form=event.target;if(form.matches("form[data-mgw-demo-submit]")){event.preventDefault();const message=form.getAttribute("data-mgw-demo-submit");if(message)window.alert(message);}},true);\n',encoding='utf-8')
 print(f'CSP enforced on {len(changes)} HTML pages; inline handlers replaced with external listeners.')

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('root',type=Path);args=parser.parse_args();build(args.root.resolve())
