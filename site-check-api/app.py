from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import threading
import time
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Literal

VERSION = "0.1.2"
MAX_PAGES = 5
MAX_REDIRECTS = 5
MAX_HTML_BYTES = 2_000_000
TIMEOUT = (5, 12)
UA = "MGWebmaster-SiteCheck/0.1 (+https://www.mgwebmaster.it/)"
RATE_LIMIT = 5
RATE_WINDOW_SECONDS = 600
TURNSTILE_SECRET = os.getenv("TURNSTILE_SECRET","").strip()
TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
_RATE_LOCK = threading.Lock()
_RATE_BUCKETS = {}
_RATE_SALT = os.urandom(16)

SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", "high"),
    "content-security-policy": ("CSP", "high"),
    "x-content-type-options": ("X-Content-Type-Options", "medium"),
    "referrer-policy": ("Referrer-Policy", "medium"),
    "permissions-policy": ("Permissions-Policy", "medium"),
    "x-frame-options": ("X-Frame-Options", "medium"),
}
SKIP_EXT = (".jpg",".jpeg",".png",".gif",".webp",".svg",".pdf",".zip",".rar",".7z",".mp4",".mp3",".css",".js",".xml",".json",".ico",".woff",".woff2",".ttf")
HINTS = ("servizi","services","servicii","service","chi-sono","about","despre","contatti","contact","prezzi","pricing","preturi","negozio","shop","prodotti","products")


class AuditError(RuntimeError):
    pass


class UnsafeTargetError(AuditError):
    pass


def normalize_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise AuditError("Inserisci un URL.")
    if "://" not in value:
        value = "https://" + value
    p = urlparse(value)
    if p.scheme not in {"http", "https"}:
        raise UnsafeTargetError("Sono consentiti solo URL HTTP/HTTPS.")
    if p.username or p.password:
        raise UnsafeTargetError("URL con credenziali incorporate non consentiti.")
    if not p.hostname:
        raise AuditError("Dominio non valido.")
    if p.port not in {None, 80, 443}:
        raise UnsafeTargetError("Sono consentite solo le porte web standard 80/443.")
    host = p.hostname.encode("idna").decode("ascii").lower()
    netloc = host + (f":{p.port}" if p.port else "")
    return urlunparse((p.scheme.lower(), netloc, p.path or "/", "", p.query, ""))


def public_target(url: str) -> str:
    url = normalize_url(url)
    p = urlparse(url)
    host = p.hostname or ""
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise UnsafeTargetError("Host locale non consentito.")
    try:
        infos = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise AuditError("Dominio non risolvibile.") from exc
    ips = {x[4][0] for x in infos}
    for raw in ips:
        ip = ipaddress.ip_address(raw)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise UnsafeTargetError("Destinazione privata o riservata non consentita.")
    return url


def same_site(a: str, b: str) -> bool:
    ah = (urlparse(a).hostname or "").lower().removeprefix("www.")
    bh = (urlparse(b).hostname or "").lower().removeprefix("www.")
    return bool(ah and ah == bh)


def clean_text(soup: BeautifulSoup) -> str:
    copy = BeautifulSoup(str(soup), "html.parser")
    for tag in copy(["script","style","noscript","svg","template"]):
        tag.decompose()
    return re.sub(r"\s+", " ", copy.get_text(" ", strip=True)).strip()


def schema_types(soup: BeautifulSoup) -> list[str]:
    found = set()
    def walk(x):
        if isinstance(x, dict):
            t = x.get("@type")
            if isinstance(t, str):
                found.add(t)
            elif isinstance(t, list):
                found.update(v for v in t if isinstance(v, str))
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    for node in soup.find_all("script", attrs={"type": re.compile(r"ld\+json", re.I)}):
        raw = node.string or node.get_text("", strip=True)
        if not raw:
            continue
        try:
            walk(json.loads(raw))
        except Exception:
            pass
    return sorted(found)


class Engine:
    def __init__(self):
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": UA, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5"})

    def fetch(self, url: str, html_only=True, max_bytes=MAX_HTML_BYTES):
        current = public_target(url)
        start = time.perf_counter()
        for _ in range(MAX_REDIRECTS + 1):
            public_target(current)
            try:
                r = self.s.get(current, timeout=TIMEOUT, allow_redirects=False, stream=True)
            except requests.RequestException as exc:
                raise AuditError("Connessione al sito non riuscita.") from exc
            if r.status_code in {301,302,303,307,308}:
                loc = r.headers.get("Location")
                r.close()
                if not loc:
                    raise AuditError("Redirect senza destinazione.")
                current = urljoin(current, loc)
                public_target(current)
                continue
            ctype = (r.headers.get("Content-Type") or "").lower()
            if html_only and "text/html" not in ctype and "application/xhtml+xml" not in ctype:
                r.close()
                raise AuditError("La risorsa non è una pagina HTML.")
            parts, size = [], 0
            for chunk in r.iter_content(65536):
                if not chunk:
                    continue
                size += len(chunk)
                if size > max_bytes:
                    r.close()
                    raise AuditError("Risorsa troppo grande per la scansione gratuita.")
                parts.append(chunk)
            elapsed = int((time.perf_counter() - start) * 1000)
            return r, b"".join(parts), elapsed
        raise AuditError("Troppi redirect.")

    def probe(self, url: str) -> int:
        try:
            r, _, _ = self.fetch(url, html_only=False, max_bytes=512_000)
            status = int(r.status_code)
            r.close()
            return status
        except AuditError:
            return 0

    @staticmethod
    def priority(url: str):
        path = (urlparse(url).path or "/").lower()
        if path in {"", "/"}:
            return (0, 0, path)
        return (0 if any(h in path for h in HINTS) else 1, len([x for x in path.split("/") if x]), path)

    def audit_page(self, url: str):
        r, body, response_ms = self.fetch(url)
        final = normalize_url(r.url or url)
        html = body.decode(r.encoding or "utf-8", errors="replace")
        soup = BeautifulSoup(html, "html.parser")
        text = clean_text(soup)
        words = re.findall(r"\b[\wÀ-ÿ'-]+\b", text, flags=re.UNICODE)
        title = re.sub(r"\s+", " ", soup.title.get_text(" ", strip=True) if soup.title else "").strip()
        d = soup.find("meta", attrs={"name": re.compile("^description$", re.I)})
        desc = re.sub(r"\s+", " ", (d.get("content") or "") if d else "").strip()
        h1s, h2s = soup.find_all("h1"), soup.find_all("h2")
        can = soup.find("link", rel=lambda v: v and "canonical" in v)
        canonical = (can.get("href") or "").strip() if can else ""
        rob = soup.find("meta", attrs={"name": re.compile("^robots$", re.I)})
        robots = (rob.get("content") or "").strip() if rob else ""
        imgs = soup.find_all("img")
        scripts = len(soup.find_all("script", src=True))
        styles = len(soup.find_all("link", rel=lambda x: x and "stylesheet" in x))
        hrefs = [a.get("href","") for a in soup.find_all("a", href=True)]
        lower = text.lower()
        issues = []

        def add(code, area, sev, title_, msg):
            issues.append({"code":code,"area":area,"severity":sev,"title":title_,"message":msg,"page":final})

        if r.status_code >= 400:
            add("http_error","SEO tecnica","high",f"HTTP {r.status_code}","La pagina restituisce un errore HTTP.")
        if urlparse(final).scheme != "https":
            add("https","Sicurezza","high","HTTPS non attivo","La pagina non utilizza HTTPS.")
        if not title:
            add("title_missing","SEO tecnica","high","Title mancante","La pagina non ha un title leggibile.")
        elif len(title) < 20 or len(title) > 70:
            add("title_length","SEO tecnica","medium","Title da rivedere","La lunghezza del title è poco equilibrata.")
        if not desc:
            add("description","SEO tecnica","medium","Meta description mancante","Non è stata rilevata una meta description.")
        if not h1s:
            add("h1","Contenuti","high","H1 mancante","La pagina non presenta un H1.")
        elif len(h1s) > 1:
            add("h1_multiple","Contenuti","low","Più H1 rilevati","Sono presenti più H1; conviene verificarne la gerarchia.")
        if len(words) < 180:
            add("thin","Contenuti","medium","Contenuto molto breve","La pagina contiene poco testo utile rispetto a una normale pagina servizio.")
        if not canonical:
            add("canonical","SEO tecnica","medium","Canonical non rilevata","Non è stato rilevato un URL canonical.")
        if "noindex" in robots.lower():
            add("noindex","SEO tecnica","high","Pagina noindex","La pagina chiede ai motori di ricerca di non essere indicizzata.")
        missing_alt = sum(1 for i in imgs if i.get("alt") is None)
        no_dims = sum(1 for i in imgs if not i.get("width") or not i.get("height"))
        if imgs and missing_alt / len(imgs) > .25:
            add("alt","Contenuti","low","ALT immagini incompleti","Diverse immagini non hanno un attributo ALT.")
        if imgs and no_dims / len(imgs) > .50:
            add("dims","Prestazioni","medium","Dimensioni immagini non dichiarate","Molte immagini non dichiarano width e height.")
        if response_ms > 1500:
            add("server","Prestazioni","high","Risposta server lenta","Il server ha impiegato molto tempo a rispondere durante il test.")
        elif response_ms > 800:
            add("server","Prestazioni","medium","Risposta server migliorabile","La risposta iniziale del server è migliorabile.")
        if len(body) > 750_000:
            add("html_weight","Prestazioni","medium","HTML molto pesante","Il documento HTML è insolitamente pesante.")
        if scripts > 20:
            add("scripts","Prestazioni","medium","Molti script","La pagina carica molti script.")
        if styles > 10:
            add("styles","Prestazioni","low","Molti fogli di stile","La pagina usa numerosi fogli di stile.")

        csp_value = (r.headers.get("content-security-policy") or "").lower()
        for header, (label, sev) in SECURITY_HEADERS.items():
            present = bool((r.headers.get(header) or "").strip())
            if header == "strict-transport-security" and urlparse(final).scheme != "https":
                present = False
            if header == "x-frame-options" and "frame-ancestors" in csp_value:
                present = True
            if not present:
                add("sec_"+header,"Sicurezza",sev,f"{label} non rilevato","Manca una protezione HTTP consigliata; serve una verifica della configurazione.")

        internal = []
        for raw in hrefs:
            if not raw or raw.startswith(("#","mailto:","tel:","javascript:")):
                continue
            candidate = urljoin(final, raw)
            p = urlparse(candidate)
            if p.scheme in {"http","https"} and same_site(final, candidate):
                candidate = urlunparse((p.scheme,p.netloc,p.path or "/","","",""))
                if not candidate.lower().endswith(SKIP_EXT):
                    internal.append(candidate)

        has_phone = bool(re.search(r"(?:\+?\d[\d\s().-]{7,}\d)", text)) or any(x.lower().startswith("tel:") for x in hrefs)
        has_maps = any("google.com/maps" in x.lower() or "maps.app.goo.gl" in x.lower() for x in hrefs)
        has_address = any(x in lower for x in ("via ","viale ","piazza ","strada ","corso ","street ","road ","bulevard ","adres"))
        has_cta = any(x in lower for x in ("contatt","preventiv","chiama","scriv","whatsapp","contact","quote","sună","contactează","ofert"))

        return {
            "url":final,"issues":issues,"links":sorted(set(internal),key=self.priority),
            "local":{"phone":has_phone,"maps":has_maps,"address":has_address,"schema":schema_types(soup)},
            "cta":has_cta
        }

    @staticmethod
    def score(area, pages):
        penalties={"high":14,"medium":7,"low":3}
        vals=[]
        for p in pages:
            value=100
            for i in p["issues"]:
                if i["area"]==area:
                    value-=penalties.get(i["severity"],0)
            vals.append(max(0,min(100,value)))
        return round(sum(vals)/len(vals)) if vals else None

    def audit(self, raw: str):
        started=time.perf_counter()
        requested=public_target(raw)
        first=self.audit_page(requested)
        pages=[first]
        seen={normalize_url(first["url"])}
        for candidate in first["links"]:
            if len(pages)>=MAX_PAGES:
                break
            try:
                candidate=public_target(candidate)
            except AuditError:
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            try:
                pages.append(self.audit_page(candidate))
            except AuditError:
                pass

        issues=[i for p in pages for i in p["issues"]]
        root=urlunparse((urlparse(first["url"]).scheme,urlparse(first["url"]).netloc,"/","","",""))
        if self.probe(urljoin(root,"robots.txt"))!=200:
            issues.append({"code":"robots_txt","area":"SEO tecnica","severity":"low","title":"robots.txt non rilevato","message":"Non è stato rilevato un robots.txt raggiungibile dalla scansione.","page":first["url"]})
        if self.probe(urljoin(root,"sitemap.xml"))!=200:
            issues.append({"code":"sitemap","area":"SEO tecnica","severity":"low","title":"Sitemap XML non rilevata","message":"Non è stata rilevata una sitemap.xml standard; conviene verificarne la configurazione.","page":first["url"]})
        if not any(p["cta"] for p in pages):
            issues.append({"code":"cta","area":"Contenuti","severity":"medium","title":"Contatto poco evidente","message":"Nelle pagine controllate non è emerso un invito al contatto facilmente riconoscibile.","page":first["url"]})

        seo=self.score("SEO tecnica",pages)
        perf=self.score("Prestazioni",pages)
        sec=self.score("Sicurezza",pages)
        content=self.score("Contenuti",pages)
        localdata=[p["local"] for p in pages]
        types={x.lower() for p in localdata for x in p["schema"]}
        signals={
            "schema":any(x in types for x in ("localbusiness","professionalservice","organization")),
            "phone":any(p["phone"] for p in localdata),
            "address":any(p["address"] for p in localdata),
            "maps":any(p["maps"] for p in localdata),
        }
        local=None if not any(signals.values()) else min(100,35+(20 if signals["schema"] else 0)+(20 if signals["phone"] else 0)+(15 if signals["address"] else 0)+(10 if signals["maps"] else 0))
        scores={"seo":seo,"performance":perf,"security":sec,"content":content,"local":local}
        weights={"seo":.30,"performance":.20,"security":.20,"content":.20,"local":.10}
        active=[(scores[k],w) for k,w in weights.items() if scores[k] is not None]
        overall=round(sum(v*w for v,w in active)/sum(w for _,w in active)) if active else 0

        grouped={}
        for i in issues:
            key=i["code"]
            if key not in grouped:
                grouped[key]={**i,"occurrences":1}
            else:
                grouped[key]["occurrences"]+=1
        unique=list(grouped.values())
        for i in unique:
            if i["occurrences"]>1:
                i["message"] += f" Rilevato in {i['occurrences']} pagine controllate."
        order={"high":0,"medium":1,"low":2}
        unique.sort(key=lambda i:order.get(i["severity"],3))
        counts={s:sum(i["severity"]==s for i in unique) for s in ("high","medium","low")}
        counts["total"]=len(unique)
        return {
            "requested_url":requested,"final_url":first["url"],"scanned_at_epoch":int(time.time()),
            "duration_ms":int((time.perf_counter()-started)*1000),"pages_checked":len(pages),
            "overall_score":overall,"scores":scores,"counts":counts,
            "issues":[{"area":i["area"],"severity":i["severity"],"title":i["title"],"message":i["message"],"page":i["page"]} for i in unique[:8]],
            "disclaimer":"Scansione automatica sintetica. Non sostituisce un audit tecnico professionale e non dimostra, da sola, la presenza di malware o intrusioni."
        }


class ScanRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)
    authorized: Literal[True]


origin=os.getenv("MG_SITE_ORIGIN","https://www.mgwebmaster.it")
allowed_origins=list(dict.fromkeys([
    origin,
    "https://www.mgwebmaster.it",
    "https://mgwebmaster.it",
]))
app=FastAPI(title="MG Webmaster Site Check API",version=VERSION,docs_url=None,redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET","POST","OPTIONS"],
    allow_headers=["Content-Type","Accept"],
)
engine=Engine()


def _client_key(request: Request) -> str:
    raw = (
        request.headers.get("cf-connecting-ip")
        or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )
    return hashlib.sha256(_RATE_SALT + raw.encode("utf-8", errors="ignore")).hexdigest()


def _verify_turnstile(token: str, remote_ip: str | None = None):
    if not TURNSTILE_SECRET:
        raise HTTPException(status_code=503, detail="Protezione Turnstile non configurata.")
    token = (token or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="Verifica anti-bot mancante.")
    payload = {"secret": TURNSTILE_SECRET, "response": token}
    if remote_ip:
        payload["remoteip"] = remote_ip
    try:
        r = requests.post(TURNSTILE_VERIFY_URL, data=payload, timeout=(5, 10))
        data = r.json()
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Verifica anti-bot non disponibile.") from exc
    if not data.get("success"):
        raise HTTPException(status_code=403, detail="Verifica anti-bot non superata.")


def _rate_limit(request: Request):
    now = time.time()
    key = _client_key(request)
    with _RATE_LOCK:
        hits = [t for t in _RATE_BUCKETS.get(key, []) if now - t < RATE_WINDOW_SECONDS]
        if len(hits) >= RATE_LIMIT:
            _RATE_BUCKETS[key] = hits
            raise HTTPException(status_code=429, detail="Limite temporaneo raggiunto. Riprova tra qualche minuto.")
        hits.append(now)
        _RATE_BUCKETS[key] = hits
        if len(_RATE_BUCKETS) > 5000:
            stale = [k for k,v in _RATE_BUCKETS.items() if not v or now - v[-1] >= RATE_WINDOW_SECONDS]
            for k in stale[:1000]:
                _RATE_BUCKETS.pop(k, None)


@app.get("/health")
def health():
    return {"ok":True,"service":"mg-site-check","version":VERSION}


@app.post("/v1/scan")
async def scan(request: Request):
    try:
        _rate_limit(request)
        raw = await request.body()
        try:
            data = json.loads(raw.decode("utf-8"))
            payload = ScanRequest.model_validate(data)
            turnstile_token = str(data.get("turnstile_token") or "")
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Richiesta non valida.") from exc
        remote_ip = (
            request.headers.get("cf-connecting-ip")
            or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
            or (request.client.host if request.client else None)
        )
        _verify_turnstile(turnstile_token, remote_ip)
        return engine.audit(payload.url)
    except HTTPException:
        raise
    except UnsafeTargetError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc
    except AuditError as exc:
        raise HTTPException(status_code=422,detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500,detail="Analisi non completata. Riprova più tardi.") from exc
