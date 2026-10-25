from __future__ import annotations

from contextlib import asynccontextmanager
import asyncio
import hashlib
import ipaddress
import logging
import multiprocessing
import json
import os
import re
import threading
import time
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from typing import Literal

from security import (AuditError, UnsafeTargetError, ScanLimitError, Budget, SafeFetcher,
                      SCAN_SECONDS, normalize_url)

from passive_security import php_evidence, php_report, passive_findings, localize_report

from advisory_feed import start_refresh, metadata as feed_metadata
from csp_analysis import policies as csp_policies, parse as parse_csp

from report_model import MODEL, summarize, group_issues

VERSION = "0.7.0"
MAX_PAGES = 5
RATE_LIMIT = 5
RATE_WINDOW_SECONDS = 600
TURNSTILE_SECRET = os.getenv("TURNSTILE_SECRET","").strip()
TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
_RATE_LOCK = threading.Lock()
_RATE_BUCKETS = {}
_RATE_SALT = os.urandom(16)
_MAX_RATE_BUCKETS = 5000
_MAX_BODY_BYTES = 8192
_SCAN_SLOTS = threading.BoundedSemaphore(2)
_GLOBAL_HITS = []
_LOG = logging.getLogger("mgw.sitecheck")
# Empty by default: never trust arbitrary client-supplied forwarding headers.
# Only configure networks of proxies whose append/overwrite behavior is verified.
_TRUSTED_PROXIES = tuple(ipaddress.ip_network(n.strip()) for n in
                         os.getenv("MG_TRUSTED_PROXY_CIDRS", "").split(",") if n.strip())

SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", "medium"),
    "content-security-policy": ("CSP", "medium"),
    "x-content-type-options": ("X-Content-Type-Options", "medium"),
    "referrer-policy": ("Referrer-Policy", "medium"),
    "permissions-policy": ("Permissions-Policy", "medium"),
    "x-frame-options": ("X-Frame-Options", "medium"),
}
SKIP_EXT = (".jpg",".jpeg",".png",".gif",".webp",".svg",".pdf",".zip",".rar",".7z",".mp4",".mp3",".css",".js",".xml",".json",".ico",".woff",".woff2",".ttf")
HINTS = ("servizi","services","servicii","service","chi-sono","about","despre","contatti","contact","prezzi","pricing","preturi","negozio","shop","prodotti","products")


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


class Engine(SafeFetcher):
    def probe(self, url: str) -> int:
        try:
            r, _, _ = self.fetch(url, html_only=False, max_bytes=512_000)
            status = int(r.status_code)
            r.close()
            return status
        except ScanLimitError:
            raise
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
            add("h1","Contenuti","medium","H1 mancante","La pagina non presenta un H1; verificare la struttura del contenuto.")
            issues[-1].update(title_ro="Titlu H1 neidentificat", message_ro="Pagina nu prezintă un H1; verifică structura conținutului.")
        elif len(h1s) > 1:
            add("h1_multiple","Contenuti","low","Più H1 rilevati","Sono presenti più H1; conviene verificarne la gerarchia.")
        if len(words) < 180:
            add("thin","Contenuti","medium","Contenuto molto breve","La pagina contiene poco testo utile rispetto a una normale pagina servizio.")
        if not canonical:
            add("canonical","SEO tecnica","medium","Canonical non rilevata","Non è stato rilevato un URL canonical.")
        if re.search(r"(?:^|[\s,;])(?:noindex|none)(?:$|[\s,;])", robots, re.I):
            add("noindex","SEO tecnica","low","Noindex: verificare se è voluto","La pagina richiede l’esclusione dall’indice. Verificare se è intenzionale: per pagine riservate o di servizio può essere corretto; per una pagina che deve comparire nei risultati richiede una correzione.")
            issues[-1].update(title_ro="Noindex: verifică dacă este intenționat", message_ro="Pagina solicită excluderea din index. Verifică dacă este intenționată: poate fi corectă pentru pagini private sau utilitare; o pagină care trebuie să apară în rezultate necesită corectare.")
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
            if header == "content-security-policy":
                present = bool(csp_policies(soup, r.headers))
            if header == "strict-transport-security" and urlparse(final).scheme != "https":
                present = False
            if header == "x-frame-options" and any(parse_csp(p).get("frame-ancestors") for p in csp_value.split(",")):
                present = True
            if not present:
                add("sec_"+header,"Sicurezza",sev,f"{label} non rilevato","Manca una protezione HTTP consigliata; serve una verifica della configurazione.")

        raw_headers = getattr(r, "raw", None)
        raw_headers = getattr(raw_headers, "headers", None)
        cookie_headers = list(raw_headers.getlist("Set-Cookie")) if raw_headers is not None and hasattr(raw_headers, "getlist") else []
        if not cookie_headers and r.headers.get("set-cookie"):
            cookie_headers = [r.headers["set-cookie"]]
        php = php_evidence(r.headers, final, cookie_headers)
        issues.extend(passive_findings(soup, r.headers, final, cookie_headers))
        php_check = php_report(php)
        if php_check["status"] in {"unsupported", "potentially_outdated"}:
            issues.append({"code": "sec_php_version", "area": "Sicurezza", "severity": "high",
                           **{k: php_check[k] for k in ("title", "message", "title_ro", "message_ro")}, "page": final})

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
            "url":final,"status_code":r.status_code,"issues":issues,"php":php,"links":sorted(set(internal),key=self.priority),
            "local":{"phone":has_phone,"maps":has_maps,"address":has_address,"schema":schema_types(soup)},
            "cta":has_cta
        }

    @staticmethod
    def score(area, pages):
        penalties={"high":14,"medium":7,"low":3}
        code_penalties={
            "http_error":22,
            "noindex":0,
            "scripts":0, "styles":0, "server":0,
            "https":20,
            "sec_strict-transport-security":16,
            "sec_content-security-policy":16,
        }
        vals=[]
        for p in pages:
            if p.get("status_code", 200) >= 400 or any(i["code"] == "http_error" for i in p["issues"]):
                continue
            value=100
            for i in p["issues"]:
                if i["area"]==area:
                    value-=code_penalties.get(i["code"],penalties.get(i["severity"],0))
            vals.append(max(0,min(100,value)))
        return round(sum(vals)/len(vals)) if vals else None

    def audit(self, raw: str):
        started=time.perf_counter()
        requested=normalize_url(raw)
        first=self.audit_page(requested)
        pages=[first]
        seen={normalize_url(first["url"])}
        for candidate in first["links"]:
            if len(pages)>=MAX_PAGES:
                break
            try:
                self.budget.remaining()
                candidate=normalize_url(candidate)
            except ScanLimitError:
                raise
            except AuditError:
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            try:
                pages.append(self.audit_page(candidate))
            except ScanLimitError:
                raise
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

        # Local competitiveness is not measured; keep it explicitly unavailable.
        areas = {'seo': 'SEO tecnica', 'performance': 'Prestazioni',
                 'security': 'Sicurezza', 'content': 'Contenuti'}
        scores = {key: self.score(area, pages) for key, area in areas.items()}
        scores['local'] = None
        page_issue_ids = {id(i) for p in pages for i in p['issues']}
        # Site-wide robots/sitemap/CTA findings apply once, not divided by page count.
        for key, area in areas.items():
            if scores[key] is not None:
                global_penalty = sum({'high': 14, 'medium': 7, 'low': 3}.get(i['severity'], 0)
                                     for i in issues if id(i) not in page_issue_ids and i['area'] == area)
                scores[key] = max(0, scores[key] - global_penalty)
        unique=group_issues(issues)
        summary=summarize(scores, unique)
        counts={severity:sum(i["severity"]==severity for i in unique) for severity in ("high","medium","low")}
        counts["total"]=len(unique)

        return {
            "requested_url":requested,"final_url":first["url"],"scanned_at_epoch":int(time.time()),
            "duration_ms":int((time.perf_counter()-started)*1000),"pages_checked":len(pages),
            "overall_score":summary["technical_score"],"scores":scores,"counts":counts,"criticality":summary["security_priority"],
            **summary,
            "issues":unique,
            "php":php_report([observation for p in pages for observation in p.get("php", [])]),
            "disclaimer":"Controllo preliminare su un massimo di cinque pagine, non un audit completo. I punteggi tecnici descrivono solo i controlli eseguiti sulle pagine analizzate. I conteggi indicano gruppi di segnalazioni. Qualità dei testi, Core Web Vitals, competitività locale e capacità di posizionamento non sono valutati. Nessuna segnalazione non significa assenza di problemi. La scansione non certifica sicurezza né assenza di malware."
        }


class ScanRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)
    authorized: Literal[True]
    language: Literal["it", "ro"] = "it"


origin=os.getenv("MG_SITE_ORIGIN","https://www.mgwebmaster.it")
allowed_origins=list(dict.fromkeys([
    origin,
    "https://www.mgwebmaster.it",
    "https://mgwebmaster.it",
]))
@asynccontextmanager
async def lifespan(application):
    stop = start_refresh()
    try:
        yield
    finally:
        stop.set()


app=FastAPI(lifespan=lifespan,title="MG Webmaster Site Check API",version=VERSION,docs_url=None,redoc_url=None,openapi_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET","POST","OPTIONS"],
    allow_headers=["Content-Type","Accept"],
)


def _client_ip(request: Request) -> str:
    peer = request.client.host if request.client else "unknown"
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return "unknown"
    if not any(address in network for network in _TRUSTED_PROXIES):
        return address.compressed
    chain = request.headers.get("x-forwarded-for", "").split(",")
    if len(chain) > 16:
        return address.compressed
    # Skip only explicitly trusted proxies, walking from the server towards the client.
    for raw in reversed(chain):
        if not any(address in network for network in _TRUSTED_PROXIES):
            break
        try:
            address = ipaddress.ip_address(raw.strip())
        except ValueError:
            return peer
    return address.compressed


def _client_key(request: Request) -> str:
    return hashlib.sha256(_RATE_SALT + _client_ip(request).encode()).hexdigest()


def _verify_turnstile(token: str):
    if not TURNSTILE_SECRET:
        raise HTTPException(status_code=503, detail="Protezione anti-bot non configurata.")
    token = (token or "").strip()
    if not token or len(token) > 2048:
        raise HTTPException(status_code=400, detail="Verifica anti-bot mancante o non valida.")
    # Do not send untrusted proxy headers as remoteip to the validation service.
    with requests.Session() as session:
        session.trust_env = False
        try:
            response = session.post(
                TURNSTILE_VERIFY_URL, data={"secret": TURNSTILE_SECRET, "response": token},
                headers={"Accept-Encoding": "identity"},
                timeout=(3, 5), allow_redirects=False, stream=True,
            )
            with response:
                if response.status_code != 200:
                    raise ValueError("Siteverify response")
                raw = response.raw.read(16385, decode_content=False)
                if len(raw) > 16384:
                    raise ValueError("Siteverify response too large")
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise ValueError("Siteverify format")
        except Exception as exc:
            raise HTTPException(status_code=502, detail="Verifica anti-bot non disponibile.") from exc
    if (data.get("success") is not True
            or data.get("hostname") not in {"www.mgwebmaster.it", "mgwebmaster.it"}
            or data.get("action") != "site_scan"):
        raise HTTPException(status_code=403, detail="Verifica anti-bot non superata.")


def _rate_limit(request: Request):
    now = time.monotonic()
    key = _client_key(request)
    with _RATE_LOCK:
        hits = [t for t in _RATE_BUCKETS.get(key, []) if now - t < RATE_WINDOW_SECONDS]
        if len(hits) >= RATE_LIMIT:
            raise HTTPException(status_code=429, detail="Limite temporaneo raggiunto. Riprova più tardi.",
                                headers={"Retry-After": str(RATE_WINDOW_SECONDS)})
        if key not in _RATE_BUCKETS and len(_RATE_BUCKETS) >= _MAX_RATE_BUCKETS:
            stale = [k for k, v in _RATE_BUCKETS.items() if not v or now - v[-1] >= RATE_WINDOW_SECONDS]
            for k in stale:
                del _RATE_BUCKETS[k]
            if len(_RATE_BUCKETS) >= _MAX_RATE_BUCKETS:
                raise HTTPException(status_code=429, detail="Servizio temporaneamente occupato.")
        hits.append(now)
        _RATE_BUCKETS[key] = hits


def _scan_quota():
    # Invalid anti-bot tokens must not exhaust the quota for verified visitors.
    now = time.monotonic()
    with _RATE_LOCK:
        _GLOBAL_HITS[:] = [t for t in _GLOBAL_HITS if now - t < RATE_WINDOW_SECONDS]
        if len(_GLOBAL_HITS) >= 20:
            raise HTTPException(status_code=429, detail="Limite temporaneo del servizio raggiunto.",
                                headers={"Retry-After": str(RATE_WINDOW_SECONDS)})
        _GLOBAL_HITS.append(now)


async def _read_body(request: Request):
    size = 0
    chunks = []
    declared = request.headers.get("content-length")
    if declared is not None:
        if not declared.isdigit():
            raise HTTPException(status_code=400, detail="Richiesta non valida.")
        if int(declared) > _MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="Richiesta troppo grande.")
    if request.headers.get("content-encoding", "identity").lower() != "identity":
        raise HTTPException(status_code=415, detail="Compressione della richiesta non supportata.")
    async for chunk in request.stream():
        size += len(chunk)
        if size > _MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="Richiesta troppo grande.")
        chunks.append(chunk)
    return b"".join(chunks)


def _audit_worker(url, sender):
    try:
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_AS, (192 * 1024 * 1024, 192 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_CPU, (40, 41))
        except ImportError:
            # Unix limits apply on Render; Windows still has the parent hard timeout.
            pass
        sender.send((200, Engine(Budget()).audit(url)))
    except UnsafeTargetError:
        sender.send((400, "Destinazione non consentita per la scansione."))
    except ScanLimitError:
        sender.send((504, "Limite di tempo o risorse della scansione raggiunto."))
    except AuditError:
        sender.send((422, "Impossibile completare la scansione di questo sito."))
    except Exception:
        sender.send((500, "Analisi non completata. Riprova più tardi."))
    finally:
        sender.close()


def _run_audit(url, timeout=SCAN_SECONDS, worker=_audit_worker):
    # A killable child bounds DNS resolution, slow responses AND HTML/JSON parsing.
    # A timed-out thread would continue consuming resources after returning an error.
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=worker, args=(url, sender), daemon=True)
    try:
        process.start()
        sender.close()
        if not receiver.poll(timeout):
            raise HTTPException(status_code=504, detail="Tempo massimo della scansione raggiunto.")
        try:
            status, result = receiver.recv()
        except EOFError as exc:
            raise HTTPException(status_code=502, detail="Motore di analisi non disponibile.") from exc
        if status != 200:
            raise HTTPException(status_code=status, detail=result)
        return result
    finally:
        receiver.close()
        sender.close()
        if process.pid is not None:
            if process.is_alive():
                process.terminate()
            process.join(timeout=1)
            if process.is_alive():
                process.kill()
                process.join(timeout=1)
            process.close()


@app.middleware("http")
async def response_headers(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Robots-Tag"] = "noindex"
    return response


@app.exception_handler(HTTPException)
async def api_error(request, exc):
    language = getattr(request.state, "language", request.headers.get("accept-language", "it")[:2])
    romanian = {
        400: "Adresa URL sau cererea nu este validă. Verifică datele și încearcă din nou.",
        403: "Verificarea anti-bot nu a fost validată. Repetă verificarea și încearcă din nou.",
        408: "Timpul de trimitere a cererii a expirat. Încearcă din nou.",
        413: "Cererea este prea mare.",
        415: "Formatul cererii nu este acceptat.",
        422: "Analiza acestui site nu a putut fi finalizată.",
        429: "Limita temporară de cereri a fost atinsă. Încearcă din nou mai târziu.",
        500: "Analiza nu a fost finalizată. Încearcă din nou mai târziu.",
        502: "Serviciul de analiză sau verificare nu este disponibil momentan.",
        503: "Serviciul este ocupat sau indisponibil momentan. Încearcă din nou mai târziu.",
        504: "Limita de timp sau de resurse a analizei a fost atinsă.",
    }
    detail = romanian.get(exc.status_code, "Cererea nu a putut fi finalizată.") if language == "ro" else exc.detail
    return JSONResponse({"detail": detail}, status_code=exc.status_code, headers=exc.headers)


@app.get("/health")
def health():
    return {"ok": True, "status": "healthy", "service": "mg-site-check", "version": VERSION, "score_model": MODEL, "php_advisories": feed_metadata()}


@app.post("/v1/scan")
async def scan(request: Request):
    _rate_limit(request)
    if not _SCAN_SLOTS.acquire(blocking=False):
        raise HTTPException(status_code=503, detail="Motore occupato. Riprova tra poco.",
                            headers={"Retry-After": "15"})
    try:
        try:
            raw = await asyncio.wait_for(_read_body(request), timeout=10)
        except asyncio.TimeoutError as exc:
            raise HTTPException(status_code=408, detail="Tempo di invio della richiesta scaduto.") from exc
        try:
            data = json.loads(raw.decode("utf-8"))
            payload = ScanRequest.model_validate(data)
            request.state.language = payload.language
            token = data.get("turnstile_token", "")
            if not isinstance(token, str):
                raise ValueError("Token format")
            normalize_url(payload.url)
        except (ValueError, AuditError, UnicodeError) as exc:
            raise HTTPException(status_code=400, detail="URL o richiesta non validi.") from exc
        await run_in_threadpool(_verify_turnstile, token)
        _scan_quota()
        result = await run_in_threadpool(_run_audit, payload.url)
        _LOG.info("scan_completed pages=%s", result.get("pages_checked", 0))
        return localize_report(result, payload.language)
    except HTTPException as exc:
        _LOG.info("scan_rejected status=%s", exc.status_code)
        raise
    except Exception as exc:
        _LOG.error("scan_failed category=%s", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Analisi non completata. Riprova più tardi.") from exc
    finally:
        _SCAN_SLOTS.release()

