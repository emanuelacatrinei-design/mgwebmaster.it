"""Bounded, DNS-pinned HTTP transport for untrusted scan targets.

No cookies, proxy environment variables, automatic redirects or target scripts.
The parent process enforces a separate hard deadline, including DNS and parsing.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, urlunparse

import certifi
import urllib3
from requests.structures import CaseInsensitiveDict
from requests.utils import get_encoding_from_headers

MAX_URL_LENGTH = 2048
MAX_REDIRECTS = 5
MAX_HTML_BYTES = 2_000_000
SCAN_SECONDS = 45
MAX_TOTAL_BYTES = 12_000_000
MAX_REQUESTS = 36
UA = "MGWebmaster-SiteCheck/0.2 (+https://www.mgwebmaster.it/)"


class AuditError(RuntimeError):
    pass


class UnsafeTargetError(AuditError):
    pass


class ScanLimitError(AuditError):
    pass


def normalize_url(value: str) -> str:
    value = (value or "").strip()
    if not value or len(value) > MAX_URL_LENGTH:
        raise AuditError("URL mancante o troppo lungo.")
    if re.search(r"[\x00-\x20\x7f\\]", value):
        raise UnsafeTargetError("URL non valido.")
    if "://" not in value:
        value = "https://" + value
    try:
        p = urlparse(value)
        if p.scheme not in {"http", "https"}:
            raise UnsafeTargetError("Sono consentiti solo URL HTTP/HTTPS.")
        if p.username is not None or p.password is not None:
            raise UnsafeTargetError("URL con credenziali non consentiti.")
        if not p.hostname or p.port not in {None, 80, 443}:
            raise UnsafeTargetError("Dominio o porta non consentiti.")
        host = p.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        try:
            addr = ipaddress.ip_address(host)
            host = f"[{addr.compressed}]" if addr.version == 6 else addr.compressed
        except ValueError:
            if len(host) > 253 or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in host.split(".")
            ):
                raise UnsafeTargetError("Dominio non valido.")
        netloc = host + (f":{p.port}" if p.port else "")
        return urlunparse((p.scheme, netloc, p.path or "/", "", p.query, ""))
    except (ValueError, UnicodeError) as exc:
        raise UnsafeTargetError("URL non valido.") from exc


def public_ip(raw: str) -> bool:
    try:
        ip = ipaddress.ip_address(raw)
        if not ip.is_global or ip.is_multicast:
            return False
        if ip.version == 6:
            # Reject transition/translation mechanisms, including mapped private IPv4.
            if ip.ipv4_mapped or ip.sixtofour or ip.teredo:
                return False
            if any(ip in ipaddress.ip_network(n) for n in ("64:ff9b::/96", "64:ff9b:1::/48")):
                return False
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class Target:
    url: str
    host: str
    port: int
    addresses: tuple[str, ...]


def resolve_target(value: str) -> Target:
    url = normalize_url(value)
    p = urlparse(url)
    host = p.hostname or ""
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise UnsafeTargetError("Destinazione interna non consentita.")
    port = p.port or (443 if p.scheme == "https" else 80)
    try:
        literal = ipaddress.ip_address(host)
        addresses = (literal.compressed,)
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise AuditError("Dominio non risolvibile.") from exc
        addresses = tuple(dict.fromkeys(info[4][0] for info in infos))
    if not addresses or not all(public_ip(ip) for ip in addresses):
        raise UnsafeTargetError("Destinazione privata o riservata non consentita.")
    return Target(url, host, port, addresses)


class Budget:
    def __init__(self, seconds=SCAN_SECONDS):
        self.deadline = time.monotonic() + seconds
        self.bytes = 0
        self.requests = 0

    def remaining(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise ScanLimitError("Tempo massimo della scansione raggiunto.")
        return left

    def request(self):
        self.remaining()
        self.requests += 1
        if self.requests > MAX_REQUESTS:
            raise ScanLimitError("Limite delle richieste della scansione raggiunto.")

    def consume(self, size):
        self.remaining()
        self.bytes += size
        if self.bytes > MAX_TOTAL_BYTES:
            raise ScanLimitError("Limite dei dati della scansione raggiunto.")


@dataclass
class ResponseInfo:
    url: str
    status_code: int
    headers: CaseInsensitiveDict
    encoding: str | None

    def close(self):
        # All sockets have already been closed before returning this value.
        pass


class SafeFetcher:
    def __init__(self, budget=None):
        self.budget = budget or Budget()

    def fetch(self, value, html_only=True, max_bytes=MAX_HTML_BYTES):
        current = normalize_url(value)
        started = time.monotonic()
        for hop in range(MAX_REDIRECTS + 1):
            self.budget.request()
            target = resolve_target(current)
            left = self.budget.remaining()
            p = urlparse(target.url)
            # The connection host is numeric: the validated domain is never resolved again.
            # Retain the original hostname for Host, SNI AND certificate verification.
            kwargs = {"host": target.addresses[0], "port": target.port, "maxsize": 1}
            if p.scheme == "https":
                pool = urllib3.HTTPSConnectionPool(
                    **kwargs, server_hostname=target.host, assert_hostname=target.host,
                    cert_reqs="CERT_REQUIRED", ca_certs=certifi.where(),
                )
            else:
                pool = urllib3.HTTPConnectionPool(**kwargs)
            response = None
            try:
                path = p.path or "/"
                if p.query:
                    path += "?" + p.query
                response = pool.request(
                    "GET", path,
                    headers={"Host": p.netloc, "User-Agent": UA,
                             "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
                             "Accept-Encoding": "identity"},
                    redirect=False, retries=False, preload_content=False, decode_content=False,
                    assert_same_host=False,
                    timeout=urllib3.Timeout(connect=min(5, left), read=min(8, left)),
                )
                self.budget.remaining()
                headers = CaseInsensitiveDict(response.headers)
                if response.status in {301, 302, 303, 307, 308}:
                    location = headers.get("Location")
                    if not location or hop == MAX_REDIRECTS:
                        raise AuditError("Redirect non valido o limite raggiunto.")
                    # The next iteration resolves and pins every new destination.
                    current = normalize_url(urljoin(target.url, location))
                    continue
                if html_only and not any(t in headers.get("Content-Type", "").lower()
                                         for t in ("text/html", "application/xhtml+xml")):
                    raise AuditError("La risorsa non è una pagina HTML.")
                # We request identity encoding. Reject noncompliant compressed responses
                # rather than allocating memory to an unbounded decompression operation.
                if headers.get("Content-Encoding", "identity").strip().lower() != "identity":
                    raise AuditError("Compressione della risposta non supportata.")
                length = headers.get("Content-Length", "")
                if length.isdigit() and int(length) > max_bytes:
                    raise AuditError("Risorsa troppo grande per la scansione gratuita.")
                parts, size = [], 0
                while True:
                    self.budget.remaining()
                    chunk = response.read(65536, decode_content=False)
                    if not chunk:
                        break
                    self.budget.consume(len(chunk))
                    size += len(chunk)
                    if size > max_bytes:
                        raise AuditError("Risorsa troppo grande per la scansione gratuita.")
                    parts.append(chunk)
                return (ResponseInfo(target.url, response.status, headers,
                                     get_encoding_from_headers(headers)),
                        b"".join(parts), int((time.monotonic() - started) * 1000))
            except (urllib3.exceptions.HTTPError, OSError) as exc:
                raise AuditError("Connessione al sito non riuscita.") from exc
            finally:
                if response is not None:
                    response.close()
                pool.close()
        raise AuditError("Troppi redirect.")
