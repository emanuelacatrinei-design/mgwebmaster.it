import io
import socket
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock

import pytest

import app
import security as sec


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "ftp://example.com/", "https://user:pass@example.com/",
    "https://example.com:8080/", "https://example.com\\@other.example/",
    "https://example.com/\nheader", "https://example.com:wrong/",
    "https://[::1", "https://bad_host.example/", "https://example.com%00/",
])
def test_invalid_urls(url):
    with pytest.raises(sec.AuditError):
        sec.normalize_url(url)


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "0.0.0.0", "10.0.0.1", "172.16.0.1", "192.168.0.1",
    "169.254.169.254", "100.64.0.1", "224.0.0.1", "192.0.2.1",
    "::1", "::", "fc00::1", "fe80::1", "ff02::1", "::ffff:127.0.0.1",
    "64:ff9b::a00:1", "2002:7f00:1::1",
])
def test_nonpublic_addresses(ip):
    assert not sec.public_ip(ip)


def dns(*addresses):
    return [(socket.AF_INET6 if ":" in ip else socket.AF_INET,
             socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in addresses]


def test_mixed_dns_answers_are_rejected(monkeypatch):
    monkeypatch.setattr(sec.socket, "getaddrinfo", lambda *a, **k: dns("93.184.216.34", "10.0.0.1"))
    with pytest.raises(sec.UnsafeTargetError):
        sec.resolve_target("https://example.com")


class Response:
    def __init__(self, body=b"<html>ok</html>", status=200, headers=None):
        self.status = status
        self.headers = headers or {"Content-Type": "text/html; charset=utf-8"}
        self.stream = io.BytesIO(body)
        self.closed = False

    def read(self, amount, **kwargs):
        return self.stream.read(amount)

    def close(self):
        self.closed = True


def fake_network(monkeypatch, responses):
    connections = []

    class Pool:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.closed = False
            self.calls = []
            connections.append(self)

        def request(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            return responses.pop(0)

        def close(self):
            self.closed = True

    monkeypatch.setattr(sec.urllib3, "HTTPSConnectionPool", Pool)
    monkeypatch.setattr(sec.urllib3, "HTTPConnectionPool", Pool)
    return connections


def test_dns_is_not_repeated_by_connection_and_tls_identity_is_preserved(monkeypatch):
    resolver = Mock(side_effect=[dns("93.184.216.34"), dns("127.0.0.1")])
    monkeypatch.setattr(sec.socket, "getaddrinfo", resolver)
    pools = fake_network(monkeypatch, [Response()])
    response, body, _ = sec.SafeFetcher().fetch("https://example.com/path?q=1")
    assert resolver.call_count == 1
    assert pools[0].kwargs["host"] == "93.184.216.34"
    assert pools[0].kwargs["server_hostname"] == "example.com"
    assert pools[0].kwargs["assert_hostname"] == "example.com"
    assert pools[0].kwargs["cert_reqs"] == "CERT_REQUIRED"
    call = pools[0].calls[0]
    assert call[0] == ("GET", "/path?q=1")
    assert call[1]["headers"]["Host"] == "example.com"
    assert call[1]["redirect"] is False and call[1]["retries"] is False
    assert body.startswith(b"<html>") and response.url == "https://example.com/path?q=1"
    assert pools[0].closed


def test_redirect_to_private_network_is_blocked_before_connection(monkeypatch):
    monkeypatch.setattr(sec.socket, "getaddrinfo", lambda *a, **k: dns("93.184.216.34"))
    response = Response(status=302, headers={"Location": "http://169.254.169.254/"})
    pools = fake_network(monkeypatch, [response])
    with pytest.raises(sec.UnsafeTargetError):
        sec.SafeFetcher().fetch("https://example.com/")
    assert len(pools) == 1 and response.closed and pools[0].closed


def test_same_domain_rebound_on_redirect_is_blocked(monkeypatch):
    monkeypatch.setattr(sec.socket, "getaddrinfo", Mock(side_effect=[dns("93.184.216.34"), dns("127.0.0.1")]))
    pools = fake_network(monkeypatch, [Response(status=302, headers={"Location": "/next"})])
    with pytest.raises(sec.UnsafeTargetError):
        sec.SafeFetcher().fetch("https://example.com/")
    assert len(pools) == 1


def test_public_redirect_tracks_final_url(monkeypatch):
    monkeypatch.setattr(sec.socket, "getaddrinfo", lambda *a, **k: dns("93.184.216.34"))
    fake_network(monkeypatch, [Response(status=301, headers={"Location": "/new"}), Response()])
    result, _, _ = sec.SafeFetcher().fetch("https://example.com/")
    assert result.url == "https://example.com/new"


@pytest.mark.parametrize("headers,body", [
    ({"Content-Type": "text/html", "Content-Length": "1000"}, b""),
    ({"Content-Type": "text/html"}, b"x" * 101),
    ({"Content-Type": "text/html", "Content-Encoding": "gzip"}, b"compressed"),
])
def test_oversize_and_compressed_responses_rejected(monkeypatch, headers, body):
    monkeypatch.setattr(sec.socket, "getaddrinfo", lambda *a, **k: dns("93.184.216.34"))
    response = Response(body=body, headers=headers)
    pools = fake_network(monkeypatch, [response])
    with pytest.raises(sec.AuditError):
        sec.SafeFetcher().fetch("https://example.com/", max_bytes=100)
    assert response.closed and pools[0].closed


def test_total_resource_budgets():
    with pytest.raises(sec.ScanLimitError):
        sec.Budget(seconds=-1).remaining()
    budget = sec.Budget()
    budget.bytes = sec.MAX_TOTAL_BYTES
    with pytest.raises(sec.ScanLimitError):
        budget.consume(1)
    budget.requests = sec.MAX_REQUESTS
    with pytest.raises(sec.ScanLimitError):
        budget.request()


def test_full_audit_contract_with_public_fixture(monkeypatch):
    html = b'''<html><head><title>Fixture service website for a business</title>
    <meta name="description" content="A useful service description for this fixture.">
    <link rel="canonical" href="https://example.com/"></head><body><h1>Services</h1>
    <p>Contact us for a quote. Phone +39 345 322 3023.</p></body></html>'''
    def fetch(self, url, **kwargs):
        status = 200
        headers = sec.CaseInsensitiveDict({"Content-Type": "text/html; charset=utf-8"})
        return sec.ResponseInfo(url, status, headers, "utf-8"), html, 10
    monkeypatch.setattr(app.Engine, "fetch", fetch)
    report = app.Engine().audit("https://example.com/")
    assert report["pages_checked"] == 1
    assert report["final_url"] == "https://example.com/"
    assert set(report["scores"]) == {"seo", "performance", "security", "content", "local"}
    assert isinstance(report["issues"], list) and "disclaimer" in report


@pytest.fixture(scope="module")
def tls_fixture(tmp_path_factory):
    folder = tmp_path_factory.mktemp("tls")
    cert, key = folder / "cert.pem", folder / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-days", "1",
                    "-subj", "/CN=fixture.example", "-addext", "subjectAltName=DNS:fixture.example"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html>Verified TLS fixture</html>")
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_port, cert
    server.shutdown()
    server.server_close()
    thread.join()


def test_real_tls_connection_keeps_certificate_verification(monkeypatch, tls_fixture):
    port, cert = tls_fixture
    # Local fixture only: replace resolution, never the TLS implementation.
    monkeypatch.setattr(sec, "resolve_target", lambda url: sec.Target(url, "fixture.example", port, ("127.0.0.1",)))
    monkeypatch.setattr(sec.certifi, "where", lambda: str(cert))
    _, body, _ = sec.SafeFetcher().fetch("https://fixture.example/")
    assert b"Verified TLS" in body
    monkeypatch.setattr(sec, "resolve_target", lambda url: sec.Target(url, "wrong.example", port, ("127.0.0.1",)))
    with pytest.raises(sec.AuditError):
        sec.SafeFetcher().fetch("https://wrong.example/")
