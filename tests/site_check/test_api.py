import asyncio
import ipaddress
import io
import json
import multiprocessing
import os
import threading
import time
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest
from fastapi import HTTPException
from starlette.requests import Request

import app
import security as sec


@pytest.fixture(autouse=True)
def reset_limits(monkeypatch):
    app._RATE_BUCKETS.clear()
    app._GLOBAL_HITS.clear()
    monkeypatch.setattr(app, "_SCAN_SLOTS", threading.BoundedSemaphore(2))
    monkeypatch.setattr(app, "_TRUSTED_PROXIES", ())


def payload(**extra):
    return {"url": "https://example.com/", "authorized": True,
            "turnstile_token": "fixture-token", **extra}


def test_health_missing_token_and_fail_closed_configuration(monkeypatch):
    monkeypatch.setattr(app, "TURNSTILE_SECRET", "")
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app), base_url="https://api.example") as client:
            health = await client.get("/health")
            assert health.status_code == 200 and health.json()["version"] == "0.7.0"
            assert health.headers["cache-control"] == "no-store"
            assert (await client.get("/openapi.json")).status_code == 404
            response = await client.post("/v1/scan", json=payload())
            assert response.status_code == 503
    asyncio.run(run())


def test_body_size_limit_also_without_content_length():
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app), base_url="https://api.example") as client:
            response = await client.post("/v1/scan", content=b"x" * 8193)
            assert response.status_code == 413
            async def chunks():
                yield b"x" * 4096
                yield b"x" * 4097
            response = await client.post("/v1/scan", content=chunks())
            assert response.status_code == 413
    asyncio.run(run())


def test_spoofed_forwarding_headers_do_not_reset_rate_limit():
    async def run():
        transport = httpx.ASGITransport(app=app.app, client=("203.0.113.10", 123))
        async with httpx.AsyncClient(transport=transport, base_url="https://api.example") as client:
            for i in range(6):
                response = await client.post("/v1/scan", content="invalid-json", headers={
                    "CF-Connecting-IP": f"198.51.100.{i}", "X-Forwarded-For": f"198.51.100.{i}"})
                assert response.status_code == (400 if i < 5 else 429)
            assert response.headers["retry-after"] == "600"
    asyncio.run(run())


def test_trusted_chain_is_read_from_right_to_left(monkeypatch):
    monkeypatch.setattr(app, "_TRUSTED_PROXIES", (ipaddress.ip_network("10.0.0.0/8"),))
    request = Request({"type": "http", "client": ("10.0.0.2", 1), "headers": [
        (b"x-forwarded-for", b"198.51.100.99, 203.0.113.10, 10.0.0.1"),
        (b"cf-connecting-ip", b"198.51.100.99")]})
    assert app._client_ip(request) == "203.0.113.10"


@pytest.mark.parametrize("verification,expected", [
    ({"success": False, "error-codes": ["timeout-or-duplicate"]}, 403),
    ({"success": True, "hostname": "other.example", "action": "site_scan"}, 403),
    ({"success": True, "hostname": "www.mgwebmaster.it", "action": "login"}, 403),
    ({"success": True, "hostname": "www.mgwebmaster.it", "action": "site_scan"}, 200),
])
def test_turnstile_server_validation(monkeypatch, verification, expected):
    monkeypatch.setattr(app, "TURNSTILE_SECRET", "fixture-secret-not-a-real-key")
    response = Mock(status_code=200)
    response.raw = Mock()
    response.raw.read.return_value = json.dumps(verification).encode()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    session = Mock()
    session.post.return_value = response
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(app.requests, "Session", lambda: session)
    if expected == 200:
        app._verify_turnstile("fixture-token")
    else:
        with pytest.raises(HTTPException) as exc:
            app._verify_turnstile("fixture-token")
        assert exc.value.status_code == expected
    assert session.trust_env is False
    assert session.post.call_args.kwargs["allow_redirects"] is False


def test_invalid_token_never_starts_scan_or_consumes_verified_quota(monkeypatch):
    def reject(token):
        raise HTTPException(403, "Verifica anti-bot non superata.")
    scanner = Mock()
    monkeypatch.setattr(app, "_verify_turnstile", reject)
    monkeypatch.setattr(app, "_run_audit", scanner)
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app), base_url="https://api.example") as client:
            response = await client.post("/v1/scan", json=payload(language="ro"))
            assert response.status_code == 403
            assert "anti-bot" in response.json()["detail"] and "Repetă" in response.json()["detail"]
    asyncio.run(run())
    scanner.assert_not_called()
    assert app._GLOBAL_HITS == []


def test_scan_limit_and_health_remains_responsive(monkeypatch):
    release = threading.Event()
    started = threading.Event()
    def scan(url):
        started.set()
        release.wait(5)
        return {"pages_checked": 1, "final_url": url, "scores": {}, "issues": []}
    monkeypatch.setattr(app, "_verify_turnstile", lambda token: None)
    monkeypatch.setattr(app, "_run_audit", scan)
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app), base_url="https://api.example") as client:
            tasks = [asyncio.create_task(client.post("/v1/scan", json=payload())) for _ in range(2)]
            try:
                for _ in range(100):
                    if started.is_set() and app._SCAN_SLOTS._value == 0:
                        break
                    await asyncio.sleep(.01)
                third = await client.post("/v1/scan", json=payload())
                assert third.status_code == 503
                health = await asyncio.wait_for(client.get("/health"), 1)
                assert health.status_code == 200
            finally:
                release.set()
            assert all(r.status_code == 200 for r in await asyncio.gather(*tasks))
    asyncio.run(run())
    assert app._SCAN_SLOTS._value == 2


def test_verified_global_quota():
    for _ in range(20):
        app._scan_quota()
    with pytest.raises(HTTPException) as exc:
        app._scan_quota()
    assert exc.value.status_code == 429


def _slow_worker(marker, sender):
    Path(marker).write_text(str(os.getpid()))
    time.sleep(60)


def test_hard_timeout_terminates_child(tmp_path):
    marker = tmp_path / "child-started"
    before = {p.pid for p in multiprocessing.active_children()}
    started = time.monotonic()
    with pytest.raises(HTTPException) as exc:
        app._run_audit(str(marker), timeout=2, worker=_slow_worker)
    assert exc.value.status_code == 504
    assert marker.exists(), "Test must reach the blocking child operation"
    assert time.monotonic() - started < 5
    assert {p.pid for p in multiprocessing.active_children()} == before


def test_real_child_rejects_private_target():
    with pytest.raises(HTTPException) as exc:
        app._run_audit("http://127.0.0.1/", timeout=5)
    assert exc.value.status_code == 400


def _fixture_worker(url, sender):
    def fetch(self, target, **kwargs):
        html = ("<html><head><title>Example business website</title></head>"
                "<body><h1>Services</h1><p>Contact us for a quote.</p>" + "Useful information. " * 4000 + "</body></html>").encode()
        return sec.ResponseInfo(target, 200, sec.CaseInsensitiveDict({"Content-Type": "text/html"}), "utf-8"), html, 10
    app.Engine.fetch = fetch
    app._audit_worker(url, sender)


def test_normal_audit_completes_in_real_limited_child():
    report = app._run_audit("https://example.com/", timeout=5, worker=_fixture_worker)
    assert report["pages_checked"] == 1
    assert report["final_url"] == "https://example.com/"
    assert all(k in report for k in ("scores", "counts", "issues", "disclaimer"))


def test_both_language_pages_use_expected_turnstile_action():
    root = Path(__file__).resolve().parents[2]
    for rel in ("strumenti/analisi-sito/index.html", "ro/instrumente/analiza-site/index.html"):
        text = (root / rel).read_text()
        assert 'data-action="site_scan"' in text
        assert 'site-check.js?v=20261025-scores-v4b' in text

