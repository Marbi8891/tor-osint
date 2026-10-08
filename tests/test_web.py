"""Pruebas de la interfaz web: servidor real en un puerto libre, Tor mockeado."""

from __future__ import annotations

import http.client
import json
import threading
import time

import pytest

from conftest import FakeResponse, FakeSession, make_onion
from tor_osint.config import Config
from tor_osint.tor import TOR_CHECK_URL, TorClient
from tor_osint.web import is_loopback, make_server

A = f"http://{make_onion('web-a')}.onion/"
B = f"http://{make_onion('web-b')}.onion/"
LINKED = f"http://{make_onion('web-linked')}.onion/"
PAGE = f"""<title>&lt;img src=x onerror=alert(1)&gt; ACME</title>
<p>CVE-2024-1234 en 8.8.8.8, contacto sec@example.com:hunter22
<a href="{LINKED}">m</a></p>""".encode()


@pytest.fixture
def server(tmp_path, monkeypatch):
    routes = {
        A: FakeResponse(body=PAGE),
        B: FakeResponse(body=PAGE),
        TOR_CHECK_URL: FakeResponse(json_data={"IsTor": True, "IP": "203.0.113.7"}),
    }
    original_init = TorClient.__init__

    def fake_init(self, config, session=None, sleep=None, clock=None):
        original_init(self, config, session=FakeSession(routes), sleep=lambda s: None)

    monkeypatch.setattr(TorClient, "__init__", fake_init)
    data = tmp_path / "data"
    data.mkdir()
    (data / "sources.txt").write_text(f"{A}\n{B}\n", encoding="utf-8")
    config = Config(data_dir=data, results_dir=tmp_path / "results")
    srv = make_server(config, "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()


class Client:
    def __init__(self, srv):
        self.port = srv.server_address[1]
        self.token = srv.app.csrf_token
        self.host = f"127.0.0.1:{self.port}"

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        hdrs = {"Host": self.host}
        payload = None
        if method == "POST":
            hdrs.update({"Content-Type": "application/json", "X-CSRF-Token": self.token})
            payload = json.dumps(body or {})
        hdrs.update(headers or {})
        conn.request(method, path, body=payload, headers=hdrs)
        res = conn.getresponse()
        raw = res.read()
        conn.close()
        return res, raw

    def json(self, method, path, body=None, headers=None):
        res, raw = self.request(method, path, body, headers)
        return res.status, json.loads(raw)

    def crawl_and_wait(self):
        status, _ = self.json("POST", "/api/crawl", {})
        assert status == 202
        for _ in range(100):
            _, job = self.json("GET", "/api/crawl")
            if job["state"] != "running":
                return job
            time.sleep(0.05)
        raise AssertionError("el crawl no terminó")


@pytest.fixture
def client(server):
    return Client(server)


# --- seguridad --------------------------------------------------------------


def test_only_loopback_allowed(tmp_path):
    assert is_loopback("127.0.0.1") and is_loopback("::1") and is_loopback("localhost")
    assert not is_loopback("0.0.0.0") and not is_loopback("192.168.1.10")
    with pytest.raises(ValueError):
        make_server(Config(data_dir=tmp_path), "0.0.0.0", 0)


def test_index_has_csrf_token_and_security_headers(client):
    res, raw = client.request("GET", "/")
    html = raw.decode()
    assert res.status == 200
    assert client.token in html and "{{CSRF_TOKEN}}" not in html
    csp = res.getheader("Content-Security-Policy")
    assert "default-src 'none'" in csp and "script-src 'self'" in csp
    assert "unsafe-inline" not in csp
    assert res.getheader("X-Frame-Options") == "DENY"
    assert res.getheader("X-Content-Type-Options") == "nosniff"


def test_static_whitelist(client):
    res, _ = client.request("GET", "/static/app.js")
    assert res.status == 200 and res.getheader("Content-Type").startswith("text/javascript")
    for path in ("/static/../web.py", "/static/index.html", "/static/%2e%2e/cli.py", "/etc/passwd"):
        res, _ = client.request("GET", path)
        assert res.status == 404, path


def test_dns_rebinding_host_rejected(client):
    res, _ = client.request("GET", "/api/summary", headers={"Host": "evil.example:80"})
    assert res.status == 421


def test_post_requires_csrf_token(client):
    status, data = client.json("POST", "/api/sources", {"url": A}, {"X-CSRF-Token": "malo"})
    assert status == 403 and "CSRF" in data["error"]


def test_post_rejects_foreign_origin(client):
    status, _ = client.json("POST", "/api/report", {}, {"Origin": "http://evil.example"})
    assert status == 403


def test_post_requires_json_content_type(client):
    status, _ = client.json("POST", "/api/report", {}, {"Content-Type": "text/plain"})
    assert status == 415


def test_unknown_routes(client):
    assert client.json("GET", "/api/nope")[0] == 404
    assert client.json("POST", "/api/nope")[0] == 404


# --- funcionalidad ----------------------------------------------------------


def test_tor_check_hides_ip_unless_requested(client):
    status, data = client.json("POST", "/api/tor-check", {})
    assert status == 200 and data["is_tor"] is True and data["ip"] is None
    _, data = client.json("POST", "/api/tor-check", {"show_ip": True})
    assert data["ip"] == "203.0.113.7"


def test_full_workflow(client, server):
    _, summary = client.json("GET", "/api/summary")
    assert summary["sources"] == 2 and summary["pages"] == 0

    job = client.crawl_and_wait()
    assert job["state"] == "done" and len(job["stored"]) == 2 and job["current"] == 2

    _, summary = client.json("GET", "/api/summary")
    assert summary["pages"] == 2 and summary["duplicates"] == 1

    _, pages = client.json("GET", "/api/pages?limit=1")
    assert pages["total"] == 2 and len(pages["items"]) == 1
    page_id = pages["items"][0]["id"]

    _, page = client.json("GET", f"/api/pages/{page_id}")
    assert "hunter22" not in json.dumps(page)  # credencial redactada
    # Dato crudo: es el frontend quien lo pinta siempre como texto.
    assert "<img src=x onerror=alert(1)>" in page["title"]
    assert {i["type"] for i in page["iocs"]} >= {"cve", "ipv4", "email", "onion"}
    assert client.json("GET", "/api/pages/999")[0] == 404

    _, res = client.json("GET", "/api/search?q=acme")
    assert len(res["items"]) == 2
    _, res = client.json("GET", "/api/regex?pattern=CVE-202%5B0-9%5D-%5B0-9%5D%2B")
    assert res["items"][0]["matches"] == ["CVE-2024-1234"]
    assert client.json("GET", "/api/regex?pattern=%28")[0] == 400
    assert client.json("GET", "/api/search")[0] == 400

    _, res = client.json("GET", "/api/iocs?type=hash")
    assert res["items"] == []
    _, res = client.json("GET", "/api/iocs?type=cve")
    assert res["items"][0]["value"] == "CVE-2024-1234"
    assert client.json("GET", "/api/iocs?type=bogus")[0] == 400

    _, res = client.json("GET", "/api/related?value=cve-2024-1234")
    assert len({r["page_id"] for r in res["items"]}) == 2

    _, res = client.json("GET", "/api/duplicates")
    assert len(res["items"]) == 1 and len(res["items"][0]["urls"]) == 2

    _, res = client.json("GET", "/api/sources")
    assert [d["value"] for d in res["discovered"]] == [LINKED]


def test_add_source_validation(client, server):
    status, data = client.json("POST", "/api/sources", {"url": "http://example.com/"})
    assert status == 400
    new = f"http://{make_onion('web-new')}.onion/"
    status, data = client.json("POST", "/api/sources", {"url": new})
    assert status == 200 and data["added"] == new
    status, data = client.json("POST", "/api/sources", {"url": new})
    assert status == 400 and "ya está" in data["error"]
    _, data = client.json("GET", "/api/sources")
    assert new in data["valid"]


def test_crawl_explicit_urls_and_validation(client):
    assert client.json("POST", "/api/crawl", {"urls": ["http://example.com/"]})[0] == 400
    assert client.json("POST", "/api/crawl", {"urls": "no-lista"})[0] == 400
    status, job = client.json("POST", "/api/crawl", {"urls": [A]})
    assert status == 202 and job["total"] == 1


def test_report_and_exports(client):
    assert client.request("GET", "/report")[0].status == 404
    client.crawl_and_wait()
    status, data = client.json("POST", "/api/report", {})
    assert status == 200 and data["url"] == "/report"
    res, raw = client.request("GET", "/report")
    assert res.status == 200 and b"Informe tor-osint" in raw
    assert res.getheader("Content-Security-Policy").startswith("default-src 'none'")
    assert b"<img src=x" not in raw

    res, raw = client.request("GET", "/api/export?format=json")
    assert "attachment" in res.getheader("Content-Disposition")
    assert len(json.loads(raw)["pages"]) == 2
    res, raw = client.request("GET", "/api/export?format=csv&table=iocs")
    assert res.getheader("Content-Type").startswith("text/csv") and b"normalized_value" in raw
    assert client.request("GET", "/api/export?format=xml")[0].status == 400
