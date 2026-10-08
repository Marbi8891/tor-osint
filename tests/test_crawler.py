import json

import requests

from conftest import FakeResponse, FakeSession, make_onion
from tor_osint.config import Config
from tor_osint.crawler import crawl
from tor_osint.tor import TorClient

A = f"http://{make_onion('a')}.onion/"
B = f"http://{make_onion('b')}.onion/"
LINKED = f"http://{make_onion('enlazada')}.onion/"

HTML = f"""<html><head><title>Foro de pruebas</title></head><body>
<p>Contacto admin@example.com:hunter22 — fallo CVE-2024-1234 en 8.8.8.8</p>
<a href="{LINKED}">mirror</a></body></html>""".encode()


def make_client(routes):
    session = FakeSession(routes)
    return TorClient(Config(), session=session, sleep=lambda s: None), session


def test_crawl_stores_page_iocs_and_redacts(conn):
    client, _ = make_client({A: FakeResponse(body=HTML)})
    summary = crawl([A], client, conn, max_urls=10)
    assert summary.stored == [A] and summary.failed == []

    row = conn.execute("SELECT * FROM pages").fetchone()
    assert row["title"] == "Foro de pruebas"
    assert "hunter22" not in row["text"]  # la credencial no se almacena
    assert len(row["content_hash"]) == 64
    iocs = json.loads(row["iocs_json"])
    assert iocs["email"] == ["admin@example.com"]
    assert iocs["cve"] == ["CVE-2024-1234"]
    assert iocs["ipv4"] == ["8.8.8.8"]
    assert iocs["onion"] == [LINKED]
    dump = "\n".join(str(tuple(r)) for r in conn.execute("SELECT * FROM iocs"))
    assert "hunter22" not in dump


def test_crawl_is_not_recursive(conn):
    client, session = make_client({A: FakeResponse(body=HTML)})
    crawl([A], client, conn, max_urls=10)
    assert [url for url, _ in session.calls] == [A]  # el enlace descubierto NO se visita


def test_crawl_respects_max_urls(conn):
    client, session = make_client({A: FakeResponse(body=b"a"), B: FakeResponse(body=b"b")})
    summary = crawl([A, B], client, conn, max_urls=1)
    assert summary.skipped == [B]
    assert len(session.calls) == 1


def test_crawl_continues_after_failure(conn):
    client, _ = make_client({A: requests.ConnectionError("x"), B: FakeResponse(body=b"<p>ok</p>")})
    summary = crawl([A, B], client, conn, max_urls=10)
    assert summary.stored == [B]
    assert summary.failed[0][0] == A


def test_crawl_stores_http_errors_with_body(conn):
    client, _ = make_client({A: FakeResponse(404, body=b"<title>No existe</title>")})
    crawl([A], client, conn, max_urls=10)
    assert conn.execute("SELECT status FROM pages").fetchone()[0] == 404
