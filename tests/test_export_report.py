import csv
import json

from tor_osint.crawler import build_record
from tor_osint.database import store_page
from tor_osint.export import csv_safe, export_csv, export_json
from tor_osint.report import build_report, write_report
from tor_osint.tor import FetchResult

EVIL = b"""<html><head><title>&lt;script&gt;alert(1)&lt;/script&gt; Foro</title></head>
<body><p>=HYPERLINK("http://evil") user@example.com:hunter22 CVE-2024-1234 8.8.8.8
<img src=x onerror=alert(2)> &lt;b onmouseover=x&gt; dup</p></body></html>"""


def seed(conn, url="http://a.onion/", body=EVIL):
    result = FetchResult(url=url, final_url=url, status=200, content_type="text/html", content=body)
    store_page(conn, build_record(url, result))


# --- exportación ------------------------------------------------------------


def test_export_json(conn, tmp_path):
    seed(conn)
    out = export_json(conn, tmp_path / "r" / "results.json")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["generator"].startswith("tor-osint")
    assert data["pages"][0]["iocs"]["cve"] == ["CVE-2024-1234"]
    assert {i["type"] for i in data["iocs"]} >= {"email", "cve", "ipv4"}
    assert "hunter22" not in out.read_text(encoding="utf-8")


def test_export_csv_and_formula_injection(conn, tmp_path):
    seed(conn, body=b"<title>=1+1</title><p>x</p>")
    pages_csv, iocs_csv = export_csv(conn, tmp_path / "results.csv")
    assert iocs_csv.name == "results_iocs.csv"
    rows = list(csv.DictReader(pages_csv.open(encoding="utf-8")))
    assert rows[0]["title"] == "'=1+1"
    assert iocs_csv.exists()


def test_csv_safe():
    assert csv_safe("=cmd") == "'=cmd"
    assert csv_safe("@SUM(1)") == "'@SUM(1)"
    assert csv_safe("normal") == "normal"
    assert csv_safe(42) == 42


# --- informe ----------------------------------------------------------------


def test_report_escapes_untrusted_content(conn):
    seed(conn)
    html = build_report(conn, source_count=3, generated_at="2026-10-08T00:00:00+00:00")
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img" not in html and "onerror=alert" not in html.replace("onerror=alert(2)", "")
    assert "hunter22" not in html
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    assert "<a " not in html  # sin hipervínculos activos


def test_report_contains_required_sections(conn):
    seed(conn, "http://a.onion/", b"<p>igual CVE-2024-1234 admin@example.com</p>")
    seed(conn, "http://b.onion/", b"<p>igual CVE-2024-1234 admin@example.com</p>")
    html = build_report(conn, source_count=2, generated_at="2026-10-08T00:00:00+00:00")
    for needle in [
        "2026-10-08T00:00:00+00:00",
        "Fuentes configuradas",
        "Páginas recopiladas",
        "Códigos HTTP",
        "Contenido duplicado",
        "IOCs por tipo",
        "CVEs",
        "Dominios",
        "Emails",
        "IPv4",
        "Hashes",
        "URLs onion",
        "Relación IOC",
        "CVE-2024-1234",
        "admin@example.com",
        "http://a.onion/",
        "http://b.onion/",
    ]:
        assert needle in html, needle


def test_write_report_creates_file(conn, tmp_path):
    seed(conn)
    out = write_report(conn, tmp_path / "out" / "report.html", source_count=1)
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_report_empty_db(conn):
    assert "Sin datos." in build_report(conn, source_count=0)
