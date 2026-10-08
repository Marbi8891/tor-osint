"""Pruebas de extremo a extremo de la CLI (sin red: el cliente Tor se sustituye)."""

import json

import pytest

from conftest import FakeResponse, FakeSession, make_onion
from tor_osint import cli
from tor_osint.tor import TOR_CHECK_URL, TorClient

A = f"http://{make_onion('cli-a')}.onion/"
B = f"http://{make_onion('cli-b')}.onion/"
LINKED = f"http://{make_onion('cli-linked')}.onion/"
PAGE = f"""<title>Empresa ACME</title><p>Vulnerable a CVE-2024-1234 desde 8.8.8.8,
contacto sec@example.com. <a href="{LINKED}">x</a></p>""".encode()


@pytest.fixture
def routes():
    return {
        A: FakeResponse(body=PAGE),
        B: FakeResponse(body=PAGE),
        TOR_CHECK_URL: FakeResponse(json_data={"IsTor": True, "IP": "203.0.113.7"}),
    }


@pytest.fixture
def run(tmp_path, monkeypatch, routes, capsys):
    """Ejecuta la CLI en un directorio temporal con una sesión HTTP falsa."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "sources.txt").write_text(f"# test\n{A}\n{B}\nhttp://bad.onion/\n")
    for var in ("TOR_SOCKS", "TOR_TIMEOUT", "TOR_DELAY", "TOR_MAX_BYTES", "TOR_MAX_URLS"):
        monkeypatch.delenv(var, raising=False)
    original_init = TorClient.__init__

    def fake_init(self, config, session=None, sleep=None, clock=None):
        original_init(self, config, session=FakeSession(routes), sleep=lambda s: None)

    monkeypatch.setattr(TorClient, "__init__", fake_init)

    def _run(*argv):
        code = cli.main(list(argv))
        return code, capsys.readouterr().out

    return _run


def test_help_lists_all_commands(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for command in [
        "tor-check",
        "crawl",
        "search",
        "regex",
        "iocs",
        "related",
        "duplicates",
        "export",
        "report",
        "sources",
    ]:
        assert command in out


def test_tor_check_hides_ip_by_default(run):
    code, out = run("tor-check")
    assert code == 0 and "IsTor: True" in out and "203.0.113.7" not in out
    code, out = run("tor-check", "--show-ip")
    assert "203.0.113.7" in out


def test_full_workflow(run, tmp_path):
    code, out = run("crawl")
    assert code == 0 and "Guardadas: 2" in out

    code, out = run("search", "acme")
    assert "Resultados: 2" in out

    code, out = run("regex", "CVE-202[0-9]-[0-9]+")
    assert "CVE-2024-1234" in out and "Páginas con coincidencias: 2" in out

    code, out = run("iocs")
    assert "cve" in out and "email" in out

    code, out = run("iocs", "--type", "domain")
    assert "example.com" in out

    code, out = run("related", "cve-2024-1234")
    assert "Páginas relacionadas: 2" in out
    code, out = run("related", "8.8.8.8")
    assert "Páginas relacionadas: 2" in out

    code, out = run("duplicates")
    assert "Grupos de contenido duplicado: 1" in out

    code, out = run("sources", "--discovered")
    assert LINKED in out and A not in out

    code, out = run("export", "--format", "json")
    data = json.loads((tmp_path / "results" / "results.json").read_text(encoding="utf-8"))
    assert len(data["pages"]) == 2

    code, out = run("export", "--format", "csv")
    assert (tmp_path / "results" / "results.csv").exists()
    assert (tmp_path / "results" / "results_iocs.csv").exists()

    code, out = run("report", "--output", "results/custom.html")
    html = (tmp_path / "results" / "custom.html").read_text(encoding="utf-8")
    assert code == 0 and "<td>2</td>" in html  # 2 fuentes válidas configuradas


def test_crawl_explicit_url_only(run, routes):
    code, out = run("crawl", "--url", A)
    assert code == 0 and "Guardadas: 1" in out


def test_crawl_invalid_url_rejected(run):
    code, out = run("crawl", "--url", "http://example.com/")
    assert code == 2 and "no válida" in out


def test_sources_validation(run):
    _, out = run("sources")
    assert "Válidas: 2 · Rechazadas: 1" in out


def test_invalid_config_returns_error(run, monkeypatch):
    monkeypatch.setenv("TOR_DELAY", "0")
    code, _ = run("iocs")
    assert code == 2


def test_invalid_regex_returns_error(run):
    code, _ = run("regex", "(")
    assert code == 2
