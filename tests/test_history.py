"""Historial, cambios, FTS5, SimHash, HTML crudo, auditoría y migración desde v2."""

import gzip
import json
import sqlite3
import stat

import pytest

from conftest import FakeResponse, FakeSession, make_onion
from tor_osint.changes import diff_latest, diff_snapshots, page_history, recent_changes
from tor_osint.config import Config
from tor_osint.crawler import crawl, save_raw
from tor_osint.database import PageRecord, audit_entries, connect, has_fts, store_page
from tor_osint.dedup import content_hash, find_near_duplicates, hamming, simhash
from tor_osint.ioc import Ioc
from tor_osint.search import HL_END, HL_START, fts_query, search_fts
from tor_osint.tor import TorClient

A = f"http://{make_onion('hist-a')}.onion/"


def record(text, url="http://a.onion/", title="t", status=200, iocs=None, **kw):
    return PageRecord(url, url, status, title, text, content_hash(text), iocs=iocs or [], **kw)


# --- snapshots y cambios ------------------------------------------------------------


def test_each_store_adds_snapshot_and_contents_are_deduplicated(conn):
    page_id = store_page(conn, record("uno"))
    store_page(conn, record("uno"))
    store_page(conn, record("dos"))
    assert len(page_history(conn, page_id)) == 3
    assert conn.execute("SELECT COUNT(*) FROM contents").fetchone()[0] == 2


def test_diff_detects_status_title_content_and_iocs(conn):
    old = [Ioc("cve", "CVE-2024-1", "CVE-2024-0001")]
    new = [Ioc("ipv4", "8.8.8.8", "8.8.8.8")]
    page_id = store_page(conn, record("el foro publica datos antiguos", title="A", iocs=old))
    store_page(conn, record("el foro publica datos nuevos hoy", title="B", status=503, iocs=new))
    diff = diff_latest(conn, page_id)
    assert diff.changed
    assert diff.status == (200, 503) and diff.title == ("A", "B")
    assert diff.content_changed and 0 < diff.similarity < 1
    assert diff.removed == ["antiguos"] and diff.added == ["nuevos hoy"]
    assert diff.iocs_added == {"ipv4": ["8.8.8.8"]}
    assert diff.iocs_removed == {"cve": ["CVE-2024-0001"]}
    assert diff.kinds() == ["status", "título", "contenido", "iocs"]


def test_diff_without_changes_and_single_snapshot(conn):
    page_id = store_page(conn, record("igual"))
    assert diff_latest(conn, page_id) is None
    store_page(conn, record("igual"))
    assert not diff_latest(conn, page_id).changed


def test_diff_rejects_snapshots_from_other_pages(conn):
    store_page(conn, record("a", url="http://a.onion/"))
    store_page(conn, record("b", url="http://b.onion/"))
    with pytest.raises(ValueError):
        diff_snapshots(conn, 1, 2)
    with pytest.raises(ValueError):
        diff_snapshots(conn, 1, 999)


def test_recent_changes_only_lists_changed_pages(conn):
    store_page(conn, record("a1", url="http://a.onion/"))
    store_page(conn, record("a2", url="http://a.onion/"))
    store_page(conn, record("b", url="http://b.onion/"))
    store_page(conn, record("b", url="http://b.onion/"))
    store_page(conn, record("c", url="http://c.onion/"))
    changes = recent_changes(conn)
    assert [c["url"] for c in changes] == ["http://a.onion/"]
    assert changes[0]["kinds"] == ["contenido"]


def test_crawl_reports_new_and_changed(conn):
    body = {"v": b"<title>T</title><p>version uno</p>"}

    def client():
        session = FakeSession({A: FakeResponse(body=body["v"])})
        return TorClient(Config(), session=session, sleep=lambda s: None)

    first = crawl([A], client(), conn, 10)
    assert first.new == [A] and first.changed == []
    second = crawl([A], client(), conn, 10)
    assert second.new == [] and second.changed == []
    body["v"] = b"<title>T</title><p>version dos</p>"
    third = crawl([A], client(), conn, 10)
    assert third.changed == [(A, ["contenido"])]


# --- HTML crudo opcional ---------------------------------------------------------------


def test_save_raw_is_compressed_private_and_idempotent(tmp_path):
    digest = save_raw(tmp_path / "raw", b"<p>secreto user:pass</p>")
    path = tmp_path / "raw" / f"{digest}.html.gz"
    assert gzip.decompress(path.read_bytes()) == b"<p>secreto user:pass</p>"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert save_raw(tmp_path / "raw", b"<p>secreto user:pass</p>") == digest


def test_crawl_saves_raw_only_when_requested(conn, tmp_path):
    session = FakeSession({A: FakeResponse(body=b"<p>hola</p>")})
    client = TorClient(Config(), session=session, sleep=lambda s: None)
    crawl([A], client, conn, 10)
    assert not (tmp_path / "raw").exists()
    crawl([A], client, conn, 10, raw_dir=tmp_path / "raw")
    raw = [r["raw_sha256"] for r in page_history(conn, 1)]
    assert raw[0] and raw[1] is None
    assert len(list((tmp_path / "raw").iterdir())) == 1


# --- FTS5 -------------------------------------------------------------------------------


def test_fts_prefix_accents_ranking_and_snippet(conn):
    assert has_fts(conn)
    store_page(conn, record("La contraseña del panel de ACME", title="ACME", url="http://a.onion/"))
    store_page(conn, record("mención lateral de acme", title="otro", url="http://b.onion/"))
    rows = search_fts(conn, "acm")
    assert rows[0]["url"] == "http://a.onion/"  # el título pesa más (BM25)
    assert f"{HL_START}ACME{HL_END}" in rows[0]["snippet"]
    assert len(search_fts(conn, "contrasena")) == 1


def test_fts_index_follows_updates(conn):
    store_page(conn, record("palabra antigua"))
    store_page(conn, record("palabra moderna"))
    assert search_fts(conn, "antigua") == []
    assert len(search_fts(conn, "moderna")) == 1


@pytest.mark.parametrize("term", ['"; DROP TABLE pages; --', "a OR b NEAR(c)", "col:valor"])
def test_fts_query_neutralizes_operators(conn, term):
    store_page(conn, record("texto"))
    search_fts(conn, term)  # no lanza error de sintaxis FTS
    assert all(part.startswith('"') for part in fts_query(term).split())


def test_fts_empty_term_rejected(conn):
    with pytest.raises(ValueError):
        search_fts(conn, "  ")
    with pytest.raises(ValueError):
        search_fts(conn, "%%%")


# --- SimHash --------------------------------------------------------------------------------


def test_simhash_similarity():
    base = " ".join(f"palabra{i}" for i in range(300))
    near = base.replace("palabra150", "cambio")
    far = " ".join(f"otra{i}" for i in range(300))
    assert hamming(simhash(base), simhash(near)) <= 12
    assert hamming(simhash(base), simhash(far)) > 12
    assert simhash("") == "0" * 16


def test_find_near_duplicates_excludes_exact(conn):
    base = " ".join(f"palabra{i}" for i in range(300))
    store_page(conn, record(base, url="http://a.onion/"))
    store_page(conn, record(base.replace("palabra7", "x"), url="http://b.onion/"))
    store_page(conn, record(base, url="http://c.onion/"))  # idéntica a A
    store_page(conn, record(" ".join(f"otra{i}" for i in range(300)), url="http://d.onion/"))
    groups = find_near_duplicates(conn)
    assert len(groups) == 1
    assert {p["url"] for p in groups[0].pages} == {
        "http://a.onion/",
        "http://b.onion/",
        "http://c.onion/",
    }


# --- auditoría y migración ---------------------------------------------------------------


def test_crawl_is_audited(conn):
    session = FakeSession({A: FakeResponse(body=b"<p>x</p>")})
    crawl([A], TorClient(Config(), session=session, sleep=lambda s: None), conn, 10)
    entry = audit_entries(conn)[0]
    assert entry["action"] == "crawl" and entry["actor"]
    assert json.loads(entry["details_json"])["stored"] == 1


def test_migration_from_v2_database(tmp_path):
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.executescript(
        """
        CREATE TABLE pages (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT UNIQUE NOT NULL,
            source TEXT NOT NULL, fetched_at TEXT NOT NULL, status INTEGER, title TEXT,
            text TEXT, content_hash TEXT, links_json TEXT, iocs_json TEXT);
        INSERT INTO pages (url, source, fetched_at, status, title, text, content_hash,
                           links_json, iocs_json)
        VALUES ('http://a.onion/', 'http://a.onion/', '2025-01-01T00:00:00+00:00', 200,
                'Viejo', 'contenido heredado de ACME', 'h', '[]', '{}');
        PRAGMA user_version = 2;
        """
    )
    old.commit()
    old.close()

    conn = connect(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 3
    assert len(page_history(conn, 1)) == 1  # snapshot inicial
    assert conn.execute("SELECT simhash FROM pages").fetchone()[0] != "0" * 16
    assert len(search_fts(conn, "heredado")) == 1  # índice FTS reconstruido
    conn.close()
    conn = connect(path)  # reabrir no duplica snapshots
    assert len(page_history(conn, 1)) == 1
    conn.close()
