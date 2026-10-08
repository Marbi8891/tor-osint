import json

from tor_osint.database import (
    PageRecord,
    connect,
    count_pages,
    ioc_type_counts,
    ioc_values,
    pages_for_ioc,
    status_counts,
    store_page,
)
from tor_osint.ioc import Ioc


def page(url="http://x.onion/", iocs=None, **kw):
    defaults = dict(source=url, status=200, title="t", text="texto", content_hash="h")
    defaults.update(kw)
    return PageRecord(url=url, iocs=iocs or [], **defaults)


def test_schema_and_indexes(conn):
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    assert {"pages", "iocs", "idx_pages_content_hash", "idx_iocs_normalized"} <= names
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 2


def test_connect_creates_parent_dir(tmp_path):
    db = tmp_path / "nested" / "r.db"
    connect(db).close()
    assert db.exists()


def test_store_and_upsert_by_url(conn):
    first = store_page(conn, page(text="uno", fetched_at="2026-01-01T00:00:00+00:00"))
    second = store_page(conn, page(text="dos", status=404, fetched_at="2026-01-02T00:00:00+00:00"))
    assert first == second
    assert count_pages(conn) == 1
    row = conn.execute("SELECT text, status FROM pages").fetchone()
    assert (row["text"], row["status"]) == ("dos", 404)
    assert status_counts(conn) == [(404, 1)]


def test_iocs_stored_with_first_and_last_seen(conn):
    ioc = Ioc("email", "A@B.com", "a@b.com")
    store_page(conn, page(iocs=[ioc], fetched_at="2026-01-01T00:00:00+00:00"))
    store_page(conn, page(iocs=[ioc], fetched_at="2026-02-01T00:00:00+00:00"))
    row = conn.execute("SELECT * FROM iocs").fetchone()
    assert row["first_seen"].startswith("2026-01-01")
    assert row["last_seen"].startswith("2026-02-01")
    assert json.loads(conn.execute("SELECT iocs_json FROM pages").fetchone()[0]) == {
        "email": ["a@b.com"]
    }


def test_stale_iocs_removed_on_recrawl(conn):
    store_page(conn, page(iocs=[Ioc("cve", "CVE-2024-1234", "CVE-2024-1234")]))
    store_page(conn, page(iocs=[Ioc("ipv4", "8.8.8.8", "8.8.8.8")]))
    assert [r["type"] for r in conn.execute("SELECT type FROM iocs")] == ["ipv4"]


def test_ioc_aggregation_and_hash_alias(conn):
    store_page(
        conn, page("http://a.onion/", iocs=[Ioc("md5", "x", "m" * 32), Ioc("cve", "c", "CVE-1")])
    )
    store_page(conn, page("http://b.onion/", iocs=[Ioc("md5", "x", "m" * 32)]))
    assert ("md5", 1, 2) in ioc_type_counts(conn)
    hashes = ioc_values(conn, "hash")
    assert len(hashes) == 1 and hashes[0]["pages"] == 2
    assert [r["url"] for r in pages_for_ioc(conn, ["m" * 32])] == [
        "http://a.onion/",
        "http://b.onion/",
    ]
    assert pages_for_ioc(conn, []) == []
