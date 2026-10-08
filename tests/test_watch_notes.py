import pytest

from tor_osint.database import PageRecord, store_page
from tor_osint.dedup import content_hash
from tor_osint.ioc import Ioc, normalize_any
from tor_osint.notes import (
    add_note,
    add_tag,
    delete_note,
    list_notes,
    remove_tag,
    tag_counts,
    tags_for,
    targets_with_tag,
)
from tor_osint.watch import (
    acknowledge_alerts,
    add_watch,
    count_open_alerts,
    fold,
    list_alerts,
    list_watches,
    remove_watch,
    scan_page,
)


def store(conn, text, url="http://a.onion/", iocs=None, title="t"):
    return store_page(
        conn, PageRecord(url, url, 200, title, text, content_hash(text), iocs=iocs or [])
    )


CVE = Ioc("cve", "cve-2024-1234", "CVE-2024-1234")


# --- normalización -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("cve-2024-1234", ("cve", "CVE-2024-1234")),
        ("Example.COM", ("domain", "example.com")),
        ("8.8.8.8", ("ipv4", "8.8.8.8")),
        ("Admin@X.org", ("email", "admin@x.org")),
        ("texto libre", (None, "texto libre")),
    ],
)
def test_normalize_any(value, expected):
    assert normalize_any(value) == expected


def test_fold_removes_accents_and_case():
    assert fold("ContraSEÑA Ácme") == "contrasena acme"


# --- watchlist ------------------------------------------------------------------------


def test_watch_term_matches_existing_data_and_ignores_accents(conn):
    store(conn, "La empresa Ácme filtró datos")
    watch_id, alerts = add_watch(conn, "term", "acme")
    assert alerts == 1
    assert list_watches(conn)[0]["open_alerts"] == 1
    assert list_alerts(conn)[0]["watch_id"] == watch_id


def test_watch_ioc_uses_normalized_value(conn):
    store(conn, "texto", iocs=[CVE])
    _, alerts = add_watch(conn, "ioc", "cve-2024-1234")
    assert alerts == 1


def test_alert_not_repeated_until_content_changes(conn):
    add_watch(conn, "term", "acme")
    page_id = store(conn, "acme v1")
    assert scan_page(conn, page_id) == 1
    assert scan_page(conn, page_id) == 0  # mismo contenido: sin alerta nueva
    store(conn, "acme v2")
    assert scan_page(conn, page_id) == 1
    assert count_open_alerts(conn) == 2


def test_acknowledge_and_list_all(conn):
    add_watch(conn, "term", "acme")
    store(conn, "acme", url="http://a.onion/")
    store(conn, "acme", url="http://b.onion/")
    from tor_osint.watch import scan_all

    scan_all(conn)
    first = list_alerts(conn)[-1]["id"]
    assert acknowledge_alerts(conn, [first]) == 1
    assert count_open_alerts(conn) == 1
    assert acknowledge_alerts(conn) == 1
    assert list_alerts(conn) == [] and len(list_alerts(conn, include_acknowledged=True)) == 2


@pytest.mark.parametrize(("kind", "value"), [("term", "ab"), ("term", " "), ("otro", "x")])
def test_watch_validation(conn, kind, value):
    with pytest.raises(ValueError):
        add_watch(conn, kind, value)


def test_watch_duplicates_and_removal(conn):
    watch_id, _ = add_watch(conn, "term", "Acme")
    with pytest.raises(ValueError):
        add_watch(conn, "term", "ACME")
    remove_watch(conn, watch_id)
    assert list_watches(conn) == []
    with pytest.raises(ValueError):
        remove_watch(conn, watch_id)


# --- notas y etiquetas ---------------------------------------------------------------------


def test_notes_on_pages_and_iocs(conn):
    page_id = store(conn, "x")
    add_note(conn, "page", str(page_id), "Revisar")
    note_id = add_note(conn, "ioc", "cve-2024-1234", "Crítico")
    assert [n["body"] for n in list_notes(conn, "ioc", "CVE-2024-1234")] == ["Crítico"]
    assert len(list_notes(conn)) == 2
    delete_note(conn, note_id)
    assert len(list_notes(conn)) == 1


@pytest.mark.parametrize(
    ("target_type", "target", "body"),
    [("page", "999", "x"), ("page", "abc", "x"), ("otro", "1", "x"), ("ioc", "x", " ")],
)
def test_note_validation(conn, target_type, target, body):
    with pytest.raises(ValueError):
        add_note(conn, target_type, target, body)


def test_tags(conn):
    page_id = store(conn, "x")
    assert add_tag(conn, "page", str(page_id), "Phishing Kit") == "phishing-kit"
    add_tag(conn, "page", str(page_id), "phishing-kit")  # idempotente
    add_tag(conn, "ioc", "Example.COM", "phishing-kit")
    assert tags_for(conn, "ioc", "example.com") == ["phishing-kit"]
    assert tag_counts(conn) == [("phishing-kit", 2)]
    rows = targets_with_tag(conn, "phishing-kit")
    assert {(r["target_type"], r["url"]) for r in rows} == {
        ("page", "http://a.onion/"),
        ("ioc", None),
    }
    remove_tag(conn, "ioc", "example.com", "phishing-kit")
    with pytest.raises(ValueError):
        remove_tag(conn, "ioc", "example.com", "phishing-kit")
    with pytest.raises(ValueError):
        add_tag(conn, "page", str(page_id), "<script>")
