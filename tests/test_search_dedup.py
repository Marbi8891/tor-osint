import pytest

from tor_osint.database import PageRecord, store_page
from tor_osint.dedup import EMPTY_HASH, content_hash, find_duplicates, normalize_text
from tor_osint.search import MAX_PATTERN_LEN, regex_search, search_text


def add(conn, url, text, title="t"):
    store_page(
        conn,
        PageRecord(
            url=url, source=url, status=200, title=title, text=text, content_hash=content_hash(text)
        ),
    )


# --- búsqueda ---------------------------------------------------------------


def test_search_title_and_text_case_insensitive(conn):
    add(conn, "http://a.onion/", "Informe sobre ACME Corp", title="Uno")
    add(conn, "http://b.onion/", "nada", title="Empresa acme")
    add(conn, "http://c.onion/", "otra cosa")
    assert {r["url"] for r in search_text(conn, "acme")} == {"http://a.onion/", "http://b.onion/"}


def test_search_like_wildcards_are_literal(conn):
    add(conn, "http://a.onion/", "descuento 100% real")
    add(conn, "http://b.onion/", "descuento 1000 real")
    add(conn, "http://c.onion/", "user_name")
    add(conn, "http://d.onion/", "username")
    assert [r["url"] for r in search_text(conn, "100%")] == ["http://a.onion/"]
    assert [r["url"] for r in search_text(conn, "user_name")] == ["http://c.onion/"]


def test_search_empty_term_rejected(conn):
    with pytest.raises(ValueError):
        search_text(conn, "  ")


# --- regex ------------------------------------------------------------------


def test_regex_search_local(conn):
    add(conn, "http://a.onion/", "afecta CVE-2021-44228 y cve-2023-0001")
    add(conn, "http://b.onion/", "sin vulnerabilidades")
    hits = regex_search(conn, r"CVE-202[0-9]-[0-9]+")
    assert len(hits) == 1
    assert hits[0].matches == ["CVE-2021-44228", "cve-2023-0001"]


def test_regex_uses_full_match_with_groups_and_ignores_empty(conn):
    add(conn, "http://a.onion/", "ip 10.0.0.1")
    assert regex_search(conn, r"(\d+)\.(\d+)")[0].matches == ["0.1", "10.0"]
    assert regex_search(conn, r"z*") == []


def test_regex_max_matches(conn):
    add(conn, "http://a.onion/", " ".join(f"w{i}" for i in range(50)))
    assert len(regex_search(conn, r"w\d+", max_matches=5)[0].matches) == 5


@pytest.mark.parametrize("pattern", ["(", "a" * (MAX_PATTERN_LEN + 1)])
def test_regex_invalid(conn, pattern):
    with pytest.raises(ValueError):
        regex_search(conn, pattern)


# --- deduplicación ----------------------------------------------------------


def test_normalize_and_hash():
    assert normalize_text("  hola\n\n  mundo\t") == "hola mundo"
    assert content_hash("hola   mundo") == content_hash("\nhola mundo ")
    assert content_hash("hola mundo") != content_hash("Hola mundo")
    assert content_hash("") == EMPTY_HASH


def test_find_duplicates(conn):
    add(conn, "http://a.onion/", "mismo contenido")
    add(conn, "http://b.onion/", "mismo   contenido")
    add(conn, "http://c.onion/x", "mismo contenido")
    add(conn, "http://d.onion/", "distinto")
    add(conn, "http://e.onion/", "")  # páginas vacías no cuentan como duplicado
    add(conn, "http://f.onion/", "")
    groups = find_duplicates(conn)
    assert len(groups) == 1
    assert groups[0].urls == ["http://a.onion/", "http://b.onion/", "http://c.onion/x"]
    assert groups[0].content_hash == content_hash("mismo contenido")


def test_dedup_by_url(conn):
    add(conn, "http://a.onion/", "v1")
    add(conn, "http://a.onion/", "v2")
    assert conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0] == 1
