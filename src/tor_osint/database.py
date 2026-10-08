"""Persistencia SQLite: páginas, IOCs y consultas de agregación."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .ioc import Ioc

SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE NOT NULL,
    source TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    status INTEGER,
    title TEXT,
    text TEXT,
    content_hash TEXT,
    links_json TEXT,
    iocs_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_pages_content_hash ON pages(content_hash);
CREATE INDEX IF NOT EXISTS idx_pages_fetched_at ON pages(fetched_at);
CREATE INDEX IF NOT EXISTS idx_pages_source ON pages(source);

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    page_id INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
    UNIQUE (type, normalized_value, page_id)
);
CREATE INDEX IF NOT EXISTS idx_iocs_normalized ON iocs(normalized_value);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
CREATE INDEX IF NOT EXISTS idx_iocs_page ON iocs(page_id);
"""


def utc_now() -> str:
    """Marca de tiempo ISO-8601 en UTC."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: Path | str) -> sqlite3.Connection:
    """Abre (o crea) la base de datos y aplica el esquema. Compatible con la BD de la v2.0."""
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    conn.commit()
    return conn


@dataclass
class PageRecord:
    """Página ya procesada (texto redactado) lista para almacenar."""

    url: str
    source: str
    status: int | None
    title: str
    text: str
    content_hash: str
    links: list[str] = field(default_factory=list)
    iocs: list[Ioc] = field(default_factory=list)
    fetched_at: str = field(default_factory=utc_now)


def store_page(conn: sqlite3.Connection, page: PageRecord) -> int:
    """Inserta o actualiza una página (deduplicación por URL) y sus IOCs. Devuelve su id."""
    grouped: dict[str, list[str]] = {}
    for ioc in page.iocs:
        grouped.setdefault(ioc.type, []).append(ioc.normalized)

    with conn:
        conn.execute(
            """
            INSERT INTO pages (url, source, fetched_at, status, title, text,
                               content_hash, links_json, iocs_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(url) DO UPDATE SET
                source=excluded.source,
                fetched_at=excluded.fetched_at,
                status=excluded.status,
                title=excluded.title,
                text=excluded.text,
                content_hash=excluded.content_hash,
                links_json=excluded.links_json,
                iocs_json=excluded.iocs_json
            """,
            (
                page.url,
                page.source,
                page.fetched_at,
                page.status,
                page.title,
                page.text,
                page.content_hash,
                json.dumps(page.links, ensure_ascii=False),
                json.dumps(grouped, ensure_ascii=False, sort_keys=True),
            ),
        )
        page_id = conn.execute("SELECT id FROM pages WHERE url = ?", (page.url,)).fetchone()[0]
        # Los IOCs que ya no están en la versión actual de la página dejan de correlacionarse;
        # los que siguen presentes conservan su first_seen.
        current = {(i.type, i.normalized) for i in page.iocs}
        stale = [
            (row["id"],)
            for row in conn.execute(
                "SELECT id, type, normalized_value FROM iocs WHERE page_id = ?", (page_id,)
            )
            if (row["type"], row["normalized_value"]) not in current
        ]
        conn.executemany("DELETE FROM iocs WHERE id = ?", stale)
        conn.executemany(
            """
            INSERT INTO iocs (type, value, normalized_value, first_seen, last_seen, page_id)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(type, normalized_value, page_id) DO UPDATE SET
                last_seen=excluded.last_seen,
                value=excluded.value
            """,
            [
                (i.type, i.value, i.normalized, page.fetched_at, page.fetched_at, page_id)
                for i in page.iocs
            ],
        )
    return int(page_id)


def count_pages(conn: sqlite3.Connection) -> int:
    """Número de páginas almacenadas."""
    return int(conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0])


def status_counts(conn: sqlite3.Connection) -> list[tuple[int | None, int]]:
    """Recuento de páginas por código HTTP."""
    rows = conn.execute(
        "SELECT status, COUNT(*) FROM pages GROUP BY status ORDER BY status"
    ).fetchall()
    return [(r[0], r[1]) for r in rows]


def expand_ioc_types(ioc_type: str | None) -> Sequence[str] | None:
    """Traduce el alias ``hash`` a md5/sha1/sha256; ``None`` significa todos."""
    if ioc_type is None:
        return None
    if ioc_type == "hash":
        return ("md5", "sha1", "sha256")
    return (ioc_type,)


def ioc_type_counts(conn: sqlite3.Connection) -> list[tuple[str, int, int]]:
    """Por tipo: (tipo, valores distintos, apariciones en páginas)."""
    rows = conn.execute(
        """
        SELECT type, COUNT(DISTINCT normalized_value), COUNT(*)
        FROM iocs GROUP BY type ORDER BY type
        """
    ).fetchall()
    return [(r[0], r[1], r[2]) for r in rows]


def ioc_values(
    conn: sqlite3.Connection, ioc_type: str | None = None, limit: int | None = None
) -> list[sqlite3.Row]:
    """Valores de IOC agregados: tipo, valor, nº de páginas, primera y última vez visto."""
    types = expand_ioc_types(ioc_type)
    where, params = "", []
    if types:
        where = f"WHERE type IN ({','.join('?' * len(types))})"
        params.extend(types)
    sql = f"""
        SELECT type, normalized_value AS value, COUNT(DISTINCT page_id) AS pages,
               MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen
        FROM iocs {where}
        GROUP BY type, normalized_value
        ORDER BY pages DESC, type, value
    """  # noqa: S608 - solo se interpolan marcadores "?"
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)
    return conn.execute(sql, params).fetchall()


def pages_for_ioc(conn: sqlite3.Connection, normalized_values: Iterable[str]) -> list[sqlite3.Row]:
    """Páginas en las que aparece alguno de los valores normalizados indicados."""
    values = list(dict.fromkeys(normalized_values))
    if not values:
        return []
    marks = ",".join("?" * len(values))
    return conn.execute(
        f"""
        SELECT i.type, i.normalized_value AS value, i.first_seen, i.last_seen,
               p.id AS page_id, p.url, p.title, p.status, p.fetched_at
        FROM iocs i JOIN pages p ON p.id = i.page_id
        WHERE i.normalized_value IN ({marks})
        ORDER BY i.type, p.fetched_at DESC
        """,  # noqa: S608 - solo se interpolan marcadores "?"
        values,
    ).fetchall()
