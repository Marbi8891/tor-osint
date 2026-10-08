"""Persistencia SQLite: páginas, historial, IOCs, auditoría y consultas de agregación."""

from __future__ import annotations

import getpass
import json
import logging
import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .dedup import simhash
from .ioc import Ioc

log = logging.getLogger(__name__)

SCHEMA_VERSION = 3

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

-- v3: historial. Cada texto distinto se guarda una sola vez (deduplicado por hash).
CREATE TABLE IF NOT EXISTS contents (
    hash TEXT PRIMARY KEY,
    text TEXT NOT NULL,
    first_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    page_id INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
    fetched_at TEXT NOT NULL,
    status INTEGER,
    title TEXT,
    content_hash TEXT NOT NULL REFERENCES contents(hash),
    iocs_json TEXT,
    raw_sha256 TEXT
);
CREATE INDEX IF NOT EXISTS idx_snapshots_page ON snapshots(page_id, id);

-- v3: registro de auditoría (cadena de custodia).
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    details_json TEXT NOT NULL
);

-- v3: watchlist y alertas locales.
CREATE TABLE IF NOT EXISTS watchlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('term', 'ioc')),
    value TEXT NOT NULL,
    normalized TEXT NOT NULL,
    label TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (kind, normalized)
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    watch_id INTEGER NOT NULL REFERENCES watchlist(id) ON DELETE CASCADE,
    page_id INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
    content_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    UNIQUE (watch_id, page_id, content_hash)
);
CREATE INDEX IF NOT EXISTS idx_alerts_open ON alerts(acknowledged, created_at);

-- v3: notas y etiquetas del investigador sobre páginas o IOCs.
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type TEXT NOT NULL CHECK (target_type IN ('page', 'ioc')),
    target TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_target ON notes(target_type, target);
CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type TEXT NOT NULL CHECK (target_type IN ('page', 'ioc')),
    target TEXT NOT NULL,
    tag TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (target_type, target, tag)
);
CREATE INDEX IF NOT EXISTS idx_tags_tag ON tags(tag);

-- v3: enriquecimiento offline de CVEs (feed NVD importado manualmente).
CREATE TABLE IF NOT EXISTS cve_info (
    cve_id TEXT PRIMARY KEY,
    cvss_score REAL,
    severity TEXT,
    cvss_version TEXT,
    description TEXT,
    published TEXT,
    imported_at TEXT NOT NULL
);
"""

FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS pages_fts USING fts5(
    title, text, content='pages', content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);
CREATE TRIGGER IF NOT EXISTS pages_fts_ai AFTER INSERT ON pages BEGIN
    INSERT INTO pages_fts(rowid, title, text) VALUES (new.id, new.title, new.text);
END;
CREATE TRIGGER IF NOT EXISTS pages_fts_ad AFTER DELETE ON pages BEGIN
    INSERT INTO pages_fts(pages_fts, rowid, title, text)
    VALUES ('delete', old.id, old.title, old.text);
END;
CREATE TRIGGER IF NOT EXISTS pages_fts_au AFTER UPDATE ON pages BEGIN
    INSERT INTO pages_fts(pages_fts, rowid, title, text)
    VALUES ('delete', old.id, old.title, old.text);
    INSERT INTO pages_fts(rowid, title, text) VALUES (new.id, new.title, new.text);
END;
"""


def utc_now() -> str:
    """Marca de tiempo ISO-8601 en UTC."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def has_fts(conn: sqlite3.Connection) -> bool:
    """``True`` si el índice FTS5 está disponible en esta base de datos."""
    row = conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'pages_fts'").fetchone()
    return row is not None


def _migrate(conn: sqlite3.Connection) -> None:
    """Aplica el esquema y migra bases de datos anteriores (v1/v2) a v3."""
    previous = conn.execute("PRAGMA user_version").fetchone()[0]
    conn.executescript(SCHEMA)
    if "simhash" not in _columns(conn, "pages"):
        conn.execute("ALTER TABLE pages ADD COLUMN simhash TEXT")

    fts_created = False
    if not has_fts(conn):
        try:
            conn.executescript(FTS_SCHEMA)
            fts_created = True
        except sqlite3.OperationalError:
            log.warning("SQLite sin FTS5: la búsqueda usará LIKE")
    if fts_created:
        conn.execute("INSERT INTO pages_fts(pages_fts) VALUES ('rebuild')")

    if previous < SCHEMA_VERSION:
        # Páginas anteriores al historial: se crea un snapshot inicial y su SimHash.
        rows = conn.execute(
            """
            SELECT p.* FROM pages p
            WHERE NOT EXISTS (SELECT 1 FROM snapshots s WHERE s.page_id = p.id)
            """
        ).fetchall()
        for row in rows:
            _insert_snapshot(
                conn,
                row["id"],
                row["fetched_at"],
                row["status"],
                row["title"],
                row["text"] or "",
                row["content_hash"] or "",
                row["iocs_json"],
                None,
            )
        for row in conn.execute("SELECT id, text FROM pages WHERE simhash IS NULL").fetchall():
            conn.execute(
                "UPDATE pages SET simhash = ? WHERE id = ?", (simhash(row["text"] or ""), row["id"])
            )
        if rows:
            log.info(
                "Migración v%s -> v%s: %d snapshots iniciales", previous, SCHEMA_VERSION, len(rows)
            )
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


def connect(path: Path | str) -> sqlite3.Connection:
    """Abre (o crea) la base de datos, aplica el esquema y migra versiones anteriores."""
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    with conn:
        _migrate(conn)
    return conn


# --- auditoría ---------------------------------------------------------------


def current_actor() -> str:
    """Usuario del sistema que ejecuta la herramienta (para el registro de auditoría)."""
    try:
        return getpass.getuser()
    except (OSError, KeyError):
        return "desconocido"


def audit(conn: sqlite3.Connection, action: str, **details: Any) -> None:
    """Registra una acción en ``audit_log`` (nunca guarda secretos, solo metadatos)."""
    with conn:
        conn.execute(
            "INSERT INTO audit_log (at, actor, action, details_json) VALUES (?, ?, ?, ?)",
            (utc_now(), current_actor(), action, json.dumps(details, ensure_ascii=False)),
        )


def audit_entries(conn: sqlite3.Connection, limit: int = 100) -> list[sqlite3.Row]:
    """Últimas entradas del registro de auditoría."""
    return conn.execute(
        "SELECT id, at, actor, action, details_json FROM audit_log ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()


# --- páginas -----------------------------------------------------------------


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
    raw_sha256: str | None = None


def _group_iocs(iocs: list[Ioc]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for ioc in iocs:
        grouped.setdefault(ioc.type, []).append(ioc.normalized)
    return grouped


def _insert_snapshot(
    conn: sqlite3.Connection,
    page_id: int,
    fetched_at: str,
    status: int | None,
    title: str | None,
    text: str,
    content_hash: str,
    iocs_json: str | None,
    raw_sha256: str | None,
) -> int:
    conn.execute(
        "INSERT OR IGNORE INTO contents (hash, text, first_seen) VALUES (?, ?, ?)",
        (content_hash, text, fetched_at),
    )
    cur = conn.execute(
        """
        INSERT INTO snapshots (page_id, fetched_at, status, title, content_hash, iocs_json,
                               raw_sha256)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (page_id, fetched_at, status, title, content_hash, iocs_json, raw_sha256),
    )
    return int(cur.lastrowid or 0)


def store_page(conn: sqlite3.Connection, page: PageRecord) -> int:
    """Inserta o actualiza una página (deduplicación por URL), su snapshot y sus IOCs.

    Devuelve el id de la página. Cada llamada añade un snapshot al historial.
    """
    iocs_json = json.dumps(_group_iocs(page.iocs), ensure_ascii=False, sort_keys=True)
    with conn:
        conn.execute(
            """
            INSERT INTO pages (url, source, fetched_at, status, title, text,
                               content_hash, links_json, iocs_json, simhash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(url) DO UPDATE SET
                source=excluded.source,
                fetched_at=excluded.fetched_at,
                status=excluded.status,
                title=excluded.title,
                text=excluded.text,
                content_hash=excluded.content_hash,
                links_json=excluded.links_json,
                iocs_json=excluded.iocs_json,
                simhash=excluded.simhash
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
                iocs_json,
                simhash(page.text),
            ),
        )
        page_id = conn.execute("SELECT id FROM pages WHERE url = ?", (page.url,)).fetchone()[0]
        _insert_snapshot(
            conn,
            page_id,
            page.fetched_at,
            page.status,
            page.title,
            page.text,
            page.content_hash,
            iocs_json,
            page.raw_sha256,
        )
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


def latest_snapshot_for_url(conn: sqlite3.Connection, url: str) -> sqlite3.Row | None:
    """Último snapshot de la página con esa URL (antes de un nuevo crawl), o ``None``."""
    return conn.execute(
        """
        SELECT s.* FROM snapshots s JOIN pages p ON p.id = s.page_id
        WHERE p.url = ? ORDER BY s.id DESC LIMIT 1
        """,
        (url,),
    ).fetchone()


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
    """Traduce los alias ``hash`` y ``crypto``; ``None`` significa todos."""
    if ioc_type is None:
        return None
    if ioc_type == "hash":
        return ("md5", "sha1", "sha256")
    if ioc_type == "crypto":
        return ("btc", "eth")
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


def discovered_onions(conn: sqlite3.Connection, known: Iterable[str]) -> list[sqlite3.Row]:
    """URLs .onion vistas en páginas que no están entre las fuentes ``known``."""
    known_set = set(known)
    return [row for row in ioc_values(conn, "onion") if row["value"] not in known_set]


def list_pages(conn: sqlite3.Connection, limit: int = 50, offset: int = 0) -> list[sqlite3.Row]:
    """Listado paginado de páginas (sin el texto completo)."""
    return conn.execute(
        """
        SELECT p.id, p.url, p.source, p.fetched_at, p.status, p.title, p.content_hash,
               (SELECT COUNT(*) FROM iocs i WHERE i.page_id = p.id) AS ioc_count,
               (SELECT COUNT(*) FROM snapshots s WHERE s.page_id = p.id) AS snapshot_count
        FROM pages p ORDER BY p.fetched_at DESC, p.id DESC LIMIT ? OFFSET ?
        """,
        (limit, offset),
    ).fetchall()


def get_page(conn: sqlite3.Connection, page_id: int) -> sqlite3.Row | None:
    """Una página completa por id, o ``None``."""
    return conn.execute("SELECT * FROM pages WHERE id = ?", (page_id,)).fetchone()


def page_iocs(conn: sqlite3.Connection, page_id: int) -> list[sqlite3.Row]:
    """IOCs asociados a una página."""
    return conn.execute(
        """
        SELECT type, value, normalized_value, first_seen, last_seen
        FROM iocs WHERE page_id = ? ORDER BY type, normalized_value
        """,
        (page_id,),
    ).fetchall()
