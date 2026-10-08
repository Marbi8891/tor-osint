"""Búsqueda local (texto y regex) sobre el contenido almacenado.

La regex del usuario se ejecuta solo contra la base de datos local, nunca
durante el crawling ni contra datos remotos.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass

MAX_PATTERN_LEN = 1_000
# Marcadores de resaltado en los snippets FTS: caracteres de control que no
# aparecen en el texto extraído; CLI y web los convierten en su formato.
HL_START, HL_END = "\x02", "\x03"
_TOKEN_RE = re.compile(r"\w+", re.UNICODE)


@dataclass(frozen=True)
class RegexHit:
    """Página con coincidencias de una regex."""

    page_id: int
    url: str
    title: str
    matches: list[str]


def _escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def search_text(conn: sqlite3.Connection, term: str) -> list[sqlite3.Row]:
    """Busca ``term`` (sin distinguir mayúsculas, literal) en título y texto."""
    if not term.strip():
        raise ValueError("el término de búsqueda está vacío")
    pattern = f"%{_escape_like(term.lower())}%"
    return conn.execute(
        r"""
        SELECT id, url, fetched_at, status, title, content_hash
        FROM pages
        WHERE lower(title) LIKE ? ESCAPE '\' OR lower(text) LIKE ? ESCAPE '\'
        ORDER BY fetched_at DESC
        """,
        (pattern, pattern),
    ).fetchall()


def fts_query(term: str) -> str:
    """Convierte texto libre en una consulta FTS5 segura: cada palabra entre comillas
    (sin operadores del usuario) y con prefijo, combinadas con AND implícito."""
    tokens = _TOKEN_RE.findall(term)
    if not tokens:
        raise ValueError("el término de búsqueda no contiene palabras")
    return " ".join(f'"{t}"*' for t in tokens[:32])


def search_fts(conn: sqlite3.Connection, term: str, limit: int = 200) -> list[sqlite3.Row]:
    """Búsqueda de texto completo (FTS5) ordenada por relevancia (BM25) con snippet.

    Ignora tildes y mayúsculas y admite prefijos ("acm" encuentra "ACME").
    """
    if not term.strip():
        raise ValueError("el término de búsqueda está vacío")
    return conn.execute(
        """
        SELECT p.id, p.url, p.fetched_at, p.status, p.title, p.content_hash,
               snippet(pages_fts, 1, ?, ?, '…', 16) AS snippet,
               bm25(pages_fts, 5.0, 1.0) AS rank
        FROM pages_fts JOIN pages p ON p.id = pages_fts.rowid
        WHERE pages_fts MATCH ?
        ORDER BY rank
        LIMIT ?
        """,
        (HL_START, HL_END, fts_query(term), limit),
    ).fetchall()


def compile_pattern(pattern: str) -> re.Pattern[str]:
    """Compila la regex del usuario (insensible a mayúsculas) con límite de longitud."""
    if len(pattern) > MAX_PATTERN_LEN:
        raise ValueError(f"regex demasiado larga (máx. {MAX_PATTERN_LEN} caracteres)")
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise ValueError(f"regex inválida: {exc}") from exc


def regex_search(conn: sqlite3.Connection, pattern: str, max_matches: int = 20) -> list[RegexHit]:
    """Busca ``pattern`` en el título y el texto de cada página almacenada."""
    expression = compile_pattern(pattern)
    hits: list[RegexHit] = []
    for row in conn.execute("SELECT id, url, title, text FROM pages ORDER BY id"):
        found: dict[str, None] = {}
        for field_value in (row["title"] or "", row["text"] or ""):
            for match in expression.finditer(field_value):
                if match.group(0):  # ignora coincidencias vacías (p. ej. "a*")
                    found.setdefault(match.group(0))
        if found:
            matches = sorted(found)[:max_matches]
            hits.append(RegexHit(row["id"], row["url"], row["title"] or "", matches))
    return hits
