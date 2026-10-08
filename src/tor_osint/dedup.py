"""Normalización de contenido, hash SHA-256 y detección de duplicados."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass

_WS_RE = re.compile(r"\s+")
EMPTY_HASH = hashlib.sha256(b"").hexdigest()


def normalize_text(text: str) -> str:
    """Normaliza el texto para comparar contenido: espacios colapsados y extremos recortados."""
    return _WS_RE.sub(" ", text).strip()


def content_hash(text: str) -> str:
    """SHA-256 (hex) del texto normalizado en UTF-8."""
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class DuplicateGroup:
    """Varias URLs con exactamente el mismo contenido normalizado."""

    content_hash: str
    urls: list[str]
    titles: list[str]


def find_duplicates(conn: sqlite3.Connection) -> list[DuplicateGroup]:
    """Agrupa las páginas por ``content_hash`` (ignora páginas sin texto)."""
    rows = conn.execute(
        """
        SELECT content_hash, url, COALESCE(title, '') AS title
        FROM pages
        WHERE content_hash IN (
            SELECT content_hash FROM pages
            WHERE content_hash IS NOT NULL AND content_hash != ?
            GROUP BY content_hash HAVING COUNT(*) > 1
        )
        ORDER BY content_hash, url
        """,
        (EMPTY_HASH,),
    ).fetchall()
    groups: dict[str, DuplicateGroup] = {}
    for row in rows:
        group = groups.setdefault(row["content_hash"], DuplicateGroup(row["content_hash"], [], []))
        group.urls.append(row["url"])
        group.titles.append(row["title"])
    return sorted(groups.values(), key=lambda g: (-len(g.urls), g.content_hash))
