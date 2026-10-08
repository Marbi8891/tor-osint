"""Normalización de contenido, hash SHA-256 y detección de duplicados."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass

_WS_RE = re.compile(r"\s+")
_WORD_RE = re.compile(r"\w+", re.UNICODE)
EMPTY_HASH = hashlib.sha256(b"").hexdigest()
SIMHASH_BITS = 64
EMPTY_SIMHASH = "0" * 16
# Calibrado con textos de ≥ 60 palabras: casi duplicados p95 ≤ 13 bits; ajenos ≥ 20.
DEFAULT_NEAR_DISTANCE = 14
MAX_SIMHASH_WORDS = 50_000  # límite de coste: textos de 2 MB tardarían segundos


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


# --- casi duplicados (SimHash) ------------------------------------------------


def simhash(text: str, shingle: int = 3) -> str:
    """SimHash de 64 bits (hex) sobre shingles de ``shingle`` palabras.

    Textos parecidos producen huellas con pocos bits distintos (distancia de
    Hamming baja), a diferencia de SHA-256, donde un solo carácter lo cambia todo.
    """
    words = [w.lower() for w in _WORD_RE.findall(text)][:MAX_SIMHASH_WORDS]
    if not words:
        return EMPTY_SIMHASH
    size = min(shingle, len(words))
    vector = [0] * SIMHASH_BITS
    for i in range(len(words) - size + 1):
        token = " ".join(words[i : i + size]).encode("utf-8")
        value = int.from_bytes(hashlib.blake2b(token, digest_size=8).digest(), "big")
        for bit in range(SIMHASH_BITS):
            vector[bit] += 1 if value >> bit & 1 else -1
    fingerprint = sum(1 << bit for bit in range(SIMHASH_BITS) if vector[bit] > 0)
    return f"{fingerprint:016x}"


def hamming(a: str, b: str) -> int:
    """Distancia de Hamming entre dos SimHash en hex."""
    return (int(a, 16) ^ int(b, 16)).bit_count()


@dataclass(frozen=True)
class NearDuplicateGroup:
    """Páginas con contenido parecido (no idéntico): mirrors con pequeños cambios."""

    pages: list[dict[str, object]]
    max_distance: int


def find_near_duplicates(
    conn: sqlite3.Connection, max_distance: int = DEFAULT_NEAR_DISTANCE
) -> list[NearDuplicateGroup]:
    """Agrupa páginas cuyo SimHash difiere en ``max_distance`` bits o menos.

    Excluye los pares con el mismo SHA-256 (ya aparecen en ``duplicates``). La
    comparación es O(n²): adecuada para colecciones de laboratorio (miles de páginas).
    """
    rows = conn.execute(
        """
        SELECT id, url, COALESCE(title, '') AS title, content_hash, simhash FROM pages
        WHERE simhash IS NOT NULL AND simhash != ? AND content_hash != ?
        ORDER BY id
        """,
        (EMPTY_SIMHASH, EMPTY_HASH),
    ).fetchall()
    parent = {row["id"]: row["id"] for row in rows}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    worst: dict[int, int] = {}
    for i, a in enumerate(rows):
        for b in rows[i + 1 :]:
            if a["content_hash"] == b["content_hash"]:
                continue
            distance = hamming(a["simhash"], b["simhash"])
            if distance <= max_distance:
                ra, rb = find(a["id"]), find(b["id"])
                parent[rb] = ra
                worst[ra] = max(worst.get(ra, 0), worst.pop(rb, 0), distance)

    groups: dict[int, list[dict[str, object]]] = {}
    for row in rows:
        root = find(row["id"])
        groups.setdefault(root, []).append(
            {"id": row["id"], "url": row["url"], "title": row["title"], "simhash": row["simhash"]}
        )
    result = [
        NearDuplicateGroup(pages, worst.get(root, 0))
        for root, pages in groups.items()
        if len(pages) > 1
    ]
    return sorted(result, key=lambda g: (-len(g.pages), g.max_distance))
