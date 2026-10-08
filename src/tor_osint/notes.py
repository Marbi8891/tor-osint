"""Notas y etiquetas del investigador sobre páginas e IOCs."""

from __future__ import annotations

import re
import sqlite3

from .database import audit, utc_now
from .ioc import normalize_any

TARGET_TYPES = ("page", "ioc")
MAX_NOTE_LEN = 10_000
TAG_RE = re.compile(r"[\w.-]{1,40}", re.UNICODE)


def resolve_target(conn: sqlite3.Connection, target_type: str, target: str) -> str:
    """Valida el objetivo y devuelve su clave canónica (id de página o IOC normalizado)."""
    if target_type not in TARGET_TYPES:
        raise ValueError("el objetivo debe ser 'page' o 'ioc'")
    target = str(target).strip()
    if target_type == "page":
        if (
            not target.isdigit()
            or conn.execute("SELECT 1 FROM pages WHERE id = ?", (int(target),)).fetchone() is None
        ):
            raise ValueError("página no encontrada")
        return str(int(target))
    if not target or len(target) > 500:
        raise ValueError("valor de IOC no válido")
    return normalize_any(target)[1]


def normalize_tag(tag: str) -> str:
    """Etiqueta en minúsculas con caracteres seguros (letras, números, ``_ . -``)."""
    tag = tag.strip().lower().replace(" ", "-")
    if not TAG_RE.fullmatch(tag):
        raise ValueError("etiqueta no válida (1-40 caracteres: letras, números, _ . -)")
    return tag


def add_note(conn: sqlite3.Connection, target_type: str, target: str, body: str) -> int:
    """Añade una nota y devuelve su id."""
    key = resolve_target(conn, target_type, target)
    body = body.strip()
    if not body or len(body) > MAX_NOTE_LEN:
        raise ValueError(f"la nota debe tener entre 1 y {MAX_NOTE_LEN} caracteres")
    with conn:
        cur = conn.execute(
            "INSERT INTO notes (target_type, target, body, created_at) VALUES (?, ?, ?, ?)",
            (target_type, key, body, utc_now()),
        )
    audit(conn, "note.add", note_id=cur.lastrowid, target_type=target_type, target=key)
    return int(cur.lastrowid or 0)


def delete_note(conn: sqlite3.Connection, note_id: int) -> None:
    """Elimina una nota."""
    with conn:
        cur = conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    if cur.rowcount == 0:
        raise ValueError("nota no encontrada")
    audit(conn, "note.delete", note_id=note_id)


def list_notes(
    conn: sqlite3.Connection, target_type: str | None = None, target: str | None = None
) -> list[sqlite3.Row]:
    """Notas de un objetivo concreto, o todas si no se indica."""
    if target_type and target is not None:
        key = resolve_target(conn, target_type, target)
        return conn.execute(
            "SELECT * FROM notes WHERE target_type = ? AND target = ? ORDER BY id DESC",
            (target_type, key),
        ).fetchall()
    return conn.execute("SELECT * FROM notes ORDER BY id DESC").fetchall()


def add_tag(conn: sqlite3.Connection, target_type: str, target: str, tag: str) -> str:
    """Etiqueta un objetivo (idempotente). Devuelve la etiqueta normalizada."""
    key = resolve_target(conn, target_type, target)
    tag = normalize_tag(tag)
    with conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO tags (target_type, target, tag, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (target_type, key, tag, utc_now()),
        )
    audit(conn, "tag.add", target_type=target_type, target=key, tag=tag)
    return tag


def remove_tag(conn: sqlite3.Connection, target_type: str, target: str, tag: str) -> None:
    """Quita una etiqueta de un objetivo."""
    key = resolve_target(conn, target_type, target)
    with conn:
        cur = conn.execute(
            "DELETE FROM tags WHERE target_type = ? AND target = ? AND tag = ?",
            (target_type, key, normalize_tag(tag)),
        )
    if cur.rowcount == 0:
        raise ValueError("etiqueta no encontrada en ese objetivo")
    audit(conn, "tag.remove", target_type=target_type, target=key, tag=tag)


def tags_for(conn: sqlite3.Connection, target_type: str, target: str) -> list[str]:
    """Etiquetas de un objetivo."""
    key = resolve_target(conn, target_type, target)
    return [
        r[0]
        for r in conn.execute(
            "SELECT tag FROM tags WHERE target_type = ? AND target = ? ORDER BY tag",
            (target_type, key),
        )
    ]


def tag_counts(conn: sqlite3.Connection) -> list[tuple[str, int]]:
    """Etiquetas en uso con su número de objetivos."""
    rows = conn.execute("SELECT tag, COUNT(*) FROM tags GROUP BY tag ORDER BY 2 DESC, 1").fetchall()
    return [(r[0], r[1]) for r in rows]


def targets_with_tag(conn: sqlite3.Connection, tag: str) -> list[sqlite3.Row]:
    """Objetivos con una etiqueta (con URL y título si son páginas)."""
    return conn.execute(
        """
        SELECT t.target_type, t.target, t.created_at, p.url, p.title
        FROM tags t
        LEFT JOIN pages p ON t.target_type = 'page' AND p.id = CAST(t.target AS INTEGER)
        WHERE t.tag = ? ORDER BY t.target_type, t.target
        """,
        (normalize_tag(tag),),
    ).fetchall()
