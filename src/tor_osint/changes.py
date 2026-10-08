"""Historial de páginas y detección de cambios entre crawls."""

from __future__ import annotations

import difflib
import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any

MAX_DIFF_WORDS = 20_000
MAX_FRAGMENT_CHARS = 400
MAX_FRAGMENTS = 50


@dataclass
class SnapshotDiff:
    """Diferencias entre dos snapshots de la misma página."""

    page_id: int
    old_id: int
    new_id: int
    old_fetched_at: str
    new_fetched_at: str
    status: tuple[int | None, int | None] | None = None
    title: tuple[str | None, str | None] | None = None
    content_changed: bool = False
    similarity: float = 1.0
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    iocs_added: dict[str, list[str]] = field(default_factory=dict)
    iocs_removed: dict[str, list[str]] = field(default_factory=dict)
    truncated: bool = False

    @property
    def changed(self) -> bool:
        """Hay algún cambio relevante entre ambos snapshots."""
        return bool(
            self.status
            or self.title
            or self.content_changed
            or self.iocs_added
            or self.iocs_removed
        )

    def kinds(self) -> list[str]:
        """Tipos de cambio en forma corta (status, título, contenido, iocs)."""
        kinds = []
        if self.status:
            kinds.append("status")
        if self.title:
            kinds.append("título")
        if self.content_changed:
            kinds.append("contenido")
        if self.iocs_added or self.iocs_removed:
            kinds.append("iocs")
        return kinds


def page_history(conn: sqlite3.Connection, page_id: int) -> list[sqlite3.Row]:
    """Snapshots de una página, del más reciente al más antiguo."""
    return conn.execute(
        """
        SELECT id, fetched_at, status, title, content_hash, raw_sha256, iocs_json
        FROM snapshots WHERE page_id = ? ORDER BY id DESC
        """,
        (page_id,),
    ).fetchall()


def _snapshot(conn: sqlite3.Connection, snapshot_id: int) -> sqlite3.Row:
    row = conn.execute(
        """
        SELECT s.*, c.text FROM snapshots s JOIN contents c ON c.hash = s.content_hash
        WHERE s.id = ?
        """,
        (snapshot_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"snapshot {snapshot_id} no encontrado")
    return row


def _ioc_delta(old_json: str | None, new_json: str | None) -> tuple[dict, dict]:
    old: dict[str, list[str]] = json.loads(old_json or "{}")
    new: dict[str, list[str]] = json.loads(new_json or "{}")
    added, removed = {}, {}
    for ioc_type in sorted(set(old) | set(new)):
        before, after = set(old.get(ioc_type, [])), set(new.get(ioc_type, []))
        if after - before:
            added[ioc_type] = sorted(after - before)
        if before - after:
            removed[ioc_type] = sorted(before - after)
    return added, removed


def _fragment(words: list[str]) -> str:
    text = " ".join(words)
    return text if len(text) <= MAX_FRAGMENT_CHARS else text[:MAX_FRAGMENT_CHARS] + "…"


def diff_snapshots(conn: sqlite3.Connection, old_id: int, new_id: int) -> SnapshotDiff:
    """Compara dos snapshots: estado HTTP, título, texto (por palabras) e IOCs."""
    old, new = _snapshot(conn, old_id), _snapshot(conn, new_id)
    if old["page_id"] != new["page_id"]:
        raise ValueError("los snapshots pertenecen a páginas distintas")
    diff = SnapshotDiff(
        page_id=new["page_id"],
        old_id=old_id,
        new_id=new_id,
        old_fetched_at=old["fetched_at"],
        new_fetched_at=new["fetched_at"],
    )
    if old["status"] != new["status"]:
        diff.status = (old["status"], new["status"])
    if (old["title"] or "") != (new["title"] or ""):
        diff.title = (old["title"], new["title"])
    diff.iocs_added, diff.iocs_removed = _ioc_delta(old["iocs_json"], new["iocs_json"])

    if old["content_hash"] != new["content_hash"]:
        diff.content_changed = True
        a, b = old["text"].split(), new["text"].split()
        if len(a) > MAX_DIFF_WORDS or len(b) > MAX_DIFF_WORDS:
            diff.truncated = True
            a, b = a[:MAX_DIFF_WORDS], b[:MAX_DIFF_WORDS]
        matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
        diff.similarity = round(matcher.ratio(), 4)
        for op, i1, i2, j1, j2 in matcher.get_opcodes():
            if op in ("delete", "replace") and len(diff.removed) < MAX_FRAGMENTS:
                diff.removed.append(_fragment(a[i1:i2]))
            if op in ("insert", "replace") and len(diff.added) < MAX_FRAGMENTS:
                diff.added.append(_fragment(b[j1:j2]))
    return diff


def diff_latest(conn: sqlite3.Connection, page_id: int) -> SnapshotDiff | None:
    """Diferencias entre los dos últimos snapshots de una página (``None`` si solo hay uno)."""
    rows = conn.execute(
        "SELECT id FROM snapshots WHERE page_id = ? ORDER BY id DESC LIMIT 2", (page_id,)
    ).fetchall()
    if len(rows) < 2:
        return None
    return diff_snapshots(conn, rows[1]["id"], rows[0]["id"])


def recent_changes(conn: sqlite3.Connection, limit: int = 50) -> list[dict[str, Any]]:
    """Páginas cuyo último snapshot difiere del anterior, de la más reciente a la más antigua.

    Solo compara campos baratos (hash, estado, título, IOCs); el diff de texto se
    calcula bajo demanda con ``diff_snapshots``.
    """
    rows = conn.execute(
        """
        WITH ranked AS (
            SELECT s.*, ROW_NUMBER() OVER (PARTITION BY s.page_id ORDER BY s.id DESC) AS rn
            FROM snapshots s
        )
        SELECT p.id AS page_id, p.url, p.title AS page_title,
               n.id AS new_id, n.fetched_at, n.status AS new_status, n.title AS new_title,
               n.content_hash AS new_hash, n.iocs_json AS new_iocs,
               o.id AS old_id, o.status AS old_status, o.title AS old_title,
               o.content_hash AS old_hash, o.iocs_json AS old_iocs
        FROM ranked n
        JOIN ranked o ON o.page_id = n.page_id AND o.rn = 2
        JOIN pages p ON p.id = n.page_id
        WHERE n.rn = 1
        ORDER BY n.fetched_at DESC, n.id DESC
        """
    ).fetchall()
    changes: list[dict[str, Any]] = []
    for row in rows:
        kinds = []
        if row["old_status"] != row["new_status"]:
            kinds.append("status")
        if (row["old_title"] or "") != (row["new_title"] or ""):
            kinds.append("título")
        if row["old_hash"] != row["new_hash"]:
            kinds.append("contenido")
        added, removed = _ioc_delta(row["old_iocs"], row["new_iocs"])
        if added or removed:
            kinds.append("iocs")
        if kinds:
            changes.append(
                {
                    "page_id": row["page_id"],
                    "url": row["url"],
                    "title": row["page_title"],
                    "fetched_at": row["fetched_at"],
                    "kinds": kinds,
                    "iocs_added": added,
                    "iocs_removed": removed,
                    "old_snapshot": row["old_id"],
                    "new_snapshot": row["new_id"],
                }
            )
            if len(changes) >= limit:
                break
    return changes
