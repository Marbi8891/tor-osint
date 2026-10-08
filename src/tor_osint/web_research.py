"""Endpoints de la interfaz web para la gestión de la investigación.

Mixin de ``WebApp``: historial y cambios, watchlist y alertas, notas y etiquetas,
grafo de correlación, casi duplicados, auditoría y verificación de evidencias.
Cada método recibe la query (GET) o el cuerpo JSON (POST) y devuelve datos
serializables; la validación de entrada lanza ``ValueError`` (→ HTTP 400).
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import AbstractContextManager
from dataclasses import asdict
from typing import Any

from .changes import diff_latest, diff_snapshots, page_history, recent_changes
from .config import Config
from .custody import verify_manifest
from .database import audit, audit_entries
from .dedup import DEFAULT_NEAR_DISTANCE, find_near_duplicates
from .ioc import IOC_TYPES
from .notes import (
    add_note,
    add_tag,
    delete_note,
    list_notes,
    remove_tag,
    tag_counts,
    tags_for,
    targets_with_tag,
)
from .watch import (
    acknowledge_alerts,
    add_watch,
    count_open_alerts,
    list_alerts,
    list_watches,
    remove_watch,
    scan_all,
)

Query = dict[str, list[str]]
MAX_GRAPH_IOCS = 150
MAX_GRAPH_PAGES = 300


def _q(query: Query, name: str, default: str = "") -> str:
    return query.get(name, [default])[0].strip()


def _qint(query: Query, name: str, default: int, lo: int, hi: int) -> int:
    raw = _q(query, name, str(default)) or str(default)
    if not raw.lstrip("-").isdigit():
        raise ValueError(f"{name} debe ser un entero")
    return max(lo, min(hi, int(raw)))


def _bint(body: dict[str, Any], name: str) -> int:
    value = body.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} debe ser un entero")
    return value


def _bstr(body: dict[str, Any], name: str) -> str:
    value = body.get(name)
    if not isinstance(value, str):
        raise ValueError(f"{name} debe ser texto")
    return value


def _rows(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


class ResearchApi:
    """Métodos de la API de investigación (los usa ``WebApp``)."""

    config: Config

    def db(self) -> AbstractContextManager[sqlite3.Connection]:  # implementado en WebApp
        raise NotImplementedError

    # --- historial y cambios --------------------------------------------------------

    def changes(self, query: Query) -> dict[str, Any]:
        """Páginas que cambiaron en su último crawl."""
        with self.db() as conn:
            return {"items": recent_changes(conn, _qint(query, "limit", 50, 1, 500))}

    def history(self, page_id: int) -> dict[str, Any]:
        """Snapshots de una página."""
        with self.db() as conn:
            rows = page_history(conn, page_id)
        if not rows:
            raise ValueError("página sin historial o inexistente")
        items = []
        for row in rows:
            item = dict(row)
            iocs = json.loads(item.pop("iocs_json") or "{}")
            item["ioc_count"] = sum(len(v) for v in iocs.values())
            items.append(item)
        return {"page_id": page_id, "items": items}

    def diff(self, query: Query) -> dict[str, Any]:
        """Diferencias entre dos snapshots (o los dos últimos de la página)."""
        page_id = _qint(query, "page", 0, 0, 10**12)
        old, new = _q(query, "from"), _q(query, "to")
        with self.db() as conn:
            if old and new:
                if not (old.isdigit() and new.isdigit()):
                    raise ValueError("from y to deben ser ids de snapshot")
                result = diff_snapshots(conn, int(old), int(new))
                if result.page_id != page_id:
                    raise ValueError("los snapshots no pertenecen a esa página")
            else:
                result = diff_latest(conn, page_id)
        if result is None:
            return {"page_id": page_id, "diff": None}
        data = asdict(result)
        data["kinds"] = result.kinds()
        return {"page_id": page_id, "diff": data}

    # --- watchlist y alertas ------------------------------------------------------------

    def watchlist(self) -> dict[str, Any]:
        """Vigilancias con sus recuentos de alertas."""
        with self.db() as conn:
            return {"items": _rows(list_watches(conn))}

    def alerts(self, query: Query) -> dict[str, Any]:
        """Alertas pendientes (o todas con ``all=1``)."""
        with self.db() as conn:
            rows = list_alerts(conn, include_acknowledged=_q(query, "all") == "1")
            return {"open": count_open_alerts(conn), "items": _rows(rows)}

    def watch_add(self, body: dict[str, Any]) -> dict[str, Any]:
        """Añade una vigilancia y devuelve las coincidencias iniciales."""
        label = body.get("label")
        with self.db() as conn:
            watch_id, alerts = add_watch(
                conn,
                _bstr(body, "kind"),
                _bstr(body, "value"),
                label if isinstance(label, str) else None,
            )
        return {"id": watch_id, "alerts": alerts}

    def watch_delete(self, body: dict[str, Any]) -> dict[str, Any]:
        """Elimina una vigilancia."""
        with self.db() as conn:
            remove_watch(conn, _bint(body, "id"))
        return {"deleted": True}

    def watch_scan(self, _body: dict[str, Any]) -> dict[str, Any]:
        """Reevalúa la BD completa contra la watchlist."""
        with self.db() as conn:
            return {"alerts": scan_all(conn)}

    def alerts_ack(self, body: dict[str, Any]) -> dict[str, Any]:
        """Marca alertas como revisadas (todas si no se indican ids)."""
        ids = body.get("ids")
        if ids is not None and (
            not isinstance(ids, list) or not all(type(i) is int for i in ids) or len(ids) > 1000
        ):
            raise ValueError("ids debe ser una lista de enteros")
        with self.db() as conn:
            return {"acknowledged": acknowledge_alerts(conn, ids)}

    # --- notas y etiquetas ------------------------------------------------------------------

    def annotations(self, query: Query) -> dict[str, Any]:
        """Notas y etiquetas de un objetivo (página o IOC)."""
        target_type, target = _q(query, "target_type"), _q(query, "target")
        with self.db() as conn:
            return {
                "notes": _rows(list_notes(conn, target_type, target)),
                "tags": tags_for(conn, target_type, target),
            }

    def tags(self, query: Query) -> dict[str, Any]:
        """Etiquetas en uso, o los objetivos de una etiqueta."""
        tag = _q(query, "tag")
        with self.db() as conn:
            if tag:
                return {"tag": tag, "items": _rows(targets_with_tag(conn, tag))}
            return {"items": [{"tag": t, "count": c} for t, c in tag_counts(conn)]}

    def note_add(self, body: dict[str, Any]) -> dict[str, Any]:
        """Añade una nota."""
        with self.db() as conn:
            note_id = add_note(
                conn, _bstr(body, "target_type"), str(body.get("target", "")), _bstr(body, "body")
            )
        return {"id": note_id}

    def note_delete(self, body: dict[str, Any]) -> dict[str, Any]:
        """Elimina una nota."""
        with self.db() as conn:
            delete_note(conn, _bint(body, "id"))
        return {"deleted": True}

    def tag_add(self, body: dict[str, Any]) -> dict[str, Any]:
        """Etiqueta un objetivo."""
        with self.db() as conn:
            tag = add_tag(
                conn, _bstr(body, "target_type"), str(body.get("target", "")), _bstr(body, "tag")
            )
        return {"tag": tag}

    def tag_delete(self, body: dict[str, Any]) -> dict[str, Any]:
        """Quita una etiqueta de un objetivo."""
        with self.db() as conn:
            remove_tag(
                conn, _bstr(body, "target_type"), str(body.get("target", "")), _bstr(body, "tag")
            )
        return {"deleted": True}

    # --- análisis -----------------------------------------------------------------------------

    def near_duplicates(self, query: Query) -> dict[str, Any]:
        """Grupos de casi duplicados por SimHash."""
        distance = _qint(query, "distance", DEFAULT_NEAR_DISTANCE, 0, 32)
        with self.db() as conn:
            groups = find_near_duplicates(conn, distance)
        return {"distance": distance, "items": [asdict(g) for g in groups]}

    def graph(self, query: Query) -> dict[str, Any]:
        """Grafo bipartito página ↔ IOC con los IOCs compartidos por varias páginas."""
        min_pages = _qint(query, "min_pages", 2, 1, 1000)
        ioc_type = _q(query, "type")
        if ioc_type and ioc_type not in IOC_TYPES:
            raise ValueError("tipo de IOC desconocido")
        where = "WHERE type = ?" if ioc_type else ""
        params: list[Any] = [*([ioc_type] if ioc_type else []), min_pages, MAX_GRAPH_IOCS]
        with self.db() as conn:
            shared = conn.execute(
                f"""
                SELECT type, normalized_value AS value, COUNT(DISTINCT page_id) AS pages
                FROM iocs {where}
                GROUP BY type, normalized_value HAVING pages >= ?
                ORDER BY pages DESC, type, value LIMIT ?
                """,  # noqa: S608 - "where" es un literal fijo; los valores van como "?"
                params,
            ).fetchall()
            edges, page_ids = [], set()
            for row in shared:
                for (page_id,) in conn.execute(
                    "SELECT DISTINCT page_id FROM iocs WHERE type = ? AND normalized_value = ?",
                    (row["type"], row["value"]),
                ):
                    if len(page_ids) >= MAX_GRAPH_PAGES and page_id not in page_ids:
                        continue
                    page_ids.add(page_id)
                    edges.append([f"p{page_id}", f"i:{row['type']}:{row['value']}"])
            pages = []
            if page_ids:
                marks = ",".join("?" * len(page_ids))
                pages = conn.execute(
                    f"SELECT id, url, title FROM pages WHERE id IN ({marks})",  # noqa: S608
                    sorted(page_ids),
                ).fetchall()
        nodes = [
            {"id": f"p{p['id']}", "kind": "page", "page_id": p["id"], "label": p["title"] or "",
             "url": p["url"]}
            for p in pages
        ] + [
            {"id": f"i:{r['type']}:{r['value']}", "kind": "ioc", "type": r["type"],
             "label": r["value"], "pages": r["pages"]}
            for r in shared
        ]  # fmt: skip
        return {"min_pages": min_pages, "nodes": nodes, "edges": edges,
                "truncated": len(shared) >= MAX_GRAPH_IOCS}  # fmt: skip

    def audit_log(self, query: Query) -> dict[str, Any]:
        """Últimas entradas del registro de auditoría."""
        with self.db() as conn:
            rows = audit_entries(conn, _qint(query, "limit", 100, 1, 1000))
        items = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            items.append(item)
        return {"items": items}

    def verify(self, _body: dict[str, Any]) -> dict[str, Any]:
        """Verifica los hashes del manifiesto de evidencias."""
        result = verify_manifest(self.config.results_dir)
        with self.db() as conn:
            audit(
                conn,
                "verify",
                ok=len(result.ok),
                modified=len(result.modified),
                missing=len(result.missing),
            )
        return {**asdict(result), "passed": result.passed}
