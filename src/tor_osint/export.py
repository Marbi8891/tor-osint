"""Exportación de páginas e IOCs a JSON y CSV."""

from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path

from . import __version__
from .database import utc_now

PAGE_COLUMNS = (
    "id",
    "url",
    "source",
    "fetched_at",
    "status",
    "title",
    "text",
    "content_hash",
    "links",
    "iocs",
)
IOC_COLUMNS = ("id", "type", "value", "normalized_value", "first_seen", "last_seen", "page_id")
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _pages(conn: sqlite3.Connection) -> list[dict[str, object]]:
    rows = conn.execute(
        """
        SELECT id, url, source, fetched_at, status, title, text, content_hash,
               links_json, iocs_json
        FROM pages ORDER BY id
        """
    ).fetchall()
    pages = []
    for row in rows:
        item = dict(zip(PAGE_COLUMNS, tuple(row), strict=True))
        item["links"] = json.loads(row["links_json"] or "[]")
        item["iocs"] = json.loads(row["iocs_json"] or "{}")
        pages.append(item)
    return pages


def _iocs(conn: sqlite3.Connection) -> list[dict[str, object]]:
    rows = conn.execute(f"SELECT {', '.join(IOC_COLUMNS)} FROM iocs ORDER BY id").fetchall()  # noqa: S608
    return [dict(row) for row in rows]


def export_json(conn: sqlite3.Connection, output: Path) -> Path:
    """Escribe un único JSON con metadatos, páginas e IOCs."""
    output.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "generator": f"tor-osint {__version__}",
        "generated_at": utc_now(),
        "pages": _pages(conn),
        "iocs": _iocs(conn),
    }
    output.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return output


def csv_safe(value: object) -> object:
    """Neutraliza la inyección de fórmulas en hojas de cálculo (CSV injection)."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def export_csv(conn: sqlite3.Connection, output: Path) -> tuple[Path, Path]:
    """Escribe ``output`` (páginas) y ``<output>_iocs.csv`` (IOCs). Devuelve ambas rutas."""
    output.parent.mkdir(parents=True, exist_ok=True)
    iocs_output = output.with_name(f"{output.stem}_iocs{output.suffix or '.csv'}")

    with output.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(PAGE_COLUMNS)
        for page in _pages(conn):
            page["links"] = json.dumps(page["links"], ensure_ascii=False)
            page["iocs"] = json.dumps(page["iocs"], ensure_ascii=False)
            writer.writerow([csv_safe(page[c]) for c in PAGE_COLUMNS])

    with iocs_output.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(IOC_COLUMNS)
        for ioc in _iocs(conn):
            writer.writerow([csv_safe(ioc[c]) for c in IOC_COLUMNS])

    return output, iocs_output
