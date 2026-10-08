"""Informe HTML local y autocontenido.

Todo el contenido procedente de las fuentes se escapa con ``html.escape``. El
documento incluye una CSP que bloquea scripts y cargas externas, y las URLs se
muestran como texto (no como enlaces) para evitar visitas accidentales.
"""

from __future__ import annotations

import html
import sqlite3
from pathlib import Path

from . import __version__
from .database import (
    count_pages,
    ioc_type_counts,
    ioc_values,
    pages_for_ioc,
    status_counts,
    utc_now,
)
from .dedup import find_duplicates

MAX_ROWS_PER_SECTION = 500
SECTIONS = (
    ("cve", "CVEs"),
    ("domain", "Dominios"),
    ("email", "Emails"),
    ("ipv4", "IPv4"),
    ("hash", "Hashes (MD5 / SHA-1 / SHA-256)"),
    ("onion", "URLs onion"),
    ("url", "URLs clearnet"),
)

CSS = """
:root { color-scheme: light dark; --border: #8884; --muted: #888; }
body { font-family: system-ui, sans-serif; max-width: 1200px; margin: 32px auto;
       padding: 0 16px; line-height: 1.45; }
table { border-collapse: collapse; width: 100%; margin: 8px 0 24px; font-size: 14px; }
th, td { border: 1px solid var(--border); padding: 6px 8px; text-align: left;
         vertical-align: top; }
th { background: #8881; }
code { overflow-wrap: anywhere; font-size: 13px; }
.muted { color: var(--muted); }
.cards { display: flex; flex-wrap: wrap; gap: 12px; }
.card { border: 1px solid var(--border); border-radius: 8px; padding: 12px 16px; min-width: 140px; }
.card b { display: block; font-size: 24px; }
"""


def _e(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return '<p class="muted">Sin datos.</p>'
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _ioc_section(conn: sqlite3.Connection, ioc_type: str, title: str) -> str:
    values = ioc_values(conn, ioc_type, limit=MAX_ROWS_PER_SECTION + 1)
    note = ""
    if len(values) > MAX_ROWS_PER_SECTION:
        values = values[:MAX_ROWS_PER_SECTION]
        note = f'<p class="muted">Mostrando los primeros {MAX_ROWS_PER_SECTION} valores.</p>'
    rows = []
    for row in values:
        pages = pages_for_ioc(conn, [row["value"]])
        page_list = "<br>".join(
            f'<code>{_e(p["url"])}</code> <span class="muted">#{p["page_id"]}</span>'
            for p in pages
            if p["type"] == row["type"]
        )
        rows.append(
            [
                f"<code>{_e(row['value'])}</code>",
                _e(row["type"]),
                _e(row["pages"]),
                _e(row["first_seen"]),
                _e(row["last_seen"]),
                page_list,
            ]
        )
    headers = ["Valor", "Tipo", "Páginas", "Primera vez", "Última vez", "Aparece en"]
    return f"<h3>{_e(title)}</h3>{note}{_table(headers, rows)}"


def build_report(
    conn: sqlite3.Connection, source_count: int, generated_at: str | None = None
) -> str:
    """Genera el HTML del informe a partir de la base de datos."""
    generated_at = generated_at or utc_now()
    total_pages = count_pages(conn)
    duplicates = find_duplicates(conn)
    type_counts = ioc_type_counts(conn)

    cards = "".join(
        f'<div class="card"><b>{_e(v)}</b>{_e(k)}</div>'
        for k, v in (
            ("Fuentes configuradas", source_count),
            ("Páginas recopiladas", total_pages),
            ("Grupos duplicados", len(duplicates)),
            ("IOCs distintos", sum(c[1] for c in type_counts)),
        )
    )
    status_table = _table(
        ["Código HTTP", "Páginas"],
        [[_e(s if s is not None else "—"), _e(n)] for s, n in status_counts(conn)],
    )
    ioc_table = _table(
        ["Tipo", "Valores distintos", "Apariciones"],
        [[_e(t), _e(d), _e(n)] for t, d, n in type_counts],
    )
    dup_table = _table(
        ["SHA-256 del contenido", "URLs"],
        [
            [
                f"<code>{_e(g.content_hash)}</code>",
                "<br>".join(f"<code>{_e(u)}</code>" for u in g.urls),
            ]
            for g in duplicates
        ],
    )
    pages_rows = [
        [
            _e(r["id"]),
            _e(r["title"] or "(sin título)"),
            f"<code>{_e(r['url'])}</code>",
            _e(r["status"]),
            _e(r["fetched_at"]),
            f"<code>{_e(r['content_hash'])}</code>",
        ]
        for r in conn.execute(
            "SELECT id, title, url, status, fetched_at, content_hash FROM pages "
            "ORDER BY fetched_at DESC LIMIT ?",
            (MAX_ROWS_PER_SECTION,),
        )
    ]
    pages_table = _table(["ID", "Título", "URL", "HTTP", "Fecha", "SHA-256"], pages_rows)
    sections = "".join(_ioc_section(conn, t, title) for t, title in SECTIONS)

    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="referrer" content="no-referrer">
<title>Informe tor-osint</title>
<style>{CSS}</style>
</head>
<body>
<h1>Informe tor-osint</h1>
<p class="muted">Generado: {_e(generated_at)} · tor-osint {_e(__version__)} ·
Contenido remoto tratado como no confiable; credenciales redactadas antes del almacenamiento.</p>

<h2>Resumen</h2>
<div class="cards">{cards}</div>

<h2>Códigos HTTP</h2>
{status_table}

<h2>Contenido duplicado</h2>
{dup_table}

<h2>IOCs por tipo</h2>
{ioc_table}

<h2>Relación IOC ↔ páginas</h2>
{sections}

<h2>Páginas</h2>
{pages_table}
</body>
</html>
"""


def write_report(conn: sqlite3.Connection, output: Path, source_count: int) -> Path:
    """Escribe el informe en ``output`` y devuelve la ruta."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(build_report(conn, source_count), encoding="utf-8")
    return output
