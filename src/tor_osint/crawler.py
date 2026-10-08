"""Crawler controlado: solo consulta las fuentes indicadas, sin recursión.

Los enlaces .onion descubiertos se registran (``links_json`` e IOCs de tipo
``onion``), pero nunca se convierten automáticamente en nuevas tareas: el
investigador decide qué fuentes añadir a ``data/sources.txt``.
"""

from __future__ import annotations

import gzip
import hashlib
import logging
import os
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .database import PageRecord, audit, latest_snapshot_for_url, store_page
from .dedup import content_hash
from .ioc import extract_iocs
from .parser import parse_content
from .redact import redact
from .tor import FetchResult, TorClient
from .watch import scan_page

log = logging.getLogger(__name__)


@dataclass
class CrawlSummary:
    """Resumen de una ejecución de ``crawl``."""

    stored: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    new: list[str] = field(default_factory=list)
    changed: list[tuple[str, list[str]]] = field(default_factory=list)
    alerts: int = 0


def save_raw(raw_dir: Path, content: bytes) -> str:
    """Guarda el HTML original comprimido como evidencia y devuelve su SHA-256.

    El fichero se nombra por su hash (idempotente) y se crea con permisos 0600:
    contiene el contenido SIN redactar, por eso solo se guarda si se pide.
    Nunca se abre, renderiza ni ejecuta.
    """
    digest = hashlib.sha256(content).hexdigest()
    raw_dir.mkdir(parents=True, exist_ok=True)
    target = raw_dir / f"{digest}.html.gz"
    if not target.exists():
        tmp = target.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh, gzip.GzipFile(fileobj=fh, mode="wb", mtime=0) as gz:
            gz.write(content)
        tmp.replace(target)
    return digest


def _change_kinds(previous: sqlite3.Row, record: PageRecord) -> list[str]:
    kinds = []
    if previous["status"] != record.status:
        kinds.append("status")
    if (previous["title"] or "") != record.title:
        kinds.append("título")
    if previous["content_hash"] != record.content_hash:
        kinds.append("contenido")
    return kinds


def build_record(source: str, result: FetchResult) -> PageRecord:
    """Convierte una descarga en un registro listo para guardar.

    Orden importante: parseo → redacción de secretos → IOCs y hash. Así ningún
    secreto llega a la base de datos, a los IOCs ni al hash publicado.
    """
    parsed = parse_content(result.final_url, result.content, result.content_type, result.encoding)
    title = redact(parsed.title)
    text = redact(parsed.text)
    links = [redact(link) for link in parsed.links]
    return PageRecord(
        url=result.final_url,
        source=source,
        status=result.status,
        title=title,
        text=text,
        content_hash=content_hash(text),
        links=links,
        iocs=extract_iocs(f"{title}\n{text}", links),
    )


def crawl(
    sources: list[str],
    client: TorClient,
    conn: sqlite3.Connection,
    max_urls: int,
    on_progress: Callable[[int, int, str], None] | None = None,
    raw_dir: Path | None = None,
) -> CrawlSummary:
    """Consulta cada fuente una vez (máximo ``max_urls``) y guarda el resultado en SQLite.

    ``on_progress(índice, total, url)`` se invoca antes de cada petición (lo usa la web).
    Con ``raw_dir`` se guarda además el HTML original comprimido (sin redactar).
    Cada página guardada se compara con su snapshot anterior y se evalúa contra
    la watchlist.
    """
    summary = CrawlSummary()
    if len(sources) > max_urls:
        summary.skipped = sources[max_urls:]
        log.warning("Se consultarán solo %d de %d fuentes (max_urls)", max_urls, len(sources))

    selected = sources[:max_urls]
    for index, source in enumerate(selected, start=1):
        if on_progress:
            on_progress(index, len(selected), source)
        log.info("Consultando %s", source)
        result = client.fetch(source)
        if not result.ok or not result.content:
            reason = result.error or "respuesta vacía"
            log.error("%s: %s", source, reason)
            summary.failed.append((source, reason))
            continue
        try:
            record = build_record(source, result)
            if raw_dir is not None:
                record.raw_sha256 = save_raw(raw_dir, result.content)
            previous = latest_snapshot_for_url(conn, record.url)
            page_id = store_page(conn, record)
            summary.alerts += scan_page(conn, page_id)
        except (sqlite3.Error, ValueError, OSError) as exc:
            log.error("No se pudo procesar %s: %s", source, exc)
            summary.failed.append((source, f"error procesando: {type(exc).__name__}"))
            continue
        summary.stored.append(record.url)
        if previous is None:
            summary.new.append(record.url)
        elif kinds := _change_kinds(previous, record):
            summary.changed.append((record.url, kinds))
        log.info(
            "%s -> HTTP %s, %d IOCs, %d enlaces",
            record.url,
            record.status,
            len(record.iocs),
            len(record.links),
        )
    audit(
        conn,
        "crawl",
        requested=len(sources),
        stored=len(summary.stored),
        failed=len(summary.failed),
        new=len(summary.new),
        changed=len(summary.changed),
        alerts=summary.alerts,
        raw_saved=raw_dir is not None,
    )
    return summary
