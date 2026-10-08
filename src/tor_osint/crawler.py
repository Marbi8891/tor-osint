"""Crawler controlado: solo consulta las fuentes indicadas, sin recursión.

Los enlaces .onion descubiertos se registran (``links_json`` e IOCs de tipo
``onion``), pero nunca se convierten automáticamente en nuevas tareas: el
investigador decide qué fuentes añadir a ``data/sources.txt``.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field

from .database import PageRecord, store_page
from .dedup import content_hash
from .ioc import extract_iocs
from .parser import parse_content
from .redact import redact
from .tor import FetchResult, TorClient

log = logging.getLogger(__name__)


@dataclass
class CrawlSummary:
    """Resumen de una ejecución de ``crawl``."""

    stored: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


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
    sources: list[str], client: TorClient, conn: sqlite3.Connection, max_urls: int
) -> CrawlSummary:
    """Consulta cada fuente una vez (máximo ``max_urls``) y guarda el resultado en SQLite."""
    summary = CrawlSummary()
    if len(sources) > max_urls:
        summary.skipped = sources[max_urls:]
        log.warning("Se consultarán solo %d de %d fuentes (max_urls)", max_urls, len(sources))

    for source in sources[:max_urls]:
        log.info("Consultando %s", source)
        result = client.fetch(source)
        if not result.ok or not result.content:
            reason = result.error or "respuesta vacía"
            log.error("%s: %s", source, reason)
            summary.failed.append((source, reason))
            continue
        try:
            record = build_record(source, result)
            store_page(conn, record)
        except (sqlite3.Error, ValueError) as exc:
            log.error("No se pudo procesar %s: %s", source, exc)
            summary.failed.append((source, f"error procesando: {type(exc).__name__}"))
            continue
        summary.stored.append(record.url)
        log.info(
            "%s -> HTTP %s, %d IOCs, %d enlaces",
            record.url,
            record.status,
            len(record.iocs),
            len(record.links),
        )
    return summary
