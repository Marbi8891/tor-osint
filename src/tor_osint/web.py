"""Interfaz web local: API JSON + frontend estático, solo con la biblioteca estándar.

Modelo de amenazas: la interfaz corre en la máquina del investigador y muestra
contenido remoto no confiable. Por eso:

- solo escucha en loopback y valida la cabecera ``Host`` (frente a DNS rebinding);
- toda petición POST exige ``Content-Type: application/json`` y un token CSRF
  aleatorio por proceso (y, si viene, un ``Origin`` propio);
- las respuestas llevan una CSP estricta (sin scripts inline ni recursos externos);
- el frontend pinta los datos con ``textContent``, nunca como HTML.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import sqlite3
import threading
from contextlib import closing
from dataclasses import asdict, dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .changes import recent_changes
from .config import Config
from .crawler import crawl
from .custody import record_artifact
from .database import (
    connect,
    count_pages,
    discovered_onions,
    get_page,
    has_fts,
    ioc_type_counts,
    ioc_values,
    list_pages,
    page_iocs,
    pages_for_ioc,
    status_counts,
    utc_now,
)
from .dedup import find_duplicates
from .enrich import cve_details
from .export import export_csv, export_json
from .interop import export_misp, export_stix
from .ioc import CLI_IOC_TYPES, candidate_normalizations, normalize_any
from .notes import list_notes, tags_for
from .report import write_report
from .search import regex_search, search_fts, search_text
from .sources import add_source, is_valid_onion_url, load_sources, normalize_onion_url
from .tor import TorClient
from .watch import count_open_alerts
from .web_research import ResearchApi

log = logging.getLogger(__name__)

MAX_BODY_BYTES = 64 * 1024
MAX_PAGE_TEXT = 100_000
STATIC_FILES = {
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/static/core.js": ("core.js", "text/javascript; charset=utf-8"),
    "/static/status.js": ("status.js", "text/javascript; charset=utf-8"),
    "/static/views.js": ("views.js", "text/javascript; charset=utf-8"),
    "/static/research.js": ("research.js", "text/javascript; charset=utf-8"),
    "/static/style.css": ("style.css", "text/css; charset=utf-8"),
}
APP_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
_PAGE_RE = re.compile(r"^/api/pages/(\d{1,12})(/history)?$")


class HttpError(Exception):
    """Error controlado que se devuelve al cliente como JSON."""

    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class CrawlJob:
    """Estado del crawl en segundo plano (solo uno a la vez)."""

    state: str = "idle"  # idle | running | done | error
    started_at: str | None = None
    finished_at: str | None = None
    total: int = 0
    current: int = 0
    current_url: str | None = None
    stored: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)
    skipped: int = 0
    new: int = 0
    changed: int = 0
    alerts: int = 0
    error: str | None = None


def is_loopback(host: str) -> bool:
    """``True`` si ``host`` es localhost o una IP de loopback."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _rows(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def _int_param(query: dict[str, list[str]], name: str, default: int, lo: int, hi: int) -> int:
    raw = query.get(name, [str(default)])[0]
    try:
        value = int(raw)
    except ValueError as exc:
        raise HttpError(HTTPStatus.BAD_REQUEST, f"{name} debe ser un entero") from exc
    return max(lo, min(hi, value))


def _str_param(query: dict[str, list[str]], name: str) -> str:
    value = query.get(name, [""])[0].strip()
    if not value:
        raise HttpError(HTTPStatus.BAD_REQUEST, f"falta el parámetro {name}")
    return value


class WebApp(ResearchApi):
    """Lógica de la aplicación web, independiente del servidor HTTP."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.csrf_token = secrets.token_urlsafe(32)
        self.allowed_hosts: set[str] = set()
        self.job = CrawlJob()
        self._job_lock = threading.Lock()

    def set_port(self, *ports: int) -> None:
        """Fija los valores válidos de la cabecera Host (loopback) para los puertos dados."""
        self.allowed_hosts = {
            f"{host}:{port}" for port in ports for host in ("127.0.0.1", "localhost", "[::1]")
        }

    def db(self) -> closing[sqlite3.Connection]:
        """Conexión nueva por petición (el servidor atiende cada petición en un hilo)."""
        return closing(connect(self.config.database))

    # --- páginas estáticas --------------------------------------------------

    def index_html(self) -> bytes:
        """Devuelve ``index.html`` con el token CSRF incrustado en una etiqueta meta."""
        template = resources.files("tor_osint").joinpath("static/index.html").read_text("utf-8")
        return template.replace("{{CSRF_TOKEN}}", self.csrf_token).encode("utf-8")

    @staticmethod
    def static_file(name: str) -> bytes:
        """Lee un fichero de la lista blanca de estáticos."""
        return resources.files("tor_osint").joinpath(f"static/{name}").read_bytes()

    # --- API GET -------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        """Datos del panel principal."""
        sources = load_sources(self.config.sources)
        with self.db() as conn:
            types = ioc_type_counts(conn)
            return {
                "open_alerts": count_open_alerts(conn),
                "recent_changes": recent_changes(conn, 10),
                "version": __version__,
                "sources": len(sources.valid),
                "rejected_sources": len(sources.rejected),
                "pages": count_pages(conn),
                "duplicates": len(find_duplicates(conn)),
                "iocs_distinct": sum(t[1] for t in types),
                "ioc_types": [{"type": t, "distinct": d, "total": n} for t, d, n in types],
                "status_counts": [{"status": s, "pages": n} for s, n in status_counts(conn)],
                "socks": self.config.socks,
                "database": str(self.config.database),
            }

    def sources(self) -> dict[str, Any]:
        """Fuentes válidas, líneas rechazadas y .onion descubiertas no incluidas."""
        result = load_sources(self.config.sources)
        with self.db() as conn:
            discovered = _rows(discovered_onions(conn, result.valid))
        return {
            "file": str(self.config.sources),
            "valid": result.valid,
            "rejected": [{"line": n, "value": v} for n, v in result.rejected],
            "discovered": discovered,
        }

    def pages(self, query: dict[str, list[str]]) -> dict[str, Any]:
        """Listado paginado de páginas."""
        limit = _int_param(query, "limit", 50, 1, 500)
        offset = _int_param(query, "offset", 0, 0, 10_000_000)
        with self.db() as conn:
            return {
                "total": count_pages(conn),
                "limit": limit,
                "offset": offset,
                "items": _rows(list_pages(conn, limit, offset)),
            }

    def page(self, page_id: int) -> dict[str, Any]:
        """Detalle de una página con texto (truncado), enlaces e IOCs."""
        with self.db() as conn:
            row = get_page(conn, page_id)
            if row is None:
                raise HttpError(HTTPStatus.NOT_FOUND, "página no encontrada")
            iocs = _rows(page_iocs(conn, page_id))
            notes = _rows(list_notes(conn, "page", str(page_id)))
            tags = tags_for(conn, "page", str(page_id))
        text = row["text"] or ""
        return {
            "id": row["id"],
            "url": row["url"],
            "source": row["source"],
            "fetched_at": row["fetched_at"],
            "status": row["status"],
            "title": row["title"],
            "content_hash": row["content_hash"],
            "text": text[:MAX_PAGE_TEXT],
            "text_truncated": len(text) > MAX_PAGE_TEXT,
            "links": json.loads(row["links_json"] or "[]"),
            "iocs": iocs,
            "notes": notes,
            "tags": tags,
        }

    def search(self, query: dict[str, list[str]]) -> dict[str, Any]:
        """Búsqueda de texto completo (FTS5, con snippet) o literal (``mode=substring``)."""
        term = _str_param(query, "q")
        with self.db() as conn:
            if query.get("mode", [""])[0] != "substring" and has_fts(conn):
                return {"mode": "fts", "items": _rows(search_fts(conn, term))}
            return {"mode": "substring", "items": _rows(search_text(conn, term))}

    def regex(self, query: dict[str, list[str]]) -> dict[str, Any]:
        """Búsqueda por regex sobre datos locales."""
        pattern = _str_param(query, "pattern")
        max_matches = _int_param(query, "max", 20, 1, 200)
        with self.db() as conn:
            hits = regex_search(conn, pattern, max_matches)
        return {"items": [asdict(h) for h in hits]}

    def iocs(self, query: dict[str, list[str]]) -> dict[str, Any]:
        """Estadísticas y valores de IOCs, opcionalmente filtrados por tipo."""
        ioc_type = query.get("type", [""])[0] or None
        if ioc_type is not None and ioc_type not in CLI_IOC_TYPES:
            raise HttpError(HTTPStatus.BAD_REQUEST, "tipo de IOC desconocido")
        limit = _int_param(query, "limit", 200, 1, 5000)
        with self.db() as conn:
            types = ioc_type_counts(conn)
            items = _rows(ioc_values(conn, ioc_type, limit=limit))
            cvss = cve_details(conn, [i["value"] for i in items if i["type"] == "cve"])
        for item in items:
            if item["value"] in cvss:
                item["cvss"] = cvss[item["value"]]
        return {
            "types": [{"type": t, "distinct": d, "total": n} for t, d, n in types],
            "items": items,
        }

    def related(self, query: dict[str, list[str]]) -> dict[str, Any]:
        """Páginas en las que aparece un IOC concreto."""
        value = _str_param(query, "value")
        ioc_type, normalized = normalize_any(value)
        with self.db() as conn:
            rows = pages_for_ioc(conn, candidate_normalizations(value))
            notes = _rows(list_notes(conn, "ioc", value))
            tags = tags_for(conn, "ioc", value)
            cvss = cve_details(conn, [normalized]).get(normalized) if ioc_type == "cve" else None
        return {
            "value": value,
            "normalized": normalized,
            "type": ioc_type,
            "items": _rows(rows),
            "notes": notes,
            "tags": tags,
            "cvss": cvss,
        }

    def duplicates(self) -> dict[str, Any]:
        """Grupos de URLs con contenido idéntico."""
        with self.db() as conn:
            return {"items": [asdict(g) for g in find_duplicates(conn)]}

    def export(self, query: dict[str, list[str]]) -> tuple[bytes, str, str]:
        """Genera la exportación en ``results/`` y devuelve (contenido, tipo, nombre)."""
        fmt = query.get("format", ["json"])[0]
        results = self.config.results_dir
        ctype = "application/json; charset=utf-8"
        with self.db() as conn:
            if fmt == "json":
                paths = [export_json(conn, results / "results.json")]
            elif fmt == "csv":
                paths = list(export_csv(conn, results / "results.csv"))
                ctype = "text/csv; charset=utf-8"
            elif fmt == "stix":
                paths = [export_stix(conn, results / "results.stix.json")[0]]
            elif fmt == "misp":
                paths = [export_misp(conn, results / "results.misp.json")]
            else:
                raise HttpError(HTTPStatus.BAD_REQUEST, "formato no soportado")
            for path in paths:
                record_artifact(conn, path, f"export.{fmt}")
        path = paths[1] if fmt == "csv" and query.get("table", [""])[0] == "iocs" else paths[0]
        return path.read_bytes(), ctype, path.name

    def report_html(self) -> bytes:
        """Contenido del último informe generado."""
        path = self.config.results_dir / "report.html"
        if not path.exists():
            raise HttpError(HTTPStatus.NOT_FOUND, "todavía no se ha generado el informe")
        return path.read_bytes()

    # --- API POST ------------------------------------------------------------

    def add_source(self, body: dict[str, Any]) -> dict[str, Any]:
        """Añade una fuente (acción explícita del investigador)."""
        url = str(body.get("url", ""))
        try:
            return {"added": add_source(self.config.sources, url)}
        except ValueError as exc:
            raise HttpError(HTTPStatus.BAD_REQUEST, str(exc)) from exc

    def tor_check(self, body: dict[str, Any]) -> dict[str, Any]:
        """Comprueba Tor; la IP de salida solo se devuelve si se pide."""
        status = TorClient(self.config).check_tor()
        return {
            "is_tor": status.is_tor,
            "error": status.error,
            "ip": status.ip if body.get("show_ip") is True else None,
        }

    def generate_report(self) -> dict[str, Any]:
        """Genera ``results/report.html``."""
        source_count = len(load_sources(self.config.sources).valid)
        with self.db() as conn:
            path = write_report(conn, self.config.results_dir / "report.html", source_count)
            entry = record_artifact(conn, path, "report")
        return {"path": str(path), "url": "/report", "sha256": entry["sha256"]}

    def crawl_status(self) -> dict[str, Any]:
        """Estado del crawl en segundo plano."""
        with self._job_lock:
            data = asdict(self.job)
        data["failed"] = [{"url": u, "reason": r} for u, r in self.job.failed]
        return data

    def start_crawl(self, body: dict[str, Any]) -> dict[str, Any]:
        """Lanza un crawl en segundo plano sobre todas las fuentes o las indicadas."""
        urls = body.get("urls") or []
        if not isinstance(urls, list) or not all(isinstance(u, str) for u in urls):
            raise HttpError(HTTPStatus.BAD_REQUEST, "urls debe ser una lista de cadenas")
        if urls:
            invalid = [u for u in urls if not is_valid_onion_url(u)]
            if invalid:
                raise HttpError(HTTPStatus.BAD_REQUEST, f"URL .onion no válida: {invalid[0][:200]}")
            sources = list(dict.fromkeys(normalize_onion_url(u) for u in urls))
        else:
            sources = load_sources(self.config.sources).valid
        if not sources:
            raise HttpError(HTTPStatus.BAD_REQUEST, "no hay fuentes válidas que consultar")

        with self._job_lock:
            if self.job.state == "running":
                raise HttpError(HTTPStatus.CONFLICT, "ya hay un crawl en curso")
            self.job = CrawlJob(
                state="running",
                started_at=utc_now(),
                total=min(len(sources), self.config.max_urls),
            )
        threading.Thread(target=self._run_crawl, args=(sources,), daemon=True).start()
        return self.crawl_status()

    def _run_crawl(self, sources: list[str]) -> None:
        def progress(index: int, total: int, url: str) -> None:
            with self._job_lock:
                self.job.current, self.job.total, self.job.current_url = index, total, url

        try:
            with self.db() as conn:
                client = TorClient(self.config)
                summary = crawl(sources, client, conn, self.config.max_urls, progress)
            with self._job_lock:
                self.job.stored = summary.stored
                self.job.failed = summary.failed
                self.job.skipped = len(summary.skipped)
                self.job.new = len(summary.new)
                self.job.changed = len(summary.changed)
                self.job.alerts = summary.alerts
                self.job.state = "done"
        except Exception as exc:  # el hilo nunca debe morir en silencio
            log.exception("Error en el crawl")
            with self._job_lock:
                self.job.state = "error"
                self.job.error = type(exc).__name__
        finally:
            with self._job_lock:
                self.job.finished_at = utc_now()
                self.job.current_url = None


class RequestHandler(BaseHTTPRequestHandler):
    """Traduce HTTP a llamadas de ``WebApp`` y aplica los controles de seguridad."""

    server_version = f"tor-osint/{__version__}"
    sys_version = ""
    app: WebApp  # se asigna en make_server

    # --- utilidades ----------------------------------------------------------

    def log_message(self, fmt: str, *args: object) -> None:
        log.debug("%s - %s", self.address_string(), fmt % args)

    def _send(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        csp: str = APP_CSP,
        extra: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, data: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _check_host(self) -> None:
        if self.headers.get("Host", "") not in self.app.allowed_hosts:
            raise HttpError(HTTPStatus.MISDIRECTED_REQUEST, "cabecera Host no permitida")

    def _read_json(self) -> dict[str, Any]:
        """Valida CSRF, Origin y Content-Type, y parsea el cuerpo JSON."""
        token = self.headers.get("X-CSRF-Token", "")
        if not hmac.compare_digest(token, self.app.csrf_token):
            raise HttpError(HTTPStatus.FORBIDDEN, "token CSRF inválido")
        origin = self.headers.get("Origin")
        if origin is not None and urlsplit(origin).netloc not in self.app.allowed_hosts:
            raise HttpError(HTTPStatus.FORBIDDEN, "Origin no permitido")
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            raise HttpError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "se espera application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise HttpError(HTTPStatus.BAD_REQUEST, "Content-Length inválido") from exc
        if length > MAX_BODY_BYTES:
            raise HttpError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "cuerpo demasiado grande")
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            data = json.loads(raw or b"{}")
        except json.JSONDecodeError as exc:
            raise HttpError(HTTPStatus.BAD_REQUEST, "JSON inválido") from exc
        if not isinstance(data, dict):
            raise HttpError(HTTPStatus.BAD_REQUEST, "se espera un objeto JSON")
        return data

    def _guard(self, handler: Any) -> None:
        try:
            self._check_host()
            handler()
        except HttpError as exc:
            self._json({"error": exc.message}, exc.status)
        except ValueError as exc:  # p. ej. regex o término inválidos
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except sqlite3.Error:
            log.exception("Error de base de datos")
            self._json({"error": "error de base de datos"}, HTTPStatus.INTERNAL_SERVER_ERROR)
        except Exception:
            log.exception("Error inesperado")
            self._json({"error": "error interno"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    # --- rutas ---------------------------------------------------------------

    def do_GET(self) -> None:
        self._guard(self._route_get)

    def do_HEAD(self) -> None:
        self._guard(self._route_get)

    def do_POST(self) -> None:
        self._guard(self._route_post)

    def _route_get(self) -> None:
        parts = urlsplit(self.path)
        path, query = parts.path, parse_qs(parts.query)
        app = self.app
        if path in ("/", "/index.html"):
            self._send(HTTPStatus.OK, app.index_html(), "text/html; charset=utf-8")
        elif path in STATIC_FILES:
            name, ctype = STATIC_FILES[path]
            self._send(HTTPStatus.OK, app.static_file(name), ctype)
        elif path == "/report":
            self._send(HTTPStatus.OK, app.report_html(), "text/html; charset=utf-8", REPORT_CSP)
        elif path == "/api/export":
            body, ctype, filename = app.export(query)
            self._send(
                HTTPStatus.OK,
                body,
                ctype,
                extra={"Content-Disposition": f'attachment; filename="{filename}"'},
            )
        elif match := _PAGE_RE.match(path):
            page_id = int(match.group(1))
            self._json(app.history(page_id) if match.group(2) else app.page(page_id))
        elif path in GET_ROUTES:
            self._json(GET_ROUTES[path](app, query))
        else:
            raise HttpError(HTTPStatus.NOT_FOUND, "ruta no encontrada")

    def _route_post(self) -> None:
        path = urlsplit(self.path).path
        if path not in POST_ROUTES:
            raise HttpError(HTTPStatus.NOT_FOUND, "ruta no encontrada")
        body = self._read_json()
        status = HTTPStatus.ACCEPTED if path == "/api/crawl" else HTTPStatus.OK
        self._json(POST_ROUTES[path](self.app, body), status)


# Tablas de rutas: ruta → función(app, query|body). Las POST pasan antes por CSRF/Origin.
GET_ROUTES: dict[str, Any] = {
    "/api/summary": lambda app, q: app.summary(),
    "/api/sources": lambda app, q: app.sources(),
    "/api/pages": lambda app, q: app.pages(q),
    "/api/search": lambda app, q: app.search(q),
    "/api/regex": lambda app, q: app.regex(q),
    "/api/iocs": lambda app, q: app.iocs(q),
    "/api/related": lambda app, q: app.related(q),
    "/api/duplicates": lambda app, q: app.duplicates(),
    "/api/near-duplicates": lambda app, q: app.near_duplicates(q),
    "/api/crawl": lambda app, q: app.crawl_status(),
    "/api/changes": lambda app, q: app.changes(q),
    "/api/diff": lambda app, q: app.diff(q),
    "/api/watchlist": lambda app, q: app.watchlist(),
    "/api/alerts": lambda app, q: app.alerts(q),
    "/api/annotations": lambda app, q: app.annotations(q),
    "/api/tags": lambda app, q: app.tags(q),
    "/api/graph": lambda app, q: app.graph(q),
    "/api/audit": lambda app, q: app.audit_log(q),
}
POST_ROUTES: dict[str, Any] = {
    "/api/sources": lambda app, b: app.add_source(b),
    "/api/tor-check": lambda app, b: app.tor_check(b),
    "/api/crawl": lambda app, b: app.start_crawl(b),
    "/api/report": lambda app, b: app.generate_report(),
    "/api/watch": lambda app, b: app.watch_add(b),
    "/api/watch/delete": lambda app, b: app.watch_delete(b),
    "/api/watch/scan": lambda app, b: app.watch_scan(b),
    "/api/alerts/ack": lambda app, b: app.alerts_ack(b),
    "/api/notes": lambda app, b: app.note_add(b),
    "/api/notes/delete": lambda app, b: app.note_delete(b),
    "/api/tags": lambda app, b: app.tag_add(b),
    "/api/tags/delete": lambda app, b: app.tag_delete(b),
    "/api/verify": lambda app, b: app.verify(b),
}


CONTAINER_ENV = "TOR_OSINT_CONTAINER"


def make_server(
    config: Config,
    host: str = "127.0.0.1",
    port: int = 8765,
    container: bool = False,
    public_port: int | None = None,
) -> ThreadingHTTPServer:
    """Crea el servidor (sin arrancarlo). ``port=0`` elige un puerto libre.

    Fuera de un contenedor solo se permite loopback. Con ``container=True`` (y la
    variable ``TOR_OSINT_CONTAINER=1``, que solo define la imagen Docker) se escucha en
    todas las interfaces *del contenedor*; Docker Compose publica el puerto solo en el
    127.0.0.1 del anfitrión y la validación de la cabecera Host sigue activa.
    ``public_port`` es el puerto publicado en el anfitrión si difiere del interno.
    """
    if container:
        if os.environ.get(CONTAINER_ENV) != "1":
            raise ValueError(
                f"--container solo funciona dentro de la imagen Docker ({CONTAINER_ENV}=1)"
            )
        host = "0.0.0.0"  # noqa: S104 - interfaz del contenedor, publicada solo en loopback
    elif not is_loopback(host):
        raise ValueError("por seguridad la interfaz web solo puede escuchar en loopback")
    app = WebApp(config)
    handler = type("BoundHandler", (RequestHandler,), {"app": app})
    server_cls = ThreadingHTTPServer
    if ":" in host:  # IPv6 (::1)
        server_cls = type("Server6", (ThreadingHTTPServer,), {"address_family": socket.AF_INET6})
    server = server_cls((host.strip("[]"), port), handler)
    server.daemon_threads = True
    ports = [server.server_address[1]]
    if public_port is not None:
        if not 1 <= public_port <= 65535:
            raise ValueError("puerto público fuera de rango")
        ports.append(public_port)
    app.set_port(*ports)
    server.app = app  # type: ignore[attr-defined]
    return server
