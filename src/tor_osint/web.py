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
from .config import Config
from .crawler import crawl
from .database import (
    connect,
    count_pages,
    discovered_onions,
    get_page,
    ioc_type_counts,
    ioc_values,
    list_pages,
    page_iocs,
    pages_for_ioc,
    status_counts,
    utc_now,
)
from .dedup import find_duplicates
from .export import export_csv, export_json
from .ioc import CLI_IOC_TYPES, candidate_normalizations
from .report import write_report
from .search import regex_search, search_text
from .sources import add_source, is_valid_onion_url, load_sources, normalize_onion_url
from .tor import TorClient

log = logging.getLogger(__name__)

MAX_BODY_BYTES = 64 * 1024
MAX_PAGE_TEXT = 100_000
STATIC_FILES = {
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/static/style.css": ("style.css", "text/css; charset=utf-8"),
}
APP_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
_PAGE_RE = re.compile(r"^/api/pages/(\d{1,12})$")


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


class WebApp:
    """Lógica de la aplicación web, independiente del servidor HTTP."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.csrf_token = secrets.token_urlsafe(32)
        self.allowed_hosts: set[str] = set()
        self.job = CrawlJob()
        self._job_lock = threading.Lock()

    def set_port(self, port: int) -> None:
        """Fija los valores válidos de la cabecera Host una vez conocido el puerto."""
        self.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}

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
        }

    def search(self, query: dict[str, list[str]]) -> dict[str, Any]:
        """Búsqueda literal en título y texto."""
        term = _str_param(query, "q")
        with self.db() as conn:
            return {"items": _rows(search_text(conn, term))}

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
            return {
                "types": [{"type": t, "distinct": d, "total": n} for t, d, n in types],
                "items": _rows(ioc_values(conn, ioc_type, limit=limit)),
            }

    def related(self, query: dict[str, list[str]]) -> dict[str, Any]:
        """Páginas en las que aparece un IOC concreto."""
        value = _str_param(query, "value")
        with self.db() as conn:
            rows = pages_for_ioc(conn, candidate_normalizations(value))
        return {"value": value, "items": _rows(rows)}

    def duplicates(self) -> dict[str, Any]:
        """Grupos de URLs con contenido idéntico."""
        with self.db() as conn:
            return {"items": [asdict(g) for g in find_duplicates(conn)]}

    def export(self, query: dict[str, list[str]]) -> tuple[bytes, str, str]:
        """Genera la exportación en ``results/`` y devuelve (contenido, tipo, nombre)."""
        fmt = query.get("format", ["json"])[0]
        results = self.config.results_dir
        with self.db() as conn:
            if fmt == "json":
                path = export_json(conn, results / "results.json")
                return path.read_bytes(), "application/json; charset=utf-8", path.name
            if fmt == "csv":
                pages_csv, iocs_csv = export_csv(conn, results / "results.csv")
                path = iocs_csv if query.get("table", ["pages"])[0] == "iocs" else pages_csv
                return path.read_bytes(), "text/csv; charset=utf-8", path.name
        raise HttpError(HTTPStatus.BAD_REQUEST, "formato no soportado (json o csv)")

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
        return {"path": str(path), "url": "/report"}

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
        elif path == "/api/summary":
            self._json(app.summary())
        elif path == "/api/sources":
            self._json(app.sources())
        elif path == "/api/pages":
            self._json(app.pages(query))
        elif match := _PAGE_RE.match(path):
            self._json(app.page(int(match.group(1))))
        elif path == "/api/search":
            self._json(app.search(query))
        elif path == "/api/regex":
            self._json(app.regex(query))
        elif path == "/api/iocs":
            self._json(app.iocs(query))
        elif path == "/api/related":
            self._json(app.related(query))
        elif path == "/api/duplicates":
            self._json(app.duplicates())
        elif path == "/api/crawl":
            self._json(app.crawl_status())
        elif path == "/api/export":
            body, ctype, filename = app.export(query)
            self._send(
                HTTPStatus.OK,
                body,
                ctype,
                extra={"Content-Disposition": f'attachment; filename="{filename}"'},
            )
        else:
            raise HttpError(HTTPStatus.NOT_FOUND, "ruta no encontrada")

    def _route_post(self) -> None:
        path = urlsplit(self.path).path
        routes = {
            "/api/sources": self.app.add_source,
            "/api/tor-check": self.app.tor_check,
            "/api/crawl": self.app.start_crawl,
            "/api/report": lambda _body: self.app.generate_report(),
        }
        if path not in routes:
            raise HttpError(HTTPStatus.NOT_FOUND, "ruta no encontrada")
        body = self._read_json()
        status = HTTPStatus.ACCEPTED if path == "/api/crawl" else HTTPStatus.OK
        self._json(routes[path](body), status)


def make_server(config: Config, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    """Crea el servidor (sin arrancarlo). ``port=0`` elige un puerto libre."""
    if not is_loopback(host):
        raise ValueError("por seguridad la interfaz web solo puede escuchar en loopback")
    app = WebApp(config)
    handler = type("BoundHandler", (RequestHandler,), {"app": app})
    server_cls = ThreadingHTTPServer
    if ":" in host:  # IPv6 (::1)
        server_cls = type("Server6", (ThreadingHTTPServer,), {"address_family": socket.AF_INET6})
    server = server_cls((host.strip("[]"), port), handler)
    server.daemon_threads = True
    app.set_port(server.server_address[1])
    server.app = app  # type: ignore[attr-defined]
    return server
