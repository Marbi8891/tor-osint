"""Interfaz de línea de comandos de tor-osint."""

from __future__ import annotations

import argparse
import logging
import sqlite3
import sys
import webbrowser
from collections.abc import Sequence
from contextlib import closing
from pathlib import Path

from . import __version__, cli_case
from .config import Config, ConfigError, load_config
from .crawler import crawl
from .database import (
    connect,
    discovered_onions,
    has_fts,
    ioc_type_counts,
    ioc_values,
    pages_for_ioc,
)
from .dedup import DEFAULT_NEAR_DISTANCE, find_duplicates, find_near_duplicates
from .export import export_csv, export_json
from .ioc import CLI_IOC_TYPES, candidate_normalizations
from .report import write_report
from .search import HL_END, HL_START, regex_search, search_fts, search_text
from .sources import add_source, is_valid_onion_url, load_sources, normalize_onion_url
from .tor import TorClient

log = logging.getLogger("tor_osint")

EPILOG = """\
ejemplos:
  tor-osint tor-check
  tor-osint crawl
  tor-osint crawl --url http://<id-v3>.onion/
  tor-osint search "empresa"
  tor-osint regex "CVE-202[0-9]-[0-9]+"
  tor-osint iocs --type domain
  tor-osint related CVE-2024-1234
  tor-osint duplicates
  tor-osint export --format csv
  tor-osint report --output results/report.html
  tor-osint web --open

variables de entorno: TOR_SOCKS, TOR_TIMEOUT, TOR_DELAY, TOR_MAX_BYTES, TOR_MAX_URLS
(las opciones de la CLI tienen prioridad sobre el entorno).
"""


def build_parser() -> argparse.ArgumentParser:
    """Construye el parser de argumentos con todos los subcomandos."""
    parser = argparse.ArgumentParser(
        prog="tor-osint",
        description=(
            "Plataforma local de investigación OSINT sobre fuentes .onion definidas "
            "explícitamente por el investigador, consultadas a través de Tor (SOCKS5h)."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="más detalle en los logs (-vv para debug)",
    )
    parser.add_argument("--data-dir", type=Path, help="directorio de datos (por defecto: data)")
    parser.add_argument(
        "--db", type=Path, help="ruta de la BD SQLite (por defecto: data/results.db)"
    )
    parser.add_argument(
        "--sources", type=Path, help="fichero de fuentes (por defecto: data/sources.txt)"
    )
    parser.add_argument(
        "--results-dir", type=Path, help="directorio de resultados (por defecto: results)"
    )

    net = argparse.ArgumentParser(add_help=False)
    group = net.add_argument_group("red / Tor")
    group.add_argument("--socks", help="proxy SOCKS de Tor host:puerto (TOR_SOCKS)")
    group.add_argument("--timeout", type=int, help="timeout por petición en segundos (TOR_TIMEOUT)")
    group.add_argument(
        "--delay", type=float, help="segundos mínimos entre peticiones (TOR_DELAY, mín. 0.5)"
    )
    group.add_argument(
        "--max-bytes", type=int, help="tamaño máximo de respuesta en bytes (TOR_MAX_BYTES)"
    )

    sub = parser.add_subparsers(dest="command", required=True, metavar="COMANDO")

    p = sub.add_parser(
        "tor-check",
        parents=[net],
        help="comprueba que el tráfico sale por Tor (check.torproject.org)",
    )
    p.add_argument(
        "--show-ip", action="store_true", help="muestra la IP de salida de Tor (oculta por defecto)"
    )

    p = sub.add_parser(
        "crawl", parents=[net], help="consulta las fuentes (una vez cada una, sin recursión)"
    )
    p.add_argument(
        "--url",
        action="append",
        default=[],
        metavar="URL",
        help="consulta solo esta URL .onion (repetible); ignora sources.txt",
    )
    p.add_argument("--max-urls", type=int, help="máximo de URLs por ejecución (TOR_MAX_URLS)")
    p.add_argument(
        "--save-raw",
        action="store_true",
        help="guarda también el HTML original comprimido en data/raw (SIN redactar)",
    )

    p = sub.add_parser("sources", help="valida las fuentes y lista enlaces .onion descubiertos")
    p.add_argument("--add", metavar="URL", help="añade una URL .onion válida a las fuentes")
    p.add_argument(
        "--discovered",
        action="store_true",
        help="lista .onion vistas en páginas que NO están en las fuentes",
    )

    p = sub.add_parser("search", help="búsqueda de texto completo (FTS5) en títulos y textos")
    p.add_argument("term")
    p.add_argument(
        "--substring",
        action="store_true",
        help="búsqueda literal de subcadena (LIKE) en lugar de FTS5",
    )

    p = sub.add_parser("regex", help="busca una expresión regular en el contenido local")
    p.add_argument("pattern")
    p.add_argument("--max-matches", type=int, default=20, help="coincidencias por página")

    p = sub.add_parser("iocs", help="estadísticas y listado de IOCs")
    p.add_argument("--type", choices=CLI_IOC_TYPES, help="filtra por tipo (hash = md5+sha1+sha256)")
    p.add_argument("--limit", type=int, default=50, help="máximo de valores a listar")

    p = sub.add_parser("related", help="páginas en las que aparece un IOC concreto")
    p.add_argument("value", help="email, dominio, IP, hash, CVE o URL")

    p = sub.add_parser("duplicates", help="grupos de URLs con el mismo contenido (SHA-256)")
    p.add_argument(
        "--near", action="store_true", help="casi duplicados por SimHash (mirrors con cambios)"
    )
    p.add_argument(
        "--distance",
        type=int,
        default=DEFAULT_NEAR_DISTANCE,
        help=f"bits de diferencia máximos para --near (por defecto {DEFAULT_NEAR_DISTANCE})",
    )

    p = sub.add_parser("export", help="exporta páginas e IOCs")
    p.add_argument("--format", choices=["json", "csv"], default="json")
    p.add_argument(
        "--output", type=Path, help="fichero de salida (por defecto: results/results.<formato>)"
    )

    p = sub.add_parser("web", parents=[net], help="abre la interfaz web local (solo 127.0.0.1)")
    p.add_argument("--host", default="127.0.0.1", help="loopback: 127.0.0.1, localhost o ::1")
    p.add_argument("--port", type=int, default=8765, help="puerto (por defecto: 8765)")
    p.add_argument("--open", action="store_true", help="abre el navegador automáticamente")
    p.add_argument("--max-urls", type=int, help="máximo de URLs por crawl (TOR_MAX_URLS)")

    p = sub.add_parser("report", help="genera un informe HTML local")
    p.add_argument("--output", type=Path, help="por defecto: results/report.html")

    cli_case.register(sub)
    return parser


def setup_logging(verbosity: int) -> None:
    """Configura logging a stderr; stdout queda para los resultados."""
    level = logging.WARNING if verbosity == 0 else logging.INFO if verbosity == 1 else logging.DEBUG
    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s", stream=sys.stderr)


def make_config(args: argparse.Namespace) -> Config:
    """Combina entorno y opciones de la CLI (la CLI tiene prioridad)."""
    return load_config().with_overrides(
        socks=getattr(args, "socks", None),
        timeout=getattr(args, "timeout", None),
        delay=getattr(args, "delay", None),
        max_bytes=getattr(args, "max_bytes", None),
        max_urls=getattr(args, "max_urls", None),
        data_dir=args.data_dir,
        results_dir=args.results_dir,
        db_path=args.db,
        sources_path=args.sources,
    )


# --- comandos ---------------------------------------------------------------


def cmd_tor_check(args: argparse.Namespace, config: Config) -> int:
    status = TorClient(config).check_tor()
    if status.error:
        print(
            f"[!] No se pudo contactar con check.torproject.org vía {config.socks}: {status.error}"
        )
        print("[i] Comprueba el servicio: sudo systemctl status tor")
        return 1
    print(f"[+] IsTor: {status.is_tor}")
    if args.show_ip:
        print(f"[+] IP de salida: {status.ip}")
    return 0 if status.is_tor else 1


def cmd_crawl(args: argparse.Namespace, config: Config) -> int:
    if args.url:
        invalid = [u for u in args.url if not is_valid_onion_url(u)]
        if invalid:
            for url in invalid:
                print(f"[!] URL .onion no válida: {url}")
            return 2
        sources = list(dict.fromkeys(normalize_onion_url(u) for u in args.url))
    else:
        sources = load_sources(config.sources).valid
    if not sources:
        print(f"[!] No hay fuentes válidas en {config.sources}")
        return 1

    raw_dir = config.raw_dir if args.save_raw else None
    if raw_dir:
        print(f"[!] Se guardará el HTML original SIN redactar en {raw_dir} (permisos 0600)")
    with _db(config) as conn:
        summary = crawl(sources, TorClient(config), conn, config.max_urls, raw_dir=raw_dir)

    new = set(summary.new)
    changed = dict(summary.changed)
    for url in summary.stored:
        if url in new:
            print(f"[+] {url}  (nueva)")
        elif url in changed:
            print(f"[~] {url}  (cambios: {', '.join(changed[url])})")
        else:
            print(f"[=] {url}  (sin cambios)")
    for url, reason in summary.failed:
        print(f"[!] {url}: {reason}")
    if summary.skipped:
        print(f"[i] {len(summary.skipped)} fuentes omitidas por --max-urls")
    print(
        f"\nGuardadas: {len(summary.stored)} · Nuevas: {len(summary.new)} · "
        f"Con cambios: {len(summary.changed)} · Fallidas: {len(summary.failed)}"
    )
    if summary.alerts:
        print(f"[!] {summary.alerts} alerta(s) nuevas de la watchlist: tor-osint alerts")
    print(f"BD: {config.database}")
    return 0 if summary.stored or not summary.failed else 1


def cmd_sources(args: argparse.Namespace, config: Config) -> int:
    if args.add:
        print(f"[+] Fuente añadida: {add_source(config.sources, args.add)}")
        return 0
    result = load_sources(config.sources)
    if not args.discovered:
        for url in result.valid:
            print(f"[ok] {url}")
        for lineno, line in result.rejected:
            print(f"[x] línea {lineno}: {line}")
        print(f"\nVálidas: {len(result.valid)} · Rechazadas: {len(result.rejected)}")
        return 0

    with _db(config) as conn:
        discovered = discovered_onions(conn, result.valid)
    for row in discovered:
        print(f"{row['value']}  (en {row['pages']} página/s)")
    print(f"\n{len(discovered)} .onion descubiertas no incluidas en {config.sources}.")
    print("No se consultan automáticamente: añádelas a mano si procede.")
    return 0


def cmd_search(args: argparse.Namespace, config: Config) -> int:
    with _db(config) as conn:
        use_fts = not args.substring and has_fts(conn)
        rows = search_fts(conn, args.term) if use_fts else search_text(conn, args.term)
    for row in rows:
        print(f"\n[{row['id']}] {row['title'] or '(sin título)'}")
        print(f"    {row['url']}")
        print(f"    HTTP: {row['status']} · Fecha: {row['fetched_at']}")
        if use_fts and row["snippet"]:
            snippet = row["snippet"].replace(HL_START, "[").replace(HL_END, "]")
            print(f"    … {snippet}")
        print(f"    SHA-256: {row['content_hash']}")
    print(f"\nResultados: {len(rows)}")
    return 0


def cmd_regex(args: argparse.Namespace, config: Config) -> int:
    with _db(config) as conn:
        hits = regex_search(conn, args.pattern, args.max_matches)
    for hit in hits:
        print(f"\n[{hit.page_id}] {hit.title or '(sin título)'}")
        print(f"    {hit.url}")
        for match in hit.matches:
            print(f"      - {match}")
    print(f"\nPáginas con coincidencias: {len(hits)}")
    return 0


def cmd_iocs(args: argparse.Namespace, config: Config) -> int:
    with _db(config) as conn:
        if args.type is None:
            counts = ioc_type_counts(conn)
            print(f"{'TIPO':<10} {'DISTINTOS':>10} {'APARICIONES':>12}")
            for ioc_type, distinct, total in counts:
                print(f"{ioc_type:<10} {distinct:>10} {total:>12}")
            if not counts:
                print("Sin IOCs almacenados.")
            return 0
        rows = ioc_values(conn, args.type, limit=args.limit)
    for row in rows:
        print(f"{row['type']:<7} {row['pages']:>4} pág.  {row['value']}  (últ. {row['last_seen']})")
    print(f"\nValores listados: {len(rows)} (límite {args.limit})")
    return 0


def cmd_related(args: argparse.Namespace, config: Config) -> int:
    with _db(config) as conn:
        rows = pages_for_ioc(conn, candidate_normalizations(args.value))
    if not rows:
        print("Sin coincidencias en la base de datos local.")
        return 0
    for row in rows:
        print(f"\n[{row['page_id']}] ({row['type']}) {row['title'] or '(sin título)'}")
        print(f"    {row['url']}")
        print(f"    visto: {row['first_seen']} → {row['last_seen']} · HTTP {row['status']}")
    print(f"\nPáginas relacionadas: {len({r['page_id'] for r in rows})}")
    return 0


def cmd_duplicates(args: argparse.Namespace, config: Config) -> int:
    if args.near:
        with _db(config) as conn:
            near = find_near_duplicates(conn, args.distance)
        for group in near:
            print(f"\nGrupo de {len(group.pages)} páginas (hasta {group.max_distance} bits)")
            for page in group.pages:
                print(f"    [{page['id']}] {page['url']}  {str(page['title'])[:60]}")
        print(f"\nGrupos de casi duplicados: {len(near)} (distancia ≤ {args.distance})")
        return 0
    with _db(config) as conn:
        groups = find_duplicates(conn)
    for group in groups:
        print(f"\nSHA-256 {group.content_hash} ({len(group.urls)} URLs)")
        for url, title in zip(group.urls, group.titles, strict=True):
            print(f"    {url}  {title[:60]}")
    print(f"\nGrupos de contenido duplicado: {len(groups)}")
    return 0


def cmd_export(args: argparse.Namespace, config: Config) -> int:
    output = args.output or config.results_dir / f"results.{args.format}"
    with _db(config) as conn:
        if args.format == "json":
            print(f"[+] {export_json(conn, output)}")
        else:
            for path in export_csv(conn, output):
                print(f"[+] {path}")
    return 0


def cmd_report(args: argparse.Namespace, config: Config) -> int:
    output = args.output or config.results_dir / "report.html"
    source_count = len(load_sources(config.sources).valid)
    with _db(config) as conn:
        path = write_report(conn, output, source_count)
    print(f"[+] Informe generado: {path}")
    return 0


def _db(config: Config) -> closing[sqlite3.Connection]:
    """Abre la BD y garantiza su cierre al salir del bloque ``with``."""
    return closing(connect(config.database))


def cmd_web(args: argparse.Namespace, config: Config) -> int:
    from .web import make_server  # import diferido: la CLI no necesita el servidor

    server = make_server(config, args.host, args.port)
    host = f"[{args.host}]" if ":" in args.host else args.host
    url = f"http://{host}:{server.server_address[1]}/"
    print(f"[+] Interfaz web en {url}  (Ctrl+C para salir)")
    print("[i] Solo accesible desde esta máquina.")
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


COMMANDS = {
    "tor-check": cmd_tor_check,
    "crawl": cmd_crawl,
    "sources": cmd_sources,
    "search": cmd_search,
    "regex": cmd_regex,
    "iocs": cmd_iocs,
    "related": cmd_related,
    "duplicates": cmd_duplicates,
    "export": cmd_export,
    "report": cmd_report,
    "web": cmd_web,
    **cli_case.COMMANDS,
}


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada: devuelve el código de salida."""
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)
    try:
        config = make_config(args)
        return COMMANDS[args.command](args, config)
    except (ConfigError, ValueError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    except sqlite3.Error as exc:
        print(f"[!] Error de base de datos: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Interrumpido por el usuario", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
