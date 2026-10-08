"""Subcomandos de gestión de la investigación: historial, cambios, watchlist,
alertas, notas, etiquetas y auditoría.

Se registran desde ``cli.build_parser`` para que ``cli.py`` siga siendo legible.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from .changes import diff_latest, diff_snapshots, page_history, recent_changes
from .config import Config
from .database import audit_entries, connect
from .enrich import import_nvd
from .notes import (
    TARGET_TYPES,
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
    KINDS,
    acknowledge_alerts,
    add_watch,
    list_alerts,
    list_watches,
    remove_watch,
    scan_all,
)


def _db(config: Config) -> closing[sqlite3.Connection]:
    return closing(connect(config.database))


def register(sub: Any) -> None:
    """Añade los subcomandos de este módulo al parser principal."""
    p = sub.add_parser("history", help="historial de snapshots de una página")
    p.add_argument("page_id", type=int)

    p = sub.add_parser("diff", help="diferencias entre dos versiones de una página")
    p.add_argument("page_id", type=int)
    p.add_argument("--from", dest="old", type=int, help="snapshot antiguo (por defecto: penúltimo)")
    p.add_argument("--to", dest="new", type=int, help="snapshot nuevo (por defecto: último)")

    p = sub.add_parser("changes", help="páginas que cambiaron en su último crawl")
    p.add_argument("--limit", type=int, default=50)

    p = sub.add_parser("watch", help="watchlist: términos e IOCs a vigilar")
    wsub = p.add_subparsers(dest="watch_cmd", required=True, metavar="ACCIÓN")
    w = wsub.add_parser("add", help="vigila un término o un IOC")
    w.add_argument("kind", choices=KINDS, help="term (texto libre) o ioc (dominio, IP, CVE…)")
    w.add_argument("value")
    w.add_argument("--label", help="descripción corta")
    wsub.add_parser("list", help="lista las vigilancias")
    w = wsub.add_parser("rm", help="elimina una vigilancia y sus alertas")
    w.add_argument("watch_id", type=int)
    wsub.add_parser("scan", help="reevalúa toda la BD contra la watchlist")

    p = sub.add_parser("alerts", help="alertas de la watchlist")
    p.add_argument("--all", action="store_true", help="incluye las ya revisadas")
    p.add_argument(
        "--ack",
        nargs="*",
        type=int,
        metavar="ID",
        help="marca como revisadas las alertas indicadas (o todas si no se indica ninguna)",
    )

    p = sub.add_parser("note", help="notas sobre páginas o IOCs")
    nsub = p.add_subparsers(dest="note_cmd", required=True, metavar="ACCIÓN")
    n = nsub.add_parser("add", help="añade una nota")
    n.add_argument("target_type", choices=TARGET_TYPES)
    n.add_argument("target", help="id de página o valor del IOC")
    n.add_argument("text")
    n = nsub.add_parser("list", help="lista notas (todas o de un objetivo)")
    n.add_argument("target_type", nargs="?", choices=TARGET_TYPES)
    n.add_argument("target", nargs="?")
    n = nsub.add_parser("rm", help="elimina una nota")
    n.add_argument("note_id", type=int)

    p = sub.add_parser("tag", help="etiquetas sobre páginas o IOCs")
    tsub = p.add_subparsers(dest="tag_cmd", required=True, metavar="ACCIÓN")
    for action, help_text in (("add", "añade una etiqueta"), ("rm", "quita una etiqueta")):
        t = tsub.add_parser(action, help=help_text)
        t.add_argument("target_type", choices=TARGET_TYPES)
        t.add_argument("target", help="id de página o valor del IOC")
        t.add_argument("tag")
    t = tsub.add_parser("list", help="etiquetas en uso, o los objetivos de una etiqueta")
    t.add_argument("tag", nargs="?")
    t = tsub.add_parser("show", help="etiquetas de un objetivo")
    t.add_argument("target_type", choices=TARGET_TYPES)
    t.add_argument("target")

    p = sub.add_parser(
        "nvd-import", help="importa CVSS de un JSON de NVD (API 2.0) descargado a mano"
    )
    p.add_argument("file", type=Path, help="fichero .json o .json.gz")
    p.add_argument(
        "--all", action="store_true", help="importa todos los CVE, no solo los de la BD local"
    )

    p = sub.add_parser("audit", help="registro de auditoría (cadena de custodia)")
    p.add_argument("--limit", type=int, default=50)


# --- historial y cambios --------------------------------------------------------


def cmd_history(args: argparse.Namespace, config: Config) -> int:
    with _db(config) as conn:
        rows = page_history(conn, args.page_id)
    if not rows:
        print("Página sin historial o inexistente.")
        return 1
    previous_hash = None
    for row in reversed(rows):
        mark = "=" if row["content_hash"] == previous_hash else "*"
        previous_hash = row["content_hash"]
        raw = f" · raw {row['raw_sha256'][:12]}…" if row["raw_sha256"] else ""
        print(
            f"{mark} snapshot {row['id']:<5} {row['fetched_at']}  HTTP {row['status']}  "
            f"{row['content_hash'][:16]}…{raw}  {(row['title'] or '')[:50]}"
        )
    print("\n* = contenido distinto del snapshot anterior · = = sin cambios")
    return 0


def _print_ioc_delta(label: str, delta: dict[str, list[str]]) -> None:
    for ioc_type, values in delta.items():
        for value in values:
            print(f"    {label} {ioc_type:<7} {value}")


def cmd_diff(args: argparse.Namespace, config: Config) -> int:
    with _db(config) as conn:
        if args.old and args.new:
            diff = diff_snapshots(conn, args.old, args.new)
        elif args.old or args.new:
            raise ValueError("indica --from y --to a la vez, o ninguno")
        else:
            diff = diff_latest(conn, args.page_id)
    if diff is None:
        print("La página solo tiene un snapshot: no hay nada que comparar.")
        return 0
    if diff.page_id != args.page_id:
        raise ValueError("los snapshots no pertenecen a esa página")
    print(f"Página {diff.page_id}: snapshot {diff.old_id} ({diff.old_fetched_at})")
    print(f"           → snapshot {diff.new_id} ({diff.new_fetched_at})\n")
    if not diff.changed:
        print("Sin cambios.")
        return 0
    if diff.status:
        print(f"HTTP: {diff.status[0]} → {diff.status[1]}")
    if diff.title:
        print(f"Título: {diff.title[0]!r} → {diff.title[1]!r}")
    if diff.content_changed:
        print(f"Contenido: similitud {diff.similarity:.0%}")
        for fragment in diff.removed:
            print(f"  - {fragment}")
        for fragment in diff.added:
            print(f"  + {fragment}")
        if diff.truncated:
            print("  (diff limitado a las primeras palabras de cada versión)")
    if diff.iocs_added or diff.iocs_removed:
        print("IOCs:")
        _print_ioc_delta("+", diff.iocs_added)
        _print_ioc_delta("-", diff.iocs_removed)
    return 0


def cmd_changes(args: argparse.Namespace, config: Config) -> int:
    with _db(config) as conn:
        changes = recent_changes(conn, args.limit)
    for change in changes:
        print(f"\n[{change['page_id']}] {change['title'] or '(sin título)'}")
        print(f"    {change['url']}")
        print(f"    {change['fetched_at']} · cambios: {', '.join(change['kinds'])}")
        for ioc_type, values in change["iocs_added"].items():
            print(f"    + {ioc_type}: {', '.join(values[:5])}")
    print(f"\nPáginas con cambios en su último crawl: {len(changes)}")
    if changes:
        print("Detalle: tor-osint diff <page_id>")
    return 0


# --- watchlist y alertas ---------------------------------------------------------


def cmd_watch(args: argparse.Namespace, config: Config) -> int:
    with _db(config) as conn:
        if args.watch_cmd == "add":
            watch_id, alerts = add_watch(conn, args.kind, args.value, args.label)
            print(f"[+] Vigilancia {watch_id} añadida · {alerts} coincidencia(s) en la BD actual")
        elif args.watch_cmd == "rm":
            remove_watch(conn, args.watch_id)
            print(f"[+] Vigilancia {args.watch_id} eliminada")
        elif args.watch_cmd == "scan":
            print(f"[+] Alertas nuevas: {scan_all(conn)}")
        else:
            rows = list_watches(conn)
            for row in rows:
                label = f"  ({row['label']})" if row["label"] else ""
                print(
                    f"[{row['id']}] {row['kind']:<4} {row['value']}{label}  · "
                    f"{row['open_alerts']} pendiente(s) / {row['alerts']} total"
                )
            print(f"\nVigilancias: {len(rows)}")
    return 0


def cmd_alerts(args: argparse.Namespace, config: Config) -> int:
    with _db(config) as conn:
        if args.ack is not None:
            count = acknowledge_alerts(conn, args.ack or None)
            print(f"[+] Alertas marcadas como revisadas: {count}")
            return 0
        rows = list_alerts(conn, include_acknowledged=args.all)
    for row in rows:
        state = "✓" if row["acknowledged"] else "!"
        print(f"\n{state} alerta {row['id']} · {row['created_at']}")
        print(f"    vigilancia {row['watch_id']} ({row['kind']}): {row['value']}")
        print(f"    [{row['page_id']}] {row['title'] or '(sin título)'} · {row['url']}")
    print(f"\nAlertas{' (todas)' if args.all else ' pendientes'}: {len(rows)}")
    if rows and not args.all:
        print("Marcar como revisadas: tor-osint alerts --ack [ID ...]")
    return 0


# --- notas y etiquetas -------------------------------------------------------------


def cmd_note(args: argparse.Namespace, config: Config) -> int:
    with _db(config) as conn:
        if args.note_cmd == "add":
            note_id = add_note(conn, args.target_type, args.target, args.text)
            print(f"[+] Nota {note_id} añadida")
            return 0
        if args.note_cmd == "rm":
            delete_note(conn, args.note_id)
            print(f"[+] Nota {args.note_id} eliminada")
            return 0
        if bool(args.target_type) != bool(args.target):
            raise ValueError("indica tipo y objetivo a la vez (p. ej.: note list page 3)")
        rows = list_notes(conn, args.target_type, args.target)
    for row in rows:
        print(f"\n[{row['id']}] {row['target_type']} {row['target']} · {row['created_at']}")
        for line in row["body"].splitlines():
            print(f"    {line}")
    print(f"\nNotas: {len(rows)}")
    return 0


def cmd_tag(args: argparse.Namespace, config: Config) -> int:
    with _db(config) as conn:
        if args.tag_cmd == "add":
            tag = add_tag(conn, args.target_type, args.target, args.tag)
            print(f"[+] Etiqueta '{tag}' añadida")
        elif args.tag_cmd == "rm":
            remove_tag(conn, args.target_type, args.target, args.tag)
            print(f"[+] Etiqueta '{args.tag}' eliminada")
        elif args.tag_cmd == "show":
            tags = tags_for(conn, args.target_type, args.target)
            print(", ".join(tags) if tags else "Sin etiquetas.")
        elif args.tag:
            rows = targets_with_tag(conn, args.tag)
            for row in rows:
                extra = f"  {row['url']}" if row["url"] else ""
                print(f"{row['target_type']:<4} {row['target']}{extra}")
            print(f"\nObjetivos con '{args.tag}': {len(rows)}")
        else:
            counts = tag_counts(conn)
            for tag, count in counts:
                print(f"{tag:<30} {count}")
            if not counts:
                print("Sin etiquetas.")
    return 0


def cmd_audit(args: argparse.Namespace, config: Config) -> int:
    with _db(config) as conn:
        rows = audit_entries(conn, args.limit)
    for row in reversed(rows):
        details = json.loads(row["details_json"])
        summary = " ".join(f"{k}={v}" for k, v in details.items())
        print(f"{row['at']}  {row['actor']:<12} {row['action']:<14} {summary}")
    print(f"\nEntradas: {len(rows)}")
    return 0


def cmd_nvd_import(args: argparse.Namespace, config: Config) -> int:
    if not args.file.is_file():
        raise ValueError(f"no existe el fichero {args.file}")
    with _db(config) as conn:
        result = import_nvd(conn, args.file, only_known=not args.all)
    print(f"[+] Entradas leídas: {result.read} · CVE importados: {result.imported}")
    if result.skipped_unknown:
        print(f"[i] {result.skipped_unknown} CVE ignorados por no aparecer en la BD (usa --all)")
    print(f"[i] SHA-256 del fichero: {result.sha256}")
    return 0


COMMANDS = {
    "history": cmd_history,
    "diff": cmd_diff,
    "changes": cmd_changes,
    "watch": cmd_watch,
    "alerts": cmd_alerts,
    "note": cmd_note,
    "tag": cmd_tag,
    "audit": cmd_audit,
    "nvd-import": cmd_nvd_import,
}
