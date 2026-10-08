"""Watchlist local: términos e IOCs que el investigador quiere vigilar.

Tras cada crawl, cada página guardada se compara con la watchlist. Se genera una
alerta por (vigilancia, página, versión del contenido): si la página no cambia,
no se repite la alerta; si cambia y sigue coincidiendo, se crea una nueva.
Todo ocurre sobre datos locales: no hay consultas externas.
"""

from __future__ import annotations

import sqlite3
import unicodedata

from .database import audit, utc_now
from .ioc import normalize_any

MIN_TERM_LEN = 3
MAX_VALUE_LEN = 500
KINDS = ("term", "ioc")


def fold(text: str) -> str:
    """Minúsculas y sin tildes, para comparar términos de forma tolerante."""
    decomposed = unicodedata.normalize("NFKD", text.casefold())
    return "".join(c for c in decomposed if not unicodedata.combining(c))


def normalize_watch(kind: str, value: str) -> str:
    """Forma normalizada con la que se compara una vigilancia."""
    value = value.strip()
    if kind not in KINDS:
        raise ValueError("tipo de vigilancia no válido (term o ioc)")
    if not value or len(value) > MAX_VALUE_LEN:
        raise ValueError(f"el valor debe tener entre 1 y {MAX_VALUE_LEN} caracteres")
    if kind == "term":
        if len(value) < MIN_TERM_LEN:
            raise ValueError(f"un término debe tener al menos {MIN_TERM_LEN} caracteres")
        return fold(value)
    return normalize_any(value)[1]


def add_watch(
    conn: sqlite3.Connection, kind: str, value: str, label: str | None = None
) -> tuple[int, int]:
    """Añade una vigilancia y la evalúa contra lo ya almacenado.

    Devuelve ``(id, alertas_generadas)``. Lanza ``ValueError`` si ya existe.
    """
    normalized = normalize_watch(kind, value)
    try:
        with conn:
            cur = conn.execute(
                """
                INSERT INTO watchlist (kind, value, normalized, label, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (kind, value.strip(), normalized, (label or "").strip()[:100] or None, utc_now()),
            )
    except sqlite3.IntegrityError as exc:
        raise ValueError("esa vigilancia ya existe") from exc
    watch_id = int(cur.lastrowid or 0)
    alerts = scan_all(conn, watch_id)
    audit(conn, "watch.add", watch_id=watch_id, kind=kind, value=value.strip(), alerts=alerts)
    return watch_id, alerts


def remove_watch(conn: sqlite3.Connection, watch_id: int) -> None:
    """Elimina una vigilancia y sus alertas."""
    with conn:
        cur = conn.execute("DELETE FROM watchlist WHERE id = ?", (watch_id,))
    if cur.rowcount == 0:
        raise ValueError("vigilancia no encontrada")
    audit(conn, "watch.remove", watch_id=watch_id)


def list_watches(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Vigilancias con su número de alertas totales y pendientes."""
    return conn.execute(
        """
        SELECT w.id, w.kind, w.value, w.normalized, w.label, w.created_at,
               COUNT(a.id) AS alerts,
               COALESCE(SUM(a.acknowledged = 0), 0) AS open_alerts
        FROM watchlist w LEFT JOIN alerts a ON a.watch_id = w.id
        GROUP BY w.id ORDER BY w.id
        """
    ).fetchall()


def _matches(watch: sqlite3.Row, folded_text: str, iocs: set[str]) -> bool:
    if watch["kind"] == "term":
        return watch["normalized"] in folded_text
    return watch["normalized"] in iocs


def scan_page(conn: sqlite3.Connection, page_id: int, watch_id: int | None = None) -> int:
    """Evalúa una página contra la watchlist (o una sola vigilancia). Devuelve alertas nuevas."""
    page = conn.execute(
        "SELECT id, title, text, content_hash FROM pages WHERE id = ?", (page_id,)
    ).fetchone()
    if page is None:
        return 0
    query, params = "SELECT * FROM watchlist", ()
    if watch_id is not None:
        query, params = "SELECT * FROM watchlist WHERE id = ?", (watch_id,)
    watches = conn.execute(query, params).fetchall()
    if not watches:
        return 0
    folded = fold(f"{page['title'] or ''}\n{page['text'] or ''}")
    iocs = {
        r[0]
        for r in conn.execute("SELECT normalized_value FROM iocs WHERE page_id = ?", (page_id,))
    }
    created = 0
    with conn:
        for watch in watches:
            if _matches(watch, folded, iocs):
                cur = conn.execute(
                    """
                    INSERT OR IGNORE INTO alerts (watch_id, page_id, content_hash, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (watch["id"], page_id, page["content_hash"] or "", utc_now()),
                )
                created += cur.rowcount
    return created


def scan_all(conn: sqlite3.Connection, watch_id: int | None = None) -> int:
    """Evalúa todas las páginas almacenadas. Devuelve el número de alertas nuevas."""
    ids = [r[0] for r in conn.execute("SELECT id FROM pages ORDER BY id")]
    return sum(scan_page(conn, page_id, watch_id) for page_id in ids)


def list_alerts(
    conn: sqlite3.Connection, include_acknowledged: bool = False, limit: int = 200
) -> list[sqlite3.Row]:
    """Alertas (por defecto solo las pendientes), de la más reciente a la más antigua."""
    where = "" if include_acknowledged else "WHERE a.acknowledged = 0"
    return conn.execute(
        f"""
        SELECT a.id, a.created_at, a.acknowledged, a.content_hash,
               w.id AS watch_id, w.kind, w.value, w.label,
               p.id AS page_id, p.url, p.title
        FROM alerts a
        JOIN watchlist w ON w.id = a.watch_id
        JOIN pages p ON p.id = a.page_id
        {where}
        ORDER BY a.id DESC LIMIT ?
        """,  # noqa: S608 - "where" es un literal fijo
        (limit,),
    ).fetchall()


def count_open_alerts(conn: sqlite3.Connection) -> int:
    """Número de alertas pendientes."""
    return int(conn.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged = 0").fetchone()[0])


def acknowledge_alerts(conn: sqlite3.Connection, alert_ids: list[int] | None = None) -> int:
    """Marca alertas como revisadas (todas si ``alert_ids`` es ``None``). Devuelve cuántas."""
    with conn:
        if alert_ids is None:
            cur = conn.execute("UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0")
        else:
            cur = conn.executemany(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ?", [(i,) for i in alert_ids]
            )
    if cur.rowcount:
        audit(conn, "alerts.ack", count=cur.rowcount)
    return cur.rowcount
