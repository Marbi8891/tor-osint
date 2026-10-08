"""Enriquecimiento offline de CVEs a partir de un fichero de NVD descargado a mano.

La herramienta nunca consulta NVD por su cuenta (no hay correlación externa
automática). El investigador descarga un JSON de la API 2.0 de NVD, por ejemplo:

    curl -o nvd.json "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"

y lo importa con ``tor-osint nvd-import nvd.json``. Admite ``.json`` y ``.json.gz``.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .database import audit, utc_now

MAX_FILE_BYTES = 1024 * 1024 * 1024  # 1 GiB descomprimido como máximo
MAX_DESCRIPTION = 2_000
# Preferencia de métricas: CVSS más reciente primero.
_METRICS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


@dataclass(frozen=True)
class ImportResult:
    """Resultado de una importación."""

    read: int
    imported: int
    skipped_unknown: int
    sha256: str


def _load(path: Path) -> dict[str, Any]:
    if path.suffix == ".gz":
        with gzip.open(path, "rb") as fh:
            raw = fh.read(MAX_FILE_BYTES + 1)  # límite frente a bombas de descompresión
    else:
        raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("fichero NVD demasiado grande (máx. 1 GiB)")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON inválido: {exc.msg}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("formato no reconocido: se espera la API 2.0 de NVD ('vulnerabilities')")
    return data


def _best_metric(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    for key in _METRICS:
        for metric in metrics.get(key) or []:
            cvss = metric.get("cvssData") or {}
            score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity") or metric.get("baseSeverity")
            if isinstance(score, (int, float)):
                return (
                    float(score),
                    (str(severity).upper() if severity else None),
                    cvss.get("version"),
                )
    return None, None, None


def parse_cve(item: dict[str, Any]) -> dict[str, Any] | None:
    """Extrae id, CVSS, severidad, descripción en inglés y fecha de una entrada NVD."""
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict) or not isinstance(cve.get("id"), str):
        return None
    cve_id = cve["id"].strip().upper()
    if not cve_id.startswith("CVE-"):
        return None
    description = next(
        (
            d.get("value", "")
            for d in cve.get("descriptions") or []
            if isinstance(d, dict) and d.get("lang") == "en"
        ),
        "",
    )
    score, severity, version = _best_metric(cve.get("metrics") or {})
    return {
        "cve_id": cve_id,
        "cvss_score": score,
        "severity": severity,
        "cvss_version": version,
        "description": str(description)[:MAX_DESCRIPTION],
        "published": cve.get("published"),
    }


def import_nvd(conn: sqlite3.Connection, path: Path, only_known: bool = True) -> ImportResult:
    """Importa CVEs de un JSON de NVD. Por defecto solo los que aparecen en la BD local."""
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    data = _load(path)
    known = {
        r[0] for r in conn.execute("SELECT DISTINCT normalized_value FROM iocs WHERE type='cve'")
    }
    rows, skipped = [], 0
    for item in data["vulnerabilities"]:
        parsed = parse_cve(item)
        if parsed is None:
            continue
        if only_known and parsed["cve_id"] not in known:
            skipped += 1
            continue
        rows.append(parsed)
    now = utc_now()
    with conn:
        conn.executemany(
            """
            INSERT INTO cve_info (cve_id, cvss_score, severity, cvss_version, description,
                                  published, imported_at)
            VALUES (:cve_id, :cvss_score, :severity, :cvss_version, :description, :published,
                    :imported_at)
            ON CONFLICT(cve_id) DO UPDATE SET
                cvss_score=excluded.cvss_score, severity=excluded.severity,
                cvss_version=excluded.cvss_version, description=excluded.description,
                published=excluded.published, imported_at=excluded.imported_at
            """,
            [{**r, "imported_at": now} for r in rows],
        )
    result = ImportResult(len(data["vulnerabilities"]), len(rows), skipped, digest)
    audit(
        conn,
        "nvd.import",
        file=path.name,
        sha256=digest,
        read=result.read,
        imported=result.imported,
        only_known=only_known,
    )
    return result


def cve_details(conn: sqlite3.Connection, cve_ids: list[str] | None = None) -> dict[str, dict]:
    """Información CVSS conocida, indexada por CVE (todas o las indicadas)."""
    if cve_ids is None:
        rows = conn.execute("SELECT * FROM cve_info").fetchall()
    else:
        ids = list(dict.fromkeys(c.upper() for c in cve_ids))
        if not ids:
            return {}
        marks = ",".join("?" * len(ids))
        rows = conn.execute(
            f"SELECT * FROM cve_info WHERE cve_id IN ({marks})",  # noqa: S608 - marcadores "?"
            ids,
        ).fetchall()
    return {row["cve_id"]: dict(row) for row in rows}
