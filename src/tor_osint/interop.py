"""Exportación a formatos de intercambio de inteligencia de amenazas: STIX 2.1 y MISP.

Se generan sin dependencias. La conformidad se comprueba en los tests con la
librería oficial ``stix2`` (OASIS), instalada solo como dependencia de desarrollo.

Tipos sin representación estándar:
- STIX 2.1 no tiene objetos núcleo para carteras de criptomonedas ni huellas PGP:
  se omiten (se informa del recuento).
- En MISP, ETH, ATT&CK y PGP se exportan como ``text`` con un comentario.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .database import ioc_values

# --- STIX 2.1 -------------------------------------------------------------------

_STIX_PATTERNS = {
    "email": "email-addr:value",
    "domain": "domain-name:value",
    "url": "url:value",
    "onion": "url:value",
    "ipv4": "ipv4-addr:value",
    "md5": "file:hashes.MD5",
    "sha1": "file:hashes.'SHA-1'",
    "sha256": "file:hashes.'SHA-256'",
}
STIX_UNSUPPORTED = ("btc", "eth", "pgp")


def stix_timestamp(value: str | None = None) -> str:
    """Marca de tiempo en el formato de STIX (UTC con milisegundos y sufijo ``Z``)."""
    moment = datetime.fromisoformat(value) if value else datetime.now(timezone.utc)
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _stix_id(object_type: str) -> str:
    return f"{object_type}--{uuid.uuid4()}"


def _escape_pattern(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def build_stix_bundle(conn: sqlite3.Connection, now: str | None = None) -> tuple[dict, int]:
    """Bundle STIX 2.1 con identidad, indicadores, vulnerabilidades, técnicas ATT&CK y un
    ``report`` que los agrupa. Devuelve ``(bundle, omitidos)``."""
    created = stix_timestamp(now)
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": _stix_id("identity"),
        "created": created,
        "modified": created,
        "name": f"tor-osint {__version__}",
        "identity_class": "system",
    }
    common = {"spec_version": "2.1", "created": created, "modified": created}
    objects: list[dict[str, Any]] = []
    skipped = 0

    for row in ioc_values(conn):
        ioc_type, value = row["type"], row["value"]
        description = (
            f"Visto en {row['pages']} página(s) entre {row['first_seen']} y {row['last_seen']}."
        )
        if ioc_type in _STIX_PATTERNS:
            objects.append(
                {
                    "type": "indicator",
                    "id": _stix_id("indicator"),
                    **common,
                    "created_by_ref": identity["id"],
                    "name": f"{ioc_type}: {value}"[:250],
                    "description": description,
                    "indicator_types": ["unknown"],
                    "pattern": f"[{_STIX_PATTERNS[ioc_type]} = '{_escape_pattern(value)}']",
                    "pattern_type": "stix",
                    "valid_from": stix_timestamp(row["first_seen"]),
                    "labels": [f"tor-osint:{ioc_type}"],
                }
            )
        elif ioc_type == "cve":
            objects.append(
                {
                    "type": "vulnerability",
                    "id": _stix_id("vulnerability"),
                    **common,
                    "created_by_ref": identity["id"],
                    "name": value,
                    "description": description,
                    "external_references": [{"source_name": "cve", "external_id": value}],
                }
            )
        elif ioc_type == "attack":
            objects.append(
                {
                    "type": "attack-pattern",
                    "id": _stix_id("attack-pattern"),
                    **common,
                    "created_by_ref": identity["id"],
                    "name": value,
                    "description": description,
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": value,
                            "url": "https://attack.mitre.org/"
                            + ("tactics/" if value.startswith("TA") else "techniques/")
                            + value.replace(".", "/"),
                        }
                    ],
                }
            )
        else:
            skipped += 1

    report: dict[str, Any] = {
        "type": "report",
        "id": _stix_id("report"),
        **common,
        "created_by_ref": identity["id"],
        "name": "tor-osint: indicadores recopilados",
        "description": "Exportación local de tor-osint. Fuentes .onion definidas por el analista.",
        "report_types": ["threat-report"],
        "published": created,
        "object_refs": [identity["id"]] + [o["id"] for o in objects],
    }
    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "objects": [identity, *objects, report],
    }
    return bundle, skipped


def export_stix(conn: sqlite3.Connection, output: Path) -> tuple[Path, int]:
    """Escribe el bundle STIX 2.1. Devuelve (ruta, IOCs omitidos por no ser representables)."""
    bundle, skipped = build_stix_bundle(conn)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
    return output, skipped


# --- MISP -----------------------------------------------------------------------------

# (tipo MISP, categoría MISP, to_ids, comentario)
_MISP_TYPES: dict[str, tuple[str, str, bool, str]] = {
    "email": ("email", "Network activity", False, ""),
    "domain": ("domain", "Network activity", True, ""),
    "url": ("url", "Network activity", True, ""),
    "onion": ("url", "Network activity", True, "Servicio onion"),
    "ipv4": ("ip-dst", "Network activity", True, ""),
    "md5": ("md5", "Payload delivery", True, ""),
    "sha1": ("sha1", "Payload delivery", True, ""),
    "sha256": ("sha256", "Payload delivery", True, ""),
    "cve": ("vulnerability", "External analysis", False, ""),
    "btc": ("btc", "Financial fraud", False, ""),
    "eth": ("text", "Financial fraud", False, "Dirección Ethereum"),
    "attack": ("text", "External analysis", False, "MITRE ATT&CK"),
    "pgp": ("text", "Other", False, "Huella OpenPGP"),
}


def build_misp_event(conn: sqlite3.Connection, now: datetime | None = None) -> dict[str, Any]:
    """Evento MISP (formato JSON de importación) con un atributo por IOC distinto."""
    now = now or datetime.now(timezone.utc)
    timestamp = str(int(now.timestamp()))
    attributes = []
    for row in ioc_values(conn):
        misp_type, category, to_ids, comment = _MISP_TYPES[row["type"]]
        note = f"Visto en {row['pages']} página(s) · {row['first_seen']} → {row['last_seen']}"
        attributes.append(
            {
                "uuid": str(uuid.uuid4()),
                "type": misp_type,
                "category": category,
                "value": row["value"],
                "to_ids": to_ids,
                "comment": f"{comment} · {note}" if comment else note,
                "timestamp": timestamp,
                "distribution": "5",  # hereda la distribución del evento
            }
        )
    return {
        "Event": {
            "uuid": str(uuid.uuid4()),
            "info": f"tor-osint {__version__}: indicadores de fuentes .onion",
            "date": now.date().isoformat(),
            "timestamp": timestamp,
            "threat_level_id": "4",  # sin definir
            "analysis": "0",  # inicial
            "distribution": "0",  # solo tu organización
            "published": False,
            "Tag": [{"name": "tlp:amber"}],
            "Attribute": attributes,
        }
    }


def export_misp(conn: sqlite3.Connection, output: Path) -> Path:
    """Escribe el evento MISP en JSON."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(build_misp_event(conn), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return output
