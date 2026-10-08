"""Cadena de custodia de las evidencias generadas (exportaciones e informes).

Cada fichero que produce la herramienta se registra en ``results/manifest.json``
con su SHA-256, tamaño, fecha, usuario y versión, y en el ``audit_log`` de la BD.
``tor-osint verify`` recalcula los hashes para detectar ficheros modificados o
eliminados después de generarse.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .database import audit, current_actor, utc_now

MANIFEST_NAME = "manifest.json"


def sha256_file(path: Path) -> str:
    """SHA-256 de un fichero, leído por bloques."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_manifest(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"generator": "tor-osint", "entries": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"manifiesto corrupto: {path}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        raise ValueError(f"manifiesto con formato inesperado: {path}")
    return data


def record_artifact(
    conn: sqlite3.Connection, path: Path, kind: str, manifest_dir: Path | None = None
) -> dict[str, Any]:
    """Registra ``path`` en el manifiesto (de su directorio por defecto) y en la auditoría."""
    manifest_path = (manifest_dir or path.parent) / MANIFEST_NAME
    manifest = _load_manifest(manifest_path)
    try:
        name = str(path.resolve().relative_to(manifest_path.parent.resolve()))
    except ValueError:
        name = str(path.resolve())
    entry = {
        "file": name,
        "kind": kind,
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
        "created_at": utc_now(),
        "actor": current_actor(),
        "tool_version": __version__,
    }
    manifest["entries"].append(entry)
    tmp = manifest_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, manifest_path)
    audit(conn, f"artifact.{kind}", file=name, sha256=entry["sha256"], bytes=entry["bytes"])
    return entry


@dataclass(frozen=True)
class VerifyResult:
    """Estado de cada fichero del manifiesto (última versión registrada de cada uno)."""

    ok: list[str]
    modified: list[str]
    missing: list[str]

    @property
    def passed(self) -> bool:
        """``True`` si todos los ficheros existen y coinciden con su hash."""
        return not self.modified and not self.missing


def verify_manifest(manifest_dir: Path) -> VerifyResult:
    """Comprueba los ficheros registrados en ``manifest_dir/manifest.json``."""
    manifest_path = manifest_dir / MANIFEST_NAME
    if not manifest_path.exists():
        raise ValueError(f"no existe el manifiesto {manifest_path}")
    latest: dict[str, dict[str, Any]] = {}
    for entry in _load_manifest(manifest_path)["entries"]:
        latest[entry["file"]] = entry  # un fichero regenerado sustituye a su versión anterior
    ok, modified, missing = [], [], []
    for name, entry in sorted(latest.items()):
        path = Path(name) if Path(name).is_absolute() else manifest_dir / name
        if not path.exists():
            missing.append(name)
        elif sha256_file(path) != entry["sha256"]:
            modified.append(name)
        else:
            ok.append(name)
    return VerifyResult(ok, modified, missing)
