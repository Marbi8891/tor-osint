"""Validación de URLs .onion y carga de fuentes definidas por el investigador."""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

log = logging.getLogger(__name__)

_BASE32_RE = re.compile(r"[a-z2-7]+")
_DNS_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
V2_LEN = 16
V3_LEN = 56


def onion_version(label: str) -> int | None:
    """Devuelve 2 o 3 si ``label`` es una dirección onion válida, o ``None``.

    - v3 (56 caracteres): se verifica la versión (0x03) y el checksum SHA3-256
      según la especificación rend-spec-v3.
    - v2 (16 caracteres): solo se puede validar la sintaxis base32. Tor dejó de
      soportar v2 en 2021, por lo que no serán accesibles.
    """
    label = label.lower()
    if len(label) not in (V2_LEN, V3_LEN) or not _BASE32_RE.fullmatch(label):
        return None
    if len(label) == V2_LEN:
        return 2
    try:
        raw = base64.b32decode(label.upper())
    except binascii.Error:
        return None
    pubkey, checksum, version = raw[:32], raw[32:34], raw[34:]
    if version != b"\x03":
        return None
    expected = hashlib.sha3_256(b".onion checksum" + pubkey + version).digest()[:2]
    return 3 if checksum == expected else None


def onion_host_label(host: str) -> str | None:
    """Extrae la etiqueta onion de un host (admite subdominios: ``www.<id>.onion``)."""
    host = host.lower().rstrip(".")
    if not host.endswith(".onion"):
        return None
    labels = host[: -len(".onion")].split(".")
    if not labels or not all(_DNS_LABEL_RE.fullmatch(lab) for lab in labels):
        return None
    return labels[-1]


def is_valid_onion_url(url: str) -> bool:
    """Valida esquema http/https, dominio .onion, longitud y caracteres (y checksum v3)."""
    try:
        parts = urlsplit(url.strip())
        _ = parts.port  # lanza ValueError si el puerto es inválido
    except ValueError:
        return False
    if parts.scheme.lower() not in ("http", "https"):
        return False
    if parts.username is not None or parts.password is not None:
        return False  # nunca aceptamos credenciales embebidas en la URL
    label = onion_host_label(parts.hostname or "")
    return label is not None and onion_version(label) is not None


def normalize_onion_url(url: str) -> str:
    """Normaliza esquema y host a minúsculas y elimina el fragmento."""
    parts = urlsplit(url.strip())
    netloc = (parts.hostname or "").lower()
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


@dataclass(frozen=True)
class SourceLoadResult:
    """Fuentes válidas y líneas rechazadas (número de línea, contenido)."""

    valid: list[str]
    rejected: list[tuple[int, str]]


def parse_sources(lines: list[str]) -> SourceLoadResult:
    """Valida, normaliza y deduplica una lista de líneas de fuentes."""
    valid: list[str] = []
    rejected: list[tuple[int, str]] = []
    for lineno, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not is_valid_onion_url(line):
            rejected.append((lineno, line))
            continue
        url = normalize_onion_url(line)
        label = onion_host_label(urlsplit(url).hostname or "")
        if label and onion_version(label) == 2:
            log.warning("Línea %d: onion v2 obsoleta, probablemente inaccesible: %s", lineno, url)
        valid.append(url)
    return SourceLoadResult(list(dict.fromkeys(valid)), rejected)


def load_sources(path: Path) -> SourceLoadResult:
    """Carga ``path`` (una URL .onion por línea, ``#`` para comentarios)."""
    if not path.exists():
        log.warning("No existe el fichero de fuentes: %s", path)
        return SourceLoadResult([], [])
    result = parse_sources(path.read_text(encoding="utf-8").splitlines())
    for lineno, line in result.rejected:
        log.warning("Línea %d ignorada (no es una URL .onion válida): %s", lineno, line[:200])
    return result


def add_source(path: Path, url: str) -> str:
    """Añade ``url`` a ``path`` tras validarla. Devuelve la URL normalizada.

    Es la única forma de ampliar el alcance desde la CLI o la interfaz web, y
    siempre es una acción explícita del investigador. Lanza ``ValueError`` si la
    URL no es válida o ya está incluida.
    """
    url = url.strip()
    if not is_valid_onion_url(url):
        raise ValueError("no es una URL .onion válida")
    normalized = normalize_onion_url(url)
    if normalized in load_sources(path).valid:
        raise ValueError("la fuente ya está incluida")
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    prefix = "" if not existing or existing.endswith("\n") else "\n"
    with path.open("a", encoding="utf-8") as fh:
        fh.write(f"{prefix}{normalized}\n")
    log.info("Fuente añadida: %s", normalized)
    return normalized
