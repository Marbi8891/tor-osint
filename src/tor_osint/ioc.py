"""Extracción y normalización de indicadores de compromiso (IOCs).

Las expresiones regulares son heurísticas: se priorizan pocos falsos positivos
evidentes (nombres de fichero, versiones, partes locales de emails) frente a
una cobertura exhaustiva.
"""

from __future__ import annotations

import ipaddress
import re
from contextlib import suppress
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from .sources import is_valid_onion_url, normalize_onion_url

IOC_TYPES = ("email", "domain", "url", "ipv4", "md5", "sha1", "sha256", "cve", "onion")
CLI_IOC_TYPES = (*IOC_TYPES, "hash")

# Extensiones de fichero que suelen confundirse con TLDs (index.html, Node.js, logo@2x.png).
# Algunas son TLDs reales (.zip, .sh, .md); se acepta ese falso negativo a propósito.
FILE_EXTENSIONS = frozenset(
    """
    html htm xhtml php asp aspx jsp js mjs ts css scss json xml yml yaml toml ini cfg conf
    txt log md rst csv tsv pdf doc docx xls xlsx ppt pptx odt png jpg jpeg gif svg webp bmp
    ico tif tiff mp3 mp4 avi mkv mov wav exe dll so bin bat cmd ps1 sh py pyc rb pl java
    class jar go rs c h cpp hpp cs zip rar gz tgz bz2 xz tar 7z iso img bak tmp old swp
    """.split()  # noqa: SIM905 - más legible que una lista literal de 90 elementos
)

_TLD = r"[a-zA-Z]{2,63}"
_LABEL = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"

EMAIL_RE = re.compile(
    rf"(?<![\w.%+-])[a-zA-Z0-9._%+-]{{1,64}}@(?:{_LABEL}\.)+{_TLD}\b(?!\.[a-zA-Z0-9])"
)
# No debe ir precedido de '@' (eso es un email) ni seguido de '...@' (parte local de un email).
DOMAIN_RE = re.compile(rf"(?<![\w.@-])(?:{_LABEL}\.)+{_TLD}\b(?![\w.-]*@)(?!\.?[\w-])")
URL_RE = re.compile(r"\bhttps?://[^\s<>'\"`(){}\[\]|\\^]+", re.IGNORECASE)
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4_RE = re.compile(rf"(?<![\d.]){_OCTET}(?:\.{_OCTET}){{3}}(?!\.?\d)")
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)
ONION_IN_TEXT_RE = re.compile(
    r"\b(?:https?://)?(?:[a-z0-9-]+\.)*[a-z2-7]{56}\.onion\b[^\s<>'\"`(){}\[\]]*", re.IGNORECASE
)

_TRAILING_PUNCT = ".,;:!?'\")]}>"
_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}


@dataclass(frozen=True)
class Ioc:
    """Un indicador: ``value`` tal y como aparece, ``normalized`` para correlacionar."""

    type: str
    value: str
    normalized: str


# --- normalizadores ---------------------------------------------------------


def normalize_email(value: str) -> str:
    """Email en minúsculas."""
    return value.strip().lower()


def normalize_domain(value: str) -> str:
    """Dominio en minúsculas y sin punto final."""
    return value.strip().lower().rstrip(".")


def normalize_cve(value: str) -> str:
    """CVE en mayúsculas."""
    return value.strip().upper()


def normalize_hash(value: str) -> str:
    """Hash en minúsculas."""
    return value.strip().lower()


def normalize_ipv4(value: str) -> str:
    """IPv4 en forma canónica."""
    return str(ipaddress.IPv4Address(value.strip()))


def normalize_url(value: str) -> str:
    """Esquema y host en minúsculas, sin credenciales ni fragmento."""
    parts = urlsplit(value.strip())
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = f"{host}:{port}" if port else host
    return urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, ""))


def _strip_trailing(value: str) -> str:
    return value.rstrip(_TRAILING_PUNCT)


def _tld_is_plausible(domain: str) -> bool:
    return domain.rsplit(".", 1)[-1].lower() not in FILE_EXTENSIONS


# --- extractores -------------------------------------------------------------


def extract_emails(text: str) -> list[Ioc]:
    """Emails, descartando los que terminan en una extensión de fichero (``logo@2x.png``)."""
    found = {}
    for match in EMAIL_RE.finditer(text):
        value = match.group(0)
        if _tld_is_plausible(value) and ".." not in value:
            found.setdefault(normalize_email(value), value)
    return [Ioc("email", v, n) for n, v in sorted(found.items())]


def extract_domains(text: str) -> list[Ioc]:
    """Dominios (excluye .onion, nombres de fichero y partes locales de emails).

    Incluye también los dominios de los emails encontrados.
    """
    found: dict[str, str] = {}
    candidates = [m.group(0) for m in DOMAIN_RE.finditer(text)]
    candidates += [e.value.rsplit("@", 1)[1] for e in extract_emails(text)]
    for value in candidates:
        norm = normalize_domain(value)
        if norm.endswith(".onion") or not _tld_is_plausible(norm):
            continue
        found.setdefault(norm, value)
    return [Ioc("domain", v, n) for n, v in sorted(found.items())]


def extract_urls(text: str) -> list[Ioc]:
    """URLs http/https de clearnet (las .onion van a ``extract_onion_urls``)."""
    found: dict[str, str] = {}
    for match in URL_RE.finditer(text):
        value = _strip_trailing(match.group(0))
        parts = urlsplit(value)
        host = (parts.hostname or "").lower()
        if not host or "." not in host or host.endswith(".onion"):
            continue
        found.setdefault(normalize_url(value), value)
    return [Ioc("url", v, n) for n, v in sorted(found.items())]


def extract_ipv4(text: str) -> list[Ioc]:
    """Direcciones IPv4 sin ceros a la izquierda ni fragmentos de cadenas más largas."""
    found: dict[str, str] = {}
    for match in IPV4_RE.finditer(text):
        found.setdefault(normalize_ipv4(match.group(0)), match.group(0))
    return [Ioc("ipv4", v, n) for n, v in sorted(found.items())]


def extract_hashes(text: str) -> list[Ioc]:
    """Hashes MD5/SHA-1/SHA-256 por longitud.

    Se descartan cadenas solo de dígitos o solo de letras: casi nunca son hashes reales.
    """
    found: dict[tuple[str, str], str] = {}
    for match in HASH_RE.finditer(text):
        value = match.group(0)
        if value.isdigit() or value.isalpha() or len(set(value.lower())) < 4:
            continue
        found.setdefault((_HASH_TYPES[len(value)], normalize_hash(value)), value)
    return [Ioc(t, v, n) for (t, n), v in sorted(found.items())]


def extract_cves(text: str) -> list[Ioc]:
    """Identificadores CVE con año plausible (>= 1999)."""
    found: dict[str, str] = {}
    for match in CVE_RE.finditer(text):
        if int(match.group(1)) < 1999:
            continue
        found.setdefault(normalize_cve(match.group(0)), match.group(0))
    return [Ioc("cve", v, n) for n, v in sorted(found.items())]


def extract_onion_urls(text: str, links: list[str] | None = None) -> list[Ioc]:
    """URLs .onion válidas (checksum v3) del texto y de los enlaces de la página."""
    found: dict[str, str] = {}
    candidates = [_strip_trailing(m.group(0)) for m in ONION_IN_TEXT_RE.finditer(text)]
    candidates += list(links or [])
    for value in candidates:
        url = value if "://" in value else f"http://{value}"
        if is_valid_onion_url(url):
            found.setdefault(normalize_onion_url(url), value)
    return [Ioc("onion", v, n) for n, v in sorted(found.items())]


def extract_iocs(text: str, links: list[str] | None = None) -> list[Ioc]:
    """Ejecuta todos los extractores sobre ``text`` (y ``links`` para las .onion)."""
    return [
        *extract_emails(text),
        *extract_domains(text),
        *extract_urls(text),
        *extract_ipv4(text),
        *extract_hashes(text),
        *extract_cves(text),
        *extract_onion_urls(text, links),
    ]


def candidate_normalizations(value: str) -> list[str]:
    """Posibles formas normalizadas de un valor introducido por el usuario (``related``)."""
    value = value.strip()
    candidates = [value, value.lower(), value.upper()]
    if "://" in value:
        candidates.append(normalize_url(value))
        if is_valid_onion_url(value):
            candidates.append(normalize_onion_url(value))
    with suppress(ValueError):
        candidates.append(normalize_ipv4(value))
    return list(dict.fromkeys(candidates))
