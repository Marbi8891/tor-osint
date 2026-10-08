"""Configuración: valores por defecto, variables de entorno y validación."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path

from . import __version__

USER_AGENT = f"tor-osint/{__version__} (research client; +local-lab)"

# Límites duros: ni el entorno ni la CLI pueden superarlos.
MAX_ALLOWED_BYTES = 20 * 1024 * 1024
MAX_ALLOWED_TIMEOUT = 300
MIN_DELAY = 0.5
MAX_REDIRECTS = 5


class ConfigError(ValueError):
    """Valor de configuración inválido."""


@dataclass(frozen=True)
class Config:
    """Configuración inmutable de una ejecución."""

    socks: str = "127.0.0.1:9050"
    timeout: int = 30
    delay: float = 2.0
    max_bytes: int = 2 * 1024 * 1024
    max_urls: int = 100
    max_redirects: int = MAX_REDIRECTS
    data_dir: Path = field(default_factory=lambda: Path("data"))
    results_dir: Path = field(default_factory=lambda: Path("results"))
    db_path: Path | None = None
    sources_path: Path | None = None

    @property
    def database(self) -> Path:
        """Ruta efectiva de la base de datos SQLite."""
        return self.db_path or self.data_dir / "results.db"

    @property
    def sources(self) -> Path:
        """Ruta efectiva del fichero de fuentes."""
        return self.sources_path or self.data_dir / "sources.txt"

    @property
    def proxy_url(self) -> str:
        """URL del proxy SOCKS5 con resolución DNS remota (socks5h)."""
        host, port = parse_socks(self.socks)
        return f"socks5h://{host}:{port}"

    def with_overrides(self, **overrides: object) -> Config:
        """Devuelve una copia con los valores no nulos de ``overrides`` aplicados y validada."""
        clean = {k: v for k, v in overrides.items() if v is not None}
        return replace(self, **clean).validated()

    def validated(self) -> Config:
        """Valida los valores y devuelve ``self``; lanza ``ConfigError`` si algo no es válido."""
        parse_socks(self.socks)
        if not 1 <= self.timeout <= MAX_ALLOWED_TIMEOUT:
            raise ConfigError(f"timeout debe estar entre 1 y {MAX_ALLOWED_TIMEOUT} s")
        if self.delay < MIN_DELAY:
            raise ConfigError(f"delay mínimo: {MIN_DELAY} s (rate limiting)")
        if not 1024 <= self.max_bytes <= MAX_ALLOWED_BYTES:
            raise ConfigError(f"max_bytes debe estar entre 1024 y {MAX_ALLOWED_BYTES}")
        if not 1 <= self.max_urls <= 10_000:
            raise ConfigError("max_urls debe estar entre 1 y 10000")
        if not 0 <= self.max_redirects <= MAX_REDIRECTS:
            raise ConfigError(f"max_redirects debe estar entre 0 y {MAX_REDIRECTS}")
        return self


def parse_socks(value: str) -> tuple[str, int]:
    """Parsea ``host:port`` y valida el puerto."""
    host, sep, port_s = value.strip().rpartition(":")
    if not sep or not host or not port_s.isdigit():
        raise ConfigError(f"TOR_SOCKS inválido (esperado host:puerto): {value!r}")
    port = int(port_s)
    if not 1 <= port <= 65535:
        raise ConfigError(f"puerto SOCKS fuera de rango: {port}")
    return host, port


def _env_number(env: Mapping[str, str], name: str, cast: type, default: float) -> float:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return cast(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} no es un número válido: {raw!r}") from exc


def load_config(env: Mapping[str, str] | None = None) -> Config:
    """Construye la configuración a partir de variables de entorno (``TOR_*``)."""
    env = os.environ if env is None else env
    base = Config()
    return Config(
        socks=env.get("TOR_SOCKS", base.socks),
        timeout=int(_env_number(env, "TOR_TIMEOUT", int, base.timeout)),
        delay=float(_env_number(env, "TOR_DELAY", float, base.delay)),
        max_bytes=int(_env_number(env, "TOR_MAX_BYTES", int, base.max_bytes)),
        max_urls=int(_env_number(env, "TOR_MAX_URLS", int, base.max_urls)),
    ).validated()
