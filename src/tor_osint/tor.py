"""Cliente HTTP sobre Tor (SOCKS5h) con límites de seguridad y comprobación de Tor."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urljoin

import requests

from .config import USER_AGENT, Config
from .sources import is_valid_onion_url

log = logging.getLogger(__name__)

TOR_CHECK_URL = "https://check.torproject.org/api/ip"
ALLOWED_CONTENT_TYPES = ("text/html", "application/xhtml+xml", "text/plain")
REDIRECT_CODES = (301, 302, 303, 307, 308)


@dataclass
class FetchResult:
    """Resultado de una descarga. ``content`` son bytes no confiables."""

    url: str
    final_url: str
    status: int | None = None
    content_type: str = ""
    encoding: str | None = None
    content: bytes = b""
    truncated: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        """Hay respuesta HTTP y no hubo error de transporte/política."""
        return self.error is None and self.status is not None


@dataclass(frozen=True)
class TorStatus:
    """Resultado de ``tor-check``."""

    is_tor: bool
    ip: str | None = None
    error: str | None = None


def build_session(config: Config) -> requests.Session:
    """Crea una sesión requests enrutada por Tor con User-Agent identificable."""
    session = requests.Session()
    session.proxies.update({"http": config.proxy_url, "https": config.proxy_url})
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "text/html,text/plain;q=0.9"})
    session.trust_env = False  # ignora HTTP(S)_PROXY del entorno: todo va por Tor
    session.max_redirects = 0
    return session


class TorClient:
    """Cliente con timeout, límite de tamaño, rate limiting y redirecciones controladas.

    Las redirecciones se siguen manualmente: solo hacia URLs .onion válidas,
    con un máximo configurable y detección de bucles.
    """

    def __init__(
        self,
        config: Config,
        session: requests.Session | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config
        self.session = session or build_session(config)
        self._sleep = sleep
        self._clock = clock
        self._last_request: float | None = None

    def _throttle(self) -> None:
        """Garantiza al menos ``config.delay`` segundos entre peticiones."""
        if self._last_request is not None:
            wait = self.config.delay - (self._clock() - self._last_request)
            if wait > 0:
                self._sleep(wait)
        self._last_request = self._clock()

    def fetch(self, url: str) -> FetchResult:
        """Descarga ``url`` (debe ser .onion válida) aplicando todos los límites."""
        result = FetchResult(url=url, final_url=url)
        if not is_valid_onion_url(url):
            result.error = "URL rechazada: no es una URL .onion válida"
            return result

        current = url
        seen: set[str] = set()
        for _ in range(self.config.max_redirects + 1):
            if current in seen:
                result.error = f"bucle de redirección detectado en {current}"
                return result
            seen.add(current)
            self._throttle()
            try:
                response = self.session.get(
                    current, timeout=self.config.timeout, allow_redirects=False, stream=True
                )
            except requests.RequestException as exc:
                log.error("Error de conexión con %s: %s", current, type(exc).__name__)
                log.debug("Detalle: %s", exc)
                result.error = f"error de conexión: {type(exc).__name__}"
                return result

            with response:
                result.final_url = current
                result.status = response.status_code
                if response.status_code in REDIRECT_CODES:
                    location = response.headers.get("Location", "")
                    target = urljoin(current, location)
                    if not location or not is_valid_onion_url(target):
                        result.error = f"redirección rechazada (fuera de .onion): {target[:200]}"
                        return result
                    log.info("Redirección %s -> %s", current, target)
                    current = target
                    continue
                self._read_body(response, result)
                return result

        result.error = f"demasiadas redirecciones (máx. {self.config.max_redirects})"
        return result

    def _read_body(self, response: requests.Response, result: FetchResult) -> None:
        """Lee el cuerpo hasta ``max_bytes`` si el Content-Type es textual."""
        content_type = response.headers.get("Content-Type", "")
        mime = content_type.split(";")[0].strip().lower()
        result.content_type = mime
        if mime and mime not in ALLOWED_CONTENT_TYPES:
            result.error = f"Content-Type no soportado: {mime[:100]}"
            return
        # Solo usamos el charset si el servidor lo declara; si no, el parser lo detecta.
        result.encoding = response.encoding if "charset=" in content_type.lower() else None

        buffer = bytearray()
        try:
            for chunk in response.iter_content(chunk_size=16_384):
                buffer.extend(chunk)
                if len(buffer) > self.config.max_bytes:
                    result.truncated = True
                    log.warning(
                        "Respuesta truncada a %d bytes: %s", self.config.max_bytes, result.final_url
                    )
                    break
        except requests.RequestException as exc:
            log.error("Error leyendo %s: %s", result.final_url, type(exc).__name__)
            result.error = f"error de lectura: {type(exc).__name__}"
        result.content = bytes(buffer[: self.config.max_bytes])

    def check_tor(self) -> TorStatus:
        """Consulta el endpoint oficial de The Tor Project para verificar el circuito."""
        self._throttle()
        try:
            response = self.session.get(TOR_CHECK_URL, timeout=self.config.timeout)
            response.raise_for_status()
            data = response.json()
        except (requests.RequestException, ValueError) as exc:
            log.debug("tor-check: %s", exc)
            return TorStatus(is_tor=False, error=type(exc).__name__)
        return TorStatus(is_tor=bool(data.get("IsTor")), ip=data.get("IP"))
