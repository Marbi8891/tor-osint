"""Utilidades comunes: direcciones onion v3 válidas y una sesión HTTP falsa (sin red)."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Iterator

import pytest

from tor_osint.config import Config
from tor_osint.database import connect

# Servicio onion oficial de The Tor Project (checksum v3 válido).
TORPROJECT_ONION = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid"


def make_onion(seed: str) -> str:
    """Genera una dirección onion v3 sintácticamente válida (checksum correcto)."""
    pubkey = hashlib.sha256(seed.encode()).digest()
    version = b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + pubkey + version).digest()[:2]
    return base64.b32encode(pubkey + checksum + version).decode().lower()


class FakeResponse:
    """Respuesta mínima compatible con lo que usa ``TorClient``."""

    def __init__(
        self,
        status: int = 200,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
        json_data: object = None,
    ) -> None:
        self.status_code = status
        self._body = body
        self.headers = (
            headers if headers is not None else {"Content-Type": "text/html; charset=utf-8"}
        )
        self._json = json_data
        self.closed = False
        ct = self.headers.get("Content-Type", "")
        self.encoding = ct.split("charset=")[1] if "charset=" in ct else None

    def iter_content(self, chunk_size: int = 1) -> Iterator[bytes]:
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i : i + chunk_size]

    def json(self) -> object:
        return self._json

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            import requests

            raise requests.HTTPError(f"HTTP {self.status_code}")

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        self.closed = True


class FakeSession:
    """Devuelve respuestas predefinidas por URL y registra las peticiones."""

    def __init__(self, routes: dict[str, FakeResponse | Exception]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, dict[str, object]]] = []

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.calls.append((url, kwargs))
        route = self.routes.get(url)
        if route is None:
            import requests

            raise requests.ConnectionError(f"sin ruta para {url}")
        if isinstance(route, Exception):
            raise route
        return route


@pytest.fixture
def config(tmp_path) -> Config:
    return Config(data_dir=tmp_path / "data", results_dir=tmp_path / "results", delay=0.5)


@pytest.fixture
def conn():
    connection = connect(":memory:")
    yield connection
    connection.close()
