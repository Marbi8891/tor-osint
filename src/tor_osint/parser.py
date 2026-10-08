"""Parseo de HTML no confiable: título, texto visible y enlaces.

Nunca se ejecuta JavaScript ni se cargan recursos remotos: BeautifulSoup solo
construye un árbol en memoria con ``html.parser`` (stdlib), y los elementos
activos (script, style, iframe...) se eliminan antes de extraer texto.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

MAX_TITLE_CHARS = 1_000
MAX_TEXT_CHARS = 2_000_000
MAX_LINKS = 2_000
_STRIP_TAGS = ("script", "style", "noscript", "svg", "template", "iframe", "object", "embed")
_WS_RE = re.compile(r"\s+")


@dataclass
class ParsedPage:
    """Contenido extraído de una página."""

    title: str = ""
    text: str = ""
    links: list[str] = field(default_factory=list)


def _clean(value: str) -> str:
    return _WS_RE.sub(" ", value).strip()


def parse_content(
    base_url: str, content: bytes, content_type: str = "text/html", encoding: str | None = None
) -> ParsedPage:
    """Extrae título, texto y enlaces absolutos http(s) de ``content``.

    ``text/plain`` se decodifica directamente; el resto se trata como HTML y la
    codificación se detecta a partir del charset declarado o de ``<meta charset>``.
    """
    if content_type == "text/plain":
        text = content.decode(encoding or "utf-8", errors="replace")
        return ParsedPage(text=_clean(text)[:MAX_TEXT_CHARS])

    soup = BeautifulSoup(content, "html.parser", from_encoding=encoding)
    for tag in soup(_STRIP_TAGS):
        tag.decompose()

    title = _clean(soup.title.get_text(" ")) if soup.title else ""
    text = _clean(soup.get_text(" "))

    links: list[str] = []
    for tag in soup.find_all("a", href=True):
        href = str(tag["href"]).strip()
        try:
            absolute = urljoin(base_url, href)
            scheme = urlsplit(absolute).scheme.lower()
        except ValueError:
            continue
        if scheme in ("http", "https"):
            links.append(absolute.split("#", 1)[0])
        if len(links) >= MAX_LINKS:
            break

    return ParsedPage(
        title=title[:MAX_TITLE_CHARS],
        text=text[:MAX_TEXT_CHARS],
        links=list(dict.fromkeys(links)),
    )
