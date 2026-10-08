import pytest

from conftest import TORPROJECT_ONION, make_onion
from tor_osint.sources import (
    is_valid_onion_url,
    load_sources,
    normalize_onion_url,
    onion_version,
    parse_sources,
)

V3 = make_onion("a")


def test_real_v3_checksum_is_valid():
    assert onion_version(TORPROJECT_ONION) == 3


def test_v3_bad_checksum_rejected():
    # Cambiar un carácter rompe el checksum aunque la sintaxis sea correcta.
    broken = ("b" if TORPROJECT_ONION[0] != "b" else "c") + TORPROJECT_ONION[1:]
    assert onion_version(broken) is None


def test_v2_syntax_accepted():
    assert onion_version("expyuzz4wqqyqhjn") == 2


@pytest.mark.parametrize(
    "url",
    [
        f"http://{V3}.onion/",
        f"https://{V3}.onion/path?q=1",
        f"http://{V3.upper()}.ONION",
        f"http://www.{V3}.onion/",
        f"http://{V3}.onion:8080/",
        "http://expyuzz4wqqyqhjn.onion/",
    ],
)
def test_valid_onion_urls(url):
    assert is_valid_onion_url(url)


@pytest.mark.parametrize(
    "url",
    [
        f"ftp://{V3}.onion/",  # esquema
        f"{V3}.onion",  # sin esquema
        "http://example.com/",  # no es .onion
        "http://short.onion/",  # longitud
        f"http://{V3[:-1]}1.onion/",  # carácter fuera de base32 (1)
        f"http://{V3}x.onion/",  # 57 caracteres
        f"http://user:pass@{V3}.onion/",  # credenciales embebidas
        f"http://{V3}.onion:99999/",  # puerto inválido
        f"http://{V3}.onion.evil.com/",  # sufijo engañoso
        "javascript:alert(1)",
        "",
    ],
)
def test_invalid_onion_urls(url):
    assert not is_valid_onion_url(url)


def test_normalize_onion_url():
    assert normalize_onion_url(f"HTTP://{V3.upper()}.onion#frag") == f"http://{V3}.onion/"


def test_parse_sources_skips_comments_invalid_and_duplicates():
    lines = [
        "# comentario",
        "",
        f"http://{V3}.onion/",
        f"HTTP://{V3.upper()}.ONION/",
        "http://example.com/",
    ]
    result = parse_sources(lines)
    assert result.valid == [f"http://{V3}.onion/"]
    assert result.rejected == [(5, "http://example.com/")]


def test_load_sources_missing_file(tmp_path):
    assert load_sources(tmp_path / "nope.txt").valid == []


def test_load_sources_file(tmp_path):
    path = tmp_path / "sources.txt"
    path.write_text(f"http://{V3}.onion/\n", encoding="utf-8")
    assert load_sources(path).valid == [f"http://{V3}.onion/"]
