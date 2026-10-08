import pytest

from tor_osint.config import Config, ConfigError, load_config, parse_socks


def test_defaults_from_empty_env():
    cfg = load_config({})
    assert cfg.socks == "127.0.0.1:9050"
    assert cfg.timeout == 30
    assert cfg.delay == 2.0
    assert cfg.max_bytes == 2 * 1024 * 1024


def test_env_overrides():
    cfg = load_config(
        {
            "TOR_SOCKS": "10.0.0.5:9150",
            "TOR_TIMEOUT": "10",
            "TOR_DELAY": "1.5",
            "TOR_MAX_BYTES": "4096",
        }
    )
    assert cfg.proxy_url == "socks5h://10.0.0.5:9150"
    assert (cfg.timeout, cfg.delay, cfg.max_bytes) == (10, 1.5, 4096)


def test_proxy_uses_socks5h_for_remote_dns():
    assert Config().proxy_url.startswith("socks5h://")


@pytest.mark.parametrize(
    "env",
    [
        {"TOR_SOCKS": "sin-puerto"},
        {"TOR_SOCKS": "127.0.0.1:99999"},
        {"TOR_TIMEOUT": "abc"},
        {"TOR_TIMEOUT": "0"},
        {"TOR_DELAY": "0"},  # el rate limiting no se puede desactivar
        {"TOR_MAX_BYTES": "999999999999"},
    ],
)
def test_invalid_env_rejected(env):
    with pytest.raises(ConfigError):
        load_config(env)


def test_cli_overrides_ignore_none_and_validate():
    cfg = Config().with_overrides(timeout=None, delay=3.0)
    assert cfg.timeout == 30 and cfg.delay == 3.0
    with pytest.raises(ConfigError):
        Config().with_overrides(max_bytes=10)


def test_parse_socks_ipv6_like_host():
    assert parse_socks("[::1]:9050") == ("[::1]", 9050)
