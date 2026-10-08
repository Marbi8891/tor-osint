import requests

from conftest import FakeResponse, FakeSession, make_onion
from tor_osint.config import Config
from tor_osint.tor import TOR_CHECK_URL, TorClient, build_session

A = f"http://{make_onion('a')}.onion/"
B = f"http://{make_onion('b')}.onion/"


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def client(routes, **cfg):
    clock = FakeClock()
    session = FakeSession(routes)
    c = TorClient(Config(**cfg), session=session, sleep=clock.sleep, clock=clock)
    return c, session, clock


def test_build_session_uses_tor_proxy_and_user_agent():
    s = build_session(Config(socks="127.0.0.1:9150"))
    assert s.proxies["http"] == s.proxies["https"] == "socks5h://127.0.0.1:9150"
    assert s.headers["User-Agent"].startswith("tor-osint/")
    assert s.trust_env is False


def test_fetch_ok_passes_timeout_and_disables_auto_redirects():
    c, session, _ = client({A: FakeResponse(body=b"<p>hola</p>")}, timeout=7)
    result = c.fetch(A)
    assert result.ok and result.content == b"<p>hola</p>" and result.status == 200
    _, kwargs = session.calls[0]
    assert kwargs["timeout"] == 7
    assert kwargs["allow_redirects"] is False
    assert kwargs["stream"] is True


def test_fetch_rejects_non_onion_without_network():
    c, session, _ = client({})
    result = c.fetch("http://example.com/")
    assert not result.ok and session.calls == []


def test_fetch_truncates_to_max_bytes():
    c, _, _ = client({A: FakeResponse(body=b"x" * 5000)}, max_bytes=1024)
    result = c.fetch(A)
    assert result.truncated and len(result.content) == 1024


def test_fetch_rejects_binary_content_type():
    c, _, _ = client(
        {A: FakeResponse(body=b"MZ", headers={"Content-Type": "application/x-msdownload"})}
    )
    result = c.fetch(A)
    assert result.error and "Content-Type" in result.error
    assert result.content == b""


def test_follows_onion_redirect():
    routes = {A: FakeResponse(302, headers={"Location": B}), B: FakeResponse(body=b"ok")}
    c, _, _ = client(routes)
    result = c.fetch(A)
    assert result.ok and result.final_url == B and result.content == b"ok"


def test_rejects_redirect_to_clearnet():
    c, session, _ = client({A: FakeResponse(302, headers={"Location": "https://example.com/"})})
    result = c.fetch(A)
    assert result.error and "fuera de .onion" in result.error
    assert len(session.calls) == 1


def test_detects_redirect_loop():
    routes = {
        A: FakeResponse(302, headers={"Location": B}),
        B: FakeResponse(302, headers={"Location": A}),
    }
    c, _, _ = client(routes)
    assert "bucle" in c.fetch(A).error


def test_redirect_limit():
    hops = [f"http://{make_onion(str(i))}.onion/" for i in range(4)]
    routes = {hops[i]: FakeResponse(302, headers={"Location": hops[i + 1]}) for i in range(3)}
    c, _, _ = client(routes, max_redirects=1)
    assert "demasiadas redirecciones" in c.fetch(hops[0]).error


def test_connection_error_is_controlled():
    c, _, _ = client({A: requests.ConnectTimeout("timeout")})
    result = c.fetch(A)
    assert not result.ok and "ConnectTimeout" in result.error


def test_rate_limiting_between_requests_including_failures():
    c, _, clock = client({A: requests.ConnectionError("x"), B: FakeResponse(body=b"ok")}, delay=2.0)
    c.fetch(A)
    c.fetch(B)
    assert clock.sleeps == [2.0]


def test_tor_check_ok():
    c, _, _ = client({TOR_CHECK_URL: FakeResponse(json_data={"IsTor": True, "IP": "203.0.113.9"})})
    status = c.check_tor()
    assert status.is_tor and status.error is None


def test_tor_check_not_tor_and_errors():
    c, _, _ = client({TOR_CHECK_URL: FakeResponse(json_data={"IsTor": False})})
    assert c.check_tor().is_tor is False
    c, _, _ = client({})
    status = c.check_tor()
    assert not status.is_tor and status.error == "ConnectionError"
