import pytest

from tor_osint.redact import REDACTED, redact


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("user@example.com:Sup3rS3cret!", "Sup3rS3cret!"),
        ("user@example.com;hunter22", "hunter22"),
        ("password: hunter22", "hunter22"),
        ("PASSWORD=hunter22", "hunter22"),
        ("contraseña: hunter22", "hunter22"),
        ('api_key="abcd1234efgh"', "abcd1234efgh"),
        ("token=eyJabc.def", "eyJabc.def"),
        ("https://admin:p4ss@example.com/panel", "p4ss"),
        ("Authorization: Bearer abcdefghijklmnop", "abcdefghijklmnop"),
        ("AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP"),
        ("ghp_" + "a" * 36, "ghp_" + "a" * 36),
        ("eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4", "SflKxwRJSMeKKF2QT4"),
        (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
            "MIIEpAIBAAKCAQEA",
        ),
    ],
)
def test_secrets_are_redacted(text, secret):
    out = redact(text)
    assert secret not in out
    assert REDACTED in out


def test_email_kept_password_removed():
    assert redact("user@example.com:hunter22") == f"user@example.com:{REDACTED}"


@pytest.mark.parametrize(
    "text",
    [
        "Contacto: user@example.com",
        "Olvidé mi password y pedí un reset",
        "token ring y API keys en general",
        "Visita https://example.com/docs",
        "CVE-2024-1234 afecta a 8.8.8.8",
    ],
)
def test_benign_text_untouched(text):
    assert redact(text) == text
