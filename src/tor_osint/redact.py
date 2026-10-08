"""Redacción de credenciales y secretos antes de almacenar contenido.

Política: la herramienta no debe guardar credenciales encontradas accidentalmente.
Se sustituyen por ``[REDACTED]`` en el texto, el título y los enlaces, de modo
que no llegan ni a SQLite, ni a las exportaciones, ni al informe. Los emails sí
se conservan como IOC, pero no la contraseña que los acompañe en un combo
``email:password``.
"""

from __future__ import annotations

import re

REDACTED = "[REDACTED]"

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Bloques de clave privada (PEM/OpenSSH).
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)",
            re.DOTALL,
        ),
        f"-----{REDACTED} PRIVATE KEY-----",
    ),
    # Credenciales embebidas en URLs: scheme://user:pass@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/:@]+:[^\s/@]+@"), rf"\1{REDACTED}@"),
    # Combos email:password / email;password / email|password
    (
        re.compile(r"(\b[\w.%+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,63})([:;|])(?!//)\S+"),
        rf"\1\2{REDACTED}",
    ),
    # Cabeceras "Bearer <token>".
    (re.compile(r"(?i)\b(bearer\s+)[\w.~+/-]{8,}=*"), rf"\1{REDACTED}"),
    # Pares clave=valor / clave: valor con nombres sensibles.
    (
        re.compile(
            r"(?i)\b(pass(?:word|wd)?|pwd|contrase(?:ñ|n)a|clave|secret|token|"
            r"api[_-]?key|access[_-]?key|secret[_-]?key|authorization|"
            r"session[_-]?id|cookie)(\s*[:=]\s*)(['\"]?)[^\s'\"]{3,}\3"
        ),
        rf"\1\2{REDACTED}",
    ),
    # Tokens con formato conocido.
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),  # AWS access key id
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), REDACTED),  # GitHub
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"), REDACTED),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"), REDACTED),  # Slack
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), REDACTED),  # Google API key
    (re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b"), REDACTED),  # Stripe
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), REDACTED),  # claves tipo sk-...
    (re.compile(r"\beyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]{8,}\b"), REDACTED),  # JWT
]


def redact(text: str) -> str:
    """Devuelve ``text`` con credenciales y secretos sustituidos por ``[REDACTED]``."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text
