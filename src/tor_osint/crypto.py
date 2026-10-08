"""Validación de direcciones de criptomonedas (sin dependencias).

- Bitcoin legacy (P2PKH ``1…``, P2SH ``3…``): Base58Check con doble SHA-256.
- Bitcoin SegWit/Taproot (``bc1…``): Bech32 (BIP-173) y Bech32m (BIP-350).
- Ethereum (``0x…``): checksum de mayúsculas EIP-55, que requiere Keccak-256.

Keccak-256 se implementa aquí porque ``hashlib.sha3_256`` usa un padding distinto
(SHA-3 estandarizado) y no sirve para Ethereum.
"""

from __future__ import annotations

import hashlib

# --- Keccak-256 ---------------------------------------------------------------

_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)  # fmt: skip
# Desplazamientos de rotación r[x][y].
_ROT = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
_MASK = (1 << 64) - 1


def _rotl(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & _MASK if shift else value


def _keccak_f(a: list[list[int]]) -> None:
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(a[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y] & _MASK)
        a[0][0] ^= rc


def keccak256(data: bytes, _pad: int = 0x01) -> bytes:
    """Keccak-256 original (Ethereum). ``_pad=0x06`` da SHA3-256 (solo para tests)."""
    rate = 136
    padded = bytearray(data)
    padded.append(_pad)
    padded.extend(b"\x00" * (-len(padded) % rate))
    padded[-1] |= 0x80
    state = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for i in range(rate // 8):
            state[i % 5][i // 5] ^= int.from_bytes(block[8 * i : 8 * i + 8], "little")
        _keccak_f(state)
    out = b"".join(state[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
    return out


def eth_checksum_address(address: str) -> str:
    """Devuelve la dirección con mayúsculas EIP-55 (``0x`` + 40 hex)."""
    body = address[2:].lower()
    digest = keccak256(body.encode("ascii")).hex()
    return "0x" + "".join(
        ch.upper() if ch.isalpha() and int(digest[i], 16) >= 8 else ch for i, ch in enumerate(body)
    )


def is_valid_eth(address: str) -> bool:
    """Valida ``0x`` + 40 hex. Si mezcla mayúsculas y minúsculas, exige checksum EIP-55."""
    if len(address) != 42 or not address.startswith("0x"):
        return False
    body = address[2:]
    try:
        int(body, 16)
    except ValueError:
        return False
    if body.islower() or body.isupper() or body.isdigit():
        return True  # sin información de checksum
    return eth_checksum_address(address) == address


# --- Base58Check ----------------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}


def _b58decode(value: str) -> bytes:
    number = 0
    for ch in value:
        number = number * 58 + _B58_INDEX[ch]
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading + raw


def is_valid_btc_base58(address: str) -> bool:
    """P2PKH (versión 0x00) o P2SH (0x05) con checksum doble SHA-256 correcto."""
    if not 26 <= len(address) <= 35 or any(ch not in _B58_INDEX for ch in address):
        return False
    raw = _b58decode(address)
    if len(raw) != 25 or raw[0] not in (0x00, 0x05):
        return False
    payload, checksum = raw[:-4], raw[-4:]
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum


# --- Bech32 / Bech32m ----------------------------------------------------------------

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST, _BECH32M_CONST = 1, 0x2BC830A3


def _polymod(values: list[int]) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data: list[int], frombits: int, tobits: int) -> list[int] | None:
    acc = bits = 0
    out = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return out


def is_valid_btc_bech32(address: str) -> bool:
    """Dirección SegWit ``bc1``: v0 con Bech32 (20/32 bytes), v1+ con Bech32m (2-40 bytes)."""
    if address.lower() != address and address.upper() != address:
        return False  # mayúsculas y minúsculas mezcladas no son válidas
    address = address.lower()
    if not 14 <= len(address) <= 90 or not address.startswith("bc1"):
        return False
    data_part = address[3:]
    if any(c not in _CHARSET for c in data_part):
        return False
    data = [_CHARSET.index(c) for c in data_part]
    const = _polymod(_hrp_expand("bc") + data)
    witness_version = data[0]
    if witness_version > 16:
        return False
    expected = _BECH32_CONST if witness_version == 0 else _BECH32M_CONST
    if const != expected:
        return False
    program = _convertbits(data[1:-6], 5, 8)
    if program is None or not 2 <= len(program) <= 40:
        return False
    return witness_version != 0 or len(program) in (20, 32)
