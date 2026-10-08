"""Validadores de criptomonedas con vectores oficiales (EIP-55, BIP-173, BIP-350)."""

import hashlib
import os

import pytest

from tor_osint.crypto import (
    eth_checksum_address,
    is_valid_btc_base58,
    is_valid_btc_bech32,
    is_valid_eth,
    keccak256,
)
from tor_osint.ioc import extract_attack, extract_btc, extract_eth, extract_iocs, extract_pgp

# Vectores de la especificación EIP-55.
EIP55 = [
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
]
GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"  # dirección del bloque génesis
P2SH = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
BIP173 = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"
BIP350 = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"


def test_keccak256_known_vector():
    assert keccak256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )


@pytest.mark.parametrize("size", [0, 1, 135, 136, 137, 500])
def test_keccak_permutation_matches_hashlib_sha3(size):
    # Con el padding de SHA-3 la misma permutación debe coincidir con hashlib.
    data = os.urandom(size)
    assert keccak256(data, _pad=0x06) == hashlib.sha3_256(data).digest()


@pytest.mark.parametrize("address", EIP55)
def test_eip55_vectors(address):
    assert eth_checksum_address(address.lower()) == address
    assert is_valid_eth(address)
    assert is_valid_eth(address.lower()) and is_valid_eth("0x" + address[2:].upper())
    flipped = address[:2] + address[2:].swapcase()
    assert not is_valid_eth(flipped)


@pytest.mark.parametrize(
    "address", ["0x123", "0x" + "g" * 40, "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"]
)
def test_eth_invalid(address):
    assert not is_valid_eth(address)


def test_base58check():
    assert is_valid_btc_base58(GENESIS) and is_valid_btc_base58(P2SH)
    assert not is_valid_btc_base58(GENESIS[:-1] + "b")  # checksum roto
    assert not is_valid_btc_base58("1" + "0" * 30)  # '0' no existe en Base58
    assert not is_valid_btc_base58("1abc")


def test_bech32_and_bech32m():
    assert is_valid_btc_bech32(BIP173) and is_valid_btc_bech32(BIP173.lower())
    assert is_valid_btc_bech32(BIP350)
    assert not is_valid_btc_bech32(BIP173[:-1] + "5")  # checksum roto
    assert not is_valid_btc_bech32(BIP173[:10] + BIP173[10:].lower())  # mayúsculas mezcladas
    # La versión de testigo fija la constante: v0 exige Bech32 y v1+ exige Bech32m.
    program = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
    assert is_valid_btc_bech32(_encode(0, program, BECH32))
    assert not is_valid_btc_bech32(_encode(0, program, BECH32M))
    assert is_valid_btc_bech32(_encode(1, program, BECH32M))
    assert not is_valid_btc_bech32(_encode(1, program, BECH32))


BECH32, BECH32M = 1, 0x2BC830A3


def _encode(version: int, program: bytes, const: int) -> str:
    """Codificador mínimo para construir casos de prueba con una constante concreta."""
    from tor_osint import crypto

    data = [version, *crypto._convertbits(list(program), 8, 5)]
    polymod = crypto._polymod([*crypto._hrp_expand("bc"), *data, 0, 0, 0, 0, 0, 0]) ^ const
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return "bc1" + "".join(crypto._CHARSET[d] for d in data + checksum)


# --- extractores -------------------------------------------------------------------------


def test_extract_btc():
    text = f"Pagos: {GENESIS}, {BIP173}. Falsa: {GENESIS[:-1]}b"
    assert {i.normalized for i in extract_btc(text)} == {GENESIS, BIP173.lower()}


def test_extract_eth_requires_checksum_when_mixed_case():
    good, bad = EIP55[0], EIP55[0][:2] + EIP55[0][2:].swapcase()
    null = "0x" + "0" * 40
    tx = "0x" + "ab" * 32  # hash de transacción, no dirección
    iocs = extract_eth(f"{good} {bad} {null} {tx}")
    assert [i.normalized for i in iocs] == [good.lower()]


def test_extract_attack():
    iocs = extract_attack("Usa T1059.001 y TA0001; t1059 y T12345 no cuentan")
    assert [i.normalized for i in iocs] == ["T1059.001", "TA0001"]


def test_extract_pgp():
    fpr = "3AA5 C34B 6E2F 4A9C 1B07  D6E5 2F8B 0C47 1D2A 9F11"
    iocs = extract_pgp(f"Huella: {fpr.lower()}")
    assert [i.normalized for i in iocs] == [fpr.replace(" ", "")]
    assert extract_pgp("1234 5678 9012 3456 7890 1234 5678 9012 3456 7890") == []


def test_new_types_do_not_leak_into_other_extractors():
    text = f"{EIP55[0]} {BIP173} T1059"
    types = {i.type for i in extract_iocs(text)}
    assert types == {"eth", "btc", "attack"}
