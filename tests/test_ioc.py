import pytest

from conftest import make_onion
from tor_osint.ioc import (
    candidate_normalizations,
    extract_cves,
    extract_domains,
    extract_emails,
    extract_hashes,
    extract_iocs,
    extract_ipv4,
    extract_onion_urls,
    extract_urls,
    normalize_cve,
    normalize_domain,
    normalize_email,
    normalize_hash,
    normalize_ipv4,
    normalize_url,
)

V3 = make_onion("ioc")
MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def norm(iocs):
    return [i.normalized for i in iocs]


# --- normalización ---------------------------------------------------------


def test_normalizers():
    assert normalize_email(" Admin@Example.COM ") == "admin@example.com"
    assert normalize_domain("Sub.Example.COM.") == "sub.example.com"
    assert normalize_cve("cve-2024-1234") == "CVE-2024-1234"
    assert normalize_hash(MD5.upper()) == MD5
    assert normalize_ipv4("8.8.8.8") == "8.8.8.8"
    assert (
        normalize_url("HTTPS://User:pw@Example.COM:443/Path?q=1#frag")
        == "https://example.com:443/Path?q=1"
    )


# --- emails -----------------------------------------------------------------


def test_emails_extracted_and_lowercased():
    text = "Contacto: Admin@Example.COM, soporte@mail.example.org."
    assert norm(extract_emails(text)) == ["admin@example.com", "soporte@mail.example.org"]


@pytest.mark.parametrize("text", ["logo@2x.png", "icon@3x.jpg", "no es email", "a@b", "x@@y.com"])
def test_email_false_positives(text):
    assert extract_emails(text) == []


# --- dominios ----------------------------------------------------------------


def test_domains_extracted_and_lowercased():
    text = "Visita Example.COM y https://sub.test.org/path; correo a john.doe@corp.net."
    assert norm(extract_domains(text)) == ["corp.net", "example.com", "sub.test.org"]


@pytest.mark.parametrize(
    "text",
    [
        "abre index.html o config.json",
        "usa Node.js y main.py",
        "versión 1.2.3",
        "e.g. i.e.",
        "john.doe@",  # parte local de un email incompleto
        f"{V3}.onion",
    ],
)
def test_domain_false_positives(text):
    assert extract_domains(text) == []


def test_email_local_part_is_not_a_domain():
    assert "john.doe" not in norm(extract_domains("first.last@example.com"))
    assert norm(extract_domains("first.last@example.com")) == ["example.com"]


# --- URLs -------------------------------------------------------------------


def test_urls_extracted_trailing_punct_stripped():
    text = "Ver (https://Example.com/a?b=1). Y http://test.org/x, fin"
    assert norm(extract_urls(text)) == ["http://test.org/x", "https://example.com/a?b=1"]


def test_urls_exclude_onion_and_hostless():
    assert extract_urls(f"http://{V3}.onion/ http://localhost/ https:// ") == []


# --- IPv4 -------------------------------------------------------------------


def test_ipv4_extracted():
    assert norm(extract_ipv4("C2 en 8.8.8.8 y 192.168.1.10.")) == ["192.168.1.10", "8.8.8.8"]


@pytest.mark.parametrize("text", ["999.1.1.1", "1.2.3.4.5", "01.02.03.04", "1.2.3", "v10.0.0.1234"])
def test_ipv4_false_positives(text):
    assert extract_ipv4(text) == []


# --- hashes -----------------------------------------------------------------


def test_hashes_by_type_and_lowercased():
    iocs = extract_hashes(f"{MD5.upper()} {SHA1} {SHA256}")
    assert {(i.type, i.normalized) for i in iocs} == {
        ("md5", MD5),
        ("sha1", SHA1),
        ("sha256", SHA256),
    }


@pytest.mark.parametrize(
    "text",
    [
        "1" * 32,  # solo dígitos
        "abcdef" * 6 + "ab",  # solo letras
        "0" * 64,
        MD5 + "ff",  # longitud 34: no es un hash conocido
        "g" + MD5[1:],  # carácter no hex
    ],
)
def test_hash_false_positives(text):
    assert extract_hashes(text) == []


# --- CVE --------------------------------------------------------------------


def test_cves_uppercased_and_deduplicated():
    assert norm(extract_cves("cve-2024-1234, CVE-2024-1234 y CVE-2021-44228")) == [
        "CVE-2021-44228",
        "CVE-2024-1234",
    ]


@pytest.mark.parametrize("text", ["CVE-24-1234", "CVE-2024-12", "CVE-1950-1234", "XCVE-2024-1234"])
def test_cve_false_positives(text):
    assert extract_cves(text) == []


# --- onion ------------------------------------------------------------------


def test_onion_urls_from_text_and_links():
    other = make_onion("otra")
    iocs = extract_onion_urls(f"mirror: {V3}.onion/foro.", [f"http://{other}.onion/x#frag"])
    assert norm(iocs) == sorted([f"http://{V3}.onion/foro", f"http://{other}.onion/x"])


def test_onion_with_bad_checksum_ignored():
    bad = ("b" if V3[0] != "b" else "c") + V3[1:]
    assert extract_onion_urls(f"http://{bad}.onion/") == []


# --- agregado ---------------------------------------------------------------


def test_extract_iocs_combines_all_types():
    text = f"a@b.com 8.8.8.8 CVE-2024-1234 {SHA256} https://x.org/ http://{V3}.onion/"
    types = {i.type for i in extract_iocs(text)}
    assert types == {"email", "domain", "ipv4", "cve", "sha256", "url", "onion"}


def test_candidate_normalizations():
    cands = candidate_normalizations("cve-2024-1234")
    assert "CVE-2024-1234" in cands
    assert "example.com" in candidate_normalizations("Example.COM")
    assert "https://example.com/A" in candidate_normalizations("HTTPS://EXAMPLE.com/A")
