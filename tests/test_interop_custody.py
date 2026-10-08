"""STIX 2.1 (validado con la librería oficial de OASIS), MISP y cadena de custodia."""

import json

import pytest

from tor_osint.custody import record_artifact, sha256_file, verify_manifest
from tor_osint.database import PageRecord, audit_entries, store_page
from tor_osint.dedup import content_hash
from tor_osint.interop import (
    STIX_UNSUPPORTED,
    build_misp_event,
    build_stix_bundle,
    export_stix,
    stix_timestamp,
)
from tor_osint.ioc import extract_iocs

stix2 = pytest.importorskip("stix2")
from stix2patterns.validator import run_validator  # noqa: E402 - tras importorskip

TEXT = (
    "Contacto ops@example.com en evil-example.com (203.0.113.7), "
    "panel https://evil-example.com/login?x=1 y http://"
    "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/. "
    "Muestras d41d8cd98f00b204e9800998ecf8427e da39a3ee5e6b4b0d3255bfef95601890afd80709 "
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. "
    "Explota CVE-2021-44228 con T1059.001 y TA0001. Pago 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa "
    "o 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed. Clave 3AA5 C34B 6E2F 4A9C 1B07  D6E5 2F8B "
    "0C47 1D2A 9F11. Comilla en dominio raro o'brien.example.org"
)


@pytest.fixture
def seeded(conn):
    iocs = extract_iocs(TEXT)
    store_page(
        conn, PageRecord("http://a.onion/", "s", 200, "t", TEXT, content_hash(TEXT), iocs=iocs)
    )
    return conn


def test_stix_timestamp_format():
    assert stix_timestamp("2026-10-08T04:57:53+00:00") == "2026-10-08T04:57:53.000Z"


def test_stix_bundle_is_valid_per_oasis_library(seeded):
    bundle, skipped = build_stix_bundle(seeded)
    parsed = stix2.parse(json.dumps(bundle), allow_custom=False)  # lanza si no es conforme
    types = [o.type for o in parsed.objects]
    assert types[0] == "identity" and types[-1] == "report"
    assert {"indicator", "vulnerability", "attack-pattern"} <= set(types)
    assert skipped == 3  # btc, eth y pgp no tienen objeto núcleo en STIX 2.1
    for obj in bundle["objects"]:
        if obj["type"] == "indicator":
            assert run_validator(obj["pattern"]) == [], obj["pattern"]
    refs = set(bundle["objects"][-1]["object_refs"])
    assert refs == {o["id"] for o in bundle["objects"][:-1]}


def test_stix_patterns_by_type(seeded):
    bundle, _ = build_stix_bundle(seeded)
    patterns = {o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"}
    assert "[ipv4-addr:value = '203.0.113.7']" in patterns
    assert "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']" in patterns
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert f"[file:hashes.'SHA-256' = '{sha256}']" in patterns
    assert any(p.startswith("[url:value = 'http://2gzyxa5") for p in patterns)
    vulns = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
    assert vulns[0]["external_references"][0] == {
        "source_name": "cve",
        "external_id": "CVE-2021-44228",
    }
    attack = {o["name"]: o for o in bundle["objects"] if o["type"] == "attack-pattern"}
    assert attack["T1059.001"]["external_references"][0]["url"].endswith("techniques/T1059/001")
    assert attack["TA0001"]["external_references"][0]["url"].endswith("tactics/TA0001")


def test_stix_escapes_quotes_in_patterns(conn):
    from tor_osint.ioc import Ioc

    value = "http://example.com/a'b\\c"
    store_page(
        conn,
        PageRecord("http://a.onion/", "s", 200, "t", "x", "h", iocs=[Ioc("url", value, value)]),
    )
    bundle, _ = build_stix_bundle(conn)
    pattern = next(o["pattern"] for o in bundle["objects"] if o["type"] == "indicator")
    assert pattern == "[url:value = 'http://example.com/a\\'b\\\\c']"
    assert run_validator(pattern) == []
    stix2.parse(json.dumps(bundle), allow_custom=False)


def test_stix_unsupported_types_constant():
    assert set(STIX_UNSUPPORTED) == {"btc", "eth", "pgp"}


def test_misp_event(seeded):
    event = build_misp_event(seeded)["Event"]
    assert event["distribution"] == "0" and event["published"] is False
    attrs = {(a["type"], a["value"]): a for a in event["Attribute"]}
    assert attrs[("ip-dst", "203.0.113.7")]["to_ids"] is True
    assert attrs[("vulnerability", "CVE-2021-44228")]["category"] == "External analysis"
    assert ("btc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") in attrs
    assert attrs[("text", "T1059.001")]["comment"].startswith("MITRE ATT&CK")
    assert all(a["uuid"] and a["category"] for a in event["Attribute"])
    assert len({a["uuid"] for a in event["Attribute"]}) == len(event["Attribute"])


# --- cadena de custodia ----------------------------------------------------------------


def test_manifest_and_verify(seeded, tmp_path):
    path, _ = export_stix(seeded, tmp_path / "results.stix.json")
    entry = record_artifact(seeded, path, "export.stix")
    assert entry["sha256"] == sha256_file(path) and entry["file"] == "results.stix.json"
    other = tmp_path / "report.html"
    other.write_text("<p>informe</p>", encoding="utf-8")
    record_artifact(seeded, other, "report")
    assert verify_manifest(tmp_path).passed
    assert audit_entries(seeded)[0]["action"] == "artifact.report"

    other.write_text("<p>manipulado</p>", encoding="utf-8")
    path.unlink()
    result = verify_manifest(tmp_path)
    assert not result.passed
    assert result.modified == ["report.html"] and result.missing == ["results.stix.json"]


def test_regenerated_file_supersedes_previous_entry(conn, tmp_path):
    path = tmp_path / "r.json"
    path.write_text("v1", encoding="utf-8")
    record_artifact(conn, path, "export.json")
    path.write_text("v2", encoding="utf-8")
    record_artifact(conn, path, "export.json")
    assert verify_manifest(tmp_path).ok == ["r.json"]


def test_verify_errors(tmp_path):
    with pytest.raises(ValueError):
        verify_manifest(tmp_path)
    (tmp_path / "manifest.json").write_text("{roto", encoding="utf-8")
    with pytest.raises(ValueError):
        verify_manifest(tmp_path)
