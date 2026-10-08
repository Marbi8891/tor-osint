import gzip
import json

import pytest

from tor_osint.database import PageRecord, audit_entries, store_page
from tor_osint.dedup import content_hash
from tor_osint.enrich import cve_details, import_nvd, parse_cve
from tor_osint.ioc import Ioc
from tor_osint.report import build_report


def nvd_item(cve_id, metrics, description="Remote code execution"):
    return {
        "cve": {
            "id": cve_id,
            "published": "2021-12-10T10:15:09.143",
            "descriptions": [
                {"lang": "es", "value": "otra"},
                {"lang": "en", "value": description},
            ],
            "metrics": metrics,
        }
    }


V31 = {
    "cvssMetricV31": [
        {"cvssData": {"version": "3.1", "baseScore": 10.0, "baseSeverity": "CRITICAL"}}
    ]
}
V2 = {"cvssMetricV2": [{"cvssData": {"version": "2.0", "baseScore": 9.3}, "baseSeverity": "HIGH"}]}
V40_AND_V31 = {
    "cvssMetricV40": [{"cvssData": {"version": "4.0", "baseScore": 8.7, "baseSeverity": "HIGH"}}],
    **V31,
}


@pytest.fixture
def nvd_file(tmp_path):
    data = {
        "resultsPerPage": 3,
        "vulnerabilities": [
            nvd_item("CVE-2021-44228", V31),
            nvd_item("CVE-2010-0001", V2),
            nvd_item("CVE-2024-9999", {}),
            {"cve": {"sin": "id"}},
        ],
    }
    path = tmp_path / "nvd.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def seed(conn):
    iocs = [Ioc("cve", "CVE-2021-44228", "CVE-2021-44228"), Ioc("cve", "x", "CVE-2010-0001")]
    store_page(
        conn, PageRecord("http://a.onion/", "s", 200, "t", "x", content_hash("x"), iocs=iocs)
    )


def test_parse_cve_prefers_newest_cvss():
    assert parse_cve(nvd_item("CVE-1", V40_AND_V31))["cvss_version"] == "4.0"
    parsed = parse_cve(nvd_item("cve-2010-0001", V2))
    assert parsed["cve_id"] == "CVE-2010-0001"
    assert (parsed["cvss_score"], parsed["severity"]) == (9.3, "HIGH")
    assert parsed["description"] == "Remote code execution"
    assert parse_cve(nvd_item("CVE-2", {}))["cvss_score"] is None
    assert parse_cve({"nada": 1}) is None


def test_import_only_known_by_default(conn, nvd_file):
    seed(conn)
    result = import_nvd(conn, nvd_file)
    assert (result.read, result.imported, result.skipped_unknown) == (4, 2, 1)
    details = cve_details(conn)
    assert details["CVE-2021-44228"]["severity"] == "CRITICAL"
    assert "CVE-2024-9999" not in details
    entry = audit_entries(conn)[0]
    assert entry["action"] == "nvd.import" and result.sha256 in entry["details_json"]


def test_import_all_and_gzip_and_reimport_updates(conn, nvd_file, tmp_path):
    gz = tmp_path / "nvd.json.gz"
    gz.write_bytes(gzip.compress(nvd_file.read_bytes()))
    assert import_nvd(conn, gz, only_known=False).imported == 3
    assert import_nvd(conn, gz, only_known=False).imported == 3  # idempotente
    assert conn.execute("SELECT COUNT(*) FROM cve_info").fetchone()[0] == 3


@pytest.mark.parametrize("content", ["no es json", "[]", '{"otra": 1}'])
def test_import_rejects_invalid_files(conn, tmp_path, content):
    path = tmp_path / "bad.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError):
        import_nvd(conn, path)


def test_report_shows_cvss(conn, nvd_file):
    seed(conn)
    import_nvd(conn, nvd_file)
    html = build_report(conn, source_count=1)
    assert "CVSS (NVD)" in html and "10.0 CRITICAL" in html and "sev-CRITICAL" in html
