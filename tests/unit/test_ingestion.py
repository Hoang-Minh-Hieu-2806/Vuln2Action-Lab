"""Unit tests for ingestion schemas/parsers."""
from vuln2action.connectors import (
    get_sample_cve,
    load_sample_cves,
    lookup_cwe,
    parse_cpe,
    parse_cve_dict,
)


def test_parse_cve_dict_minimal():
    rec = parse_cve_dict({"cve_id": "CVE-X", "description": "d"})
    assert rec.cve_id == "CVE-X"
    assert rec.cwe == []


def test_load_sample_cves_has_three():
    recs = load_sample_cves()
    assert len(recs) == 3
    assert {r.cve_id for r in recs} == {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}


def test_get_sample_cve():
    assert get_sample_cve("CVE-2024-0001").lab_id == "cve-001"


def test_cwe_lookup_and_cpe_parse():
    assert lookup_cwe("CWE-79") is not None
    assert lookup_cwe("CWE-9999") is None
    assert parse_cpe("cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*").product == "p"
