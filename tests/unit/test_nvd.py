"""NVD parsing and client behaviour without network access."""

import pytest

from vuln2action.connectors.nvd import (
    NvdClient,
    parse_nvd_cve,
    parse_nvd_records,
    save_nvd_snapshot,
)


def _payload() -> dict:
    return {
        "resultsPerPage": 2,
        "startIndex": 0,
        "totalResults": 2,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {"lang": "es", "value": "descripcion"},
                        {"lang": "en", "value": "Apache Log4j2 remote code execution."},
                    ],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}]},
                    "weaknesses": [
                        {
                            "description": [
                                {"lang": "en", "value": "CWE-502"},
                                {"lang": "en", "value": "CWE-917"},
                            ]
                        }
                    ],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                    "references": [
                        {"url": "https://example.com/a"},
                        {"url": "https://example.com/a"},
                        {"url": "https://example.com/b"},
                    ],
                }
            },
            {
                "cve": {
                    "id": "CVE-2020-0001",
                    "vulnStatus": "Rejected",
                    "descriptions": [{"lang": "en", "value": "** REJECT **"}],
                }
            },
        ],
    }


def test_parse_nvd_cve_normalises_all_fields():
    record = parse_nvd_cve(_payload()["vulnerabilities"][0])
    assert record.cve_id == "CVE-2021-44228"
    assert record.description == "Apache Log4j2 remote code execution."
    assert record.cvss == 10.0
    assert record.cwe == ["CWE-502", "CWE-917"]
    assert record.cpe == ["cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"]
    assert record.references == ["https://example.com/a", "https://example.com/b"]
    assert record.lab_id == ""


def test_parse_nvd_cve_accepts_inner_object_and_description_fallback():
    inner = _payload()["vulnerabilities"][0]["cve"]
    inner["descriptions"] = [{"lang": "fr", "value": "une description"}]
    record = parse_nvd_cve(inner)
    assert record.description == "une description"


def test_parse_nvd_cve_uses_cvss_v2_fallback():
    record = parse_nvd_cve(
        {
            "id": "CVE-2019-0001",
            "descriptions": [{"lang": "en", "value": "legacy scoring"}],
            "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]},
        }
    )
    assert record.cvss == 5.0


def test_parse_nvd_cve_prefers_nvd_source_over_vendor_score():
    record = parse_nvd_cve(
        {
            "id": "CVE-2020-1472",
            "descriptions": [{"lang": "en", "value": "multiple CVSS sources"}],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "secure@microsoft.com",
                        "type": "Secondary",
                        "cvssData": {"baseScore": 5.5},
                    },
                    {
                        "source": "nvd@nist.gov",
                        "type": "Secondary",
                        "cvssData": {"baseScore": 10.0},
                    },
                ]
            },
        }
    )
    assert record.cvss == 10.0


def test_parse_nvd_cve_rejects_missing_description():
    with pytest.raises(ValueError, match="no description"):
        parse_nvd_cve({"id": "CVE-2019-0002", "descriptions": []})


def test_parse_nvd_records_skips_rejected_by_default():
    assert [r.cve_id for r in parse_nvd_records(_payload())] == ["CVE-2021-44228"]
    assert len(parse_nvd_records(_payload(), include_rejected=True)) == 2


def test_parse_nvd_records_requires_vulnerabilities_list():
    with pytest.raises(TypeError, match="vulnerabilities"):
        parse_nvd_records({"resultsPerPage": 0})


class FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict:
        return self._payload


class FakeSession:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.responses = list(responses)
        self.calls: list[dict] = []

    def get(self, url: str, params=None, headers=None, timeout=None) -> FakeResponse:
        self.calls.append({"url": url, "params": params, "headers": headers, "timeout": timeout})
        return self.responses.pop(0)


def _client(session: FakeSession, **kwargs) -> NvdClient:
    return NvdClient(session=session, min_interval=0, sleep=lambda _: None, **kwargs)


def test_fetch_cve_sends_upper_case_id_and_api_key():
    wrapper = _payload()["vulnerabilities"][0]
    session = FakeSession([FakeResponse(200, {"vulnerabilities": [wrapper]})])
    client = _client(session, api_key="secret")
    assert client.fetch_cve("cve-2021-44228")["cve"]["id"] == "CVE-2021-44228"
    call = session.calls[0]
    assert call["params"] == {"cveId": "CVE-2021-44228"}
    assert call["headers"]["apiKey"] == "secret"


def test_iter_cves_paginates_and_stops_at_max_records():
    page_one = {
        "totalResults": 3,
        "vulnerabilities": [{"cve": {"id": "A"}}, {"cve": {"id": "B"}}],
    }
    page_two = {"totalResults": 3, "vulnerabilities": [{"cve": {"id": "C"}}]}
    session = FakeSession([FakeResponse(200, page_one), FakeResponse(200, page_two)])
    items = list(_client(session).iter_cves(max_records=3, results_per_page=2))
    assert [item["cve"]["id"] for item in items] == ["A", "B", "C"]
    assert [call["params"]["startIndex"] for call in session.calls] == [0, 2]


def test_client_retries_on_retryable_status():
    wrapper = {"cve": {"id": "CVE-2021-44228"}}
    session = FakeSession([FakeResponse(429), FakeResponse(200, {"vulnerabilities": [wrapper]})])
    client = _client(session, max_retries=1, backoff_seconds=0)
    assert client.fetch_cve("CVE-2021-44228")["cve"]["id"] == "CVE-2021-44228"
    assert len(session.calls) == 2


def test_fetch_cve_raises_when_absent():
    session = FakeSession([FakeResponse(200, {"vulnerabilities": []})])
    with pytest.raises(KeyError, match="not found"):
        _client(session).fetch_cve("CVE-1999-0001")


def test_save_nvd_snapshot_writes_json(tmp_path):
    path = save_nvd_snapshot({"vulnerabilities": []}, out_dir=tmp_path, name="snap")
    assert path.name == "snap.json"
    assert '"vulnerabilities"' in path.read_text(encoding="utf-8")
