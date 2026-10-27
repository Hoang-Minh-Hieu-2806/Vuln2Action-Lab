"""Phase-2 scripts: dataset building and snapshot helpers (no network)."""

import io
import json
import zipfile
from types import SimpleNamespace

import pytest

from scripts import build_dataset, download_data
from vuln2action.utils.filesystem import write_json


def _raw_payload() -> dict:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "sample description"}],
                    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }


def test_build_dataset_writes_processed_cves(tmp_path):
    raw = write_json(tmp_path / "raw" / "nvd.json", _raw_payload())
    out_dir = tmp_path / "processed"
    exit_code = build_dataset.main(["--nvd", str(raw), "--out-dir", str(out_dir)])
    assert exit_code == 0
    records = json.loads((out_dir / "cves.json").read_text(encoding="utf-8"))
    assert records[0]["cve_id"] == "CVE-2024-0001"
    assert records[0]["cwe"] == ["CWE-79"]


def test_build_dataset_applies_lab_map_and_catalogs(tmp_path):
    raw = write_json(tmp_path / "nvd.json", _raw_payload())
    lab_map = write_json(tmp_path / "lab_map.json", {"CVE-2024-0001": "cve-001"})
    cwe = tmp_path / "cwe.xml"
    cwe.write_text(
        '<Weakness_Catalog><Weaknesses><Weakness ID="79" Name="XSS">'
        "<Description>xss</Description></Weakness></Weaknesses></Weakness_Catalog>",
        encoding="utf-8",
    )
    out_dir = tmp_path / "processed"
    exit_code = build_dataset.main(
        [
            "--nvd",
            str(raw),
            "--cwe",
            str(cwe),
            "--lab-map",
            str(lab_map),
            "--out-dir",
            str(out_dir),
        ]
    )
    assert exit_code == 0
    records = json.loads((out_dir / "cves.json").read_text(encoding="utf-8"))
    assert records[0]["lab_id"] == "cve-001"
    cwes = json.loads((out_dir / "cwe.json").read_text(encoding="utf-8"))
    assert cwes[0]["cwe_id"] == "CWE-79"


def test_build_dataset_requires_an_input():
    with pytest.raises(SystemExit):
        build_dataset.main([])


def test_extract_xml_handles_zip_and_plain_bytes():
    xml = b"<root/>"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("catalog.xml", xml)
    assert download_data._extract_xml(buffer.getvalue()) == xml
    assert download_data._extract_xml(xml) == xml


def test_extract_xml_rejects_zip_without_xml():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("readme.txt", "no xml here")
    with pytest.raises(ValueError, match="no XML"):
        download_data._extract_xml(buffer.getvalue())


def _download_args(**overrides) -> SimpleNamespace:
    base = {"last_mod_start": "", "last_mod_end": "", "pub_start": "", "pub_end": ""}
    base.update(overrides)
    return SimpleNamespace(**base)


def test_nvd_query_params_translates_date_windows():
    args = _download_args(
        last_mod_start="2024-01-01T00:00:00Z",
        last_mod_end="2024-02-01T00:00:00Z",
    )
    assert download_data._nvd_query_params(args) == {
        "lastModStartDate": "2024-01-01T00:00:00Z",
        "lastModEndDate": "2024-02-01T00:00:00Z",
    }


def test_nvd_query_params_requires_paired_dates():
    with pytest.raises(ValueError, match="must be used together"):
        download_data._nvd_query_params(_download_args(pub_start="2024-01-01T00:00:00Z"))
