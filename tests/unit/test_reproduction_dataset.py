"""Paper-reproduction dataset construction and source parsers."""

from __future__ import annotations

import gzip
import json

from scripts import audit_reproduction_dataset, build_reproduction_dataset
from vuln2action.connectors.cve2capec import load_cve2capec
from vuln2action.connectors.exploitdb import parse_exploitdb_csv
from vuln2action.connectors.mitre import parse_capec_xml, parse_cwe_xml
from vuln2action.connectors.reproduction import (
    allocate_quotas,
    build_cve_cwe_pairs,
    build_cwe_capec_pairs,
    make_splits,
    sample_records_by_year,
)
from vuln2action.domain import CveRecord

CWE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Name="CWE" Version="4.13">
  <Weaknesses>
    <Weakness ID="79" Name="XSS">
      <Description>Improper neutralization.</Description>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="74" />
      </Related_Weaknesses>
      <Related_Attack_Patterns>
        <Related_Attack_Pattern CAPEC_ID="66" />
      </Related_Attack_Patterns>
    </Weakness>
    <Weakness ID="74" Name="Injection">
      <Description>Injection parent.</Description>
    </Weakness>
    <Weakness ID="89" Name="SQL Injection">
      <Description>SQL injection.</Description>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""

CAPEC_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3" Name="CAPEC" Version="3.9">
  <Attack_Patterns>
    <Attack_Pattern ID="66" Name="SQL Injection" Abstraction="Standard">
      <Description>An attacker injects SQL.</Description>
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="89" />
      </Related_Weaknesses>
      <Execution_Flow>
        <Attack_Step>
          <Step>1</Step>
          <Phase>Explore</Phase>
          <Description>Survey the target.</Description>
          <Technique>Fingerprint the database.</Technique>
        </Attack_Step>
        <Attack_Step>
          <Step>2</Step>
          <Phase>Exploit</Phase>
          <Description>Send the payload.</Description>
        </Attack_Step>
      </Execution_Flow>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>
"""


def _nvd_payload(cve_id: str) -> dict:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "published": "2023-01-01T00:00:00",
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": f"description for {cve_id}"}],
                    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
                }
            }
        ]
    }


def test_parse_cwe_xml_extracts_parent_and_capec():
    records = parse_cwe_xml(CWE_XML)
    by_id = {record.cwe_id: record for record in records}
    assert by_id["CWE-79"].parent_ids == ["CWE-74"]
    assert by_id["CWE-79"].related_capec_ids == ["CAPEC-66"]


def test_parse_capec_xml_extracts_flow_and_related_cwe():
    records = parse_capec_xml(CAPEC_XML)
    record = records[0]
    assert record.related_cwe_ids == ["CWE-89"]
    assert record.abstraction == "Standard"
    assert [step.phase for step in record.execution_flow] == ["Explore", "Exploit"]
    assert record.execution_flow[0].techniques == ["Fingerprint the database."]


def test_parse_exploitdb_csv_keeps_metadata_only():
    csv_text = (
        "id,file,description,date_published,author,type,platform,port,date_added,"
        "date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url\n"
        "1,exploits/test/1.py,Test exploit,2023-01-01,me,webapps,linux,,2023-01-01,"
        '2023-01-02,1,CVE-2023-0001;OSVDB-1,"tag one;tag two",,https://x,https://y,https://z\n'
    )
    records = parse_exploitdb_csv(csv_text)
    assert len(records) == 1
    assert records[0].exploit_id == "EDB-1"
    assert records[0].cve_ids == ["CVE-2023-0001"]
    assert records[0].code_url.endswith("/exploits/test/1.py")
    assert records[0].verified is True


def test_load_cve2capec_filters_selected_ids(tmp_path):
    path = tmp_path / "CVE-2023.jsonl.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write(json.dumps({"CVE-2023-0001": {"CWE": ["79"], "CAPEC": ["66"]}}) + "\n")
        handle.write(json.dumps({"CVE-2023-0002": {"CWE": ["89"], "CAPEC": ["7"]}}) + "\n")
    mapping = load_cve2capec(path, {"CVE-2023-0001"})
    assert set(mapping) == {"CVE-2023-0001"}
    assert mapping["CVE-2023-0001"].cwe_ids == ["CWE-79"]
    assert mapping["CVE-2023-0001"].capec_ids == ["CAPEC-66"]


def test_allocate_quotas_is_proportional_and_exact():
    quotas = allocate_quotas({2022: 100, 2023: 300}, 200)
    assert sum(quotas.values()) == 200
    assert quotas == {2022: 50, 2023: 150}


def test_sample_records_by_year_is_deterministic():
    records = {
        2022: [CveRecord(cve_id=f"CVE-2022-{i:04d}", description="x") for i in range(10)],
        2023: [CveRecord(cve_id=f"CVE-2023-{i:04d}", description="x") for i in range(10)],
    }
    first = sample_records_by_year(records, 10, seed=7)
    second = sample_records_by_year(records, 10, seed=7)
    assert [item.cve_id for item in first] == [item.cve_id for item in second]
    assert len(first) == 10


def test_build_cwe_capec_pairs_unions_both_directions():
    cwes = parse_cwe_xml(CWE_XML)
    capecs = parse_capec_xml(CAPEC_XML)
    pairs = build_cwe_capec_pairs(cwes, capecs)
    assert {"cwe_id": "CWE-79", "capec_id": "CAPEC-66"} in pairs
    assert {"cwe_id": "CWE-89", "capec_id": "CAPEC-66"} in pairs


def test_cve_cwe_pairs_flag_legacy_cwes():
    records = [CveRecord(cve_id="CVE-2023-0001", description="x", cwe=["CWE-79", "CWE-264"])]
    pairs = build_cve_cwe_pairs(records, known_cwe_ids={"CWE-79"})
    assert pairs == [
        {"cve_id": "CVE-2023-0001", "cwe_id": "CWE-79", "cwe_in_catalog": True},
        {"cve_id": "CVE-2023-0001", "cwe_id": "CWE-264", "cwe_in_catalog": False},
    ]


def test_make_splits_keeps_evaluation_sets_disjoint():
    cve_ids = [f"CVE-2023-{i:04d}" for i in range(200)]
    reference_ids = cve_ids[:80]
    splits = make_splits(cve_ids, reference_ids, seed=3, capec_eval_size=10, human_eval_size=5)
    train = set(splits["train"])
    validation = set(splits["validation"])
    capec_eval = set(splits["capec_eval_100"])
    human_eval = set(splits["human_eval_20"])
    assert len(capec_eval) == 10
    assert len(human_eval) == 5
    assert not (train & validation or train & capec_eval or train & human_eval)
    assert not (validation & capec_eval or validation & human_eval or capec_eval & human_eval)


def test_build_reproduction_dataset_script_end_to_end(tmp_path):
    raw = tmp_path / "raw"
    out = tmp_path / "processed"
    (raw / "nvd").mkdir(parents=True)
    (raw / "cve2capec").mkdir(parents=True)
    (raw / "exploitdb").mkdir(parents=True)
    with gzip.open(raw / "nvd" / "nvdcve-2.0-2023.json.gz", "wt", encoding="utf-8") as handle:
        json.dump(_nvd_payload("CVE-2023-0001"), handle)
    (raw / "cwe.xml").write_text(CWE_XML, encoding="utf-8")
    (raw / "capec.xml").write_text(CAPEC_XML, encoding="utf-8")
    (raw / "exploitdb" / "files_exploits.csv").write_text(
        "id,file,description,date_published,author,type,platform,port,date_added,"
        "date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url\n"
        "1,exploits/1.py,Test,2023-01-01,me,webapps,linux,,2023-01-01,2023-01-02,1,"
        "CVE-2023-0001,,,,,,\n",
        encoding="utf-8",
    )
    with gzip.open(raw / "cve2capec" / "CVE-2023.jsonl.gz", "wt", encoding="utf-8") as handle:
        handle.write(json.dumps({"CVE-2023-0001": {"CWE": ["79"], "CAPEC": ["66"]}}) + "\n")

    exit_code = build_reproduction_dataset.main(
        [
            "--nvd-feed-dir",
            str(raw / "nvd"),
            "--cwe",
            str(raw / "cwe.xml"),
            "--capec",
            str(raw / "capec.xml"),
            "--exploitdb",
            str(raw / "exploitdb" / "files_exploits.csv"),
            "--cve2capec",
            str(raw / "cve2capec"),
            "--out-dir",
            str(out),
            "--target-cves",
            "1",
            "--start-year",
            "2023",
            "--end-year",
            "2023",
        ]
    )
    assert exit_code == 0
    assert (out / "cves.jsonl").exists()
    assert (out / "cve_capec_candidates.jsonl").exists()
    stats = json.loads((out / "stats.json").read_text(encoding="utf-8"))
    assert stats["selected_cves"] == 1
    assert stats["cve_cwe_pairs"] == 1
    assert stats["cwe_capec_pairs"] >= 1
    report = audit_reproduction_dataset.audit(out)
    assert report["ok"], report
