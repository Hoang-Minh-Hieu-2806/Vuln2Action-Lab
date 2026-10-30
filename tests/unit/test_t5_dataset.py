"""T5 dataset builder: CAPEC phase extraction, ordering, and reproducibility.

Fixtures are tiny CAPEC catalogs so the tests stay offline. The tracked
``data/processed/t5_flows.json`` is git-ignored, so a separate test validates a
real build only when the CAPEC snapshot happens to be present.
"""

import pytest

from scripts.build_t5_dataset import (
    PHASES,
    TASK_PREFIX,
    MissingSourceError,
    build_input,
    build_payload,
    build_target,
    parse_capec_flows,
    split_records,
)

CAPEC_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3">
  <Attack_Patterns>
    <Attack_Pattern ID="66" Name="SQL Injection">
      <Description>Injects SQL through user input.</Description>
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="89" />
      </Related_Weaknesses>
      <Example_Instances>
        <Example>Login bypass in ExampleApp. See also: CVE-2006-5525</Example>
      </Example_Instances>
      <Execution_Flow>
        <Attack_Step>
          <Step>1</Step><Phase>Explore</Phase>
          <Description>Survey the application for inputs.</Description>
          <Technique>Use a proxy to record requests.</Technique>
        </Attack_Step>
        <Attack_Step>
          <Step>2</Step><Phase>Experiment</Phase>
          <Description>Probe with quote characters.</Description>
        </Attack_Step>
        <Attack_Step>
          <Step>3</Step><Phase>Exploit</Phase>
          <Description>Extract data with a tautology.</Description>
        </Attack_Step>
      </Execution_Flow>
    </Attack_Pattern>
    <Attack_Pattern ID="7" Name="Incomplete Flow">
      <Description>Only two phases are documented.</Description>
      <Execution_Flow>
        <Attack_Step>
          <Step>1</Step><Phase>Explore</Phase>
          <Description>Look around.</Description>
        </Attack_Step>
        <Attack_Step>
          <Step>2</Step><Phase>Exploit</Phase>
          <Description>Do the thing.</Description>
        </Attack_Step>
      </Execution_Flow>
    </Attack_Pattern>
    <Attack_Pattern ID="8" Name="No Flow">
      <Description>Nothing documented.</Description>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>
"""


@pytest.fixture()
def capec_path(tmp_path):
    path = tmp_path / "capec.xml"
    path.write_text(CAPEC_XML, encoding="utf-8")
    return path


def test_parse_keeps_only_complete_three_phase_flows(capec_path):
    records = parse_capec_flows(capec_path)
    assert [record["capec_id"] for record in records] == ["CAPEC-66"]


def test_parse_extracts_phases_in_order(capec_path):
    record = parse_capec_flows(capec_path)[0]
    assert [step["phase"] for step in record["steps"]] == list(PHASES)
    assert record["steps"][0]["techniques"] == ["Use a proxy to record requests."]


def test_steps_are_sorted_even_if_source_is_out_of_order(tmp_path):
    xml = CAPEC_XML.replace(
        "<Step>1</Step><Phase>Explore</Phase>", "<Step>9</Step><Phase>Explore</Phase>"
    )
    path = tmp_path / "capec.xml"
    path.write_text(xml, encoding="utf-8")
    record = parse_capec_flows(path)[0]
    assert [step["phase"] for step in record["steps"]] == list(PHASES)


def test_parse_collects_cwes_and_example_cves(capec_path):
    record = parse_capec_flows(capec_path)[0]
    assert record["cwe_ids"] == ["CWE-89"]
    assert record["cve_ids"] == ["CVE-2006-5525"]


def test_build_input_has_task_prefix_and_context():
    text = build_input("CAPEC-66", "SQL Injection", "Injects SQL.", ["CWE-89"], ["CVE-1"])
    assert text.startswith(TASK_PREFIX)
    assert "CAPEC-66 SQL Injection." in text
    assert "Weaknesses: CWE-89." in text
    assert "Known examples: CVE-1." in text


def test_build_target_renders_three_phases():
    steps = [
        {"step": "1", "phase": "Explore", "description": "survey", "techniques": ["proxy"]},
        {"step": "2", "phase": "Experiment", "description": "probe", "techniques": []},
        {"step": "3", "phase": "Exploit", "description": "extract", "techniques": []},
    ]
    target = build_target("CAPEC-66", "SQL Injection", steps)
    assert target.startswith("CAPEC-66 SQL Injection")
    assert "1. Explore: survey" in target
    assert "   - proxy" in target
    assert "3. Exploit: extract" in target


def test_split_is_deterministic_and_disjoint(capec_path):
    records = parse_capec_flows(capec_path)
    first_train, first_val = split_records(records, validation_fraction=0.5, seed=7)
    second_train, _second_val = split_records(records, validation_fraction=0.5, seed=7)
    assert [r["capec_id"] for r in first_train] == [r["capec_id"] for r in second_train]
    assert not ({r["capec_id"] for r in first_train} & {r["capec_id"] for r in first_val})


def test_split_guarantees_a_validation_slice_for_tiny_inputs(capec_path):
    records = parse_capec_flows(capec_path)
    train, validation = split_records(records, validation_fraction=0.99, seed=1)
    assert validation, "a single-record catalog must not silently skip validation"
    assert len(train) + len(validation) == len(records)


def test_split_rejects_invalid_fraction(capec_path):
    records = parse_capec_flows(capec_path)
    with pytest.raises(ValueError):
        split_records(records, validation_fraction=1.0)


def test_payload_declares_provenance_and_no_ground_truth_overclaim(capec_path):
    records = parse_capec_flows(capec_path)
    train, validation = split_records(records, validation_fraction=0.0)
    payload = build_payload(
        train, validation, source_path=capec_path, seed=13, validation_fraction=0.0
    )
    assert payload["provenance"]["source_kind"] == "MITRE CAPEC catalog Execution_Flow"
    assert "not validated reproduction steps" in payload["provenance"]["ground_truth_claim"]
    assert payload["limitations"]
    assert payload["phase_step_counts"]["Explore"] == 1


def test_missing_source_raises_actionable_error(tmp_path):
    with pytest.raises(MissingSourceError, match="download_data.py"):
        parse_capec_flows(tmp_path / "absent.xml")


def test_cli_writes_dataset(tmp_path, capec_path):
    from scripts.build_t5_dataset import main

    out = tmp_path / "flows.json"
    code = main(["--source", str(capec_path), "--out", str(out), "--validation-fraction", "0.0"])
    assert code == 0
    assert out.is_file()

    import json

    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["train_count"] == 1
    assert payload["train"][0]["capec_id"] == "CAPEC-66"


def test_real_capec_catalog_builds_when_available():
    """Only runs when the opt-in CAPEC snapshot has been downloaded."""
    from scripts.build_t5_dataset import parse_capec_flows as parse

    try:
        records = parse()
    except MissingSourceError:
        pytest.skip("CAPEC snapshot not downloaded")
    assert len(records) > 100
    for record in records[:5]:
        assert {step["phase"] for step in record["steps"]} == set(PHASES)
        assert record["target_flow"].startswith(record["capec_id"])
