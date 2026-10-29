"""Independent CAPEC evaluation: label independence, splits, and provenance.

These tests pin down the properties that make the independent set meaningful:
labels come from MITRE example text (not a CWE closure), unreachable labels are
counted rather than silently dropped, unlabelled cases are excluded from metrics
instead of being scored as failures, and the tracked file is verifiable.
"""

import json

import pytest

from evaluation.retrieval import evaluate_capec_independent as indep
from evaluation.retrieval.evaluate_capec_independent import (
    IndependentBenchmark,
    IndependentCase,
    LabelEvidence,
    evaluate_independent,
    load_independent_benchmark,
)
from evaluation.retrieval.evaluate_capec_independent import (
    main as evaluate_main,
)
from scripts.build_capec_independent import (
    build_cases,
    build_payload,
    extract_capec_example_labels,
    extract_cwe_observed_examples,
)
from vuln2action.retrieval.capec import build_capec_index, parse_capec_related_weaknesses

CAPEC_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3">
  <Attack_Patterns>
    <Attack_Pattern ID="66" Name="SQL Injection">
      <Description>Constructs SQL statements from user input.</Description>
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="89" />
      </Related_Weaknesses>
      <Example_Instances>
        <Example>SQL injection in ExampleApp login. See also: CVE-2006-5525</Example>
      </Example_Instances>
    </Attack_Pattern>
    <Attack_Pattern ID="7" Name="Blind SQL Injection">
      <Description>Refines SQL injection queries without visible output.</Description>
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="89" />
      </Related_Weaknesses>
    </Attack_Pattern>
    <Attack_Pattern ID="80" Name="Query Timeouts">
      <Description>Exhausts server resources with slow queries.</Description>
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="400" />
      </Related_Weaknesses>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>
"""

CWE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7">
  <Weaknesses>
    <Weakness ID="89" Name="SQL Injection">
      <Description>SQL elements.</Description>
      <Observed_Examples>
        <Observed_Example>
          <Reference>CVE-2006-5525</Reference>
          <Description>SQL injection in an application.</Description>
        </Observed_Example>
      </Observed_Examples>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""


@pytest.fixture()
def index():
    return build_capec_index(parse_capec_related_weaknesses(CAPEC_XML))


def test_extracts_mitre_example_labels_with_evidence(tmp_path):
    path = tmp_path / "capec.xml"
    path.write_text(CAPEC_XML, encoding="utf-8")
    evidence = extract_capec_example_labels(path)
    assert set(evidence) == {"CVE-2006-5525"}
    item = evidence["CVE-2006-5525"][0]
    assert item["capec_id"] == "CAPEC-66"
    assert item["capec_name"] == "SQL Injection"
    assert "CVE-2006-5525" in item["text"]


def test_extracts_cwe_observed_examples(tmp_path):
    path = tmp_path / "cwe.xml"
    path.write_text(CWE_XML, encoding="utf-8")
    observed = extract_cwe_observed_examples(path)
    assert observed == {"CVE-2006-5525": ["CWE-89"]}


def test_build_cases_uses_mitre_label_not_closure(index, monkeypatch):
    """The label must be the MITRE citation, even when the closure is larger."""
    import scripts.build_capec_independent as builder

    monkeypatch.setattr(builder, "load_capec_index", lambda: index)
    evidence = {"CVE-TEST-1": [{"capec_id": "CAPEC-7", "capec_name": "Blind", "text": "x"}]}
    records = {
        "CVE-TEST-1": {
            "cve_id": "CVE-TEST-1",
            "description": "blind sql injection",
            "cwe": ["CWE-89"],
        }
    }
    cases, stats = build_cases(evidence, {}, records)
    assert len(cases) == 1
    case = cases[0]
    # Closure of CWE-89 is {66, 7}; the MITRE label is only CAPEC-7.
    assert case["capec_label"] == ["CAPEC-7"]
    assert set(case["candidates"]) == {"CAPEC-66", "CAPEC-7"}
    assert set(case["capec_label"]) < set(case["candidates"])
    assert case["label_fully_reachable"] is True
    assert stats["evaluable"] == 1


def test_build_cases_flags_unreachable_labels(index, monkeypatch):
    import scripts.build_capec_independent as builder

    monkeypatch.setattr(builder, "load_capec_index", lambda: index)
    # CAPEC-80 relates to CWE-400, not CWE-89, so it is outside the pool.
    evidence = {"CVE-TEST-2": [{"capec_id": "CAPEC-80", "capec_name": "Timeouts", "text": "x"}]}
    records = {
        "CVE-TEST-2": {"cve_id": "CVE-TEST-2", "description": "slow query", "cwe": ["CWE-89"]}
    }
    cases, stats = build_cases(evidence, {}, records)
    assert cases[0]["label_fully_reachable"] is False
    assert cases[0]["label_reachable_in_candidates"] == []
    assert stats["label_unreachable"] == 1


def test_build_cases_falls_back_to_cwe_observed_examples(index, monkeypatch):
    import scripts.build_capec_independent as builder

    monkeypatch.setattr(builder, "load_capec_index", lambda: index)
    evidence = {"CVE-TEST-3": [{"capec_id": "CAPEC-66", "capec_name": "SQLi", "text": "x"}]}
    records = {"CVE-TEST-3": {"cve_id": "CVE-TEST-3", "description": "sql", "cwe": []}}
    cases, stats = build_cases(evidence, {"CVE-TEST-3": ["CWE-89"]}, records)
    assert cases[0]["cwe_source"] == "cwe-observed-examples"
    assert cases[0]["cwe_ids"] == ["CWE-89"]
    assert stats["cwe_from_cwe_observed_examples"] == 1


def test_build_cases_skips_missing_records_and_cwes(index, monkeypatch):
    import scripts.build_capec_independent as builder

    monkeypatch.setattr(builder, "load_capec_index", lambda: index)
    evidence = {"CVE-NONE": [{"capec_id": "CAPEC-66", "capec_name": "x", "text": "x"}]}
    cases, stats = build_cases(evidence, {}, {})
    assert cases == []
    assert stats["skipped_no_nvd_record"] == 1


def test_build_cases_requires_min_candidates(index, monkeypatch):
    import scripts.build_capec_independent as builder

    monkeypatch.setattr(builder, "load_capec_index", lambda: index)
    evidence = {"CVE-TEST-4": [{"capec_id": "CAPEC-80", "capec_name": "x", "text": "x"}]}
    records = {"CVE-TEST-4": {"cve_id": "CVE-TEST-4", "description": "q", "cwe": ["CWE-400"]}}
    cases, stats = build_cases(evidence, {}, records, min_candidates=2)
    assert cases == []
    assert stats["skipped_too_few_candidates"] == 1


def test_build_payload_declares_independence(index, monkeypatch):
    import scripts.build_capec_independent as builder

    monkeypatch.setattr(builder, "load_capec_index", lambda: index)
    payload = build_payload([], {"evaluable": 0})
    assert payload["kind"] == "independent"
    assert "Example_Instances" in payload["labels_source"]
    assert "closure" in payload["description"].lower()
    assert payload["labeling_criteria"]
    assert payload["uncertainty"]


def _case(case_id, cve_id, label, candidates, status="mitre-evidence"):
    return IndependentCase(
        case_id=case_id,
        cve_id=cve_id,
        query="sql injection in a login form",
        cwe_ids=["CWE-89"],
        capec_label=label,
        candidates=candidates,
        label_evidence=[LabelEvidence(capec_id=label[0], capec_name="x", text="e")],
        review_status=status,
    )


def _benchmark(cases):
    return IndependentBenchmark(version="test", k=1, cases=cases)


def test_evaluate_reports_all_and_reachable_splits(index):
    benchmark = _benchmark(
        [
            _case("C1", "CVE-1", ["CAPEC-66"], ["CAPEC-66", "CAPEC-7"]),
            _case("C2", "CVE-2", ["CAPEC-80"], ["CAPEC-66", "CAPEC-7"]),  # unreachable
        ]
    )
    report = evaluate_independent(["tfidf"], benchmark, index)
    assert report["labeled_cases"] == 2
    assert report["reachable_cases"] == 1
    assert report["coverage"] == 0.5
    assert report["results"]["tfidf"]["all"]["cases"] == 2
    assert report["results"]["tfidf"]["reachable"]["cases"] == 1
    assert report["unreachable_cases"] == 1


def test_unreachable_label_counts_as_miss_in_all_split(index):
    benchmark = _benchmark([_case("C1", "CVE-1", ["CAPEC-80"], ["CAPEC-66", "CAPEC-7"])])
    report = evaluate_independent(["tfidf"], benchmark, index)
    block = report["results"]["tfidf"]["all"]
    assert block["membership"]["top_1_accuracy"] == 0.0
    assert block["failures"][0]["cve_id"] == "CVE-1"


def test_unlabeled_cases_are_excluded_not_penalised(index):
    benchmark = _benchmark(
        [
            _case("C1", "CVE-1", ["CAPEC-66"], ["CAPEC-66", "CAPEC-7"]),
            _case("C2", "CVE-2", ["CAPEC-66"], ["CAPEC-66"], status="pending-review"),
        ]
    )
    report = evaluate_independent(["tfidf"], benchmark, index)
    assert report["labeled_cases"] == 1
    assert report["unlabeled_case_ids"] == ["C2"]
    block = report["results"]["tfidf"]["all"]
    assert block["cases"] == 1
    assert block["membership"]["top_1_accuracy"] == 1.0


def test_labels_without_review_status_do_not_count(index):
    case = _case("C1", "CVE-1", ["CAPEC-66"], ["CAPEC-66"], status="rejected")
    assert case.is_labeled is False


def test_failure_rows_are_reported(index):
    benchmark = _benchmark([_case("C1", "CVE-1", ["CAPEC-7"], ["CAPEC-66", "CAPEC-7"])])
    report = evaluate_independent(["tfidf"], benchmark, index)
    failures = report["results"]["tfidf"]["all"]["failures"]
    # Either it picked CAPEC-7 (correct) or it failed with a recorded reason.
    for failure in failures:
        assert failure["reason"] in {"no ranking (no shared vocabulary)", "wrong top-1"}


def test_cli_writes_reports(index, tmp_path, monkeypatch):
    import evaluation.retrieval.evaluate_capec_independent as module

    monkeypatch.setattr(module, "load_capec_index", lambda path=None: index)
    capec_path = tmp_path / "capec.xml"
    capec_path.write_text(CAPEC_XML, encoding="utf-8")
    benchmark_path = tmp_path / "indep.json"
    benchmark_path.write_text(
        json.dumps(
            {
                "version": "test",
                "kind": "independent",
                "labels_source": "unit test",
                "k": 1,
                "cases": [
                    {
                        "case_id": "C1",
                        "cve_id": "CVE-1",
                        "query": "sql injection",
                        "cwe_ids": ["CWE-89"],
                        "capec_label": ["CAPEC-66"],
                        "candidates": ["CAPEC-66", "CAPEC-7"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    out_dir = tmp_path / "out"
    code = evaluate_main(
        [
            "--benchmark",
            str(benchmark_path),
            "--capec",
            str(capec_path),
            "--methods",
            "tfidf",
            "--save",
            str(out_dir),
        ]
    )
    assert code == 0
    run_dirs = list(out_dir.glob("capec_independent_*"))
    assert len(run_dirs) == 1
    report = json.loads((run_dirs[0] / "report.json").read_text(encoding="utf-8"))
    assert report["total_cases"] == 1
    assert (run_dirs[0] / "per_case.csv").is_file()
    assert (run_dirs[0] / "report.md").is_file()


def test_tracked_independent_set_is_verifiable():
    benchmark = load_independent_benchmark(indep._resolve(indep.DEFAULT_BENCHMARK))
    assert benchmark.kind == "independent"
    assert len(benchmark.cases) >= 20, "acceptance criterion: 20-30 independent cases"
    assert "Example_Instances" in benchmark.labels_source
    assert benchmark.labeling_criteria and benchmark.uncertainty

    cve_ids = [case.cve_id for case in benchmark.cases]
    assert len(set(cve_ids)) == len(cve_ids)
    for case in benchmark.cases:
        assert case.cve_id.startswith("CVE-")
        assert case.query.strip()
        assert case.capec_label, "independent labels must be explicit"
        assert case.label_evidence, "every label must carry MITRE evidence text"
        assert all(item.capec_id in case.capec_label for item in case.label_evidence)
        assert case.cwe_source in {"nvd", "cwe-observed-examples"}


def test_tracked_labels_are_not_the_cwe_closure():
    """The whole point: labels must differ from the candidate closure.

    If every label equalled the closure again, the independent set would have
    collapsed back into the circular 120-case benchmark.
    """
    from vuln2action.retrieval.capec import load_capec_index

    try:
        index = load_capec_index()
    except FileNotFoundError:
        pytest.skip("CAPEC snapshot not downloaded")

    benchmark = load_independent_benchmark(indep._resolve(indep.DEFAULT_BENCHMARK))
    identical = 0
    for case in benchmark.cases:
        closure = set(index.candidates_for_cwes(case.cwe_ids))
        if closure and closure == set(case.capec_label):
            identical += 1
    assert identical == 0, "independent labels must never equal the candidate closure"
