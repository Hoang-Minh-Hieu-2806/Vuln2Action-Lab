"""CAPEC benchmark evaluation: metrics, fair comparison, and provenance checks.

The evaluation must never inflate a score. These tests pin down the two protocols
(membership vs discriminative), the common-subset aggregation that keeps the
TF-IDF/Word2Vec comparison honest, and the fact that the tracked benchmark file
carries real, traceable labels.
"""

import csv
import json

import pytest

from evaluation.retrieval import evaluate_capec
from evaluation.retrieval.evaluate_capec import (
    CapecBenchmark,
    CapecBenchmarkCase,
    evaluate,
    load_capec_benchmark,
    summarise_rows,
)
from evaluation.retrieval.evaluate_capec import (
    main as evaluate_main,
)
from vuln2action.retrieval.capec import (
    build_capec_index,
    parse_capec_related_weaknesses,
)

CAPEC_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog>
  <Attack_Patterns>
    <Attack_Pattern ID="66" Name="SQL Injection">
      <Description>Constructs SQL statements from user input.</Description>
      <Related_Weaknesses><Related_Weakness CWE_ID="89" /></Related_Weaknesses>
    </Attack_Pattern>
    <Attack_Pattern ID="7" Name="Blind SQL Injection">
      <Description>Refines SQL injection queries without visible output.</Description>
      <Related_Weaknesses><Related_Weakness CWE_ID="89" /></Related_Weaknesses>
    </Attack_Pattern>
    <Attack_Pattern ID="80" Name="Query Timeouts">
      <Description>Exhausts server resources with slow queries.</Description>
      <Related_Weaknesses><Related_Weakness CWE_ID="400" /></Related_Weaknesses>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>
"""


@pytest.fixture()
def index():
    return build_capec_index(parse_capec_related_weaknesses(CAPEC_XML))


def _benchmark(cases: list[CapecBenchmarkCase]) -> CapecBenchmark:
    return CapecBenchmark(version="test", k=1, cases=cases)


def test_membership_and_discriminative_metrics_are_reported(index):
    benchmark = _benchmark(
        [
            CapecBenchmarkCase(
                case_id="C1",
                cve_id="CVE-1",
                query="SQL injection in a login form",
                cwe_ids=["CWE-89"],
                capec_label=["CAPEC-66", "CAPEC-7"],
                candidates=["CAPEC-66", "CAPEC-7"],
            )
        ]
    )
    report = evaluate(["tfidf"], benchmark, index)
    result = report["results"]["tfidf"]
    assert result["membership"]["top_1_accuracy"] == 1.0
    assert result["membership"]["correct"] == 1
    assert result["discriminative"]["recall_at_5"] == 1.0
    assert result["rows"][0]["predicted"] in {"CAPEC-66", "CAPEC-7"}


def test_membership_can_be_high_while_discriminative_is_not(index):
    """A correct-by-membership pick that is not the best candidate is exposed."""
    benchmark = _benchmark(
        [
            CapecBenchmarkCase(
                case_id="C1",
                cve_id="CVE-1",
                query="refines SQL injection queries without visible output",
                cwe_ids=["CWE-89"],
                # Both are in the label set, so membership alone cannot tell them
                # apart; graded relevance uses only the CVE's CWE list.
                capec_label=["CAPEC-66", "CAPEC-7"],
                candidates=["CAPEC-66", "CAPEC-7"],
            )
        ]
    )
    report = evaluate(["tfidf"], benchmark, index)
    row = report["results"]["tfidf"]["rows"][0]
    assert row["predicted"] == "CAPEC-7"
    assert row["membership_correct"] == 1.0


def test_empty_ranking_counts_against_the_method(index):
    benchmark = _benchmark(
        [
            CapecBenchmarkCase(
                case_id="C1",
                cve_id="CVE-1",
                query="zzzz qqqq",
                cwe_ids=["CWE-89"],
                capec_label=["CAPEC-66"],
                candidates=["CAPEC-66", "CAPEC-7"],
            )
        ]
    )
    result = evaluate(["tfidf"], benchmark, index)["results"]["tfidf"]
    assert result["empty_rankings"] == 1
    assert result["membership"]["top_1_accuracy"] == 0.0
    assert result["rows"][0]["ranked"] is False


def test_common_subset_excludes_cases_a_method_could_not_rank(index):
    benchmark = _benchmark(
        [
            CapecBenchmarkCase(
                case_id="C1",
                cve_id="CVE-1",
                query="SQL injection",
                cwe_ids=["CWE-89"],
                capec_label=["CAPEC-66"],
                candidates=["CAPEC-66", "CAPEC-7"],
            ),
            CapecBenchmarkCase(
                case_id="C2",
                cve_id="CVE-2",
                query="zzzz qqqq",
                cwe_ids=["CWE-89"],
                capec_label=["CAPEC-66"],
                candidates=["CAPEC-66", "CAPEC-7"],
            ),
        ]
    )
    report = evaluate(["tfidf"], benchmark, index)
    assert report["benchmark_cases"] == 2
    assert report["common_subset_size"] == 1
    common = report["results"]["tfidf"]["common_subset"]
    assert common["cases"] == 1
    assert common["membership"]["top_1_accuracy"] == 1.0


def test_summarise_rows_handles_empty_selection():
    summary = summarise_rows([], set())
    assert summary["cases"] == 0
    assert summary["membership"]["top_1_accuracy"] == 0.0
    assert summary["discriminative"]["ndcg"] == 0.0


def test_ndcg_is_none_when_graded_relevance_is_flat(index):
    """A single candidate CWE cannot discriminate, so NDCG is undefined."""
    benchmark = _benchmark(
        [
            CapecBenchmarkCase(
                case_id="C1",
                cve_id="CVE-1",
                query="SQL injection",
                cwe_ids=["CWE-89"],
                capec_label=["CAPEC-66"],
                candidates=["CAPEC-66"],
            )
        ]
    )
    result = evaluate(["tfidf"], benchmark, index)["results"]["tfidf"]
    assert result["rows"][0]["ndcg"] is None
    assert result["discriminative"]["evaluated_cases"] == 0


def test_benchmark_validator_rejects_duplicate_and_blank_ids(index):
    case = CapecBenchmarkCase(
        case_id="C1",
        cve_id="CVE-1",
        query="q",
        capec_label=["CAPEC-66", "CAPEC-66", " "],
        candidates=["CAPEC-7", "CAPEC-7"],
    )
    assert case.capec_label == ["CAPEC-66"]
    assert case.candidates == ["CAPEC-7"]


def test_evaluator_cli_writes_json_csv_and_markdown(index, tmp_path):
    benchmark_path = tmp_path / "benchmark.json"
    benchmark_path.write_text(
        json.dumps(
            {
                "version": "test",
                "labels_source": "unit test",
                "query_source": "unit test",
                "k": 1,
                "cases": [
                    {
                        "case_id": "C1",
                        "cve_id": "CVE-1",
                        "query": "SQL injection",
                        "cwe_ids": ["CWE-89"],
                        "capec_label": ["CAPEC-66"],
                        "candidates": ["CAPEC-66", "CAPEC-7"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    capec_xml = tmp_path / "capec.xml"
    capec_xml.write_text(CAPEC_XML, encoding="utf-8")
    out_dir = tmp_path / "out"

    exit_code = evaluate_main(
        [
            "--benchmark",
            str(benchmark_path),
            "--capec",
            str(capec_xml),
            "--methods",
            "tfidf",
            "--save",
            str(out_dir),
        ]
    )
    assert exit_code == 0
    run_dirs = list(out_dir.glob("capec_*"))
    assert len(run_dirs) == 1
    report = json.loads((run_dirs[0] / "report.json").read_text(encoding="utf-8"))
    assert report["results"]["tfidf"]["membership"]["top_1_accuracy"] == 1.0

    with (run_dirs[0] / "per_case.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows and rows[0]["method"] == "tfidf"
    assert rows[0]["cve_id"] == "CVE-1"
    assert (run_dirs[0] / "report.md").is_file()


def test_tracked_benchmark_is_real_and_traceable():
    benchmark = load_capec_benchmark(evaluate_capec._resolve(evaluate_capec.DEFAULT_BENCHMARK))
    assert len(benchmark.cases) >= 100, "acceptance criterion: at least 100 labelled CVEs"
    assert benchmark.labels_source.startswith("Galeax/CVE2CAPEC")
    assert "NVD" in benchmark.query_source

    cve_ids = [case.cve_id for case in benchmark.cases]
    case_ids = [case.case_id for case in benchmark.cases]
    assert len(set(cve_ids)) == len(cve_ids), "CVEs must be uniquely identified"
    assert len(set(case_ids)) == len(case_ids), "case ids must be unique"
    for case in benchmark.cases:
        assert case.cve_id.startswith("CVE-")
        assert case.query.strip()
        assert case.capec_label, "every case needs a ground-truth label"
        assert all(label.startswith("CAPEC-") for label in case.capec_label)
        assert all(cwe.startswith("CWE-") for cwe in case.cwe_ids)


def test_tracked_benchmark_labels_come_from_the_cwe_closure():
    """Document the measured circularity instead of claiming a strong result.

    Galeax derives its CAPEC sets by expanding CWEs, so we assert that the
    published label set really is the closure -- if this ever stops holding, the
    membership protocol becomes meaningful and the docs must be revisited.
    """
    from vuln2action.retrieval.capec import load_capec_index

    benchmark = load_capec_benchmark(evaluate_capec._resolve(evaluate_capec.DEFAULT_BENCHMARK))
    try:
        index = load_capec_index()
    except FileNotFoundError:
        pytest.skip("CAPEC snapshot not downloaded")

    closed = 0
    for case in benchmark.cases:
        closure = set(index.candidates_for_cwes(case.label_source_cwe))
        if closure and closure == set(case.capec_label):
            closed += 1
    ratio = closed / len(benchmark.cases)
    assert ratio > 0.99, (
        "labels are expected to equal the CWE->CAPEC closure; "
        f"only {ratio:.1%} of tracked cases did"
    )
