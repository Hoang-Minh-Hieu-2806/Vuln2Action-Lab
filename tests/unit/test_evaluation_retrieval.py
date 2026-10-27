"""Retrieval metrics and the evaluation harness (real computed scores only)."""

import json

from evaluation.retrieval import harness
from evaluation.retrieval.evaluate_retrieval import main as evaluate_cli
from evaluation.retrieval.harness import Benchmark, BenchmarkCase, evaluate, load_benchmark
from evaluation.retrieval.metrics import f1_at_k, mrr, precision_at_k, recall_at_k
from vuln2action.domain import KnowledgeDocument, RetrievedContext
from vuln2action.utils.filesystem import write_json

DOCUMENTS = [
    KnowledgeDocument(doc_id="CWE-89", text="CWE-89 SQL Injection: SQL commands"),
    KnowledgeDocument(doc_id="CWE-79", text="CWE-79 Cross-site Scripting: web output"),
    KnowledgeDocument(doc_id="CWE-22", text="CWE-22 Path Traversal: file paths"),
]


def _benchmark() -> Benchmark:
    return Benchmark(
        version="test",
        k=1,
        cases=[
            BenchmarkCase(
                case_id="C1",
                cve_id="CVE-1",
                query="sql injection",
                relevant=["CWE-89"],
            )
        ],
    )


def test_precision_recall_and_f1():
    assert precision_at_k(["A", "B"], {"A"}, 2) == 0.5
    assert precision_at_k(["A"], {"A"}, 3) == 1 / 3
    assert recall_at_k(["A", "B"], {"A", "C"}, 2) == 0.5
    assert f1_at_k(["A", "B"], {"A", "C"}, 2) == 0.5
    assert precision_at_k([], {"A"}, 2) == 0.0
    assert recall_at_k(["A"], set(), 2) == 0.0


def test_mrr():
    assert mrr([["B", "A"]], [{"A"}]) == 0.5
    assert mrr([["A", "B"]], [{"A"}]) == 1.0
    assert mrr([["B"]], [{"A"}]) == 0.0
    assert mrr([], []) == 0.0


def test_harness_computes_real_metrics():
    report = evaluate(["keyword", "tfidf"], DOCUMENTS, _benchmark())
    assert report["corpus_documents"] == 3
    assert report["benchmark_cases"] == 1
    keyword = report["results"]["keyword"]
    tfidf = report["results"]["tfidf"]
    assert keyword["precision"] == 1.0
    assert keyword["recall"] == 1.0
    assert keyword["mrr"] == 1.0
    assert keyword["mrr_at_k"] == 1.0
    assert tfidf["precision"] == 1.0
    assert keyword["cases"][0]["retrieved"][0] == "CWE-89"


def test_harness_mrr_uses_full_ranking(monkeypatch):
    class FakeBackend:
        def search(self, query, documents, top_k=3):
            ids = ["CWE-1", "CWE-2", "CWE-3", "CWE-4"][:top_k]
            return [
                RetrievedContext(source=doc_id, text=doc_id, score=1.0, backend="fake")
                for doc_id in ids
            ]

    monkeypatch.setattr(harness, "get_backend", lambda name: FakeBackend())
    corpus = [
        KnowledgeDocument(doc_id=f"CWE-{index}", text=f"document {index}") for index in range(1, 5)
    ]
    benchmark = Benchmark(
        k=3,
        cases=[
            BenchmarkCase(
                case_id="C1",
                cve_id="CVE-1",
                query="anything",
                relevant=["CWE-4"],
            )
        ],
    )
    result = evaluate(["fake"], corpus, benchmark)["results"]["fake"]
    assert result["precision"] == 0.0
    assert result["mrr"] == 0.25
    assert result["mrr_at_k"] == 0.0


def test_harness_reports_coverage_for_missing_labels():
    benchmark = Benchmark(
        k=1,
        cases=[
            BenchmarkCase(
                case_id="C1",
                cve_id="CVE-1",
                query="sql injection",
                relevant=["CWE-9999"],
            )
        ],
    )
    report = evaluate(["keyword"], DOCUMENTS, benchmark)
    assert report["results"]["keyword"]["cases_fully_covered"] == 0
    assert report["results"]["keyword"]["recall"] == 0.0


def test_load_benchmark_round_trip(tmp_path):
    path = write_json(
        tmp_path / "benchmark.json",
        {
            "version": "test",
            "k": 2,
            "cases": [
                {
                    "case_id": "C1",
                    "cve_id": "CVE-1",
                    "query": "query",
                    "relevant": ["CWE-89"],
                }
            ],
        },
    )
    benchmark = load_benchmark(path)
    assert benchmark.k == 2
    assert benchmark.cases[0].relevant == ["CWE-89"]


def test_evaluate_cli_writes_json_and_markdown(tmp_path):
    corpus = write_json(
        tmp_path / "corpus.json",
        {
            "version": "test",
            "documents": [document.model_dump(mode="json") for document in DOCUMENTS],
        },
    )
    benchmark = write_json(
        tmp_path / "benchmark.json",
        {
            "version": "test",
            "labels_source": "unit test",
            "k": 1,
            "cases": [
                {
                    "case_id": "C1",
                    "cve_id": "CVE-1",
                    "query": "sql injection",
                    "relevant": ["CWE-89"],
                }
            ],
        },
    )
    out_dir = tmp_path / "out"
    exit_code = evaluate_cli(
        [
            "--benchmark",
            str(benchmark),
            "--corpus",
            str(corpus),
            "--save",
            str(out_dir),
        ]
    )
    assert exit_code == 0
    run_dirs = list(out_dir.glob("retrieval_*"))
    assert len(run_dirs) == 1
    report = json.loads((run_dirs[0] / "report.json").read_text(encoding="utf-8"))
    assert set(report["results"]) == {"keyword", "tfidf", "semantic"}
    assert report["results"]["keyword"]["precision"] == 1.0
    assert (run_dirs[0] / "report.md").is_file()
