"""End-to-end CVE -> CWE -> CAPEC mapping through the analysis pipeline.

Uses the real tracked CAPEC snapshot when present (opt-in download) and skips
otherwise, so CI without the 3.8 MB catalog still passes.
"""

import pytest

from vuln2action.connectors import get_sample_cve, load_sample_cves
from vuln2action.domain import CveRecord
from vuln2action.pipeline import analyze_cve
from vuln2action.pipeline.analyze import resolve_capec
from vuln2action.retrieval.capec import default_capec_index


@pytest.fixture(autouse=True)
def _require_capec_snapshot():
    try:
        default_capec_index()
    except FileNotFoundError:
        pytest.skip("CAPEC snapshot not downloaded (scripts/download_data.py --source capec)")


def test_samples_map_to_plausible_capec_patterns():
    """CWE-79/89/22 should not land on an unrelated attack pattern."""
    expectations = {
        "CVE-2024-0001": {"CWE-79"},
        "CVE-2024-0002": {"CWE-89"},
        "CVE-2024-0003": {"CWE-22"},
    }
    index = default_capec_index()
    for cve in load_sample_cves():
        outcome = analyze_cve(cve, capec_method="tfidf")
        assert outcome.capec is not None, outcome.capec_note
        assert outcome.capec.cve_id == cve.cve_id
        assert outcome.capec.method == "tfidf"
        assert outcome.capec.candidates
        # The chosen CAPEC must genuinely be related to one of the CVE's CWEs.
        document = index.documents[outcome.capec.capec_id]
        assert set(document.cwe_ids) & expectations[cve.cve_id]


def test_analysis_outcome_serialises_capec():
    outcome = analyze_cve(get_sample_cve("CVE-2024-0002"))
    payload = outcome.model_dump(mode="json")
    assert payload["capec"]["capec_id"].startswith("CAPEC-")
    assert payload["capec"]["score"] >= 0.0


def test_workflow_and_capec_are_both_present():
    outcome = analyze_cve(get_sample_cve("CVE-2024-0001"))
    assert outcome.workflow.steps
    assert outcome.capec is not None
    assert "localhost" in outcome.workflow.safety


def test_cve_without_cwe_is_reported_not_guessed():
    mapping, note = resolve_capec(CveRecord(cve_id="DEMO-1", description="sql injection", cwe=[]))
    assert mapping is None
    assert "no CWE" in note


def test_cve_with_unmapped_cwe_is_reported_not_guessed():
    mapping, note = resolve_capec(
        CveRecord(cve_id="DEMO-2", description="something odd", cwe=["CWE-99999"])
    )
    assert mapping is None
    assert "no CAPEC candidates" in note


def test_unknown_method_is_a_caller_error():
    cve = get_sample_cve("CVE-2024-0002")
    with pytest.raises(ValueError, match="Unknown CAPEC ranking method"):
        analyze_cve(cve, capec_method="bert")


def test_word2vec_method_is_optional(monkeypatch):
    pytest.importorskip("gensim")
    cve = get_sample_cve("CVE-2024-0002")
    outcome = analyze_cve(cve, capec_method="word2vec")
    assert outcome.capec is not None
    assert outcome.capec.method == "word2vec"
    # Both methods must rank the same candidate pool for a fair comparison.
    tfidf_outcome = analyze_cve(cve, capec_method="tfidf")
    assert outcome.capec.candidates == tfidf_outcome.capec.candidates
