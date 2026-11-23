"""Provenance records only retrieval metadata that the runtime exposes."""

from vuln2action.domain import EvidenceBundle, Workflow
from vuln2action.evidence.provenance import NOT_AVAILABLE, build_provenance

STEP = {"id": "lab-up", "action": "Start lab", "detail": "Start the lab."}


def _payload(generation):
    workflow = Workflow(cve_id="CVE-TEST", provider="rule_based", steps=[STEP])
    evidence = EvidenceBundle(
        collected_at="2026-01-01T00:00:00+00:00",
        generation=generation,
    )
    return {
        "workflow": workflow.model_dump(mode="json"),
        "evidence": evidence.model_dump(mode="json"),
    }


def test_runtime_retrieval_metadata_is_recorded():
    generation = {
        "provider": "rule_based",
        "retrieval_backend": "semantic",
        "input": {
            "cve_id": "CVE-TEST",
            "context_items": [
                {"source": "CWE-79", "score": 0.8, "backend": "semantic"},
                {"source": "CWE-89", "score": 0.2, "backend": "keyword"},
            ],
        },
    }
    document = build_provenance(_payload(generation))
    assert document.retrieval.backend == "semantic"
    assert [item["rank"] for item in document.retrieval.items] == [1, 2]
    assert document.retrieval.items[0]["retrieval_score"] == 0.8
    assert document.retrieval.items[0]["context_backend"] == "semantic"
    assert document.retrieval.items[0]["source_url"] == NOT_AVAILABLE


def test_capec_score_is_not_used_as_retrieval_score():
    generation = {
        "provider": "rule_based",
        "retrieval_backend": "semantic",
        "input": {"context_sources": ["CWE-79"]},
    }
    payload = _payload(generation)
    payload["evidence"]["generation"]["capec"] = {"score": 0.99}
    document = build_provenance(payload)
    assert document.retrieval.items[0]["retrieval_score"] == NOT_AVAILABLE
    assert document.retrieval.backend == "semantic"


def test_missing_backend_metadata_stays_unavailable():
    generation = {
        "provider": "rule_based",
        "input": {
            "context_items": [{"source": "CWE-79", "score": None, "backend": None}]
        },
    }
    document = build_provenance(_payload(generation))
    assert document.retrieval.backend == NOT_AVAILABLE
    assert document.retrieval.items[0]["retrieval_score"] == NOT_AVAILABLE
    assert document.retrieval.items[0]["context_backend"] == NOT_AVAILABLE


def test_empty_context_has_no_items():
    document = build_provenance(
        _payload({"provider": "rule_based", "input": {"context_items": []}})
    )
    assert document.retrieval.items == []
