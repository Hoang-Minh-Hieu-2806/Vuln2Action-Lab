"""CAPEC candidate expansion, ranking, and deterministic behaviour.

Fixtures are tiny hand-written XML catalogs so the tests stay offline and do not
depend on the 3.8 MB MITRE snapshot.
"""

import pytest

from vuln2action.retrieval.capec import (
    CapecDocument,
    CapecIndex,
    MissingDependencyError,
    build_capec_index,
    clear_capec_cache,
    map_cve_to_capec,
    parse_capec_related_weaknesses,
    rank_candidates,
    tfidf_cosine_scores,
)

CAPEC_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3">
  <Attack_Patterns>
    <Attack_Pattern ID="66" Name="SQL Injection">
      <Description>An attacker constructs SQL statements from user input.</Description>
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="89" />
        <Related_Weakness CWE_ID="1286" />
      </Related_Weaknesses>
    </Attack_Pattern>
    <Attack_Pattern ID="7" Name="Blind SQL Injection">
      <Description>An attacker refines a query using blind SQL injection.</Description>
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="89" />
      </Related_Weaknesses>
    </Attack_Pattern>
    <Attack_Pattern ID="80" Name="Using Query Timeouts">
      <Description>Slow queries can exhaust server resources.</Description>
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="400" />
      </Related_Weaknesses>
    </Attack_Pattern>
    <Attack_Pattern ID="999" Name="Pattern Without Weakness">
      <Description>No related weakness is declared.</Description>
    </Attack_Pattern>
    <Attack_Pattern ID="66" Name="Duplicate SQL Injection">
      <Description>Duplicate entry that must be ignored.</Description>
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="20" />
      </Related_Weaknesses>
    </Attack_Pattern>
    <Attack_Pattern ID="88" Name="OS Command Injection">
      <Description>An attacker injects operating system commands.</Description>
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="78" />
        <Related_Weakness CWE_ID="89" />
      </Related_Weaknesses>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>
"""


@pytest.fixture()
def index() -> CapecIndex:
    return build_capec_index(parse_capec_related_weaknesses(CAPEC_XML), source="fixture")


def test_parse_extracts_related_weaknesses_and_dedupes(index: CapecIndex):
    assert sorted(index.documents) == ["CAPEC-66", "CAPEC-7", "CAPEC-80", "CAPEC-88", "CAPEC-999"]
    # First occurrence wins for duplicate ids.
    assert index.documents["CAPEC-66"].name == "SQL Injection"
    assert index.documents["CAPEC-66"].cwe_ids == ["CWE-89", "CWE-1286"]
    assert index.documents["CAPEC-999"].cwe_ids == []


def test_candidates_are_the_union_of_cwe_relations(index: CapecIndex):
    assert index.candidates_for_cwes(["CWE-89"]) == ["CAPEC-66", "CAPEC-7", "CAPEC-88"]
    assert index.candidates_for_cwes(["CWE-89", "CWE-400"]) == [
        "CAPEC-66",
        "CAPEC-7",
        "CAPEC-80",
        "CAPEC-88",
    ]


def test_candidates_ignore_missing_and_malformed_cwe_ids(index: CapecIndex):
    assert index.candidates_for_cwes([]) == []
    assert index.candidates_for_cwes(["", "  ", "BOGUS", "CWE-XXXX"]) == []
    # Unmapped but well-formed ids are simply absent from the index.
    assert index.candidates_for_cwes(["CWE-12345"]) == []
    # Mixed input keeps whatever the valid ones contribute.
    assert index.candidates_for_cwes(["BOGUS", "cwe-400"]) == ["CAPEC-80"]


def test_pattern_without_cwe_is_never_a_candidate(index: CapecIndex):
    assert "CAPEC-999" not in index.candidates_for_cwes(["CWE-89", "CWE-400", "CWE-78", "CWE-20"])


def test_tfidf_ranking_prefers_matching_pattern(index: CapecIndex):
    ranked = rank_candidates(
        "SQL injection via crafted user input in a login form",
        ["CWE-89"],
        method="tfidf",
        index=index,
    )
    assert ranked
    assert ranked[0][0] in {"CAPEC-66", "CAPEC-7"}
    assert all(score > 0 for _, score in ranked)


def test_tfidf_scores_aligned_with_candidates(index: CapecIndex):
    candidates = ["CAPEC-66", "CAPEC-7"]
    scored = tfidf_cosine_scores("blind sql injection", index, candidates)
    assert [capec_id for capec_id, _ in scored] == candidates
    scores = dict(scored)
    assert scores["CAPEC-7"] > scores["CAPEC-66"]


def test_zero_overlap_yields_empty_ranking(index: CapecIndex):
    """No shared vocabulary means no ranking, not a silent arbitrary pick."""
    assert rank_candidates("zzzz qqqq", ["CWE-89"], method="tfidf", index=index) == []


def test_ties_are_broken_by_capec_id_deterministically():
    documents = [
        CapecDocument(capec_id="CAPEC-22", name="Same", description="same body", cwe_ids=["CWE-1"]),
        CapecDocument(capec_id="CAPEC-11", name="Same", description="same body", cwe_ids=["CWE-1"]),
    ]
    index = build_capec_index(documents)
    first = rank_candidates("same body", ["CWE-1"], method="tfidf", index=index)
    second = rank_candidates("same body", ["CWE-1"], method="tfidf", index=index)
    assert [capec_id for capec_id, _ in first] == ["CAPEC-11", "CAPEC-22"]
    assert first == second


def test_unknown_method_raises(index: CapecIndex):
    with pytest.raises(ValueError, match="Unknown CAPEC ranking method"):
        rank_candidates("sql injection", ["CWE-89"], method="bert", index=index)


def test_map_cve_to_capec_reports_candidates_and_margin(index: CapecIndex):
    mapping = map_cve_to_capec(
        "CVE-TEST-1",
        "SQL injection in the login form",
        ["CWE-89"],
        method="tfidf",
        index=index,
    )
    assert mapping is not None
    assert mapping.cve_id == "CVE-TEST-1"
    assert mapping.method == "tfidf"
    assert mapping.candidates == ["CAPEC-66", "CAPEC-7", "CAPEC-88"]
    assert mapping.capec_id == mapping.ranked[0][0]
    assert mapping.runner_up == mapping.ranked[1][0]
    assert mapping.margin >= 0.0


def test_map_returns_none_without_candidates(index: CapecIndex):
    assert map_cve_to_capec("CVE-X", "anything", ["CWE-98765"], index=index) is None
    assert map_cve_to_capec("CVE-X", "anything", [], index=index) is None


def test_map_returns_none_when_query_has_no_content_tokens(index: CapecIndex):
    assert map_cve_to_capec("CVE-X", "the and of", ["CWE-89"], index=index) is None


def test_word2vec_requires_optional_dependency(index: CapecIndex, monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "gensim":
            raise ImportError("no gensim")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(MissingDependencyError, match="gensim"):
        from vuln2action.retrieval.capec import train_word2vec

        train_word2vec(index)


def test_word2vec_ranks_same_candidates_when_available(index: CapecIndex):
    pytest.importorskip("gensim")
    from vuln2action.retrieval.capec import train_word2vec

    model = train_word2vec(index, vector_size=32, epochs=200)
    ranked = rank_candidates(
        "blind SQL injection query",
        ["CWE-89"],
        method="word2vec",
        index=index,
        word2vec_model=model,
    )
    # Same candidate pool as TF-IDF; the learned order itself is not asserted.
    assert {capec_id for capec_id, _ in ranked} == {"CAPEC-66", "CAPEC-7", "CAPEC-88"}
    assert [score for _, score in ranked] == sorted([score for _, score in ranked], reverse=True)
    repeat = rank_candidates(
        "blind SQL injection query",
        ["CWE-89"],
        method="word2vec",
        index=index,
        word2vec_model=model,
    )
    assert repeat == ranked


def test_default_index_loads_tracked_snapshot():
    clear_capec_cache()
    from vuln2action.retrieval.capec import default_capec_index

    try:
        index = default_capec_index()
    except FileNotFoundError:
        pytest.skip(
            "CAPEC snapshot not downloaded (python scripts/download_data.py --source capec)"
        )
    assert "CAPEC-66" in index.documents
    assert index.candidates_for_cwes(["CWE-89"])
    # CWE-89 is a real, widely mapped weakness.
    assert "CAPEC-66" in index.candidates_for_cwes(["CWE-89"])
