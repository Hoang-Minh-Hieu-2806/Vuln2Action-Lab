"""Retrieval backends, corpus loading, and context merging."""

import pytest

from vuln2action.connectors import get_sample_cve
from vuln2action.connectors.dataset import write_cwe_dataset
from vuln2action.domain import CveRecord, CweRecord, KnowledgeDocument
from vuln2action.retrieval import (
    KeywordBackend,
    SemanticBackend,
    SemanticContext,
    SemanticEnricher,
    TfidfBackend,
    build_contexts_for_cve,
    build_corpus,
    build_semantic_contexts,
    default_semantic_enricher,
    document_text,
    get_backend,
    load_seed_corpus,
)
from vuln2action.retrieval.semantic import ParentWeakness, RelatedAttackPattern

DOCUMENTS = [
    KnowledgeDocument(
        doc_id="CWE-89",
        text="CWE-89 SQL Injection: improper neutralisation of SQL commands",
    ),
    KnowledgeDocument(
        doc_id="CWE-79",
        text="CWE-79 Cross-site Scripting: improper neutralisation during web page generation",
    ),
    KnowledgeDocument(
        doc_id="CWE-22",
        text="CWE-22 Path Traversal: improper limitation of a pathname to a directory",
    ),
]


def test_keyword_backend_ranks_matching_document():
    hits = KeywordBackend().search("sql injection login", DOCUMENTS, top_k=1)
    assert hits[0].source == "CWE-89"
    assert hits[0].backend == "keyword"
    assert hits[0].score > 0


def test_tfidf_backend_returns_typed_contexts():
    hits = TfidfBackend().search("path traversal download", DOCUMENTS, top_k=2)
    assert hits[0].source == "CWE-22"
    assert 1 <= len(hits) <= 2
    assert all(hit.backend == "tfidf" for hit in hits)
    assert all(hit.score > 0 for hit in hits)


def test_semantic_backend_uses_mitre_metadata():
    documents = [
        KnowledgeDocument(
            doc_id="CWE-78",
            name="OS Command Injection",
            text="CWE-78 OS Command Injection: constructs an OS command from external input",
        ),
        KnowledgeDocument(
            doc_id="CWE-79",
            name="Cross-site Scripting",
            text="CWE-79 Cross-site Scripting: improper neutralisation during web page generation",
        ),
    ]
    enricher = SemanticEnricher(
        {
            "CWE-78": SemanticContext(
                doc_id="CWE-78",
                alternate_terms=["Shell injection"],
                related_attack_patterns=[
                    RelatedAttackPattern(capec_id="CAPEC-88", name="OS Command Injection")
                ],
                parents=[
                    ParentWeakness(
                        cwe_id="CWE-77",
                        name="Command Injection",
                        description="neutralisation of special elements in a command",
                    )
                ],
            )
        }
    )
    hits = SemanticBackend(enricher=enricher).search(
        "ShellShock environment variables execute commands", documents, top_k=1
    )
    assert hits[0].source == "CWE-78"
    assert hits[0].backend == "semantic"
    assert hits[0].score > 0


def test_semantic_context_parser_extracts_metadata():
    cwe_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7">
      <Weaknesses>
        <Weakness ID="77" Name="Command Injection">
          <Description>Neutralises commands incorrectly.</Description>
        </Weakness>
        <Weakness ID="78" Name="OS Command Injection">
          <Description>Builds an OS command from input.</Description>
          <Alternate_Terms>
            <Alternate_Term><Term>Shell injection</Term></Alternate_Term>
          </Alternate_Terms>
          <Related_Attack_Patterns>
            <Related_Attack_Pattern CAPEC_ID="88" />
          </Related_Attack_Patterns>
          <Related_Weaknesses>
            <Related_Weakness Nature="ChildOf" CWE_ID="77" />
          </Related_Weaknesses>
        </Weakness>
      </Weaknesses>
    </Weakness_Catalog>
    """
    capec_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3">
      <Attack_Patterns>
        <Attack_Pattern ID="88" Name="OS Command Injection" />
      </Attack_Patterns>
    </Attack_Pattern_Catalog>
    """
    contexts = build_semantic_contexts(cwe_xml, capec_xml)
    context = contexts["CWE-78"]
    assert context.alternate_terms == ["Shell injection"]
    assert context.related_attack_patterns[0].capec_id == "CAPEC-88"
    assert context.related_attack_patterns[0].name == "OS Command Injection"
    assert context.parents[0].cwe_id == "CWE-77"
    assert context.parents[0].description == "Neutralises commands incorrectly."


def test_tracked_semantic_context_covers_seed_corpus():
    enricher = default_semantic_enricher()
    assert "CWE-78" in enricher.contexts
    assert enricher.contexts["CWE-78"].alternate_terms
    assert enricher.contexts["CWE-78"].related_attack_patterns
    assert enricher.contexts["CWE-78"].parents


def test_keyword_backend_returns_no_zero_score_hits():
    assert KeywordBackend().search("the and of", DOCUMENTS, top_k=2) == []


def test_semantic_backend_returns_no_hits_for_stopword_only_query():
    assert SemanticBackend().search("the and of", DOCUMENTS, top_k=2) == []


def test_document_text_repeats_name_for_field_boost():
    document = KnowledgeDocument(
        doc_id="CWE-22",
        name="Path Traversal",
        text="CWE-22 Path Traversal: improper limitation of a pathname",
    )
    boosted = document_text(document, name_weight=2)
    assert boosted.startswith("Path Traversal Path Traversal CWE-22")
    with pytest.raises(ValueError):
        document_text(document, name_weight=0)


def test_backend_registry():
    assert isinstance(get_backend("keyword"), KeywordBackend)
    assert isinstance(get_backend("tf-idf"), TfidfBackend)
    assert isinstance(get_backend("semantic"), SemanticBackend)
    with pytest.raises(ValueError):
        get_backend("does-not-exist")
    with pytest.raises(NotImplementedError):
        get_backend("embeddings")


def test_seed_corpus_is_tracked_and_covers_common_cwes():
    documents = load_seed_corpus()
    ids = {document.doc_id for document in documents}
    assert {"CWE-79", "CWE-89", "CWE-22", "CWE-502"} <= ids
    assert all(document.text.startswith(document.doc_id) for document in documents)


def test_build_corpus_reads_processed_cwe_records(tmp_path):
    path = write_cwe_dataset(
        [CweRecord(cwe_id="CWE-89", name="SQL Injection", description="SQL commands")],
        tmp_path / "cwe.json",
    )
    documents = build_corpus(cwe_path=path, capec_path=tmp_path / "missing.json")
    assert [document.doc_id for document in documents] == ["CWE-89"]
    assert documents[0].text.startswith("CWE-89 SQL Injection:")


def test_build_corpus_falls_back_to_seed_without_processed_data():
    documents = build_corpus(use_processed=False)
    assert "CWE-79" in {document.doc_id for document in documents}


def test_build_corpus_requires_documents_for_explicit_paths(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_corpus(cwe_path=tmp_path / "missing.json", capec_path=tmp_path / "missing2.json")


def test_build_contexts_merges_record_cwe_and_backend_hits():
    cve = CveRecord(
        cve_id="CVE-TEST",
        description="sql injection login",
        cwe=["CWE-79"],
    )
    contexts = build_contexts_for_cve(cve, top_k=3, backend="keyword", corpus=DOCUMENTS)
    assert contexts[0].source == "CWE-79"
    assert contexts[0].score == 1.0
    assert any(context.backend == "keyword" and context.source == "CWE-89" for context in contexts)


def test_build_contexts_rejects_unknown_backend():
    cve = get_sample_cve("CVE-2024-0001")
    with pytest.raises(ValueError):
        build_contexts_for_cve(cve, corpus=DOCUMENTS, backend="bogus")
