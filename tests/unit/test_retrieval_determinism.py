"""Default retrieval must not depend on untracked local XML files."""

import json
from pathlib import Path

from vuln2action.domain import KnowledgeDocument
from vuln2action.retrieval import semantic

SEED = Path(__file__).resolve().parents[2] / "data" / "samples" / "cwe_semantic_context.json"
RAW_CWE = """<Weakness_Catalog><Weaknesses><Weakness ID="78" Name="Seed">
<Description>IMPLICIT_OVERRIDE_MARKER</Description></Weakness></Weaknesses></Weakness_Catalog>"""
RAW_CAPEC = """<Attack_Pattern_Catalog><Attack_Patterns><Attack_Pattern ID="999" Name="Shadow">
<Description>IMPLICIT_OVERRIDE_MARKER</Description></Attack_Pattern></Attack_Patterns></Attack_Pattern_Catalog>"""


def _fake_repo_path(tmp_path):
    def resolve(*parts):
        return tmp_path.joinpath(*parts)

    return resolve


def test_raw_xml_files_do_not_change_default_enricher(tmp_path, monkeypatch):
    seed_dir = tmp_path / "data" / "samples"
    seed_dir.mkdir(parents=True)
    (seed_dir / "cwe_semantic_context.json").write_text(
        SEED.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "data" / "raw" / "cwe").mkdir(parents=True)
    (tmp_path / "data" / "raw" / "cwe" / "cwec_latest.xml").write_text(
        RAW_CWE, encoding="utf-8"
    )
    (tmp_path / "data" / "raw" / "capec").mkdir(parents=True)
    (tmp_path / "data" / "raw" / "capec" / "capec_latest.xml").write_text(
        RAW_CAPEC, encoding="utf-8"
    )
    monkeypatch.setattr(semantic, "repo_path", _fake_repo_path(tmp_path))

    enricher = semantic.default_semantic_enricher()
    assert "CWE-78" in enricher.contexts
    dumped = json.dumps(
        {key: value.model_dump(mode="json") for key, value in enricher.contexts.items()},
        ensure_ascii=False,
    )
    assert "IMPLICIT_OVERRIDE_MARKER" not in dumped
    assert "CAPEC-999" not in dumped


def test_default_seed_mode_works_without_raw_files(tmp_path, monkeypatch):
    seed_dir = tmp_path / "data" / "samples"
    seed_dir.mkdir(parents=True)
    (seed_dir / "cwe_semantic_context.json").write_text(
        SEED.read_text(encoding="utf-8"), encoding="utf-8"
    )
    monkeypatch.setattr(semantic, "repo_path", _fake_repo_path(tmp_path))
    enricher = semantic.default_semantic_enricher()
    assert enricher.contexts
    results = semantic.semantic_search(
        "OS command injection",
        [KnowledgeDocument(doc_id="CWE-78", text="CWE-78 OS command injection")],
        enricher=enricher,
    )
    assert results
