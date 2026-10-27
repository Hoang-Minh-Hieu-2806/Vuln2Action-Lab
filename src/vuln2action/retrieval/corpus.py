"""Local knowledge corpus loading.

The pipeline prefers ``data/processed/cwe.json`` / ``capec.json`` when present
(produced by Phase-2 ingestion). Otherwise it falls back to the small tracked
seed corpus under ``data/samples/knowledge_corpus.json`` so offline runs and CI
stay deterministic.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from vuln2action.connectors.dataset import load_capec_dataset, load_cwe_dataset
from vuln2action.domain import CapecRecord, CweRecord, KnowledgeDocument
from vuln2action.utils.filesystem import read_json, repo_path

SEED_CORPUS = ("data", "samples", "knowledge_corpus.json")
PROCESSED_CWE = ("data", "processed", "cwe.json")
PROCESSED_CAPEC = ("data", "processed", "capec.json")


class CorpusFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = "1.0.0"
    description: str = ""
    source: str = ""
    documents: list[KnowledgeDocument] = Field(min_length=1)


def _definition_url(catalog: str, doc_id: str) -> str:
    number = doc_id.split("-", 1)[1] if "-" in doc_id else doc_id
    return f"https://{catalog}.mitre.org/data/definitions/{number}.html"


def cwe_document(record: CweRecord) -> KnowledgeDocument:
    return KnowledgeDocument(
        doc_id=record.cwe_id,
        kind="cwe",
        name=record.name,
        text=f"{record.cwe_id} {record.name}: {record.description}".strip(),
        source=_definition_url("cwe", record.cwe_id),
    )


def capec_document(record: CapecRecord) -> KnowledgeDocument:
    return KnowledgeDocument(
        doc_id=record.capec_id,
        kind="capec",
        name=record.name,
        text=f"{record.capec_id} {record.name}: {record.description}".strip(),
        source=_definition_url("capec", record.capec_id),
    )


def load_corpus_file(path: str | Path) -> list[KnowledgeDocument]:
    """Load either a seed corpus object or a processed CWE/CAPEC record list."""
    raw: Any = read_json(path)
    if isinstance(raw, dict):
        return list(CorpusFile.model_validate(raw).documents)
    if not isinstance(raw, list):
        raise TypeError(f"Corpus file must be an object or a list: {path}")
    documents: list[KnowledgeDocument] = []
    for item in raw:
        if not isinstance(item, dict):
            raise TypeError(f"Corpus records must be objects: {path}")
        if "cwe_id" in item:
            documents.append(cwe_document(CweRecord.model_validate(item)))
        elif "capec_id" in item:
            documents.append(capec_document(CapecRecord.model_validate(item)))
        else:
            raise TypeError(f"Corpus record has no cwe_id/capec_id: {path}")
    return documents


def load_seed_corpus(path: str | Path | None = None) -> list[KnowledgeDocument]:
    seed_path = Path(path) if path is not None else repo_path(*SEED_CORPUS)
    return load_corpus_file(seed_path)


def load_processed_corpus(
    cwe_path: str | Path | None = None,
    capec_path: str | Path | None = None,
) -> list[KnowledgeDocument]:
    cwe_file = Path(cwe_path) if cwe_path is not None else repo_path(*PROCESSED_CWE)
    capec_file = Path(capec_path) if capec_path is not None else repo_path(*PROCESSED_CAPEC)
    documents: list[KnowledgeDocument] = []
    if cwe_file.is_file():
        documents.extend(cwe_document(record) for record in load_cwe_dataset(cwe_file))
    if capec_file.is_file():
        documents.extend(capec_document(record) for record in load_capec_dataset(capec_file))
    return documents


def build_corpus(
    cwe_path: str | Path | None = None,
    capec_path: str | Path | None = None,
    seed_path: str | Path | None = None,
    use_processed: bool = True,
) -> list[KnowledgeDocument]:
    if cwe_path is not None or capec_path is not None:
        documents = load_processed_corpus(cwe_path, capec_path)
        if not documents:
            raise FileNotFoundError("No documents found in the requested corpus paths")
        return documents
    if use_processed:
        documents = load_processed_corpus()
        if documents:
            return documents
    return load_seed_corpus(seed_path)


@lru_cache(maxsize=1)
def default_corpus() -> tuple[KnowledgeDocument, ...]:
    return tuple(build_corpus())


def clear_corpus_cache() -> None:
    default_corpus.cache_clear()
