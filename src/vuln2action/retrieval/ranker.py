"""Build, deduplicate, and rank evidence-bearing context."""

from collections.abc import Sequence

from vuln2action.connectors.catalog import lookup_cwe
from vuln2action.domain import CveRecord, KnowledgeDocument, RetrievedContext
from vuln2action.retrieval.base import get_backend
from vuln2action.retrieval.corpus import default_corpus


def rank_contexts(contexts: list[RetrievedContext], top_k: int = 3) -> list[RetrievedContext]:
    best: dict[str, RetrievedContext] = {}
    for context in contexts:
        previous = best.get(context.source)
        if previous is None or context.score > previous.score:
            best[context.source] = context
    return sorted(best.values(), key=lambda item: item.score, reverse=True)[:top_k]


def build_contexts_for_cve(
    cve: CveRecord,
    top_k: int = 3,
    backend: str = "semantic",
    corpus: Sequence[KnowledgeDocument] | None = None,
) -> list[RetrievedContext]:
    """Merge record-known CWEs, backend retrieval hits, and reference metadata."""
    documents = list(corpus) if corpus is not None else list(default_corpus())
    by_id = {document.doc_id: document for document in documents}
    contexts: list[RetrievedContext] = []

    for cwe_id in cve.cwe:
        document = by_id.get(cwe_id)
        if document is not None:
            contexts.append(
                RetrievedContext(
                    source=document.doc_id,
                    text=document.text,
                    score=1.0,
                    backend="record-cwe",
                )
            )
            continue
        record = lookup_cwe(cwe_id)
        if record is not None:
            contexts.append(
                RetrievedContext(
                    source=record.cwe_id,
                    text=f"{record.cwe_id} {record.name}: {record.description}",
                    score=1.0,
                    backend="cwe-lookup",
                )
            )

    if documents:
        contexts.extend(get_backend(backend).search(cve.description, documents, top_k=top_k))

    for url in cve.references:
        contexts.append(
            RetrievedContext(
                source=f"reference:{url}",
                text=f"Reference metadata: {url}",
                score=0.5,
                backend="reference-metadata",
            )
        )
    return rank_contexts(contexts, top_k=top_k)
