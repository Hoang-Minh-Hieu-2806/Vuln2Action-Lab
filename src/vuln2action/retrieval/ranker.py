"""Build, deduplicate, and rank evidence-bearing context."""

from vuln2action.connectors.catalog import lookup_cwe
from vuln2action.domain import CveRecord, RetrievedContext


def rank_contexts(contexts: list[RetrievedContext], top_k: int = 3) -> list[RetrievedContext]:
    best: dict[str, RetrievedContext] = {}
    for context in contexts:
        previous = best.get(context.source)
        if previous is None or context.score > previous.score:
            best[context.source] = context
    return sorted(best.values(), key=lambda item: item.score, reverse=True)[:top_k]


def build_contexts_for_cve(cve: CveRecord, top_k: int = 3) -> list[RetrievedContext]:
    contexts: list[RetrievedContext] = []
    for cwe_id in cve.cwe:
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
