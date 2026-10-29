"""Retrieval and generation stage without execution."""

from pydantic import BaseModel, ConfigDict

from vuln2action.domain import CveRecord, RetrievedContext, Workflow
from vuln2action.generation import get_generator
from vuln2action.retrieval.capec import CapecMapping, default_capec_index, map_cve_to_capec
from vuln2action.retrieval.ranker import build_contexts_for_cve


class AnalysisOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cve: CveRecord
    contexts: list[RetrievedContext]
    workflow: Workflow
    provider: str
    capec: CapecMapping | None = None
    capec_note: str = ""


def resolve_capec(
    cve: CveRecord,
    method: str = "tfidf",
) -> tuple[CapecMapping | None, str]:
    """Map a CVE to a CAPEC pattern, degrading gracefully when unsupported.

    The CAPEC snapshot is an opt-in download (``data/raw/capec``), so a missing
    catalog or an absent ``gensim`` install must not break the offline pipeline.
    Instead of failing, the reason is returned so a report can state plainly that
    no CAPEC mapping was produced and why.
    """
    if not method:
        return None, "CAPEC mapping disabled"
    if not cve.cwe:
        return None, "no CWE assigned to this CVE, so no CAPEC candidates exist"
    try:
        index = default_capec_index()
    except FileNotFoundError:
        return None, "CAPEC catalog not downloaded (scripts/download_data.py --source capec)"
    try:
        mapping = map_cve_to_capec(
            cve.cve_id,
            cve.description,
            cve.cwe,
            method=method,
            index=index,
        )
    except RuntimeError as exc:
        # Optional dependency missing (e.g. gensim) for the requested method.
        return None, str(exc)
    if mapping is None:
        return None, f"no CAPEC candidates found for {', '.join(cve.cwe)}"
    return mapping, ""


def analyze_cve(
    cve: CveRecord,
    provider: str = "rule_based",
    top_k: int = 3,
    backend: str = "semantic",
    capec_method: str = "tfidf",
) -> AnalysisOutcome:
    generator = get_generator(provider)
    contexts = build_contexts_for_cve(cve, top_k=top_k, backend=backend)
    workflow = generator.generate(cve, contexts)
    capec, capec_note = resolve_capec(cve, method=capec_method)
    return AnalysisOutcome(
        cve=cve,
        contexts=contexts,
        workflow=workflow,
        provider=generator.name,
        capec=capec,
        capec_note=capec_note,
    )
