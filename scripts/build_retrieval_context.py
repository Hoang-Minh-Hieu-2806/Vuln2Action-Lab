"""Build the tracked CWE semantic-context file from local MITRE snapshots.

The tracked file lets CI and offline seed-corpus runs use the same alternate
terms, related CAPEC names, and parent definitions as the full local catalog.
It contains metadata only; no CVE labels or exploit code.

Example::

    python scripts/build_retrieval_context.py \
      --cwe data/raw/cwe/cwec_latest.xml \
      --capec data/raw/capec/capec_latest.xml

This reads local files only and never downloads anything.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from vuln2action.config import project_root
from vuln2action.retrieval.corpus import load_seed_corpus
from vuln2action.retrieval.semantic import SemanticContextFile, build_semantic_contexts
from vuln2action.utils.filesystem import write_json


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


def _sort_key(doc_id: str) -> tuple[str, int]:
    prefix, _, number = doc_id.partition("-")
    return prefix, int(number) if number.isdigit() else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build tracked CWE semantic context from local MITRE XML."
    )
    parser.add_argument("--cwe", default="data/raw/cwe/cwec_latest.xml")
    parser.add_argument("--capec", default="data/raw/capec/capec_latest.xml")
    parser.add_argument(
        "--seed-corpus",
        default="data/samples/knowledge_corpus.json",
        help="Corpus whose CWE ids should be included in the tracked context.",
    )
    parser.add_argument(
        "--output",
        default="data/samples/cwe_semantic_context.json",
        help="Tracked JSON output path.",
    )
    args = parser.parse_args(argv)

    cwe_path = _resolve(args.cwe)
    capec_path = _resolve(args.capec)
    if not cwe_path.is_file():
        parser.error(f"CWE snapshot not found: {cwe_path}")
    if not capec_path.is_file():
        parser.error(f"CAPEC snapshot not found: {capec_path}")

    documents = load_seed_corpus(_resolve(args.seed_corpus))
    doc_ids = {document.doc_id for document in documents if document.kind == "cwe"}
    contexts = build_semantic_contexts(cwe_path, capec_path, doc_ids=doc_ids)
    missing = sorted(doc_ids - set(contexts))
    if missing:
        parser.error(f"CWE ids missing from the CWE snapshot: {', '.join(missing)}")

    payload = SemanticContextFile(
        version="1.0.0",
        source="MITRE CWE and CAPEC local snapshots",
        documents=sorted(contexts.values(), key=lambda context: _sort_key(context.doc_id)),
    )
    output = write_json(_resolve(args.output), payload.model_dump(mode="json"))
    print(f"wrote {len(payload.documents)} CWE contexts to: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
