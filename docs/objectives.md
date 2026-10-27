# Objectives

1. **O1 — Uniform ingestion:** parse CVE/CWE/CPE/CAPEC/reference data into
   typed domain contracts (`src/vuln2action/domain/`) through read-only connectors.
2. **O2 — Retrieval baseline:** implement keyword, TF-IDF, and MITRE-enriched
   semantic retrieval behind one shared ranker interface, leaving room for
   neural embeddings later.
3. **O3 — Pluggable generation:** expose a `GenerationProvider` abstraction so
   the pipeline works with `RuleBasedGenerator` today and `LLMGenerator` /
   `T5Generator` tomorrow without architectural changes.
4. **O4 — Controlled reproduction:** design planner/executor/validator stages
   that only target isolated Docker labs on localhost.
5. **O5 — Evidence & reporting:** collect command output, HTTP metadata, logs,
   timestamps, and validation verdicts into reproducible reports.
6. **O6 — Evaluation readiness:** scaffold retrieval/generation/reproduction
   metrics (precision/recall, BLEU/ROUGE, success rate) without fabricating
   results.
7. **O7 — Student-friendly foundation:** clean structure, type hints, minimal
   dependencies, and a runnable sample pipeline from day one.
