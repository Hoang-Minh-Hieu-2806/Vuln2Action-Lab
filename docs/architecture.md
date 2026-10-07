# Architecture

```
CVE Input
  -> ingestion/    (cve.py, cwe.py, cpe.py, capec.py, exploit.py)
  -> retrieval/    (keyword.py, tfidf.py, embeddings.py -> ranker.py)
  -> generation/   (GenerationProvider: RuleBased | LLM | T5 + prompts/parser)
  -> reproduction/ (planner -> executor -> validator -> result)
  -> evidence/     (collector, logger, reporter)
  -> pipeline/     (analyze.py, pipeline.py orchestration)
  -> api/          (optional FastAPI; scaffold only)
```

## Layers

- **Ingestion:** normalises raw records into dataclasses (e.g. `CveRecord`).
  No network calls in Phase 1; sample JSON only.
- **Retrieval:** each backend returns scored `RetrievedContext` items;
  `ranker.py` merges/dedupes them. Keyword works now; TF-IDF works when
  `scikit-learn` is installed; embeddings is a stub.
- **Generation:** `GenerationProvider` ABC with `generate(cve, contexts)`.
  `RuleBasedGenerator` builds deterministic steps from CVE/CWE/CPE signals.
  `LLMGenerator`/`T5Generator` are explicit stubs (raise helpful errors until
  configured). `prompts.py` centralises prompt templates; `parser.py`
  validates/normalises workflow dicts.
- **Reproduction:** `ReproductionPlanner` turns a workflow into steps;
  `ReproductionExecutor` runs them **only** against localhost labs (guarded);
  currently simulated. `Validator` returns PASS/FAIL; `ReproductionResult`
  is the typed outcome.
- **Evidence:** `collector` gathers artefacts (command output, HTTP metadata,
  logs, timestamps); `reporter` renders Markdown/JSON reports.
- **Pipeline:** `analyze.py` (ingest->retrieve->generate) and `pipeline.py`
  (full run incl. reproduction + evidence) — used by `scripts/run_pipeline.py`.
- **Labs:** each `labs/<id>/` has its own compose file + validation script.
- **Evaluation:** separate harnesses per stage with real metric implementations
  where trivial (P/R/F1, MRR) and stubs where models are needed (BLEU/ROUGE).

## Design rules

- No component imports T5/LLM specifics directly; they depend on the
  `GenerationProvider` interface + `config/models.yaml`.
- No hard-coded absolute paths; use `pathlib` + `src/utils/filesystem.py`.
- No secrets in code; env via `.env` (git-ignored).
