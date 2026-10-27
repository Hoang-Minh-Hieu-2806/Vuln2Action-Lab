# Architecture

```
CVE Input
  -> connectors/   (samples, catalog snapshots, lab manifests)
  -> domain/       (strict cross-stage contracts)
  -> retrieval/    (text.py, keyword.py, tfidf.py, semantic.py, embeddings.py -> ranker.py)
  -> generation/   (GenerationProvider: RuleBased | LLM | T5 + prompts/parser)
  -> reproduction/ (planner -> executor -> validator -> result)
  -> evidence/     (collector, logger, reporter)
  -> pipeline/     (analyze.py, pipeline.py orchestration)
  -> api/          (optional FastAPI; scaffold only)
```

## Layers

- **Connectors:** normalise raw records into validated Pydantic models.
  Phase 1 uses sample JSON only. Phase 2 adds an opt-in NVD 2.0 client plus
  CWE/CAPEC XML and CPE parsers over local snapshots. The pipeline never
  downloads automatically; only `scripts/download_data.py` touches the network.
- **Retrieval:** `corpus.py` builds typed `KnowledgeDocument`s from processed
  CWE/CAPEC records or the tracked seed corpus; `base.py` defines the backend
  interface and registry. `text.py` provides the shared stopword list,
  tokenizer, CamelCase splitter, and name-boosted document text.
  `KeywordBackend` (Dice overlap), `TfidfBackend` (word 1–2 grams, sublinear
  TF), and `SemanticBackend` (MITRE-enriched word + character n-gram TF-IDF)
  return only positive-scored `RetrievedContext` items; `ranker.py` merges them
  with record-known CWEs and reference metadata, dedupes by source, and keeps
  top-k. `semantic.py` reads the tracked seed context and optionally the local
  CWE/CAPEC XML snapshots; it never downloads anything. Neural embeddings are
  an explicit stub.
- **Generation:** `GenerationProvider` ABC with typed `generate(cve, contexts)`.
  `RuleBasedGenerator` builds deterministic steps from CVE/CWE/CPE signals.
  `LLMGenerator`/`T5Generator` are explicit stubs (raise helpful errors until
  configured). `prompts.py` centralises prompt templates; `parser.py`
  validates/normalises workflow dicts.
- **Reproduction:** `ReproductionPlanner` turns a workflow into steps;
  `ReproductionExecutor` runs them **only** against localhost labs (guarded).
  Simulation returns `SIMULATED`. With `simulate=False` the executor runs only
  the manifest's `setup_command` / `validation_command` / `teardown_command`
  from the lab directory (no shell), and `PASS`/`FAIL` is derived solely from
  the validator's emitted `V2A_VALIDATION_JSON` payload.
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
- No hard-coded absolute paths; use `pathlib` + `vuln2action.utils.filesystem`.
- Settings are validated once and injected at the pipeline composition root.
- No secrets in code; env via `.env` (git-ignored).
