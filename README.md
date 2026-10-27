# Vuln2Action-Lab

An LLM-assisted framework for **CVE analysis, reproduction workflow generation,
and vulnerability validation in isolated Docker environments**.

This is a **university research/engineering project** (3-person team). It is a
practical, defensive-security lab framework — **not** an autonomous hacking system.

```
CVE Input
    v
CVE / CWE / CPE / CAPEC / Reference Ingestion
    v
Vulnerability Knowledge Retrieval
    v
Relevant Context
    v
Workflow Generation (rule-based baseline / LLM API / local T5 in future)
    v
Reproduction Workflow
    v
Isolated Docker Vulnerability Lab (localhost only)
    v
Validation -> SIMULATED / PASS / FAIL / ERROR
    v
Evidence Collection -> Report
```

> The design is inspired by existing vulnerability-reproduction research, but it
> does **not** claim to reproduce any specific paper completely. See
> `docs/research-paper.md`.

## Repository structure

```
Vuln2Action-Lab/
  README.md  LICENSE  .gitignore  .env.example
  requirements.txt  pyproject.toml  Makefile  docker-compose.yml
  docs/            # problem, objectives, scope, architecture, methodology, ...
  config/          # settings.yaml, models.yaml, datasets.yaml
  data/samples/    # fake sample CVEs + tracked CWE retrieval/semantic corpus
  src/vuln2action/
    domain/        # strict Pydantic contracts shared by every stage
    connectors/    # sample/catalog/lab-manifest + NVD/CWE/CAPEC adapters
    retrieval/     # backend registry, corpus loader, keyword/TF-IDF/semantic, ranker
    generation/    # provider interface + rule-based/LLM/T5 backends
    reproduction/  # planner -> guarded executor -> truthful validator
    evidence/      # typed collector and run-scoped reports
    pipeline/      # analysis + end-to-end orchestration
    cli.py         # installed `vuln2action` command
  api/             # optional FastAPI layer (scaffold only)
  labs/            # isolated Docker labs: cve-001, cve-002, cve-003
  evaluation/      # retrieval harness (real metrics) + generation/reproduction stubs
  tests/           # unit + integration (pytest)
  scripts/         # run_pipeline.py, run_evaluation.py, download_data.py, ...
  results/         # generated evidence (git-ignored except .gitkeep)
  notebooks/       # exploratory experiments
```

## Current implementation status

- [x] Installable `src/vuln2action` package and CLI entry point
- [x] Validated settings, domain contracts, lab manifests, logging, filesystem utils
- [x] Generation abstraction (`GenerationProvider`: rule-based works; LLM/T5 are stubs)
- [x] Retrieval backends (keyword, TF-IDF, and MITRE-enriched semantic retrieval,
      selectable from the CLI)
- [x] Reproduction planner/executor/validator boundary (simulated, localhost-only)
- [x] Simulation reports `SIMULATED`; only real lab validators may report `PASS`
- [x] One live isolated Docker lab (`cve-001`) with a vulnerable/patched
      counterfactual and a real `PASS`/`FAIL` validator
- [x] Opt-in NVD 2.0 ingestion, local snapshots, CWE/CPE/CAPEC parsers, and a
      dataset builder
- [x] Tracked CVE→CWE retrieval benchmark with measured P@k / R@k / F1@k / MRR
- [x] Sample end-to-end CLI pipeline over fake sample CVEs
- [ ] Live labs for `cve-002`/`cve-003`; generation and reproduction benchmarks

## Installation

Requires **Python 3.11+**.

```bash
python -m pip install -e ".[test]"
```

Optional (API server):

```bash
python -m pip install -e ".[api,test]"
```

Copy env template (only needed for future LLM/API generation):

```bash
copy .env.example .env
```

## Running tests

```bash
pytest -v
# or
python -m pytest -v
```

GitHub Actions runs Ruff, byte-compilation, the complete test suite, CLI smoke
tests, the tracked retrieval evaluation, and package builds on Python 3.11 and
3.12 for every pull request and for pushes to `main` or `codex/**` branches.

## Running the sample pipeline

Rule-based baseline over a fake sample CVE (no network, no Docker needed):

```bash
vuln2action --sample CVE-2024-0001 --provider rule_based
```

List available sample CVEs:

```bash
vuln2action --list-samples
```

Other providers (`llm`, `t5`) are accepted as arguments but currently raise a
clear "not configured" error until credentials/models are set up. This is intentional:
the pipeline never hard-codes T5 as the only model.

Choose the retrieval backend explicitly (default comes from
`config/settings.yaml`):

```bash
vuln2action --sample CVE-2024-0001 --retrieval keyword
vuln2action --sample CVE-2024-0001 --retrieval tfidf
vuln2action --sample CVE-2024-0001 --retrieval semantic
```

`semantic` is the default in `config/settings.yaml`. It keeps the same
`RetrievalBackend` interface and does not require a model download or network
call.

### Real isolated lab (requires Docker)

The default run is offline and simulated. To execute the checked-in lab
validator instead:

```bash
vuln2action --sample CVE-2024-0001 --execute
```

This builds `labs/cve-001` (vulnerable + patched services, bound to
`127.0.0.1` only), runs `labs/cve-001/validation/labctl.py validate`, and
reports a real `PASS`/`FAIL`. The lab network is created automatically and the
containers are torn down afterwards. `--execute` is refused for placeholder
labs and for any target that is not localhost.

## Data snapshots (Phase 2)

Downloads are **opt-in only**; the pipeline never fetches anything by itself.
Raw snapshots land in `data/raw/` and processed records in `data/processed/`
(both git-ignored).

```bash
# One CVE, the CWE catalog, and the CAPEC catalog
python scripts/download_data.py --source nvd --cve CVE-2021-44228
python scripts/download_data.py --source cwe
python scripts/download_data.py --source capec

# Normalise snapshots into typed records
python scripts/build_dataset.py \
  --nvd data/raw/nvd \
  --cwe data/raw/cwe/cwec_latest.xml \
  --capec data/raw/capec/capec_latest.xml \
  --lab-map config/lab_map.example.json
```

- `--max-records` (default 100) caps NVD pagination; `--results-per-page` is
  limited to NVD's maximum of 2000.
- Set `NVD_API_KEY` to raise the NVD rate limit; without it the client waits
  6 seconds between requests.
- `scripts/build_dataset.py` reads local files only and writes
  `data/processed/cves.json`, `cwe.json`, and `capec.json`.
- Processed CVEs carry no `lab_id` unless a `--lab-map` entry matches. Running
  the execution pipeline for a real CVE still requires a lab manifest registered
  for that exact CVE id.

## Retrieval and evaluation (Phase 3)

Retrieval has a small corpus loader, a shared backend interface, and three
measurable backends:

- `KeywordBackend` — Dice overlap over stopword-filtered content tokens
  (dependency-free).
- `TfidfBackend` — cosine similarity over word unigram+bigram TF-IDF vectors
  with sublinear term frequency and the same stopword filtering (falls back to
  keyword only if scikit-learn is unavailable).
- `SemanticBackend` — word + character n-gram TF-IDF over CWE text enriched
  with MITRE alternate terms, related CAPEC attack-pattern names, and direct
  parent-weakness definitions. It also splits CamelCase product names such as
  `ShellShock`. This is **knowledge-graph semantic enrichment**, not a neural
  embedding model; neural embeddings remain an explicit stub.
- All backends drop zero-score documents instead of padding results.
- TF-IDF and semantic retrieval repeat the CWE/CAPEC name ahead of the body as
  a simple field boost.
- `build_contexts_for_cve` merges record-known CWEs (score 1.0), backend hits,
  and reference metadata, then deduplicates by source and keeps top-k.

The tracked file `data/samples/cwe_semantic_context.json` contains the small
seed-context subset so CI and offline runs do not need the raw MITRE snapshots.
It is generated from MITRE CWE/CAPEC metadata only; NVD relevance labels are
never used as retrieval features. When `data/raw/cwe/cwec_latest.xml` and
`data/raw/capec/capec_latest.xml` are present, the full catalog is enriched
automatically. Regenerate the tracked subset after updating the snapshots with:

```bash
python scripts/build_retrieval_context.py
```

Pipeline corpus selection is automatic: processed `data/processed/cwe.json` +
`capec.json` when present, otherwise the tracked seed corpus
`data/samples/knowledge_corpus.json` (31 CWE documents). The evaluation harness
defaults to the tracked seed corpus so runs are reproducible; pass `--corpus`
to evaluate the full processed catalog.

The tracked benchmark (`evaluation/datasets/retrieval_benchmark.json`) contains
9 real CVEs. The query is the NVD description; the relevance labels are the CWE
ids assigned by NVD. Only CWE relevance is scored: NVD does not assign CAPEC
ids, so CAPEC documents are available to the pipeline but are not labelled
targets. Run all three backends with P@k / R@k / F1@k / MRR / MRR@k:

```bash
python scripts/run_evaluation.py --stage retrieval
```

Measured on the tracked 31-document corpus with `k=3` (re-run to reproduce;
values change only if the corpus, labels, or code change). Precision/recall/F1
use the top-k cutoff; `MRR` uses the full ranking and `MRR@3` is the cutoff
variant. Zero-score documents are excluded, and P@k divides by `k`:

| Backend | P@3 | R@3 | F1@3 | MRR | MRR@3 |
| --- | --- | --- | --- | --- | --- |
| keyword | 0.185 | 0.417 | 0.243 | 0.525 | 0.481 |
| tfidf | 0.222 | 0.611 | 0.322 | 0.611 | 0.593 |
| semantic | 0.296 | 0.750 | 0.410 | 0.792 | 0.778 |

Semantic enrichment fixes several vocabulary-gap cases without changing the
benchmark labels: Drupal (`CWE-20`) moves from outside the top-3 to rank 1,
Log4Shell retrieves `CWE-20` at rank 2, and the Struts exception-handling case
moves to rank 2. Shellshock (`CWE-78`) is still outside the top-3: its NVD
description talks about environment variables and shell behaviour, while the
CWE entry is framed as OS command injection. That remaining case is the
measured motivation for a later neural-embedding experiment (still not
implemented). On the full local 969-CWE catalog at `k=10`, semantic also beats
TF-IDF (P 0.044 vs 0.033, R 0.333 vs 0.278, F1 0.077 vs 0.059, MRR 0.215 vs
0.192), though all absolute scores are low because the corpus is much larger.

Evaluate against the full locally built CWE catalog (requires Phase 2 data) and
save JSON + Markdown reports:

```bash
python scripts/run_evaluation.py --stage retrieval \
  --corpus data/processed/cwe.json --k 10 \
  --save results/evaluation/retrieval
```

The benchmark labels come from NVD; no score is hard-coded. If a label is
missing from the chosen corpus, the report shows how many cases are fully
covered instead of silently inflating recall.

## Configuration

- `config/settings.yaml` — pipeline defaults (provider, retrieval backend/top-k, lab network, timeouts)
- `config/models.yaml` — generation provider configs (rule-based params, LLM API, T5 checkpoint)
- `config/datasets.yaml` — dataset paths (no auto-download; see `scripts/download_data.py`)

Load via:

```python
from vuln2action.config import load_settings

settings = load_settings()
```

## Security / safety scope

- Operates **only** against intentionally vulnerable, isolated Docker labs
  (`labs/`, localhost / `vuln2action-lab-net`).
- The executor **refuses** non-local targets (see `src/vuln2action/reproduction/executor.py`).
- Simulated plans can never produce a `PASS` verdict.
- A real `PASS` can only come from a checked-in lab validator, and `labs/cve-001`
  requires *both* the vulnerable and the patched counterfactual to hold.
- No real exploit code is shipped. Sample CVEs under `data/samples/` are fake;
  the retrieval corpus there is public MITRE CWE metadata.
- Never commit secrets: `.env` is git-ignored; use `.env.example` as a template.
- Do not point the framework at real-world systems. Ever.
