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
  data/samples/    # small FAKE sample CVEs for pipeline smoke tests
  src/vuln2action/
    domain/        # strict Pydantic contracts shared by every stage
    connectors/    # sample/catalog/lab-manifest adapters
    retrieval/     # keyword, TF-IDF, optional embeddings, ranker
    generation/    # provider interface + rule-based/LLM/T5 backends
    reproduction/  # planner -> guarded executor -> truthful validator
    evidence/      # typed collector and run-scoped reports
    pipeline/      # analysis + end-to-end orchestration
    cli.py         # installed `vuln2action` command
  api/             # optional FastAPI layer (scaffold only)
  labs/            # isolated Docker labs: cve-001, cve-002, cve-003
  evaluation/      # retrieval / generation / reproduction metrics scaffolds
  tests/           # unit + integration (pytest)
  scripts/         # run_pipeline.py, download_data.py, build_dataset.py, ...
  results/         # generated evidence (git-ignored except .gitkeep)
  notebooks/       # exploratory experiments
```

## Current implementation status (foundation refactor complete)

- [x] Installable `src/vuln2action` package and CLI entry point
- [x] Validated settings, domain contracts, lab manifests, logging, filesystem utils
- [x] Generation abstraction (`GenerationProvider`: rule-based works; LLM/T5 are stubs)
- [x] Retrieval baselines (keyword works; TF-IDF works if sklearn installed; embeddings stub)
- [x] Reproduction planner/executor/validator boundary (simulated, localhost-only)
- [x] Simulation reports `SIMULATED`; only real lab validators may report `PASS`
- [x] Sample end-to-end CLI pipeline over fake sample CVEs
- [ ] Real CVE ingestion (NVD API), real retrieval corpus, real Docker labs (Phases 2-5)

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
tests, and package builds on Python 3.11 and 3.12 for every pull request and
for pushes to `main` or `codex/**` branches.

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

## Configuration

- `config/settings.yaml` — pipeline defaults (provider, retrieval top-k, lab network, timeouts)
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
- No real exploit code is shipped. Sample data under `data/samples/` is **fake**.
- Never commit secrets: `.env` is git-ignored; use `.env.example` as a template.
- Do not point the framework at real-world systems. Ever.
