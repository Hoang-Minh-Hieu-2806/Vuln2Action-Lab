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
Validation -> PASS / FAIL
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
  src/
    ingestion/     # cve, cwe, cpe, capec, exploit (parsers/schemas)
    retrieval/     # keyword, tfidf, embeddings, ranker
    generation/    # GenerationProvider ABC: rule-based / llm / t5 + prompts/parser
    reproduction/  # planner -> executor -> validator -> result
    evidence/      # collector, logger, reporter
    pipeline/      # analyze.py + pipeline.py (end-to-end orchestration)
    utils/         # config, logging, filesystem
  api/             # optional FastAPI layer (scaffold only)
  labs/            # isolated Docker labs: cve-001, cve-002, cve-003
  evaluation/      # retrieval / generation / reproduction metrics scaffolds
  tests/           # unit + integration (pytest)
  scripts/         # run_pipeline.py, download_data.py, build_dataset.py, ...
  results/         # generated evidence (git-ignored except .gitkeep)
  notebooks/       # exploratory experiments
```

## Current implementation status (Phase 1: Foundation)

- [x] Package structure, config loading, logging, filesystem utils
- [x] Data models/schemas (ingestion + reproduction result)
- [x] Generation abstraction (`GenerationProvider`: rule-based works; LLM/T5 are stubs)
- [x] Retrieval baselines (keyword works; TF-IDF works if sklearn installed; embeddings stub)
- [x] Reproduction planner/executor/validator **placeholders** (simulated, localhost-only)
- [x] Sample end-to-end CLI pipeline over fake sample CVEs
- [ ] Real CVE ingestion (NVD API), real retrieval corpus, real Docker labs (Phases 2-5)

## Installation

Requires **Python 3.11+**.

```bash
pip install -r requirements.txt
```

Optional (API server):

```bash
pip install fastapi "uvicorn[standard]"
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

## Running the sample pipeline

Rule-based baseline over a fake sample CVE (no network, no Docker needed):

```bash
python scripts/run_pipeline.py --sample CVE-2024-0001 --provider rule_based
```

List available sample CVEs:

```bash
python scripts/run_pipeline.py --list-samples
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
from src.utils.config import load_settings
s = load_settings()
```

## Security / safety scope

- Operates **only** against intentionally vulnerable, isolated Docker labs
  (`labs/`, localhost / `vuln2action-lab-net`).
- The executor **refuses** non-local targets (see `src/reproduction/executor.py`).
- No real exploit code is shipped. Sample data under `data/samples/` is **fake**.
- Never commit secrets: `.env` is git-ignored; use `.env.example` as a template.
- Do not point the framework at real-world systems. Ever.
