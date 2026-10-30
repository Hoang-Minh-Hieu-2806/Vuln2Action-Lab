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
- [x] Generation abstraction (`GenerationProvider`: rule-based baseline; local T5
      fine-tune with CPU training + inference; LLM API still a stub)
- [x] Retrieval backends (keyword, TF-IDF, and MITRE-enriched semantic retrieval,
      selectable from the CLI)
- [x] Reproduction planner/executor/validator boundary (simulated, localhost-only)
- [x] Simulation reports `SIMULATED`; only real lab validators may report `PASS`
- [x] One live isolated Docker lab (`cve-001`) with a vulnerable/patched
      counterfactual and a real `PASS`/`FAIL` validator
- [x] Opt-in NVD 2.0 ingestion, local snapshots, CWE/CPE/CAPEC parsers, and a
      dataset builder
- [x] Tracked CVE→CWE retrieval benchmark with measured P@k / R@k / F1@k / MRR
- [x] CVE→CWE→CAPEC mapping (TF-IDF vs Word2Vec + cosine) with a tracked
      120-CVE benchmark and a measured, caveated comparison
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

`t5` is a real local seq2seq generator (optional heavy extra):

```bash
python -m pip install -e ".[t5]"
python scripts/download_data.py --source capec
python scripts/build_t5_dataset.py
python scripts/train_t5.py --allow-download --epochs 6 --batch-size 8 --max-steps 120
python scripts/run_t5.py --sample CVE-2024-0002 --checkpoint models/t5-capec-flows
```

Training data, provenance, measured losses and quality caveats are documented in
`docs/t5-training.md`. Output is textual guidance, never a validated exploit.

Evaluate the generator against the rule-based baseline (BLEU, ROUGE, phase
accuracy, repetition, leakage audit):

```bash
python scripts/run_evaluation.py --stage generation --systems rule_based,t5 \
    --save results/evaluation/generation
```

Metrics, the leakage audit and a failure analysis are in
`docs/generation-evaluation.md`. Decoding controls (n-gram blocking, repetition
penalty, length-aware beam search) and structural normalisation are documented in
`docs/generation-quality.md`; on the same 28 validation cases they cut repetition
from 0.60 to 0.007 and raise corpus BLEU to 0.1337 (rule-based: 0.0010), with all
three phases present in every output.

```bash
python scripts/run_evaluation.py --stage generation --systems t5-improved \
    --save results/evaluation/generation
```

`llm` remains a stub until credentials are configured; the pipeline never
hard-codes any single model as mandatory.

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

## CVE → CAPEC mapping (Phase 3b)

`src/vuln2action/retrieval/capec.py` implements the paper's first stage: expand
a CVE's CWE list into CAPEC candidates through the MITRE taxonomy, then rank
those candidates against the CVE description with **TF-IDF + cosine** (baseline)
and **Word2Vec + cosine**. Both methods see the identical candidate pool, ties
break by CAPEC id, and a query with no shared vocabulary returns *no* ranking
instead of an arbitrary pick.

The CAPEC catalog is an opt-in download (`data/raw/`, git-ignored):

```bash
python scripts/download_data.py --source capec
python scripts/build_capec_benchmark.py --download --year 2021 --size 120
python scripts/run_evaluation.py --stage capec --save results/evaluation
```

`analyze_cve()` now attaches the mapping (`AnalysisOutcome.capec`); when the
catalog or the optional `gensim` is missing it returns `capec=None` plus a
`capec_note` explaining why, so offline runs and CI never break.

Word2Vec needs the optional extra:

```bash
python -m pip install -e ".[ranking]"   # gensim
```

### Benchmark

`evaluation/datasets/capec_benchmark.json` holds **120 real CVEs** (unique ids)
built by `scripts/build_capec_benchmark.py` from two independent downloads:

- **queries**: verbatim NVD descriptions (`nvdcve-2.0-2021.json.gz`);
- **labels**: `Galeax/CVE2CAPEC` `database/CVE-2021.jsonl.gz` (commit recorded
  in the file), the same reference the paper cites for its 89/100 accuracy.

No label was written or edited by hand. Cases lacking a label, a CWE, or any
candidate are dropped and counted in `sample_stats`.

### Important caveat (measured, not assumed)

Galeax builds each CVE's CAPEC set by expanding its CWEs, so **the label set is
exactly the CWE→CAPEC closure**. Verified over all 18,540 joinable CVE-2021
records: the published set matched the closure 100% of the time (a unit test
re-checks this on the tracked file). A "is the prediction inside the label set?"
metric is therefore close to free for any method ranking those same candidates —
it measures candidate expansion, not ranking quality. We report it for
comparability and never as an achievement claim.

The harness also reports **discriminative** metrics that do not use the Galeax
label: graded relevance from the CVE's own NVD CWEs (a CAPEC is relevant when it
is related to more of them), then NDCG, Top-1 CWE coverage, Top-1-matches-best
and R@5. Cases where every method ranks (the *common subset*) are aggregated
separately, because TF-IDF legitimately returns empty rankings on zero-overlap
text while Word2Vec always emits a weak score — comparing raw totals would
reward the method that always answers.

Measured with the commands above (re-run to reproduce; nothing hard-coded):

| Method | Top-1 (label) | NDCG* | Top-1 CWE cov. | Best-cand | R@5 | MRR | Empty |
| --- | --- | --- | --- | --- | --- | --- | --- |
| tfidf (120 cases) | 0.9417 | 0.8244* | 0.9609 | 0.9826 | 0.9583 | 0.9500 | 5 |
| word2vec (120 cases) | 0.9833 | 0.8901* | 0.9667 | 0.9917 | 0.9917 | 0.9884 | 0 |
| tfidf (115 common) | 0.9826 | 0.8244* | 0.9609 | 0.9826 | 1.0000 | 0.9913 | 0 |
| word2vec (115 common) | 0.9826 | 0.8901* | 0.9652 | 0.9913 | 0.9913 | 0.9879 | 0 |

\* **NDCG is computed on only 2 of the 120 cases** (the rest have a single CWE, so
every candidate gets the same graded gain and NDCG is undefined). Treat those
NDCG values as anecdotal, not as evidence that Word2Vec ranks better. The report
records `ndcg_base_cases` and `ndcg_is_representative` so the base cannot be
mistaken for the full set.

Reading it honestly: on the common subset both methods tie on the membership
metric (0.9826), so **that metric does not separate them**. The `top1_cwe_coverage`
and `best-cand` columns are near-saturated for the reason above, and the NDCG
difference rests on 2 cases. These are 120-case numbers on a small CPU-trained
model — not a reproduction of the paper's 89/100 or its 0.84/0.94 similarity
scores. For a comparison the labels cannot flatter, see the independent
evaluation set below.

## Independent CVE → CAPEC evaluation (P0.3)

The 120-CVE benchmark above cannot falsify anything: its labels are the very
CWE→CAPEC closure used to build the candidates, and its `top1_cwe_coverage`
grading is derived from the same CWEs. `evaluation/datasets/capec_independent.json`
is a small, deliberately independent set built by
`scripts/build_capec_independent.py`:

- **Labels:** MITRE CAPEC `Example_Instances` sentences that *name a CVE*
  ("… See also: CVE-1999-0906"). MITRE analysts wrote these to describe the
  attack pattern a real incident exhibits; they are not computed from CWE maps.
  Each label keeps its verbatim evidence text (`label_evidence`) so a reviewer
  can accept or reject it.
- **Queries:** real NVD 2.0 descriptions.
- **Candidates:** the same CWE→CAPEC expansion as the main benchmark. CWEs come
  from NVD, or from the CWE catalog's `Observed_Examples` when NVD has none
  (recorded per case in `cwe_source`).

```bash
python scripts/build_capec_independent.py          # reads cached NVD data
python scripts/run_evaluation.py --stage capec-independent --save results/evaluation
```

Measured on 21 evaluable cases (`--stage capec-independent`):

| Method | Split | Top-1 | R@5 | MRR | Empty | n |
| --- | --- | --- | --- | --- | --- | --- |
| tfidf | all | 0.3333 | 0.5714 | 0.4444 | 0 | 21 |
| tfidf | reachable | 0.5833 | 1.0000 | 0.7778 | 0 | 12 |
| word2vec | all | 0.1905 | 0.4762 | 0.3171 | 0 | 21 |
| word2vec | reachable | 0.3333 | 0.8333 | 0.5549 | 0 | 12 |

**The conclusion reverses.** On labels that are not derived from the CWE map,
TF-IDF beats Word2Vec (Top-1 0.33 vs 0.19 over all cases; 0.58 vs 0.33 on cases
where the label is reachable). Label coverage is only **12/21 = 0.571**: in 9
cases the MITRE-written label is not in the CWE-derived candidate pool at all, so
no ranking method could have found it. That coverage ceiling, not the ranker, is
the dominant failure mode of this architecture. Details and failure analysis are
in `docs/analysis.md`.



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
