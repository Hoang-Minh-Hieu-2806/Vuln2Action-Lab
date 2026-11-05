# Paper reproduction contract: Vuln2Action

Reference: S. Kumari and G. Yadav, "Vuln2Action: An LLM-based framework for
generating vulnerability reproduction steps and mapping exploits",
*Journal of Information Security and Applications* 99 (2026) 104420.

This document fixes the scope for a **method-faithful reproduction**. It is not
a claim that the exact paper numbers can be reproduced: the original dataset is
not public and the paper used an NVIDIA A100 32 GB. Results will be reported
with explicit deviations.

## What "full reproduction" means here

We reproduce every methodological component:

1. Integrated CVE/CWE/CAPEC/ExploitDB dataset construction.
2. CVE -> CWE -> candidate CAPEC -> best CAPEC selection with TF-IDF and
   Word2Vec plus cosine similarity.
3. Two-stage T5 training for execution-flow generation.
4. Technique -> ExploitDB description mapping and SBERT-based exploit-code
   retrieval.
5. Flask GUI.
6. BLEU/ROUGE, CAPEC accuracy, FLAN-T5 comparison, resource measurements, and
   human evaluation.

Not claimed:

- exact dataset row counts from the paper;
- exact `BLEU = 0.7589` or other reported values;
- exact human ratings;
- training on the same A100 hardware.

## Paper facts to target

| Item | Paper |
| --- | --- |
| CVE cutoff | CVEs indexed in 2023; exploits 1999-2023 (`latest` mode used here extends to 2026 as a user-requested deviation) |
| CVE count | 114,560 |
| CVE-CWE pairs | 28,831 |
| CWE-CAPEC pairs | 46,575 |
| CWE entries | 915 |
| CAPEC entries | 1,024 |
| CAPEC selection | TF-IDF and Word2Vec + cosine; Word2Vec selected |
| CAPEC ground truth | [Galeax/CVE2CAPEC](https://github.com/Galeax/CVE2CAPEC) (ref. 55) |
| CAPEC accuracy | 89/100 |
| T5 split | 80% train / 20% validation |
| T5 training | lr 5e-5, AdamW, cross-entropy, 50 epochs |
| T5 results | BLEU 0.7589; ROUGE-1/2/L reported in Table 5 |
| FLAN-T5 | BASE variant, BLEU 0.6813 |
| Exploit mapping | Word2Vec + cosine for descriptions; SBERT + threshold for code |
| GUI | Flask + HTML/Bootstrap/JavaScript |
| Human evaluation | 20 CVEs, 3 cybersecurity experts |
| Human results | correctness 86.9%, completeness 4.3/5, clarity 4.4/5 |

## Target architecture in this repository

Keep the existing typed package and provider boundary. Add:

```text
src/vuln2action/
  connectors/exploitdb.py      # CSV metadata; no code execution
  mapping/                     # CVE-CWE-CAPEC candidate generation and ranking
    candidates.py
    word2vec.py
    tfidf.py
    select.py
  generation/
    t5.py                      # real training/inference adapter, not a stub
    flow_dataset.py            # CVE description -> Explore/Experiment/Exploit
  evaluation/
    capec/                     # accuracy against CVE2CAPEC
    generation/                # BLEU/ROUGE, FLAN-T5 comparison
  gui/                         # Flask app
labs/
  exploit-isolated/            # optional, local-only exploit code display
scripts/
  download_reproduction_data.py
  build_reproduction_dataset.py
  train_word2vec.py
  train_t5.py
  evaluate_capec.py
  evaluate_generation.py
```

The main pipeline must remain offline by default. Network access stays in
explicit scripts. Exploit code must never enter the retrieval corpus or a
public Kaggle dataset.

## Step 1: dataset build

The NVD 2.0 annual feeds start at 2002. Two selection modes are available:

- `stratified`: paper-faithful proportional sample across 2002-2023.
- `newest`: the latest 55,000 CVEs by NVD `published` timestamp, using all
  downloaded feeds (including 2024-2026 when present).

The target is **55,000 CVEs**, about half of the paper's 114,560.

Paper-faithful mode:

```bash
python scripts/download_reproduction_data.py --source all --start-year 2002 --end-year 2023
python scripts/build_reproduction_dataset.py --target-cves 55000 --seed 42 --selection-strategy stratified
```

Latest-CVE mode:

```bash
python scripts/download_reproduction_data.py --source all --start-year 2002 --end-year 2026
python scripts/build_reproduction_dataset.py --target-cves 55000 --selection-strategy newest
```

The generated `data/processed/reproduction/` uses the newest mode. The earlier
paper-faithful snapshot is kept at `data/processed/reproduction_paper_2023/`.

Latest mode is deliberately **not** the paper's 2023 cutoff. It selects the
latest 55,000 NVD records by `published` time, including NVD 2024-2026. Two
consequences must be reported in every result:

- None of the paper's 20 human-evaluation CVEs is in this 55k sample, so the
  20-CVE human-eval split is a deterministic latest-CVE fill. It is not the
  paper's human-eval set.
- Only 27 ExploitDB rows overlap the 55k sample, because recent CVEs rarely
  have public ExploitDB entries. The exploit-mapping stage needs either a
  historical exploit-linked subset or a future hybrid selection mode; it must
  not be evaluated on 27 rows as if that were the paper setup.

Outputs under `data/processed/reproduction/`:

```text
cves.jsonl                     selected CVE records
cwe.json                       CWE catalog with parent/CAPEC relations
capec.json                     CAPEC catalog with execution flows
cve_cwe.jsonl                  CVE-CWE pairs
cwe_capec.jsonl                CWE-CAPEC pairs
cve_capec_candidates.jsonl     candidate CAPECs for each CVE-CWE pair
cve2capec_reference.jsonl      evaluation-only reference mapping
exploitdb.jsonl                ExploitDB metadata; no source code
splits.json                    train/validation/CAPEC-eval/human-eval splits
stats.json                     counts, catalog versions, per-year distribution
```

The 100-CVE CAPEC evaluation set and 20-CVE human evaluation set are removed
from train/validation before the split to prevent leakage.

Some old NVD records use legacy CWE identifiers (for example CWE-264 or
CWE-399) that are absent from the current CWE catalog. They are kept as labels
with `cwe_in_catalog: false`; they produce no CWE→CAPEC candidates and are
reported in `stats.json` and by the audit script. They are not silently
rewritten to a modern CWE because that would introduce artificial labels.

The measured 55k snapshot and its deviation table are in
`docs/reproduction-dataset-report-vi.md`.

## Step 2: best-CAPEC selection

Candidates are the union of the CWE–CAPEC candidates for each CVE. The CVE
description is compared with each candidate CAPEC's `name + description`.
TF-IDF (unigram+bigram, sublinear TF) and Word2Vec (skip-gram, 100 dimensions,
window 5, 10 epochs, seed 42) are both evaluated with cosine similarity.

```bash
python scripts/select_capec.py --dataset data/processed/reproduction \
  --method both --scope eval --split capec_eval_100
python scripts/select_capec.py --dataset data/processed/reproduction \
  --method word2vec --scope all
```

Measured results:

| Method | Candidate coverage | Candidate recall | Top-1 / 100 | Top-1 among answered |
|---|---:|---:|---:|---:|
| TF-IDF | 80 | 80 | 78 | 97.5% |
| Word2Vec | 80 | 80 | 78 | 97.5% |

The paper reports 89/100. This reproduction reports **78/100**, not 89/100.
The main limit is candidate coverage: 20 of the 100 CVEs have no candidate
CAPEC because their direct CWE has no relation in the current CAPEC catalog.
On all 55,000 CVEs, Word2Vec selects a CAPEC for 39,181 CVEs and is correct on
38,374 of 38,581 answered CVEs (99.46% conditional; 69.77% over all 55,000).
Full details are in `docs/capec-selection-report-vi.md`.

## Step 3: execution-flow dataset

The selected CAPEC is converted into the paper's Explore/Experiment/Exploit
flow. Train/validation rows only are kept to avoid evaluation leakage.

```bash
python scripts/build_flow_dataset.py \
  --dataset data/processed/reproduction \
  --predictions data/processed/reproduction/capec_selection/capec_predictions_word2vec_all.jsonl \
  --out data/processed/reproduction/flow_dataset
```

Measured output: **30,077 rows** (23,964 train, 6,113 validation), 174 unique
CAPECs, mean 4.03 steps and 5.75 techniques per flow. 25,484 rows have all three
phases. 15,793 CVEs have no selected CAPEC and 9,010 selected CAPECs have no
execution flow.

`flow_dataset.jsonl` stores `target` (description + techniques),
`target_steps`, and `target_techniques`. Their word-length means/P90 are
258.6/521, 145.3/290, and 113.9/230. Because the targets are long, the training
default is `target_techniques` with `max_target_length=256`; a 128-token budget
truncates many flows. Full details are in `docs/flow-dataset-report-vi.md`.

## Step 4: technique -> ExploitDB description mapping

Each flow technique is matched to the closest ExploitDB description with
Word2Vec + cosine similarity. Only descriptions and metadata are used; exploit
source code is never downloaded or executed.

```bash
python scripts/map_techniques_exploitdb.py \
  --flow-dataset data/processed/reproduction/flow_dataset \
  --exploitdb data/processed/reproduction/exploitdb.jsonl \
  --out data/processed/reproduction/flow_dataset_stage2 \
  --epochs 10
```

Measured output: 665 unique techniques, all mapped to 46,709 ExploitDB
descriptions, mean cosine 0.8911 (median 0.8933). The stage-2 target
`target_exploit_techniques` has mean length 37.4 words (P90 65), so 128 target
tokens are sufficient for this field. Full details are in
`docs/stage2-exploit-mapping-report-vi.md`.

This is a semantic, CVE-independent mapping. Only 27 ExploitDB rows share a CVE
with the latest 55k sample, so the paper's CVE-specific exploit-code retrieval
and SBERT threshold stage remain blocked until a hybrid or historical
exploit-linked subset is added.

## Step 5: local Flask GUI

The GUI reads only the local dataset and never executes exploit code.

```bash
pip install -e ".[gui]"
python gui/app.py
# http://127.0.0.1:5000
```

It accepts a CVE id from the 55k sample or a free description, shows the selected
CAPEC, the Explore/Experiment/Exploit flow, candidate CAPECs, and technique ->
ExploitDB descriptions. It also exposes `GET /health` and
`GET /api/analyze?cve_id=...`. With the real dataset, `/health` reports 55,000
CVEs, 615 CAPECs, 39,181 predictions, and 665 technique mappings. See
`docs/gui-report-vi.md`.

The GUI currently displays the reference CAPEC flow, not a T5-generated flow;
that mode waits for a trained checkpoint.

## T4 x2 training configuration

Kaggle provides 2 x T4 (16 GB each). Use:

- `t5-base` as the primary model; `t5-small` only as a fallback/ablation.
- DDP across 2 GPUs, `fp16`, per-device batch size 8, gradient accumulation 4
  (effective batch 32).
- `max_input_length=256`, `max_target_length=256` for the flow targets. The
  earlier 128-token plan is kept only as a fallback and must use
  `target_techniques`; 128 truncates a large fraction of the full targets.
- `gradient_checkpointing=True`.
- learning rate `5e-5`, AdamW, cross-entropy.
- 50 epochs as the target; record the actual number if quota forces a stop.
- checkpoint every 500-1000 steps, save to Kaggle Dataset/Drive, resume with
  `resume_from_checkpoint`.
- benchmark one epoch before committing to 50; if an epoch is too slow, reduce
  the dataset or use `t5-small` and record the deviation.

```bash
python -m torch.distributed.run --nproc_per_node=2 scripts/train_t5.py \
  --dataset data/processed/reproduction/flow_dataset \
  --output-dir outputs/t5_stage1 \
  --model-name t5-base --target-field target_techniques \
  --max-input-length 256 --max-target-length 256 \
  --per-device-batch-size 8 --gradient-accumulation-steps 4 \
  --save-steps 500 --eval-steps 500 --auto-resume

python scripts/evaluate_t5.py \
  --checkpoint outputs/t5_stage1/final \
  --dataset data/processed/reproduction/flow_dataset \
  --target-field target_techniques --num-beams 4
```

`scripts/train_t5.py` also accepts `--stage 2 --target-field <field>` for a
future exploit-enriched target. The current flow dataset has no such field, and
stage 2 is blocked by the 27-row ExploitDB overlap documented above.

Using multiple Kaggle accounts to bypass quota is not a design assumption and
may violate Kaggle's terms. The training code must be able to finish under a
single account's quota through checkpoint/resume. Extra accounts may only run
independent experiments, not evade limits.

## Evaluation plan

1. **CAPEC mapping**: 100 CVEs, compare selected CAPEC against CVE2CAPEC;
   report accuracy and per-CWE/per-year error analysis.
2. **Generation**: BLEU and ROUGE-1/2/L on the 20% validation split.
3. **Model comparison**: T5 vs FLAN-T5-base under the same split.
4. **Exploit mapping**: qualitative examples plus retrieval similarity scores;
   SBERT threshold study.
5. **Resource use**: inference latency and CPU/GPU memory on the available
   hardware, clearly labelled as T4 x2 rather than A100.
6. **Human evaluation**: 20 CVEs, correctness/completeness/clarity. Latest
   mode uses 20 deterministic recent CVEs, not the paper's 20 CVEs (none of the
   paper CVEs is in the latest 55k sample). The reproduction currently has one
   advisor reviewer, not the paper's three independent experts. Report this as
   a **single-expert advisor review**, not as a three-expert study. Optional
   internal sanity checks may be added, but they must not be merged into the
   advisor's scores.

## Safety boundary

- Exploit code is stored only under a git-ignored local directory and is
  displayed only by the isolated lab with explicit opt-in.
- The executor remains localhost-only; no real-world targets.
- No automatic execution of retrieved exploit code.
- Kaggle uploads contain CVE/CWE/CAPEC/ExploitDB **descriptions and metadata**
  only, never exploit source files.

## 14-day schedule

| Day | Milestone |
| --- | --- |
| 1-2 | Data audit; download/parse NVD, CWE, CAPEC, ExploitDB, CVE2CAPEC |
| 3 | Candidate CAPEC generation; TF-IDF/Word2Vec; 100-CVE evaluation |
| 4 | Build execution-flow dataset; 80/20 split; benchmark one T5 epoch |
| 5-8 | T5 stage 1 and stage 2 training; checkpoint/resume |
| 9 | SBERT exploit mapping; BLEU/ROUGE evaluation |
| 10 | Flask GUI; end-to-end pipeline; isolated lab mode |
| 11 | Advisor human evaluation (20 CVEs, single reviewer) |
| 12 | Tests, reproducibility scripts, docs |
| 13 | Buffer and fixes |
| 14 | Freeze, demo, final report |

## Reporting rules

Every report must distinguish:

- paper values vs reproduced values;
- A100 vs T4 x2;
- full 50 epochs vs early stopping;
- `t5-base` vs `t5-small`;
- paper's three independent experts vs this reproduction's single advisor
  reviewer;
- public metadata vs local-only exploit code.

The final report must not claim exact reproduction of the paper.
