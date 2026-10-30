# Execution-flow generation evaluation (P1.2)

Reproducible evaluation of the `t5` generator against the `rule_based` baseline on
the held-out CAPEC validation split, plus an audit of train/validation leakage.

> These are **language-overlap metrics on attack-pattern prose**. They say how
> closely a generated flow resembles MITRE's written flow. They do not say the
> flow is correct, complete, or safe. Treat them as a regression signal.

## 1. Commands

```bash
# One-time prerequisites (dataset from P1.1; checkpoint already trained there)
python scripts/download_data.py --source capec
python scripts/build_t5_dataset.py
python scripts/train_t5.py --allow-download --epochs 6 --batch-size 8 --max-steps 120

# Evaluate (CPU, ~3-4 min for 28 cases; no download needed)
python scripts/run_evaluation.py --stage generation --systems rule_based,t5 \
    --save results/evaluation/generation

# Optional control group: stock FLAN-T5 (never fine-tuned here)
python scripts/run_evaluation.py --stage generation --systems flan-t5 --allow-download
```

Outputs land in `results/evaluation/generation/generation_<UTC>/`:
`report.json`, `report.md`, `per_case.csv`, `leakage.json`.

## 2. Metric definitions

| Metric | Definition | Notes |
| --- | --- | --- |
| Corpus BLEU | sacrebleu algorithm, n=4, `exp` smoothing, one brevity penalty | Pooled counts; the primary BLEU number |
| Sentence BLEU | same, per case, averaged | Short flows fall below 4-gram order and score 0, so it is naturally low |
| ROUGE-1/2/L | Lin (2004), F1 over word n-grams; L via LCS | No stemming |
| Phase order accuracy | candidate phase sequence == reference sequence | Strict: a repeated phase fails |
| Phase order (dedup) | same after collapsing consecutive repeats | Isolates "right skeleton" from "looped" |
| Phase coverage | share of Explore/Experiment/Exploit present | 0 … 1 |
| Output validity | all three phases present and text non-empty | Binary, averaged |
| Repetition rate | `1 − unique 3-grams / total 3-grams` | Looping text approaches 1.0 |
| Phase step recall | share of reference steps in a phase that a candidate step covers (≥50% token overlap) | Per-phase diagnostic |

BLEU is validated against `sacrebleu` and ROUGE against `rouge_score` in
`tests/unit/test_generation_metrics.py` (fixed reference values, so the extra
packages are not a CI dependency).

## 3. Leakage audit — read this before the scores

The dataset split is a hash of the CAPEC id, so no id appears in both splits.
But sibling patterns share near-identical MITRE prose, so text-level leakage is
possible. `audit_leakage()` compares every validation target against every train
target with `difflib`, flagging pairs ≥ 0.85 similarity.

Measured on this split (threshold 0.85):

| Validation | Closest train case | Similarity | Shared CWE |
| --- | --- | --- | --- |
| CAPEC-53 Postfix, Null Terminate, Backslash | CAPEC-52 Embedding NULL Bytes | 0.928 | yes |
| CAPEC-591 Reflected XSS | CAPEC-247 XSS Using Invalid Characters | 0.892 | no |
| CAPEC-143 Detect Unpublicized Web Pages | CAPEC-144 Detect Unpublicized Web Services | 0.875 | yes |

- CAPEC id overlap: **0**
- Exact duplicate targets: **0**
- Near-duplicates: **3 of 28**
- **Leakage-free subset: 25 cases**

All scores are reported on both the full 28 and the clean 25. The gap is small
(e.g. corpus BLEU 0.0877 → 0.0802 for T5), so leakage is not inflating the
headline, but the clean subset is the honest number and is what should be quoted.

## 4. Results (28 validation cases)

| System | Corpus BLEU | Sentence BLEU | ROUGE-1 | ROUGE-2 | ROUGE-L | Phase order | Phase (dedup) | Coverage | Valid | Repetition |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| rule_based | 0.0010 | 0.0057 | 0.1191 | 0.0093 | 0.0874 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| t5 (fine-tuned) | **0.0877** | 0.0751 | 0.3207 | 0.1174 | 0.2254 | 0.0000 | 0.1786 | 0.5833 | 0.1786 | 0.5785 |

Leakage-free subset (25 cases):

| System | Corpus BLEU | Sentence BLEU | Phase order | Repetition |
| --- | --- | --- | --- | --- |
| rule_based | 0.0011 | 0.0061 | 0.0000 | 0.0000 |
| t5 | 0.0802 | 0.0669 | 0.0000 | 0.5816 |

### Per-phase step recall

| System | Explore | Experiment | Exploit |
| --- | --- | --- | --- |
| rule_based | 0.0000 | 0.0000 | 0.0000 |
| t5 | 0.0357 | 0.0000 | 0.0000 |

### How to read this

- **The metric separates the systems.** T5 is ~88× corpus BLEU and ~2.7× ROUGE-1
  over the baseline, so the harness is measuring a real difference, not noise.
- **T5 is still poor in absolute terms.** 0.0877 corpus BLEU is far from the
  paper's ~0.75. That gap is the honest finding of P1.1/P1.2.
- **The rule-based baseline is not a fair rival** for this task: it emits lab
  procedure steps ("Start isolated lab", "Run lab validator"), not CAPEC attack
  prose. Its near-zero score is expected and is useful only as a lower bound.
- **Phase order is 0.0000 for both.** T5 emits the right labels in order but
  repeats them (see §5), so the strict metric fails. The dedup variant (0.1786)
  and phase coverage (0.5833) show that the skeleton is partially learned. With
  28 cases, one case moves the dedup metric by 0.0357.
- **Exploit is the weakest phase**: present in only 5/28 outputs, so exploit-step
  recall is 0.0000. Experiment is missing in 12/28.

## 5. Failure analysis (5 representative cases)

Taken from `report.json` → `systems.t5.failures`, sorted worst-first.

1. **CAPEC-127 Directory Indexing** — BLEU 0.0012, repetition 0.7429, missing
   Experiment and Exploit.
   `1. Explore: [Determine target directory] … crafts a malicious directory tree …
   - The adversary crafts a malicious directory tree on a target directory.` (×many)
   *Mode:* the model latches onto one sentence and loops.

2. **CAPEC-19 Embedding Scripts within Scripts** — BLEU 0.0123, repetition
   0.5132, missing Exploit.
   `- The adversary must first identify a target application that they wish to
   target.` repeated inside the Explore step.
   *Mode:* technique bullets repeat; the flow never advances phase.

3. **CAPEC-692 Spoof Version Control System Commit Metadata** — BLEU 0.0227,
   repetition 0.6489, missing Experiment and Exploit; the text degenerates into
   `an automated tool, an automated tool, an automated tool, …`
   *Mode:* degenerate token loop, the classic small-model failure.

4. **CAPEC-644 Use of Captured Hashes (Pass The Hash)** — BLEU 0.0266,
   repetition 0.5224, missing Experiment and Exploit. It reuses generic web-app
   boilerplate (`Survey the application for user-controllable inputs`, `Use a
   spidering tool`) that belongs to XSS patterns.
   *Mode:* **hallucinated/mismatched content** — plausible CAPEC wording applied
   to the wrong attack class.

5. **CAPEC-499 Android Intent Intercept** — BLEU 0.0278, repetition 0.4925,
   missing Experiment and Exploit; same web-app boilerplate as case 4.
   *Mode:* same as above; the model has not learned mobile-specific vocabulary.

The five cover the three failure families requested: repeated text (1, 2, 3),
hallucinated steps (4, 5), and missing phases (all five; Exploit missing 23/28,
Experiment 12/28).

## 6. FLAN-T5 control group

`--systems flan-t5` loads `google/flan-t5-small` unchanged. It is recorded with
`fine_tuned: false` and `kind: baseline`, so it can never be mistaken for a
model trained in this project. On 3 cases it scored corpus BLEU 0.0000 — i.e. it
produces prose that does not follow the phase format at all. It is a control, not
a competitor, and no conclusion is drawn from it here.

## 7. Dataset provenance

- Source: MITRE CAPEC `Execution_Flow` phases (see `docs/t5-training.md`).
- 176 flows (148 train / 28 validation), 651 steps.
- Labels are MITRE's analyst-assigned phases, copied verbatim.
- Targets are attack-pattern prose, **not** validated reproduction steps for any CVE.

## 8. Limitations

- **28 validation cases.** Confidence intervals are wide; treat differences as
  directional. The clean subset is 25.
- **BLEU/ROUGE measure surface overlap.** A correct flow phrased differently
  scores low; a wrong flow echoing MITRE boilerplate scores higher. This is why
  the failure analysis matters more than the table.
- **Leakage threshold is a judgement call** (0.85 difflib). All flagged pairs are
  listed so a reader can disagree and re-run with `NEAR_DUPLICATE_THRESHOLD`.
- **The checkpoint is weak.** Repetition 0.58 and Exploit missing in 23/28 cases
  mean the generator is a working pipeline, not a usable assistant.
- **No human evaluation** and no semantic metric (BERTScore); both are out of
  scope for P1.2.
- **Not comparable to the paper**: different data (176 vs 114,560 records),
  different compute (CPU, 120 steps vs A100), different target granularity.
