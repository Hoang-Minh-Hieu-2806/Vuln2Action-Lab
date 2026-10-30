# Execution-flow quality improvements (P1.3)

Diagnosis of the P1.2 failures, the decoding changes that address them, and a
before/after comparison on the **same** 28-case validation set (25-case leakage-free
subset). No retraining was performed; the P1.1 checkpoint is untouched.

> **Tuning disclosure.** Every decoding choice below was selected by looking at the
> *validation* split only. The test-like role of this split is therefore spent:
> these numbers are optimistic relative to a fresh hold-out, and no new
> held-out evaluation exists yet. Nothing was tuned on the independent CAPEC set.

## 1. Diagnosis

Measured on the P1.2 baseline outputs (`t5-baseline`, 28 cases):

| Symptom | Measurement | Cause |
| --- | --- | --- |
| Repeated phases | 12/28 outputs were `Explore` only; 23/28 had >0.5 3-gram repetition (mean 0.58) | Greedy n-gram loop *inside* one step body |
| Truncation | 14/28 outputs sat at the 256-token cap; 25/28 did not end on terminal punctuation | The loop consumed the budget before the next phase |
| Missing Exploit | 23/28 outputs had no Exploit phase | Direct consequence of truncation |
| Hallucinated boilerplate | Cases like CAPEC-644/499 (non-web attacks) emitted web-app text | Small model + generic CAPEC phrasing in training data |
| **Root cause in training data** | **54% of training targets (80/148) exceeded the 320-token training cap, and 42 of those lost the Exploit phase entirely** | Training truncated targets, so the model rarely saw a complete flow |

The last row is the important one: the model was partly *taught* to stop before
Exploit. Decoding can work around this, but cannot fully repair it.

## 2. Changes

### 2.1 Decoding (no retraining)

`T5ProviderSettings` gained `no_repeat_ngram_size`, `repetition_penalty`,
`length_penalty`, `early_stopping`, `min_new_tokens`, `normalise_output`. Defaults
are neutral, so an untouched config reproduces P1.2 exactly.

Two named presets live in `evaluation/generation/evaluate_generation.py`:

| Preset | Settings |
| --- | --- |
| `baseline` | `max_new_tokens=256`, `num_beams=4` (P1.2 reproduction) |
| `improved` | `max_new_tokens=512`, `num_beams=4`, `no_repeat_ngram_size=3`, `repetition_penalty=1.15`, `length_penalty=2.0`, `early_stopping=True` |

`no_repeat_ngram_size` breaks the within-step loop; `length_penalty=2.0` makes beam
search prefer the longer complete flow, which restores the brevity penalty that
shorter outputs would otherwise lose.

### 2.2 Structural enforcement (`normalise_flow_structure`)

Applied only to produced text. It **reorders** steps so the phase order is
Explore → Experiment → Exploit. It **never** inserts a phase, drops a step, or
merges repeated phases — an earlier implementation collapsed consecutive
duplicates, which deleted legitimate MITRE steps (two `Experiment` steps are
normal) and was reverted. When phases are missing they are reported in
`Workflow.safety` (`missing phases: Exploit`), not filled in.

### 2.3 Evaluator fidelity fixes

Two measurement defects were found and fixed while doing this:

- The candidate header omitted the CAPEC name (`CAPEC-10` vs
  `CAPEC-10 Buffer Overflow via Environment Variables`), penalising both systems
  unfairly. The name now comes from the case metadata.
- Step detail was truncated at 800 characters (6–11 lines hit it); raised to 1200.

Because of the header fix, the *baseline* numbers here are slightly higher than
the P1.2 report (corpus BLEU 0.0877 → 0.1121). This table is internally
consistent; do not compare `t5-baseline` here against the P1.2 table.

## 3. Results — 28 validation cases

| System | Corpus BLEU | Sentence BLEU | ROUGE-1 | ROUGE-2 | ROUGE-L | Phase order | Phase (dedup) | Coverage | Valid | Repetition |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| rule_based | 0.0010 | 0.0057 | 0.1191 | 0.0093 | 0.0874 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| t5-baseline | 0.1121 | 0.1062 | 0.3355 | 0.1375 | 0.2511 | 0.0000 | 0.1786 | 0.5833 | 0.1786 | 0.5992 |
| **t5-improved** | **0.1337** | **0.1195** | **0.4265** | **0.1794** | **0.2517** | **0.5000** | **1.0000** | **1.0000** | **1.0000** | **0.0069** |

Leakage-free subset (25 cases):

| System | Corpus BLEU | Sentence BLEU | ROUGE-1 | Phase order | Phase (dedup) | Valid | Repetition |
| --- | --- | --- | --- | --- | --- | --- | --- |
| rule_based | 0.0011 | 0.0061 | 0.1193 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| t5-baseline | 0.1044 | 0.0982 | 0.3252 | 0.0000 | 0.1600 | 0.1600 | 0.6027 |
| **t5-improved** | **0.1288** | **0.1147** | **0.4182** | **0.5200** | **1.0000** | **1.0000** | **0.0077** |

Per-phase step recall:

| System | Explore | Experiment | Exploit |
| --- | --- | --- | --- |
| rule_based | 0.0000 | 0.0000 | 0.0000 |
| t5-baseline | 0.0357 | 0.0000 | 0.0000 |
| t5-improved | 0.0000 | 0.0357 | **0.2262** |

### Improvement summary

- Repetition **0.5992 → 0.0069** (86× lower).
- Output validity **0.1786 → 1.0000**: every output now has all three phases.
- Phase coverage **0.5833 → 1.0000**; dedup phase order **0.1786 → 1.0000**.
- Corpus BLEU **0.1121 → 0.1337** (+19%); ROUGE-1 0.3355 → 0.4265.
- Exploit recall 0.0 → 0.2262: Exploit is now present everywhere, and its content
  partially matches MITRE about a fifth of the time.

### Ablation (validation only, used to choose the preset)

These runs predate the header fix in §2.3, so their absolute BLEU is lower than
the table in §3. Only the *relative* ordering is used; the chosen preset was
re-measured after the fix (that is the `t5-improved` row in §3).

| Variant | Corpus BLEU | Strict phase | Repetition |
| --- | --- | --- | --- |
| no-repeat 5-gram only, lp=1.0 | 0.1401 | 0.1429 | 0.3140 |
| no-repeat 2-gram + rep-penalty 1.05, lp=1.0 | 0.0254 | 0.3214 | 0.0020 |
| no-repeat 3-gram + rep-penalty 1.15, lp=1.5 | 0.0807 | 0.5000 | 0.0026 |
| **no-repeat 3-gram + rep-penalty 1.15, lp=2.0** | **0.1117** | **0.5000** | **0.0028** |
| same, lp=2.5 | 0.1132 | 0.5000 | 0.0030 |

`no_repeat_ngram_size=5` alone gives the highest BLEU but leaves repetition at
0.31 and phase accuracy at 0.14: it is the weaker fix measured on the wrong axis.
`n=2` controls repetition but strangles output length. `lp=1.5` is over-eager and
shortens flows. `lp=2.0` and `lp=2.5` are close; 2.0 was kept as the more
conservative length bias.

## 4. Five representative outputs (improved)

1. **CAPEC-127 Directory Indexing** — BLEU 0.002 → 0.059, repetition 0.722 → 0.000.
   `1. Explore: [Survey the application for directory indexing] … | 2. Experiment:
   [Determine target directory] … | 3. Exploit: …` Previously a single looping
   Explore step; now a complete three-phase flow.
2. **CAPEC-10 Buffer Overflow via Environment Variables** — BLEU 0.1458 → 0.1828,
   repetition 0.575 → 0.010. Complete flow, and the Experiment step is on-topic
   ("an adversary will attempt to overflow the buffer").
3. **CAPEC-74 Manipulating State** — **regression**: BLEU 0.0879 → 0.0598 while
   repetition falls 0.764 → 0.007. The loop is gone but the replacement text is
   vaguer ("identify a target or an adversary to identify the target"), so
   surface overlap with MITRE drops.
4. **CAPEC-198 XSS Targeting Error Pages** — **regression**: BLEU 0.1355 → 0.0417,
   repetition 0.638 → 0.000. Now structurally valid, but the Experiment step
   drifts into unrelated web-server wording.
5. **CAPEC-644 Use of Captured Hashes (Pass The Hash)** — BLEU 0.0838 → 0.1583,
   repetition 0.595 → 0.000. Structure fixed, but it still opens with web-app
   boilerplate ("Survey the application for user-controllable inputs") for a
   credential-theft attack — the hallucination mode is **not** fixed.

## 5. Regressions

Sentence BLEU improves on 17/28 cases and worsens on 11, despite the corpus
average rising. The losses are concentrated in cases where the baseline's loop
happened to echo reference phrasing; removing the loop removes that accidental
overlap. Absolute losses are small (0.005–0.094) except CAPEC-198 (0.1355 →
0.0417) and CAPEC-252 (0.1713 → 0.1000). None regress below the rule-based
baseline.

Strict phase-order accuracy is 0.5 rather than 1.0 because 14 references contain
more than three steps (e.g. two `Experiment` steps) while improved outputs emit a
minimal three-phase skeleton. That is a *granularity* mismatch, not a format
failure — dedup phase order is 1.0000.

## 6. Is decoding enough? (proposal, not executed)

Decoding fixed structure and repetition but not content. The remaining bottleneck
is in the data: 54% of training targets were truncated at 320 tokens, and 42 of
those never contained an Exploit phase, so the model was trained to omit it.

**Minimal proposed change (requires approval, no retraining done):**

1. Raise `--max-target-length` to 512 and `--max-input-length` to 512 (inputs
   already fit; only targets were cut).
2. Filter or truncate-per-phase instead of truncating the tail, so no target ever
   ends before Exploit.
3. Retrain with the same seed/hyper-parameters for a like-for-like comparison.

Expected effect: Exploit presence should stop depending on decoding luck. This
must be measured, not assumed.

## 7. Limitations

- **Validation-set tuning.** The preset was chosen on these 28 cases; the numbers
  are optimistic and a fresh hold-out is needed before quoting them elsewhere.
- **No retraining**, so the truncation defect in the training data remains.
- **Content quality is still poor.** Corpus BLEU 0.1337 is far from the paper's
  ~0.75; hallucinated boilerplate persists (CAPEC-644) and per-phase recall for
  Explore/Experiment is ≤0.04.
- **28 cases / 25 clean.** One case moves corpus BLEU by roughly 0.004 and phase
  accuracy by 0.036.
- **Structural repair only reorders.** It cannot create a missing phase, and a
  missing phase is surfaced in `safety` rather than silently filled.
- CPU decoding with `lp=2.0` and 512 tokens takes ~19 minutes for 28 cases, so
  this configuration is impractical for interactive use.

## 8. Reproduce

```bash
# baseline (P1.2 decoding) and improved, same cases
python scripts/run_evaluation.py --stage generation --systems t5-baseline \
    --save results/evaluation/generation
python scripts/run_evaluation.py --stage generation --systems t5-improved \
    --save results/evaluation/generation
python scripts/run_evaluation.py --stage generation --systems rule_based \
    --save results/evaluation/generation
```

Run the systems separately: `lp=2.0` at 512 tokens makes a combined run exceed a
one-hour CPU budget.
