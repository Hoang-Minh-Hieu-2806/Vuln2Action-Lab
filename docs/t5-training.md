# T5 execution-flow generation (P1.1)

The `t5` provider is now a real seq2seq generator instead of a stub. It maps a
vulnerability description to a structured **Explore → Experiment → Exploit**
flow and returns it as the same typed `Workflow` the rest of the pipeline
consumes, so rule-based and T5 remain interchangeable.

> All output is **textual guidance**. Nothing here is a validated exploit, and
> the generator is never pointed at a real target.

## 1. What is generated

```
CAPEC-10 Buffer Overflow via Environment Variables
1. Explore: [Determine target application] The adversary identifies a target …
2. Experiment: [Find injection vector] The adversary identifies an injection …
3. Exploit: [Overflow the buffer] The adversary crafts input that overflows …
```

`parse_flow()` accepts numbered and unnumbered phase markers on separate lines
or run together, because small checkpoints frequently drop newlines.
`flow_to_workflow()` turns parsed steps into `WorkflowStep`s; if generation is
unparseable the raw text is preserved as a single `review` step rather than
being dropped.

## 2. Training data provenance

Built by `scripts/build_t5_dataset.py` from **MITRE CAPEC `Execution_Flow`**.

| Property | Value |
| --- | --- |
| Source | `data/raw/capec/capec_latest.xml` (opt-in download) |
| Label origin | Each `Attack_Step`'s analyst-assigned `Phase` (`Explore`/`Experiment`/`Exploit`) and description text, copied verbatim |
| Patterns in catalog | 615 |
| Patterns with a usable 3-phase flow | 239 |
| Records kept | **176** (a pattern must declare ≥1 step in *all three* phases) |
| Steps | Explore 204 · Experiment 242 · Exploit 205 |
| Split | 148 train / 28 validation (deterministic SHA-256 bucket, seed 13) |

**What the labels are.** CAPEC phases are MITRE's own classification of attack
steps: a real, external ground truth. We only re-order steps by phase and
re-render them; no step, technique, or exploit is invented.

**What they are not.** A CAPEC pattern is a *class* of attack, not a concrete
CVE. These targets are procedural abstractions. They contain no product-specific
preconditions, no versions, and no executable payloads. The dataset file itself
records this in `provenance.ground_truth_claim` and `limitations`.

Inputs are the pattern's id, name, description, related CWEs and any example
CVEs MITRE lists. No CVE scraping happens in the builder, so it stays offline
once the CAPEC snapshot exists.

## 3. Commands

```bash
# 0. Optional heavy extra (not needed for the rule-based baseline or CI)
python -m pip install -e ".[t5]"

# 1. Build the dataset (requires the CAPEC snapshot)
python scripts/download_data.py --source capec      # explicit download
python scripts/build_t5_dataset.py                  # -> data/processed/t5_flows.json

# 2. Fine-tune on CPU (deterministic seed; downloads only when allowed)
python scripts/train_t5.py --allow-download \
    --epochs 6 --batch-size 8 --max-steps 120 \
    --learning-rate 1e-3 --max-target-length 320 --seed 13

# 3. Generate
python scripts/run_t5.py --sample CVE-2024-0002 \
    --checkpoint models/t5-capec-flows
```

`--allow-download` is required to fetch `t5-small`/`t5-base` weights. Without
it the scripts use only the local Hugging Face cache, so an offline machine
fails with an actionable message instead of downloading silently. The
`models/` directory is git-ignored; only `models/.gitkeep` is tracked.

Training writes `models/<run>/training_summary.json` with the seed, hyper
parameters, per-epoch losses and the final validation loss.

## 4. Measured training run (this machine, CPU only)

A bounded run was executed end-to-end; these are the real numbers from
`models/t5-capec-flows/training_summary.json`.

| Setting | Value |
| --- | --- |
| Base | `t5-small` (60.5M params) |
| Device | CPU |
| Epochs × steps | 6 × 20 = **120 steps** |
| Batch size | 8 |
| Learning rate | 1e-3 |
| Max target length | 320 |
| Seed | 13 |
| Final train loss | **2.4443** |
| Validation loss | **2.4777** |
| Wall clock | ~27 min |

Loss trajectory: 4.39 (epoch 1) → 3.41 → 3.08 → 2.85 → 2.62 → 2.44.
Loss fell steadily and validation tracked training, so the run is healthy.

### Quality: what actually works and what does not

Verified by generating validation-split patterns with the fine-tuned
checkpoint:

**Works**
- Emits the correct header (`CAPEC-10 Buffer Overflow via Environment Variables`).
- Emits the three phase labels in the right order.
- Produces a plausible step count (4–6) rather than a fixed template.

**Does not work**
- Descriptions **repeat**: a typical output is `[Determine target application]`
  repeated for Experiment steps. The model learned the *shape* of a flow and
  the phase vocabulary, but not the per-step content.
- It is not CVE-specific. Given the repo's fake `CVE-2024-0002`, it produced
  degenerate output (`Experiment: Experiment: …`) because that text is far from
  its training distribution.

**Honest conclusion:** fine-tuning ran and the loss dropped substantially, but
120 CPU steps on 148 records is a *demonstration that the pipeline works*, not a
usable generator. Reaching the paper's BLEU ≈ 0.75 would need orders of magnitude
more compute and data than were available here. No quality claim is made.

## 5. Limitations

- **Scale:** 176 records and 120 optimizer steps. The paper trains on 114,560
  CVEs; nothing here is comparable.
- **Target granularity:** attack-pattern level, not CVE-level. A flow explains
  "how this class of attack proceeds", not "what to type against version X".
- **Coverage:** only 239 of 615 CAPEC patterns document all three phases, so the
  model cannot describe patterns whose flows are incomplete.
- **Repetition:** greedy/beam decoding with a small model loops. Adding
  `no_repeat_ngram_size` or training longer would help; not done here.
- **Determinism:** seeds are fixed and batch order is driven by a fixed
  `torch.Generator`, but CPU BLAS reductions are not bit-identical across
  machines, so exact losses will vary slightly elsewhere.
- **No evaluation yet:** BLEU/ROUGE scoring is P1.2 and is intentionally out of
  scope. The metrics above are training/validation loss only.
