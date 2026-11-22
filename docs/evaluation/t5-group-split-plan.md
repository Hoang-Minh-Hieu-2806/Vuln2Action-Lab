# T5 holdout / group-split plan

Status: **PLAN ONLY — not executed, no dataset or training config changed.**

## Problem

The paper-scale flow dataset has 55,420 rows but only 176 distinct CAPEC
execution-flow targets. A CVE split alone does not prevent the same target text
from appearing in both train and validation:

- 11,083 / 11,089 validation targets already appear verbatim in training.
- The earlier 28-case split had 3 near-duplicates at `difflib` similarity >= 0.85.
- BLEU measured on such a validation set measures template recall, not
  generalisation to unseen attack flows.

## Proposed protocol

1. **Group key:** primary key is the normalised target text (`target`,
   `target_steps` or `target_techniques`, whichever field is being evaluated).
   Secondary key is the source CVE id.
2. **Grouping:** join records that share a normalised target, and additionally
   records whose targets have `difflib.SequenceMatcher` ratio >= 0.85. Use
   union-find so transitive near-duplicates stay in one group.
3. **Split at group level:** assign whole groups to train / validation / test.
   Never split a group across sets. Keep a deterministic seed and record it.
4. **Fixed test holdout:** the test group set is written once and is not used for
   decoding choices, epoch selection, checkpoint selection or prompt edits.
5. **Leakage report before training:** publish exact-duplicate count,
   normalised-duplicate count, near-duplicate pair count, and CVE overlap for
   every split pair.
6. **After split:** assert zero shared group ids between sets. Store the split
   manifest with a SHA-256 next to the model artifact.

## Reporting

Report CVE-only, gold-CAPEC-conditioned and hybrid results separately. Do not
merge them into a single headline BLEU. For each result state:
- which split was used;
- whether the split was group-disjoint;
- whether any decoding choice was tuned on that split;
- the number of cases and the number of distinct targets.

## Scope boundaries

- Do not modify `data/processed/reproduction/flow_dataset*` in this phase.
- Do not retrain stage 1 or start stage 2.
- Do not reuse the current validation set as a "new" holdout after tuning on it;
  `docs/generation-quality.md` already disclosed that its decoding preset was
  chosen on those 28 cases.

## Minimum implementation sketch (not applied)

```text
normalise(text) -> lowercase, collapse whitespace, strip numbering
pairs = [(i, j, ratio) for targets where ratio >= 0.85]
groups = union_find(exact-normalised matches + near-duplicate pairs)
assign groups -> train/validation/test with fixed seed
assert group_ids(train) & group_ids(validation) == empty
assert group_ids(train | validation) & group_ids(test) == empty
```
