# Human evaluation package

Status: **PARTIALLY DONE — not yet sendable**.

Files:
- `protocol.md` — rubric, flags, aggregation, safety instructions.
- `reviewer-form.md` — one block per case, separate reference section.
- `cases.json` — candidate list of 20 CVE ids with provenance.
- `sampling-and-data-format.md` — authoritative sampling, JSONL schema and
  advisor instructions. No scores are filled.

## Why it is not sendable yet

1. `data/processed/reproduction/` is absent on this machine. The authoritative
   case list is `splits.json["human_eval_20"]`, produced by
   `src/vuln2action/connectors/reproduction.py:make_splits`. `cases.json` contains
   the source list `PAPER_HUMAN_EVAL_CVES`, which may be padded deterministically
   when a CVE is outside the selected cutoff.
2. The generated workflows for those cases are not available locally. They
   require the paper-scale dataset plus a stage-1 checkpoint; the Kaggle run is
   still in progress.
3. No score has been filled and none will be filled by the team.

## To make it sendable

- Obtain `splits.json` from the dataset owner or rebuild the dataset.
- Replace `cases.json["cve_ids"]` with the exact `human_eval_20` list.
- Generate the 20 workflows with the chosen provider and checkpoint.
- Fill dataset sha256, checkpoint id and settings in the form header.
- Send `protocol.md` + filled `reviewer-form.md` to the advisor.

## Non-claims

- One advisor reviewer, not three experts.
- Not a reproduction of the paper's Table 6.
- No workflow execution by the reviewer.
- No fabricated or pre-filled scores.
