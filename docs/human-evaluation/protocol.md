# Human evaluation protocol (single advisor reviewer)

## Purpose

Collect an independent judgement of the generated reproduction workflows. This
is a **single-advisor review**, not the paper's three-expert study. It must never
be reported as a reproduction of the paper's human evaluation.

## Scope

- Cases: 20 CVE ids recorded in `cases.json`.
- Reviewer: 1 advisor, with cybersecurity background.
- Object of evaluation: the generated workflow text only.
- Reviewer does **not** execute any workflow and does **not** access any real
  target system.

## Material shown to the reviewer

For each case, provide:
1. CVE id and verbatim NVD description.
2. Generated workflow (the steps to evaluate), with provider and checkpoint id.
3. Optional: selected CAPEC id and name.

Keep the following in a **separate reference section** that is not shown until
the reviewer has scored the case:
- Reference CAPEC execution flow.
- Expected technique keywords.
- ExploitDB description used as weak reference.

Rationale: avoid leaking the expected answer into the scored material.

## Rubric

Score each criterion on a 1-5 scale. Also allow the explicit flags
`Insufficient information`, `Not applicable`, and `Cannot assess`; a flagged
field has no numeric score and must be excluded from averages.

### Correctness (1-5)

| Score | Meaning |
|---|---|
| 1 | Steps describe a different vulnerability or are factually wrong. |
| 2 | Mostly wrong; only isolated terms match the CVE. |
| 3 | Partially correct; the main weakness is identified but key steps are missing or wrong. |
| 4 | Correct attack intent; one non-critical step is inaccurate or out of order. |
| 5 | All steps accurately reproduce the intended exploit narrative. |

### Completeness (1-5)

| Score | Meaning |
|---|---|
| 1 | Only a title or a single vague step. |
| 2 | One phase present; most critical steps absent. |
| 3 | Two phases present; critical steps missing. |
| 4 | All three phases present; one critical step missing. |
| 5 | All critical steps present in a coherent order. |

### Clarity (1-5)

| Score | Meaning |
|---|---|
| 1 | Unintelligible or heavily repetitive. |
| 2 | Hard to follow; ambiguous pronouns or repeated text. |
| 3 | Understandable with effort; some steps need interpretation. |
| 4 | Clear and interpretable with minor ambiguity. |
| 5 | Unambiguous, well ordered, directly usable as guidance. |

## Aggregation

- Report per-case scores and a per-criterion mean over numeric scores only.
- Report the count of flagged fields per criterion.
- Do not round to look better; keep two decimal places.
- Do not compute precision/recall/F1 from these 1-5 scales unless the scoring
  mapping is documented and applied uniformly. The paper's F1 uses a different
  mapping and must not be silently reused.

## Safety instructions for the reviewer

- Do not run the workflow, any command in it, or any exploit code.
- Do not test against any system other than the already isolated lab, and even
  there testing is not required for this review.
- Treat the workflow as text to be judged, not as instructions to follow.

## Provenance to record with the results

- Dataset SHA-256 (`data/processed/reproduction/` snapshot).
- `evaluation/datasets/retrieval_benchmark.json` is unrelated; record
  `splits.json` sha256 instead.
- Checkpoint identifier or path.
- Provider name and generation settings.
- Date of review and reviewer role ("advisor, 1 person").
- Any case removed from scoring and why.
