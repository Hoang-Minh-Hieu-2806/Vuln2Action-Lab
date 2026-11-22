# Public schema compatibility audit

Date: 2026-11-22. Branch: `dev`, HEAD `4283360` plus the uncommitted evidence
provenance batch. This is an audit only: no source file was modified, no commit,
no push, no Kaggle/training/benchmark/GUI changes.

## 1. Scope

Symbols audited:
- `Workflow` (`src/vuln2action/domain/workflow.py:27`)
- `EvidenceBundle` (`src/vuln2action/domain/evidence.py:16`)
- `GeneratedFlow` (`src/vuln2action/generation/t5.py:71`)
- `flow_to_workflow` (`src/vuln2action/generation/t5.py:144`)

Change under audit: two optional fields with default `None`:
`Workflow.checkpoint_id`, `EvidenceBundle.checkpoint_id`. `GeneratedFlow` was
not modified; `flow_to_workflow` gained a keyword-only parameter at the end.

## 2. Consumers and call sites

| Consumer / call site | Location | Uses |
|---|---|---|
| Public package export | `src/vuln2action/__init__.py:4-11` | `Workflow` is exported at top level |
| Domain export | `src/vuln2action/domain/__init__.py:4,22,35,47` | `Workflow`, `EvidenceBundle` |
| Rule-based generator | `generation/rule_based.py:20` | keyword `Workflow(...)` |
| T5 generator | `generation/t5.py:190`, `:298-307` | keyword `Workflow(...)`, `GeneratedFlow(...)`, `flow_to_workflow(...)` |
| Strict parser | `generation/parser.py:11-19` | `Workflow.model_validate(raw)` |
| Planner | `reproduction/planner.py:7` | reads `workflow.steps`, `workflow.lab_id`, `workflow.cve_id` |
| Evidence collector | `evidence/collector.py:16,33-40` | `EvidenceBundle()`, `add_workflow` |
| Pipeline result | `pipeline/run.py:25,30,70-86` | typed `Workflow`, `EvidenceBundle`, dump to JSON |
| CLI `--json-only` | `cli.py:64-65` | `outcome.to_dict()` -> JSON |
| API `/analysis` | `api/routes/analysis.py:20` | `outcome.model_dump(mode="json")` |
| API `/results` | `api/routes/results.py:19-25` | raw stored `report.json`, no schema validation |
| Generation evaluation | `evaluation/generation/evaluate_generation.py:165` | reads `Workflow.steps` |
| Docs | `docs/t5-training.md:22`, `docs/paper-deviation-report-vi.md:77` | prose only, no field-level schema contract |

No JSON/YAML fixture in `data/samples/` or `results/` contains a serialized
`Workflow` or `EvidenceBundle`; the search for `"workflow"`, `"checkpoint_id"`
and `"validation_result"` in those trees returned no matches.

`GeneratedFlow` and `flow_to_workflow` are **not** re-exported from
`vuln2action.generation`; they are reachable only via `vuln2action.generation.t5`.

## 3. Runtime evidence

Probe command (temp script, no repo files touched) produced:

```text
WORKFLOW_FIELDS: ['cve_id', 'provider', 'steps', 'context_summary', 'safety', 'lab_id', 'checkpoint_id']
EVIDENCE_FIELDS: ['collected_at', 'logs', 'command_outputs', 'http', 'generation', 'workflow', 'plan', 'checkpoint_id', 'validation_result']
FLOWSIG: (text: 'str', cve: 'CveRecord', contexts: 'list[RetrievedContext]', *, provider: 'str' = 't5', lab_id: str = '', normalise: bool = True, checkpoint_id: 'str | None' = None) -> 'Workflow'
GENERATEDFLOW_FIELDS: ['text', 'checkpoint', 'steps']
NEW_WORKFLOW_JSON: {..., 'checkpoint_id': 'ckpt'}
OLD_STRICT_READS_NEW: NO -> ValidationError
NEW_READS_OLD: None D
```

Both models use `ConfigDict(extra="forbid")`
(`domain/workflow.py:28`, `domain/evidence.py:17`).

## 4. Risk classification by scenario

| Scenario | Classification | Evidence |
|---|---|---|
| Old in-repo consumer reads new evidence | SAFE | All internal readers use the current models; `pytest -q` 248 passed, 6 skipped |
| Old **strict external** model reads new JSON | **POTENTIAL BREAKING CHANGE** | `OLD_STRICT_READS_NEW: NO -> ValidationError` with `extra="forbid"` |
| New consumer reads old evidence/workflow JSON | SAFE | `NEW_READS_OLD: None D`; `test_old_evidence_without_checkpoint_loads` |
| Old consumer constructs objects positionally | SAFE | Pydantic `BaseModel.__init__` is keyword-only; all repo calls use keywords; `GeneratedFlow` dataclass fields unchanged (`text`, `checkpoint`, `steps`) |
| Old consumer calls `flow_to_workflow` positionally | SAFE | `*` in signature: `checkpoint_id` is keyword-only and appended last |
| Strict schema validation with the new model | SAFE internally; NOT EVALUATED externally | internal `Workflow.model_validate` and `EvidenceBundle.model_validate` pass |
| Snapshot / exact serialized-output comparison | **POTENTIAL BREAKING CHANGE** externally; SAFE internally | serialized dict now contains `checkpoint_id`; internal tests compute both sides at runtime (`test_pipeline.py:20`, `test_docker_lab.py:62`); no committed snapshot fixtures found |
| CLI/API JSON contract consumers | **POTENTIAL BREAKING CHANGE** | `cli.py:64-65` and `api/routes/analysis.py:20` dump the new key; `api/routes/results.py` returns raw JSON; no `response_model` enforcement |
| External consumers outside this repository | **NOT EVALUATED** | No external SDK, client schema or snapshot repository is available locally; package docs do not enumerate consumers |

No CONFIRMED BREAKING CHANGE was found inside the repository.

## 5. Mandatory final commands (fresh, this session)

| Command | Actual result |
|---|---|
| `python -m ruff check .` | **exit 1 — 5 errors**, all pre-existing in `labs/`: `app.py:35 RUF100`, `app.py:47 RUF100`, `labctl.py:37/47/55 PLW1510`. CI-scoped `ruff check src api scripts tests evaluation gui` passes. |
| `python -m pytest -q` | **exit 0 — 248 passed, 6 skipped** |

The 5 `ruff check .` errors are unrelated to the schema change and explain why
CI lints only `src api scripts tests evaluation`. They are reported, not fixed,
because this audit forbids source edits.

## 6. Release readiness

**Not fully release-ready for external consumers.** Internal compatibility is
verified: old artifacts load, new artifacts round-trip, rule-based runs do not
fail, and no positional call site exists. The unresolved risk is that both models
use `extra="forbid"`, so any external strict schema or exact snapshot that does
not know `checkpoint_id` will reject or mismatch the new JSON. External
consumers are NOT EVALUATED, so full compatibility cannot be claimed.

Recommendation for a release: treat this as an additive schema change in a
minor version, publish a migration note listing the two new keys, and confirm
with any downstream client before release. Do not change code in this audit.

## 7. Proposed follow-ups (not performed)

1. Add a documented `schema_version` to evidence artifacts if downstream
   consumers need explicit negotiation.
2. If strict external clients must stay unchanged, emit `checkpoint_id` only
   when non-null (`model_dump(exclude_none=True)`) — but this changes current
   dump behaviour and needs its own compatibility audit.
3. Fix the 5 pre-existing `labs/` ruff findings in a separate batch so
   `ruff check .` can become the CI gate.
4. Ask any external consumer to validate a sample new `report.json` against
   their schema; classify as SAFE only after that evidence exists.
