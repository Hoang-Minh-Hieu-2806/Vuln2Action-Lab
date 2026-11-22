# GUI preparation for T5-generated flow (no checkpoint required)

Status: **AUDIT ONLY — no UI code changed.** Date: 2026-11-22.

## Current behavior (verified)

| Item | Finding | Source |
|---|---|---|
| Flow construction | `_flow_view(capec, technique_map)` converts the selected CAPEC record into view steps | `gui/app.py:56`, `:147` |
| `analyze()` | returns a single `flow` key derived from the reference CAPEC, plus `method`, `score`, `candidates` | `gui/app.py:110-150` |
| Model metadata | no provider, checkpoint, generation settings or safety label in the response | `gui/app.py:133-149` |
| API test | asserts `payload["flow"][0]...` only | `tests/unit/test_gui.py:85-98` |
| Template | `gui/templates/index.html` renders the single `flow` field | template source |
| Config | T5 `checkpoint: ""`, `base_checkpoint: t5-small` | `config/models.yaml:21-31` |

The GUI currently displays a **reference CAPEC flow**. It does not call the
pipeline or the T5 provider, and it never executes exploit code.

## Required data contract when a checkpoint exists

Introduce two explicitly named fields, never one ambiguous `flow`:

| Field | Meaning |
|---|---|
| `reference_flow` | MITRE `Execution_Flow` for the selected CAPEC; unchanged |
| `generated_flow` | output of `GenerationProvider.generate` for the CVE description |
| `generation` | provider, checkpoint id, settings, input CVE id, context sources |
| `generation_status` | `unavailable` / `available` / `error` with a short reason |

Rules:
- If no fine-tuned checkpoint is configured, `generated_flow` must be `null` and
  `generation_status` must explain why — never substitute the reference flow.
- Do not call an untuned `t5-small` fallback "T5-generated" in a demo.
- Keep `reference_flow` available even when generation is unavailable.
- The template must label the source next to each flow.

## Safe plumbing that can be prepared now

1. Add the field names to the API response with `null` values and a status
   string, without touching the existing `flow` key until the template is
   updated; keep backward compatibility for `tests/unit/test_gui.py`.
2. Add a unit test asserting that `generated_flow is None` when no checkpoint is
   configured and that `generation_status` is not `available`.
3. Add the template labels but render the generated section only when the field
   is non-null.
4. Only after a real checkpoint exists, wire `analyze()` to the pipeline and
   update the API test to assert both flows and their labels.

## Not allowed in this phase

- Simulating T5 output.
- Relabelling the CAPEC reference flow as generated.
- Adding fake steps or fake model metadata for a demo.
- Auto-downloading a checkpoint from the GUI.

## Dependencies

Real completion requires the stage-1 checkpoint from the Kaggle kernel
`phamquang0606/vuln2action-paper-stage1-cve-only-target-fp32`, which is still
running. No checkpoint artifact is available locally yet.
