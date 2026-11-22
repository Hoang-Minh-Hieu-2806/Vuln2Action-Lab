# T5 provider -> pipeline -> evidence audit

Date: 2026-11-22. HEAD: `4283360`. This is a source-level audit; no training
result is claimed and no source file was changed in this phase.

## Call chain (verified in source)

```text
vuln2action.pipeline.run.run_pipeline
  -> analyze_cve                     (pipeline/analyze.py:56)
     -> get_generator(provider)      (generation/base.py:17)
        -> T5Generator()             (generation/t5.py:204)
     -> build_contexts_for_cve       (retrieval/ranker.py)
     -> generator.generate(cve, contexts)
        -> generate_flow             (generation/t5.py:274)
           -> _ensure_loaded         (generation/t5.py:225)
           -> model.generate + parse_flow
        -> flow_to_workflow          (generation/t5.py:144, :298-304)
  -> ReproductionPlanner.plan       (reproduction/planner.py:7)
  -> ReproductionExecutor.execute    (reproduction/executor.py:56)
     -> select_validation_command    (reproduction/executor.py:21)
     -> _run(manifest argv)          (reproduction/executor.py:138)
  -> Validator.validate              (reproduction/validator.py:7)
  -> EvidenceCollector               (evidence/collector.py)
```

## Mandatory table

| Component | Actual behavior | Source file/function | Evidence | Gap | Severity |
|---|---|---|---|---|---|
| Provider factory | `t5` selects `T5Generator()`; default remains `rule_based` | `generation/base.py:17-30`, `config/models.yaml:21-31` | source + CLI smoke | none | low |
| Checkpoint resolution | `checkpoint or settings.checkpoint or base_checkpoint`; config has `checkpoint: ""` -> `t5-small` | `generation/t5.py:213-214` | config + source | fine-tuned Kaggle checkpoint is not wired into config; GUI cannot show a real generated flow yet | medium |
| Generation input | CVE record + retrieved contexts; T5 prompt built by `build_model_input` | `generation/t5.py:274`, `generation/prompts.py` | source | CAPEC context is not explicitly forced into the T5 prompt; CAPEC mapping is recorded separately as evidence | medium |
| Generation output | raw text parsed into `Workflow`; `GeneratedFlow.checkpoint` exists but is not carried into `Workflow` | `generation/t5.py:296`, `:144`, `:304` | source | evidence cannot show which checkpoint produced the workflow | medium |
| Fallback | injected model/tokenizer skips heavy load; `nullcontext` when torch absent; no checkpoint found raises `T5UnavailableError` | `generation/t5.py:225-243`, `:274-285` | source + unit tests | none | low |
| Pipeline wiring | `run_pipeline` calls `analyze_cve` then planner/executor/validator | `pipeline/run.py:36-95` | integration test | none | low |
| Workflow overwrite | no code replaces a generated workflow with a reference CAPEC flow | `pipeline/run.py:47-59` | source | none | low |
| Evidence: generation | provider, CVE id, description, context sources, CAPEC mapping, output workflow | `pipeline/run.py:70-82` | `tests/integration/test_pipeline.py` | **no checkpoint/model id** | medium |
| Evidence: workflow and plan | full `Workflow` and `ExecutionPlan` dumped | `pipeline/run.py:83-84` | integration test | none | low |
| Evidence: reference vs generated | not distinguished; there is no `reference_flow` / `generated_flow` pair | `domain/evidence.py:22-24`, `gui/app.py:110-150` | source | user cannot tell MITRE reference flow from generated flow | high |
| Executor argv | manifest is the only argv source; workflow text only picks an allowlisted action key | `reproduction/executor.py:21-31`, `:108-124` | `tests/unit/test_executor.py` | both `cve-001` actions call the same fixed-marker validator | high |
| Validator | PASS requires vulnerable unescaped marker + patched escaped marker | `labs/cve-001/validation/labctl.py:109-139` | source | marker is fixed, not derived from workflow | high |
| GUI | `analyze()` returns `_flow_view(capec, ...)` only; no provider/checkpoint fields | `gui/app.py:110-150`, `:56` | source | no T5-generated flow view | high |
| CI lab coverage | Docker integration tests skipped unless `V2A_DOCKER_TESTS=1`; workflow does not set it | `.github/workflows/ci.yml`, `tests/integration/test_docker_lab.py` | CI #6 + pytest -rs | PASS/FAIL/evidence not machine-checked by CI | medium |

Status summary: VERIFIED for provider factory, pipeline wiring, manifest-only
argv and evidence input/output; PARTIALLY VERIFIED for generation input and
checkpoint resolution; NOT IMPLEMENTED for reference/generated flow separation
and GUI generated view; NOT EVALUATED for stage-1 Kaggle output.

## Findings that need a decision (not changed here)

1. **Checkpoint provenance.** Add a checkpoint/model id to the evidence bundle,
   or carry `GeneratedFlow.checkpoint` into `Workflow`. Small, but touches a
   public schema — needs approval.
2. **Reference vs generated flow.** `gui/app.py` currently presents a single
   `flow` field built from the CAPEC reference. Any T5 view must add a separate
   field and label, never relabel the reference flow.
3. **Validator action granularity.** Two different action keys call the same
   validator with a fixed marker. Changing this requires a new validator path
   that accepts an allowlisted marker and re-testing vulnerable/patched.
4. **CI lab job.** A separate Docker job is feasible, but must not weaken unit
   tests or skip the counterfactual check.

No bug was fixed in this phase, so no new test was added.
