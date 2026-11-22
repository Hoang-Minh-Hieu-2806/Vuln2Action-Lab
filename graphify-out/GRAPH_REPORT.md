# Graph Report - Vuln2Action-Lab  (2026-11-22)

## Corpus Check
- 272 files · ~126,700 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 33 file(s) not represented in the graph (top: .ipynb 23, (none) 8, .example 1)

## Summary
- 2078 nodes · 4658 edges · 121 communities (81 shown, 40 thin omitted)
- Extraction: 94% EXTRACTED · 6% INFERRED · 0% AMBIGUOUS · INFERRED: 268 edges (avg confidence: 0.87)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- io
- Counter
- dataclasses
- CAPEC mapping and retrieval
- parametrize
- difflib
- Checkpoint/resume on Kaggle
- datasets.yaml
- manifest.json
- hashlib
- gzip
- build_capec_benchmark.py
- evaluate_retrieval.py
- functools
- post
- analysis.py
- schemas/cve.py
- main()
- KnowledgeDocument
- GeneratedFlow
- RetrievedContext
- CapecIndex
- parse_workflow()
- inspect
- retrieval/base.py
- semantic.py
- csv
- pathlib
- build_capec_independent.py
- collections_abc
- ci.yml
- Benchmark
- mitre.py
- flow_dataset.py
- config.py
- models.yaml
- Flask
- cve2capec.py
- input/docker-compose.yml
- cve-001/docker-compose.yml
- evaluate_capec_independent.py
- evaluate_independent()
- argparse
- 1.1 Labels are the
- CapecBenchmark
- settings.yaml
- build_hybrid_eval.py
- 1. Diagnosis
- json
- catalog.py
- get
- input/lab.yaml
- 1. Commands
- cve-001/lab.yaml
- labctl.py
- 10. Git status before
- main.py
- contextlib
- Aggregation
- cve-002/docker-compose.yml
- cve-003/docker-compose.yml
- Assertions NOT evaluated
- 1. Git state at
- build_expanded_flow_dataset.py
- Chạy evaluation
- cve-002/lab.yaml
- cve-003/lab.yaml
- collections
- 1. Ph??ng ph?p
- Independent CAPEC benchmark —
- 1. C?ch d?ng
- Assertions (implemented and locally
- T5 holdout / group-split
- 1. Mục tiêu
- 1. Ch?y local
- Core engineering
- Artifacts to capture
- docker-compose.yml
- Lab cve-001 — live
- Human evaluation package
- Case 1 of 20
- reproduction/metrics.py
- IndependentCase
- build_dataset.py
- embeddings.py
- Architecture
- Vuln2Action-Lab run: t5-demo-cve-001
- Optional local API
- Vuln2Action-Lab docs
- cve-001 validation
- Lab cve-002 (placeholder, Phase
- Placeholder validation script dir
- Lab cve-003 (placeholder, Phase
- Placeholder validation script dir
- Labs
- Blocker register — Batch
- Evidence index — Batch
- Execution session report —
- Implementation audit — Batch
- Task status matrix —
- Test results — Batch
- Minimal core vs optional
- vuln2action-lab

## God Nodes (most connected - your core abstractions)
1. `CveRecord` - 72 edges
2. `write_json()` - 38 edges
3. `project_root()` - 35 edges
4. `get_sample_cve()` - 35 edges
5. `KnowledgeDocument` - 33 edges
6. `CapecRecord` - 32 edges
7. `RetrievedContext` - 31 edges
8. `CapecIndex` - 31 edges
9. `run_pipeline()` - 29 edges
10. `read_json()` - 28 edges

## Surprising Connections (you probably didn't know these)
- `test_load_sample_cves_has_three()` --calls--> `load_sample_cves()`  [INFERRED]
  tests/unit/test_ingestion.py → src/vuln2action/connectors/samples.py
- `test_get_sample_cve()` --calls--> `get_sample_cve()`  [INFERRED]
  tests/unit/test_ingestion.py → src/vuln2action/connectors/samples.py
- `search()` --calls--> `RetrievedContext`  [INFERRED]
  tests/unit/test_evaluation_retrieval.py → src/vuln2action/domain/knowledge.py
- `test_factory_rejects_unknown_provider()` --calls--> `get_generator()`  [INFERRED]
  tests/unit/test_generation_t5.py → src/vuln2action/generation/base.py
- `test_keyword_backend_ranks_matching_document()` --calls--> `KeywordBackend`  [INFERRED]
  tests/unit/test_retrieval_backends.py → src/vuln2action/retrieval/keyword.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Paper methodological components reproduced** — docs_paper_explained_vi_cve_cwe_capec_chain, docs_paper_explained_vi_two_stage_training, docs_paper_explained_vi_execution_flow, docs_paper_explained_vi_exploit_code_retrieval, docs_paper_explained_vi_flask_gui [INFERRED 0.75]
- **Truthful deviation and non-claim reporting** — docs_paper_reproduction_method_faithful_reproduction, docs_paper_deviation_report_vi_deviation_table, docs_paper_deviation_report_vi_single_advisor_review, docs_research_paper_explicit_non_claim [INFERRED 0.75]
- **T5 stage-1 evaluation and failure findings** — docs_t5_stage1_eval_vi_checkpoint693, docs_t5_stage1_eval_vi_target_leakage, docs_t5_stage1_paper10_eval_vi_collapse, docs_t5_stage1_paper10_eval_vi_capec_conditioned [INFERRED 0.75]
- **Top 5 risks for defense** — reports_full_project_audit_2026_11_22_t5_checkpoint_gap, reports_full_project_audit_2026_11_22_validation_leakage, reports_full_project_audit_2026_11_22_circular_benchmark, reports_full_project_audit_2026_11_22_gui_reference_flow_only, reports_full_project_audit_2026_11_22_bleu_protocol_conflation [EXTRACTED 1.00]
- **Active external blockers** — reports_project_blockers_b1, reports_project_blockers_b2, reports_project_blockers_b3, reports_project_blockers_b4, reports_project_blockers_b6 [EXTRACTED 1.00]
- **Minimum defensible demo stack** — reports_full_project_architecture_current_rule_based_generation, reports_full_project_architecture_current_cve_001_lab, reports_full_project_architecture_current_evidencecollector [EXTRACTED 1.00]

## Communities (121 total, 40 thin omitted)

### Community 0 - "io"
Cohesion: 0.05
Nodes (53): _download(), download_capec(), download_cwe(), download_nvd(), _extract_xml(), main(), _nvd_query_params(), _resolve() (+45 more)

### Community 1 - "Counter"
Cohesion: 0.06
Nodes (45): bleu(), _bleu_statistics(), _brevity_penalty(), _collapse_repeats(), corpus_bleu(), extract_phase_sequence(), _lcs_length(), missing_phases() (+37 more)

### Community 2 - "dataclasses"
Cohesion: 0.05
Nodes (27): main(), _resolve(), _techniques(), _background_texts(), _build_selector(), main(), _resolve(), CapecPrediction (+19 more)

### Community 3 - "CAPEC mapping and retrieval"
Cohesion: 0.06
Nodes (60): CAPEC mapping and retrieval, Lab cve-001 (vulnerable + patched), Current architecture — implementation reality (2026-11-22), EvidenceCollector and evidence bundle, GenerationProvider interface, LLMGenerator (stub), Manifest-only argv execution and localhost guard, ReproductionPlanner -> Executor -> Validator pipeline (+52 more)

### Community 4 - "parametrize"
Cohesion: 0.07
Nodes (28): load_lab_manifest(), ExecutionPlan, ExecutionResult, PlanStep, LabManifest, is_allowed_target(), parse_validation_output(), ReproductionExecutor (+20 more)

### Community 5 - "difflib"
Cohesion: 0.08
Nodes (37): _aggregate(), audit_leakage(), _comparison_table(), _cve_for(), DatasetMissingError, evaluate_system(), _fine_tuned_checkpoint(), FlowCase (+29 more)

### Community 6 - "Checkpoint/resume on Kaggle"
Cohesion: 0.06
Nodes (35): 1-epoch T5-base benchmark (eval loss 0.4455), Stage 1 Kaggle dataset minhiw/vuln2action-flow-114560, Kaggle T4 x2 T5 smoke test, Stage 2 Kaggle dataset minhiw/vuln2action-stage2-114560, Objectives O1–O7, 114,560-CVE paper-faithful reproduction dataset, Mandatory paper-vs-repo deviation table, Single advisor reviewer vs paper's 3 experts (+27 more)

### Community 7 - "datasets.yaml"
Cohesion: 0.04
Nodes (47): description, path, description, notes, path, regenerate, source, description (+39 more)

### Community 8 - "manifest.json"
Cohesion: 0.04
Nodes (45): artifact_sha256, evidence/evidence.json, evidence/report.json, evidence/report.md, execution/execution.json, input/docker-compose.yml, input/lab.yaml, input/sample_cves.json (+37 more)

### Community 9 - "hashlib"
Cohesion: 0.09
Nodes (27): build_input(), build_payload(), build_target(), _capid_key(), _clean(), main(), MissingSourceError, parse_capec_flows() (+19 more)

### Community 10 - "gzip"
Cohesion: 0.09
Nodes (24): main(), _resolve(), allocate_quotas(), build_candidate_rows(), build_cve_cwe_pairs(), build_reference_rows(), catalog_metadata(), exploit_rows_for_selected() (+16 more)

### Community 11 - "build_capec_benchmark.py"
Cohesion: 0.09
Nodes (24): build_cases(), build_payload(), _download(), _external_dir(), fetch_galeax_db(), fetch_nvd_feed(), galeax_commit_sha(), load_galeax_labels() (+16 more)

### Community 12 - "evaluate_retrieval.py"
Cohesion: 0.11
Nodes (24): main(), _markdown(), _resolve(), _table(), main(), Benchmark, BenchmarkCase, evaluate() (+16 more)

### Community 13 - "functools"
Cohesion: 0.07
Nodes (17): build_capec_index(), CapecDocument, CapecMapping, _clean(), clear_capec_cache(), default_capec_index(), load_capec_index(), MissingDependencyError (+9 more)

### Community 14 - "post"
Cohesion: 0.10
Nodes (18): reproduce(), main(), load_settings(), get_sample_cve(), load_sample_cves(), EvidenceCollector, run_pipeline(), test_broken_patched_counterfactual_is_not_pass() (+10 more)

### Community 15 - "analysis.py"
Cohesion: 0.09
Nodes (15): analyze(), CveRecord, AnalysisOutcome, analyze_cve(), resolve_capec(), PipelineResult, build_contexts_for_cve(), test_analysis_outcome_serialises_capec() (+7 more)

### Community 16 - "schemas/cve.py"
Cohesion: 0.09
Nodes (10): EvidenceBundle, HttpEvidence, ReproductionResult, ReproductionStatus, Workflow, WorkflowStep, test_evidence_keeps_checkpoint_metadata(), test_serialization_roundtrip_keeps_checkpoint() (+2 more)

### Community 17 - "main()"
Cohesion: 0.14
Nodes (26): main(), apply_lab_map(), build_from_payload(), build_from_snapshots(), dedupe_cves(), load_capec_dataset(), load_cve_dataset(), load_cwe_dataset() (+18 more)

### Community 18 - "KnowledgeDocument"
Cohesion: 0.10
Nodes (22): KnowledgeDocument, build_corpus(), capec_document(), clear_corpus_cache(), CorpusFile, cwe_document(), default_corpus(), _definition_url() (+14 more)

### Community 19 - "GeneratedFlow"
Cohesion: 0.09
Nodes (13): GeneratedFlow, require_t5_stack(), T5Generator, T5UnavailableError, _FakeModel, _FakeTokenizer, test_decoding_kwargs_include_improved_controls(), test_decoding_kwargs_omit_neutral_controls() (+5 more)

### Community 20 - "RetrievedContext"
Cohesion: 0.12
Nodes (13): RetrievedContext, GenerationProvider, get_generator(), LLMGenerator, build_context_summary(), RuleBasedGenerator, build_model_input(), rank_contexts() (+5 more)

### Community 21 - "CapecIndex"
Cohesion: 0.12
Nodes (20): CapecIndex, map_cve_to_capec(), _mean_vector(), rank_candidates(), tfidf_cosine_scores(), train_word2vec(), word2vec_cosine_scores(), test_candidates_are_the_union_of_cwe_relations() (+12 more)

### Community 22 - "parse_workflow()"
Cohesion: 0.09
Nodes (22): parse_workflow(), flow_to_workflow(), normalise_flow_structure(), parse_flow(), test_flow_to_workflow_keeps_checkpoint(), test_factory_rejects_unknown_provider(), test_factory_returns_t5_provider(), test_flow_to_workflow_keeps_technique_text() (+14 more)

### Community 23 - "inspect"
Cohesion: 0.09
Nodes (11): _latest_checkpoint(), main(), _require_training_deps(), _resolve(), _training_arguments(), get_evidence_logger(), get_logger(), _NewTrainingArguments (+3 more)

### Community 24 - "retrieval/base.py"
Cohesion: 0.14
Nodes (12): get_backend(), RetrievalBackend, keyword_score(), keyword_search(), KeywordBackend, document_text(), tfidf_search(), TfidfBackend (+4 more)

### Community 25 - "semantic.py"
Cohesion: 0.12
Nodes (16): build_semantic_contexts(), _clean(), default_semantic_enricher(), _index_text(), load_semantic_contexts(), ParentWeakness, _read_xml(), RelatedAttackPattern (+8 more)

### Community 26 - "csv"
Cohesion: 0.12
Nodes (17): _comparison_table(), evaluate_method(), _graded_relevance(), _hit_rank(), load_capec_benchmark(), main(), _markdown(), _mean() (+9 more)

### Community 27 - "pathlib"
Cohesion: 0.13
Nodes (8): main(), _resolve(), _sort_key(), ReportPaths, _safe_run_id(), save_report(), ensure_dir(), repo_path()

### Community 28 - "build_capec_independent.py"
Cohesion: 0.14
Nodes (15): build_payload(), _download(), _external_dir(), extract_capec_example_labels(), extract_cwe_observed_examples(), load_nvd_records(), main(), MissingInputError (+7 more)

### Community 29 - "collections_abc"
Cohesion: 0.13
Nodes (7): _reference_with_flow(), best_candidate(), capec_sort_key(), Word2VecCapecSelector, _query_text(), split_camel_case(), tokenize()

### Community 30 - "ci.yml"
Cohesion: 0.09
Nodes (22): jobs, quality, python-version, name, on, pull_request, push, permissions (+14 more)

### Community 31 - "Benchmark"
Cohesion: 0.09
Nodes (23): Benchmark, Configuration, Current implementation status, CVE → CAPEC mapping (Phase 3b), Data snapshots (Phase 2), Vuln2Action-Lab, http://127.0.0.1:5000, Important caveat (measured, not assumed) (+15 more)

### Community 32 - "mitre.py"
Cohesion: 0.18
Nodes (15): _clean(), _dedupe(), parse_capec_xml(), parse_cwe_xml(), _parse_execution_flow(), _read_xml(), _related_ids(), _strip_namespaces() (+7 more)

### Community 33 - "flow_dataset.py"
Cohesion: 0.17
Nodes (13): build_flow_dataset(), build_flow_row(), _clean(), enrich_flow_row(), flow_targets(), _load_predictions(), phase_steps(), _step_with_techniques() (+5 more)

### Community 34 - "config.py"
Cohesion: 0.13
Nodes (11): ApplicationSettings, EvidenceSettings, GenerationProvidersSettings, GenerationSettings, LabSettings, PipelineSettings, RetrievalSettings, T5ProviderSettings (+3 more)

### Community 35 - "models.yaml"
Cohesion: 0.10
Nodes (20): api_base_env, api_key_env, default_model, enabled, model_env, timeout_seconds, providers, llm (+12 more)

### Community 36 - "Flask"
Cohesion: 0.18
Nodes (10): create_app(), analyze(), analyze_api(), analyze_form(), _flow_view(), _load_predictions(), _load_technique_map(), _build_dataset() (+2 more)

### Community 37 - "cve2capec.py"
Cohesion: 0.14
Nodes (8): _iter_lines(), _iter_paths(), load_cve2capec(), _normalise(), references_from_cve(), CapecStep, CveCapecReference, ExploitReference

### Community 38 - "input/docker-compose.yml"
Cohesion: 0.11
Nodes (19): APP_MODE, external, name, name, networks, lab-net, build, container_name (+11 more)

### Community 39 - "cve-001/docker-compose.yml"
Cohesion: 0.11
Nodes (19): APP_MODE, external, name, name, networks, lab-net, build, container_name (+11 more)

### Community 40 - "evaluate_capec_independent.py"
Cohesion: 0.20
Nodes (12): _evaluate_subset(), IndependentBenchmark, LabelEvidence, load_independent_benchmark(), main(), _markdown(), _resolve(), _safe_stdout() (+4 more)

### Community 41 - "evaluate_independent()"
Cohesion: 0.21
Nodes (15): evaluate_independent(), build_cases(), _benchmark(), _case(), test_build_cases_falls_back_to_cwe_observed_examples(), test_build_cases_flags_unreachable_labels(), test_build_cases_requires_min_candidates(), test_build_cases_skips_missing_records_and_cwes() (+7 more)

### Community 42 - "argparse"
Cohesion: 0.16
Nodes (6): main(), _resolve(), main(), _build_cve(), main(), _safe_stdout()

### Community 43 - "1.1 Labels are the"
Cohesion: 0.11
Nodes (18): 1.1 Labels are the candidate generator's own closure, 1.2 The discriminative metrics were also near-saturated or invalid, 1.3 Data leakage, 1.4 Why a second evaluation set was necessary, 1. Audit of the existing evaluation, 2.1 Label source, 2.2 Labeling criteria, 2.3 Resulting set (+10 more)

### Community 44 - "CapecBenchmark"
Cohesion: 0.24
Nodes (10): CapecBenchmark, CapecBenchmarkCase, evaluate(), _benchmark(), test_benchmark_validator_rejects_duplicate_and_blank_ids(), test_common_subset_excludes_cases_a_method_could_not_rank(), test_empty_ranking_counts_against_the_method(), test_membership_and_discriminative_metrics_are_reported() (+2 more)

### Community 45 - "settings.yaml"
Cohesion: 0.12
Nodes (16): evidence, formats, output_dir, labs, allowed_hosts, network, timeout_seconds, pipeline (+8 more)

### Community 46 - "build_hybrid_eval.py"
Cohesion: 0.26
Nodes (11): _load_capecs(), _load_predictions(), _load_references(), main(), _resolve(), _row_for_input(), _write_view(), read_jsonl() (+3 more)

### Community 47 - "1. Diagnosis"
Cohesion: 0.12
Nodes (16): 1. Diagnosis, 2.1 Decoding (no retraining), 2.2 Structural enforcement (`normalise_flow_structure`), 2.3 Evaluator fidelity fixes, 2. Changes, 3. Results — 28 validation cases, 4. Five representative outputs (improved), 5. Regressions (+8 more)

### Community 48 - "json"
Cohesion: 0.24
Nodes (8): _load_candidates(), _load_references(), main(), _resolve(), _score(), _load_metrics(), main(), _resolve()

### Community 49 - "catalog.py"
Cohesion: 0.17
Nodes (8): lookup_cwe(), parse_cpe(), parse_cve_dict(), CpeRecord, test_cwe_lookup_and_cpe_parse(), test_get_sample_cve(), test_load_sample_cves_has_three(), test_parse_cve_dict_minimal()

### Community 50 - "get"
Cohesion: 0.18
Nodes (8): read_result(), parse_exploitdb_csv(), _read_text(), _split(), dataset_stats(), ExploitRecord, test_parse_exploitdb_csv_filters_paper_year_window(), test_parse_exploitdb_csv_keeps_metadata_only()

### Community 51 - "input/lab.yaml"
Cohesion: 0.13
Nodes (14): actions, probe, validate, allowed_hosts, compose_file, has_patched_counterfactual, kind, lab_id (+6 more)

### Community 52 - "1. Commands"
Cohesion: 0.13
Nodes (15): 1. Commands, 2. Metric definitions, 3. Leakage audit — read this before the scores, 4. Results (28 validation cases), 5. Failure analysis (5 representative cases), 6. FLAN-T5 control group, 7. Dataset provenance, 8. Limitations (+7 more)

### Community 53 - "cve-001/lab.yaml"
Cohesion: 0.13
Nodes (14): actions, probe, validate, allowed_hosts, compose_file, has_patched_counterfactual, kind, lab_id (+6 more)

### Community 54 - "labctl.py"
Cohesion: 0.23
Nodes (8): command_down(), command_up(), command_validate(), _compose(), ensure_network(), fetch(), main(), wait_ready()

### Community 55 - "10. Git status before"
Cohesion: 0.14
Nodes (14): 10. Git status before and after, 11. Unverified steps, 12. Blockers and next actions, 1. Conclusion, 2. Commands actually run, 3. Docker build result, 4. Docker execution result, 5. Validator result (+6 more)

### Community 57 - "contextlib"
Cohesion: 0.21
Nodes (6): main(), _require_eval_deps(), _resolve(), load_model_settings(), load_yaml(), project_root()

### Community 58 - "Aggregation"
Cohesion: 0.17
Nodes (12): Aggregation, Clarity (1-5), Completeness (1-5), Correctness (1-5), Human evaluation protocol (single advisor reviewer), Human evaluation protocol (single advisor reviewer), Material shown to the reviewer, Provenance to record with the results (+4 more)

### Community 59 - "cve-002/docker-compose.yml"
Cohesion: 0.17
Nodes (11): external, name, name, networks, lab-net, services, target, build (+3 more)

### Community 60 - "cve-003/docker-compose.yml"
Cohesion: 0.17
Nodes (11): external, name, name, networks, lab-net, services, target, build (+3 more)

### Community 61 - "Assertions NOT evaluated"
Cohesion: 0.18
Nodes (11): Assertions NOT evaluated, Evidence provenance + Docker lab assertions — implementation report, Evidence provenance + Docker lab assertions — implementation report, Files changed (tracked source and tests), Remaining risks, Safety properties preserved, Schema change and backward compatibility, Status (+3 more)

### Community 62 - "1. Git state at"
Cohesion: 0.18
Nodes (11): 1. Git state at start and end, 2. Execution flow (actual source), 3. Data-flow verification (exact files/symbols), 4. Security audit, 5. Definition of Done for T5 demo, 6. Fresh checks this batch, 7. What must be fixed/prepared (Batch 2/3 only), 8. Blockers requiring user decision (+3 more)

### Community 63 - "build_expanded_flow_dataset.py"
Cohesion: 0.31
Nodes (5): _load_references(), _load_selected(), main(), _resolve(), _stats()

### Community 64 - "Chạy evaluation"
Cohesion: 0.20
Nodes (10): Chạy evaluation, Hybrid hai tầng: CVE → CAPEC → execution flow, Giới hạn, Hybrid hai tầng: CVE → CAPEC → execution flow, Kiến trúc, Kết quả, Lỗi selection, Tạo dataset evaluation (+2 more)

### Community 65 - "cve-002/lab.yaml"
Cohesion: 0.20
Nodes (9): allowed_hosts, compose_file, has_patched_counterfactual, kind, lab_id, schema_version, status, validation_command (+1 more)

### Community 66 - "cve-003/lab.yaml"
Cohesion: 0.20
Nodes (9): allowed_hosts, compose_file, has_patched_counterfactual, kind, lab_id, schema_version, status, validation_command (+1 more)

### Community 67 - "collections"
Cohesion: 0.33
Nodes (4): audit(), _duplicates(), main(), _resolve()

### Community 68 - "1. Ph??ng ph?p"
Cohesion: 0.25
Nodes (8): 1. Ph??ng ph?p, 2. K?t qu? 100 CVE evaluation, 3. To?n b? 114.560 CVE, 4. So v?i b?n 55k, 5. File ??u ra, 6. Gi?i h?n, B?o c?o b??c 2: ch?n CAPEC t?t nh?t (dataset 114.560 CVE), B?o c?o b??c 2: ch?n CAPEC t?t nh?t (dataset 114.560 CVE)

### Community 69 - "Independent CAPEC benchmark —"
Cohesion: 0.25
Nodes (8): Independent CAPEC benchmark — freeze record, Frozen measurements (from `docs/analysis.md`), Frozen protocol, Identity, Independent CAPEC benchmark — freeze record, Interpretation rules, Provenance, Re-run check

### Community 70 - "1. C?ch d?ng"
Cohesion: 0.25
Nodes (8): 1. C?ch d?ng, 2. K?t qu?, 3. File ??u ra, 4. C?ch t?i l?p, 5. Stage 2, 6. Gi?i h?n, B?o c?o b??c 3: execution-flow dataset (114.560 CVE), B?o c?o b??c 3: execution-flow dataset (114.560 CVE)

### Community 71 - "Assertions (implemented and locally"
Cohesion: 0.25
Nodes (8): Assertions (implemented and locally verified), CI lab integration plan, Cleanup and safety, Conditions, Current state (verified), CI lab integration plan, Recommended job (separate, opt-in-safe), Why the job is still not enabled

### Community 72 - "T5 holdout / group-split"
Cohesion: 0.29
Nodes (7): T5 holdout / group-split plan, Minimum implementation sketch (not applied), Problem, Proposed protocol, Reporting, Scope boundaries, T5 holdout / group-split plan

### Community 73 - "1. Mục tiêu"
Cohesion: 0.29
Nodes (7): 1. Mục tiêu, 2. Cách làm, 3. Kết quả, 4. Giới hạn, 5. Hướng tiếp theo, Mở rộng flow dataset theo hướng CVE-only, Mở rộng flow dataset theo hướng CVE-only

### Community 74 - "1. Ch?y local"
Cohesion: 0.29
Nodes (7): 1. Ch?y local, 2. Ch?c n?ng, 3. Ki?m tra v?i dataset th?t, 4. An to?n, 5. Gi?i h?n, B?o c?o Flask GUI, B?o c?o Flask GUI

### Community 75 - "Core engineering"
Cohesion: 0.29
Nodes (7): Core engineering, Definition of Done — Vuln2Action-Lab roadmap, Definition of Done — Vuln2Action-Lab roadmap, Global release gate, Integration and presentation, Per workstream acceptance criteria, Research and evaluation

### Community 76 - "Artifacts to capture"
Cohesion: 0.29
Nodes (7): Artifacts to capture, Demo and defense checklist — Vuln2Action-Lab, Demo script (primary, no checkpoint required), Demo and defense checklist — Vuln2Action-Lab, Never demo / never claim, Optional demo (only if checkpoint exists), Rehearsal acceptance

### Community 77 - "docker-compose.yml"
Cohesion: 0.33
Nodes (5): driver, name, name, networks, lab-net

### Community 78 - "Lab cve-001 — live"
Cohesion: 0.33
Nodes (6): Lab cve-001 — live demo (CVE-2024-0001, FAKE), Files, Lab cve-001 — live demo (CVE-2024-0001, FAKE), Manual control, One-shot: setup + validate + teardown with a typed PASS/FAIL verdict, Run it

### Community 79 - "Human evaluation package"
Cohesion: 0.40
Nodes (5): Human evaluation package, Human evaluation package, Non-claims, To make it sendable, Why it is not sendable yet

### Community 80 - "Case 1 of 20"
Cohesion: 0.40
Nodes (5): Case 1 of 20, Cases 2-20, Reviewer form — generated workflow quality, Reviewer form — generated workflow quality, Summary (filled by the team, not the reviewer)

### Community 85 - "Architecture"
Cohesion: 0.50
Nodes (4): Architecture, Design rules, Architecture, Layers

## Knowledge Gaps
- **239 isolated node(s):** `vuln2action-lab`, `Vuln2Action-Lab`, `Repository structure`, `Current implementation status`, `Paper-reproduction dataset (step 1)` (+234 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 865 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **40 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `CveRecord` connect `analysis.py` to `io`, `dataclasses`, `difflib`, `gzip`, `post`, `schemas/cve.py`, `main()`, `KnowledgeDocument`, `GeneratedFlow`, `RetrievedContext`, `parse_workflow()`, `pathlib`, `flow_dataset.py`, `config.py`, `Flask`, `cve2capec.py`, `argparse`, `catalog.py`, `get`?**
  _High betweenness centrality (0.033) - this node is a cross-community bridge._
- **Are the 16 inferred relationships involving `CveRecord` (e.g. with `test_cve_with_unmapped_cwe_is_reported_not_guessed()` and `test_cve_without_cwe_is_reported_not_guessed()`) actually correct?**
  _`CveRecord` has 16 INFERRED edges - model-reasoned connections that need verification._
- **What connects `vuln2action-lab`, `Vuln2Action-Lab`, `Repository structure` to the rest of the system?**
  _239 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `io` be split into smaller, more focused modules?**
  _Cohesion score 0.05128205128205128 - nodes in this community are weakly interconnected._
- **Why does `project_root()` connect `contextlib` to `io`, `dataclasses`, `parametrize`, `difflib`, `hashlib`, `gzip`, `build_capec_benchmark.py`, `evaluate_retrieval.py`, `post`, `inspect`, `csv`, `pathlib`, `build_capec_independent.py`, `config.py`, `evaluate_capec_independent.py`, `argparse`, `build_hybrid_eval.py`, `json`, `build_expanded_flow_dataset.py`, `collections`, `build_dataset.py`?**
  _High betweenness centrality (0.017) - this node is a cross-community bridge._
- **Should `Counter` be split into smaller, more focused modules?**
  _Cohesion score 0.05960755275823769 - nodes in this community are weakly interconnected._
- **Why does `KnowledgeDocument` connect `KnowledgeDocument` to `cve2capec.py`, `evaluate_retrieval.py`, `analysis.py`, `schemas/cve.py`, `retrieval/base.py`, `semantic.py`?**
  _High betweenness centrality (0.011) - this node is a cross-community bridge._