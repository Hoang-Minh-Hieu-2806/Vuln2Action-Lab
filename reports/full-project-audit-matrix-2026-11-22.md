# Full audit matrix — 2026-11-22

Status vocabulary: VERIFIED, PARTIALLY VERIFIED, NOT VERIFIED, NOT IMPLEMENTED,
BLOCKED, NOT EVALUATED.

| ID | Component | Status | Direct evidence | Limitation |
|---|---|---|---|---|
| A1 | Repo structure / module boundaries | VERIFIED | `src/vuln2action/{domain,connectors,retrieval,generation,reproduction,evidence,pipeline}` | — |
| A2 | CLI entry point | VERIFIED | `src/vuln2action/cli.py:64-65`, smoke test | — |
| A3 | API scaffold | PARTIALLY VERIFIED | `api/main.py:16-20`, `routes/*.py` | no response_model, read-only |
| A4 | GUI | PARTIALLY VERIFIED | `gui/app.py:56,110-150` | reference flow only |
| A5 | Config injection | VERIFIED | `config/settings.yaml`, `models.yaml:21-31` | provider `enabled` ignored by factory |
| B1 | NVD / MITRE connectors | VERIFIED (code) | `connectors/nvd.py`, `mitre.py`, `reproduction.py` | no raw NVD snapshot local |
| B2 | Dataset paper-scale 114.560 | NOT VERIFIED | `data/processed/reproduction` absent | doc-only number |
| B3 | 89.311 CVE có CWE / 96.368 pairs | NOT VERIFIED | same | doc-only |
| B4 | 55.420 flow rows / 176 CAPEC | NOT VERIFIED | same | doc-only |
| B5 | 665 techniques / 45.538 ExploitDB | NOT VERIFIED | `docs/stage2-exploit-mapping-report-vi.md` | doc-only |
| B6 | Deterministic split builder | VERIFIED | `connectors/reproduction.py:222-255`, `tests/unit/test_reproduction_dataset.py` | split file not local |
| B7 | Leakage check | VERIFIED (finding) | `docs/t5-stage1-eval-vi.md:51` | 11.083/11.089 overlap |
| C1 | Retrieval keyword/TF-IDF/semantic | VERIFIED | `retrieval/*.py`, `tests/unit/test_retrieval_backends.py` | — |
| C2 | Neural embeddings | NOT IMPLEMENTED | `retrieval/embeddings.py` stub | — |
| C3 | CAPEC mapping scripts | VERIFIED | `scripts/select_capec.py`, `tests/unit/test_capec_selection.py` | — |
| C4 | CAPEC 86/100, 87/100 | PARTIALLY VERIFIED | `evaluation/datasets/capec_benchmark.json` + docs | circular label |
| C5 | Independent 21-CVE set | VERIFIED (artifact) | hash `93128e50...49c8`, `docs/evaluation/capec-independent-freeze.md` | metrics from docs |
| C6 | P@3 0,296 vs 0,3333 | VERIFIED (cause) | `retrieval/semantic.py:236-240`, local raw XML = True | environment-dependent |
| D1 | Rule-based generation | VERIFIED | `generation/rule_based.py:20`, `test_generation.py` | lab-script prose |
| D2 | T5 adapter + decoding | VERIFIED (code) | `generation/t5.py:204-307`, `test_generation_t5.py` | no paper checkpoint |
| D3 | Prompt/input construction | PARTIALLY VERIFIED | `generation/prompts.py`, `t5.py:274` | CAPEC context not forced into prompt |
| D4 | Empty/looping output handling | VERIFIED | `parse_flow`, `flow_to_workflow`, `tests/unit/test_generation_t5.py` | content quality low |
| D5 | GUI generated_flow | NOT IMPLEMENTED | `gui/app.py:147` | plan in `reports/gui-generation-preparation.md` |
| E1 | Local toy T5 artifact | VERIFIED | `models/t5-capec-flows/training_summary.json` | t5-small, 120 steps, 148 records |
| E2 | Kaggle stage 1 | BLOCKED | notebook dirs + docs only | no local artifact; audit forbidden to access Kaggle |
| E3 | CVE-only BLEU 0,1640/0,2567 | NOT VERIFIED (historical doc) | `docs/t5-stage1-paper10-eval-vi.md` | not re-run |
| E4 | CAPEC-conditioned 0,8594 | NOT COMPARABLE | same doc, section 8 | different input condition |
| E5 | Hybrid 0,7508 | NOT COMPARABLE | `docs/hybrid-two-stage-vi.md:167` | different protocol, 997 samples |
| F1 | 120-CVE benchmark | VERIFIED (circularity finding) | `docs/analysis.md:16-30` | not independent |
| F2 | Independent 21 cases | PARTIALLY VERIFIED | frozen file + docs | 12/21 reachable, old CVEs |
| F3 | Human eval 20 CVE | BLOCKED | `docs/human-evaluation/cases.json` candidate only | no splits.json, no outputs, no scores |
| F4 | Group-split holdout | NOT IMPLEMENTED | `docs/evaluation/t5-group-split-plan.md` | plan only |
| G1 | cve-001 vulnerable/patched | VERIFIED | `labs/cve-001/target/app.py`, `docker-compose.yml` | — |
| G2 | Validator semantics | VERIFIED | `labctl.py:109-139` | fixed marker |
| G3 | Allowlist executor | VERIFIED | `executor.py:21-31,108-124`, `test_executor.py` | 2 actions same command |
| G4 | Localhost guard | VERIFIED | `test_executor_refuses_non_local_target_before_running` | — |
| G5 | Negative counterfactual | VERIFIED (historical) | `test_broken_patched_counterfactual_is_not_pass` | not rerun in audit |
| G6 | cve-002/003 | NOT IMPLEMENTED | `lab.yaml:status=placeholder` | — |
| H1 | checkpoint_id flow | VERIFIED | `t5.py:296-307`, `run.py:70-86` | string, not hash |
| H2 | Round-trip + backward compat | VERIFIED | `tests/unit/test_evidence_provenance.py` | internal only |
| H3 | External strict consumers | NOT EVALUATED | `reports/public-schema-compatibility-audit.md` | `OLD_STRICT_READS_NEW: NO` |
| J1 | CI on dev | VERIFIED | `.github/workflows/ci.yml:3-8`, run #6 historical | — |
| J2 | Fresh pytest | VERIFIED | 248 passed, 6 skipped (this audit) | 6 = Docker opt-in |
| J3 | Fresh ruff CI scope | VERIFIED | exit 0 | — |
| J4 | Full `ruff check .` | VERIFIED (finding) | exit 1, 5 errors in `labs/` | pre-existing |
| J5 | Docker CI job | NOT IMPLEMENTED | `reports/ci-lab-integration-plan.md` | job not enabled |
| K1 | README checklist T5 | VERIFIED (stale) | `README.md:87` unchecked | honest, matches reality |
| K2 | Paper deviation draft | VERIFIED | `docs/paper-deviation-report-vi.md` | draft, placeholder |
