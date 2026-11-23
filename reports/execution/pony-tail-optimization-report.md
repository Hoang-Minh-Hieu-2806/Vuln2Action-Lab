# Pony Tail optimization & debugging report — Batch 0 baseline

## 1. Skill used

- Skill: `ponytail` (level `full`, default), confirmed present at
  `~/.cache/opencode/packages/@dietrichgebert/ponytail@latest/node_modules/@dietrichgebert/ponytail/skills/ponytail/SKILL.md`.
- Full `SKILL.md` read (52 lines). No extra references exist in the skill folder.
- Rules applied: read before writing; smallest complete change; delete before add; grep callers before bug fixes; add one small test for new non-trivial logic; keep existing boundaries; no unnecessary abstraction, dependency, or schema change.
- No source file was changed in Batch 0.

## 2. Git baseline

| Item | Value |
|---|---|
| Branch | `dev` |
| HEAD | `a152519b9ca26a2c6baa583b2255b64b6e893a55` |
| Tracking | `origin/dev` |
| Staged changes | none |
| Unstaged changes | 26 tracked files (194 insertions, 154 deletions) from previous sessions |
| Untracked | 12 files, including new tests, `utils/vectors.py`, two reports, `.playwright-cli/` |

All pre-existing modifications were preserved. No reset, clean, checkout, stash, commit, or push.

## 3. Modules inspected at map level

`src/vuln2action` 62 py files; `api` 11; `gui` 2; `evaluation` 13; `scripts` 21; `tests` 46; `labs` 2.
No file was read in full during Batch 0 beyond the skill file; detailed code reading belongs to later batches.

## 4. Bugs found / fixed

None in Batch 0. No code was read deeply enough to confirm or reject a bug yet.

## 5. Performance optimizations

None in Batch 0. No baseline measurement of a hot path was taken.

## 6. Benchmarks before/after

No code benchmark performed. Safe baseline checks only (below).

## 7. Refactors

None in Batch 0.

## 8. Security findings

None confirmed in Batch 0. Known out-of-scope: `ruff check .` still reports 5 pre-existing lab-helper warnings (2× RUF100, 3× PLW1510).

## 9. Test results

| Command | Result |
|---|---|
| `python -m pytest -q -rs` | 304 passed, 7 skipped, exit 0 |
| Skips | 6 Docker opt-in (`V2A_DOCKER_TESTS=1`), 1 FastAPI missing |
| `python -m ruff check src api scripts tests evaluation gui` | All checks passed, exit 0 |
| `python -m compileall -q src/vuln2action api scripts tests evaluation` | exit 0 |
| CLI `--sample CVE-2024-0001 --json-only` | `SIMULATED`, 9 evidence keys |
| Retrieval `--stage retrieval --json-only` | `keyword`, `semantic`, `tfidf` |
| `--stage reproduction` | exit 2, explicit invalid choice |
| `python -m ruff check .` | exit 1, 5 pre-existing labs warnings |

SKIPPED and BLOCKED are not counted as PASS.

## 10. Regression risks

None from Batch 0 (no code change). Existing working tree already contains prior-session changes; later batches must avoid touching them without reason.

## 11. Unresolved issues

- FastAPI absent → API test skipped.
- Docker integration tests skipped by explicit constraint.
- Full-repo Ruff warnings in `labs/`.
- No source-level bug confirmed yet.

## 12. Not checked

Detailed source code of all modules, Kaggle notebooks, benchmark data, Docker runtime, network/API bind behavior, and any performance hot path.

## 13. Files changed in Batch 0

Only this report: `reports/execution/pony-tail-optimization-report.md`. No source, config, test, or data change.

## Finding table

| Finding | Severity | Status | Evidence |
|---|---|---|---|
| Pre-existing full-repo Ruff warnings in labs | Low | Deferred | `ruff check .`: 5 errors; CI scope clean |
| FastAPI test skipped | Low | Blocked | `pytest -rs`: missing fastapi |
| Docker integration skipped | Medium | Blocked | 6 skips; explicit no-Docker constraint |

## Batch 1 — critical/high-impact bugs (approved)

### 1. Findings

**FIXED — nested NVD configuration CPEs were silently dropped**
- Location: `src/vuln2action/connectors/nvd.py:221-240`, function `_cpe_criteria()`.
- Cause: `walk()` recursed only into `node.get("nodes")`. NVD 2.0 configurations also use
  `node.get("children")` for nested `AND`/`OR` groups; those subtrees were never visited.
- Impact: `CveRecord.cpe` missed affected products whenever `cpeMatch` lived under `children`.
  That understates `dataset_stats()["selected_cves_with_cpe"]` (`connectors/reproduction.py:321`)
  and corrupts affected-product evidence used by reports.
- Trigger: any NVD record shaped like
  `configurations[].nodes[].children[].cpeMatch` with `vulnerable: true`.
- Repro before fix: new test
  `tests/unit/test_nvd.py::test_parse_nvd_cve_collects_cpe_from_nested_configuration_children`
  failed with `[] != ['cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*']`.
- Minimal fix: one line, `walk(node.get("children") or [])` after the existing `nodes` recursion.
  No interface, schema, dataset, or benchmark change. Existing `found` dedupe still applies.
- After fix: focused NVD/reproduction/dataset tests 33 passed; full suite 305 passed, 7 skipped.

**NEEDS_INVESTIGATION — empty allowlist silently becomes a default allowlist**
- Location: `src/vuln2action/reproduction/executor.py:34-36`,
  `allowed = allowed_hosts or {"localhost", "127.0.0.1", "lab", "local"}`.
- Passing `set()` (or any empty collection) yields the permissive default instead of denying all.
- Current callers are safe: `pipeline/run.py:60` always builds a non-empty set, and tests pass
  explicit non-empty sets. No caller was found that triggers the empty-set case.
- Not fixed: changing this would alter security-boundary semantics, which requires separate
  approval per the Batch 1 constraints.

### 2. Findings not fixed
- `is_allowed_target()` empty-set semantics above — security boundary, needs approval.
- FastAPI runtime test skipped — optional dependency absent, out of scope.
- Docker integration tests skipped — explicitly disallowed in this batch.
- Full-repo Ruff warnings in `labs/` — pre-existing, out of scope.

### 3. Files changed by Batch 1
| File | Change |
|---|---|
| `src/vuln2action/connectors/nvd.py` | +1 line (`children` recursion) |
| `tests/unit/test_nvd.py` | +29 lines (regression test) |
| `reports/execution/pony-tail-optimization-report.md` | this section |

No other tracked or untracked file was touched. No dataset, benchmark, model, config, schema,
or public interface change. No refactor, dead-code deletion, or performance work.

### 4. Tests before/after
| Check | Before fix | After fix |
|---|---|---|
| New nested-CPE regression test | FAIL (`[] != expected CPE`) | PASS |
| `python -m pytest -q tests/unit/test_nvd.py tests/unit/test_reproduction_dataset.py tests/unit/test_dataset_scripts.py` | not run | 33 passed |
| `python -m pytest -q -rs` | 304 passed, 7 skipped (Batch 0) | 305 passed, 7 skipped |
| `python -m ruff check src api scripts tests evaluation gui` | All checks passed | All checks passed |
| `python -m compileall -q src/vuln2action api scripts tests evaluation` | exit 0 | exit 0 |

Skips remain 6 Docker opt-in + 1 missing FastAPI; SKIPPED/BLOCKED are not PASS.

### 5. Git status before/after
| Item | Before Batch 1 | After Batch 1 |
|---|---|---|
| Branch / HEAD | `dev` / `a152519...` | unchanged |
| Staged | none | none |
| Modified tracked | 26 (pre-existing) | 28 (26 pre-existing + `nvd.py`, `test_nvd.py`) |
| Untracked | 14 paths (12 baseline + Batch 0 report artifacts) | 14 paths, unchanged |

No reset, clean, checkout, stash, commit, push, or branch switch was used.

### 6. Regression risks
- Low. The only production change adds recursion into NVD `children`; it cannot remove or alter
  previously extracted CPEs because results are still deduplicated and ordered by traversal.
- Records without `children` behave identically to before.
- Existing 28 modified/untracked artifacts were preserved; no overlap with the 26 protected files
  except the explicitly required report file.

### 7. Needs approval
- Whether to change `is_allowed_target()` so an explicitly empty allowlist denies all targets.
- Batch 2 has not started.

## Batch 2 — profiling, benchmark, proposals (no source change)

### A. Methodology and environment

- Skill `ponytail` (full) reapplied: measure before proposing; no change without evidence.
- Harness: `C:\Users\HOANGM~1\AppData\Local\Temp\opencode\v2a_batch2_bench.py`, outside the repo.
- Timing: `time.perf_counter()`, `gc.collect()` before each run; report min/median/mean/max.
  Median is the headline number. Memory: `tracemalloc` peak; attribution via `take_snapshot()`.
  Hot functions: `cProfile` sorted by cumulative time.
- Same repo root, same tracked inputs, same process environment for every compared run.
- Inputs are real repository files only: 2021 NVD gzip (16.9 MB), CWE/CAPEC XML (19.1/3.8 MB),
  31-document seed corpus, 3 sample CVEs, local T5 checkpoint (242 MB). No dataset was edited.
- Environment: Python 3.13.2, Windows 11 (10.0.26300), 12 logical CPUs,
  Intel64 Family 6 Model 154; pydantic 2.14.1, numpy 2.5.3, scikit-learn 1.9.1,
  scipy 1.18.1, torch 2.15.0+cpu, transformers 5.22.0, gensim 4.4.0, pytest 9.1.1.

### B. Measured baseline

| Flow | Real input | Runs | Median | tracemalloc peak |
|---|---|---:|---:|---:|
| NVD ingest (gz read + JSON + `parse_nvd_records`) | 22,613 records | 3 | 4.224 s | 943.26 MiB |
| — JSON decode only | same payload | 3 | 1.803 s | not isolated |
| — Pydantic parse only | same payload | 3 | 0.833 s | 29.92 MiB |
| CWE/CAPEC XML parse | 984 CWE + 615 CAPEC | 3 | 0.629 s | 129.44 MiB |
| Corpus cold load | 31 documents, 14.5 KB | 20 | 0.0006 s | 0.05 MiB |
| `default_corpus()` cached | 31 documents | 1000 | ~0.0000 s | n/a |
| `semantic_search` | 31 documents, top_k=3 | 30 | 0.056–0.058 s | 2.91 MiB |
| `tfidf_search` | 31 documents | 30 | 0.0046 s | n/a |
| `keyword_search` | 31 documents | 30 | 0.0006 s | n/a |
| `build_contexts_for_cve(semantic)` | 1 CVE | 30 | 0.056 s | n/a |
| Rule-based generation | 1 CVE, 3 contexts | 200 | 0.0001 s | n/a |
| `analyze_cve` full (rule_based) | 1 CVE | 10 | 0.060 s | 2.91 MiB |
| `save_report` | 1 small payload | 10 | 0.015 s | 0.03 MiB |
| T5 generation, reused instance | local checkpoint | 2 | 6.92 s (6.89–6.95) | n/a |
| T5 via fresh generator per call | local checkpoint | 2 | 11.11 s (7.53–14.68) | n/a |

T5 variance is high (an earlier single cold call took 29.73 s); the numbers are not a fixed speedup
claim, only evidence that repeated model loading is materially more expensive than reuse.

### C. Bottlenecks confirmed by profiling

1. **NVD ingestion CPU/memory churn.** cProfile (1 run, 6.012 s):
   `parse_nvd_records` 3.742 s cumulative; `_cpe_criteria` 2.129 s; `walk()` called **794,378**
   times (~35 calls/record) with 1.647 s self time; `json.loads`/`raw_decode` 1.436 s;
   Pydantic model init 0.821 s. Peak 943 MiB is transient allocation churn; the post-parse
   snapshot still attributes 34.19 MiB to `json/decoder.py` and 27.11 MiB to `pydantic/main.py`.
   Files: `src/vuln2action/connectors/nvd.py` (already modified in Batch 1).

2. **Semantic retrieval refits vectorizers on every query.** cProfile (10 searches, 0.851 s):
   `TfidfVectorizer.fit_transform` 0.770 s cumulative (~90%), `_count_vocab` 0.584 s,
   char n-grams 0.305 s. A probe that pre-fits the two vectorizers once on the same 31 real
   documents and only transforms the query took **0.0033 s median (n=1000)** versus
   **0.056–0.058 s** for `semantic_search` — about 17x lower for the scored portion.
   Ranking inputs are identical; no algorithm change is proposed.
   Files: `src/vuln2action/retrieval/semantic.py` (already modified), `retrieval/corpus.py`
   for cache invalidation.

3. **T5 generator is recreated per analysis.** `src/vuln2action/pipeline/analyze.py:63` calls
   `get_generator(provider)` on every call; `generation/base.py:28-31` returns a fresh `T5Generator`,
   which lazily loads the 242 MB local checkpoint on first `generate()`. Measured fresh-generator
   median 11.11 s versus 6.92 s with one reused instance. Output logic is unchanged by reuse.
   Files: `src/vuln2action/generation/base.py` (unmodified), `analysis.py` (unmodified).

4. **One-time CAPEC index load:** 0.133 s on first `analyze_cve` in profile, already `lru_cache`d.
   Classified NOT WORTH OPTIMIZING.

### D. Proposal table

| ID | Bottleneck | Class | Evidence | Cause | Solution | Est. impact | Regression risk | Files |
|---|---|---|---|---|---|---|---|---|
| P1 | Semantic vectorizer refit | HIGH IMPACT / MEDIUM RISK | 0.770 s/10 searches in fit_transform; reuse probe 0.0033 s vs 0.058 s | Both vectorizers are constructed and fitted per query over an unchanged cached corpus | Cache fitted vectorizers + matrices keyed by corpus identity; clear alongside `clear_corpus_cache()` | ~50–55 ms saved per semantic query on this corpus | Cache invalidation must be correct; `semantic.py` already modified | `retrieval/semantic.py`, `retrieval/corpus.py` |
| P2 | T5 generator recreated per call | HIGH IMPACT / LOW RISK | 11.11 s fresh vs 6.92 s reused (local checkpoint) | `get_generator("t5")` returns a new instance each call; each reloads weights | Cache only the T5 provider instance in `generation/base.py` | Removes repeated 242 MB load per run/CVE | Shared instance is stateless except model/tokenizer; rule_based/llm paths unchanged; memory held for process lifetime | `generation/base.py` |
| P3 | NVD recursive `walk()` | HIGH IMPACT / MEDIUM RISK | 794,378 calls, 2.111 s cumulative; peak 943 MiB | Recursive traversal creates many temporary lists/dicts | Replace with explicit stack preserving traversal order | Up to ~2 s per 22k-record feed, lower transient memory | `nvd.py` already modified; must preserve CPE order exactly | `connectors/nvd.py` |
| P4 | Full NVD payload held in memory | HIGH IMPACT / HIGH RISK | JSON decode 1.803 s; 943 MiB transient peak | `json.load()` materialises whole feed before Pydantic conversion | Stream/parse incrementally | Lower peak memory; needs new loader contract | Public loader/schema change, dataset build semantics | `connectors/nvd.py`, `connectors/reproduction.py` |
| P5 | CWE/CAPEC XML parse | LOW IMPACT / LOW RISK | 0.629 s, 129 MiB | ElementTree builds full trees | `iterparse` + element clearing | Small gain only in dataset-build, not per-CVE pipeline | Low | `connectors/mitre.py` |
| P6 | Corpus load, rule generation, report save, cached corpus | NOT WORTH OPTIMIZING | 0.0006 s, 0.0001 s, 0.015 s, ~0 s | Already cheap | None | Negligible | n/a | none |

### E. Proposed diff for P2 (HIGH IMPACT / LOW RISK) — NOT APPLIED

```diff
--- a/src/vuln2action/generation/base.py
+++ b/src/vuln2action/generation/base.py
@@
 from abc import ABC, abstractmethod
+from functools import lru_cache
@@
-def get_generator(name: str) -> GenerationProvider:
+@lru_cache(maxsize=1)
+def _t5_generator() -> GenerationProvider:
+    from vuln2action.generation.t5 import T5Generator
+
+    return T5Generator()
+
+
+def get_generator(name: str) -> GenerationProvider:
@@
     if key in {"t5", "local"}:
-        from vuln2action.generation.t5 import T5Generator
-
-        return T5Generator()
+        return _t5_generator()
```

No source change was made in Batch 2. P1/P3/P4 also need explicit approval because their target
files already carry pre-existing modifications.

### F. Not measured / NOT_MEASURED
- `mean_vector()` in `utils/vectors.py`: no trained Word2Vec model artifact found in the repo,
  so no meaningful vector-dimension workload exists. NOT_MEASURED.
- NVD HTTP client throttle/retry path: no network call made. NOT_MEASURED.
- Docker, Kaggle, training, GPU: excluded by constraints.
- Large multi-CVE T5 throughput: only 3 real sample CVEs were available; no extrapolation claimed.

### G. Files read / changed / Git status
- Read in Batch 2: `retrieval/corpus.py`, `retrieval/semantic.py` (enricher/search section),
  `retrieval/text.py`, `retrieval/tfidf.py`, `retrieval/keyword.py`, `generation/base.py`,
  `generation/t5.py` (initialisation/loading), `pipeline/analyze.py`, `evidence/reporter.py`,
  `evidence/provenance.py`, `connectors/reproduction.py`, `config/models.yaml`.
- Changed by Batch 2: only this report (untracked, explicitly required) and the temporary harness
  outside the repo. No source, config, test, dataset, model, or benchmark file changed.
- Git before/after Batch 2: `dev` @ `a152519...`, staged none, 28 modified tracked
  (26 pre-existing + Batch 1 `nvd.py`/`test_nvd.py`), 14 untracked paths — unchanged.

### H. Regression risks and approval needed
- No regression from Batch 2 itself: zero production code changes.
- P1 risk: stale vectorizer cache if corpus changes without cache invalidation.
- P2 risk: a shared T5 instance persists for the process lifetime; acceptable because the provider
  holds no per-request mutable state besides the model/tokenizer.
- P3 risk: traversal-order change would alter CPE ordering in evidence; must be tested if approved.
- Approval needed before any edit: P2 diff above; P1/P3/P4 as a group or individually.
- Batch 3 has not started.

## Full campaign — final release readiness (Stages 0–7)

### 1. Skill Pony Tail used
- Skill tool loaded `ponytail` (full level); `SKILL.md` read in full; no reference files exist.
- Applied rules: read before write; grep callers before fixes; smallest complete diff; one small
  regression test per non-trivial change; no new dependency; revert controlled when no measured gain.

### 2. Git baseline
- Branch `dev`, HEAD `a152519b9ca26a2c6baa583b2255b64b6e893a55`, staged: none.
- Campaign start: 28 modified tracked, 14 untracked. Campaign end: 32 modified tracked, 16 untracked.
- No reset/clean/stash/checkout/commit/push/branch switch. All 28 pre-existing tracked diffs preserved.

### 3. Repository overview
- Local single-user security research CLI/API/GUI; pipeline:
  CVE → ingestion → retrieval → generation → isolated lab → validation → evidence/report.
- Scope reviewed: `src/vuln2action`, `api`, `gui`, `evaluation`, `scripts`, `tests`, `labs`, `data`, `reports`.
- Environment: Python 3.13.2, Windows 11, 12 CPUs, pydantic 2.14.1, scikit-learn 1.9.1,
  numpy 2.5.3, torch 2.15.0+cpu, transformers 5.22.0, gensim 4.4.0, pytest 9.1.1.

### 4. Critical bugs
- No new critical correctness bug was confirmed beyond the already-fixed NVD 2.0 nested-CVE issue.
- Security finding `executor.py:35` (explicit empty allowlist falling back to a permissive default)
  was confirmed, reproduced by failing tests, and fixed fail-closed.

### 5. Bug fixes
- NVD `children` CPE extraction preserved; 4 added tests cover flat/no-children, `vulnerable=false`,
  deep children, dedupe and traversal order.
- `is_allowed_target()` now treats `None` as the default allowlist but any explicitly empty or
  invalid collection as deny-all.
- `load_model_settings()` now raises an actionable `ValueError` for legacy `enabled` flags.

### 6. Performance bottlenecks
- Confirmed: semantic retrieval refitting two TF-IDF vectorizers per query; T5 generator recreated
  per `analyze_cve()` call; NVD ingestion dominated by JSON decode + Pydantic conversion.
- Not optimized: corpus loading, rule-based generation, report save, cached corpus, one-time CAPEC index.

### 7. Benchmark before/after
| Flow | Baseline | Final | Evidence |
|---|---:|---:|---|
| Semantic search | 0.056–0.058 s median | 0.0030 s median | n=30, same 31-doc corpus |
| NVD ingest | 4.224 s median, 943 MiB peak | unchanged (trial reverted) | n=3, 22,613 records |
| T5 fresh generator | 11.1 s (user-reported) | 9.82 s / 2.16 s (n=2) | high variance, no fixed % claim |
| T5 reused via factory | 6.9 s (user-reported) | 1.37 s median (n=2, 1.34–1.39) | same local checkpoint |
| Full pytest | 305 passed, 7 skipped | 325 passed, 7 skipped | fresh runs |

### 8. T5 caching results
- `generation/base.py` caches only the T5 provider, keyed by the full `T5ProviderSettings` dump
  (checkpoint, base checkpoint, device, decoding knobs, allow_download), guarded by `Lock`.
- `clear_generator_cache()` added and exported. A failed config/constructor leaves no cache entry.
- 7 new cache tests + 8 provider tests passed. Weights/prompt/decoding unchanged.

### 9. Semantic search optimization results
- Fitted vectorizers and matrices cached under `(indexed texts, name_weight, char_weight)` with a lock;
  `clear_semantic_cache()` releases them. ImportError fallback to keyword search preserved.
- 8-case pre/post snapshot exactly equal; all retrieval metrics unchanged
  (semantic precision 0.296296, recall 0.75, F1 0.409524, MRR 0.791667, MRR@3 0.777778).
- 5 new cache tests passed; corpus-change and weight-change cases verified.

### 10. NVD ingestion results
- Iterative stack traversal was implemented and measured: median 4.224 s → 4.192 s, peak memory
  unchanged at 943.26 MiB. No reliable gain, so it was reverted by controlled edit.
- CPE output on the real 22,613-record feed was exactly equal before/after the trial and after revert.
- Final `nvd.py` diff remains only the Batch 1 `children` line.

### 11. Refactoring
- No speculative refactor. Existing `mean_vector` consolidation and `read_jsonl` generator remain valid.
- Two dead harness deletions were pre-existing and evidence-based; `evaluate_tfidf.py` kept as a
  valid manual research entry point. No new file deleted.

### 12. Security review
- No `shell=True`, `os.system`, `pickle`, `eval`/`exec` or `yaml.load` found in `src`.
- `subprocess.run` in executor uses no shell; manifest checks, lab-dir containment, localhost guard,
  validator check, atomic writes, collision guard and provenance path-traversal guard remain intact.
- GUI binds `127.0.0.1`; API factory has no public bind; no API started during this campaign.

### 13. Executor allowlist finding
- Contract established: `None` = default local allowlist; explicit empty = deny-all; invalid entries
  ignored; explicit entries never widened.
- 4 regression tests added; 3 failed before the fix. `test_reproduction.py` + `test_executor.py`: 20 passed.

### 14. API/GUI/config verification
- API settings loaded once into `app.state.settings`; GUI fresh-clone test passed.
- FastAPI optional dependency is declared (`api = fastapi>=0.110, uvicorn[standard]>=0.29`) but absent.
  Runtime API test remains BLOCKED/NOT TESTED; no dependency installed.
- Legacy `enabled` now yields a file-path-specific actionable migration error; new test passed.

### 15. Evidence/provenance verification
- 32 evidence/provenance tests passed; 1 FastAPI skip.
- Atomic write, sidecar-before-report, overwrite protection, digest validation, missing/malformed
  sidecar, invalid reference and path-escape handling verified by existing tests.
- No historical evidence, result, dataset, benchmark label or report content was modified.

### 16. Test results
| Command | Result |
|---|---|
| `python -m pytest -q -rs` | 325 passed, 7 skipped, exit 0 |
| `python -m ruff check src api scripts tests evaluation gui` | All checks passed, exit 0 |
| `python -m compileall -q src/vuln2action api scripts tests evaluation` | exit 0 |
| CLI smoke `--sample CVE-2024-0001 --json-only` | exit 0, `SIMULATED` |
| Retrieval smoke `--stage retrieval --json-only` | keyword/tfidf/semantic; semantic P@3 unchanged |
| Unsupported stage `reproduction` | exit 2, explicit argparse error |

### 17. Skipped/blocked tests
- 6 Docker integration skips: require `V2A_DOCKER_TESTS=1`; explicitly not run.
- 1 FastAPI skip: optional dependency absent; BLOCKED/NOT TESTED, not counted as PASS.
- Kaggle, training, Docker images and GPU paths were not exercised.

### 18. Files changed
- Source: `generation/base.py`, `generation/__init__.py`, `reproduction/executor.py`,
  `retrieval/semantic.py`, `config.py`, `connectors/nvd.py`.
- Tests: `test_generator_cache.py` (new), `test_semantic_cache.py` (new), `test_nvd.py`,
  `test_reproduction.py`, `test_provider_config.py`.
- Report: this file. No dataset, benchmark, model, checkpoint or historical artifact changed.

### 19. Risks remaining
- T5 cache holds the model for process lifetime; shared instance is stateless apart from model/tokenizer.
  Reported timings have high variance; treat them as directional, not a fixed speedup.
- Semantic cache grows per distinct corpus/weight key; corpus identity is part of the key, so a changed
  corpus cannot reuse stale matrices. Explicit clear functions are provided.
- Full-repo Ruff still has 5 pre-existing `labs/` warnings (2×RUF100, 3×PLW1510), outside CI scope.

### 20. Known limitations
- API runtime not verified (FastAPI absent); Docker integration not run; Kaggle artifact unavailable.
- `mean_vector` perf NOT_MEASURED (no Word2Vec model artifact); NVD HTTP throttle path NOT_MEASURED;
  large multi-CVE T5 throughput not extrapolated.
- GUI/API were not opened as public services.

### 21. Final release readiness assessment
**READY WITH KNOWN LIMITATIONS.** Local CLI/evidence/retrieval/generation paths are verified with
325 passing tests and clean CI-scope Ruff/compile. Known limitations are the blocked API runtime test,
Docker opt-in tests, unavailable Kaggle artifact and pre-existing lab Ruff warnings; none were hidden
or counted as PASS. No commit or push occurred.

### Finding classification
| Finding | Status |
|---|---|
| NVD 2.0 nested CPE extraction | FIXED_AND_TESTED |
| T5 provider recreation | FIXED_AND_TESTED |
| Semantic vectorizer refit | FIXED_AND_TESTED |
| NVD iterative traversal trial | DEFERRED (no measured gain; reverted) |
| Executor empty-allowlist fallback | FIXED_AND_TESTED |
| Legacy `enabled` config | FIXED_AND_TESTED |
| API runtime test | BLOCKED (FastAPI absent) |
| Docker integration | BLOCKED (explicit constraint) |
| Kaggle artifact / training | BLOCKED (explicit constraint) |
| Full-repo Ruff labs warnings | DEFERRED (pre-existing, out of CI scope) |
| mean_vector / dead harness / read_jsonl | NOT_APPLICABLE (already resolved in prior audit) |
