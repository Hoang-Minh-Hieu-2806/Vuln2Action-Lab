# Roadmap

- **Phase 1 — Foundation (complete):** installable package, typed contracts,
  validated config, lab manifests, baselines,
  sample pipeline, tests, docs. Done when `pytest` and
  `vuln2action --sample CVE-2024-0001` returns SIMULATED offline.
- **Phase 2 — CVE ingestion (implemented):** NVD 2.0 client, local snapshots,
  CWE/CPE/CAPEC parsers, and a dataset builder. Downloads stay opt-in and are
  never triggered by the pipeline.
- **Phase 3 — Retrieval (implemented):** tracked CWE corpus + 9-case CVE→CWE
  benchmark with NVD labels; keyword/TF-IDF plus MITRE-enriched semantic
  retrieval behind one backend interface; measured P/R/F1/MRR via
  `scripts/run_evaluation.py --stage retrieval`. Semantic enrichment improves
  all aggregate metrics on the seed benchmark. Neural embeddings remain an
  explicit stub until a measured experiment justifies their cost.
- **Phase 3b — CVE→CAPEC (implemented):** CWE→CAPEC candidate expansion from the
  MITRE catalog, ranked by TF-IDF and Word2Vec with cosine similarity, plus a
  120-CVE tracked benchmark (`evaluation/datasets/capec_benchmark.json`) whose
  labels come from Galeax/CVE2CAPEC and whose queries are real NVD text. The
  harness reports the paper-compatible membership metric alongside
  discriminative metrics, because the Galeax labels are exactly the CWE→CAPEC
  closure and membership alone cannot compare ranking methods.
- **Phase 4 — Generation (T5 implemented):** local `t5-small` fine-tuning on
  MITRE CAPEC execution-flow phases with CPU training, checkpointing and an
  inference CLI, behind the existing `GenerationProvider` interface. A bounded
  run completed (120 steps, train loss 2.44, val 2.48) but output quality is not
  usable yet; see `docs/t5-training.md`. Rule-based remains the default; the
  LLM-API provider is still a stub; evaluation is implemented in Phase 7.
  Decoding controls and structural normalisation (P1.3) cut repetition from 0.60
  to 0.007 and make every output three-phase; content quality remains low and the
  training-target truncation is still unfixed (docs/generation-quality.md).
- **Phase 5 — Docker reproduction (in progress):** `labs/cve-001` is live with
  vulnerable/patched services and a checked-in PASS/FAIL validator; `cve-002`
  and `cve-003` remain placeholders.
- **Phase 6 — Validation/evidence:** strict PASS/FAIL criteria, evidence
  schema v1, Markdown/JSON reports under `results/`.
- **Phase 7 — Evaluation (retrieval + generation complete):** the tracked
  retrieval benchmark reports P/R/F1/MRR. Generation evaluation reports corpus
  and sentence BLEU, ROUGE-1/2/L, phase-order accuracy, phase coverage,
  repetition and per-phase step recall, with a train/validation leakage audit
  (`docs/generation-evaluation.md`). Scores stay reproducible; nothing is
  hard-coded.
- **Phase 8 — Integration/demo:** optional FastAPI + notebooks + final report.
