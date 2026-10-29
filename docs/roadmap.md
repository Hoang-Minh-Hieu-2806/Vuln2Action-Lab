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
- **Phase 4 — Generation:** richer rule templates + prompt library; LLM-API
  and/or local T5 behind the same `GenerationProvider` interface.
- **Phase 5 — Docker reproduction (in progress):** `labs/cve-001` is live with
  vulnerable/patched services and a checked-in PASS/FAIL validator; `cve-002`
  and `cve-003` remain placeholders.
- **Phase 6 — Validation/evidence:** strict PASS/FAIL criteria, evidence
  schema v1, Markdown/JSON reports under `results/`.
- **Phase 7 — Evaluation (retrieval complete):** the tracked retrieval
  benchmark reports P/R/F1/MRR; extend generation/reproduction benchmarks and
  keep every score reproducible.
- **Phase 8 — Integration/demo:** optional FastAPI + notebooks + final report.
