# Roadmap

- **Phase 1 — Foundation (complete):** installable package, typed contracts,
  validated config, lab manifests, baselines,
  sample pipeline, tests, docs. Done when `pytest` and
  `vuln2action --sample CVE-2024-0001` returns SIMULATED offline.
- **Phase 2 — CVE ingestion:** NVD API client, local snapshots, CWE/CPE/CAPEC
  parsers, dataset builder (`scripts/build_dataset.py`).
- **Phase 3 — Retrieval:** local corpus + keyword/TFIDF comparison with
  measured P/R/F1/MRR; embeddings experiment only if justified.
- **Phase 4 — Generation:** richer rule templates + prompt library; LLM-API
  and/or local T5 behind the same `GenerationProvider` interface.
- **Phase 5 — Docker reproduction:** 1-3 real isolated labs with per-lab
  compose files and validation scripts; guarded localhost-only executor.
- **Phase 6 — Validation/evidence:** strict PASS/FAIL criteria, evidence
  schema v1, Markdown/JSON reports under `results/`.
- **Phase 7 — Evaluation:** extend `evaluation/datasets/benchmark.json`;
  report retrieval/generation/reproduction metrics honestly.
- **Phase 8 — Integration/demo:** optional FastAPI + notebooks + final report.
