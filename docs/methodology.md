# Methodology

1. **Foundation (now):** scaffold structure, schemas, baselines, sample
   pipeline, tests. Everything runs offline on fake data.
2. **Ingestion:** add NVD CVE API client + CWE/CAPEC parsers over local
   snapshots (opt-in download via `scripts/download_data.py`, never automatic).
3. **Retrieval:** build a small local corpus; compare keyword vs TF-IDF with
   `evaluation/retrieval/`; add embeddings only if baselines underperform.
4. **Generation:** freeze the `GenerationProvider` interface; improve the
   rule-based templates; then experiment with LLM-API prompts and/or a small
   local T5 fine-tune. Track with `evaluation/generation/`.
5. **Reproduction:** implement 1-3 Docker labs (`labs/cve-00x/`) with explicit
   validation scripts; wire the executor to run lab-scoped commands only.
6. **Validation/evidence:** harden PASS/FAIL criteria; standardise report schema.
7. **Evaluation:** run `evaluation/` harnesses on the placeholder benchmark,
   then extend the benchmark — never fabricate scores.
8. **Integration/demo:** optional FastAPI endpoints + notebook walkthrough.

All experiments run against **team-owned isolated labs**. Findings are
reported as reproduction evidence, not as operational exploits.
