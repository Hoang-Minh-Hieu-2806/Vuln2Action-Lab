# Research questions

- **RQ1 (retrieval):** How effectively can relevant vulnerability context
  (CWE/CAPEC/references) be retrieved for a given CVE with lightweight
  methods (keyword, TF-IDF, and MITRE-enriched semantic retrieval) before
  using neural embeddings?
- **RQ2 (generation):** How accurately can a model (or rule baseline) generate
  a *reproducible* workflow — complete, ordered, lab-grounded steps — from
  CVE + retrieved context?
- **RQ3 (validation):** How reliably can generated workflows be validated in
  isolated Docker labs (PASS/FAIL agreement, success rate, execution time,
  false positives)?
- **RQ4 (abstraction):** Does a provider-agnostic generation interface let the
  team swap rule-based/LLM/T5 backends without pipeline changes?
- **RQ5 (evidence):** What minimal evidence bundle (logs, outputs, timestamps,
  verdicts) is sufficient for a third party to re-run and confirm a result?
