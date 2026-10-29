# Methodology

1. **Foundation (now):** scaffold structure, schemas, baselines, sample
   pipeline, tests. Everything runs offline on fake data.
2. **Ingestion (implemented):** NVD 2.0 client, local snapshots, CWE/CAPEC XML
   parsers, and a dataset builder. Downloads remain opt-in via
   `scripts/download_data.py`; `scripts/build_dataset.py` only reads local files.
3. **Retrieval (implemented):** a small tracked CWE corpus
   (`data/samples/knowledge_corpus.json`) plus a CVE→CWE benchmark with NVD
   labels. The corpus contains the 11 CWE entries used as labels plus 20 common
   distractor CWEs; queries are raw NVD descriptions and labels are NVD's CWE
   assignments (not hand-written). Keyword, TF-IDF, and semantic retrieval
   share one backend interface and the same stopword-filtered text
   normalisation. TF-IDF adds word bigrams/sublinear TF and a light CWE/CAPEC
   name boost. Semantic retrieval additionally indexes MITRE alternate terms,
   related CAPEC attack-pattern names, and direct parent-weakness definitions,
   splits CamelCase names, and blends word and character n-gram TF-IDF. The
   enrichment comes from MITRE catalog metadata only, never from NVD labels.
   The tracked `data/samples/cwe_semantic_context.json` keeps the seed subset
   reproducible offline; raw MITRE snapshots extend it to the full catalog when
   present. The pipeline merges record-known CWEs, retrieved contexts, and
   reference metadata. The harness excludes zero-score hits and reports P@k /
   R@k / F1@k at the cutoff plus MRR over the full ranking (and MRR@k); code
   lives in `evaluation/retrieval/`. Rejected variants are recorded rather than
   silently tuned away: full CAPEC descriptions and CWE `Extended_Description`
   created hub documents (especially CWE-20/CWE-78); CWE
   `Observed_Examples` were excluded because they can name benchmark CVEs; and
   an alternate-term max-fusion variant improved the 9-case benchmark but was
   not stable under leave-one-out evaluation, so it is not the default. Neural
   embeddings remain a stub until a measured experiment justifies their cost.
4. **Generation:** freeze the `GenerationProvider` interface; improve the
   rule-based templates; then experiment with LLM-API prompts and/or a small
   local T5 fine-tune. Track with `evaluation/generation/`.
5. **CVE→CAPEC mapping (implemented):** expand a CVE's NVD CWE list into CAPEC
   candidates using the catalog's `Related_Weakness` links, then rank the
   candidates against the description with TF-IDF + cosine and Word2Vec +
   cosine. Both methods rank the same pool; ties break by CAPEC id; a query
   with no shared vocabulary yields no ranking rather than an arbitrary pick.
   The 120-case tracked benchmark stores verbatim NVD queries and
   Galeax/CVE2CAPEC label sets. Because Galeax labels are exactly the
   CWE→CAPEC closure (verified on 18,540 CVEs), the harness reports the
   paper-compatible membership metric *and* discriminative metrics (NDCG,
   Top-1 CWE coverage, R@5) computed from NVD CWEs, plus a common-subset
   aggregate so a method that always answers is not rewarded for coverage.
   The stage degrades to `capec=None` + a reason when the opt-in catalog or
   the optional `gensim` extra is absent.
6. **Reproduction:** implement 1-3 Docker labs (`labs/cve-00x/`) with explicit
   validation scripts; wire the executor to run lab-scoped commands only.
   `cve-001` is live (vulnerable + patched, real PASS/FAIL); `cve-002`/`003`
   remain placeholders.
7. **Validation/evidence:** reserve PASS/FAIL for lab evidence; simulations are
   labelled SIMULATED and stored with a typed report schema.
8. **Evaluation:** the retrieval and CAPEC harnesses run on tracked benchmarks
   with real labels; extend generation/reproduction benchmarks next. Never
   fabricate scores.
9. **Integration/demo:** optional FastAPI endpoints + notebook walkthrough.

All experiments run against **team-owned isolated labs**. Findings are
reported as reproduction evidence, not as operational exploits.
