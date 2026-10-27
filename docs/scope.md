# Scope

## In scope

- Local CVE/CWE/CPE/CAPEC schema parsing and sample data.
- Opt-in NVD 2.0 snapshot ingestion plus CWE/CAPEC catalog parsing
  (`scripts/download_data.py` → `scripts/build_dataset.py`). No automatic
  downloads and no bulk fetching during setup.
- Keyword, TF-IDF, and MITRE-enriched semantic retrieval over a local
  knowledge base (no model download or network call at query time).
- Rule-based reproduction-workflow generation (human-readable steps).
- Simulated/placeholder execution against **isolated Docker labs on localhost**.
- Truthful `SIMULATED` outcomes and typed evidence/report contracts; real
  `PASS`/`FAIL` is limited to labs with a checked-in validator and a patched
  counterfactual (`labs/cve-001` today).
- Evaluation harnesses: measured retrieval metrics over a tracked CVE→CWE
  benchmark; generation/reproduction benchmarks remain placeholders.
- Optional local FastAPI scaffold for demo purposes.

## Out of scope (will not be built in this project)

- Autonomous hacking of real-world systems — **explicitly forbidden**.
- Scanning, exploiting, or testing any system the team does not own and
  has not built as an isolated lab.
- Shipping real weaponised exploit code.
- Kubernetes, Terraform, cloud deployment, microservices, Redis/Kafka,
  PostgreSQL, vector databases, auth, or frontend — unless a later phase
  genuinely requires them (none do at this stage).
- Automatic bulk downloading of large datasets during setup.
- Committing secrets/API keys (`.env` is git-ignored by policy).

## Safety rule

If a target is not `localhost` / `127.0.0.1` / the isolated lab network,
the executor must refuse to run. See `src/vuln2action/reproduction/executor.py`.
