# Optional local API

The FastAPI layer exposes the following localhost-oriented endpoints:

- `GET /cve/{cve_id}` — return normalised CVE record (sample data for now).
- `POST /analysis` — run ingest -> retrieve -> generate, return workflow.
- `POST /reproduction` — plan and simulate a workflow; it never reports `PASS`.
- `GET /results/{run_id}` — fetch stored `ReproductionResult`/report.

It is intended only for a local demo and has no authentication. Run with:

```bash
uvicorn api.main:app --reload
```
