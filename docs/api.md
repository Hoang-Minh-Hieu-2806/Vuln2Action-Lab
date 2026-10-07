# API (future sketch)

The FastAPI layer (`api/`) is a **scaffold** in Phase 1. Intended endpoints:

- `GET /cve/{cve_id}` — return normalised CVE record (sample data for now).
- `POST /analysis` — run ingest -> retrieve -> generate, return workflow.
- `POST /reproduction` — plan + (simulated) execute a workflow on a lab.
- `GET /results/{run_id}` — fetch stored `ReproductionResult`/report.

Schemas live in `api/schemas/`. No auth in Phase 1 (localhost demo only).
Run later with:

```bash
uvicorn api.main:app --reload
```
