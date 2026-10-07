"""FastAPI app factory (scaffold). Run later: uvicorn api.main:app --reload."""
from __future__ import annotations

try:
    from fastapi import FastAPI

    from api.routes import analysis, cve, reproduction, results

    def create_app() -> FastAPI:
        app = FastAPI(title="Vuln2Action-Lab", version="0.1.0")
        app.include_router(cve.router)
        app.include_router(analysis.router)
        app.include_router(reproduction.router)
        app.include_router(results.router)
        return app

    app = create_app()
except ImportError:  # FastAPI optional in Phase 1
    app = None  # type: ignore[assignment]
