"""Optional FastAPI application factory."""

from __future__ import annotations

try:
    from fastapi import FastAPI
except ImportError:  # FastAPI optional in Phase 1
    FastAPI = None  # type: ignore[assignment,misc]


def create_app():
    if FastAPI is None:
        raise RuntimeError("Install the optional API dependencies: pip install -e .[api]")
    from api.routes import analysis, cve, reproduction, results

    application = FastAPI(title="Vuln2Action-Lab", version="0.2.0")
    application.include_router(cve.router)
    application.include_router(analysis.router)
    application.include_router(reproduction.router)
    application.include_router(results.router)
    return application


if FastAPI is not None:
    app = create_app()
else:
    app = None  # type: ignore[assignment]
