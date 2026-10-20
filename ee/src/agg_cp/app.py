"""FastAPI application factory for the Agent Governance Gateway control plane."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse


def create_app() -> FastAPI:
    """Build and return the control-plane FastAPI application.

    No module-level mutable state; every call returns a fresh app.
    """
    app = FastAPI(
        title="Agent Governance Gateway - Control Plane",
        docs_url=None,
        redoc_url=None,
    )

    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @app.get("/ready")
    async def ready() -> JSONResponse:
        # T6 adds DB connectivity and schema-head checks here.
        return JSONResponse({"status": "ok"})

    return app
