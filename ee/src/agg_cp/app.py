"""FastAPI application factory for the Agent Governance Gateway control plane.

No module-level mutable state.  The DB engine lives in the FastAPI
lifespan (created on startup, disposed on shutdown).  Environment
variables are read only inside :func:`settings_from_env`, never at
import time.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse


@dataclass(frozen=True)
class Settings:
    """Control-plane configuration.  Immutable (frozen dataclass)."""

    db_url: str | None = None


def settings_from_env() -> Settings:
    """Build :class:`Settings` from environment variables.

    Reads ``AGG_DATABASE_URL`` or ``AGG_DATABASE_URL_FILE`` (the file
    is read once; useful for Docker secrets mounted as files).
    Never called at import time.
    """
    url = os.environ.get("AGG_DATABASE_URL")
    if url is None:
        url_file = os.environ.get("AGG_DATABASE_URL_FILE")
        if url_file:
            url = Path(url_file).read_text(encoding="utf-8").strip()
    return Settings(db_url=url)


def create_app(
    *,
    db_url: str | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    """Build and return the control-plane FastAPI application.

    No module-level mutable state; every call returns a fresh app.
    The engine lifecycle is managed by the FastAPI lifespan context.
    """
    if settings is None:
        settings = Settings(db_url=db_url)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if settings.db_url:
            from .db import make_engine

            app.state.engine = make_engine(settings.db_url)
        yield
        engine = getattr(app.state, "engine", None)
        if engine is not None:
            await engine.dispose()

    app = FastAPI(
        title="Agent Governance Gateway - Control Plane",
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )

    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @app.get("/ready")
    def ready() -> JSONResponse:
        """200 only when DB reachable AND schema at Alembic head.

        503 with a short, non-secret reason otherwise.  The URL,
        password and raw exception text are never exposed.
        """
        if not settings.db_url:
            return JSONResponse(
                {"status": "error", "reason": "no database configured"},
                status_code=503,
            )
        from .db import check_db_ready

        ok, reason = check_db_ready(settings.db_url)
        if ok:
            return JSONResponse({"status": "ok"})
        return JSONResponse(
            {"status": "error", "reason": reason},
            status_code=503,
        )

    return app
