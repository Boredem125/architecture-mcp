from __future__ import annotations

# FastAPI application entry point: health plus the connector's REST view.
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sandbox.api.auth import TokenAuthMiddleware, ensure_tokens
from sandbox.api.hardening import SecurityHeadersMiddleware, install_error_handlers
from sandbox.api.routes import connector, health
from sandbox.config import SandboxConfig

logger = structlog.get_logger()

_config: SandboxConfig | None = None


def get_config() -> SandboxConfig:
    """Lazy-load configuration singleton."""
    global _config
    if _config is None:
        _config = SandboxConfig()
    return _config


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    config = get_config()
    logger.info(
        "sandbox_starting",
        environment=config.environment,
        log_level=config.log_level,
    )
    yield
    logger.info("sandbox_shutting_down")


ROOTS_ENV = "SANDBOX_CONNECTOR_ROOTS"


def connector_roots_from_env() -> dict[str, str]:
    """Roots the connector routes may serve (SEC-10): normalized request form -> stored root.

    Read once at startup; ``sandbox serve --root`` passes them through the
    environment so every uvicorn worker sees them. Empty means every connector
    call is refused.
    """
    out: dict[str, str] = {}
    for raw in os.environ.get(ROOTS_ENV, "").split(os.pathsep):
        if not raw.strip():
            continue
        try:
            stored = os.path.realpath(raw.strip())
        except (OSError, ValueError):
            continue
        out[os.path.normcase(os.path.normpath(stored))] = stored
    return out


def create_app(config: SandboxConfig | None = None) -> FastAPI:
    global _config
    if config is not None:
        _config = config

    app = FastAPI(
        title="Agent Governance Gateway API",
        description=(
            "Local REST view of a connector folder: status, pending escalations, "
            "audit, verify, and approve/deny with the approver token."
        ),
        version="1.0.0",
        lifespan=lifespan,
    )

    ensure_tokens()
    # Starlette runs the last-added middleware outermost: auth inside the
    # security headers, so 401/403 replies carry the headers too.
    app.add_middleware(TokenAuthMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    install_error_handlers(app)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.state.connector_roots = connector_roots_from_env()
    app.include_router(health.router)
    app.include_router(connector.router)

    return app


app = create_app()
