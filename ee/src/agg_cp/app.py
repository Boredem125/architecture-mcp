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
    public_url: str | None = None
    oidc_secrets_dir: str | None = None
    oidc_allow_hosts: str | None = None


def settings_from_env() -> Settings:
    """Build :class:`Settings` from environment variables.

    Reads ``AGG_DATABASE_URL`` or ``AGG_DATABASE_URL_FILE`` (the file
    is read once; useful for Docker secrets mounted as files), plus
    ``AGG_PUBLIC_URL``, ``AGG_OIDC_SECRETS_DIR`` and ``AGG_OIDC_ALLOW_HOSTS``
    (empty means unset).  Never called at import time.
    """
    url = os.environ.get("AGG_DATABASE_URL")
    if url is None:
        url_file = os.environ.get("AGG_DATABASE_URL_FILE")
        if url_file:
            url = Path(url_file).read_text(encoding="utf-8").strip()
    return Settings(
        db_url=url,
        public_url=os.environ.get("AGG_PUBLIC_URL") or None,
        oidc_secrets_dir=os.environ.get("AGG_OIDC_SECRETS_DIR") or None,
        oidc_allow_hosts=os.environ.get("AGG_OIDC_ALLOW_HOSTS") or None,
    )


def _default_oidc_http():
    """Real default oidc_http: httpx with follow_redirects=False, short timeout."""
    import httpx

    client = httpx.Client(follow_redirects=False, timeout=10.0)

    class _HttpxOidcHttp:
        def get_json(self, url: str) -> dict:
            resp = client.get(url)
            resp.raise_for_status()
            return resp.json()

        def post_form(self, url: str, data: dict) -> dict:
            resp = client.post(url, data=data)
            resp.raise_for_status()
            return resp.json()

    return _HttpxOidcHttp()


def create_app(
    *,
    db_url: str | None = None,
    settings: Settings | None = None,
    clock: object | None = None,
    oidc_http: object | None = None,
    resolve: object | None = None,
) -> FastAPI:
    """Build and return the control-plane FastAPI application.

    No module-level mutable state; every call returns a fresh app.
    The engine lifecycle is managed by the FastAPI lifespan context.

    T8P2 injection contract: ``clock``, ``oidc_http``, ``resolve``
    are passed through to the auth router.
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

    # Register auth routes if DB is configured
    if settings.db_url:
        from .clock import SystemClock

        actual_clock = clock if clock is not None else SystemClock()

        # Default oidc_http: httpx with follow_redirects=False and short timeout
        actual_oidc_http = oidc_http
        if actual_oidc_http is None:
            actual_oidc_http = _default_oidc_http()

        # Default resolve: socket.getaddrinfo
        actual_resolve = resolve
        if actual_resolve is None:
            import socket

            def _dns_resolve(host: str) -> list[str]:
                addrs = socket.getaddrinfo(host, None)
                return list({info[4][0] for info in addrs})

            actual_resolve = _dns_resolve

        allow_hosts = frozenset()
        if settings.oidc_allow_hosts:
            allow_hosts = frozenset(
                h.strip() for h in settings.oidc_allow_hosts.split(",") if h.strip()
            )

        from .auth import build_auth_router

        auth_router = build_auth_router(
            db_url=settings.db_url,
            clock=actual_clock,
            oidc_http=actual_oidc_http,
            resolve=actual_resolve,
            public_url=settings.public_url or "https://localhost",
            oidc_secrets_dir=settings.oidc_secrets_dir,
            oidc_allow_hosts=allow_hosts,
        )
        app.include_router(auth_router)

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
