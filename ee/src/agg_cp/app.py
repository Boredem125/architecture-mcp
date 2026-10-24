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
    # DB pool settings (env: AGG_DB_POOL_SIZE, AGG_DB_MAX_OVERFLOW, etc.)
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_pool_pre_ping: bool = True
    db_pool_recycle: int = 3600


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
        db_pool_size=int(os.environ.get("AGG_DB_POOL_SIZE", "5")),
        db_max_overflow=int(os.environ.get("AGG_DB_MAX_OVERFLOW", "10")),
        db_pool_pre_ping=os.environ.get("AGG_DB_POOL_PRE_PING", "true").lower()
        in ("true", "1", "yes"),
        db_pool_recycle=int(os.environ.get("AGG_DB_POOL_RECYCLE", "3600")),
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
    database_url: str | None = None,
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
    # Accept both db_url and database_url (alias)
    effective_db_url = db_url or database_url
    if settings is None:
        if effective_db_url is not None:
            settings = Settings(db_url=effective_db_url)
        else:
            settings = settings_from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if settings.db_url:
            from .db import make_engine

            app.state.engine = make_engine(
                settings.db_url,
                pool_size=settings.db_pool_size,
                max_overflow=settings.db_max_overflow,
                pool_pre_ping=settings.db_pool_pre_ping,
                pool_recycle=settings.db_pool_recycle,
            )

        # Start periodic device_silent sweep (T11, ruling 4)
        sweep_task = None
        if settings.db_url:
            import asyncio

            async def _sweep_loop():
                """Run sweep_all_orgs every 60 s.

                Uses its own short-lived psycopg connection as agg_app.
                ``sweep_all_orgs`` iterates orgs via the SECURITY DEFINER
                ``sweep_org_ids()`` and sets ``app.org_id`` per org.
                Errors are logged and swallowed so the task never dies.

                The sync DB work runs in a thread via
                ``asyncio.to_thread`` so the event loop stays
                responsive for incoming HTTP requests.
                """
                import datetime as dt
                import logging
                import psycopg

                _log = logging.getLogger("agg_cp.sweep")
                conninfo = settings.db_url.replace("+psycopg", "")

                def _do_sweep():
                    from .sync.audit import sweep_all_orgs
                    with psycopg.connect(conninfo) as conn:
                        conn.execute("SET ROLE agg_app")
                        now = dt.datetime.now(dt.timezone.utc)
                        sweep_all_orgs(conn, now)
                        conn.commit()

                while True:
                    try:
                        await asyncio.sleep(60)
                    except asyncio.CancelledError:
                        return
                    try:
                        await asyncio.to_thread(_do_sweep)
                    except asyncio.CancelledError:
                        return
                    except Exception:
                        _log.exception("sweep_all_orgs error")

            sweep_task = asyncio.create_task(_sweep_loop())
            app.state.sweep_task = sweep_task

        yield

        # Cancel the sweep task cleanly on shutdown
        if sweep_task is not None:
            sweep_task.cancel()
            import asyncio
            try:
                await sweep_task
            except asyncio.CancelledError:
                pass

        engine = getattr(app.state, "engine", None)
        if engine is not None:
            await engine.dispose()

    app = FastAPI(
        title="Agent Governance Gateway - Control Plane",
        openapi_url=None,
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
        # Add routes directly so they appear as top-level APIRoute
        # objects on app.routes (FastAPI 0.154+ wraps include_router
        # in _IncludedRouter which hides routes from introspection).
        for _r in auth_router.routes:
            app.router.routes.append(_r)

        from .api import build_api_router

        api_router = build_api_router(db_url=settings.db_url, clock=actual_clock)
        for _r in api_router.routes:
            app.router.routes.append(_r)

        from .sync.enroll import enroll_router

        _enroll_r = enroll_router(db_url=settings.db_url, clock=actual_clock)
        for _r in _enroll_r.routes:
            app.router.routes.append(_r)

        from .sync.signer import build_signer_router

        _signer_r = build_signer_router(
            db_url=settings.db_url, clock=actual_clock
        )
        for _r in _signer_r.routes:
            app.router.routes.append(_r)

        from .sync.bundles import bundle_router

        _bundle_r = bundle_router(
            db_url=settings.db_url, clock=actual_clock
        )
        for _r in _bundle_r.routes:
            app.router.routes.append(_r)

        from .sync.audit_upload import audit_upload_router

        _audit_r = audit_upload_router(
            db_url=settings.db_url, clock=actual_clock
        )
        for _r in _audit_r.routes:
            app.router.routes.append(_r)

        from .sync.escalations import escalation_router

        _esc_r = escalation_router(
            db_url=settings.db_url, clock=actual_clock
        )
        for _r in _esc_r.routes:
            app.router.routes.append(_r)

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
