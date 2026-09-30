from __future__ import annotations

# FastAPI application entry point for the AI Agent Sandbox Security System
from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sandbox.api.auth import TokenAuthMiddleware, ensure_tokens
from sandbox.api.routes import agent_runtime, agents, audit, connector, dashboard, e2b, health, hitl, hook, launcher, policies, requests, security, sessions
from sandbox.api.websocket import broadcaster, router as ws_router
from sandbox.agents.runtime import AgentRuntime
from sandbox.broker.privilege_broker import PrivilegeBroker
from sandbox.config import SandboxConfig
from sandbox.crypto.tokens import TokenIssuer
from sandbox.hitl.memory_orchestrator import MemoryHITLOrchestrator
from sandbox.launcher.launcher import AppLauncher
from sandbox.launcher.recorder import SessionRecorder
from sandbox.pipeline.session_manager import SessionManager
from sandbox.translate.translator import ActionTranslator

logger = structlog.get_logger()

_config: SandboxConfig | None = None
_session_manager: SessionManager | None = None
_agent_runtime: AgentRuntime | None = None
_launcher: AppLauncher | None = None
_broker: PrivilegeBroker | None = None
_memory_hitl: MemoryHITLOrchestrator | None = None
_translator: ActionTranslator | None = None


def get_config() -> SandboxConfig:
    """Lazy-load configuration singleton."""
    global _config
    if _config is None:
        _config = SandboxConfig()
    return _config


def get_session_manager() -> SessionManager:
    """Lazy-load session manager singleton."""
    global _session_manager
    if _session_manager is None:
        config = get_config()
        token_issuer = TokenIssuer()
        _session_manager = SessionManager(token_issuer, config.session)
    return _session_manager


def get_agent_runtime() -> AgentRuntime:
    """Lazy-load agent runtime singleton with event broadcaster."""
    global _agent_runtime
    if _agent_runtime is None:
        config = get_config()
        _agent_runtime = AgentRuntime(
            session_manager=get_session_manager(),
            event_broadcaster=broadcaster,
            containment_settings=config.containment,
            executor_settings=config.executor,
        )
    return _agent_runtime


def get_memory_hitl() -> MemoryHITLOrchestrator:
    global _memory_hitl
    if _memory_hitl is None:
        config = get_config()
        _memory_hitl = MemoryHITLOrchestrator(
            broadcaster=broadcaster,
            default_timeout=config.hitl.critical_timeout_seconds,
        )
    return _memory_hitl


def get_broker() -> PrivilegeBroker:
    global _broker
    if _broker is None:
        _broker = PrivilegeBroker(
            broadcaster=broadcaster,
            timeout_seconds=get_config().hitl.critical_timeout_seconds,
        )
    return _broker


def get_launcher() -> AppLauncher:
    global _launcher
    if _launcher is None:
        config = get_config()
        _launcher = AppLauncher(
            settings=config.launcher,
            broadcaster=broadcaster,
        )
    return _launcher


def get_translator() -> ActionTranslator:
    global _translator
    if _translator is None:
        _translator = ActionTranslator(get_config().translate)
    return _translator


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


def create_app(config: SandboxConfig | None = None) -> FastAPI:
    global _config
    if config is not None:
        _config = config

    app = FastAPI(
        title="AI Agent Sandbox Security System",
        description=(
            "Enterprise-grade 3-zone, 9-agent containment pipeline for AI agent security. "
            "Deny-by-default policy enforcement, HITL gates, anomaly detection, "
            "immutable audit logging, and rollback capabilities."
        ),
        version="1.0.0",
        lifespan=lifespan,
    )

    ensure_tokens()
    app.add_middleware(TokenAuthMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router)
    app.include_router(sessions.router)
    app.include_router(requests.router)
    app.include_router(hitl.router)
    app.include_router(audit.router)
    app.include_router(agents.router)
    app.include_router(policies.router)
    app.include_router(security.router)
    app.include_router(dashboard.router)
    app.include_router(agent_runtime.router)
    app.include_router(hook.router)
    app.include_router(e2b.router)
    app.include_router(launcher.router)
    app.include_router(connector.router)
    app.include_router(ws_router)

    app.state.event_broadcaster = broadcaster

    return app


app = create_app()
