from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check() -> dict:
    return {
        "status": "healthy",
        "service": "ai-agent-sandbox",
        "version": "1.0.0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/ready")
async def readiness_check() -> dict:
    checks = {
        "connector_routes": True,
    }
    all_ready = all(checks.values())
    return {
        "ready": all_ready,
        "checks": checks,
    }
