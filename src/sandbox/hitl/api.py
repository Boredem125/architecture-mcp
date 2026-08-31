"""FastAPI routes for the HITL reviewer web UI.

Exposes REST endpoints for listing pending reviews, submitting
approve/deny decisions, viewing queue stats, and listing active
reviewers.  All endpoints require authentication via the
:func:`get_current_reviewer` dependency.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from sandbox.hitl.queue import HITLQueue
from sandbox.hitl.reviewer import Reviewer, ReviewerRegistry, ReviewerRole
from sandbox.models.enums import HITLDecision, RiskTier
from sandbox.models.messages import HITLContextPackage, HITLResult

logger = structlog.get_logger(__name__)


# =====================================================================
# Deny reason codes — fixed list per spec
# =====================================================================


class DenyReasonCode(StrEnum):
    """Standardised denial reason codes for audit consistency."""

    POLICY_VIOLATION = "POLICY_VIOLATION"
    INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"
    SCOPE_EXCEEDED = "SCOPE_EXCEEDED"
    SUSPICIOUS_PATTERN = "SUSPICIOUS_PATTERN"
    MANUAL_OVERRIDE = "MANUAL_OVERRIDE"
    DATA_SAFETY = "DATA_SAFETY"
    UNAUTHORIZED_TARGET = "UNAUTHORIZED_TARGET"


# =====================================================================
# Request / response Pydantic models
# =====================================================================


class ApproveRequest(BaseModel):
    """Body for approving a pending HITL request."""

    reviewer_id: str = Field(..., min_length=1, description="ID of the approving reviewer")
    reason: str = Field(..., min_length=1, description="Justification for approval")


class DenyRequest(BaseModel):
    """Body for denying a pending HITL request."""

    reviewer_id: str = Field(..., min_length=1, description="ID of the denying reviewer")
    reason_code: DenyReasonCode = Field(..., description="Standardised denial reason code")


class PendingItemResponse(BaseModel):
    """Serialisation wrapper for a single pending review item."""

    request_id: str
    session_id: str
    agent_id: str
    action_type: str
    risk_tier: str
    escalation_reason: str
    timeout_at_utc: str
    reviewer_guidance: str

    @classmethod
    def from_context(cls, ctx: HITLContextPackage) -> PendingItemResponse:
        return cls(
            request_id=ctx.request_id,
            session_id=ctx.session_id,
            agent_id=ctx.agent_id,
            action_type=ctx.action_type,
            risk_tier=ctx.risk_tier,
            escalation_reason=ctx.escalation_reason,
            timeout_at_utc=ctx.timeout_at_utc,
            reviewer_guidance=ctx.reviewer_guidance,
        )


class PendingDetailResponse(BaseModel):
    """Full context package returned for a single pending request."""

    request_id: str
    session_id: str
    agent_id: str
    action_type: str
    risk_tier: str
    parameters: dict
    escalation_reason: str
    policy_decision: str
    content_safety_flags: list[str]
    anomaly_flags: list[str]
    session_history_summary: str
    timeout_at_utc: str
    reviewer_guidance: str

    @classmethod
    def from_context(cls, ctx: HITLContextPackage) -> PendingDetailResponse:
        return cls(
            request_id=ctx.request_id,
            session_id=ctx.session_id,
            agent_id=ctx.agent_id,
            action_type=ctx.action_type,
            risk_tier=ctx.risk_tier,
            parameters=ctx.parameters,
            escalation_reason=ctx.escalation_reason,
            policy_decision=ctx.policy_decision,
            content_safety_flags=ctx.content_safety_flags,
            anomaly_flags=ctx.anomaly_flags,
            session_history_summary=ctx.session_history_summary,
            timeout_at_utc=ctx.timeout_at_utc,
            reviewer_guidance=ctx.reviewer_guidance,
        )


class DecisionResponse(BaseModel):
    """Response after a reviewer submits a decision."""

    request_id: str
    decision: str
    reviewer_id: str | None
    reason: str


class QueueStatsResponse(BaseModel):
    """Queue statistics snapshot."""

    pending_count: int
    avg_wait_ms: float
    timeout_rate: float
    total_enqueued: int
    total_decided: int
    total_timeouts: int


class ReviewerResponse(BaseModel):
    """Public representation of a registered reviewer."""

    id: str
    name: str
    role: str
    is_active: bool
    mfa_verified: bool


# =====================================================================
# Dependency: authentication placeholder
# =====================================================================


async def get_current_reviewer() -> str:
    """Authenticate the current request and return the reviewer ID.

    .. note::

        This is a placeholder dependency.  In production, replace with
        JWT/OAuth2 token validation that extracts the reviewer identity
        from the ``Authorization`` header.
    """
    # TODO: Implement real authentication (JWT/OAuth2).
    # For now, every request is treated as authenticated.  The actual
    # reviewer_id comes from the request body for decision endpoints.
    return "authenticated"


CurrentReviewer = Annotated[str, Depends(get_current_reviewer)]


# =====================================================================
# Shared state — injected at app startup
# =====================================================================

# These are module-level singletons wired by the application factory.
# In production, use FastAPI's dependency injection or a proper DI
# container.  Set them before including the router.
_queue: HITLQueue | None = None
_registry: ReviewerRegistry | None = None


def configure(queue: HITLQueue, registry: ReviewerRegistry) -> None:
    """Wire shared dependencies for the HITL API routes.

    Must be called before the first request is served.

    Args:
        queue: The HITL review queue instance.
        registry: The reviewer registry instance.
    """
    global _queue, _registry  # noqa: PLW0603
    _queue = queue
    _registry = registry


def _get_queue() -> HITLQueue:
    if _queue is None:
        raise RuntimeError("HITLQueue not configured — call hitl.api.configure() first")
    return _queue


def _get_registry() -> ReviewerRegistry:
    if _registry is None:
        raise RuntimeError(
            "ReviewerRegistry not configured — call hitl.api.configure() first"
        )
    return _registry


# =====================================================================
# Router
# =====================================================================

router = APIRouter(prefix="/api/v1/hitl", tags=["hitl"])


@router.get(
    "/pending",
    response_model=list[PendingItemResponse],
    summary="List pending review requests",
)
async def list_pending(
    _reviewer: CurrentReviewer,
) -> list[PendingItemResponse]:
    """Return all items currently in the HITL review queue."""
    queue = _get_queue()
    items = await queue.peek()
    return [PendingItemResponse.from_context(item) for item in items]


@router.get(
    "/pending/{request_id}",
    response_model=PendingDetailResponse,
    summary="Get a specific pending request with full context",
)
async def get_pending_detail(
    request_id: str,
    _reviewer: CurrentReviewer,
) -> PendingDetailResponse:
    """Return the full context package for a single pending request."""
    queue = _get_queue()
    items = await queue.peek()

    for item in items:
        if item.request_id == request_id:
            return PendingDetailResponse.from_context(item)

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Pending request {request_id!r} not found",
    )


@router.post(
    "/pending/{request_id}/approve",
    response_model=DecisionResponse,
    summary="Approve a pending request",
)
async def approve_request(
    request_id: str,
    body: ApproveRequest,
    _reviewer: CurrentReviewer,
) -> DecisionResponse:
    """Approve a pending HITL request with a required justification."""
    queue = _get_queue()
    registry = _get_registry()

    # Verify the reviewer exists and is qualified.
    reviewer = registry.get(body.reviewer_id)
    if reviewer is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Reviewer {body.reviewer_id!r} not registered",
        )
    if not reviewer.is_active or not reviewer.mfa_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Reviewer is not active or MFA not verified",
        )

    try:
        result = await queue.submit_decision(
            request_id=request_id,
            decision=HITLDecision.APPROVE,
            reviewer_id=body.reviewer_id,
            reason=body.reason,
        )
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Pending request {request_id!r} not found",
        )

    logger.info(
        "hitl_api.approved",
        request_id=request_id,
        reviewer_id=body.reviewer_id,
    )
    return DecisionResponse(
        request_id=result.request_id,
        decision=result.decision,
        reviewer_id=result.reviewer_id,
        reason=result.reason,
    )


@router.post(
    "/pending/{request_id}/deny",
    response_model=DecisionResponse,
    summary="Deny a pending request",
)
async def deny_request(
    request_id: str,
    body: DenyRequest,
    _reviewer: CurrentReviewer,
) -> DecisionResponse:
    """Deny a pending HITL request with a standardised reason code."""
    queue = _get_queue()
    registry = _get_registry()

    reviewer = registry.get(body.reviewer_id)
    if reviewer is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Reviewer {body.reviewer_id!r} not registered",
        )
    if not reviewer.is_active or not reviewer.mfa_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Reviewer is not active or MFA not verified",
        )

    try:
        result = await queue.submit_decision(
            request_id=request_id,
            decision=HITLDecision.DENY,
            reviewer_id=body.reviewer_id,
            reason=f"[{body.reason_code}]",
        )
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Pending request {request_id!r} not found",
        )

    logger.info(
        "hitl_api.denied",
        request_id=request_id,
        reviewer_id=body.reviewer_id,
        reason_code=body.reason_code,
    )
    return DecisionResponse(
        request_id=result.request_id,
        decision=result.decision,
        reviewer_id=result.reviewer_id,
        reason=result.reason,
    )


@router.get(
    "/stats",
    response_model=QueueStatsResponse,
    summary="Queue statistics",
)
async def get_stats(
    _reviewer: CurrentReviewer,
) -> QueueStatsResponse:
    """Return current queue statistics: pending count, avg wait, timeout rate."""
    queue = _get_queue()
    stats = await queue.get_stats()
    return QueueStatsResponse(**stats)


@router.get(
    "/reviewers",
    response_model=list[ReviewerResponse],
    summary="List active reviewers",
)
async def list_reviewers(
    _reviewer: CurrentReviewer,
) -> list[ReviewerResponse]:
    """Return all reviewers currently on duty."""
    registry = _get_registry()
    on_duty = registry.get_on_duty()
    return [
        ReviewerResponse(
            id=r.id,
            name=r.name,
            role=r.role,
            is_active=r.is_active,
            mfa_verified=r.mfa_verified,
        )
        for r in on_duty
    ]
