"""Reviewer management for HITL review workflow.

Tracks registered human reviewers, their qualification tiers, duty
status, and MFA verification.  The :class:`ReviewerRegistry` maps
:class:`~sandbox.models.enums.RiskTier` levels to the minimum
:class:`ReviewerRole` required to adjudicate a request.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

import structlog

from sandbox.models.enums import RiskTier

logger = structlog.get_logger(__name__)


class ReviewerRole(StrEnum):
    """Reviewer privilege tiers (ascending authority)."""

    L1 = "L1"
    L2 = "L2"
    ADMIN = "ADMIN"


# Mapping from role to numeric rank for comparison.
_ROLE_RANK: dict[ReviewerRole, int] = {
    ReviewerRole.L1: 1,
    ReviewerRole.L2: 2,
    ReviewerRole.ADMIN: 3,
}


@dataclass
class Reviewer:
    """A registered human reviewer.

    Attributes:
        id: Unique reviewer identifier.
        name: Display name.
        role: Qualification tier.
        is_active: Whether the reviewer is currently on duty.
        mfa_verified: Whether MFA has been verified this session.
    """

    id: str
    name: str
    role: ReviewerRole
    is_active: bool = True
    mfa_verified: bool = False


class ReviewerRegistry:
    """In-memory registry of HITL reviewers.

    Manages reviewer registration, qualification lookups by risk tier,
    and duty-status queries.

    Qualification rules per AGENT_05 spec:
    - **HIGH** risk: L1 or above
    - **CRITICAL** risk: L2 or above
    - **CRITICAL + irreversible** (proxied as ADMIN-only): ADMIN only
    """

    def __init__(self) -> None:
        self._reviewers: dict[str, Reviewer] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, reviewer: Reviewer) -> None:
        """Add or update a reviewer in the registry.

        Args:
            reviewer: The reviewer to register.
        """
        self._reviewers[reviewer.id] = reviewer
        logger.info(
            "reviewer_registry.registered",
            reviewer_id=reviewer.id,
            role=reviewer.role,
            is_active=reviewer.is_active,
        )

    def unregister(self, reviewer_id: str) -> None:
        """Remove a reviewer from the registry.

        Args:
            reviewer_id: ID of the reviewer to remove.

        Raises:
            KeyError: If the reviewer is not registered.
        """
        if reviewer_id not in self._reviewers:
            raise KeyError(f"Reviewer {reviewer_id!r} not found")
        del self._reviewers[reviewer_id]
        logger.info("reviewer_registry.unregistered", reviewer_id=reviewer_id)

    # ------------------------------------------------------------------
    # Qualification queries
    # ------------------------------------------------------------------

    def get_qualified(self, risk_tier: RiskTier) -> list[Reviewer]:
        """Return reviewers qualified to adjudicate a given risk tier.

        Qualification mapping:
        - ``HIGH``: L1 and above
        - ``CRITICAL``: L2 and above
        - ``CRITICAL`` + irreversible escalation: ADMIN only (callers
          should pass ``RiskTier.CRITICAL`` and filter by role if the
          action is irreversible, or simply check for ADMIN availability)

        For ``LOW`` and ``MEDIUM`` tiers (which normally do not require
        HITL review), all active reviewers are returned.

        Args:
            risk_tier: The risk classification of the pending action.

        Returns:
            List of active, MFA-verified reviewers meeting the minimum
            role requirement.
        """
        min_role = self._min_role_for_tier(risk_tier)
        min_rank = _ROLE_RANK[min_role]

        qualified = [
            r
            for r in self._reviewers.values()
            if (
                r.is_active
                and r.mfa_verified
                and _ROLE_RANK[r.role] >= min_rank
            )
        ]

        logger.debug(
            "reviewer_registry.get_qualified",
            risk_tier=risk_tier,
            min_role=min_role,
            found=len(qualified),
        )
        return qualified

    def get_on_duty(self) -> list[Reviewer]:
        """Return all reviewers currently marked as active.

        Returns:
            List of active reviewers regardless of MFA status.
        """
        return [r for r in self._reviewers.values() if r.is_active]

    def is_available(self) -> bool:
        """Check whether any qualified, MFA-verified reviewer is on duty.

        Returns:
            ``True`` if at least one active, MFA-verified reviewer
            exists in the registry.
        """
        return any(
            r.is_active and r.mfa_verified for r in self._reviewers.values()
        )

    # ------------------------------------------------------------------
    # Lookup helpers
    # ------------------------------------------------------------------

    def get(self, reviewer_id: str) -> Reviewer | None:
        """Retrieve a reviewer by ID, or ``None`` if not found."""
        return self._reviewers.get(reviewer_id)

    def all(self) -> list[Reviewer]:
        """Return every registered reviewer."""
        return list(self._reviewers.values())

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _min_role_for_tier(risk_tier: RiskTier) -> ReviewerRole:
        """Determine the minimum reviewer role for a risk tier."""
        match risk_tier:
            case RiskTier.CRITICAL:
                return ReviewerRole.L2
            case RiskTier.HIGH:
                return ReviewerRole.L1
            case _:
                # LOW / MEDIUM do not normally require HITL; any role
                # suffices if the pipeline escalates anyway.
                return ReviewerRole.L1
