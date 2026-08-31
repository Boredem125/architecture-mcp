"""OPA HTTP client for policy evaluation.

Wraps the Open Policy Agent REST API to evaluate Rego policies
for session scope, action scope, temporal scope, blast-radius
limits, and reversibility escalation.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from sandbox.models.enums import PolicyDecision
from sandbox.models.messages import PolicyResult

logger = logging.getLogger(__name__)


class OPAClient:
    """Async client for Open Policy Agent policy evaluation.

    All evaluation methods follow a fail-closed pattern: if OPA is
    unreachable or returns an unexpected response, the decision
    defaults to DENY.
    """

    def __init__(self, base_url: str = "http://localhost:8181") -> None:
        self._base_url = base_url.rstrip("/")
        self._http = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(5.0, connect=3.0),
        )

    # ------------------------------------------------------------------
    # Low-level evaluation
    # ------------------------------------------------------------------

    async def evaluate(self, policy_path: str, input_data: dict[str, Any]) -> dict[str, Any]:
        """POST to ``/v1/data/{policy_path}`` and return the ``result`` dict.

        Raises :class:`OPAEvaluationError` on transport or protocol failures
        so callers can distinguish "policy said no" from "OPA is down".
        """
        url = f"/v1/data/{policy_path.strip('/')}"
        try:
            response = await self._http.post(url, json={"input": input_data})
            response.raise_for_status()
            body = response.json()
            return body.get("result", {})
        except (httpx.HTTPError, httpx.InvalidURL, KeyError, ValueError) as exc:
            logger.error("OPA evaluation failed for %s: %s", policy_path, exc)
            raise OPAEvaluationError(policy_path, exc) from exc

    # ------------------------------------------------------------------
    # High-level policy checks
    # ------------------------------------------------------------------

    async def check_session_scope(
        self,
        enriched_request: dict[str, Any],
        session: dict[str, Any],
    ) -> PolicyResult:
        """Evaluate ``sandbox/session_scope`` -- is the intent allowed?"""
        input_data = {**enriched_request, "session": session}
        return await self._eval_allow(
            policy_path="sandbox/session_scope",
            input_data=input_data,
            request_id=enriched_request.get("request_id", ""),
            rule_name="session_scope",
        )

    async def check_action_scope(
        self,
        enriched_request: dict[str, Any],
        session: dict[str, Any],
    ) -> PolicyResult:
        """Evaluate ``sandbox/action_scope`` -- is the resource in scope?"""
        input_data = {**enriched_request, "session": session}
        return await self._eval_allow(
            policy_path="sandbox/action_scope",
            input_data=input_data,
            request_id=enriched_request.get("request_id", ""),
            rule_name="action_scope",
        )

    async def check_temporal_scope(self, session: dict[str, Any]) -> PolicyResult:
        """Evaluate ``sandbox/temporal_scope`` -- is the session still valid?"""
        input_data = {"session": session}
        return await self._eval_allow(
            policy_path="sandbox/temporal_scope",
            input_data=input_data,
            request_id=session.get("session_id", ""),
            rule_name="temporal_scope",
        )

    async def check_blast_radius(self, session: dict[str, Any]) -> PolicyResult:
        """Evaluate ``sandbox/blast_radius`` -- are limits exceeded?

        The blast_radius policy uses a ``deny`` rule (true when limits are
        breached), so the logic is inverted compared to the ``allow`` policies.
        """
        input_data = {"session": session}
        request_id = session.get("session_id", "")
        try:
            result = await self.evaluate("sandbox/blast_radius", input_data)
            denied = result.get("deny", False)
            if denied:
                return PolicyResult(
                    request_id=request_id,
                    decision=PolicyDecision.DENY,
                    matched_rule="blast_radius",
                    reason="Session resource limits exceeded",
                )
            return PolicyResult(
                request_id=request_id,
                decision=PolicyDecision.ALLOW,
                matched_rule="blast_radius",
            )
        except OPAEvaluationError as exc:
            return self._deny_on_error(request_id, "blast_radius", exc)

    async def check_reversibility(
        self,
        enriched_request: dict[str, Any],
    ) -> PolicyResult:
        """Evaluate ``sandbox/reversibility`` -- should this escalate?

        Returns ESCALATE when the action is irreversible and needs
        human-in-the-loop approval; ALLOW otherwise.
        """
        request_id = enriched_request.get("request_id", "")
        try:
            result = await self.evaluate("sandbox/reversibility", enriched_request)
            should_escalate = result.get("escalate", False)
            if should_escalate:
                return PolicyResult(
                    request_id=request_id,
                    decision=PolicyDecision.ESCALATE,
                    matched_rule="reversibility",
                    reason="Action is irreversible or destructive; human approval required",
                )
            return PolicyResult(
                request_id=request_id,
                decision=PolicyDecision.ALLOW,
                matched_rule="reversibility",
            )
        except OPAEvaluationError as exc:
            return self._deny_on_error(request_id, "reversibility", exc)

    # ------------------------------------------------------------------
    # Composite evaluation
    # ------------------------------------------------------------------

    async def evaluate_all(
        self,
        enriched_request: dict[str, Any],
        session: dict[str, Any],
    ) -> PolicyResult:
        """Run every policy check in sequence.

        Returns the first DENY or ESCALATE encountered, or ALLOW if
        every check passes.  Checks execute in the following order:

        1. temporal_scope  -- reject expired sessions immediately
        2. blast_radius    -- reject over-limit sessions
        3. session_scope   -- verify intent is permitted
        4. action_scope    -- verify resource is in scope
        5. reversibility   -- flag irreversible actions for HITL
        """
        checks: list[PolicyResult] = [
            await self.check_temporal_scope(session),
            await self.check_blast_radius(session),
            await self.check_session_scope(enriched_request, session),
            await self.check_action_scope(enriched_request, session),
            await self.check_reversibility(enriched_request),
        ]

        for result in checks:
            if result.decision != PolicyDecision.ALLOW:
                return result

        return PolicyResult(
            request_id=enriched_request.get("request_id", ""),
            decision=PolicyDecision.ALLOW,
            matched_rule="all_passed",
            reason="All policy checks passed",
        )

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    async def health_check(self) -> bool:
        """Return ``True`` if OPA is reachable and healthy."""
        try:
            response = await self._http.get("/health")
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Shut down the underlying HTTP client."""
        await self._http.aclose()

    async def __aenter__(self) -> OPAClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _eval_allow(
        self,
        policy_path: str,
        input_data: dict[str, Any],
        request_id: str,
        rule_name: str,
    ) -> PolicyResult:
        """Evaluate an ``allow``-based policy and return a PolicyResult."""
        try:
            result = await self.evaluate(policy_path, input_data)
            allowed = result.get("allow", False)
            if allowed:
                return PolicyResult(
                    request_id=request_id,
                    decision=PolicyDecision.ALLOW,
                    matched_rule=rule_name,
                )
            return PolicyResult(
                request_id=request_id,
                decision=PolicyDecision.DENY,
                matched_rule=rule_name,
                reason=f"Policy '{rule_name}' denied the request",
            )
        except OPAEvaluationError as exc:
            return self._deny_on_error(request_id, rule_name, exc)

    @staticmethod
    def _deny_on_error(
        request_id: str,
        rule_name: str,
        exc: Exception,
    ) -> PolicyResult:
        """Fail closed: OPA unreachable => DENY."""
        logger.warning(
            "Failing closed for rule %s due to OPA error: %s",
            rule_name,
            exc,
        )
        return PolicyResult(
            request_id=request_id,
            decision=PolicyDecision.DENY,
            matched_rule=rule_name,
            reason=f"OPA unreachable or error during '{rule_name}' evaluation",
        )


class OPAEvaluationError(Exception):
    """Raised when an OPA evaluation request fails at the transport or protocol level."""

    def __init__(self, policy_path: str, cause: Exception) -> None:
        self.policy_path = policy_path
        self.cause = cause
        super().__init__(f"OPA evaluation failed for '{policy_path}': {cause}")
