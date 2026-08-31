"""NATS subject definitions for the agent sandbox pipeline.

Every inter-agent communication channel is defined here as a class-level
constant so that subject strings are never scattered as magic literals
across the codebase.
"""

from __future__ import annotations


class Subjects:
    """Canonical NATS subject constants for the sandbox pipeline."""

    # --- Pipeline flow (Zone 1 → Zone 2 → back) ---

    REQUEST_QUEUE: str = "sandbox.pipeline.requests"
    """Zone 1 task-agent requests entering the sandbox pipeline."""

    ENRICHED_REQUEST: str = "sandbox.pipeline.enriched"
    """Request evaluator → policy engine (classified & enriched)."""

    POLICY_RESULT: str = "sandbox.pipeline.policy"
    """Policy engine → content safety or HITL."""

    CONTENT_SAFETY: str = "sandbox.pipeline.content_safety"
    """Content safety scanner decisions."""

    HITL_QUEUE: str = "sandbox.pipeline.hitl"
    """Escalations requiring human-in-the-loop review."""

    HITL_RESULT: str = "sandbox.pipeline.hitl_result"
    """HITL reviewer decisions flowing back into the pipeline."""

    COMMAND_SIGN: str = "sandbox.pipeline.sign"
    """Approved commands awaiting cryptographic signing."""

    SIGNED_COMMAND: str = "sandbox.pipeline.signed"
    """Signed commands ready for the executor agent."""

    SNAPSHOT_REQUEST: str = "sandbox.pipeline.snapshot_request"
    """Pre-execution snapshot requests to the rollback agent."""

    SNAPSHOT_CONFIRM: str = "sandbox.pipeline.snapshot_confirm"
    """Rollback agent confirms snapshot → executor may proceed."""

    EXECUTION_RESULT: str = "sandbox.pipeline.execution"
    """Executor output awaiting content safety scrubbing."""

    SCRUBBED_OUTPUT: str = "sandbox.pipeline.scrubbed"
    """Scrubbed execution output heading to the result queue."""

    RESULT_QUEUE: str = "sandbox.pipeline.results"
    """Final results returned to the task agent in Zone 1."""

    # --- Audit ---

    AUDIT_STREAM: str = "sandbox.audit.fragments"
    """Every pipeline step publishes an audit fragment here."""

    # --- Anomaly detection ---

    ANOMALY_EVENTS: str = "sandbox.anomaly.events"
    """Pipeline events consumed by the anomaly detector."""

    ANOMALY_SIGNALS: str = "sandbox.anomaly.signals"
    """Anomaly detector alerts fed back into the pipeline."""

    # --- Session lifecycle ---

    KILL_SWITCH: str = "sandbox.session.kill"
    """Emergency session termination (anomaly → session manager)."""

    SESSION_EVENTS: str = "sandbox.session.events"
    """Session lifecycle events (created, extended, terminated)."""

    # --- Rollback ---

    ROLLBACK_TRIGGER: str = "sandbox.rollback.trigger"
    """On-demand rollback trigger."""

    ROLLBACK_RESULT: str = "sandbox.rollback.result"
    """Outcome of a rollback operation."""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def agent_inbox(agent_name: str) -> str:
        """Return the direct inbox subject for a named agent.

        Args:
            agent_name: Logical agent identifier (e.g. ``"request-evaluator"``).

        Returns:
            A subject of the form ``sandbox.agent.<agent_name>.inbox``.
        """
        return f"sandbox.agent.{agent_name}.inbox"
