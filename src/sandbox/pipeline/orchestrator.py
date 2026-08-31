from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from sandbox.models.enums import (
    ActionType,
    ContentDecision,
    ExecutionResult,
    HITLDecision,
    PolicyDecision,
    RiskTier,
)
from sandbox.models.audit import AuditFragment, AuditRecord
from sandbox.models.messages import (
    ActionRequest,
    ContentSafetyResult,
    EnrichedRequest,
    ExecutionOutput,
    HITLContextPackage,
    HITLResult,
    PipelineStatus,
    PolicyResult,
    ScrubbedOutput,
    SignedCommand,
    SnapshotRecord,
)
from sandbox.models.session import SessionState
from sandbox.pipeline.session_manager import SessionManager

logger = structlog.get_logger()


class PipelineOrchestrator:
    """Routes requests through the 8-step mediation pipeline.

    Step 1-2: Request Evaluator (schema + intent classification)
    Step 3:   Policy Engine (OPA deny-by-default)
    Step 4:   Content Safety (injection + secret scan)
    Step 5:   HITL Gate (conditional, for CRITICAL tier)
    Step 6:   Command Signing
    Step 7:   Execution (Zone 3) with pre-snapshot
    Step 8:   Audit Log Write
    """

    def __init__(
        self,
        session_manager: SessionManager,
        request_evaluator: Any = None,
        policy_engine: Any = None,
        content_safety: Any = None,
        hitl_orchestrator: Any = None,
        anomaly_detector: Any = None,
        audit_agent: Any = None,
        rollback_agent: Any = None,
        executor: Any = None,
        command_signer: Any = None,
        event_broadcaster: Any = None,
    ) -> None:
        self._session_manager = session_manager
        self._request_evaluator = request_evaluator
        self._policy_engine = policy_engine
        self._content_safety = content_safety
        self._hitl_orchestrator = hitl_orchestrator
        self._anomaly_detector = anomaly_detector
        self._audit_agent = audit_agent
        self._rollback_agent = rollback_agent
        self._executor = executor
        self._command_signer = command_signer
        self._event_broadcaster = event_broadcaster
        self._audit_fragments: dict[str, list[AuditFragment]] = {}

    async def process_request(
        self,
        request: ActionRequest,
        session: SessionState,
    ) -> PipelineStatus:
        """Run a request through the full pipeline. Returns final status."""
        request_id = request.request_id
        session_id = session.session_id
        start_time = time.monotonic()
        self._audit_fragments[request_id] = []

        status = PipelineStatus(
            request_id=request_id,
            session_id=session_id,
            status="PROCESSING",
        )

        try:
            await self._emit("pipeline_start", request_id, session_id,
                             action_type=request.action_type.value,
                             agent_id=session.agent_id)

            # --- Step 0: Session validation ---
            valid, reason = self._session_manager.validate_session(session_id)
            if not valid:
                await self._emit("step_failed", request_id, session_id, step=0, step_name="session_validation", reason=reason)
                return self._halt(status, 0, "session_validation", reason, start_time)

            token_valid, token_reason = self._session_manager.validate_token(
                session_id, request.session_token
            )
            if not token_valid:
                await self._emit("step_failed", request_id, session_id, step=0, step_name="token_validation", reason=token_reason)
                return self._halt(status, 0, "token_validation", token_reason, start_time)
            await self._emit("step_completed", request_id, session_id, step=0, step_name="session_validation", result="VALID")

            # --- Steps 1-2: Request Evaluator ---
            enriched = await self._step_evaluate(request, session, request_id, session_id)
            if enriched is None:
                await self._emit("step_failed", request_id, session_id, step=2, step_name="request_evaluator", reason="SCHEMA_INVALID")
                return self._halt(status, 2, "request_evaluator", "SCHEMA_INVALID", start_time)
            await self._emit("step_completed", request_id, session_id, step=2, step_name="request_evaluator",
                             risk_tier=enriched.risk_tier.value, intent=enriched.intent_class.value)

            # Notify anomaly detector (async, non-blocking)
            await self._notify_anomaly(enriched, session)

            # --- Step 3: Policy Engine ---
            policy_result = await self._step_policy(enriched, session, request_id, session_id)
            await self._emit("step_completed", request_id, session_id, step=3, step_name="policy_engine",
                             decision=policy_result.decision.value, reason=policy_result.reason or "")
            if policy_result.decision == PolicyDecision.DENY:
                session.deny_count += 1
                return self._deny(status, 3, "policy_engine", policy_result.reason, start_time)

            # --- Step 5: HITL Gate (if ESCALATE or CRITICAL) ---
            if (
                policy_result.decision == PolicyDecision.ESCALATE
                or enriched.risk_tier == RiskTier.CRITICAL
            ):
                await self._emit("hitl_required", request_id, session_id, risk_tier=enriched.risk_tier.value, agent_id=session.agent_id)
                hitl_result = await self._step_hitl(enriched, session, policy_result, request_id, session_id)
                await self._emit("step_completed", request_id, session_id, step=5, step_name="hitl_gate",
                                 decision=hitl_result.decision.value)
                if hitl_result.decision != HITLDecision.APPROVE:
                    session.deny_count += 1
                    session.hitl_count += 1
                    return self._deny(
                        status, 5, "hitl_gate",
                        f"HITL_{hitl_result.decision.value}: {hitl_result.reason}",
                        start_time,
                    )
                session.hitl_count += 1

            # --- Step 4: Content Safety (inbound scan) ---
            safety_result = await self._step_content_safety_inbound(
                enriched, request_id, session_id
            )
            await self._emit("step_completed", request_id, session_id, step=4, step_name="content_safety",
                             decision=safety_result.decision.value)
            if safety_result.decision == ContentDecision.BLOCK:
                return self._deny(status, 4, "content_safety", safety_result.reason, start_time)

            # --- Step 6: Command Signing ---
            signed_cmd = await self._step_sign_command(enriched, session, request_id, session_id)
            await self._emit("step_completed", request_id, session_id, step=6, step_name="command_signing",
                             command_hash=signed_cmd.command_hash[:16])

            # --- Pre-step 7: Rollback snapshot ---
            snapshot = None
            if enriched.action_type in (ActionType.WRITE, ActionType.EXECUTE):
                snapshot = await self._step_snapshot(enriched, session, request_id, session_id)
                if snapshot is None:
                    await self._emit("step_failed", request_id, session_id, step=7, step_name="rollback_snapshot", reason="SNAPSHOT_FAILED")
                    return self._halt(
                        status, 7, "rollback_snapshot", "SNAPSHOT_FAILED", start_time
                    )
                await self._emit("step_completed", request_id, session_id, step=7, step_name="rollback_snapshot",
                                 snapshot_id=snapshot.snapshot_id)

            # --- Step 7: Execution (Zone 3) ---
            exec_output = await self._step_execute(signed_cmd, request_id, session_id)
            await self._emit("step_completed", request_id, session_id, step=7, step_name="execution",
                             result=exec_output.result.value)

            # --- Post-step 7: Content Safety (output scrub) ---
            scrubbed = await self._step_content_safety_outbound(
                exec_output, request_id, session_id
            )

            # Update session counters
            session.increment_action(enriched.action_type)

            # --- Step 8: Audit Log Write ---
            await self._step_audit(
                request_id, session_id, session, enriched, policy_result,
                safety_result, exec_output, scrubbed, snapshot, start_time,
            )

            elapsed = int((time.monotonic() - start_time) * 1000)
            status.status = "COMPLETED"
            status.current_step = 8
            status.step_name = "audit_write"
            status.decision = "ALLOW"
            status.total_latency_ms = elapsed

            await self._emit("pipeline_completed", request_id, session_id,
                             action_type=enriched.action_type.value,
                             risk_tier=enriched.risk_tier.value,
                             decision="ALLOW", latency_ms=elapsed,
                             agent_id=session.agent_id)

            logger.info(
                "pipeline_completed",
                request_id=request_id,
                action_type=enriched.action_type.value,
                risk_tier=enriched.risk_tier.value,
                latency_ms=elapsed,
            )
            return status

        except Exception as e:
            logger.error("pipeline_error", request_id=request_id, error=str(e))
            await self._emit("pipeline_error", request_id, session_id, error=str(e))
            return self._halt(status, status.current_step, "pipeline_error", str(e), start_time)

    # --- Pipeline step implementations ---

    async def _step_evaluate(
        self,
        request: ActionRequest,
        session: SessionState,
        request_id: str,
        session_id: str,
    ) -> EnrichedRequest | None:
        if self._request_evaluator is None:
            return self._default_evaluate(request, session)
        from sandbox.models.messages import MessageEnvelope
        envelope = MessageEnvelope(
            session_id=session_id,
            request_id=request_id,
            sender="pipeline-orchestrator:1.0.0",
            recipient="request-evaluator",
            payload=request.model_dump(),
        )
        result = await self._request_evaluator.process(envelope)
        if result is None:
            return None
        return EnrichedRequest(**result.payload)

    def _default_evaluate(self, request: ActionRequest, session: SessionState) -> EnrichedRequest:
        """Fallback evaluator when agent is not wired."""
        risk_tier = self._classify_risk(request, session)
        return EnrichedRequest(
            action_type=request.action_type,
            parameters=request.parameters,
            session_token=request.session_token,
            request_id=request.request_id,
            intent_class=request.action_type,
            risk_tier=risk_tier,
        )

    def _classify_risk(self, request: ActionRequest, session: SessionState) -> RiskTier:
        tier = RiskTier.LOW
        if request.action_type == ActionType.READ:
            tier = RiskTier.LOW
        elif request.action_type == ActionType.WRITE:
            tier = RiskTier.MEDIUM
        elif request.action_type in (ActionType.EXECUTE, ActionType.NETWORK):
            tier = RiskTier.HIGH
        elif request.action_type == ActionType.SECRET_ACCESS:
            tier = RiskTier.CRITICAL

        if request.action_type.value not in session.action_history:
            tier = tier.upgrade()

        params_str = str(request.parameters)
        if any(c in params_str for c in ["|", ";", "&&", "$(", "`"]):
            tier = RiskTier.HIGH if tier < RiskTier.HIGH else tier

        return tier

    async def _step_policy(
        self,
        enriched: EnrichedRequest,
        session: SessionState,
        request_id: str,
        session_id: str,
    ) -> PolicyResult:
        if self._policy_engine is None:
            return self._default_policy(enriched, session)
        from sandbox.models.messages import MessageEnvelope
        envelope = MessageEnvelope(
            session_id=session_id,
            request_id=request_id,
            sender="pipeline-orchestrator:1.0.0",
            recipient="policy-engine",
            payload=enriched.model_dump(),
        )
        result = await self._policy_engine.process(envelope)
        if result is None:
            return PolicyResult(
                request_id=request_id,
                decision=PolicyDecision.DENY,
                reason="POLICY_ENGINE_ERROR",
            )
        return PolicyResult(**result.payload)

    def _default_policy(self, enriched: EnrichedRequest, session: SessionState) -> PolicyResult:
        if enriched.intent_class.value not in [
            a.value for a in session.capability_token.allowed_actions
        ]:
            return PolicyResult(
                request_id=enriched.request_id,
                decision=PolicyDecision.DENY,
                reason=f"Action {enriched.intent_class.value} not in session allowlist",
            )
        if (
            enriched.intent_class in (ActionType.WRITE, ActionType.EXECUTE)
            and session.capability_token.max_writes > 0
            and session.write_count >= session.capability_token.max_writes
        ):
            return PolicyResult(
                request_id=enriched.request_id,
                decision=PolicyDecision.DENY,
                reason="Write budget exhausted",
            )
        if enriched.risk_tier == RiskTier.CRITICAL:
            return PolicyResult(
                request_id=enriched.request_id,
                decision=PolicyDecision.ESCALATE,
                reason="CRITICAL tier requires HITL",
            )
        return PolicyResult(
            request_id=enriched.request_id,
            decision=PolicyDecision.ALLOW,
            matched_rule="default_allow",
        )

    async def _step_content_safety_inbound(
        self,
        enriched: EnrichedRequest,
        request_id: str,
        session_id: str,
    ) -> ContentSafetyResult:
        if self._content_safety is None:
            return ContentSafetyResult(
                request_id=request_id,
                decision=ContentDecision.CLEAR,
            )
        from sandbox.models.messages import MessageEnvelope
        envelope = MessageEnvelope(
            session_id=session_id,
            request_id=request_id,
            sender="pipeline-orchestrator:1.0.0",
            recipient="content-safety",
            payload={"direction": "inbound", **enriched.model_dump()},
        )
        result = await self._content_safety.process(envelope)
        if result is None:
            return ContentSafetyResult(
                request_id=request_id,
                decision=ContentDecision.BLOCK,
                reason="Content safety agent unavailable — fail closed",
            )
        return ContentSafetyResult(**result.payload)

    async def _step_hitl(
        self,
        enriched: EnrichedRequest,
        session: SessionState,
        policy_result: PolicyResult,
        request_id: str,
        session_id: str,
    ) -> HITLResult:
        if self._hitl_orchestrator is None:
            return HITLResult(
                request_id=request_id,
                decision=HITLDecision.DENY,
                reason="No HITL orchestrator available — auto-deny",
            )
        context = HITLContextPackage(
            request_id=request_id,
            session_id=session_id,
            agent_id=session.agent_id,
            action_type=enriched.action_type,
            risk_tier=enriched.risk_tier,
            parameters=enriched.parameters,
            escalation_reason=policy_result.reason,
            policy_decision=policy_result.decision,
        )
        from sandbox.models.messages import MessageEnvelope
        envelope = MessageEnvelope(
            session_id=session_id,
            request_id=request_id,
            sender="pipeline-orchestrator:1.0.0",
            recipient="hitl-orchestrator",
            payload=context.model_dump(),
        )
        result = await self._hitl_orchestrator.process(envelope)
        if result is None:
            return HITLResult(
                request_id=request_id,
                decision=HITLDecision.TIMEOUT,
                reason="HITL orchestrator unresponsive",
            )
        return HITLResult(**result.payload)

    async def _step_sign_command(
        self,
        enriched: EnrichedRequest,
        session: SessionState,
        request_id: str,
        session_id: str,
    ) -> SignedCommand:
        from sandbox.crypto.signing import compute_hash
        import orjson
        params_bytes = orjson.dumps(enriched.parameters, option=orjson.OPT_SORT_KEYS)
        cmd_hash = compute_hash(
            enriched.action_type.value.encode() + params_bytes
        )
        timeout_map = {
            ActionType.READ: 30000,
            ActionType.WRITE: 30000,
            ActionType.EXECUTE: 120000,
            ActionType.NETWORK: 30000,
            ActionType.SECRET_ACCESS: 10000,
        }
        return SignedCommand(
            request_id=request_id,
            session_id=session_id,
            action_type=enriched.action_type,
            parameters=enriched.parameters,
            scope=[a.value for a in session.capability_token.allowed_actions],
            timeout_ms=timeout_map.get(enriched.action_type, 30000),
            command_hash=cmd_hash,
        )

    async def _step_snapshot(
        self,
        enriched: EnrichedRequest,
        session: SessionState,
        request_id: str,
        session_id: str,
    ) -> SnapshotRecord | None:
        if self._rollback_agent is None:
            return SnapshotRecord(
                request_id=request_id,
                session_id=session_id,
                action_type=enriched.action_type,
            )
        from sandbox.models.messages import MessageEnvelope
        envelope = MessageEnvelope(
            session_id=session_id,
            request_id=request_id,
            sender="pipeline-orchestrator:1.0.0",
            recipient="rollback-agent",
            payload={
                "action": "snapshot",
                "action_type": enriched.action_type.value,
                "targets": list(enriched.parameters.get("targets", [])),
            },
        )
        result = await self._rollback_agent.process(envelope)
        if result is None:
            return None
        return SnapshotRecord(**result.payload)

    async def _step_execute(
        self,
        command: SignedCommand,
        request_id: str,
        session_id: str,
    ) -> ExecutionOutput:
        if self._executor is None:
            return ExecutionOutput(
                request_id=request_id,
                result=ExecutionResult.SKIPPED,
                stderr="No executor configured",
            )
        from sandbox.models.messages import MessageEnvelope
        envelope = MessageEnvelope(
            session_id=session_id,
            request_id=request_id,
            sender="pipeline-orchestrator:1.0.0",
            recipient="executor",
            payload=command.model_dump(),
        )
        result = await self._executor.process(envelope)
        if result is None:
            return ExecutionOutput(
                request_id=request_id,
                result=ExecutionResult.FAILURE,
                stderr="Executor returned no result",
            )
        return ExecutionOutput(**result.payload)

    async def _step_content_safety_outbound(
        self,
        exec_output: ExecutionOutput,
        request_id: str,
        session_id: str,
    ) -> ScrubbedOutput:
        if self._content_safety is None:
            return ScrubbedOutput(
                request_id=request_id,
                stdout=exec_output.stdout,
                stderr=exec_output.stderr,
                exit_code=exec_output.exit_code,
                result=exec_output.result,
            )
        from sandbox.models.messages import MessageEnvelope
        envelope = MessageEnvelope(
            session_id=session_id,
            request_id=request_id,
            sender="pipeline-orchestrator:1.0.0",
            recipient="content-safety",
            payload={"direction": "outbound", **exec_output.model_dump()},
        )
        result = await self._content_safety.process(envelope)
        if result is None:
            return ScrubbedOutput(
                request_id=request_id,
                result=ExecutionResult.FAILURE,
                stderr="Content safety scrubber unavailable — output withheld",
            )
        return ScrubbedOutput(**result.payload)

    async def _step_audit(
        self,
        request_id: str,
        session_id: str,
        session: SessionState,
        enriched: EnrichedRequest,
        policy_result: PolicyResult,
        safety_result: ContentSafetyResult,
        exec_output: ExecutionOutput,
        scrubbed: ScrubbedOutput,
        snapshot: SnapshotRecord | None,
        start_time: float,
    ) -> None:
        elapsed = int((time.monotonic() - start_time) * 1000)
        record = AuditRecord(
            session_id=session_id,
            agent_id=session.agent_id,
            action_type=enriched.action_type,
            risk_tier=enriched.risk_tier,
            intent_class=enriched.intent_class.value,
            policy_decision=policy_result.decision,
            policy_version=policy_result.policy_version,
            matched_rule=policy_result.matched_rule,
            content_safety_decision=safety_result.decision,
            injection_flags=safety_result.injection_flags,
            secret_redaction_count=safety_result.secret_redaction_count,
            command_hash=exec_output.request_id,
            execution_result=exec_output.result,
            output_hash=scrubbed.output_hash,
            scrubbed=scrubbed.scrubbed,
            rollback_snapshot_id=snapshot.snapshot_id if snapshot else None,
            total_pipeline_latency_ms=elapsed,
        )

        if self._audit_agent is not None:
            from sandbox.models.messages import MessageEnvelope
            envelope = MessageEnvelope(
                session_id=session_id,
                request_id=request_id,
                sender="pipeline-orchestrator:1.0.0",
                recipient="audit-agent",
                payload=record.model_dump(),
            )
            result = await self._audit_agent.process(envelope)
            if result is None:
                logger.error("audit_write_failed", request_id=request_id)

    async def _notify_anomaly(
        self,
        enriched: EnrichedRequest,
        session: SessionState,
    ) -> None:
        if self._anomaly_detector is None:
            return
        try:
            from sandbox.models.messages import MessageEnvelope
            envelope = MessageEnvelope(
                session_id=session.session_id,
                request_id=enriched.request_id,
                sender="pipeline-orchestrator:1.0.0",
                recipient="anomaly-detector",
                payload={
                    "event_type": "request",
                    "action_type": enriched.action_type.value,
                    "risk_tier": enriched.risk_tier.value,
                    "parameters": enriched.parameters,
                },
            )
            await self._anomaly_detector.process(envelope)
        except Exception:
            logger.warning("anomaly_notification_failed", request_id=enriched.request_id)

    # --- Event broadcasting ---

    async def _emit(self, event_type: str, request_id: str, session_id: str, **kwargs: Any) -> None:
        if self._event_broadcaster is None:
            return
        event = {
            "event": event_type,
            "request_id": request_id,
            "session_id": session_id,
            **kwargs,
        }
        try:
            await self._event_broadcaster.broadcast(event)
        except Exception:
            pass

    # --- Status helpers ---

    def _halt(
        self, status: PipelineStatus, step: int, step_name: str, reason: str, start_time: float
    ) -> PipelineStatus:
        status.status = "HALTED"
        status.current_step = step
        status.step_name = step_name
        status.reason = reason
        status.total_latency_ms = int((time.monotonic() - start_time) * 1000)
        logger.warning("pipeline_halted", request_id=status.request_id, step=step_name, reason=reason)
        return status

    def _deny(
        self, status: PipelineStatus, step: int, step_name: str, reason: str, start_time: float
    ) -> PipelineStatus:
        status.status = "DENIED"
        status.current_step = step
        status.step_name = step_name
        status.decision = "DENY"
        status.reason = reason
        status.total_latency_ms = int((time.monotonic() - start_time) * 1000)
        logger.info("pipeline_denied", request_id=status.request_id, step=step_name, reason=reason)
        return status
