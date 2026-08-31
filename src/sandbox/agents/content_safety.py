from __future__ import annotations

import structlog

from sandbox.agents.base import BaseAgent
from sandbox.models.enums import ContentDecision, ExecutionResult, RiskTier
from sandbox.models.messages import (
    ContentSafetyResult,
    ExecutionOutput,
    MessageEnvelope,
    ScrubbedOutput,
)
from sandbox.safety.blocklist import CommandBlocklist
from sandbox.safety.injection_detector import InjectionDetector
from sandbox.safety.output_scrubber import OutputScrubber
from sandbox.safety.secret_scanner import SecretScanner

logger = structlog.get_logger()


class ContentSafetyAgent(BaseAgent):
    """A04 — Zone 2. Scans inbound requests and outbound results.

    Runs injection detection, secret scanning, blocklist checks on requests.
    Scrubs secrets and injection content from Zone 3 output.
    Stateless — each scan is independent.
    """

    agent_name = "content-safety"
    agent_version = "1.0.0"
    zone = 2
    pipeline_step = 4

    def __init__(self) -> None:
        super().__init__()
        self._injection_detector = InjectionDetector()
        self._secret_scanner = SecretScanner()
        self._blocklist = CommandBlocklist()
        self._scrubber = OutputScrubber(self._secret_scanner, self._injection_detector)

    async def process(self, envelope: MessageEnvelope) -> MessageEnvelope | None:
        payload = envelope.payload
        direction = payload.get("direction", "inbound")

        if direction == "outbound":
            return await self._scan_outbound(envelope)
        return await self._scan_inbound(envelope)

    async def _scan_inbound(self, envelope: MessageEnvelope) -> MessageEnvelope:
        payload = envelope.payload
        request_id = envelope.request_id
        session_id = envelope.session_id
        flags: list[str] = []

        params_str = str(payload.get("parameters", {}))

        is_injection, injection_flags = self._injection_detector.scan(params_str)
        if is_injection:
            flags.extend(injection_flags)

        has_secrets, secret_matches = self._secret_scanner.scan(params_str)
        if has_secrets:
            flags.append("secrets_in_request")

        action_type = payload.get("action_type", "")
        command = payload.get("parameters", {}).get("command", "")
        if command:
            is_blocked, block_reason = self._blocklist.check(
                command, payload.get("parameters", {})
            )
            if is_blocked:
                flags.append(f"blocklist:{block_reason}")

        if any("injection" in f.lower() or "blocklist" in f for f in flags):
            decision = ContentDecision.BLOCK
            reason = f"Content blocked: {', '.join(flags)}"
        elif has_secrets:
            decision = ContentDecision.BLOCK
            reason = "Secrets detected in request parameters"
        else:
            decision = ContentDecision.CLEAR
            reason = ""

        result = ContentSafetyResult(
            request_id=request_id,
            decision=decision,
            injection_flags=flags,
            secret_redaction_count=len(secret_matches) if has_secrets else 0,
            reason=reason,
        )

        audit_data = {
            "content_safety_decision": decision.value,
            "injection_flags": flags,
            "secret_redaction_count": result.secret_redaction_count,
        }
        self.create_audit_fragment(request_id, session_id, audit_data)

        logger.info(
            "content_safety_inbound",
            request_id=request_id,
            decision=decision.value,
            flags=flags,
        )

        return self.create_envelope(
            session_id=session_id,
            request_id=request_id,
            recipient="task-agent" if decision == ContentDecision.BLOCK else "command-signer",
            payload=result.model_dump(),
        )

    async def _scan_outbound(self, envelope: MessageEnvelope) -> MessageEnvelope:
        payload = envelope.payload
        request_id = envelope.request_id
        session_id = envelope.session_id

        stdout = payload.get("stdout", "")
        stderr = payload.get("stderr", "")

        stdout_result = self._scrubber.scrub(stdout)
        stderr_result = self._scrubber.scrub(stderr)

        total_redactions = stdout_result.redaction_count + stderr_result.redaction_count

        from sandbox.crypto.signing import compute_hash

        combined = f"{stdout_result.scrubbed_text}{stderr_result.scrubbed_text}"
        output_hash = compute_hash(combined.encode())

        scrubbed = ScrubbedOutput(
            request_id=request_id,
            stdout=stdout_result.scrubbed_text,
            stderr=stderr_result.scrubbed_text,
            exit_code=payload.get("exit_code", 0),
            result=ExecutionResult(payload.get("result", "SUCCESS")),
            scrubbed=True,
            redaction_count=total_redactions,
            output_hash=output_hash,
        )

        logger.info(
            "content_safety_outbound",
            request_id=request_id,
            redactions=total_redactions,
            injection_neutralized=stdout_result.injection_neutralized or stderr_result.injection_neutralized,
        )

        return self.create_envelope(
            session_id=session_id,
            request_id=request_id,
            recipient="result-queue",
            payload=scrubbed.model_dump(),
        )
