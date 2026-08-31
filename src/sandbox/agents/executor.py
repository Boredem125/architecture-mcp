from __future__ import annotations

import time

import structlog

from sandbox.agents.base import BaseAgent
from sandbox.executor.isolation import IsolationProfile, SubprocessIsolator
from sandbox.executor.subprocess_runner import SubprocessRunner
from sandbox.models.enums import ActionType, ExecutionResult
from sandbox.models.messages import ExecutionOutput, MessageEnvelope, SignedCommand

logger = structlog.get_logger()


class ExecutorAgent(BaseAgent):
    """A09 — Zone 3. Signed command execution.

    The sole interface between Zone 2 and the real compute environment.
    Verifies signatures, runs commands in isolated subprocesses, returns
    scrubbed results to Zone 2 only — never to Zone 1 directly.
    Stateless — each subprocess is ephemeral.
    """

    agent_name = "executor"
    agent_version = "1.0.0"
    zone = 3
    pipeline_step = 7

    def __init__(
        self,
        default_timeout: int = 30,
        max_memory_mb: int = 512,
        max_pids: int = 32,
    ) -> None:
        super().__init__()
        self._default_timeout = default_timeout
        self._max_memory_mb = max_memory_mb
        self._max_pids = max_pids

    async def process(self, envelope: MessageEnvelope) -> MessageEnvelope | None:
        payload = envelope.payload
        request_id = envelope.request_id
        session_id = envelope.session_id

        try:
            command = SignedCommand(**payload)
        except Exception as e:
            logger.error("command_parse_failed", request_id=request_id, error=str(e))
            return self._error_envelope(
                session_id, request_id, f"Invalid command format: {e}"
            )

        timeout_seconds = command.timeout_ms / 1000.0
        action_type = command.action_type

        profile = IsolationProfile(
            max_cpu_cores=1,
            max_memory_mb=self._max_memory_mb,
            max_pids=self._max_pids,
            timeout_seconds=int(timeout_seconds),
            allowed_paths=command.parameters.get("allowed_paths", []),
            network_allowed=action_type == ActionType.NETWORK,
            action_type=action_type.value,
        )

        isolator = SubprocessIsolator(profile)
        runner = SubprocessRunner(isolator)

        start = time.monotonic()
        try:
            output = await runner.execute(command)
        except Exception as e:
            elapsed = int((time.monotonic() - start) * 1000)
            logger.error("execution_failed", request_id=request_id, error=str(e))
            output = ExecutionOutput(
                request_id=request_id,
                result=ExecutionResult.FAILURE,
                stderr=str(e),
                duration_ms=elapsed,
            )

        logger.info(
            "command_executed",
            request_id=request_id,
            action_type=action_type.value,
            result=output.result.value,
            duration_ms=output.duration_ms,
            exit_code=output.exit_code,
        )

        return self.create_envelope(
            session_id=session_id,
            request_id=request_id,
            recipient="content-safety",
            payload={"direction": "outbound", **output.model_dump()},
        )

    def _error_envelope(
        self, session_id: str, request_id: str, error: str
    ) -> MessageEnvelope:
        output = ExecutionOutput(
            request_id=request_id,
            result=ExecutionResult.FAILURE,
            stderr=error,
        )
        return self.create_envelope(
            session_id=session_id,
            request_id=request_id,
            recipient="content-safety",
            payload={"direction": "outbound", **output.model_dump()},
        )
