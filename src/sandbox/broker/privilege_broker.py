"""Dedicated non-AI Privilege Broker.

When a jailed agent needs PowerShell/root/outside-folder access, it goes
through a shim that forwards here. The broker:
1. Enqueues the request for human approval (via the HITL orchestrator).
2. On APPROVE — runs the exact, unmodified approved command outside the jail
   using a trusted non-AI executor, captures output, writes it to
   broker_out/<request_id>.txt inside the jail.
3. On DENY/TIMEOUT — writes a denial note, nothing runs.

The agent process NEVER touches root. The broker is the only path to
elevated execution.
"""
from __future__ import annotations

import asyncio
import subprocess
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class BrokerRequestState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"
    EXECUTED = "executed"
    FAILED = "failed"


@dataclass
class BrokerRequest:
    request_id: str
    session_id: str
    run_id: str
    agent_id: str
    command: str
    jail_dir: str
    exec_cwd: str = ""  # where the approved command runs; falls back to jail_dir
    state: BrokerRequestState = BrokerRequestState.PENDING
    created_at: float = field(default_factory=time.time)
    decided_at: float = 0.0
    reviewer_id: str = ""
    reason: str = ""
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "session_id": self.session_id,
            "run_id": self.run_id,
            "agent_id": self.agent_id,
            "command": self.command,
            "state": self.state,
            "created_at": self.created_at,
            "decided_at": self.decided_at,
            "reviewer_id": self.reviewer_id,
            "reason": self.reason,
            "exit_code": self.exit_code,
        }


class PrivilegeBroker:
    """Mediates privileged command execution through human approval."""

    def __init__(
        self,
        broadcaster: Any = None,
        recorder: Any = None,
        timeout_seconds: int = 300,
        exec_timeout: int = 120,
        recorder_factory: Callable[[str], Any] | None = None,
    ) -> None:
        self._broadcaster = broadcaster
        self._recorder = recorder
        self._timeout = timeout_seconds
        self._exec_timeout = exec_timeout
        # A single injected recorder can't be right when each request has its
        # own jail_dir, so fall back to a per-jail recorder built on demand
        # and cached (bug 5). An explicit self._recorder always wins.
        self._recorder_factory = recorder_factory
        self._recorder_cache: dict[str, Any] = {}
        self._requests: dict[str, BrokerRequest] = {}
        self._waiters: dict[str, asyncio.Event] = {}

    def _recorder_for(self, req: BrokerRequest) -> Any:
        if self._recorder is not None:
            return self._recorder
        if self._recorder_factory is None:
            return None
        cached = self._recorder_cache.get(req.jail_dir)
        if cached is None:
            cached = self._recorder_factory(req.jail_dir)
            self._recorder_cache[req.jail_dir] = cached
        return cached

    async def submit_request(
        self,
        session_id: str,
        run_id: str,
        agent_id: str,
        command: str,
        jail_dir: str,
        exec_cwd: str = "",
    ) -> BrokerRequest:
        """Submit a privileged command for human approval. Returns immediately."""
        request_id = uuid.uuid4().hex[:16]
        req = BrokerRequest(
            request_id=request_id,
            session_id=session_id,
            run_id=run_id,
            agent_id=agent_id,
            command=command,
            jail_dir=jail_dir,
            exec_cwd=exec_cwd,
        )
        self._requests[request_id] = req
        self._waiters[request_id] = asyncio.Event()

        if self._broadcaster:
            await self._broadcaster.broadcast({
                "event": "broker_request",
                "request_id": request_id,
                "session_id": session_id,
                "run_id": run_id,
                "agent_id": agent_id,
                "command": command,
            })

        recorder = self._recorder_for(req)
        if recorder:
            recorder.log_action(
                session_id=session_id,
                agent_id=agent_id,
                action="broker_request",
                details={
                    "request_id": request_id,
                    "command": command,
                },
            )

        logger.info(
            "broker.request_submitted",
            request_id=request_id,
            command=command[:200],
        )
        return req

    async def wait_for_decision(
        self, request_id: str, timeout: float | None = None
    ) -> BrokerRequest:
        """Block until the request is approved/denied or times out."""
        req = self._requests.get(request_id)
        if req is None:
            raise KeyError(f"Broker request {request_id} not found")

        event = self._waiters.get(request_id)
        if event is None:
            return req

        effective_timeout = timeout or self._timeout
        try:
            await asyncio.wait_for(event.wait(), timeout=effective_timeout)
        except asyncio.TimeoutError:
            req.state = BrokerRequestState.TIMEOUT
            req.decided_at = time.time()
            self._write_denial(req, "Request timed out — auto-denied")

        return req

    async def approve(
        self, request_id: str, reviewer_id: str, reason: str = ""
    ) -> BrokerRequest:
        """Approve a pending request and execute the command."""
        req = self._requests.get(request_id)
        if req is None:
            raise KeyError(f"Broker request {request_id} not found")
        if req.state != BrokerRequestState.PENDING:
            raise ValueError(f"Request {request_id} is already {req.state}")

        req.state = BrokerRequestState.APPROVED
        req.decided_at = time.time()
        req.reviewer_id = reviewer_id
        req.reason = reason

        recorder = self._recorder_for(req)
        if recorder:
            recorder.log_action(
                session_id=req.session_id,
                agent_id=req.agent_id,
                action="broker_approved",
                details={
                    "request_id": request_id,
                    "reviewer_id": reviewer_id,
                    "command": req.command,
                },
            )

        await self._execute_approved(req)

        event = self._waiters.pop(request_id, None)
        if event:
            event.set()

        if self._broadcaster:
            await self._broadcaster.broadcast({
                "event": "broker_decision",
                "request_id": request_id,
                "decision": "approved",
                "reviewer_id": reviewer_id,
                "exit_code": req.exit_code,
            })

        return req

    async def deny(
        self, request_id: str, reviewer_id: str, reason: str = ""
    ) -> BrokerRequest:
        """Deny a pending request."""
        req = self._requests.get(request_id)
        if req is None:
            raise KeyError(f"Broker request {request_id} not found")
        if req.state != BrokerRequestState.PENDING:
            raise ValueError(f"Request {request_id} is already {req.state}")

        req.state = BrokerRequestState.DENIED
        req.decided_at = time.time()
        req.reviewer_id = reviewer_id
        req.reason = reason

        self._write_denial(req, f"DENIED by {reviewer_id}: {reason}")

        event = self._waiters.pop(request_id, None)
        if event:
            event.set()

        recorder = self._recorder_for(req)
        if recorder:
            recorder.log_action(
                session_id=req.session_id,
                agent_id=req.agent_id,
                action="broker_denied",
                details={
                    "request_id": request_id,
                    "reviewer_id": reviewer_id,
                    "reason": reason,
                },
            )

        if self._broadcaster:
            await self._broadcaster.broadcast({
                "event": "broker_decision",
                "request_id": request_id,
                "decision": "denied",
                "reviewer_id": reviewer_id,
            })

        return req

    def get_request(self, request_id: str) -> BrokerRequest | None:
        return self._requests.get(request_id)

    def list_pending(self) -> list[BrokerRequest]:
        return [
            r for r in self._requests.values()
            if r.state == BrokerRequestState.PENDING
        ]

    def list_all(self) -> list[BrokerRequest]:
        return list(self._requests.values())

    async def _execute_approved(self, req: BrokerRequest) -> None:
        """Run the approved command outside the jail and capture output."""
        # Run in the request's exec_cwd (falls back to the jail dir), never the
        # API server's cwd (bug 4). Verify it exists or pass None.
        exec_cwd = req.exec_cwd or req.jail_dir or None
        if exec_cwd is not None and not Path(exec_cwd).is_dir():
            logger.warning(
                "broker.exec_cwd_missing",
                request_id=req.request_id,
                exec_cwd=exec_cwd,
            )
            exec_cwd = None

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(
                    req.command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=self._exec_timeout,
                    cwd=exec_cwd,
                ),
            )
            req.exit_code = result.returncode
            req.stdout = result.stdout
            req.stderr = result.stderr
            req.state = BrokerRequestState.EXECUTED

            output_dir = Path(req.jail_dir) / "broker_out"
            output_dir.mkdir(parents=True, exist_ok=True)
            output_file = output_dir / f"{req.request_id}.txt"
            output_file.write_text(
                f"EXIT_CODE: {result.returncode}\n"
                f"--- STDOUT ---\n{result.stdout}\n"
                f"--- STDERR ---\n{result.stderr}\n",
                encoding="utf-8",
            )

            logger.info(
                "broker.executed",
                request_id=req.request_id,
                exit_code=result.returncode,
            )

        except subprocess.TimeoutExpired:
            req.state = BrokerRequestState.FAILED
            req.stderr = f"Command timed out after {self._exec_timeout}s"
            self._write_denial(req, "Execution timed out")
            logger.error("broker.timeout", request_id=req.request_id)

        except Exception as e:
            req.state = BrokerRequestState.FAILED
            req.stderr = str(e)
            self._write_denial(req, f"Execution failed: {e}")
            logger.error(
                "broker.exec_failed",
                request_id=req.request_id,
                error=str(e),
            )

    def _write_denial(self, req: BrokerRequest, message: str) -> None:
        """Write a denial/error note into the jail's broker_out."""
        try:
            output_dir = Path(req.jail_dir) / "broker_out"
            output_dir.mkdir(parents=True, exist_ok=True)
            output_file = output_dir / f"{req.request_id}.txt"
            output_file.write_text(
                f"STATUS: {req.state.upper()}\n"
                f"REASON: {message}\n",
                encoding="utf-8",
            )
        except OSError as e:
            logger.warning(
                "broker.write_denial_failed",
                request_id=req.request_id,
                error=str(e),
            )
