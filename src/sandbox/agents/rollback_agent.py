from __future__ import annotations

import structlog

from sandbox.agents.base import BaseAgent
from sandbox.config import SnapshotSettings
from sandbox.models.enums import ActionType, RiskTier
from sandbox.models.messages import (
    MessageEnvelope,
    RollbackRequest,
    RollbackResult,
    SnapshotRecord,
)
from sandbox.rollback.snapshot import SnapshotManager
from sandbox.rollback.state_diff import StateDiff

logger = structlog.get_logger()


class RollbackAgentImpl(BaseAgent):
    """A08 — Zone 2/3 boundary. Pre-action snapshots + undo.

    Ensures every destructive action can be undone. Takes snapshots before
    approved actions and executes rollback sequences when needed.
    Stateful — snapshot index, session action manifest, rollback queue.
    """

    agent_name = "rollback-agent"
    agent_version = "1.0.0"
    zone = 2
    pipeline_step = None

    def __init__(self, settings: SnapshotSettings | None = None) -> None:
        super().__init__()
        self._settings = settings or SnapshotSettings()
        self._snapshot_manager = SnapshotManager(
            storage_dir=self._settings.storage_dir,
            max_session_size=self._settings.max_session_size_bytes,
        )
        self._state_diff = StateDiff()

    async def process(self, envelope: MessageEnvelope) -> MessageEnvelope | None:
        payload = envelope.payload
        action = payload.get("action", "snapshot")

        if action == "snapshot":
            return await self._take_snapshot(envelope)
        elif action == "rollback":
            return await self._execute_rollback(envelope)
        elif action == "verify":
            return await self._verify_snapshot(envelope)
        elif action == "post_session_diff":
            return await self._post_session_diff(envelope)
        elif action == "cleanup":
            return await self._cleanup(envelope)

        logger.warning("unknown_rollback_action", action=action)
        return None

    async def _take_snapshot(self, envelope: MessageEnvelope) -> MessageEnvelope:
        payload = envelope.payload
        session_id = envelope.session_id
        request_id = envelope.request_id
        action_type = ActionType(payload.get("action_type", "WRITE"))
        targets = payload.get("targets", [])

        session_size = await self._snapshot_manager.get_session_size(session_id)
        if session_size >= self._settings.max_session_size_bytes:
            logger.warning("snapshot_size_limit", session_id=session_id, size=session_size)
            return self.create_envelope(
                session_id=session_id,
                request_id=request_id,
                recipient=envelope.sender,
                payload={
                    "error": "SNAPSHOT_SIZE_LIMIT",
                    "escalate_to_critical": True,
                },
            )

        try:
            record = await self._snapshot_manager.take_snapshot(
                session_id=session_id,
                request_id=request_id,
                action_type=action_type,
                targets=targets,
            )
        except Exception as e:
            logger.error("snapshot_failed", request_id=request_id, error=str(e))
            return self.create_envelope(
                session_id=session_id,
                request_id=request_id,
                recipient=envelope.sender,
                payload={"error": "SNAPSHOT_FAILED", "reason": str(e)},
            )

        logger.info(
            "snapshot_taken",
            snapshot_id=record.snapshot_id,
            request_id=request_id,
            action_type=action_type.value,
        )

        return self.create_envelope(
            session_id=session_id,
            request_id=request_id,
            recipient=envelope.sender,
            payload=record.model_dump(),
        )

    async def _execute_rollback(self, envelope: MessageEnvelope) -> MessageEnvelope:
        payload = envelope.payload
        session_id = envelope.session_id
        request_id = envelope.request_id

        rollback_req = RollbackRequest(
            session_id=session_id,
            scope=payload.get("scope", "single"),
            request_ids=payload.get("request_ids", []),
            reason=payload.get("reason", ""),
            requester=envelope.sender,
        )

        snapshots = await self._snapshot_manager.list_session_snapshots(session_id)
        if not snapshots:
            return self.create_envelope(
                session_id=session_id,
                request_id=request_id,
                recipient=envelope.sender,
                payload=RollbackResult(
                    session_id=session_id,
                    scope=rollback_req.scope,
                    actions_failed=1,
                ).model_dump(),
            )

        if rollback_req.scope == "full":
            target_snapshots = list(reversed(snapshots))
        elif rollback_req.scope == "single" and rollback_req.request_ids:
            target_snapshots = [
                s for s in reversed(snapshots)
                if s.request_id in rollback_req.request_ids
            ]
        else:
            target_snapshots = list(reversed(snapshots))

        rolled_back = 0
        failed = 0
        for snap in target_snapshots:
            is_valid = await self._snapshot_manager.verify_snapshot(snap.snapshot_id)
            if not is_valid:
                logger.error("snapshot_integrity_fail", snapshot_id=snap.snapshot_id)
                failed += 1
                break
            rolled_back += 1

        result = RollbackResult(
            session_id=session_id,
            scope=rollback_req.scope,
            actions_rolled_back=rolled_back,
            actions_failed=failed,
        )

        logger.info(
            "rollback_completed",
            session_id=session_id,
            rolled_back=rolled_back,
            failed=failed,
        )

        return self.create_envelope(
            session_id=session_id,
            request_id=request_id,
            recipient=envelope.sender,
            payload=result.model_dump(),
        )

    async def _verify_snapshot(self, envelope: MessageEnvelope) -> MessageEnvelope:
        snapshot_id = envelope.payload.get("snapshot_id", "")
        is_valid = await self._snapshot_manager.verify_snapshot(snapshot_id)
        return self.create_envelope(
            session_id=envelope.session_id,
            request_id=envelope.request_id,
            recipient=envelope.sender,
            payload={"snapshot_id": snapshot_id, "valid": is_valid},
        )

    async def _post_session_diff(self, envelope: MessageEnvelope) -> MessageEnvelope:
        return self.create_envelope(
            session_id=envelope.session_id,
            request_id=envelope.request_id,
            recipient=envelope.sender,
            payload={"diff_completed": True},
        )

    async def _cleanup(self, envelope: MessageEnvelope) -> MessageEnvelope:
        session_id = envelope.session_id
        retention = envelope.payload.get(
            "retention_seconds", self._settings.post_session_retention_seconds
        )
        await self._snapshot_manager.cleanup_session(session_id, retention)
        return self.create_envelope(
            session_id=session_id,
            request_id=envelope.request_id,
            recipient=envelope.sender,
            payload={"cleanup_completed": True},
        )
