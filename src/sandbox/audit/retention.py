"""Retention policy enforcement for audit logs.

Applies tiered retention periods based on record content, then
discovers and (optionally) removes expired session directories.

Retention tiers (highest matching wins):

====================  ====  ========================================
Tier                  Days  Trigger
====================  ====  ========================================
standard               90  default -- no escalating signals
hitl                  365  HITL was invoked
critical              365  risk tier >= CRITICAL
kill_switch           730  kill-switch or audit-failure session end
security_incident    2555  injection flags or anomaly flags present
====================  ====  ========================================
"""

from __future__ import annotations

import logging
import shutil
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import aiofiles
import orjson

from sandbox.models.audit import AuditRecord

logger = logging.getLogger(__name__)


class RetentionPolicy:
    """Determines and enforces audit-log retention periods."""

    def __init__(
        self,
        standard_days: int = 90,
        hitl_days: int = 365,
        critical_days: int = 365,
        kill_switch_days: int = 730,
        security_incident_days: int = 2555,
    ) -> None:
        self.standard_days = standard_days
        self.hitl_days = hitl_days
        self.critical_days = critical_days
        self.kill_switch_days = kill_switch_days
        self.security_incident_days = security_incident_days

    # ------------------------------------------------------------------
    # Per-record retention
    # ------------------------------------------------------------------

    def get_retention(self, record: AuditRecord) -> int:
        """Return the retention period in days for *record*.

        The highest matching tier wins, so a record that is both
        CRITICAL and has injection flags gets ``security_incident_days``.
        """
        days = self.standard_days

        if record.hitl_invoked:
            days = max(days, self.hitl_days)

        if record.risk_tier in ("CRITICAL", "HIGH"):
            days = max(days, self.critical_days)

        if record.injection_flags or record.anomaly_flags:
            days = max(days, self.security_incident_days)

        return days

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    async def scan_expired(self, log_dir: str) -> list[str]:
        """Return session directory names whose retention has elapsed.

        For each session directory that contains a ``seal.json`` file,
        the sealed timestamp and the highest retention tier observed
        across all records determine the expiry date.  Unsealed sessions
        are never considered expired.
        """
        root = Path(log_dir)
        if not root.exists():
            return []

        expired: list[str] = []
        now = datetime.now(timezone.utc)

        for session_dir in sorted(root.iterdir()):
            if not session_dir.is_dir():
                continue

            seal_path = session_dir / "seal.json"
            if not seal_path.exists():
                continue  # unsealed -- skip

            try:
                retention_days = await self._session_retention(session_dir)
                sealed_at = await self._sealed_at(seal_path)
                if sealed_at is None:
                    continue

                expiry = sealed_at + timedelta(days=retention_days)
                if now >= expiry:
                    expired.append(session_dir.name)
            except Exception:
                logger.exception(
                    "retention.scan error for session=%s", session_dir.name
                )

        return expired

    async def enforce(
        self, log_dir: str, *, dry_run: bool = True
    ) -> list[str]:
        """Delete (or list) expired session directories.

        Parameters
        ----------
        log_dir:
            Root audit log directory.
        dry_run:
            When ``True`` (the default), only lists what *would* be
            removed.  Set to ``False`` to actually delete.

        Returns
        -------
        list[str]
            Session IDs that were (or would be) removed.
        """
        expired = await self.scan_expired(log_dir)

        if dry_run:
            for sid in expired:
                logger.info("retention.enforce DRY_RUN would remove session=%s", sid)
            return expired

        removed: list[str] = []
        root = Path(log_dir)
        for sid in expired:
            session_dir = root / sid
            try:
                shutil.rmtree(session_dir)
                logger.info("retention.enforce DELETED session=%s", sid)
                removed.append(sid)
            except Exception:
                logger.exception(
                    "retention.enforce FAILED to delete session=%s", sid
                )

        return removed

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _session_retention(self, session_dir: Path) -> int:
        """Derive the highest retention tier for all records in a session.

        Reads ``seal.json`` first (it may carry aggregated indicators),
        then falls back to scanning ``records.jsonl`` for the highest
        applicable tier.
        """
        highest = self.standard_days

        # Check seal metadata for quick indicators.
        seal_path = session_dir / "seal.json"
        if seal_path.exists():
            async with aiofiles.open(seal_path, mode="rb") as fh:
                seal: dict[str, Any] = orjson.loads(await fh.read())

            reason = seal.get("reason", "")
            if reason in ("kill_switch", "audit_failure"):
                highest = max(highest, self.kill_switch_days)

            if seal.get("total_hitl", 0) > 0:
                highest = max(highest, self.hitl_days)

        # Scan records for per-record tier escalation.
        records_path = session_dir / "records.jsonl"
        if records_path.exists():
            async with aiofiles.open(records_path, mode="rb") as fh:
                async for raw_line in fh:
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        obj = orjson.loads(line)
                    except orjson.JSONDecodeError:
                        continue

                    if obj.get("injection_flags") or obj.get("anomaly_flags"):
                        highest = max(highest, self.security_incident_days)
                        break  # already at max tier -- no need to continue

                    if obj.get("risk_tier") in ("CRITICAL", "HIGH"):
                        highest = max(highest, self.critical_days)

                    if obj.get("hitl_invoked"):
                        highest = max(highest, self.hitl_days)

        return highest

    @staticmethod
    async def _sealed_at(seal_path: Path) -> datetime | None:
        """Parse the ``sealed_at_utc`` timestamp from a seal file."""
        try:
            async with aiofiles.open(seal_path, mode="rb") as fh:
                seal = orjson.loads(await fh.read())
            raw = seal.get("sealed_at_utc", "")
            if not raw:
                return None
            return datetime.fromisoformat(raw)
        except Exception:
            return None
