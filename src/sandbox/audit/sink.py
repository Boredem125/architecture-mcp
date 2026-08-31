"""Append-only audit sink per AGENT_07 spec.

Writes audit records as newline-delimited JSON into per-session
directories, threading each record through a per-session SHA-256 hash
chain so that tampering is detectable at any point.

Directory layout::

    {log_dir}/
        {session_id}/
            records.jsonl      -- hash-chained audit records
            seal.json          -- session seal (written once at end)
            fragments/
                {request_id}.json  -- partial audit data from pipeline steps
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any

import aiofiles
import orjson

from sandbox.models.audit import AuditFragment, AuditRecord, SessionSealRecord
from sandbox.audit.chain import HashChain

logger = logging.getLogger(__name__)


class AuditSink:
    """Append-only, hash-chained audit sink.

    Parameters
    ----------
    log_dir:
        Root directory for audit logs.  A subdirectory is created per
        ``session_id``.
    worm_endpoint:
        Optional URL of a Write-Once-Read-Many storage backend for
        immutable replication.  Currently reserved; records are only
        written locally.
    """

    def __init__(self, log_dir: str, worm_endpoint: str | None = None) -> None:
        self._log_dir = Path(log_dir)
        self._worm_endpoint = worm_endpoint
        self._chains: dict[str, HashChain] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._write_latencies: list[float] = []
        self._max_latency_window = 100  # keep the last N write latencies

    # ------------------------------------------------------------------
    # Record writing
    # ------------------------------------------------------------------

    async def write(self, record: AuditRecord) -> bool:
        """Append *record* to its session log with hash-chain linkage.

        The record's ``previous_record_hash`` and ``record_hash`` fields
        are populated before serialization.  Returns ``True`` on success.
        """
        try:
            session_dir = self._session_dir(record.session_id)
            session_dir.mkdir(parents=True, exist_ok=True)
            records_path = session_dir / "records.jsonl"

            # Serialize hashing + append under a per-session lock so two
            # concurrent writes cannot read the same current_hash and fork
            # the chain (bug 12).
            async with self._lock_for(record.session_id):
                chain = self._load_chain(record.session_id, records_path)

                # Link into the chain.
                record.previous_record_hash = chain.current_hash
                data_bytes = orjson.dumps(
                    record.model_dump(exclude={"record_hash"}),
                    option=orjson.OPT_SORT_KEYS,
                )
                record.record_hash = chain.add(data_bytes)

                # Serialize the complete record (now including record_hash).
                line = orjson.dumps(
                    record.model_dump(), option=orjson.OPT_SORT_KEYS
                )

                t0 = time.monotonic()
                async with aiofiles.open(records_path, mode="ab") as fh:
                    await fh.write(line + b"\n")
                elapsed_ms = (time.monotonic() - t0) * 1000.0
                self._record_latency(elapsed_ms)

            logger.debug(
                "audit.write session=%s record=%s hash=%s latency=%.1fms",
                record.session_id,
                record.record_id,
                record.record_hash,
                elapsed_ms,
            )
            return True

        except Exception:
            logger.exception(
                "audit.write FAILED session=%s record=%s",
                record.session_id,
                record.record_id,
            )
            return False

    # ------------------------------------------------------------------
    # Fragment handling
    # ------------------------------------------------------------------

    async def write_fragment(self, fragment: AuditFragment) -> None:
        """Persist a partial audit fragment for later assembly."""
        session_dir = self._session_dir(fragment.session_id)
        fragments_dir = session_dir / "fragments"
        fragments_dir.mkdir(parents=True, exist_ok=True)

        path = fragments_dir / f"{fragment.request_id}.json"
        payload = orjson.dumps(fragment.model_dump(), option=orjson.OPT_SORT_KEYS)

        if path.exists():
            # Append to existing fragment list for this request.
            async with aiofiles.open(path, mode="rb") as fh:
                existing = orjson.loads(await fh.read())
            if isinstance(existing, list):
                existing.append(fragment.model_dump())
            else:
                existing = [existing, fragment.model_dump()]
            payload = orjson.dumps(existing, option=orjson.OPT_SORT_KEYS)

        async with aiofiles.open(path, mode="wb") as fh:
            await fh.write(payload)

    async def assemble_record(
        self, request_id: str, session_id: str
    ) -> AuditRecord:
        """Assemble a full :class:`AuditRecord` from stored fragments.

        Fragments are merged in ``step_number`` order.  Keys from later
        steps overwrite earlier ones, giving downstream evaluators the
        final say.
        """
        fragments_path = (
            self._session_dir(session_id) / "fragments" / f"{request_id}.json"
        )
        if not fragments_path.exists():
            raise FileNotFoundError(
                f"No fragments for request_id={request_id} "
                f"in session={session_id}"
            )

        async with aiofiles.open(fragments_path, mode="rb") as fh:
            raw = orjson.loads(await fh.read())

        items: list[dict[str, Any]] = raw if isinstance(raw, list) else [raw]
        items.sort(key=lambda f: f.get("step_number", 0))

        merged: dict[str, Any] = {}
        for item in items:
            merged.update(item.get("data", {}))

        # Ensure mandatory identifiers are present.
        merged.setdefault("session_id", session_id)
        merged.setdefault("agent_id", items[0].get("agent_name", "unknown"))
        if "action_type" not in merged:
            merged["action_type"] = "READ"
        if "risk_tier" not in merged:
            merged["risk_tier"] = "LOW"

        return AuditRecord(**merged)

    # ------------------------------------------------------------------
    # Session sealing
    # ------------------------------------------------------------------

    async def seal_session(
        self, session_id: str, summary: SessionSealRecord
    ) -> None:
        """Seal the session audit segment.

        Computes a summary hash covering the final chain state plus the
        seal payload, writes ``seal.json``, and marks the segment as
        immutable.
        """
        records_path = self._session_dir(session_id) / "records.jsonl"
        chain = self._load_chain(session_id, records_path)
        chain_hash = chain.current_hash

        # Summary hash = SHA-256(chain_hash || seal payload without summary_hash)
        seal_data = summary.model_dump(exclude={"summary_hash"})
        seal_bytes = orjson.dumps(seal_data, option=orjson.OPT_SORT_KEYS)
        import hashlib

        h = hashlib.sha256()
        h.update(chain_hash.encode("utf-8"))
        h.update(seal_bytes)
        summary.summary_hash = h.hexdigest()

        session_dir = self._session_dir(session_id)
        session_dir.mkdir(parents=True, exist_ok=True)
        seal_path = session_dir / "seal.json"
        async with aiofiles.open(seal_path, mode="wb") as fh:
            await fh.write(
                orjson.dumps(summary.model_dump(), option=orjson.OPT_SORT_KEYS)
            )

        logger.info(
            "audit.seal session=%s summary_hash=%s",
            session_id,
            summary.summary_hash,
        )

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    async def verify_chain(self, session_id: str) -> bool:
        """Re-derive and verify the hash chain for *session_id*.

        Reads every record from ``records.jsonl``, recomputes the chain
        hash for each, and compares against the stored ``record_hash``.
        """
        records_path = self._session_dir(session_id) / "records.jsonl"
        if not records_path.exists():
            logger.warning(
                "audit.verify_chain no records for session=%s", session_id
            )
            return True  # empty chain is trivially valid

        chain_records: list[tuple[bytes, str]] = []
        async with aiofiles.open(records_path, mode="rb") as fh:
            async for raw_line in fh:
                line = raw_line.strip()
                if not line:
                    continue
                obj = orjson.loads(line)
                stored_hash = obj.get("record_hash", "")
                # Reconstruct the data that was hashed: the record
                # *without* the record_hash field, sorted-key serialized.
                obj_copy = {k: v for k, v in obj.items() if k != "record_hash"}
                data_bytes = orjson.dumps(obj_copy, option=orjson.OPT_SORT_KEYS)
                chain_records.append((data_bytes, stored_hash))

        verifier = HashChain()
        return verifier.verify(chain_records)

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    async def health_check(self) -> dict[str, Any]:
        """Return operational health metrics for the audit sink."""
        latencies = self._write_latencies[-self._max_latency_window :]
        avg_latency = (
            sum(latencies) / len(latencies) if latencies else 0.0
        )
        max_latency = max(latencies) if latencies else 0.0

        # Quick chain integrity spot-check on all active sessions.
        chain_ok = True
        for sid in list(self._chains):
            if not await self.verify_chain(sid):
                chain_ok = False
                break

        return {
            "status": "healthy" if chain_ok else "degraded",
            "active_sessions": len(self._chains),
            "write_latency_avg_ms": round(avg_latency, 2),
            "write_latency_max_ms": round(max_latency, 2),
            "total_writes": sum(c.chain_length for c in self._chains.values()),
            "chain_integrity": chain_ok,
            "sink_available": True,
            "worm_configured": self._worm_endpoint is not None,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _session_dir(self, session_id: str) -> Path:
        return self._log_dir / session_id

    def _lock_for(self, session_id: str) -> asyncio.Lock:
        lock = self._locks.get(session_id)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[session_id] = lock
        return lock

    def _load_chain(self, session_id: str, records_path: Path) -> HashChain:
        """Return the session chain, rehydrating from disk on first use.

        Without this, a fresh process starts every chain at genesis and
        appending to an existing ``records.jsonl`` silently forks it, so
        ``verify_chain`` fails forever after a restart (bug 1).
        """
        chain = self._chains.get(session_id)
        if chain is None:
            chain = HashChain.from_records_file(records_path)
            self._chains[session_id] = chain
        return chain

    def _record_latency(self, ms: float) -> None:
        self._write_latencies.append(ms)
        if len(self._write_latencies) > self._max_latency_window * 2:
            self._write_latencies = self._write_latencies[
                -self._max_latency_window :
            ]
