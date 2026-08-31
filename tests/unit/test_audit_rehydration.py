"""Audit chain rehydration + concurrent-write locking (bugs 1 & 12)."""
from __future__ import annotations

import asyncio

import pytest

from sandbox.audit.chain import HashChain
from sandbox.audit.sink import AuditSink
from sandbox.models.audit import AuditRecord

SID = "sess-rehydrate-001"


def _record(i: int) -> AuditRecord:
    return AuditRecord(
        session_id=SID,
        agent_id="test-agent",
        action_type="READ",
        risk_tier="LOW",
        decision="ALLOW",
        reason=f"record {i}",
    )


async def test_chain_survives_process_restart(tmp_path):
    # First "process": write 3.
    sink1 = AuditSink(str(tmp_path))
    for i in range(3):
        assert await sink1.write(_record(i))
    assert await sink1.verify_chain(SID)

    # Second "process": brand-new sink, no in-memory chain. Append 2 more.
    sink2 = AuditSink(str(tmp_path))
    for i in range(3, 5):
        assert await sink2.write(_record(i))

    # The chain must still verify end-to-end — no genesis fork.
    assert await sink2.verify_chain(SID)

    records = (tmp_path / SID / "records.jsonl").read_text().splitlines()
    assert len([ln for ln in records if ln.strip()]) == 5


async def test_torn_final_line_tolerated(tmp_path):
    sink = AuditSink(str(tmp_path))
    for i in range(3):
        await sink.write(_record(i))

    records_path = tmp_path / SID / "records.jsonl"
    with records_path.open("ab") as fh:
        fh.write(b'{"record_hash": "deadbeef", "partial"')  # torn write

    # Rehydration skips the torn line and seeds from record #3.
    chain = HashChain.from_records_file(records_path)
    assert chain.chain_length == 3


async def test_seal_after_restart_uses_real_chain(tmp_path):
    from sandbox.models.audit import SessionSealRecord

    sink1 = AuditSink(str(tmp_path))
    for i in range(2):
        await sink1.write(_record(i))

    # New process seals without ever having written in-memory.
    sink2 = AuditSink(str(tmp_path))
    seal = SessionSealRecord(
        session_id=SID,
        reason="done",
        total_requests=2,
        total_denies=0,
        total_hitl=0,
        session_duration_ms=1000,
        summary_hash="",  # overwritten by seal_session
    )
    await sink2.seal_session(SID, seal)
    assert (tmp_path / SID / "seal.json").exists()
    # summary_hash must be non-genesis (it folded in the real chain head).
    assert seal.summary_hash and len(seal.summary_hash) == 64


async def test_concurrent_writes_do_not_fork_chain(tmp_path):
    sink = AuditSink(str(tmp_path))
    # Fire many writes concurrently; the per-session lock must serialize them.
    await asyncio.gather(*[sink.write(_record(i)) for i in range(25)])
    assert await sink.verify_chain(SID)
    records = (tmp_path / SID / "records.jsonl").read_text().splitlines()
    assert len([ln for ln in records if ln.strip()]) == 25
