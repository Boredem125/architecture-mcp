from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("/sessions/{session_id}")
async def get_session_audit(session_id: str) -> dict:
    log_dir = os.environ.get("AUDIT_LOG_DIR", "./audit_logs")
    session_dir = Path(log_dir) / session_id
    if not session_dir.exists():
        raise HTTPException(status_code=404, detail="No audit records for this session")

    records_file = session_dir / "records.jsonl"
    records = []
    if records_file.exists():
        import orjson
        for line in records_file.read_text().strip().split("\n"):
            if line:
                records.append(orjson.loads(line))

    seal_file = session_dir / "seal.json"
    seal = None
    if seal_file.exists():
        import orjson
        seal = orjson.loads(seal_file.read_bytes())

    return {
        "session_id": session_id,
        "record_count": len(records),
        "sealed": seal is not None,
        "records": records,
        "seal": seal,
    }


@router.get("/sessions/{session_id}/verify")
async def verify_audit_chain(session_id: str) -> dict:
    from sandbox.audit.sink import AuditSink

    log_dir = os.environ.get("AUDIT_LOG_DIR", "./audit_logs")
    sink = AuditSink(log_dir=log_dir)
    is_valid = await sink.verify_chain(session_id)
    return {"session_id": session_id, "chain_valid": is_valid}
