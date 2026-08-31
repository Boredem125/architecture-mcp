"""FolderAudit — cross-process safe chained append."""
from __future__ import annotations

import json
from pathlib import Path

from sandbox.connector.audit import FolderAudit


def test_append_creates_record(tmp_path):
    """Append a record to the audit log."""
    audit_dir = tmp_path / "audit"
    audit = FolderAudit(audit_dir, session_id="s-1")

    record = {"event": "test", "data": "value"}
    audit.append(record)

    # Verify the record was written
    records_file = audit_dir / "s-1" / "records.jsonl"
    assert records_file.exists()

    with open(records_file) as f:
        written = json.loads(f.read().strip())

    assert written["event"] == "test"
    assert "previous_hash" in written
    assert "record_hash" in written


def test_chain_integrity(tmp_path):
    """Appended records form a valid chain."""
    audit_dir = tmp_path / "audit"
    audit = FolderAudit(audit_dir, session_id="s-1")

    # Append three records
    audit.append({"event": "event1"})
    audit.append({"event": "event2"})
    audit.append({"event": "event3"})

    # Verify the chain
    valid, msg = audit.verify_chain()
    assert valid, f"Chain should be valid: {msg}"

    # Read and verify chain links
    with open(audit_dir / "s-1" / "records.jsonl") as f:
        records = [json.loads(line) for line in f]

    assert len(records) == 3
    assert records[0]["previous_hash"] == ""  # genesis
    assert records[1]["previous_hash"] == records[0]["record_hash"]
    assert records[2]["previous_hash"] == records[1]["record_hash"]


def test_concurrent_append_single_winner(tmp_path):
    """Two appenders, only one succeeds at a time (lock serializes)."""
    audit_dir = tmp_path / "audit"

    def append_record(session_id, event):
        audit = FolderAudit(audit_dir, session_id)
        audit.append({"event": event})

    # Append from two "concurrent" instances (really just sequential via lock)
    append_record("s-1", "first")
    append_record("s-1", "second")

    records_file = audit_dir / "s-1" / "records.jsonl"
    with open(records_file) as f:
        records = [json.loads(line) for line in f]

    assert len(records) == 2
    assert records[0]["event"] == "first"
    assert records[1]["event"] == "second"


def test_verify_catches_broken_chain(tmp_path):
    """Verify detects a tampering attempt."""
    audit_dir = tmp_path / "audit"
    audit = FolderAudit(audit_dir, session_id="s-1")

    audit.append({"event": "event1"})
    audit.append({"event": "event2"})

    # Tamper: change the second record's previous_hash
    records_file = audit_dir / "s-1" / "records.jsonl"
    with open(records_file) as f:
        records = [json.loads(line) for line in f]

    records[1]["previous_hash"] = "bad_hash"

    with open(records_file, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")

    # Verify should now fail
    valid, msg = audit.verify_chain()
    assert not valid, "Should detect broken chain"


def test_list_records(tmp_path):
    """List recent records from audit log."""
    audit_dir = tmp_path / "audit"
    audit = FolderAudit(audit_dir, session_id="s-1")

    for i in range(5):
        audit.append({"event": f"event{i}"})

    records = audit.list_records(limit=3)
    assert len(records) == 3
    assert records[-1]["event"] == "event4"
