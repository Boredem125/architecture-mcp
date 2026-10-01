"""FolderAudit — cross-process safe chained append without in-memory state.

Takes an advisory lock on `.sandbox/audit/.lock`, reads the last line of
`<session_id>/records.jsonl` for chain state, appends a new record, fsync,
then releases. Multiple processes coordinate via the file system alone.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from sandbox.audit.chain import HashChain
from sandbox.models.audit import AuditRecord


class FolderAudit:
    """Append-only audit log with cross-process coordination via the file system."""

    def __init__(self, audit_dir: Path, session_id: str = ""):
        self.audit_dir = Path(audit_dir)
        self.session_id = session_id or "default"
        self.lock_file = self.audit_dir / ".lock"
        self.records_file = self.audit_dir / self.session_id / "records.jsonl"

        # Ensure directories exist
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        (self.audit_dir / self.session_id).mkdir(parents=True, exist_ok=True)

    def append(self, record: dict[str, Any]) -> None:
        """Atomically append a record to the audit log with chain integrity.

        Acquires a lock, loads the current chain state from disk, computes
        the next hash, appends, fsync, then releases.
        """
        self._with_lock(self._append_locked, record)

    def _with_lock(self, fn, *args, **kwargs):
        """Context-manager replacement: acquire lock, call fn, release.

        On Windows, we use a simple check-and-create loop since fcntl
        isn't available. This is good enough for approval workflows
        (low contention, short critical section).
        """
        import time

        lock_taken = False
        try:
            # Try to create lock file exclusively (non-blocking on Windows)
            for _ in range(100):
                try:
                    # This raises if file exists (mode 'x')
                    with open(self.lock_file, "x") as _:
                        lock_taken = True
                        break
                except FileExistsError:
                    time.sleep(0.01)

            if not lock_taken:
                raise TimeoutError(f"Could not acquire audit lock after 1s")

            return fn(*args, **kwargs)
        finally:
            if lock_taken:
                try:
                    self.lock_file.unlink()
                except OSError:
                    pass

    def _append_locked(self, record: dict[str, Any]) -> None:
        """Append under lock. Caller holds the lock."""
        # Load current chain state from the last line of records.jsonl
        chain = self._load_chain()

        # Compute next record's hash
        record_bytes = json.dumps(record, separators=(",", ":"), sort_keys=True).encode("utf-8")
        record_hash = hashlib.sha256(record_bytes).hexdigest()

        # Build the chained record
        chained = dict(record)
        chained["previous_hash"] = chain.current_hash
        chained["chain_length"] = chain.chain_length + 1
        chained["record_hash"] = record_hash

        # Append to records.jsonl
        with open(self.records_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(chained) + "\n")
            f.flush()
            # fsync not available on all platforms, but we tried
            try:
                import os

                os.fsync(f.fileno())
            except (AttributeError, OSError):
                pass

    def _load_chain(self) -> HashChain:
        """Load chain state from the last valid line of records.jsonl."""
        if not self.records_file.exists():
            return HashChain(previous_hash="", chain_length=0)

        try:
            # Read backwards to find the last valid JSON line
            with open(self.records_file, "rb") as f:
                # Seek to end and read backwards
                f.seek(0, 2)
                pos = f.tell()

                # Read up to 4KB of tail
                read_size = min(pos, 4096)
                f.seek(pos - read_size)
                tail = f.read().decode("utf-8", errors="ignore")

            # Split on newlines and find the last valid JSON object
            for line in reversed(tail.split("\n")):
                if line.strip():
                    try:
                        obj = json.loads(line)
                        return HashChain(
                            previous_hash=obj.get("record_hash", ""),
                            chain_length=obj.get("chain_length", 0),
                        )
                    except json.JSONDecodeError:
                        pass

            # No valid records found, start fresh
            return HashChain(previous_hash="", chain_length=0)
        except (OSError, UnicodeDecodeError):
            return HashChain(previous_hash="", chain_length=0)

    def verify_chain(self) -> tuple[bool, str]:
        """Verify this session's chain: links AND each record's own hash.

        Returns (is_valid, message). See verify_records_bytes.
        """
        if not self.records_file.exists():
            return True, "No records"
        try:
            result = verify_records_bytes(self.records_file.read_bytes())
        except OSError as e:
            return False, f"Verification failed: {e}"
        return result["ok"], result["message"]

    def list_records(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the last N records from the audit log."""
        if not self.records_file.exists():
            return []

        records = []
        try:
            with open(self.records_file, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except OSError:
            pass

        return records[-limit:]


# Fields FolderAudit.append adds; record_hash covers everything else.
CHAIN_FIELDS = ("previous_hash", "chain_length", "record_hash")


def verify_records_bytes(data: bytes) -> dict[str, Any]:
    """Re-verify one ``records.jsonl``: the links between records and each
    record's own hash, so editing a record's content is caught even when the
    links are left intact.

    Returns {"ok", "message", "records", "head_hash"}. Deleting the *last*
    records (or rewriting the last one with its hash) is not detectable from
    the file alone: compare ``head_hash`` with one recorded elsewhere (e.g.
    ``sandbox verify --expect-head``, or an evidence pack's manifest).
    """
    prev, length = "", 0
    for i, raw in enumerate(data.split(b"\n"), start=1):
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"ok": False, "message": f"line {i}: not valid JSON", "records": length, "head_hash": prev}
        if not isinstance(rec, dict):
            return {"ok": False, "message": f"line {i}: not a JSON object", "records": length, "head_hash": prev}
        if rec.get("previous_hash") != prev:
            return {"ok": False, "message": f"line {i}: chain broken (previous_hash does not match line before)",
                    "records": length, "head_hash": prev}
        if rec.get("chain_length") != length + 1:
            return {"ok": False, "records": length, "head_hash": prev,
                    "message": f"line {i}: chain_length is {rec.get('chain_length')}, expected {length + 1}"}
        body = {k: v for k, v in rec.items() if k not in CHAIN_FIELDS}
        computed = hashlib.sha256(json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest()
        if rec.get("record_hash") != computed:
            return {"ok": False, "message": f"line {i}: record content does not match its record_hash",
                    "records": length, "head_hash": prev}
        prev, length = computed, length + 1
    return {"ok": True, "message": f"chain valid ({length} records)", "records": length, "head_hash": prev}


def session_ids(audit_dir: Path) -> list[str]:
    """Every session that has an audit chain under ``audit_dir``."""
    audit_dir = Path(audit_dir)
    if not audit_dir.is_dir():
        return []
    return sorted(p.name for p in audit_dir.iterdir() if (p / "records.jsonl").is_file())
