"""T11 tests-first: audit upload, device checkpoints, quarantine,
retention guard, ``audit verify --project``.

Interface contract (pinned -- the build removes only xfail markers)
-------------------------------------------------------------------
Client (connector, MIT):
    sandbox.connector.sync.audit_upload
        AuditUploader(layout, device_id, device_key)
            Reads the local audit chain spool per session and uploads
            records to the server in order.  The cursor
            (``.sandbox/state/sync/cursor.json``) tracks
            ``(session_id, chain_length)`` per session.

        upload_records(uploader, connect, token, server_url)
            -> UploadResult
            Uploads pending audit records for all local sessions.
            Each record is POSTed to ``POST /api/v1/sync/audit``.
            Server checks:
              - ``previous_hash`` == stored head (D3.2)
              - ``chain_length`` == head + 1 (D3.2)
              - Same position + same hash = no-op (D3.2)
              - Same position + different hash = fork -> quarantine (D3.2)
              - Gap = refused (D3.2)
            Returns the server head for head compare.

        send_checkpoint(uploader, connect, token, server_url)
            -> CheckpointResult
            Device-signs (``agg/audit-head/v1``) a checkpoint listing
            every local session since enrollment, uploaded or not (S12).
            ``upload_seq`` increments by exactly 1 (S11).
            Server refuses skip / repeat (D3.3, threat 17).
            A session's ``chain_length`` below an earlier checkpoint
            raises ``truncation`` alert (D3.3, threat 15).
            A session listed earlier and missing later raises
            ``session_missing`` (D3.3, threat 32).

        verify_head(uploader, server_head)
            Raises ``server_head_mismatch`` alert if the server head
            is behind what was acknowledged (D3.4, threat 18).

        AuditUploadError

    sandbox.connector.retention  (existing, extended in T11)
        apply()  -- must refuse to delete past the cursor in managed mode
                    (D3.6).

Like process.py, audit_upload is lazy-imported and never imported by
the hook.  A guard test enforces this.

Postgres-free (this file).  Uses ``tests.m2_fakes.FakeSyncServer`` for
HTTP, and test-generated keys for signing.

Covers threats 15 (truncation), 16 (fork -> quarantine), 17 (checkpoint
replay / skip), 18 (server deletes / rewinds audit), 32 (never-uploaded
session deleted -> session_missing), 35 (device_silent after missed
checkpoint window, N6).

RED tests xfail on M2T11Pending.  Guards verify existing code.

T6 rule: the sentinel is raised only by one helper ``_need()`` at the
top of a test; the final assertions are plain ``assert``/``pytest.raises``.
Tests never patch global ``os`` attributes.

Node-id patterns follow M2_BASELINE.md section 5:
  32 -> test_session_missing_alert
  35 -> test_device_silent_after_missed_window
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import time
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from tests.m2_pending import M2T11Pending
from tests.m2_fakes import FakeSyncServer, FakeResponse

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SRC = str(Path(__file__).resolve().parents[2] / "src")


def _need(module: str, attr: str) -> None:
    """Raise M2T11Pending if *module*.*attr* is absent."""
    try:
        mod = __import__(module, fromlist=[attr])
    except ImportError:
        raise M2T11Pending(f"{module} not importable")
    if not hasattr(mod, attr):
        raise M2T11Pending(f"{module}.{attr} not found")


def _ws(path: Path):
    """Create a workspace and return the FolderLayout."""
    from sandbox.connector.install import init
    from sandbox.connector.layout import FolderLayout
    path.mkdir(parents=True, exist_ok=True)
    init(path, claude=False, mcp=False)
    return FolderLayout(path)


def _hook(lay, tool, tool_input):
    from sandbox.connector.hook_eval import pre_tool_use
    out = asyncio.run(pre_tool_use(
        {"tool_name": tool, "tool_input": tool_input,
         "cwd": str(lay.root), "session_id": "t11"},
        lay,
    ))
    hso = out.get("hookSpecificOutput", {})
    return hso.get("permissionDecision"), hso.get("permissionDecisionReason", "")


def _write_audit_records(audit_dir: Path, session_id: str,
                         count: int, *, start_hash: str = "",
                         start_length: int = 0) -> list[dict]:
    """Write *count* valid chained audit records and return them."""
    sess_dir = audit_dir / session_id
    sess_dir.mkdir(parents=True, exist_ok=True)
    records = []
    prev_hash = start_hash
    length = start_length
    for i in range(count):
        body = {"event": "test", "ts": time.time(), "seq": i}
        body_bytes = json.dumps(body, separators=(",", ":"),
                                sort_keys=True).encode()
        record_hash = hashlib.sha256(body_bytes).hexdigest()
        length += 1
        rec = {
            **body,
            "previous_hash": prev_hash,
            "chain_length": length,
            "record_hash": record_hash,
        }
        records.append(rec)
        prev_hash = record_hash
    with open(sess_dir / "records.jsonl", "a", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")
    return records


def _device_keygen():
    """Return (signing_key, pub_bytes, key_id, device_id)."""
    sk = SigningKey.generate()
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    return sk, pub, kid, f"d-{secrets.token_hex(8)}"


def _make_checkpoint_payload(device_id: str, upload_seq: int,
                             sessions: list[dict]) -> dict:
    """Build an agg/audit-head/v1 checkpoint payload."""
    return {
        "device_id": device_id,
        "upload_seq": upload_seq,
        "sessions": sessions,
        "ts": time.time(),
    }


def _sign_envelope(kind: str, payload: dict, sk: SigningKey) -> dict:
    """Sign an agg protocol envelope."""
    tag = kind.encode("utf-8")
    canonical = json.dumps(payload, sort_keys=True,
                           separators=(",", ":")).encode()
    msg = tag + b"\x00" + canonical
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    sig = sk.sign(msg).signature.hex()
    return {
        "kind": kind,
        "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": kid, "alg": "ed25519", "sig": sig}],
    }


# ===================================================================
# Guards (pass now -- existing code)
# ===================================================================


def test_guard_audit_module_importable():
    """Guard: FolderAudit and verify_records_bytes are importable."""
    from sandbox.connector.audit import FolderAudit, verify_records_bytes
    assert callable(FolderAudit)
    assert callable(verify_records_bytes)


def test_guard_session_ids_importable():
    """Guard: session_ids is importable."""
    from sandbox.connector.audit import session_ids
    assert callable(session_ids)


def test_guard_retention_importable():
    """Guard: retention.apply and retention.plan are importable."""
    from sandbox.connector.retention import apply, plan
    assert callable(apply)
    assert callable(plan)


def test_guard_audit_chain_integrity(tmp_path):
    """Guard: a valid local audit chain verifies correctly."""
    from sandbox.connector.audit import FolderAudit, verify_records_bytes
    audit_dir = tmp_path / "audit"
    fa = FolderAudit(audit_dir, "sess1")
    fa.append({"event": "test1", "ts": 1.0})
    fa.append({"event": "test2", "ts": 2.0})
    result = verify_records_bytes(
        (audit_dir / "sess1" / "records.jsonl").read_bytes()
    )
    assert result["ok"], result["message"]
    assert result["records"] == 2


def test_guard_tampered_chain_detected(tmp_path):
    """Guard: a tampered record is detected by verify_records_bytes."""
    from sandbox.connector.audit import FolderAudit, verify_records_bytes
    audit_dir = tmp_path / "audit"
    fa = FolderAudit(audit_dir, "sess1")
    fa.append({"event": "test1", "ts": 1.0})
    fa.append({"event": "test2", "ts": 2.0})
    # Tamper with the second record
    recs_file = audit_dir / "sess1" / "records.jsonl"
    lines = recs_file.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["event"] = "tampered"
    lines[1] = json.dumps(rec)
    recs_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = verify_records_bytes(recs_file.read_bytes())
    assert not result["ok"]


def test_guard_sync_state_dir_protected(tmp_path, monkeypatch):
    """Guard: .sandbox/state/sync/ is a protected sequence (threat 20)."""
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")
    target = str(lay.root / ".sandbox" / "state" / "sync" / "cursor.json")
    decision, _ = _hook(lay, "Write", {"file_path": target, "content": "{}"})
    assert decision == "deny"


# ===================================================================
# Guards: audit cursor file is denied to the agent
# ===================================================================


def test_guard_write_audit_cursor_denied(tmp_path, monkeypatch):
    """Guard: Write tool to .sandbox/state/sync/cursor.json denied."""
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")
    target = str(lay.root / ".sandbox" / "state" / "sync" / "cursor.json")
    decision, _ = _hook(lay, "Write", {"file_path": target, "content": '{"seq": 0}'})
    assert decision == "deny"


def test_guard_edit_audit_cursor_denied(tmp_path, monkeypatch):
    """Guard: Edit tool on .sandbox/state/sync/cursor.json denied."""
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    cursor = sync_dir / "cursor.json"
    cursor.write_text('{"seq": 1}')
    decision, _ = _hook(lay, "Edit", {
        "file_path": str(cursor),
        "old_string": '"seq": 1',
        "new_string": '"seq": 999',
    })
    assert decision == "deny"


SHELL_CURSOR_FORMS = [
    'echo "{}" > .sandbox/state/sync/cursor.json',
    "rm .sandbox/state/sync/cursor.json",
    "cp /tmp/evil.json .sandbox/state/sync/cursor.json",
]


@pytest.mark.parametrize("command", SHELL_CURSOR_FORMS)
def test_guard_shell_audit_cursor_denied(tmp_path, monkeypatch, command):
    """Guard: shell writes to cursor.json are denied."""
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")
    decision, _ = _hook(lay, "Bash", {"command": command})
    assert decision == "deny"


# ===================================================================
# Guard: hook does not import sync.audit_upload (ruling 3)
# ===================================================================


def test_guard_hook_does_not_import_sync_audit_upload(tmp_path, monkeypatch):
    """Guard: pre_tool_use does not import sandbox.connector.sync.audit_upload.

    Like sync.process, audit_upload runs as part of ``sandbox sync``.
    The hook evaluates purely locally and must never import it.
    """
    import sys
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    # Remove the module if cached so we can detect a fresh import
    sys.modules.pop("sandbox.connector.sync.audit_upload", None)
    _hook(lay, "Bash", {"command": "echo safe"})
    assert "sandbox.connector.sync.audit_upload" not in sys.modules, (
        "hook_eval imported sandbox.connector.sync.audit_upload during evaluation"
    )


# ===================================================================
# RED: audit upload -- chain continuity (D3.2)
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_upload_records_in_order(tmp_path, monkeypatch):
    """Audit records are uploaded in session/chain_length order (D3.2).

    Upload 5 records for one session; the uploader sends them in order
    and the fake server returns the server head.
    """
    _need("sandbox.connector.sync.audit_upload", "AuditUploader")
    _need("sandbox.connector.sync.audit_upload", "upload_records")
    from sandbox.connector.sync.audit_upload import AuditUploader, upload_records

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    sk, pub, kid, device_id = _device_keygen()
    recs = _write_audit_records(lay.audit_dir, "sess-a", 5)

    uploaded = []

    def fake_connect(method, url, body=None, headers=None, token=None):
        if method == "POST" and "/sync/audit" in url:
            uploaded.append(body if isinstance(body, dict) else json.loads(body))
            return (200, {"server_head": {
                "session_id": "sess-a",
                "chain_length": len(uploaded),
                "head_hash": recs[len(uploaded) - 1]["record_hash"],
            }}, {})
        return (200, {}, {})

    uploader = AuditUploader(lay, device_id, bytes(sk))
    result = upload_records(uploader, fake_connect, "tok-1", "http://fake")

    assert len(uploaded) == 5
    # Chain lengths must be sequential
    for i, rec in enumerate(uploaded):
        assert rec["chain_length"] == i + 1


@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_upload_resumes_from_cursor(tmp_path, monkeypatch):
    """Upload resumes from where the cursor left off (D3.1).

    Write 10 records, set the cursor to chain_length 5, and verify
    that only records 6-10 are uploaded.
    """
    _need("sandbox.connector.sync.audit_upload", "AuditUploader")
    _need("sandbox.connector.sync.audit_upload", "upload_records")
    from sandbox.connector.sync.audit_upload import AuditUploader, upload_records

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    sk, pub, kid, device_id = _device_keygen()
    recs = _write_audit_records(lay.audit_dir, "sess-a", 10)

    # Pre-set the cursor to chain_length 5
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    cursor = {"sessions": {"sess-a": {"chain_length": 5,
                                       "head_hash": recs[4]["record_hash"]}}}
    (sync_dir / "cursor.json").write_text(json.dumps(cursor), encoding="utf-8")

    uploaded = []

    def fake_connect(method, url, body=None, headers=None, token=None):
        if method == "POST" and "/sync/audit" in url:
            data = body if isinstance(body, dict) else json.loads(body)
            uploaded.append(data)
            return (200, {"server_head": {
                "session_id": "sess-a",
                "chain_length": data["chain_length"],
                "head_hash": data["record_hash"],
            }}, {})
        return (200, {}, {})

    uploader = AuditUploader(lay, device_id, bytes(sk))
    upload_records(uploader, fake_connect, "tok-1", "http://fake")

    assert len(uploaded) == 5
    assert uploaded[0]["chain_length"] == 6


# ===================================================================
# RED: fork detection -> quarantine (D3.2, threat 16)
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_forked_chain_detected(tmp_path, monkeypatch):
    """A forked chain (same position, different hash) is quarantined (D3.2, threat 16).

    The client uploads a record that the server flags as a fork (409).
    The uploader must raise AuditUploadError and not treat the fork as
    success.
    """
    _need("sandbox.connector.sync.audit_upload", "AuditUploader")
    _need("sandbox.connector.sync.audit_upload", "upload_records")
    _need("sandbox.connector.sync.audit_upload", "AuditUploadError")
    from sandbox.connector.sync.audit_upload import (
        AuditUploader, upload_records, AuditUploadError,
    )

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    sk, pub, kid, device_id = _device_keygen()
    _write_audit_records(lay.audit_dir, "sess-a", 3)

    def fake_connect(method, url, body=None, headers=None, token=None):
        if method == "POST" and "/sync/audit" in url:
            # Server says fork on the first record
            return (409, {"error": "fork", "detail": "quarantined"}, {})
        return (200, {}, {})

    uploader = AuditUploader(lay, device_id, bytes(sk))
    with pytest.raises(AuditUploadError, match="fork|quarantine"):
        upload_records(uploader, fake_connect, "tok-1", "http://fake")


@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_reordered_chain_refused(tmp_path, monkeypatch):
    """Records uploaded out of order are refused by the server (D3.2).

    The uploader must send records in chain_length order; the fake
    server returns 400 if the chain_length is not head + 1.
    """
    _need("sandbox.connector.sync.audit_upload", "AuditUploader")
    _need("sandbox.connector.sync.audit_upload", "upload_records")
    _need("sandbox.connector.sync.audit_upload", "AuditUploadError")
    from sandbox.connector.sync.audit_upload import (
        AuditUploader, upload_records, AuditUploadError,
    )

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    sk, pub, kid, device_id = _device_keygen()
    _write_audit_records(lay.audit_dir, "sess-a", 3)

    # Server rejects any record with a gap
    def fake_connect(method, url, body=None, headers=None, token=None):
        if method == "POST" and "/sync/audit" in url:
            return (400, {"error": "gap"}, {})
        return (200, {}, {})

    uploader = AuditUploader(lay, device_id, bytes(sk))
    with pytest.raises(AuditUploadError, match="gap"):
        upload_records(uploader, fake_connect, "tok-1", "http://fake")


@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_truncated_chain_upload(tmp_path, monkeypatch):
    """A truncated local chain (fewer records than cursor) is detected (D3.2).

    Write 5 records, set cursor to 5, then rewrite with only 3.
    The uploader must detect the local truncation.
    """
    _need("sandbox.connector.sync.audit_upload", "AuditUploader")
    _need("sandbox.connector.sync.audit_upload", "upload_records")
    _need("sandbox.connector.sync.audit_upload", "AuditUploadError")
    from sandbox.connector.sync.audit_upload import (
        AuditUploader, upload_records, AuditUploadError,
    )

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    sk, pub, kid, device_id = _device_keygen()
    recs = _write_audit_records(lay.audit_dir, "sess-a", 5)

    # Set cursor to chain_length 5
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    cursor = {"sessions": {"sess-a": {"chain_length": 5,
                                       "head_hash": recs[4]["record_hash"]}}}
    (sync_dir / "cursor.json").write_text(json.dumps(cursor), encoding="utf-8")

    # Truncate: rewrite with only 3 records
    sess_dir = lay.audit_dir / "sess-a"
    with open(sess_dir / "records.jsonl", "w", encoding="utf-8") as f:
        for rec in recs[:3]:
            f.write(json.dumps(rec) + "\n")

    def fake_connect(method, url, body=None, headers=None, token=None):
        return (200, {}, {})

    uploader = AuditUploader(lay, device_id, bytes(sk))
    with pytest.raises(AuditUploadError, match="truncat"):
        upload_records(uploader, fake_connect, "tok-1", "http://fake")


# ===================================================================
# RED: device checkpoint (D3.3, threats 15, 17, 32)
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_checkpoint_upload_seq_increments(tmp_path, monkeypatch):
    """Checkpoint upload_seq increments by exactly 1 each time (D3.3, S11, threat 17)."""
    _need("sandbox.connector.sync.audit_upload", "AuditUploader")
    _need("sandbox.connector.sync.audit_upload", "send_checkpoint")
    from sandbox.connector.sync.audit_upload import AuditUploader, send_checkpoint

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    sk, pub, kid, device_id = _device_keygen()
    _write_audit_records(lay.audit_dir, "sess-a", 3)

    checkpoints_received = []

    def fake_connect(method, url, body=None, headers=None, token=None):
        if method == "POST" and "/sync/checkpoint" in url:
            data = body if isinstance(body, dict) else json.loads(body)
            checkpoints_received.append(data)
            return (200, {"upload_seq": data.get("payload", {}).get("upload_seq")}, {})
        return (200, {}, {})

    uploader = AuditUploader(lay, device_id, bytes(sk))
    send_checkpoint(uploader, fake_connect, "tok-1", "http://fake")
    send_checkpoint(uploader, fake_connect, "tok-1", "http://fake")

    assert len(checkpoints_received) == 2
    seq1 = checkpoints_received[0].get("payload", {}).get("upload_seq")
    seq2 = checkpoints_received[1].get("payload", {}).get("upload_seq")
    assert seq2 == seq1 + 1


@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_checkpoint_replay_refused(tmp_path, monkeypatch):
    """A replayed checkpoint (same upload_seq) is refused (D3.3, threat 17).

    The server returns 400 for a repeated upload_seq.
    """
    _need("sandbox.connector.sync.audit_upload", "AuditUploader")
    _need("sandbox.connector.sync.audit_upload", "send_checkpoint")
    _need("sandbox.connector.sync.audit_upload", "AuditUploadError")
    from sandbox.connector.sync.audit_upload import (
        AuditUploader, send_checkpoint, AuditUploadError,
    )

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    sk, pub, kid, device_id = _device_keygen()
    _write_audit_records(lay.audit_dir, "sess-a", 3)

    call_count = [0]

    def fake_connect(method, url, body=None, headers=None, token=None):
        if method == "POST" and "/sync/checkpoint" in url:
            call_count[0] += 1
            if call_count[0] == 1:
                return (200, {"upload_seq": 1}, {})
            return (400, {"error": "seq_repeat"}, {})
        return (200, {}, {})

    uploader = AuditUploader(lay, device_id, bytes(sk))
    send_checkpoint(uploader, fake_connect, "tok-1", "http://fake")
    with pytest.raises(AuditUploadError, match="seq_repeat|replay"):
        send_checkpoint(uploader, fake_connect, "tok-1", "http://fake")


@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_checkpoint_skip_refused(tmp_path, monkeypatch):
    """A skipped upload_seq is refused (D3.3, threat 17).

    The server returns 400 for a skipped seq.
    """
    _need("sandbox.connector.sync.audit_upload", "AuditUploader")
    _need("sandbox.connector.sync.audit_upload", "send_checkpoint")
    _need("sandbox.connector.sync.audit_upload", "AuditUploadError")
    from sandbox.connector.sync.audit_upload import (
        AuditUploader, send_checkpoint, AuditUploadError,
    )

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    sk, pub, kid, device_id = _device_keygen()
    _write_audit_records(lay.audit_dir, "sess-a", 3)

    def fake_connect(method, url, body=None, headers=None, token=None):
        if method == "POST" and "/sync/checkpoint" in url:
            return (400, {"error": "seq_skip"}, {})
        return (200, {}, {})

    uploader = AuditUploader(lay, device_id, bytes(sk))
    with pytest.raises(AuditUploadError, match="seq_skip|skip"):
        send_checkpoint(uploader, fake_connect, "tok-1", "http://fake")


@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_checkpoint_lists_all_sessions(tmp_path, monkeypatch):
    """Checkpoint lists every local session, uploaded or not (S12, threat 32).

    Write records in 3 sessions, upload only 1.  The checkpoint must
    list all 3 sessions with their current chain_length and head_hash.
    """
    _need("sandbox.connector.sync.audit_upload", "AuditUploader")
    _need("sandbox.connector.sync.audit_upload", "send_checkpoint")
    from sandbox.connector.sync.audit_upload import AuditUploader, send_checkpoint

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    sk, pub, kid, device_id = _device_keygen()
    _write_audit_records(lay.audit_dir, "sess-a", 3)
    _write_audit_records(lay.audit_dir, "sess-b", 5)
    _write_audit_records(lay.audit_dir, "sess-c", 2)

    checkpoint_data = []

    def fake_connect(method, url, body=None, headers=None, token=None):
        if method == "POST" and "/sync/checkpoint" in url:
            data = body if isinstance(body, dict) else json.loads(body)
            checkpoint_data.append(data)
            return (200, {"upload_seq": 1}, {})
        return (200, {}, {})

    uploader = AuditUploader(lay, device_id, bytes(sk))
    send_checkpoint(uploader, fake_connect, "tok-1", "http://fake")

    assert len(checkpoint_data) == 1
    payload = checkpoint_data[0].get("payload", checkpoint_data[0])
    sessions = payload["sessions"]
    session_ids = {s["session_id"] for s in sessions}
    assert session_ids == {"sess-a", "sess-b", "sess-c"}


@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_checkpoint_signed_by_device_key(tmp_path, monkeypatch):
    """Checkpoint is signed with the device key, tag agg/audit-head/v1 (D3.3)."""
    _need("sandbox.connector.sync.audit_upload", "AuditUploader")
    _need("sandbox.connector.sync.audit_upload", "send_checkpoint")
    from sandbox.connector.sync.audit_upload import AuditUploader, send_checkpoint

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    sk, pub, kid, device_id = _device_keygen()
    _write_audit_records(lay.audit_dir, "sess-a", 2)

    envelope_received = []

    def fake_connect(method, url, body=None, headers=None, token=None):
        if method == "POST" and "/sync/checkpoint" in url:
            data = body if isinstance(body, dict) else json.loads(body)
            envelope_received.append(data)
            return (200, {"upload_seq": 1}, {})
        return (200, {}, {})

    uploader = AuditUploader(lay, device_id, bytes(sk))
    send_checkpoint(uploader, fake_connect, "tok-1", "http://fake")

    env = envelope_received[0]
    assert env["kind"] == "agg/audit-head/v1"
    assert env["sig_v"] == 1
    assert len(env["signatures"]) == 1
    assert env["signatures"][0]["key_id"] == kid

    # Verify the signature
    from nacl.signing import VerifyKey
    vk = VerifyKey(pub)
    canonical = json.dumps(env["payload"], sort_keys=True,
                           separators=(",", ":")).encode()
    msg = b"agg/audit-head/v1\x00" + canonical
    sig_bytes = bytes.fromhex(env["signatures"][0]["sig"])
    vk.verify(msg, sig_bytes)  # raises if invalid


@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_session_missing_alert(tmp_path, monkeypatch):
    """A session listed in an earlier checkpoint but missing later raises
    session_missing (D3.3, threat 32).

    Write 2 sessions, checkpoint, delete one, checkpoint again: the second
    checkpoint must still list the deleted session (sessions are since
    enrollment, not just current), OR the server must raise session_missing.
    """
    _need("sandbox.connector.sync.audit_upload", "AuditUploader")
    _need("sandbox.connector.sync.audit_upload", "send_checkpoint")
    from sandbox.connector.sync.audit_upload import AuditUploader, send_checkpoint

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    sk, pub, kid, device_id = _device_keygen()
    _write_audit_records(lay.audit_dir, "sess-a", 3)
    _write_audit_records(lay.audit_dir, "sess-b", 2)

    checkpoints = []

    def fake_connect(method, url, body=None, headers=None, token=None):
        if method == "POST" and "/sync/checkpoint" in url:
            data = body if isinstance(body, dict) else json.loads(body)
            checkpoints.append(data)
            return (200, {"upload_seq": len(checkpoints)}, {})
        return (200, {}, {})

    uploader = AuditUploader(lay, device_id, bytes(sk))
    send_checkpoint(uploader, fake_connect, "tok-1", "http://fake")

    # Both sessions listed in checkpoint 1
    payload1 = checkpoints[0].get("payload", checkpoints[0])
    ids1 = {s["session_id"] for s in payload1["sessions"]}
    assert "sess-a" in ids1 and "sess-b" in ids1

    # Even if sess-b is deleted locally, the checkpoint must still list it.
    # (sessions since enrollment, not just live ones; S12)
    import shutil
    shutil.rmtree(lay.audit_dir / "sess-b")

    send_checkpoint(uploader, fake_connect, "tok-1", "http://fake")
    payload2 = checkpoints[1].get("payload", checkpoints[1])
    ids2 = {s["session_id"] for s in payload2["sessions"]}
    assert "sess-b" in ids2, (
        "Deleted session sess-b must still be listed in checkpoint (S12)"
    )


# ===================================================================
# RED: truncation alert (D3.3, threat 15)
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_truncation_alert_on_shorter_chain(tmp_path, monkeypatch):
    """A session with chain_length below an earlier checkpoint raises
    truncation (D3.3, threat 15).

    Checkpoint with chain_length 5 for sess-a.  Then the local chain
    is rewritten to 3 records.  The next checkpoint must report the
    shorter chain so the server can raise a truncation alert.
    """
    _need("sandbox.connector.sync.audit_upload", "AuditUploader")
    _need("sandbox.connector.sync.audit_upload", "send_checkpoint")
    from sandbox.connector.sync.audit_upload import AuditUploader, send_checkpoint

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    sk, pub, kid, device_id = _device_keygen()
    recs = _write_audit_records(lay.audit_dir, "sess-a", 5)

    checkpoints = []

    def fake_connect(method, url, body=None, headers=None, token=None):
        if method == "POST" and "/sync/checkpoint" in url:
            data = body if isinstance(body, dict) else json.loads(body)
            checkpoints.append(data)
            return (200, {"upload_seq": len(checkpoints)}, {})
        return (200, {}, {})

    uploader = AuditUploader(lay, device_id, bytes(sk))
    send_checkpoint(uploader, fake_connect, "tok-1", "http://fake")

    # Verify first checkpoint has chain_length 5
    payload1 = checkpoints[0].get("payload", checkpoints[0])
    sess_a1 = next(s for s in payload1["sessions"] if s["session_id"] == "sess-a")
    assert sess_a1["chain_length"] == 5

    # Rewrite with only 3 records (truncation)
    sess_dir = lay.audit_dir / "sess-a"
    with open(sess_dir / "records.jsonl", "w", encoding="utf-8") as f:
        for rec in recs[:3]:
            f.write(json.dumps(rec) + "\n")

    # The uploader/checkpoint must detect or faithfully report the shorter chain
    send_checkpoint(uploader, fake_connect, "tok-1", "http://fake")
    payload2 = checkpoints[1].get("payload", checkpoints[1])
    sess_a2 = next(s for s in payload2["sessions"] if s["session_id"] == "sess-a")
    # The checkpoint reports the actual chain_length (3), so the server can detect truncation
    assert sess_a2["chain_length"] == 3


# ===================================================================
# RED: server head compare (D3.4, threat 18)
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_server_head_mismatch_detected(tmp_path, monkeypatch):
    """The connector raises server_head_mismatch when the server's head is
    behind what was acknowledged (D3.4, threat 18).

    Upload 5 records, get server_head at chain_length 5.  Then the server
    returns a head at chain_length 3 (it rewound).  The uploader must
    raise an alert.
    """
    _need("sandbox.connector.sync.audit_upload", "AuditUploader")
    _need("sandbox.connector.sync.audit_upload", "upload_records")
    _need("sandbox.connector.sync.audit_upload", "verify_head")
    from sandbox.connector.sync.audit_upload import (
        AuditUploader, upload_records, verify_head,
    )

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    sk, pub, kid, device_id = _device_keygen()
    recs = _write_audit_records(lay.audit_dir, "sess-a", 5)

    call_count = [0]

    def fake_connect(method, url, body=None, headers=None, token=None):
        if method == "POST" and "/sync/audit" in url:
            call_count[0] += 1
            return (200, {"server_head": {
                "session_id": "sess-a",
                "chain_length": call_count[0],
                "head_hash": recs[call_count[0] - 1]["record_hash"],
            }}, {})
        return (200, {}, {})

    uploader = AuditUploader(lay, device_id, bytes(sk))
    result = upload_records(uploader, fake_connect, "tok-1", "http://fake")

    # Now server claims head is at chain_length 3 (rewound)
    rewound_head = {
        "session_id": "sess-a",
        "chain_length": 3,
        "head_hash": recs[2]["record_hash"],
    }

    # verify_head should detect the mismatch and raise or return alert
    with pytest.raises(Exception, match="server_head_mismatch|head.*mismatch|rewind"):
        verify_head(uploader, rewound_head)


@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_same_position_same_hash_is_noop(tmp_path, monkeypatch):
    """Uploading a record the server already has (same position, same hash)
    is a no-op (D3.2).
    """
    _need("sandbox.connector.sync.audit_upload", "AuditUploader")
    _need("sandbox.connector.sync.audit_upload", "upload_records")
    from sandbox.connector.sync.audit_upload import AuditUploader, upload_records

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    sk, pub, kid, device_id = _device_keygen()
    recs = _write_audit_records(lay.audit_dir, "sess-a", 3)

    # Server already has all 3 records (returns 200 with existing head)
    def fake_connect(method, url, body=None, headers=None, token=None):
        if method == "POST" and "/sync/audit" in url:
            return (200, {"server_head": {
                "session_id": "sess-a",
                "chain_length": 3,
                "head_hash": recs[2]["record_hash"],
                "noop": True,
            }}, {})
        return (200, {}, {})

    uploader = AuditUploader(lay, device_id, bytes(sk))
    # Should succeed without error
    result = upload_records(uploader, fake_connect, "tok-1", "http://fake")
    assert result is not None


# ===================================================================
# RED: retention guard in managed mode (D3.6)
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_retention_refuses_past_cursor(tmp_path, monkeypatch):
    """In managed mode, retention.apply never deletes past the cursor (D3.6).

    Write 3 sessions, set the cursor so only sess-a and sess-b are
    uploaded.  Retention must refuse to delete sess-a and sess-b even
    if they are expired.
    """
    _need("sandbox.connector.sync.audit_upload", "AuditUploader")
    from sandbox.connector.retention import plan as retention_plan
    from sandbox.connector.retention import apply as retention_apply

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    # Mark as managed
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    (sync_dir / "managed").write_text("1")

    # Write sessions with old timestamps (expired)
    for sid in ("sess-a", "sess-b", "sess-c"):
        sess_dir = lay.audit_dir / sid
        sess_dir.mkdir(parents=True, exist_ok=True)
        rec = {
            "event": "test", "ts": 1.0,
            "previous_hash": "", "chain_length": 1,
            "record_hash": hashlib.sha256(b'{"event":"test","ts":1.0}').hexdigest(),
        }
        (sess_dir / "records.jsonl").write_text(json.dumps(rec) + "\n")

    # Write session file for active session
    session_file = lay.root / ".sandbox" / "session.json"
    session_file.write_text(json.dumps({"session_id": "sess-c"}))

    # Set cursor: sess-a uploaded to chain_length 1, sess-b uploaded to chain_length 1
    cursor = {
        "sessions": {
            "sess-a": {"chain_length": 1, "head_hash": "x"},
            "sess-b": {"chain_length": 1, "head_hash": "x"},
        }
    }
    (sync_dir / "cursor.json").write_text(json.dumps(cursor))

    from sandbox.connector.policy import AuditPolicy
    audit_policy = AuditPolicy(retention_days=1,
                                retention_days_reviewed=1,
                                retention_days_incident=1)

    now = time.time() + 86400 * 2  # 2 days later, all sessions expired

    rows = retention_plan(lay, audit_policy, now=now)
    deleted = retention_apply(lay, rows, by="test")

    # sess-a and sess-b must NOT be deleted (past cursor in managed mode)
    # sess-c is the active session, so also not deleted
    # So nothing should be deleted
    assert "sess-a" not in deleted, "retention deleted sess-a past cursor"
    assert "sess-b" not in deleted, "retention deleted sess-b past cursor"


@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_retention_unmanaged_deletes_normally(tmp_path, monkeypatch):
    """In unmanaged mode, retention.apply deletes expired sessions normally.

    Regression: the cursor guard only applies in managed mode (D3.6).
    """
    _need("sandbox.connector.sync.audit_upload", "AuditUploader")
    from sandbox.connector.retention import plan as retention_plan
    from sandbox.connector.retention import apply as retention_apply

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    # NOT managed -- no managed marker

    for sid in ("sess-a", "sess-b"):
        sess_dir = lay.audit_dir / sid
        sess_dir.mkdir(parents=True, exist_ok=True)
        rec = {
            "event": "test", "ts": 1.0,
            "previous_hash": "", "chain_length": 1,
            "record_hash": hashlib.sha256(b'{"event":"test","ts":1.0}').hexdigest(),
        }
        (sess_dir / "records.jsonl").write_text(json.dumps(rec) + "\n")

    # Active session is sess-b
    session_file = lay.root / ".sandbox" / "session.json"
    session_file.write_text(json.dumps({"session_id": "sess-b"}))

    from sandbox.connector.policy import AuditPolicy
    audit_policy = AuditPolicy(retention_days=1,
                                retention_days_reviewed=1,
                                retention_days_incident=1)

    now = time.time() + 86400 * 2
    rows = retention_plan(lay, audit_policy, now=now)
    deleted = retention_apply(lay, rows, by="test")

    # sess-a should be deleted (expired, not active, not managed)
    assert "sess-a" in deleted


# ===================================================================
# RED: quarantine is not silently cleared
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_quarantine_not_silently_cleared(tmp_path, monkeypatch):
    """Quarantined records are never silently cleared (D3.2).

    Once a fork is quarantined, the quarantine entry persists regardless
    of subsequent uploads.  The original chain remains intact.
    """
    _need("sandbox.connector.sync.audit_upload", "AuditUploader")
    _need("sandbox.connector.sync.audit_upload", "upload_records")
    from sandbox.connector.sync.audit_upload import AuditUploader, upload_records

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    sk, pub, kid, device_id = _device_keygen()
    _write_audit_records(lay.audit_dir, "sess-a", 5)

    fork_reported = []
    quarantine_cleared = [False]

    def fake_connect(method, url, body=None, headers=None, token=None):
        if method == "POST" and "/sync/audit" in url:
            data = body if isinstance(body, dict) else json.loads(body)
            if data.get("chain_length") == 3:
                fork_reported.append(True)
                return (409, {"error": "fork", "quarantined": True}, {})
            return (200, {"server_head": {
                "session_id": "sess-a",
                "chain_length": data["chain_length"],
                "head_hash": data["record_hash"],
            }}, {})
        return (200, {}, {})

    uploader = AuditUploader(lay, device_id, bytes(sk))
    # The upload should report the fork, not silently continue
    try:
        upload_records(uploader, fake_connect, "tok-1", "http://fake")
    except Exception:
        pass

    assert len(fork_reported) >= 1, "Fork not reported to client"


# ===================================================================
# RED: upload from revoked device (D1.5)
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_upload_from_revoked_device_refused(tmp_path, monkeypatch):
    """An upload from a revoked device gets 401 (D1.5).

    The server refuses the upload; the uploader must handle the 401
    gracefully and not mark any record as uploaded.
    """
    _need("sandbox.connector.sync.audit_upload", "AuditUploader")
    _need("sandbox.connector.sync.audit_upload", "upload_records")
    _need("sandbox.connector.sync.audit_upload", "AuditUploadError")
    from sandbox.connector.sync.audit_upload import (
        AuditUploader, upload_records, AuditUploadError,
    )

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    sk, pub, kid, device_id = _device_keygen()
    _write_audit_records(lay.audit_dir, "sess-a", 3)

    def fake_connect(method, url, body=None, headers=None, token=None):
        return (401, {"error": "device_revoked"}, {})

    uploader = AuditUploader(lay, device_id, bytes(sk))
    with pytest.raises(AuditUploadError, match="revoked|401"):
        upload_records(uploader, fake_connect, "tok-1", "http://fake")


# ===================================================================
# RED: upload for another org or project
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_upload_cross_org_refused(tmp_path, monkeypatch):
    """An audit upload to a server that returns 404 (cross-org) is
    handled as an error.
    """
    _need("sandbox.connector.sync.audit_upload", "AuditUploader")
    _need("sandbox.connector.sync.audit_upload", "upload_records")
    _need("sandbox.connector.sync.audit_upload", "AuditUploadError")
    from sandbox.connector.sync.audit_upload import (
        AuditUploader, upload_records, AuditUploadError,
    )

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    sk, pub, kid, device_id = _device_keygen()
    _write_audit_records(lay.audit_dir, "sess-a", 2)

    def fake_connect(method, url, body=None, headers=None, token=None):
        return (404, {"error": "not_found"}, {})

    uploader = AuditUploader(lay, device_id, bytes(sk))
    with pytest.raises(AuditUploadError):
        upload_records(uploader, fake_connect, "tok-1", "http://fake")
