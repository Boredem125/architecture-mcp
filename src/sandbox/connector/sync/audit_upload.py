"""Client-side audit upload: reads the local audit chain spool and
uploads records to the control plane in order (D3, T11).

This module is lazy-imported from ``sync.process.run_once``.
The hook must never import it -- a guard test enforces this.

Design invariants:
  - The cursor (``.sandbox/state/sync/cursor.json``) tracks
    ``(session_id, chain_length)`` per session.
  - Records are uploaded in chain_length order per session.
  - The cursor sits under the non-removable deny (threat 20).
  - ``upload_seq`` increments by exactly 1 per checkpoint (S11).
  - Every local session since enrollment is listed in the checkpoint (S12).
  - Records go up as ``{session_id, records:[{chain_length, previous_hash,
    record_hash, body}]}`` chunked under the server caps (1000 records,
    1 MiB), ADR 0001 5.2/A4.1 (T16g G7-B).
  - The local chain is re-verified (``verify_records_bytes``) before any
    record of a session is sent.
  - The cursor moves only after a 200 whose ``server_head`` matches the
    batch end; otherwise ``server_head_mismatch`` is reported.
  - Every failure is typed (``AuditUploadError.errors``): ``audit_fork``
    on 409, ``audit_truncation_local`` when the cursor is past the local
    chain, ``audit_upload_failed`` with the HTTP status on any other
    4xx/5xx.  Nothing is swallowed; the caller alerts and audits.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Callable


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AuditUploadError(Exception):
    """Typed audit upload failure.

    ``errors`` is a list of ``{kind, status, session_id, reason}`` dicts,
    one per failed session (plus the checkpoint).  ``kind`` is one of
    ``audit_fork``, ``audit_truncation_local``, ``audit_upload_failed`` or
    ``server_head_mismatch``.  The message joins every reason.
    """

    def __init__(
        self,
        message: str,
        *,
        kind: str = "audit_upload_failed",
        status: int | None = None,
        session_id: str | None = None,
        errors: list[dict] | None = None,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.status = status
        self.session_id = session_id
        self.errors: list[dict] = errors if errors is not None else [{
            "kind": kind, "status": status,
            "session_id": session_id, "reason": message,
        }]


#: Server caps (ee/src/agg_cp/sync/audit_upload.py): a batch is refused
#: 413 above either.  The connector chunks strictly below both.
MAX_BATCH_RECORDS: int = 1000
MAX_BATCH_BYTES: int = 1_048_576


# ---------------------------------------------------------------------------
# AuditUploader
# ---------------------------------------------------------------------------


class AuditUploader:
    """Holds the layout, device identity and upload state.

    Parameters
    ----------
    layout : FolderLayout
        The workspace layout (provides ``audit_dir`` and state paths).
    device_id : str
        The enrolled device id.
    device_key : bytes
        The 32-byte Ed25519 signing key seed.
    """

    def __init__(self, layout: Any, device_id: str, device_key: bytes) -> None:
        self.layout = layout
        self.device_id = device_id
        self._device_key = device_key

        # Lazily initialised state
        self._cursor: dict | None = None
        # Track acknowledged server heads per session for verify_head
        self._acked_heads: dict[str, dict] = {}
        # Tracks all known session ids across the lifetime (for S12)
        self._known_sessions: set[str] = set()

    # -- cursor persistence ------------------------------------------------

    @property
    def _cursor_path(self) -> Path:
        return self.layout.root / ".sandbox" / "state" / "sync" / "cursor.json"

    def _load_cursor(self) -> dict:
        if self._cursor is not None:
            return self._cursor
        try:
            self._cursor = json.loads(
                self._cursor_path.read_text(encoding="utf-8"),
            )
        except (OSError, ValueError):
            self._cursor = {"sessions": {}, "upload_seq": 0}
        # Initialise known sessions from cursor
        for sid in self._cursor.get("sessions", {}):
            self._known_sessions.add(sid)
        return self._cursor

    def _save_cursor(self) -> None:
        cursor = self._load_cursor()
        p = self._cursor_path
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(cursor), encoding="utf-8")
        import os
        os.replace(str(tmp), str(p))

    # -- signing -----------------------------------------------------------

    def _sign_envelope(self, kind: str, payload: dict) -> dict:
        """Sign an ``agg`` protocol envelope with the device key."""
        from nacl.signing import SigningKey

        sk = SigningKey(self._device_key[:32])
        tag = kind.encode("utf-8")
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
        ).encode()
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


# ---------------------------------------------------------------------------
# upload_records
# ---------------------------------------------------------------------------


def upload_records(
    uploader: AuditUploader,
    connect: Callable[..., tuple[int, dict, dict]],
    token: str,
    server_url: str,
) -> dict:
    """Upload pending audit records for all local sessions.

    Every session is attempted (a fork in one session never blocks the
    others).  Returns ``{"uploaded", "server_head", "errors"}`` where
    ``errors`` holds non-raising problems (``server_head_mismatch``).
    Raises :class:`AuditUploadError` carrying every per-session failure
    (fork, local truncation, 4xx/5xx) after all sessions were tried.
    Transport exceptions (network) propagate unchanged.
    """
    from sandbox.connector.audit import session_ids

    uploader._load_cursor()
    audit_dir = uploader.layout.audit_dir

    total_uploaded = 0
    last_server_head: dict | None = None
    raised: list[dict] = []
    soft: list[dict] = []

    local_sessions = session_ids(audit_dir)
    for sid in local_sessions:
        uploader._known_sessions.add(sid)

    url = f"{server_url.rstrip('/')}/api/v1/sync/audit"
    for sid in local_sessions:
        try:
            n, head, mismatch = _upload_session(uploader, sid, connect, token, url)
        except AuditUploadError as exc:
            raised.extend(exc.errors)
            continue
        total_uploaded += n
        if head:
            last_server_head = head
        if mismatch is not None:
            soft.append(mismatch)

    if raised:
        raise AuditUploadError(
            "; ".join(str(e.get("reason", "")) for e in raised),
            errors=raised + soft,
        )
    return {
        "uploaded": total_uploaded,
        "server_head": last_server_head,
        "errors": soft,
    }


def _upload_session(
    uploader: AuditUploader,
    sid: str,
    connect: Callable[..., tuple[int, dict, dict]],
    token: str,
    url: str,
) -> tuple[int, dict | None, dict | None]:
    """Upload one session's pending records in chunks.

    Returns ``(uploaded_count, last_server_head, mismatch_error_or_None)``.
    Raises :class:`AuditUploadError` on local truncation, an invalid local
    chain, a fork (409) or any other non-2xx.
    """
    from sandbox.connector.audit import CHAIN_FIELDS, verify_records_bytes

    records_file = uploader.layout.audit_dir / sid / "records.jsonl"
    if not records_file.exists():
        return 0, None, None

    cursor = uploader._load_cursor()
    sessions = cursor.setdefault("sessions", {})
    sess_cursor = sessions.get(sid, {}) or {}
    cursor_length = sess_cursor.get("chain_length", 0)
    if not isinstance(cursor_length, int) or isinstance(cursor_length, bool):
        cursor_length = 0
    cursor_head = sess_cursor.get("head_hash", "")

    data = records_file.read_bytes()

    # Verify the local chain before anything leaves the machine.
    check = verify_records_bytes(data)
    if not check.get("ok"):
        raise AuditUploadError(
            f"local audit chain invalid for session {sid}: "
            f"{check.get('message', '')}",
            kind="audit_upload_failed", session_id=sid,
        )

    all_records: list[dict] = []
    for raw in data.split(b"\n"):
        if raw.strip():
            all_records.append(json.loads(raw.decode("utf-8")))

    # Local truncation: the cursor is past the local chain.
    if len(all_records) < cursor_length:
        raise AuditUploadError(
            f"truncation detected for session {sid}: local has "
            f"{len(all_records)} records but cursor at {cursor_length}",
            kind="audit_truncation_local", session_id=sid,
        )
    # Rewrite under the cursor: the uploaded head no longer matches.
    if cursor_length > 0 and cursor_head and (
        all_records[cursor_length - 1].get("record_hash") != cursor_head
    ):
        raise AuditUploadError(
            f"truncation detected for session {sid}: record "
            f"{cursor_length} no longer matches the uploaded head_hash "
            "(uploaded records rewritten)",
            kind="audit_truncation_local", session_id=sid,
        )

    pending = [r for r in all_records if r.get("chain_length", 0) > cursor_length]
    pending.sort(key=lambda r: r.get("chain_length", 0))

    uploaded = 0
    last_head: dict | None = None

    def _wire(rec: dict) -> dict:
        return {
            "chain_length": rec["chain_length"],
            "previous_hash": rec["previous_hash"],
            "record_hash": rec["record_hash"],
            "body": {k: v for k, v in rec.items() if k not in CHAIN_FIELDS},
        }

    i = 0
    while i < len(pending):
        batch: list[dict] = []
        batch_src: list[dict] = []
        while i < len(pending) and len(batch) < MAX_BATCH_RECORDS:
            candidate = batch + [_wire(pending[i])]
            size = len(json.dumps({"session_id": sid, "records": candidate}).encode("utf-8"))
            if size >= MAX_BATCH_BYTES:
                if not batch:
                    raise AuditUploadError(
                        f"record {pending[i].get('chain_length')} of session "
                        f"{sid} alone exceeds the {MAX_BATCH_BYTES} byte cap",
                        kind="audit_upload_failed", session_id=sid,
                    )
                break
            batch = candidate
            batch_src.append(pending[i])
            i += 1

        status, resp_body, _hdrs = connect(
            "POST", url, body={"session_id": sid, "records": batch}, token=token,
        )
        if not isinstance(resp_body, dict):
            resp_body = {}
        # Server-controlled text: cap what lands in the local audit record.
        err = str(resp_body.get("error", "unknown"))[:200]

        if status == 409:
            raise AuditUploadError(
                f"fork/quarantine (409) for session {sid}: {err}",
                kind="audit_fork", status=409, session_id=sid,
            )
        if status == 400:
            raise AuditUploadError(
                f"gap or chain error (400) for session {sid}: {err}",
                status=400, session_id=sid,
            )
        if status == 401:
            raise AuditUploadError(
                f"device revoked or unauthorized (401) for session {sid}: {err}",
                status=401, session_id=sid,
            )
        if status == 413:
            raise AuditUploadError(
                f"batch too large (413) for session {sid}: {err}",
                status=413, session_id=sid,
            )
        if status < 200 or status >= 300:
            raise AuditUploadError(
                f"upload failed ({status}) for session {sid}: {err}",
                status=status, session_id=sid,
            )

        last_src = batch_src[-1]
        # A 200 is an all-or-nothing ack of the batch: that is the head
        # ``verify_head`` compares later server heads against (D3.4).
        uploader._acked_heads[sid] = {
            "session_id": sid,
            "chain_length": last_src["chain_length"],
            "head_hash": last_src["record_hash"],
        }
        server_head = resp_body.get("server_head")
        if (
            not isinstance(server_head, dict)
            or server_head.get("chain_length") != last_src["chain_length"]
            or server_head.get("head_hash") != last_src["record_hash"]
        ):
            # A 200 whose head is not the batch end: the cursor stays and
            # the caller alerts server_head_mismatch (ADR 0001 A4.3).
            return uploaded, last_head, {
                "kind": "server_head_mismatch", "status": status,
                "session_id": sid,
                "reason": (
                    f"server_head_mismatch for session {sid}: batch ended at "
                    f"chain_length {last_src['chain_length']} but the server "
                    f"head is {server_head!r}"
                ),
            }

        # Cursor moves only after a matching 200.
        sessions[sid] = {
            "chain_length": last_src["chain_length"],
            "head_hash": last_src["record_hash"],
        }
        uploader._save_cursor()
        last_head = server_head
        uploaded += len(batch)

    return uploaded, last_head, None


# ---------------------------------------------------------------------------
# send_checkpoint
# ---------------------------------------------------------------------------


def send_checkpoint(
    uploader: AuditUploader,
    connect: Callable[..., tuple[int, dict, dict]],
    token: str,
    server_url: str,
) -> dict:
    """Send a device-signed checkpoint listing every local session (S12).

    Returns the server's acknowledged ``upload_seq``.
    """
    from sandbox.connector.audit import session_ids

    cursor = uploader._load_cursor()
    audit_dir = uploader.layout.audit_dir

    # Discover all local sessions and merge with known sessions
    local_sessions = session_ids(audit_dir)
    for sid in local_sessions:
        uploader._known_sessions.add(sid)
    # Also include sessions from the cursor (even if dir was deleted)
    for sid in cursor.get("sessions", {}):
        uploader._known_sessions.add(sid)

    # Build session list
    sessions_list = []
    for sid in sorted(uploader._known_sessions):
        records_file = audit_dir / sid / "records.jsonl"
        if records_file.exists():
            # Read the actual chain to get current length and head
            chain_length = 0
            head_hash = ""
            with open(records_file, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            rec = json.loads(line)
                            chain_length = rec.get("chain_length", chain_length)
                            head_hash = rec.get("record_hash", head_hash)
                        except (ValueError, json.JSONDecodeError):
                            continue
            sessions_list.append({
                "session_id": sid,
                "chain_length": chain_length,
                "head_hash": head_hash,
            })
        else:
            # Session was deleted locally but we still report it (S12)
            sess_cursor = cursor.get("sessions", {}).get(sid, {})
            sessions_list.append({
                "session_id": sid,
                "chain_length": sess_cursor.get("chain_length", 0),
                "head_hash": sess_cursor.get("head_hash", ""),
            })

    # Increment upload_seq
    upload_seq = cursor.get("upload_seq", 0) + 1

    payload = {
        "device_id": uploader.device_id,
        "upload_seq": upload_seq,
        "sessions": sessions_list,
        "ts": time.time(),
    }

    envelope = uploader._sign_envelope("agg/audit-head/v1", payload)

    url = f"{server_url.rstrip('/')}/api/v1/sync/checkpoint"
    status, resp_body, _hdrs = connect(
        "POST", url, body=envelope, token=token,
    )

    if not isinstance(resp_body, dict):
        resp_body = {}
    if status == 400:
        error = resp_body.get("error", "unknown")
        raise AuditUploadError(
            f"checkpoint refused (400): {error}", status=400,
        )
    if status == 401:
        raise AuditUploadError("checkpoint unauthorized (401)", status=401)
    if status < 200 or status >= 300:
        raise AuditUploadError(
            f"checkpoint failed ({status}): {resp_body.get('error', 'unknown')}",
            status=status,
        )

    # Persist the new upload_seq
    cursor["upload_seq"] = upload_seq
    uploader._save_cursor()

    return {"upload_seq": upload_seq}


# ---------------------------------------------------------------------------
# verify_head
# ---------------------------------------------------------------------------


def verify_head(uploader: AuditUploader, server_head: dict) -> None:
    """Raise if the server's head is behind what was acknowledged (D3.4, threat 18).

    ``server_head`` is ``{session_id, chain_length, head_hash}``.
    """
    sid = server_head.get("session_id", "")
    acked = uploader._acked_heads.get(sid)
    if acked is None:
        return  # nothing acknowledged yet for this session

    acked_length = acked.get("chain_length", 0)
    server_length = server_head.get("chain_length", 0)

    if server_length < acked_length:
        raise AuditUploadError(
            f"server_head_mismatch: server head for {sid} is at "
            f"chain_length {server_length} but we acknowledged {acked_length} "
            f"(server rewound/deleted audit records)",
            kind="server_head_mismatch", session_id=sid,
        )
