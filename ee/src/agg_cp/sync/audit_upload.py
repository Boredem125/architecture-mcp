"""Server-side audit upload routes (D3, T11).

POST /api/v1/sync/audit    -- device token auth, batch upload
POST /api/v1/sync/checkpoint -- device token auth, signed checkpoint

Connections ``SET ROLE agg_app`` like enroll.py/signer.py/bundles.py.
Auth pattern matches GET /api/v1/sync/registry and /sync/bundle.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from typing import Any

import psycopg
import psycopg.errors
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..rbac import rbac_route
from .audit import (
    MAX_NESTING_DEPTH, canonical_record_bytes, json_nesting_depth,
)


def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


_MAX_RECORDS = 1000
_MAX_BODY_BYTES = 1_048_576  # 1 MiB
_MAX_SESSION_ID_LEN = 256  # T1-18
_MAX_HASH_LEN = 128  # T1-18


# T1-26: the batch is {"session_id": "...", "records": [...]} with the
# session first (connector sync/audit_upload.py).  When the parser cannot
# read the request at all, this finds the batch session_id in the raw
# bytes so the parser-path alert is keyed per connector AND session.
_RAW_SESSION_ID_RE = re.compile(
    rb'"session_id"\s*:\s*("(?:[^"\\]|\\.)*")',
)


def _session_id_from_raw(raw_body: bytes) -> str | None:
    """Best-effort batch ``session_id`` from unparsed request bytes.

    Used only on the ``RecursionError`` path, where ``json.loads`` has
    refused the whole request.  Takes the first ``"session_id"`` string
    literal, decodes it as a JSON string, and applies the same rules as
    the parsed path (non-empty, at most ``_MAX_SESSION_ID_LEN``, no
    NUL, UTF-8 encodable).  ``None`` when nothing valid is found; the
    caller then deduplicates on the reason alone.
    """
    m = _RAW_SESSION_ID_RE.search(raw_body)
    if m is None:
        return None
    try:
        sid = json.loads(m.group(1).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(sid, str) or not sid:
        return None
    if len(sid) > _MAX_SESSION_ID_LEN or "\x00" in sid:
        return None
    try:
        sid.encode("utf-8")
    except UnicodeEncodeError:
        return None
    return sid


def _alert_unstorable(
    conn, d_org: str, d_project: str, d_connector: str, detail: dict,
) -> None:
    """Record ONE ``audit_record_unstorable`` alert for *detail*.

    The single helper behind every refusal of an unstorable body: NaN or
    Infinity (``canonical_record_bytes`` returns None), the fixed nesting
    limit (T1-26), a body deeper than the JSON parser allows
    (``RecursionError``), and Postgres ``DataError`` or
    ``StatementTooComplex`` at insert (T1-14, T1-25).

    Rolls back whatever the request had written (a 400 stores no
    record), re-applies the role and org context, then inserts the
    alert only when no alert for this connector already carries
    *detail* (``detail @> %s``), so repeated refusals of the same body
    stay at one row (T1-18).  Commits.  *detail* is the deduplication
    key: ``{session_id, chain_length}`` for a record position,
    ``{reason}`` for the parser path where no record can be read.
    """
    conn.rollback()
    conn.execute("SET ROLE agg_app")
    conn.execute(
        "SELECT set_config('app.org_id', %s, true)", [d_org],
    )
    detail_json = json.dumps(detail, sort_keys=True)
    already = conn.execute(
        "SELECT 1 FROM sync_alerts "
        "WHERE connector_id = %s::uuid "
        "AND kind = 'audit_record_unstorable' "
        "AND detail @> %s::jsonb "
        "LIMIT 1",
        [d_connector, detail_json],
    ).fetchone()
    if not already:
        conn.execute(
            "INSERT INTO sync_alerts "
            "(id, org_id, project_id, connector_id, "
            "kind, detail, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, "
            "'audit_record_unstorable', %s::jsonb, now())",
            [str(uuid.uuid4()), d_org, d_project, d_connector, detail_json],
        )
    conn.commit()


def audit_upload_router(db_url: str, clock=None) -> APIRouter:
    """Build the audit upload router."""
    conninfo = _conninfo(db_url)
    router = APIRouter()

    def _conn():
        c = psycopg.connect(conninfo)
        c.execute("SET ROLE agg_app")
        return c

    def _device_token_lookup(conn, token: str):
        """Look up a device token via SECURITY DEFINER function.

        Returns (org_id, project_id, connector_id) or None.
        """
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        row = conn.execute(
            "SELECT * FROM device_token_lookup(%s)",
            [token_hash],
        ).fetchone()
        return row

    def _get_device_public_key(conn, connector_id: str) -> str | None:
        """Look up the device public key for a connector."""
        row = conn.execute(
            "SELECT * FROM device_lookup(%s::uuid)",
            [connector_id],
        ).fetchone()
        if row is None:
            return None
        # device_lookup returns (org_id, project_id, connector_id, public_key, revoked_at)
        return row[3]  # public_key (hex)

    def _verify_envelope_signature(
        envelope: dict, expected_pub_hex: str,
    ) -> bool:
        """Verify an agg protocol envelope signature against the expected public key."""
        try:
            from nacl.signing import VerifyKey

            kind = envelope.get("kind", "")
            payload = envelope.get("payload", {})
            sigs = envelope.get("signatures", [])
            if not sigs:
                return False

            sig_entry = sigs[0]
            expected_kid = hashlib.sha256(
                bytes.fromhex(expected_pub_hex),
            ).hexdigest()

            if sig_entry.get("key_id") != expected_kid:
                return False

            tag = kind.encode("utf-8")
            canonical = json.dumps(
                payload, sort_keys=True, separators=(",", ":"),
            ).encode()
            msg = tag + b"\x00" + canonical

            vk = VerifyKey(bytes.fromhex(expected_pub_hex))
            sig_bytes = bytes.fromhex(sig_entry["sig"])
            vk.verify(msg, sig_bytes)
            return True
        except Exception:
            return False

    # -----------------------------------------------------------------
    # POST /api/v1/sync/audit (device token auth)
    # -----------------------------------------------------------------
    @rbac_route(
        router, "post", "/api/v1/sync/audit",
        role="device", scope="project",
    )
    async def upload_audit_records(request: Request) -> JSONResponse:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        token = auth[7:]

        # Read raw body for size check
        raw_body = await request.body()
        if len(raw_body) > _MAX_BODY_BYTES:
            return JSONResponse(
                {"error": "body_too_large"},
                status_code=413,
            )

        try:
            body = json.loads(raw_body)
        except (ValueError, json.JSONDecodeError):
            return JSONResponse({"error": "invalid_json"}, status_code=400)
        except RecursionError:
            # T1-15/T1-26: the request is nested deeper than this
            # platform's JSON parser allows (2,997 levels on Windows
            # 3.12, more on Linux), so no record or position can be
            # read.  The token is in the header: identify the device
            # and record one alert per connector and session (the
            # session lifted from the raw bytes when it can be, else
            # per connector), deduplicated so 40 such requests give
            # 1 row (T1-18).
            detail: dict[str, Any] = {"reason": "recursion_depth_exceeded"}
            raw_sid = _session_id_from_raw(raw_body)
            if raw_sid is not None:
                detail["session_id"] = raw_sid
            with _conn() as conn:
                device = _device_token_lookup(conn, token)
                if device is None:
                    return JSONResponse(
                        {"error": "unauthorized"}, status_code=401,
                    )
                _alert_unstorable(
                    conn, str(device[0]), str(device[1]), str(device[2]),
                    detail,
                )
            return JSONResponse(
                {"error": "audit_record_unstorable",
                 "detail": "body too deeply nested"},
                status_code=400,
            )

        # T16g G7-B: the batch contract is {session_id, records:[...]}.
        if not isinstance(body, dict):
            return JSONResponse({"error": "bad_body"}, status_code=400)
        session_id = body.get("session_id", "")
        records = body.get("records")
        if not isinstance(records, list) or not records:
            return JSONResponse({"error": "bad_body"}, status_code=400)

        if not isinstance(session_id, str) or not session_id:
            return JSONResponse(
                {"error": "missing_session_id"},
                status_code=400,
            )

        # T1-18: batch session_id validation
        if len(session_id) > _MAX_SESSION_ID_LEN:
            return JSONResponse(
                {"error": "bad_session_id"}, status_code=400,
            )
        if "\x00" in session_id:
            return JSONResponse(
                {"error": "bad_session_id"}, status_code=400,
            )
        # Check for lone surrogates in session_id
        try:
            session_id.encode("utf-8")
        except UnicodeEncodeError:
            return JSONResponse(
                {"error": "bad_session_id"}, status_code=400,
            )

        if len(records) > _MAX_RECORDS:
            return JSONResponse(
                {"error": "too_many_records"},
                status_code=413,
            )

        with _conn() as conn:
            device = _device_token_lookup(conn, token)
            if device is None:
                return JSONResponse(
                    {"error": "unauthorized"}, status_code=401,
                )
            d_org, d_project, d_connector = (
                str(device[0]), str(device[1]), str(device[2]),
            )

            # Set org context for RLS
            conn.execute(
                "SELECT set_config('app.org_id', %s, true)",
                [d_org],
            )

            # All-or-nothing: process in a transaction
            try:
                last_head: dict = {}
                for rec in records:
                    if not isinstance(rec, dict):
                        conn.rollback()
                        return JSONResponse(
                            {"error": "bad_body"}, status_code=400,
                        )
                    chain_length = rec.get("chain_length")
                    previous_hash = rec.get("previous_hash", "")
                    record_hash = rec.get("record_hash", "")
                    rec_body = rec.get("body")

                    # T1-12: remove rec_session_id override.  A record
                    # carrying session_id different from the batch is
                    # 400 bad_body; equal is allowed.
                    rec_sid = rec.get("session_id")
                    if rec_sid is not None and rec_sid != session_id:
                        conn.rollback()
                        return JSONResponse(
                            {"error": "bad_body",
                             "detail": "record session_id differs from batch"},
                            status_code=400,
                        )
                    # Use the batch session_id always
                    rec_session_id = session_id

                    # T1-15: chain_length must be an int (not bool,
                    # float, string, list, object, None).
                    if chain_length is None:
                        conn.rollback()
                        return JSONResponse(
                            {"error": "missing_chain_length"},
                            status_code=400,
                        )
                    if (isinstance(chain_length, bool)
                            or not isinstance(chain_length, int)):
                        conn.rollback()
                        return JSONResponse(
                            {"error": "bad_body",
                             "detail": "chain_length must be an integer"},
                            status_code=400,
                        )

                    # T1-18: record_hash and previous_hash must be
                    # strings of at most 128 chars, before the fork
                    # branch.
                    if not isinstance(record_hash, str) or len(record_hash) > _MAX_HASH_LEN:
                        conn.rollback()
                        return JSONResponse(
                            {"error": "bad_body",
                             "detail": "record_hash must be a string <= 128 chars"},
                            status_code=400,
                        )
                    if not isinstance(previous_hash, str) or len(previous_hash) > _MAX_HASH_LEN:
                        conn.rollback()
                        return JSONResponse(
                            {"error": "bad_body",
                             "detail": "previous_hash must be a string <= 128 chars"},
                            status_code=400,
                        )

                    # Get current head for this session
                    head_row = conn.execute(
                        "SELECT chain_length, record_hash FROM audit_records "
                        "WHERE connector_id = %s::uuid "
                        "  AND session_id = %s "
                        "ORDER BY chain_length DESC LIMIT 1",
                        [d_connector, rec_session_id],
                    ).fetchone()

                    current_length = head_row[0] if head_row else 0
                    current_hash = head_row[1] if head_row else ""

                    # Same position, same hash = no-op
                    if chain_length == current_length and record_hash == current_hash:
                        last_head = {
                            "session_id": rec_session_id,
                            "chain_length": current_length,
                            "head_hash": current_hash,
                            "noop": True,
                        }
                        continue

                    # Same position, different hash = fork -> quarantine
                    if chain_length <= current_length:
                        existing = conn.execute(
                            "SELECT record_hash FROM audit_records "
                            "WHERE connector_id = %s::uuid "
                            "  AND session_id = %s "
                            "  AND chain_length = %s",
                            [d_connector, rec_session_id, chain_length],
                        ).fetchone()
                        if existing and existing[0] != record_hash:
                            # Fork detected -- quarantine
                            conn.execute(
                                "INSERT INTO audit_quarantine "
                                "(id, org_id, connector_id, kind, detail, "
                                "created_at) "
                                "VALUES (%s, %s::uuid, %s::uuid, 'fork', "
                                "%s::jsonb, now())",
                                [
                                    str(uuid.uuid4()), d_org, d_connector,
                                    json.dumps({
                                        "session_id": rec_session_id,
                                        "chain_length": chain_length,
                                        "existing_hash": existing[0],
                                        "forked_hash": record_hash,
                                    }),
                                ],
                            )
                            # Insert alert
                            conn.execute(
                                "INSERT INTO sync_alerts "
                                "(id, org_id, project_id, connector_id, "
                                "kind, detail, created_at) "
                                "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, "
                                "'fork', %s::jsonb, now())",
                                [
                                    str(uuid.uuid4()), d_org, d_project,
                                    d_connector,
                                    json.dumps({
                                        "session_id": rec_session_id,
                                        "chain_length": chain_length,
                                    }),
                                ],
                            )
                            conn.commit()
                            return JSONResponse(
                                {"error": "fork", "detail": "quarantined"},
                                status_code=409,
                            )
                        elif existing and existing[0] == record_hash:
                            # Same position, same hash = no-op
                            last_head = {
                                "session_id": rec_session_id,
                                "chain_length": chain_length,
                                "head_hash": record_hash,
                                "noop": True,
                            }
                            continue
                        else:
                            conn.rollback()
                            return JSONResponse(
                                {"error": "gap"},
                                status_code=400,
                            )

                    # Gap check: chain_length must be exactly current + 1
                    if chain_length != current_length + 1:
                        conn.rollback()
                        return JSONResponse(
                            {"error": "gap"},
                            status_code=400,
                        )

                    # previous_hash must match current head
                    if previous_hash != current_hash:
                        conn.rollback()
                        return JSONResponse(
                            {"error": "chain_broken",
                             "detail": "previous_hash mismatch"},
                            status_code=400,
                        )

                    # T1-1: body must be a dict; absent or non-dict
                    # is 400 hash_mismatch, nothing stored.
                    if not isinstance(rec_body, dict):
                        conn.rollback()
                        return JSONResponse(
                            {"error": "hash_mismatch",
                             "detail": "body must be an object"},
                            status_code=400,
                        )

                    # Deduplication key for every unstorable-body
                    # alert on this record (T1-18): one row per
                    # connector, session and position.
                    unstorable_detail = {
                        "session_id": rec_session_id,
                        "chain_length": chain_length,
                    }

                    # T1-26: fixed nesting limit, the same on every
                    # platform, walked without recursion.  Checked
                    # before the hash so a correctly hashed body over
                    # the limit is still refused: an export line or a
                    # CLI read on another platform must never fail on
                    # a body this server accepted.
                    if json_nesting_depth(
                        rec_body, limit=MAX_NESTING_DEPTH,
                    ) > MAX_NESTING_DEPTH:
                        _alert_unstorable(
                            conn, d_org, d_project, d_connector,
                            unstorable_detail,
                        )
                        return JSONResponse(
                            {"error": "audit_record_unstorable",
                             "detail": "body too deeply nested"},
                            status_code=400,
                        )

                    # T1-25: use shared canonical_record_bytes with
                    # allow_nan=False from sync/audit.py.
                    #
                    # Why re-canonicalise instead of hashing the wire
                    # bytes (review round 3, ruling 1): the connector
                    # hashes the canonical bytes
                    # json.dumps(body, separators=(",",":"),
                    # sort_keys=True) but sends json.dumps(body) with
                    # the default separators, so the wire bytes never
                    # equal the hashed bytes.  Re-canonicalising with
                    # the shared formula is the only way to reproduce
                    # the connector's record_hash.
                    canonical = canonical_record_bytes(rec_body)
                    if canonical is None:
                        # Unstorable body (NaN, Infinity): named 400,
                        # nothing stored (T1-14), one alert (T1-18).
                        _alert_unstorable(
                            conn, d_org, d_project, d_connector,
                            unstorable_detail,
                        )
                        return JSONResponse(
                            {"error": "audit_record_unstorable",
                             "detail": "body not serialisable"},
                            status_code=400,
                        )

                    body_text = canonical.decode("utf-8")

                    expected_hash = hashlib.sha256(canonical).hexdigest()
                    if record_hash != expected_hash:
                        conn.rollback()
                        return JSONResponse(
                            {"error": "hash_mismatch"},
                            status_code=400,
                        )

                    # Insert the record (json, not jsonb -- T1-2)
                    try:
                        conn.execute(
                            "INSERT INTO audit_records "
                            "(id, org_id, connector_id, session_id, "
                            "chain_length, previous_hash, record_hash, "
                            "body, created_at) "
                            "VALUES (%s, %s::uuid, %s::uuid, %s, %s, %s, %s, "
                            "%s::json, now())",
                            [
                                str(uuid.uuid4()), d_org, d_connector,
                                rec_session_id, chain_length, previous_hash,
                                record_hash,
                                body_text,
                            ],
                        )
                    except (
                        psycopg.errors.DataError,
                        psycopg.errors.StatementTooComplex,
                    ):
                        # T1-13: catch only DataError and
                        # StatementTooComplex.  UniqueViolation keeps
                        # its 409 path.
                        _alert_unstorable(
                            conn, d_org, d_project, d_connector,
                            unstorable_detail,
                        )
                        return JSONResponse(
                            {"error": "audit_record_unstorable",
                             "detail": "body not storable"},
                            status_code=400,
                        )

                    last_head = {
                        "session_id": rec_session_id,
                        "chain_length": chain_length,
                        "head_hash": record_hash,
                    }

                conn.commit()
            except psycopg.errors.UniqueViolation:
                conn.rollback()
                # T1-13: UniqueViolation reaches the 409.
                return JSONResponse(
                    {"error": "duplicate_record"},
                    status_code=409,
                )
            except Exception:
                conn.rollback()
                raise

        return JSONResponse(
            {"server_head": last_head},
            status_code=200,
        )

    # -----------------------------------------------------------------
    # POST /api/v1/sync/checkpoint (device token auth)
    # -----------------------------------------------------------------
    @rbac_route(
        router, "post", "/api/v1/sync/checkpoint",
        role="device", scope="project",
    )
    async def upload_checkpoint(request: Request) -> JSONResponse:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        token = auth[7:]

        body = await request.json()

        with _conn() as conn:
            device = _device_token_lookup(conn, token)
            if device is None:
                return JSONResponse(
                    {"error": "unauthorized"}, status_code=401,
                )
            d_org, d_project, d_connector = (
                str(device[0]), str(device[1]), str(device[2]),
            )

            # Set org context for RLS
            conn.execute(
                "SELECT set_config('app.org_id', %s, true)",
                [d_org],
            )

            # Validate envelope structure
            kind = body.get("kind", "")
            if kind != "agg/audit-head/v1":
                return JSONResponse(
                    {"error": "invalid_kind"},
                    status_code=400,
                )

            payload = body.get("payload", {})
            payload_device_id = payload.get("device_id", "")

            # Device ID from payload must match token's device
            if payload_device_id != d_connector:
                return JSONResponse(
                    {"error": "device_id_mismatch"},
                    status_code=400,
                )

            # Verify signature against the device's registered public key
            pub_hex = _get_device_public_key(conn, d_connector)
            if pub_hex is None:
                return JSONResponse(
                    {"error": "device_not_found"},
                    status_code=400,
                )

            if not _verify_envelope_signature(body, pub_hex):
                return JSONResponse(
                    {"error": "invalid_signature"},
                    status_code=400,
                )

            upload_seq = payload.get("upload_seq", 0)
            sessions = payload.get("sessions", [])

            # Check upload_seq: must be last stored + 1
            last_seq_row = conn.execute(
                "SELECT upload_seq FROM audit_heads "
                "WHERE connector_id = %s::uuid "
                "ORDER BY upload_seq DESC LIMIT 1",
                [d_connector],
            ).fetchone()
            last_seq = last_seq_row[0] if last_seq_row else 0

            if upload_seq == last_seq:
                return JSONResponse(
                    {"error": "seq_repeat"},
                    status_code=409,
                )
            if upload_seq != last_seq + 1:
                return JSONResponse(
                    {"error": "seq_skip"},
                    status_code=400,
                )

            # Get previous checkpoint's session list for comparison
            prev_sessions: dict[str, int] = {}
            if last_seq > 0:
                prev_row = conn.execute(
                    "SELECT session_list FROM audit_heads "
                    "WHERE connector_id = %s::uuid "
                    "  AND upload_seq = %s",
                    [d_connector, last_seq],
                ).fetchone()
                if prev_row and prev_row[0]:
                    prev_list = prev_row[0]
                    if isinstance(prev_list, str):
                        prev_list = json.loads(prev_list)
                    for s in prev_list:
                        prev_sessions[s["session_id"]] = s.get("chain_length", 0)

            # Check for session_missing and truncation
            current_session_ids = {s["session_id"] for s in sessions}
            for prev_sid, prev_length in prev_sessions.items():
                if prev_sid not in current_session_ids:
                    # Session missing alert (threat 32)
                    conn.execute(
                        "INSERT INTO sync_alerts "
                        "(id, org_id, project_id, connector_id, "
                        "kind, detail, created_at) "
                        "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, "
                        "'session_missing', %s::jsonb, now())",
                        [
                            str(uuid.uuid4()), d_org, d_project,
                            d_connector,
                            json.dumps({"session_id": prev_sid}),
                        ],
                    )

            for sess in sessions:
                sid = sess["session_id"]
                cl = sess.get("chain_length", 0)
                prev_cl = prev_sessions.get(sid)
                if prev_cl is not None and cl < prev_cl:
                    # Truncation alert (threat 15)
                    conn.execute(
                        "INSERT INTO sync_alerts "
                        "(id, org_id, project_id, connector_id, "
                        "kind, detail, created_at) "
                        "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, "
                        "'truncation', %s::jsonb, now())",
                        [
                            str(uuid.uuid4()), d_org, d_project,
                            d_connector,
                            json.dumps({
                                "session_id": sid,
                                "previous_length": prev_cl,
                                "current_length": cl,
                            }),
                        ],
                    )

            # Compute a head hash from the session list
            session_blob = json.dumps(
                sessions, sort_keys=True, separators=(",", ":"),
            ).encode()
            head_hash = hashlib.sha256(session_blob).hexdigest()

            # Store the checkpoint
            try:
                conn.execute(
                    "INSERT INTO audit_heads "
                    "(id, org_id, connector_id, upload_seq, session_list, "
                    "head_hash, signature, created_at) "
                    "VALUES (%s, %s::uuid, %s::uuid, %s, %s::jsonb, %s, "
                    "%s, now())",
                    [
                        str(uuid.uuid4()), d_org, d_connector,
                        upload_seq,
                        json.dumps(sessions),
                        head_hash,
                        body.get("signatures", [{}])[0].get("sig", ""),
                    ],
                )
                conn.commit()
            except psycopg.errors.UniqueViolation:
                conn.rollback()
                return JSONResponse(
                    {"error": "seq_conflict"},
                    status_code=409,
                )

        return JSONResponse(
            {"upload_seq": upload_seq},
            status_code=200,
        )

    return router
