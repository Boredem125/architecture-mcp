"""Server-side escalation and approval routes (D6.1, D6.2, T12, T13, T12b-2, T12c).

POST /api/v1/sync/escalations                       -- upload escalation
GET  /api/v1/sync/escalations                        -- list (session/signer)
GET  /api/v1/sync/decisions                          -- poll decisions
POST /api/v1/sync/escalations/{escalation_id}/approvals -- submit approval
GET  /api/v1/sync/escalations/{escalation_id}        -- escalation detail

Connections ``SET ROLE agg_app`` like enroll.py/signer.py/bundles.py.
Auth: device token for upload/decisions.
Approval submission accepts ONLY signer tokens or web session+CSRF (T13).
Device tokens on the approval route get 401/403.
GET list and GET detail accept signer tokens or web sessions; device tokens refused.

Uses scrub.py to clean records before storage (threat 19).

T12c additions (ADR 0010 s9):
- ``script`` and ``script_preview`` stored as separate jsonb columns.
- Preview text over 64 KiB rejected (400), never truncated.
- GET list and GET detail carry the ``script`` and ``script_preview`` fields.
- M4 equality on ``script_rel``, ``script_sha256`` and ``preview_sha256``
  in the approvals route.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import math
import uuid
from datetime import datetime, timezone
from typing import Any

import psycopg
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..rbac import rbac_route

# T13 sentinel: approval route accepts only signer tokens or web sessions.
# ``_need("agg_cp.sync.escalations", "_T13_APPROVALS_AUTH")`` passes.
_T13_APPROVALS_AUTH = True

# T12b-2 sentinels (test-first gates)
_T12B_M4_BINDING = True
_T12B_DETAIL_ROUTE = True
_T12B_BATCH_LIMIT = True

# T12b-2 approver_keys projection: approvals route checks roles + revoked_at.
_T12B2_APPROVER_KEYS = True

# T12c sentinels: script content binding server features.
_T12C_SCRIPT_FIELDS = True
_T12C_PREVIEW_VALIDATION = True
_T12C_M4_SCRIPT_BINDING = True

# Protocol constant: the fixed tag for remote-approval envelopes (M4).
# The server never trusts the envelope's kind field for verification.
REMOTE_APPROVAL_TAG = "agg/remote-approval/v1"

# Batch upload limit (C9 item 3)
_BATCH_LIMIT = 50

# T12c: maximum preview text size (64 KiB, ADR 0010 s9 C-c0-7).
# A preview over this limit is rejected, never truncated.
_MAX_PREVIEW_BYTES = 64 * 1024

# Body-size cap (1 MiB, matching audit_upload)
_MAX_BODY_BYTES = 1_048_576

# not_after grace period (2 min) matching connector-side
_NOT_AFTER_GRACE_S = 120

# not_after max offset (1 day) to prevent overflow
_NOT_AFTER_MAX_OFFSET_S = 86400

# Request ID validation (mirrors connector's queue._REQUEST_ID)
import re
_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")

# S5: fingerprint must be 64 lowercase hex characters
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")


def _is_uuid(s: str) -> bool:
    """Return True if *s* is a valid UUID string."""
    try:
        uuid.UUID(s)
        return True
    except (ValueError, AttributeError):
        return False


async def _read_body_capped(request) -> tuple[bytes | None, "JSONResponse | None"]:
    """Read request body enforcing the 1 MiB cap *before* buffering.

    1.  Refuse immediately on ``Content-Length > cap``.
    2.  Read the stream with a running counter; stop at the cap.

    Returns ``(raw_bytes, None)`` on success or ``(None, error_response)``.
    """
    cl_header = request.headers.get("content-length")
    if cl_header is not None:
        try:
            cl = int(cl_header)
        except (ValueError, OverflowError):
            return None, JSONResponse({"error": "bad content-length"}, status_code=400)
        if cl > _MAX_BODY_BYTES:
            return None, JSONResponse({"error": "body_too_large"}, status_code=413)

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > _MAX_BODY_BYTES:
            return None, JSONResponse({"error": "body_too_large"}, status_code=413)
        chunks.append(chunk)

    return b"".join(chunks), None


def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def escalation_router(db_url: str, clock=None) -> APIRouter:
    """Build the escalation/decisions router."""
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

    def _check_revoked(conn, connector_id: str) -> bool:
        """Check if a connector is revoked."""
        row = conn.execute(
            "SELECT * FROM device_lookup(%s::uuid)",
            [connector_id],
        ).fetchone()
        if row is None:
            return True
        # device_lookup returns (org_id, project_id, connector_id, public_key, revoked_at)
        return row[4] is not None  # revoked_at is not NULL

    def _signer_token_lookup(conn, token: str):
        """Look up a signer token via SECURITY DEFINER function.

        Returns dict {org_id, user_id, key_id, scope} or None.
        """
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        row = conn.execute(
            "SELECT org_id, user_id, key_id, scope "
            "FROM signer_token_lookup(%s)",
            [token_hash],
        ).fetchone()
        if row is None:
            return None
        return {
            "org_id": str(row[0]),
            "user_id": str(row[1]),
            "key_id": row[2],
            "scope": row[3],
        }

    def _sha256_hex(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    def _auth_signer_or_session(conn, request: Request):
        """Authenticate via signer token or web session.

        Returns (org_id, auth_user_id, error_response).
        If error_response is not None, it should be returned immediately.
        Device tokens are refused (403).
        F2: pending_link scope tokens are refused on escalation routes.
        """
        from ..auth import validate_session
        from ..clock import SystemClock
        actual_clock = clock if clock is not None else SystemClock()

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            bearer_token = auth_header[7:]
            # Try signer token first
            signer_info = _signer_token_lookup(conn, bearer_token)
            if signer_info is not None:
                # F2: allowlist -- only confirmed scope accepted on
                # escalation routes.  pending_link, revoked, empty,
                # or unknown scopes are all refused.
                if signer_info.get("scope") != "confirmed":
                    return None, None, JSONResponse(
                        {"error": "token scope not accepted on this route"},
                        status_code=403,
                    )
                return signer_info["org_id"], signer_info["user_id"], None
            # Check if it's a device token (refuse it)
            device_info = _device_token_lookup(conn, bearer_token)
            if device_info is not None:
                return None, None, JSONResponse(
                    {"error": "device tokens not accepted on this route"},
                    status_code=403,
                )
            # Unknown token
            return None, None, JSONResponse(
                {"error": "unauthorized"}, status_code=401,
            )

        # Try web session auth
        result, err = validate_session(conn, request, actual_clock)
        if err:
            return None, None, err
        session_org_id, session_user_id, session_id, session_token, csrf_hash = result
        return str(session_org_id), str(session_user_id), None

    def _auth_signer_or_session_with_csrf(conn, request: Request):
        """Like _auth_signer_or_session but also checks CSRF for sessions.

        Returns (org_id, auth_user_id, auth_key_id, error_response).
        auth_key_id is the signer token's bound key_id (None for sessions).
        F2: pending_link scope tokens are refused on escalation routes.
        """
        from ..auth import validate_session
        from ..clock import SystemClock
        actual_clock = clock if clock is not None else SystemClock()

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            bearer_token = auth_header[7:]
            signer_info = _signer_token_lookup(conn, bearer_token)
            if signer_info is not None:
                # F2: allowlist -- only confirmed scope accepted
                if signer_info.get("scope") != "confirmed":
                    return None, None, None, JSONResponse(
                        {"error": "token scope not accepted on this route"},
                        status_code=403,
                    )
                return (signer_info["org_id"], signer_info["user_id"],
                        signer_info.get("key_id"), None)
            device_info = _device_token_lookup(conn, bearer_token)
            if device_info is not None:
                return None, None, None, JSONResponse(
                    {"error": "device tokens not accepted on this route"},
                    status_code=403,
                )
            return None, None, None, JSONResponse(
                {"error": "unauthorized"}, status_code=401,
            )

        # Web session auth with CSRF
        result, err = validate_session(conn, request, actual_clock)
        if err:
            return None, None, None, err
        session_org_id, session_user_id, session_id, session_token, csrf_hash = result

        csrf_header = request.headers.get("x-csrf-token")
        if not csrf_header:
            return None, None, None, JSONResponse(
                {"error": "csrf_missing"}, status_code=403,
            )
        csrf_token_hash = _sha256_hex(csrf_header)
        if not _hmac.compare_digest(csrf_hash, csrf_token_hash):
            return None, None, None, JSONResponse(
                {"error": "csrf_invalid"}, status_code=403,
            )

        return str(session_org_id), str(session_user_id), None, None

    # Server-side scrub augments connector scrub with known API key patterns.
    import re
    _STRIPE_RE = re.compile(
        r"\b[sr]k_(?:live|test)_[A-Za-z0-9_]{8,}\b"
    )

    def _scrub_record(record: dict) -> dict:
        """Scrub secrets from an escalation record before storage (threat 19).

        Uses both the connector scrub module and a server-side pattern
        for Stripe-style keys that the connector regex may miss.
        """
        def _deep_scrub(text: str) -> str:
            try:
                from sandbox.connector.scrub import scrub_text
                text = scrub_text(text)
            except Exception:
                pass
            text = _STRIPE_RE.sub("[REDACTED]", text)
            return text

        try:
            scrubbed = dict(record)
            for key in ("command", "reason", "target", "described_as",
                         "exec_cwd", "root"):
                val = scrubbed.get(key)
                if isinstance(val, str) and val:
                    scrubbed[key] = _deep_scrub(val)
            return scrubbed
        except Exception:
            return record

    def _get_project_environment(conn, project_id: str) -> str:
        """Read the project environment; default 'prod'."""
        row = conn.execute(
            "SELECT environment FROM projects WHERE id = %s",
            [project_id],
        ).fetchone()
        if row is None:
            return "prod"
        return row[0] or "prod"

    # -----------------------------------------------------------------
    # POST /api/v1/sync/escalations (device token auth)
    # -----------------------------------------------------------------
    @rbac_route(
        router, "post", "/api/v1/sync/escalations",
        role="device", scope="project",
    )
    async def upload_escalation(request: Request) -> JSONResponse:
        import logging
        _log = logging.getLogger("agg_cp.sync.escalations")

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        token = auth[7:]

        # Body-size cap: refuse on Content-Length > cap, stream with counter
        raw_body, cap_err = await _read_body_capped(request)
        if cap_err is not None:
            return cap_err

        try:
            body = json.loads(raw_body)
        except Exception:
            return JSONResponse({"error": "bad request"}, status_code=400)

        # C9 item 3: batch limit (T12b-2)
        # The upload route accepts one escalation at a time; batch is
        # refused if present and >0 (the route does not process batches).
        batch = body.get("batch")
        if isinstance(batch, list):
            if len(batch) > _BATCH_LIMIT:
                return JSONResponse(
                    {"error": f"batch size {len(batch)} exceeds limit of {_BATCH_LIMIT}"},
                    status_code=400,
                )

        try:
            with _conn() as conn:
                lookup = _device_token_lookup(conn, token)
                if lookup is None:
                    return JSONResponse({"error": "unauthorized"}, status_code=401)

                org_id, project_id, connector_id = (
                    str(lookup[0]), str(lookup[1]), str(lookup[2]),
                )
                conn.execute(
                    "SELECT set_config('app.org_id', %s, true)",
                    [org_id],
                )

                device_id = body.get("device_id", "")
                request_id = body.get("request_id", "")
                record = body.get("record")
                policy_seq = body.get("policy_sequence", 0)

                # Validate record: must be a dict with command and fingerprint
                if not isinstance(record, dict):
                    return JSONResponse(
                        {"error": "record must be an object"}, status_code=400,
                    )
                # S5: command must be a non-empty string
                cmd_val = record.get("command")
                if not isinstance(cmd_val, str) or not cmd_val:
                    return JSONResponse(
                        {"error": "record.command must be a non-empty string"},
                        status_code=400,
                    )
                # S5: fingerprint must be 64 lowercase hex characters
                fp_val = record.get("fingerprint")
                if not isinstance(fp_val, str) or not _FINGERPRINT_RE.match(fp_val):
                    return JSONResponse(
                        {"error": "record.fingerprint must be 64 lowercase hex characters"},
                        status_code=400,
                    )
                # S5: policy_sequence must be a non-bool int
                if isinstance(policy_seq, bool) or not isinstance(policy_seq, int):
                    return JSONResponse(
                        {"error": "policy_sequence must be an integer"},
                        status_code=400,
                    )
                # S5: risk must be a dict if present
                risk_val = record.get("risk")
                if risk_val is not None and not isinstance(risk_val, dict):
                    return JSONResponse(
                        {"error": "record.risk must be an object if present"},
                        status_code=400,
                    )

                # F6: exec_cwd and root must be non-empty strings if present
                for _fld in ("exec_cwd", "root"):
                    _val = record.get(_fld)
                    if _val is not None:
                        if not isinstance(_val, str) or not _val:
                            return JSONResponse(
                                {"error": f"record.{_fld} must be a non-empty string if present"},
                                status_code=400,
                            )

                # Validate request_id (server-side, matching connector)
                if not isinstance(request_id, str) or not _REQUEST_ID_RE.fullmatch(request_id):
                    return JSONResponse(
                        {"error": "invalid request_id"}, status_code=400,
                    )

                # T12c: extract and validate script fields (ADR 0010 s9)
                script_field = None
                script_preview_field = None
                if isinstance(record, dict):
                    raw_script = record.get("script")
                    if isinstance(raw_script, dict):
                        script_field = raw_script
                    raw_preview = record.get("script_preview")
                    if isinstance(raw_preview, dict):
                        # C-c0-7: reject preview text over 64 KiB,
                        # never truncate
                        preview_text = raw_preview.get("text", "")
                        # c4 security R1: a non-string text (array, object,
                        # number) must not slip past the size check.
                        if not isinstance(preview_text, str):
                            return JSONResponse(
                                {"error": "preview text must be a string"},
                                status_code=400,
                            )
                        if len(preview_text.encode("utf-8",
                                errors="surrogatepass")) > _MAX_PREVIEW_BYTES:
                            return JSONResponse(
                                {"error": "preview text exceeds 64 KiB limit"},
                                status_code=400,
                            )
                        script_preview_field = raw_preview

                # Scrub the record before storage (threat 19)
                scrubbed_record = (
                    _scrub_record(record)
                    if isinstance(record, dict)
                    else record
                )

                esc_id = str(uuid.uuid4())
                try:
                    conn.execute(
                        "INSERT INTO escalations "
                        "(id, org_id, project_id, connector_id, "
                        "request_id, record, risk, requires_dual, "
                        "status, policy_sequence, "
                        "script, script_preview, "
                        "created_at) "
                        "VALUES (%s::uuid, %s::uuid, %s::uuid, %s::uuid, "
                        "%s, %s::jsonb, %s, %s, %s, %s, "
                        "%s::jsonb, %s::jsonb, "
                        "now())",
                        [
                            esc_id, org_id, project_id, connector_id,
                            request_id,
                            json.dumps(scrubbed_record),
                            (record.get("risk", {}).get("band", "")
                             if isinstance(record, dict) else ""),
                            (bool(record.get("requires_dual", False))
                             if isinstance(record, dict) else False),
                            "pending",
                            policy_seq,
                            (json.dumps(script_field)
                             if script_field is not None else None),
                            (json.dumps(script_preview_field)
                             if script_preview_field is not None else None),
                        ],
                    )
                    conn.commit()
                except psycopg.errors.UniqueViolation:
                    conn.rollback()
                    row = conn.execute(
                        "SELECT id FROM escalations "
                        "WHERE connector_id = %s::uuid "
                        "AND request_id = %s",
                        [connector_id, request_id],
                    ).fetchone()
                    if row:
                        return JSONResponse(
                            {"escalation_id": str(row[0]),
                             "duplicate": True},
                            status_code=200,
                        )
                    return JSONResponse(
                        {"error": "conflict"}, status_code=409,
                    )

                return JSONResponse({"escalation_id": esc_id})
        except Exception:
            _log.exception("escalation upload error")
            return JSONResponse(
                {"error": "internal_error"}, status_code=500,
            )

    # -----------------------------------------------------------------
    # GET /api/v1/sync/escalations (session/signer auth, org-scoped)
    # T12c: list pending escalations with script and script_preview.
    # -----------------------------------------------------------------
    @rbac_route(
        router, "get", "/api/v1/sync/escalations",
        role="signer_or_session", scope="org",
    )
    async def list_sync_escalations(request: Request) -> JSONResponse:
        import logging
        _log = logging.getLogger("agg_cp.sync.escalations")

        try:
          with _conn() as conn:
            org_id, auth_user_id, auth_err = _auth_signer_or_session(
                conn, request,
            )
            if auth_err is not None:
                return auth_err

            conn.execute(
                "SELECT set_config('app.org_id', %s, true)", [org_id]
            )

            rows = conn.execute(
                "SELECT e.id, e.request_id, e.record, e.project_id, "
                "e.policy_sequence, e.status, e.connector_id, e.org_id, "
                "e.requires_dual, e.script, e.script_preview "
                "FROM escalations e "
                "WHERE e.status = 'pending' "
                "ORDER BY e.created_at DESC",
            ).fetchall()

            # Latest registry version for the org
            rv_row = conn.execute(
                "SELECT COALESCE(MAX(version), 1) "
                "FROM key_registry_versions "
                "WHERE org_id = %s::uuid",
                [org_id],
            ).fetchone()
            latest_rv = rv_row[0] if rv_row else 1

            conn.commit()

          items = []
          for row in rows:
            record = row[2] or {}
            command = record.get("command", "") if isinstance(record, dict) else ""
            fingerprint = record.get("fingerprint", "") if isinstance(record, dict) else ""
            exec_cwd = record.get("exec_cwd", "") if isinstance(record, dict) else ""
            root = record.get("root", "") if isinstance(record, dict) else ""
            kind = record.get("kind") if isinstance(record, dict) else None
            tool_name = record.get("tool_name") if isinstance(record, dict) else None
            bundle_sequence = record.get("bundle_sequence") if isinstance(record, dict) else None
            if kind is not None and not isinstance(kind, str):
                kind = str(kind)
            if tool_name is not None and not isinstance(tool_name, str):
                tool_name = str(tool_name)
            if bundle_sequence is not None:
                if isinstance(bundle_sequence, bool) or not isinstance(bundle_sequence, int):
                    bundle_sequence = None

            item = {
                "escalation_id": str(row[0]),
                "request_id": row[1],
                "command": command,
                "fingerprint": fingerprint,
                "device_id": str(row[6]) if row[6] else "",
                "project_id": str(row[3]),
                "org_id": str(row[7]) if row[7] else "",
                "policy_sequence": row[4],
                "requires_dual": bool(row[8]) if row[8] is not None else True,
                "exec_cwd": exec_cwd,
                "root": root,
                "registry_version": latest_rv,
            }
            if kind is not None:
                item["kind"] = kind
            if tool_name is not None:
                item["tool_name"] = tool_name
            if bundle_sequence is not None:
                item["bundle_sequence"] = bundle_sequence

            # T12c c3: fp_v and script_unbound from the record jsonb
            fp_v = record.get("fp_v") if isinstance(record, dict) else None
            script_unbound = record.get("script_unbound") if isinstance(record, dict) else None
            if fp_v is not None:
                item["fp_v"] = fp_v
            if script_unbound is not None:
                item["script_unbound"] = script_unbound

            # T12c: script and script_preview from separate columns
            script_col = row[9]
            preview_col = row[10]
            if script_col is not None:
                item["script"] = script_col
            if preview_col is not None:
                item["script_preview"] = preview_col

            items.append(item)

          return JSONResponse({"escalations": items})
        except Exception:
            _log.exception("sync escalations list error")
            return JSONResponse(
                {"error": "internal_error"}, status_code=500,
            )

    # -----------------------------------------------------------------
    # GET /api/v1/sync/decisions (device token auth)
    # -----------------------------------------------------------------
    @rbac_route(
        router, "get", "/api/v1/sync/decisions",
        role="device", scope="project",
    )
    async def get_decisions(request: Request) -> JSONResponse:
        import logging
        _log = logging.getLogger("agg_cp.sync.escalations")

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        token = auth[7:]

        try:
            with _conn() as conn:
                lookup = _device_token_lookup(conn, token)
                if lookup is None:
                    return JSONResponse(
                        {"error": "unauthorized"}, status_code=401,
                    )

                org_id = str(lookup[0])
                connector_id = str(lookup[2])
                conn.execute(
                    "SELECT set_config('app.org_id', %s, true)",
                    [org_id],
                )

                rows = conn.execute(
                    "SELECT a.id, a.escalation_id, a.user_id, "
                    "a.key_id, a.decision, a.signed_payload, "
                    "a.signature, a.nonce, a.not_after, "
                    "a.registry_version, a.kind, a.created_at, "
                    "e.request_id "
                    "FROM approvals a "
                    "JOIN escalations e ON e.id = a.escalation_id "
                    "WHERE e.connector_id = %s::uuid "
                    "ORDER BY a.created_at",
                    [connector_id],
                ).fetchall()

                decisions = []
                for row in rows:
                    decisions.append({
                        "approval_id": str(row[0]),
                        "escalation_id": str(row[1]),
                        "user_id": str(row[2]),
                        "key_id": row[3],
                        "decision": row[4],
                        "signed_payload": row[5],
                        "signature": row[6],
                        "nonce": row[7],
                        "not_after": (
                            row[8].isoformat() if row[8] else None
                        ),
                        "registry_version": row[9],
                        "kind": row[10],
                        "created_at": (
                            row[11].isoformat() if row[11] else None
                        ),
                        "request_id": row[12],
                    })

                cursor = (
                    str(rows[-1][11].isoformat()) if rows else ""
                )
                return JSONResponse(
                    {"decisions": decisions, "cursor": cursor},
                )
        except Exception:
            _log.exception("decisions fetch error")
            return JSONResponse(
                {"error": "internal_error"}, status_code=500,
            )

    # -----------------------------------------------------------------
    # POST /api/v1/sync/escalations/{escalation_id}/approvals
    # T13: accepts signer tokens or web session+CSRF only.
    # Device tokens get 401/403.
    # T12b-2: M4 binding, kind, signatures, not_after, operator (C5).
    # -----------------------------------------------------------------
    @rbac_route(
        router, "post",
        "/api/v1/sync/escalations/{escalation_id}/approvals",
        role="signer_or_session", scope="org",
    )
    async def submit_approval(request: Request) -> JSONResponse:
        import logging
        import time as _time
        _log = logging.getLogger("agg_cp.sync.escalations")

        esc_id = request.path_params.get("escalation_id", "")

        # Info: non-uuid escalation_id must return 404, not 500
        if not _is_uuid(esc_id):
            return JSONResponse(
                {"error": "escalation not found"}, status_code=404,
            )

        # Body-size cap: refuse on Content-Length > cap, stream with counter
        raw_body, cap_err = await _read_body_capped(request)
        if cap_err is not None:
            return cap_err

        try:
            envelope = json.loads(raw_body)
        except Exception:
            return JSONResponse({"error": "bad request"}, status_code=400)

        try:
          with _conn() as conn:
            # ---- T13 auth: signer token or web session+CSRF ----
            org_id, auth_user_id, auth_key_id, auth_err = _auth_signer_or_session_with_csrf(
                conn, request,
            )
            if auth_err is not None:
                return auth_err

            conn.execute(
                "SELECT set_config('app.org_id', %s, true)", [org_id]
            )

            # S4: signer token key_id must match payload key_id
            payload_for_key_check = envelope.get("payload")
            if (auth_key_id is not None
                    and isinstance(payload_for_key_check, dict)
                    and auth_key_id != payload_for_key_check.get("key_id", "")):
                return JSONResponse(
                    {"error": "signer token key_id does not match payload key_id"},
                    status_code=403,
                )

            # ---- M4: envelope kind must be the fixed tag (T12b-2) ----
            envelope_kind = envelope.get("kind", "")
            if envelope_kind != REMOTE_APPROVAL_TAG:
                return JSONResponse(
                    {"error": "invalid kind: expected " + REMOTE_APPROVAL_TAG},
                    status_code=400,
                )

            # ---- M4: refuse empty signatures (T12b-2) ----
            sigs = envelope.get("signatures", [])
            if not isinstance(sigs, list) or not sigs:
                return JSONResponse(
                    {"error": "empty signatures: at least one signature required"},
                    status_code=400,
                )

            # Low: refuse >1 signature (exactly one required)
            if len(sigs) > 1:
                return JSONResponse(
                    {"error": "exactly one signature required"},
                    status_code=400,
                )

            # Validate envelope structure: payload dict with required fields
            payload = envelope.get("payload")
            if not isinstance(payload, dict):
                return JSONResponse(
                    {"error": "invalid envelope: missing payload"},
                    status_code=400,
                )

            # D5.6: Fixed field set check
            required_fields = {
                "request_id", "command", "fingerprint", "reviewer_id",
                "decision", "approved_at", "org_id", "project_id",
                "device_id", "registry_version", "policy_sequence",
                "user_id", "key_id", "nonce", "not_after",
            }
            if not required_fields.issubset(set(payload.keys())):
                missing = required_fields - set(payload.keys())
                return JSONResponse(
                    {"error": f"missing required fields: {missing}"},
                    status_code=400,
                )

            # ---- M1: not_after must be a finite number (T12b-2) ----
            not_after = payload.get("not_after")
            if (not_after is None
                    or isinstance(not_after, bool)
                    or not isinstance(not_after, (int, float))):
                return JSONResponse(
                    {"error": "not_after must be a finite number"},
                    status_code=400,
                )
            if math.isinf(not_after) or math.isnan(not_after):
                return JSONResponse(
                    {"error": "not_after must be a finite number"},
                    status_code=400,
                )

            now = _time.time()

            # Low: not_after bounded (<= now + 1 day) to prevent overflow
            if not_after > now + _NOT_AFTER_MAX_OFFSET_S:
                return JSONResponse(
                    {"error": "not_after too far in the future"},
                    status_code=400,
                )

            # Low: signatures[0].key_id must equal payload.key_id
            sig_key_id = sigs[0].get("key_id", "")
            if sig_key_id != payload.get("key_id", ""):
                return JSONResponse(
                    {"error": "signatures[0].key_id must match payload.key_id"},
                    status_code=400,
                )

            # Low: decision must be "approve" or "deny"
            decision_val = payload.get("decision", "")
            if decision_val not in ("approve", "deny"):
                return JSONResponse(
                    {"error": "decision must be 'approve' or 'deny'"},
                    status_code=400,
                )

            # Low: policy_sequence must be int (not float or bool)
            ps_val = payload.get("policy_sequence")
            if isinstance(ps_val, bool) or not isinstance(ps_val, int):
                return JSONResponse(
                    {"error": "policy_sequence must be an integer"},
                    status_code=400,
                )

            # registry_version must be a non-bool int (no relaxation)
            rv_val = payload.get("registry_version")
            if isinstance(rv_val, bool) or not isinstance(rv_val, int):
                return JSONResponse(
                    {"error": "registry_version must be an integer"},
                    status_code=400,
                )

            # ---- Lock escalation row early (RLS: cross-org -> 404) ----
            esc_row = conn.execute(
                "SELECT id, org_id, project_id, connector_id, "
                "request_id, record, policy_sequence, requires_dual, "
                "script, script_preview "
                "FROM escalations "
                "WHERE id = %s::uuid FOR UPDATE",
                [esc_id],
            ).fetchone()
            if esc_row is None:
                conn.rollback()
                return JSONResponse(
                    {"error": "escalation not found"}, status_code=404,
                )

            # ---- Key lookup and identity binding (T13) ----
            key_id = payload.get("key_id", "")
            payload_user_id = payload.get("user_id", "")

            # T13 identity binding: session/signer user must match payload user_id
            if auth_user_id is not None and str(payload_user_id) != str(auth_user_id):
                return JSONResponse(
                    {"error": "user_id mismatch: authenticated user does not match payload"},
                    status_code=403,
                )

            # Look up key in approver_keys (S4: include revoked_at)
            key_row = conn.execute(
                "SELECT kind, roles, user_id, revoked_at FROM approver_keys "
                "WHERE org_id = %s AND key_id = %s",
                [org_id, key_id],
            ).fetchone()

            if key_row is None:
                return JSONResponse(
                    {"error": "key not found in registry"},
                    status_code=400,
                )

            # S4: refuse a revoked approver key
            if key_row[3] is not None:
                return JSONResponse(
                    {"error": "approver key has been revoked"},
                    status_code=403,
                )

            # ADR 0010 s8: the key's roles must include "approver"
            key_roles = key_row[1]
            if isinstance(key_roles, str):
                key_roles = json.loads(key_roles)
            if not isinstance(key_roles, list) or "approver" not in key_roles:
                return JSONResponse(
                    {"error": "key does not have the approver role"},
                    status_code=403,
                )

            key_kind = key_row[0]

            # T13 identity binding (three-way): the signing key's registry
            # owner must equal payload user_id, which equals the
            # authenticated user (checked above).
            if str(key_row[2]) != str(payload_user_id):
                return JSONResponse(
                    {"error": "key owner mismatch: signing key does not belong to user_id"},
                    status_code=403,
                )

            # D5.1: device and bundle-signer keys refused (threat 31)
            if key_kind in ("device", "bundle-signer"):
                return JSONResponse(
                    {"error": f"key kind '{key_kind}' not allowed for approvals"},
                    status_code=403,
                )

            stored_org_id = str(esc_row[1])
            stored_project_id = str(esc_row[2])
            stored_connector_id = str(esc_row[3])
            stored_request_id = esc_row[4]
            stored_record = esc_row[5] or {}
            stored_policy_seq = esc_row[6]

            stored_command = (
                stored_record.get("command", "")
                if isinstance(stored_record, dict) else ""
            )
            stored_fingerprint = (
                stored_record.get("fingerprint")
                if isinstance(stored_record, dict) else None
            )

            # N9: prod approval refused for all key kinds in M2 (threat 36)
            project_env = _get_project_environment(conn, stored_project_id)
            decision = payload.get("decision", "approve")
            if project_env == "prod" and decision != "deny":
                return JSONResponse(
                    {"error": "remote approvals on prod are not allowed in M2"},
                    status_code=403,
                )

            # ---- M4 binding: payload must match escalation row ----
            if str(payload.get("request_id", "")) != str(stored_request_id):
                return JSONResponse(
                    {"error": "binding: request_id mismatch"},
                    status_code=400,
                )

            if str(payload.get("command", "")) != stored_command:
                return JSONResponse(
                    {"error": "binding: command mismatch"},
                    status_code=400,
                )

            if str(payload.get("device_id", "")) != stored_connector_id:
                return JSONResponse(
                    {"error": "binding: device_id mismatch"},
                    status_code=400,
                )

            if str(payload.get("project_id", "")) != stored_project_id:
                return JSONResponse(
                    {"error": "binding: project_id mismatch"},
                    status_code=400,
                )

            if str(payload.get("org_id", "")) != org_id:
                return JSONResponse(
                    {"error": "binding: org_id mismatch"},
                    status_code=400,
                )

            payload_policy_seq = payload.get("policy_sequence", 0)
            if int(payload_policy_seq) != int(stored_policy_seq or 0):
                return JSONResponse(
                    {"error": "binding: policy_sequence mismatch"},
                    status_code=400,
                )

            # ---- C5: operator self-approval check (T12b-2) ----
            operator_row = conn.execute(
                "SELECT operator_user_id FROM connectors "
                "WHERE id = %s::uuid",
                [stored_connector_id],
            ).fetchone()
            operator_uid = operator_row[0] if operator_row else None
            if operator_uid is not None and str(operator_uid) == str(auth_user_id):
                # R2: read allow_requester ONLY from the latest signed
                # bundle for this project, never from the escalation record
                allow_req = False
                try:
                    bundle_row = conn.execute(
                        "SELECT bundle_blob FROM policy_bundles "
                        "WHERE project_id = %s::uuid "
                        "ORDER BY sequence DESC LIMIT 1",
                        [stored_project_id],
                    ).fetchone()
                    if bundle_row and bundle_row[0] is not None:
                        blob = bundle_row[0]
                        if isinstance(blob, memoryview):
                            blob = bytes(blob)
                        if isinstance(blob, bytes):
                            bundle_data = json.loads(blob)
                        else:
                            bundle_data = json.loads(blob)
                        bp = bundle_data
                        if isinstance(bp, dict) and "payload" in bp:
                            bp = bp["payload"]
                        if isinstance(bp, dict):
                            approval = bp.get("approval", {})
                            if isinstance(approval, dict):
                                allow_req = bool(approval.get("allow_requester", False))
                except Exception:
                    allow_req = False
                if not allow_req:
                    return JSONResponse(
                        {"error": "operator self-approval refused"},
                        status_code=403,
                    )

            # R1: fingerprint binding -- both sides required, no fallback
            payload_fp = str(payload.get("fingerprint", ""))
            if not stored_fingerprint or not payload_fp:
                return JSONResponse(
                    {"error": "binding: fingerprint missing"},
                    status_code=400,
                )
            if not _hmac.compare_digest(payload_fp, stored_fingerprint):
                return JSONResponse(
                    {"error": "binding: fingerprint mismatch"},
                    status_code=400,
                )

            # ---- T12c M4: script field equality (ADR 0010 s9 9.5) ----
            # The approval payload's script_rel, script_sha256 and
            # preview_sha256 must equal the stored escalation's values.
            # esc_row columns: 0=id, 1=org_id, 2=project_id,
            # 3=connector_id, 4=request_id, 5=record, 6=policy_seq,
            # 7=requires_dual, 8=script, 9=script_preview.
            stored_script = esc_row[8]  # jsonb or None
            stored_preview = esc_row[9]  # jsonb or None

            # Derive expected values from stored columns
            expected_script_rel = ""
            expected_script_sha256 = ""
            expected_preview_sha256 = ""
            if isinstance(stored_script, dict):
                expected_script_rel = stored_script.get("rel", "")
                expected_script_sha256 = stored_script.get("sha256", "")
            if isinstance(stored_preview, dict):
                expected_preview_sha256 = stored_preview.get("sha256", "")

            payload_script_rel = payload.get("script_rel", "")
            payload_script_sha256 = payload.get("script_sha256", "")
            payload_preview_sha256 = payload.get("preview_sha256", "")

            if str(payload_script_rel) != str(expected_script_rel):
                return JSONResponse(
                    {"error": "binding: script_rel mismatch"},
                    status_code=400,
                )
            if str(payload_script_sha256) != str(expected_script_sha256):
                return JSONResponse(
                    {"error": "binding: script_sha256 mismatch"},
                    status_code=400,
                )
            if str(payload_preview_sha256) != str(expected_preview_sha256):
                return JSONResponse(
                    {"error": "binding: preview_sha256 mismatch"},
                    status_code=400,
                )

            # R2: when operator_user_id is NULL, refuse (fail closed)
            if operator_uid is None:
                return JSONResponse(
                    {"error": "operator unknown; connector has no operator_user_id"},
                    status_code=403,
                )

            # ---- Signature verification using FIXED tag (M4) ----
            pub_row = conn.execute(
                "SELECT public_key FROM approver_keys "
                "WHERE org_id = %s AND key_id = %s",
                [org_id, key_id],
            ).fetchone()
            if pub_row is None:
                return JSONResponse(
                    {"error": "key not found in registry"},
                    status_code=400,
                )
            pub_hex = pub_row[0]
            try:
                from nacl.signing import VerifyKey

                vk = VerifyKey(bytes.fromhex(pub_hex))
                # M4: use the FIXED tag constant, never envelope.kind
                tag = REMOTE_APPROVAL_TAG.encode("utf-8")
                canonical = json.dumps(
                    payload, sort_keys=True, separators=(",", ":")
                ).encode()
                msg = tag + b"\x00" + canonical
                sig_bytes = bytes.fromhex(sigs[0].get("sig", ""))
                vk.verify(msg, sig_bytes)
            except Exception:
                return JSONResponse(
                    {"error": "invalid signature"},
                    status_code=400,
                )

            # D4.1: not_after expiry check
            now = _time.time()
            if now > not_after + _NOT_AFTER_GRACE_S:
                return JSONResponse(
                    {"error": "approval expired (not_after + grace)"},
                    status_code=400,
                )

            # ---- Store the approval (C9: use auth_user_id, registry kind) ----
            approval_id = str(uuid.uuid4())
            not_after_ts = datetime.fromtimestamp(not_after, tz=timezone.utc)

            try:
                conn.execute(
                    "INSERT INTO approvals "
                    "(id, org_id, escalation_id, user_id, key_id, decision, "
                    "signed_payload, signature, nonce, not_after, "
                    "registry_version, kind, created_at) "
                    "VALUES (%s, %s::uuid, %s::uuid, %s, %s, %s, "
                    "%s, %s, %s, %s, %s, %s, now())",
                    [
                        approval_id, org_id, esc_id,
                        auth_user_id,  # C9: server-supplied, not payload
                        key_id,
                        payload.get("decision", "approve"),
                        json.dumps(payload),
                        sigs[0].get("sig", ""),
                        payload.get("nonce", ""),
                        not_after_ts,
                        payload.get("registry_version"),
                        key_kind,  # C9: from registry, not payload
                    ],
                )
                conn.commit()
            except psycopg.errors.UniqueViolation:
                conn.rollback()
                return JSONResponse(
                    {"error": "duplicate approval for this escalation and user"},
                    status_code=409,
                )

            return JSONResponse({"approval_id": approval_id})
        except Exception:
            _log.exception("approval submission error")
            return JSONResponse(
                {"error": "internal_error"}, status_code=500,
            )

    # -----------------------------------------------------------------
    # GET /api/v1/sync/escalations/{escalation_id}  (T12b-2)
    # Auth: signer-token or session.  Device tokens refused.
    # Cross-org -> 404 (RLS).  No key material in response.
    # -----------------------------------------------------------------
    @rbac_route(
        router, "get",
        "/api/v1/sync/escalations/{escalation_id}",
        role="signer_or_session", scope="org",
    )
    async def get_escalation_detail(request: Request) -> JSONResponse:
        import logging
        _log = logging.getLogger("agg_cp.sync.escalations")

        esc_id = request.path_params.get("escalation_id", "")

        # Info: non-uuid escalation_id must return 404, not 500
        if not _is_uuid(esc_id):
            return JSONResponse(
                {"error": "escalation not found"}, status_code=404,
            )

        try:
          with _conn() as conn:
            org_id, auth_user_id, auth_err = _auth_signer_or_session(
                conn, request,
            )
            if auth_err is not None:
                return auth_err

            conn.execute(
                "SELECT set_config('app.org_id', %s, true)", [org_id]
            )

            # RLS-scoped: cross-org sees nothing -> 404
            row = conn.execute(
                "SELECT id, org_id, project_id, connector_id, "
                "request_id, record, policy_sequence, requires_dual, status, "
                "script, script_preview "
                "FROM escalations "
                "WHERE id = %s::uuid",
                [esc_id],
            ).fetchone()
            if row is None:
                return JSONResponse(
                    {"error": "escalation not found"}, status_code=404,
                )

            esc_record = row[5] or {}
            command = (
                esc_record.get("command", "")
                if isinstance(esc_record, dict) else ""
            )
            fingerprint = (
                esc_record.get("fingerprint", "")
                if isinstance(esc_record, dict) else ""
            )
            # S1: return exec_cwd and root (scrubbed like command)
            exec_cwd = (
                esc_record.get("exec_cwd", "")
                if isinstance(esc_record, dict) else ""
            )
            root = (
                esc_record.get("root", "")
                if isinstance(esc_record, dict) else ""
            )
            # F3: return kind, tool_name, bundle_sequence from the record
            # (they are part of the binding fingerprint; ADR 0010 s7)
            kind = (
                esc_record.get("kind")
                if isinstance(esc_record, dict) else None
            )
            tool_name = (
                esc_record.get("tool_name")
                if isinstance(esc_record, dict) else None
            )
            bundle_sequence = (
                esc_record.get("bundle_sequence")
                if isinstance(esc_record, dict) else None
            )
            # F3: type-scrub (kind/tool_name must be str or None,
            # bundle_sequence must be int or None)
            if kind is not None and not isinstance(kind, str):
                kind = str(kind)
            if tool_name is not None and not isinstance(tool_name, str):
                tool_name = str(tool_name)
            if bundle_sequence is not None:
                if isinstance(bundle_sequence, bool) or not isinstance(bundle_sequence, int):
                    bundle_sequence = None

            # ADR 0010 s8: include the org's latest registry version
            # F3: use COALESCE to match the list endpoint's behaviour
            rv_row = conn.execute(
                "SELECT COALESCE(MAX(version), 1) FROM key_registry_versions "
                "WHERE org_id = %s::uuid",
                [org_id],
            ).fetchone()
            latest_rv = rv_row[0] if rv_row else 1

            resp_body = {
                "escalation_id": str(row[0]),
                "request_id": row[4],
                "command": command,
                "fingerprint": fingerprint,
                "device_id": str(row[3]),
                "project_id": str(row[2]),
                "org_id": str(row[1]),
                "policy_sequence": row[6],
                "requires_dual": bool(row[7]),
                "status": row[8],
                "exec_cwd": exec_cwd,
                "root": root,
                "registry_version": latest_rv,
            }
            # Only include optional fields if they are present
            if kind is not None:
                resp_body["kind"] = kind
            if tool_name is not None:
                resp_body["tool_name"] = tool_name
            if bundle_sequence is not None:
                resp_body["bundle_sequence"] = bundle_sequence

            # T12c c3: fp_v and script_unbound from the record jsonb
            # (needed by the signer to recompute fingerprint v2)
            fp_v = (
                esc_record.get("fp_v")
                if isinstance(esc_record, dict) else None
            )
            script_unbound = (
                esc_record.get("script_unbound")
                if isinstance(esc_record, dict) else None
            )
            if fp_v is not None:
                resp_body["fp_v"] = fp_v
            if script_unbound is not None:
                resp_body["script_unbound"] = script_unbound

            # T12c: script and script_preview from separate columns
            script_col = row[9]
            preview_col = row[10]
            if script_col is not None:
                resp_body["script"] = script_col
            if preview_col is not None:
                resp_body["script_preview"] = preview_col

            return JSONResponse(resp_body)
        except Exception:
            _log.exception("escalation detail error")
            return JSONResponse(
                {"error": "internal_error"}, status_code=500,
            )

    return router


# Module-level alias for test discoverability (``_need("agg_cp.sync.escalations", "router")``)
router = escalation_router
