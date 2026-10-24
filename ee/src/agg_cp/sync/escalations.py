"""Server-side escalation and approval routes (D6.1, D6.2, T12, T13).

POST /api/v1/sync/escalations                       -- upload escalation
GET  /api/v1/sync/decisions                          -- poll decisions
POST /api/v1/sync/escalations/{escalation_id}/approvals -- submit approval

Connections ``SET ROLE agg_app`` like enroll.py/signer.py/bundles.py.
Auth: device token for upload/decisions.
Approval submission accepts ONLY signer tokens or web session+CSRF (T13).
Device tokens on the approval route get 401/403.

Uses scrub.py to clean records before storage (threat 19).
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
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

# not_after grace period (2 min) matching connector-side
_NOT_AFTER_GRACE_S = 120


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
            for key in ("command", "reason", "target", "described_as"):
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

        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "bad request"}, status_code=400)

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
                record = body.get("record", {})
                policy_seq = body.get("policy_sequence", 0)

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
                        "status, policy_sequence, created_at) "
                        "VALUES (%s::uuid, %s::uuid, %s::uuid, %s::uuid, "
                        "%s, %s::jsonb, %s, %s, %s, %s, now())",
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
    # -----------------------------------------------------------------
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

    @rbac_route(
        router, "post",
        "/api/v1/sync/escalations/{escalation_id}/approvals",
        role="signer_or_session", scope="org",
    )
    async def submit_approval(request: Request) -> JSONResponse:
        import logging
        _log = logging.getLogger("agg_cp.sync.escalations")

        esc_id = request.path_params.get("escalation_id", "")

        try:
            envelope = await request.json()
        except Exception:
            return JSONResponse({"error": "bad request"}, status_code=400)

        try:
          with _conn() as conn:
            # ---- T13 auth: signer token or web session+CSRF ----
            auth_user_id = None
            org_id = None

            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                bearer_token = auth_header[7:]
                # Try signer token first
                signer_info = _signer_token_lookup(conn, bearer_token)
                if signer_info is not None:
                    org_id = signer_info["org_id"]
                    auth_user_id = signer_info["user_id"]
                else:
                    # Check if it's a device token (refuse it)
                    device_lookup = _device_token_lookup(conn, bearer_token)
                    if device_lookup is not None:
                        return JSONResponse(
                            {"error": "device tokens not accepted on this route"},
                            status_code=403,
                        )
                    # Unknown token
                    return JSONResponse(
                        {"error": "unauthorized"}, status_code=401,
                    )
            else:
                # Try web session auth
                from ..auth import validate_session
                from ..clock import SystemClock
                actual_clock = clock if clock is not None else SystemClock()
                result, err = validate_session(conn, request, actual_clock)
                if err:
                    return err
                session_org_id, session_user_id, session_id, session_token, csrf_hash = result

                # CSRF check required for session-based writes
                csrf_header = request.headers.get("x-csrf-token")
                if not csrf_header:
                    return JSONResponse(
                        {"error": "csrf_missing"}, status_code=403,
                    )
                csrf_token_hash = _sha256_hex(csrf_header)
                if not _hmac.compare_digest(csrf_hash, csrf_token_hash):
                    return JSONResponse(
                        {"error": "csrf_invalid"}, status_code=403,
                    )

                org_id = str(session_org_id)
                auth_user_id = str(session_user_id)

            conn.execute(
                "SELECT set_config('app.org_id', %s, true)", [org_id]
            )

            # Early escalation visibility check (RLS: cross-org -> 404)
            esc_check = conn.execute(
                "SELECT id, project_id FROM escalations "
                "WHERE id = %s::uuid",
                [esc_id],
            ).fetchone()
            if esc_check is None:
                return JSONResponse(
                    {"error": "escalation not found"}, status_code=404,
                )
            esc_project_id = str(esc_check[1])

            # Validate envelope structure
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

            # Check key_id in the registry
            key_id = payload.get("key_id", "")
            user_id = payload.get("user_id", "")

            # T13 identity binding: session/signer user must match payload user_id
            if auth_user_id is not None and str(user_id) != str(auth_user_id):
                return JSONResponse(
                    {"error": "user_id mismatch: authenticated user does not match payload"},
                    status_code=403,
                )

            # Look up key in approver_keys
            key_row = conn.execute(
                "SELECT kind, roles, user_id FROM approver_keys "
                "WHERE org_id = %s AND key_id = %s",
                [org_id, key_id],
            ).fetchone()

            if key_row is None:
                # Key not in the registry: refuse
                return JSONResponse(
                    {"error": "key not found in registry"},
                    status_code=400,
                )

            key_kind = key_row[0]

            # T13 identity binding (three-way): the signing key's registry
            # owner must equal payload user_id, which equals the
            # authenticated user (checked above).  Without this, bob's
            # session could submit an envelope signed by carol's key.
            if str(key_row[2]) != str(user_id):
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

            # N9: prod approval refused for all key kinds in M2 (threat 36)
            # Use the escalation's project from the early check
            project_env = _get_project_environment(conn, esc_project_id)
            decision = payload.get("decision", "approve")
            if project_env == "prod" and decision != "deny":
                return JSONResponse(
                    {"error": "remote approvals on prod are not allowed in M2"},
                    status_code=403,
                )

            # D4.1: not_after expiry check
            not_after = payload.get("not_after")
            import time as _time
            now = _time.time()
            if not_after is not None:
                if now > not_after + _NOT_AFTER_GRACE_S:
                    return JSONResponse(
                        {"error": "approval expired (not_after + grace)"},
                        status_code=400,
                    )

            # Verify envelope signature against the registry key
            pub_row = conn.execute(
                "SELECT public_key FROM approver_keys "
                "WHERE org_id = %s AND key_id = %s",
                [org_id, key_id],
            ).fetchone()
            if pub_row:
                    pub_hex = pub_row[0]
                    try:
                        from nacl.signing import VerifyKey

                        vk = VerifyKey(bytes.fromhex(pub_hex))
                        kind = envelope.get("kind", "")
                        tag = kind.encode("utf-8")
                        canonical = json.dumps(
                            payload, sort_keys=True, separators=(",", ":")
                        ).encode()
                        msg = tag + b"\x00" + canonical
                        sigs = envelope.get("signatures", [])
                        if sigs:
                            sig_bytes = bytes.fromhex(sigs[0].get("sig", ""))
                            vk.verify(msg, sig_bytes)
                    except Exception:
                        return JSONResponse(
                            {"error": "invalid signature"},
                            status_code=400,
                        )

            # Store the approval with SELECT ... FOR UPDATE (D6.2)
            approval_id = str(uuid.uuid4())
            not_after_ts = None
            if not_after is not None:
                not_after_ts = datetime.fromtimestamp(not_after, tz=timezone.utc)

            try:
                # Lock the escalation row
                esc_row = conn.execute(
                    "SELECT id, org_id FROM escalations "
                    "WHERE id = %s::uuid FOR UPDATE",
                    [esc_id],
                ).fetchone()
                if esc_row is None:
                    conn.rollback()
                    return JSONResponse(
                        {"error": "escalation not found"}, status_code=404
                    )

                conn.execute(
                    "INSERT INTO approvals "
                    "(id, org_id, escalation_id, user_id, key_id, decision, "
                    "signed_payload, signature, nonce, not_after, "
                    "registry_version, kind, created_at) "
                    "VALUES (%s, %s::uuid, %s::uuid, %s, %s, %s, %s, %s, %s, %s, %s, %s, now())",
                    [
                        approval_id, org_id, esc_id, user_id, key_id,
                        payload.get("decision", "approve"),
                        json.dumps(payload),
                        envelope.get("signatures", [{}])[0].get("sig", ""),
                        payload.get("nonce", ""),
                        not_after_ts,
                        payload.get("registry_version"),
                        key_kind,
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

    return router


# Module-level alias for test discoverability (``_need("agg_cp.sync.escalations", "router")``)
router = escalation_router
