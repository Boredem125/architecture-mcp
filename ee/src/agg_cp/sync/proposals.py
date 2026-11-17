"""T3 proposal, approval and publish routes.

POST /api/v1/admin/bundle-proposals             -- create
GET  /api/v1/admin/bundle-proposals             -- list (cursor)
GET  /api/v1/admin/bundle-proposals/{id}        -- detail
POST /api/v1/admin/bundle-proposals/{id}/approvals -- approve
POST /api/v1/admin/bundle-proposals/{id}/publish   -- publish (T3 shell)

Spec: T3_SPEC.md 3.4-3.6, T3_SECURITY_REVIEW.md R6 MUSTs 1-9.
Body is read and capped BEFORE any DB connection (MUST 2 / T3-R1-2).
No ``await`` while a transaction is open.
"""
from __future__ import annotations

import hashlib
import json
import uuid

import psycopg
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from sandbox.connector.sync.bundles import (
    BUNDLE_FIELDS,
    BUNDLE_MAX_BYTES,
    BundleError,
    _bundle_hash,
    _canonical_json_bytes,
    _verify_change_approvals,
    loosened,
)
from sandbox.protocol.registry import verify_chain

from ..rbac import rbac_route

# -- Constants ---------------------------------------------------------------

_SERVER_OWNED = frozenset({
    "org_id", "project_id", "sequence", "base_sequence",
    "registry_version", "environment",
    "issued_at", "not_before", "expires_at",
})

_POLICY_SECTIONS = ("folder_policy", "governance_policy", "mcp_policy",
                    "approval")

def _deny_all_base() -> dict:
    """Deny-all base for base_sequence 0; a fresh dict per call (no
    module-level mutable state, test_t6_module_state)."""
    return {
        "folder_policy": {"shell": {"blocklist_action": "deny"}},
        "governance_policy": {"clauses": []},
        "mcp_policy": {"servers": []},
        "approval": {"local_fallback": False, "allow_requester": False},
    }

_MAX_BODY = BUNDLE_MAX_BYTES + 65536  # 1 MiB + 64 KiB


# -- Helpers -----------------------------------------------------------------

def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _conn(conninfo: str):
    c = psycopg.connect(conninfo)
    c.execute("SET ROLE agg_app")
    # SHOULD: backstop timeouts for T3-R1-2
    c.execute("SET lock_timeout = '10s'")
    c.execute("SET statement_timeout = '30s'")
    return c


def _is_uuid(s: str) -> bool:
    """Check if s is a valid UUID string."""
    try:
        uuid.UUID(str(s))
        return True
    except (ValueError, AttributeError):
        return False


def _is_canonical_uuid(s: str) -> bool:
    """Check if s is a canonical UUID (lowercase hyphenated, str(uuid.UUID(s)) == s)."""
    try:
        return str(uuid.UUID(s)) == s
    except (ValueError, AttributeError):
        return False


def _admin_audit(conn, org_id, action, detail_dict):
    conn.execute(
        "INSERT INTO admin_audit (id, org_id, action, detail) "
        "VALUES (%s, %s::uuid, %s, %s)",
        [str(uuid.uuid4()), str(org_id), action,
         json.dumps(detail_dict)],
    )


def _is_project_admin(conn, user_id, project_id):
    """True if caller is org admin OR project-scope admin."""
    row = conn.execute(
        "SELECT 1 FROM role_bindings WHERE user_id = %s AND ("
        "(scope_type = 'org' AND role = 'admin')"
        " OR "
        "(scope_type = 'project' AND scope_id = %s AND role = 'admin')"
        ") LIMIT 1",
        [user_id, project_id],
    ).fetchone()
    return row is not None


def _strict_json_parse(raw: str) -> dict:
    """Parse JSON with duplicate-key detection at every depth and
    NaN/Infinity refusal.  Raises ValueError on any parse issue.
    """
    def _pairs_hook(pairs):
        keys = set()
        result = {}
        for key, value in pairs:
            if key in keys:
                raise ValueError(f"duplicate key: {key!r}")
            keys.add(key)
            result[key] = value
        return result

    def _refuse_constants(s):
        raise ValueError(f"NaN/Infinity not allowed: {s!r}")

    return json.loads(raw, object_pairs_hook=_pairs_hook,
                      parse_constant=_refuse_constants)


async def _read_body_capped(request) -> tuple[bytes | None, JSONResponse | None]:
    """Read and cap the body before any DB connection (MUST 2)."""
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > _MAX_BODY:
                return None, JSONResponse({"error": "body_too_large"}, status_code=413)
        except (ValueError, OverflowError):
            return None, JSONResponse({"error": "bad content-length"}, status_code=400)
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > _MAX_BODY:
            return None, JSONResponse({"error": "body_too_large"}, status_code=413)
        chunks.append(chunk)
    return b"".join(chunks), None


def _max_sequence(conn, org_id, project_id) -> int:
    row = conn.execute(
        "SELECT COALESCE(MAX(sequence), 0) FROM policy_bundles "
        "WHERE org_id = %s::uuid AND project_id = %s::uuid",
        [org_id, project_id],
    ).fetchone()
    pb = row[0] if row else 0
    row2 = conn.execute(
        "SELECT COALESCE(MAX(sequence), 0) FROM policy_change_requests "
        "WHERE org_id = %s::uuid AND project_id = %s::uuid AND status = 'published'",
        [org_id, project_id],
    ).fetchone()
    return max(pb, row2[0] if row2 else 0)


def _genesis_fingerprint(conn, org_id):
    """Return the stored genesis fingerprint for the org, or None."""
    row = conn.execute(
        "SELECT registry_blob FROM key_registry_versions "
        "WHERE org_id = %s::uuid AND version = 1",
        [org_id],
    ).fetchone()
    if row is None:
        return None
    genesis = json.loads(bytes(row[0]))
    payload = genesis.get("payload", {})
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(
        payload["org_id"].encode("utf-8") + b":" + canonical
    ).hexdigest()


# -- Auth helpers (inside the router factory) --------------------------------

def proposals_router(db_url: str, clock=None) -> APIRouter:
    conninfo = _conninfo(db_url)
    router = APIRouter()

    def _get_clock():
        if clock is not None:
            return clock
        from agg_cp.clock import SystemClock
        return SystemClock()

    def _signer_token_lookup(conn, token: str):
        import hashlib as _hl
        th = _hl.sha256(token.encode()).hexdigest()
        row = conn.execute(
            "SELECT org_id, user_id, key_id, scope FROM signer_token_lookup(%s)",
            [th],
        ).fetchone()
        if row is None:
            return None
        return {"org_id": str(row[0]), "user_id": str(row[1]),
                "key_id": row[2], "scope": row[3]}

    def _device_token_lookup(conn, token: str):
        import hashlib as _hl
        th = _hl.sha256(token.encode()).hexdigest()
        return conn.execute("SELECT * FROM device_token_lookup(%s)", [th]).fetchone()

    def _auth(conn, request: Request):
        """Returns (org_id_str, user_id_str, session_id|None,
                    auth_method, key_id|None, err_response).
        Sets app.org_id on the connection for the token path.
        """
        from agg_cp.auth import validate_session
        auth_hdr = request.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            bearer = auth_hdr[7:]
            info = _signer_token_lookup(conn, bearer)
            if info is not None:
                if info["scope"] != "confirmed":
                    return None, None, None, None, None, JSONResponse(
                        {"error": "token scope not accepted"}, status_code=403)
                # S-1 1a: set org context BEFORE the kind lookup (MUST 5)
                conn.execute("SELECT set_config('app.org_id', %s, true)",
                             [info["org_id"]])
                kid = info.get("key_id")
                # MUST 5: kind check unconditional (drop `if kid:`)
                kr = conn.execute(
                    "SELECT kind FROM approver_keys "
                    "WHERE key_id = %s AND org_id = %s::uuid AND revoked_at IS NULL",
                    [kid, info["org_id"]],
                ).fetchone()
                if kr is None or kr[0] != "cli":
                    return None, None, None, None, None, JSONResponse(
                        {"error": "forbidden", "detail": "key not cli or revoked"},
                        status_code=403)
                return (info["org_id"], info["user_id"], None,
                        "signer_token", kid, None)
            dt = _device_token_lookup(conn, bearer)
            if dt is not None:
                return None, None, None, None, None, JSONResponse(
                    {"error": "device tokens not accepted"}, status_code=403)
            return None, None, None, None, None, JSONResponse(
                {"error": "unauthorized"}, status_code=401)
        result, err = validate_session(conn, request, _get_clock())
        if err:
            return None, None, None, None, None, err
        o, u, sid, _, _ = result
        return str(o), str(u), sid, "session", None, None

    # =================================================================
    # POST /api/v1/admin/bundle-proposals
    # =================================================================
    @rbac_route(router, "post", "/api/v1/admin/bundle-proposals",
                role="signer_or_session", scope="org")
    async def create_proposal(request: Request) -> JSONResponse:
        # MUST 2: read body before any DB connection
        raw, err = await _read_body_capped(request)
        if err:
            return err

        # Strict parse of outer body (MUST 2: duplicate keys, NaN at every depth)
        try:
            body = _strict_json_parse(raw.decode("utf-8", "replace"))
        except (ValueError, RecursionError, TypeError) as exc:
            return JSONResponse({"error": "bad_json", "detail": str(exc)[:200]},
                                status_code=400)

        if not isinstance(body, dict):
            return JSONResponse({"error": "bad_json", "detail": "body must be object"},
                                status_code=400)

        # Exact outer keys
        allowed_outer = {"project_id", "bundle", "bundle_raw"}
        extra = set(body) - allowed_outer
        if extra:
            return JSONResponse({"error": "unknown_fields",
                                 "detail": f"extra keys: {sorted(extra)}"},
                                status_code=400)

        project_id = body.get("project_id", "")
        if not project_id or not isinstance(project_id, str):
            return JSONResponse({"error": "missing project_id"}, status_code=400)
        # MUST 4: validate project_id as canonical UUID (R3-a)
        if not _is_canonical_uuid(project_id):
            return JSONResponse({"error": "bad_project_id",
                                 "detail": "project_id must be a canonical UUID"},
                                status_code=400)

        bundle_raw_str = body.get("bundle_raw")
        bundle_obj = body.get("bundle")
        if (bundle_raw_str is not None) == (bundle_obj is not None):
            return JSONResponse({"error": "bad_body",
                                 "detail": "provide exactly one of bundle or bundle_raw"},
                                status_code=400)

        # Parse the bundle
        try:
            if bundle_raw_str is not None:
                if not isinstance(bundle_raw_str, str):
                    return JSONResponse({"error": "bad_json",
                                         "detail": "bundle_raw must be a string"},
                                        status_code=400)
                bundle = _strict_json_parse(bundle_raw_str)
            else:
                # Re-serialize and re-parse strictly for dup key detection
                bundle = _strict_json_parse(json.dumps(bundle_obj))
        except (ValueError, RecursionError, TypeError) as exc:
            return JSONResponse({"error": "bad_json", "detail": str(exc)[:200]},
                                status_code=400)

        if not isinstance(bundle, dict):
            return JSONResponse({"error": "bad_json", "detail": "bundle must be object"},
                                status_code=400)

        # change_approvals refused
        if "change_approvals" in bundle:
            return JSONResponse({"error": "change_approvals_refused"}, status_code=400)

        # Unknown and server-owned fields
        for k in bundle:
            if k not in BUNDLE_FIELDS:
                return JSONResponse({"error": "unknown_fields",
                                     "detail": f"unknown key: {k}"}, status_code=400)
            if k in _SERVER_OWNED:
                return JSONResponse({"error": "server_owned_field",
                                     "detail": f"server-owned: {k}"}, status_code=400)

        # Policy sections must be objects
        for sec in _POLICY_SECTIONS:
            if sec in bundle and not isinstance(bundle[sec], dict):
                return JSONResponse({"error": "invalid_bundle",
                                     "detail": f"{sec} must be an object"}, status_code=400)

        # --- DB work (no await after this point) ---
        with _conn(conninfo) as conn:
            org_id, user_id, session_id, auth_method, key_id, aerr = _auth(conn, request)
            if aerr:
                return aerr
            conn.execute("SELECT set_config('app.org_id', %s, true)", [str(org_id)])

            if not _is_project_admin(conn, user_id, project_id):
                conn.rollback()
                return JSONResponse({"error": "forbidden"}, status_code=403)

            proj = conn.execute(
                "SELECT id, environment FROM projects "
                "WHERE id = %s::uuid AND org_id = %s::uuid",
                [project_id, str(org_id)],
            ).fetchone()
            if proj is None:
                conn.rollback()
                return JSONResponse({"error": "not_found"}, status_code=404)
            env_name = proj[1] or "prod"

            base_sequence = _max_sequence(conn, str(org_id), project_id)
            sequence = base_sequence + 1

            # registry_version from verify_chain (MUST 7)
            fp = _genesis_fingerprint(conn, str(org_id))
            from agg_cp.sync.registry import get_chain
            chain = get_chain(conn, str(org_id))
            registry_version = 0
            if chain and fp:
                try:
                    reg = verify_chain(chain, fp)
                    registry_version = reg.version
                except Exception:
                    registry_version = 0

            now = _get_clock().now()
            issued_at = int(now.timestamp())

            full = dict(bundle)
            full.update({
                "org_id": str(org_id), "project_id": project_id,
                "sequence": sequence, "base_sequence": base_sequence,
                "registry_version": registry_version, "environment": env_name,
                "issued_at": issued_at, "not_before": issued_at,
            })

            # Canonical bytes and hash -- errors -> 400 (MUST 3)
            try:
                canonical = _canonical_json_bytes(full)
            except (RecursionError, ValueError, TypeError) as exc:
                conn.rollback()
                return JSONResponse({"error": "invalid_bundle",
                                     "detail": str(exc)[:200]}, status_code=400)

            if len(canonical) > BUNDLE_MAX_BYTES:
                conn.rollback()
                return JSONResponse({"error": "too_large"}, status_code=400)

            bhash = _bundle_hash(full)

            # Base (MUST 7: envelope payload for base >= 1)
            if base_sequence > 0:
                base_row = conn.execute(
                    "SELECT bundle_blob FROM policy_bundles "
                    "WHERE org_id = %s::uuid AND project_id = %s::uuid AND sequence = %s",
                    [str(org_id), project_id, base_sequence],
                ).fetchone()
                if base_row is not None:
                    try:
                        blob = json.loads(bytes(base_row[0]))
                        # blob is the envelope; payload is the bundle (MUST 5: no fallback)
                        if not isinstance(blob, dict) or "payload" not in blob:
                            raise ValueError("base row is not a dict envelope with payload")
                        base_payload = blob["payload"]
                        if not isinstance(base_payload, dict):
                            raise ValueError("base row payload is not a dict")
                    except Exception:
                        conn.rollback()
                        return JSONResponse({"error": "invalid_bundle",
                                             "detail": "base row parse error"},
                                            status_code=400)
                else:
                    base_payload = _deny_all_base()
            else:
                base_payload = _deny_all_base()

            base_hash = hashlib.sha256(_canonical_json_bytes(base_payload)).hexdigest()

            # Diff and loosened -- errors -> 400 (MUST 3)
            try:
                sections_loosened = loosened(base_payload, full)
            except Exception as exc:
                conn.rollback()
                return JSONResponse({"error": "invalid_bundle",
                                     "detail": f"loosened error: {exc!s:.200}"}, status_code=400)

            try:
                diff = {}
                for sec in ("folder_policy", "governance_policy", "mcp_policy",
                            "approval", "environment"):
                    old = base_payload.get(sec, {})
                    new = full.get(sec, {})
                    if old != new:
                        diff[sec] = {"old": old, "new": new}
            except Exception as exc:
                conn.rollback()
                return JSONResponse({"error": "invalid_bundle",
                                     "detail": f"diff error: {exc!s:.200}"}, status_code=400)

            loosened_json = json.dumps(sections_loosened)

            # Build response BEFORE commit (MUST 3)
            proposal_id = str(uuid.uuid4())
            resp_body = {
                "id": proposal_id,
                "bundle_hash": bhash,
                "bundle": full,
                "base_sequence": base_sequence,
                "sequence": sequence,
                "registry_version": registry_version,
                "diff": diff,
                "loosened": sections_loosened,
                "status": "open",
            }

            conn.execute(
                "INSERT INTO policy_change_requests "
                "(id, org_id, project_id, status, proposer_user_id, "
                "payload, base_sequence, sequence, new_sha, base_sha, "
                "registry_version, loosened_fields, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, 'open', %s::uuid, "
                "%s, %s, %s, %s, %s, %s, %s, %s)",
                [proposal_id, str(org_id), project_id, str(user_id),
                 canonical, base_sequence, sequence, bhash, base_hash,
                 registry_version, loosened_json, now],
            )
            _admin_audit(conn, org_id, "bundle_proposal.create", {
                "proposal_id": proposal_id, "project_id": project_id,
                "bundle_hash": bhash, "base_sequence": base_sequence,
                "auth": auth_method,
                **({"key_id": key_id} if key_id else {}),
            })
            conn.commit()

        return JSONResponse(resp_body, status_code=201)

    # =================================================================
    # GET /api/v1/admin/bundle-proposals (MUST 6: list)
    # =================================================================
    @rbac_route(router, "get", "/api/v1/admin/bundle-proposals",
                role="signer_or_session", scope="org")
    async def list_proposals(request: Request) -> JSONResponse:
        with _conn(conninfo) as conn:
            org_id, user_id, _, auth, kid, aerr = _auth(conn, request)
            if aerr:
                return aerr
            conn.execute("SELECT set_config('app.org_id', %s, true)", [str(org_id)])

            project = request.query_params.get("project", "")
            cursor = request.query_params.get("cursor")
            limit = 20

            # MUST 4: validate project as canonical UUID (R3-a)
            if project and not _is_canonical_uuid(project):
                conn.rollback()
                return JSONResponse({"error": "bad_project",
                                     "detail": "project must be a canonical UUID"},
                                    status_code=400)
            # MUST 4: parse cursor to datetime, pass the object to SQL (R3-a)
            # Require a proper ISO datetime (not week dates, not plain dates).
            import datetime as _dt
            cursor_dt = None
            if cursor:
                try:
                    parsed = _dt.datetime.fromisoformat(
                        cursor.replace("Z", "+00:00"))
                    # Reject date-only or week-date formats: cursor must
                    # have a time component (our cursors come from
                    # created_at.isoformat() which always includes T).
                    if "T" not in cursor and " " not in cursor:
                        raise ValueError("cursor must be a full datetime")
                    cursor_dt = parsed
                except (ValueError, AttributeError):
                    conn.rollback()
                    return JSONResponse({"error": "bad_cursor",
                                         "detail": "cursor must be an ISO timestamp"},
                                        status_code=400)

            q = ("SELECT id, project_id, status, new_sha, base_sequence, "
                 "sequence, registry_version, created_at "
                 "FROM policy_change_requests WHERE org_id = %s::uuid")
            params: list = [str(org_id)]
            if project:
                q += " AND project_id = %s::uuid"
                params.append(project)
            if cursor_dt is not None:
                q += " AND created_at < %s"
                params.append(cursor_dt)
            q += " ORDER BY created_at DESC LIMIT %s"
            params.append(limit + 1)

            rows = conn.execute(q, params).fetchall()
            items = []
            for r in rows[:limit]:
                items.append({
                    "id": str(r[0]), "project_id": str(r[1]),
                    "status": r[2], "bundle_hash": r[3],
                    "base_sequence": r[4], "sequence": r[5],
                    "registry_version": r[6],
                    "created_at": r[7].isoformat() if r[7] else None,
                })
            next_cursor = None
            if len(rows) > limit:
                next_cursor = rows[limit - 1][7].isoformat() if rows[limit - 1][7] else None
            conn.rollback()

        return JSONResponse({"items": items, "next_cursor": next_cursor})

    # =================================================================
    # GET /api/v1/admin/bundle-proposals/{proposal_id} (MUST 6: detail)
    # =================================================================
    @rbac_route(router, "get",
                "/api/v1/admin/bundle-proposals/{proposal_id}",
                role="signer_or_session", scope="org")
    async def get_proposal(proposal_id: str, request: Request) -> JSONResponse:
        if not _is_canonical_uuid(proposal_id):
            return JSONResponse({"error": "not_found"}, status_code=404)

        with _conn(conninfo) as conn:
            org_id, user_id, _, auth, kid, aerr = _auth(conn, request)
            if aerr:
                return aerr
            conn.execute("SELECT set_config('app.org_id', %s, true)", [str(org_id)])

            row = conn.execute(
                "SELECT id, project_id, status, new_sha, base_sequence, "
                "sequence, registry_version, payload, proposer_user_id, "
                "loosened_fields, org_id, created_at "
                "FROM policy_change_requests "
                "WHERE id = %s::uuid AND org_id = %s::uuid",
                [proposal_id, str(org_id)],
            ).fetchone()
            if row is None:
                conn.rollback()
                return JSONResponse({"error": "not_found"}, status_code=404)

            _, proj_id, status, bhash, base_seq, seq, rv, payload_bytes, \
                proposer, lf, r_org, cat = row

            # payload is bytea (canonical JSON); losn is json (may arrive parsed)
            try:
                pb = bytes(payload_bytes) if payload_bytes else b""
                bundle = json.loads(pb) if pb else {}
            except Exception:
                bundle = {}
            try:
                if isinstance(lf, dict):
                    losn = lf
                elif isinstance(lf, (str, bytes)):
                    losn = json.loads(lf) if lf else {}
                else:
                    losn = {}
            except Exception:
                losn = {}

            # Approvals
            approvals = conn.execute(
                "SELECT user_id, key_id, signature FROM policy_change_approvals "
                "WHERE change_request_id = %s::uuid ORDER BY created_at",
                [proposal_id],
            ).fetchall()
            app_list = [{"user_id": str(a[0]), "key_id": a[1],
                         "kind": "cli"} for a in approvals]

            # Base for base >= 1
            base_info = None
            if base_seq and base_seq > 0:
                brow = conn.execute(
                    "SELECT bundle_blob FROM policy_bundles "
                    "WHERE org_id = %s::uuid AND project_id = %s::uuid AND sequence = %s",
                    [str(org_id), str(proj_id), base_seq],
                ).fetchone()
                if brow:
                    try:
                        base_env = json.loads(bytes(brow[0]))
                        base_apps = conn.execute(
                            "SELECT user_id, key_id, signature FROM policy_change_approvals "
                            "WHERE change_request_id IN ("
                            "  SELECT id FROM policy_change_requests "
                            "  WHERE org_id = %s::uuid AND project_id = %s::uuid "
                            "  AND sequence = %s"
                            ")",
                            [str(org_id), str(proj_id), base_seq],
                        ).fetchall()
                        base_info = {
                            "envelope": base_env,
                            "change_approvals": [
                                {"user_id": str(a[0]), "key_id": a[1]}
                                for a in base_apps
                            ],
                        }
                    except Exception:
                        pass
            conn.rollback()

        resp = {
            "id": proposal_id, "org_id": str(r_org),
            "project_id": str(proj_id), "status": status,
            "bundle_hash": bhash, "bundle": bundle,
            "base_sequence": base_seq, "sequence": seq,
            "registry_version": rv, "loosened": losn,
            "proposer_user_id": str(proposer),
            "approvals": app_list,
            "created_at": cat.isoformat() if cat else None,
        }
        if base_info:
            resp["base"] = base_info
        return JSONResponse(resp)

    # =================================================================
    # POST .../approvals (MUST 1, 4)
    # =================================================================
    @rbac_route(router, "post",
                "/api/v1/admin/bundle-proposals/{proposal_id}/approvals",
                role="signer_or_session", scope="org")
    async def approve_proposal(proposal_id: str,
                               request: Request) -> JSONResponse:
        # MUST 4 (R3-a): canonical UUID check before body parsing (path param -> 404)
        if not _is_canonical_uuid(proposal_id):
            return JSONResponse({"error": "not_found"}, status_code=404)

        # MUST 2: body before DB
        raw, berr = await _read_body_capped(request)
        if berr:
            return berr

        # Strict parse outer body (MUST 4)
        try:
            body = _strict_json_parse(raw.decode("utf-8", "replace"))
        except (ValueError, RecursionError, TypeError) as exc:
            return JSONResponse({"error": "bad_approval", "detail": str(exc)[:200]},
                                status_code=400)

        if not isinstance(body, dict):
            return JSONResponse({"error": "bad_approval"}, status_code=400)

        # Exact outer key
        if set(body.keys()) != {"approval"}:
            return JSONResponse({"error": "bad_approval",
                                 "detail": "body must have exactly {approval}"},
                                status_code=400)

        env = body["approval"]
        if not isinstance(env, dict):
            return JSONResponse({"error": "bad_approval"}, status_code=400)

        # MUST 4: exact envelope keys
        env_keys = {"kind", "sig_v", "payload", "signatures"}
        if set(env.keys()) != env_keys:
            return JSONResponse({"error": "bad_approval",
                                 "detail": "envelope must have exactly kind,sig_v,payload,signatures"},
                                status_code=400)

        if env.get("kind") != "agg/policy-change/v1":
            return JSONResponse({"error": "bad_approval", "detail": "wrong kind"},
                                status_code=400)
        if env.get("sig_v") != 1:
            return JSONResponse({"error": "bad_approval", "detail": "sig_v must be 1"},
                                status_code=400)

        sigs = env.get("signatures")
        if not isinstance(sigs, list) or len(sigs) != 1:
            return JSONResponse({"error": "exactly_one_signature",
                                 "detail": f"got {len(sigs) if isinstance(sigs, list) else 'non-list'}"},
                                status_code=400)

        sig_entry = sigs[0]
        if not isinstance(sig_entry, dict):
            return JSONResponse({"error": "bad_approval"}, status_code=400)

        # MUST 3: signature dict keys exactly {key_id, alg, sig} (P6)
        if set(sig_entry.keys()) != {"key_id", "alg", "sig"}:
            return JSONResponse({"error": "bad_approval",
                                 "detail": "signature must have exactly {key_id, alg, sig}"},
                                status_code=400)

        # MUST 3: key_id and sig must be strings (P7)
        sig_kid = sig_entry.get("key_id")
        if not isinstance(sig_kid, str):
            return JSONResponse({"error": "bad_approval",
                                 "detail": "key_id must be a string"},
                                status_code=400)
        if not isinstance(sig_entry.get("sig"), str):
            return JSONResponse({"error": "bad_approval",
                                 "detail": "sig must be a string"},
                                status_code=400)

        if sig_entry.get("alg") != "ed25519":
            return JSONResponse({"error": "bad_approval", "detail": "alg must be ed25519"},
                                status_code=400)

        a_payload = env.get("payload")
        if not isinstance(a_payload, dict) or set(a_payload.keys()) != {"bundle_hash"}:
            return JSONResponse({"error": "bad_approval",
                                 "detail": "payload must be exactly {bundle_hash}"},
                                status_code=400)

        # --- DB work ---
        with _conn(conninfo) as conn:
            org_id, user_id, session_id, auth_method, token_key_id, aerr = _auth(conn, request)
            if aerr:
                return aerr
            conn.execute("SELECT set_config('app.org_id', %s, true)", [str(org_id)])

            prop = conn.execute(
                "SELECT id, status, new_sha, proposer_user_id, project_id, "
                "base_sequence, org_id "
                "FROM policy_change_requests "
                "WHERE id = %s::uuid AND org_id = %s::uuid FOR UPDATE",
                [proposal_id, str(org_id)],
            ).fetchone()
            if prop is None:
                conn.rollback()
                return JSONResponse({"error": "not_found"}, status_code=404)

            _, pstatus, phash, proposer_id, pproject, pbase, porg = prop

            if pstatus != "open":
                conn.rollback()
                return JSONResponse({"error": "not_open"}, status_code=409)

            if a_payload["bundle_hash"] != phash:
                conn.rollback()
                return JSONResponse({"error": "hash_mismatch"}, status_code=400)

            # Step 4 (stale base, ordered before projections per D1)
            cur_max = _max_sequence(conn, str(org_id), str(pproject))
            if pbase != cur_max:
                conn.rollback()
                return JSONResponse({"error": "stale_base",
                                     "detail": f"base {pbase} != max {cur_max}"},
                                    status_code=400)

            # Step 3: projection (may only refuse)
            kr = conn.execute(
                "SELECT kind, user_id, revoked_at FROM approver_keys "
                "WHERE key_id = %s AND org_id = %s::uuid",
                [sig_kid, str(org_id)],
            ).fetchone()
            if kr is None:
                conn.rollback()
                return JSONResponse({"error": "wrong_kind", "detail": "unknown_key"},
                                    status_code=400)

            ak_kind, ak_user, ak_revoked = kr
            if ak_revoked is not None:
                conn.rollback()
                return JSONResponse({"error": "wrong_kind", "detail": "key_revoked"},
                                    status_code=400)
            if ak_kind != "cli":
                conn.rollback()
                return JSONResponse({"error": "wrong_kind", "detail": f"kind={ak_kind}"},
                                    status_code=400)

            # S-1c: token caller's approval key_id must equal the token's
            # bound key (403 not_key_owner).  Checked before proposer/owner
            # because it is an authentication property.
            if token_key_id is not None and sig_kid != token_key_id:
                conn.rollback()
                return JSONResponse({"error": "not_key_owner",
                                     "detail": "approval key_id != token key"},
                                    status_code=403)

            if str(ak_user) == str(proposer_id):
                conn.rollback()
                return JSONResponse({"error": "proposer_cannot_approve"}, status_code=400)

            if str(ak_user) != str(user_id):
                conn.rollback()
                return JSONResponse({"error": "not_key_owner"}, status_code=403)

            # already_approved keyed on registry user (MUST 2 / P1c)
            # Note: this uses ak_user from the projection; after registry
            # verification below, reg_user will be confirmed == user_id.
            existing = conn.execute(
                "SELECT 1 FROM policy_change_approvals "
                "WHERE change_request_id = %s::uuid AND user_id = %s",
                [proposal_id, str(ak_user)],
            ).fetchone()
            if existing:
                conn.rollback()
                return JSONResponse({"error": "already_approved"}, status_code=409)

            # MUST 1: steps 5-6 (verify against signed registry)
            fp = _genesis_fingerprint(conn, str(org_id))
            from agg_cp.sync.registry import get_chain
            chain = get_chain(conn, str(org_id))

            if not chain or not fp:
                conn.rollback()
                return JSONResponse({"error": "no_registry"}, status_code=400)

            try:
                reg = verify_chain(chain, fp)
            except Exception:
                conn.rollback()
                return JSONResponse({"error": "no_registry",
                                     "detail": "chain verification failed"},
                                    status_code=400)

            # Check key in registry
            reg_entry = reg._keys.get(sig_kid)
            if reg_entry is None:
                conn.rollback()
                return JSONResponse({"error": "not_in_registry"}, status_code=400)

            if reg_entry.get("kind") != "cli":
                conn.rollback()
                return JSONResponse({"error": "wrong_kind",
                                     "detail": "registry kind != cli"},
                                    status_code=400)

            # Recheck proposer from registry entry
            reg_user = reg_entry.get("user_id")
            if str(reg_user) == str(proposer_id):
                conn.rollback()
                return JSONResponse({"error": "proposer_cannot_approve"}, status_code=400)

            # MUST 2 (P1c): recheck owner from registry entry
            if str(reg_user) != str(user_id):
                conn.rollback()
                return JSONResponse({"error": "not_key_owner",
                                     "detail": "registry owner != authenticated user"},
                                    status_code=403)

            # MUST 1: call _verify_change_approvals (P1b counting role)
            # The stored payload is the canonical bundle from the proposal row.
            # _verify_change_approvals computes _bundle_hash(payload) and
            # checks signatures, cli kind, and counting role from the registry.
            try:
                stored_payload = json.loads(bytes(
                    conn.execute(
                        "SELECT payload FROM policy_change_requests "
                        "WHERE id = %s::uuid",
                        [proposal_id],
                    ).fetchone()[0]
                ))
            except Exception:
                conn.rollback()
                return JSONResponse({"error": "approval_invalid",
                                     "detail": "stored payload unreadable"},
                                    status_code=400)
            try:
                _verify_change_approvals(
                    stored_payload, [env], reg,
                    is_loosening=False, is_first_bundle=False,
                )
            except BundleError as exc:
                conn.rollback()
                return JSONResponse({"error": "approval_invalid",
                                     "detail": str(exc)[:200]},
                                    status_code=400)

            # Store with the registry entry's user_id
            canonical_env = json.dumps(env, sort_keys=True, separators=(",", ":"))
            now = _get_clock().now()
            conn.execute(
                "INSERT INTO policy_change_approvals "
                "(id, org_id, change_request_id, user_id, key_id, "
                "signature, signed_at, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, %s, %s, %s, %s)",
                [str(uuid.uuid4()), str(org_id), proposal_id,
                 str(reg_user), sig_kid, canonical_env, now, now],
            )
            _admin_audit(conn, org_id, "bundle_proposal.approve", {
                "proposal_id": proposal_id, "user_id": str(reg_user),
                "key_id": sig_kid, "auth": auth_method,
            })
            conn.commit()

        return JSONResponse({"ok": True}, status_code=201)

    # =================================================================
    # POST .../publish (T3 shell, MUST 8)
    # =================================================================
    @rbac_route(router, "post",
                "/api/v1/admin/bundle-proposals/{proposal_id}/publish",
                role="signer_or_session", scope="org")
    async def publish_proposal(proposal_id: str,
                               request: Request) -> JSONResponse:
        # MUST 2: body before DB
        raw, berr = await _read_body_capped(request)
        if berr:
            return berr

        with _conn(conninfo) as conn:
            org_id, user_id, session_id, auth_method, key_id, aerr = _auth(conn, request)
            if aerr:
                return aerr
            conn.execute("SELECT set_config('app.org_id', %s, true)", [str(org_id)])

            # Fresh-session for session auth (spec 3.2: before path id).
            # Token age not checked: S-1f says 600 s token < 900 s rule.
            if auth_method == "session" and session_id is not None:
                from agg_cp.auth import require_fresh_session
                ferr = require_fresh_session(conn, session_id, _get_clock())
                if ferr:
                    return ferr

            # MUST 4 (R3-a): canonical UUID after auth (spec 3.6: 404 after auth)
            if not _is_canonical_uuid(proposal_id):
                conn.rollback()
                return JSONResponse({"error": "not_found"}, status_code=404)

            prop = conn.execute(
                "SELECT id, status, proposer_user_id, project_id, "
                "base_sequence, org_id "
                "FROM policy_change_requests "
                "WHERE id = %s::uuid AND org_id = %s::uuid FOR UPDATE",
                [proposal_id, str(org_id)],
            ).fetchone()
            if prop is None:
                conn.rollback()
                return JSONResponse({"error": "not_found"}, status_code=404)

            _, pstatus, proposer_id, pproject, pbase, porg = prop

            if not _is_project_admin(conn, user_id, str(pproject)):
                conn.rollback()
                return JSONResponse({"error": "forbidden"}, status_code=403)

            if pstatus != "open":
                conn.rollback()
                return JSONResponse({"error": "not_open"}, status_code=409)

            # Stale base recheck
            cur_max = _max_sequence(conn, str(org_id), str(pproject))
            if pbase != cur_max:
                conn.rollback()
                _audit_refused(conninfo, org_id, proposal_id, "stale_base",
                               auth_method, key_id)
                return JSONResponse({"error": "stale_base"}, status_code=400)

            # Publisher exclusion (MUST 8)
            approvals = conn.execute(
                "SELECT user_id FROM policy_change_approvals "
                "WHERE change_request_id = %s::uuid",
                [proposal_id],
            ).fetchall()
            approval_uids = {str(r[0]) for r in approvals}

            if str(user_id) in approval_uids:
                conn.rollback()
                _audit_refused(conninfo, org_id, proposal_id,
                               "publisher_in_approvals", auth_method, key_id)
                return JSONResponse({"error": "publisher_in_approvals",
                                     "detail": "publisher is among approvals"},
                                    status_code=400)

            # Proposer exclusion (MUST 8 / T3-R1-10)
            if str(proposer_id) in approval_uids:
                conn.rollback()
                _audit_refused(conninfo, org_id, proposal_id,
                               "proposer_in_approvals", auth_method, key_id)
                return JSONResponse({"error": "proposer_in_approvals",
                                     "detail": "proposer is among approvals"},
                                    status_code=400)

            # T3 shell: verification_pending (M-9: no 2xx, no policy_bundles)
            conn.rollback()

        _audit_refused(conninfo, org_id, proposal_id,
                       "verification_pending", auth_method, key_id)
        return JSONResponse({"error": "verification_pending",
                             "detail": "T4 server verification not implemented"},
                            status_code=400)

    return router


def _audit_refused(conninfo, org_id, proposal_id, reason, auth_method, key_id):
    """Write publish-refusal audit in a separate transaction (M-2)."""
    with _conn(conninfo) as c2:
        c2.execute("SELECT set_config('app.org_id', %s, true)", [str(org_id)])
        _admin_audit(c2, org_id, "bundle_proposal.publish_refused", {
            "proposal_id": proposal_id, "reason": reason,
            "auth": auth_method,
            **({"key_id": key_id} if key_id else {}),
        })
        c2.commit()
