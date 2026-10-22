"""Server-side signer routes and logic (D5.2, D7.2, D10.6).

Routes under ``/api/v1/sync/signer/``.  Signer auth uses
``agg/signer-assert/v1`` tokens: 10 min, stored as SHA-256 hash.

Reuses T5 SECURITY DEFINER functions: ``signer_link_consume``,
``cli_key_lookup``, ``signer_token_lookup``, ``signer_nonce_insert``.
Reuses ``agg_cp.sync.registry.store_registry_version``.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from typing import Any

from fastapi import APIRouter, Header, Query, Request
from fastapi.responses import JSONResponse

from sandbox.protocol.domains import SIGNER_ASSERT
from sandbox.protocol.envelope import (
    EnvelopeError,
    verify_envelope,
)
from sandbox.protocol.registry import RegistryError

from ..rbac import rbac_route
from ..sync.registry import store_registry_version


# -- Constants -------------------------------------------------------------

SIGNER_TOKEN_MAX_AGE: int = 600  # 10 minutes


# -- Exceptions ------------------------------------------------------------

class SignerNonceReplay(Exception):
    """A replayed (key_id, nonce) pair."""


class StaleLinkSession(Exception):
    """The session is older than the max_age for a link."""


class LinkCodeConsumed(Exception):
    """The link code has already been consumed."""


class SignerScopeError(Exception):
    """The signer token scope does not allow this route."""


class SignerNotFound(Exception):
    """The requested resource was not found (IDOR protection)."""


class GenesisAlreadyExists(Exception):
    """A genesis (v1) registry already exists for this org."""


# -- Clock helper ----------------------------------------------------------
# agg_cp modules must not call ``time.time()`` directly; they use the
# injected Clock.  This helper provides a float-epoch fallback for the
# pure-logic functions that are also called from the connector tests
# (which have no Clock).  The _epoch_now function is the ONLY place
# the system clock is read inside this module.

def _epoch_now() -> float:
    """Current UTC epoch seconds via the Clock protocol."""
    from ..clock import SystemClock
    return SystemClock().now().timestamp()


# -- Pure-logic functions (testable without DB) ----------------------------

def create_signer_token() -> tuple[str, str]:
    """Generate an opaque 256-bit token; return (raw, sha256_hex)."""
    raw = secrets.token_hex(32)  # 256 bits
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


def validate_link_session(
    auth_time: float,
    max_age: int = 900,
    *,
    _now: float | None = None,
) -> None:
    """Raise :class:`StaleLinkSession` if *auth_time* is too old.

    *_now* overrides the current time (float epoch) for testing.
    """
    now = _now if _now is not None else _epoch_now()
    if now - auth_time > max_age:
        raise StaleLinkSession(
            f"session auth_time {auth_time} is older than {max_age}s"
        )


def check_signer_token_scope(
    token_scope: dict[str, Any],
    route: str,
) -> None:
    """Check that *token_scope* allows access to *route*.

    A pending-link token (status ``"pending_link"``) may only access
    the ``"link"`` route (F5).  A confirmed token accesses all routes.
    """
    status = token_scope.get("status", "")
    if status == "pending_link" and route != "link":
        raise SignerScopeError(
            f"pending_link token cannot access route {route!r}"
        )


def get_pending(
    org_id: str,
    requester_org_id: str,
) -> list[dict[str, Any]]:
    """Return pending items for *org_id*.  IDOR: mismatched org -> 404."""
    if org_id != requester_org_id:
        raise SignerNotFound(f"org {org_id} not found")
    return []


def post_signatures(
    org_id: str,
    requester_org_id: str,
    signatures: list[dict[str, Any]],
) -> dict[str, Any]:
    """Store signatures for *org_id*.  IDOR: mismatched org -> 404."""
    if org_id != requester_org_id:
        raise SignerNotFound(f"org {org_id} not found")
    return {"stored": len(signatures)}


# -- DB-backed helpers (used by routes) ------------------------------------

def _db_cli_key_lookup(conn: Any, key_id: str) -> dict[str, Any] | None:
    """Lookup a CLI key via the SECURITY DEFINER function."""
    row = conn.execute(
        "SELECT org_id, user_id, public_key, status "
        "FROM cli_key_lookup(%s)",
        [key_id],
    ).fetchone()
    if row is None:
        return None
    return {
        "org_id": str(row[0]),
        "user_id": str(row[1]),
        "public_key": row[2],
        "status": row[3],
    }


def _db_signer_nonce_insert(conn: Any, key_id: str, nonce: str) -> None:
    """Insert a nonce via the SECURITY DEFINER function (unique constraint)."""
    conn.execute(
        "SELECT signer_nonce_insert(%s, %s, now())",
        [key_id, nonce],
    )


def _db_signer_token_store(
    conn: Any,
    org_id: str,
    user_id: str,
    key_id: str,
    token_hash: str,
    scope: str,
) -> None:
    """Store a signer token hash."""
    conn.execute(
        "SELECT set_config('app.org_id', %s, false)", [org_id]
    )
    conn.execute(
        "INSERT INTO signer_tokens "
        "(id, org_id, user_id, key_id, token_hash, expires_at, scope, "
        " created_at) "
        "VALUES (%s, %s, %s, %s, %s, "
        " now() + make_interval(secs => %s), %s, now())",
        [
            str(uuid.uuid4()),
            org_id,
            user_id,
            key_id,
            token_hash,
            SIGNER_TOKEN_MAX_AGE,
            scope,
        ],
    )


def _db_signer_token_lookup(
    conn: Any, token_hash: str
) -> dict[str, Any] | None:
    """Lookup a signer token via the SECURITY DEFINER function."""
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


def _db_consume_signer_link(
    conn: Any, code_hash: str
) -> dict[str, Any] | None:
    """Consume a signer link code via the SECURITY DEFINER function."""
    row = conn.execute(
        "SELECT org_id, user_id FROM signer_link_consume(%s)",
        [code_hash],
    ).fetchone()
    if row is None or row[0] is None:
        return None
    return {"org_id": str(row[0]), "user_id": str(row[1])}


# -- Authenticate signer (agg/signer-assert/v1) ---------------------------

def authenticate_signer(
    conn: Any,
    assertion: dict[str, Any],
    aud: str,
) -> dict[str, Any]:
    """Verify a signer assertion and return token info.

    Returns dict with org_id, user_id, key_id, status (pending_link or
    confirmed).  Raises on failure.
    """
    if assertion.get("kind") != "agg/signer-assert/v1":
        raise EnvelopeError("expected agg/signer-assert/v1")

    payload = assertion.get("payload", {})
    kid = payload.get("key_id", "")
    nonce = payload.get("nonce", "")
    iat = payload.get("iat", 0)

    # iat within 2 min
    if abs(_epoch_now() - iat) > 120:
        raise EnvelopeError("iat outside 2-minute window")

    # Lookup key
    key_info = _db_cli_key_lookup(conn, kid)
    if key_info is None:
        raise EnvelopeError(f"unknown key_id: {kid}")

    pub_bytes = bytes.fromhex(key_info["public_key"])

    # Verify signature
    verify_envelope(assertion, {kid: pub_bytes})

    # Nonce: unique per (key_id, nonce) via DB constraint
    try:
        _db_signer_nonce_insert(conn, kid, nonce)
    except Exception:
        raise SignerNonceReplay(f"nonce replay: {kid}/{nonce}")

    # Map status
    scope = "confirmed" if key_info["status"] == "signer" else "pending_link"

    return {
        "org_id": key_info["org_id"],
        "user_id": key_info["user_id"],
        "key_id": kid,
        "status": scope,
    }


# -- Signer link consumption (DB-backed) ----------------------------------

def consume_signer_link(
    conn: Any,
    code: str,
    key_id: str,
    public_key: str,
) -> dict[str, Any]:
    """Consume a signer link code and bind the CLI key.

    Uses the ``signer_link_consume`` SECURITY DEFINER function for
    atomic single-use consumption (checks ``used_at IS NULL`` and
    ``expires_at > now()``).  Then binds key_id and public_key.

    No auth_time or identity from the caller: user_id and org_id come
    from the link row.  The freshness check is server-side (the web
    route that created the code validated the session; the code itself
    has an ``expires_at``).

    Returns dict with org_id, user_id, key_id on success.
    """
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    result = _db_consume_signer_link(conn, code_hash)
    if result is None:
        raise LinkCodeConsumed("link code not found or already consumed")

    # Bind the key to the consumed link (used_at already set by function)
    conn.execute(
        "SELECT set_config('app.org_id', %s, false)",
        [result["org_id"]],
    )
    conn.execute(
        "UPDATE signer_links SET key_id = %s, public_key = %s "
        "WHERE code_hash = %s AND used_at IS NOT NULL",
        [key_id, public_key, code_hash],
    )

    return {
        "org_id": result["org_id"],
        "user_id": result["user_id"],
        "key_id": key_id,
    }


# -- Pending and signatures (DB-backed, org-scoped) -----------------------

def signer_pending(
    conn: Any,
    org_id: str,
) -> list[dict[str, Any]]:
    """Return pending items (registry versions, policy changes) for signing."""
    conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
    # Return empty list for now; T9/T12 will add real pending items
    return []


def store_signer_signatures(
    conn: Any,
    org_id: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    """Store admin signatures (registry or policy-change approvals).

    Dispatches to ``store_registry_version`` for registry envelopes.
    """
    sig_type = body.get("type", "")
    envelope = body.get("envelope")

    if sig_type == "registry" and envelope is not None:
        try:
            version = store_registry_version(conn, org_id, envelope)
        except RegistryError as exc:
            raise GenesisAlreadyExists(str(exc)) if "second genesis" in str(
                exc
            ) else exc
        return {"version": version}

    # Other types (policy-change, etc.) - T9/T12
    return {"stored": 0}


# -- FastAPI router --------------------------------------------------------

_LINK_CODE_MAX_AGE: int = 900  # 15 minutes
_LINK_CODE_BYTES: int = 16    # 128 bits minimum


def build_signer_router(db_url: str, clock: Any = None) -> APIRouter:
    """Build the ``/api/v1/sync/signer`` router and the web link-code route."""

    router = APIRouter(tags=["signer"])

    # -- Web: POST /api/v1/signer-links ------------------------------------
    # Creates a link code in a fresh session (validate_session, auth_time
    # within 15 min).  User and org from the session.  Returns the code
    # once; only the hash is stored (D5.2).

    @rbac_route(router, "post", "/api/v1/signer-links",
                role="session", scope="self")
    async def create_link_code_route(request: Request):
        conn = None
        try:
            import psycopg

            url = db_url.replace("postgresql+psycopg://", "postgresql://")
            conn = psycopg.connect(url, autocommit=False)
            conn.execute("SET ROLE agg_app")

            from ..auth import validate_session
            from ..clock import SystemClock

            actual_clock = clock if clock is not None else SystemClock()
            result, err = validate_session(conn, request, actual_clock)
            if err:
                return err
            org_id, user_id, session_id, _token, _csrf_hash = result

            # Fresh session: created_at within 15 min (server-side check)
            row = conn.execute(
                "SELECT created_at FROM web_sessions WHERE id = %s",
                [session_id],
            ).fetchone()
            if row is None:
                return JSONResponse(
                    {"error": "session_not_found"}, status_code=401
                )
            created_at = row[0]
            age = (actual_clock.now() - created_at).total_seconds()
            if age > _LINK_CODE_MAX_AGE:
                return JSONResponse(
                    {"error": "session_too_old"}, status_code=403
                )

            # Generate link code (at least 128 bits)
            code = secrets.token_hex(_LINK_CODE_BYTES)
            code_hash = hashlib.sha256(code.encode()).hexdigest()

            # Insert signer_links row (stores only the hash)
            conn.execute(
                "INSERT INTO signer_links "
                "(id, org_id, user_id, code_hash, expires_at, status) "
                "VALUES (%s, %s, %s, %s, "
                " now() + make_interval(secs => %s), 'pending')",
                [
                    str(uuid.uuid4()),
                    str(org_id),
                    str(user_id),
                    code_hash,
                    _LINK_CODE_MAX_AGE,
                ],
            )
            conn.commit()

            # Return the code once (never stored in cleartext)
            return JSONResponse({"code": code})
        except Exception as exc:
            return JSONResponse(
                {"error": str(exc)}, status_code=500
            )
        finally:
            if conn is not None:
                conn.close()

    # -- POST /api/v1/sync/signer/token ------------------------------------

    @rbac_route(router, "post", "/api/v1/sync/signer/token",
                role="preauth", scope="signer-assertion")
    async def token_route(request: Request):
        assertion = await request.json()
        conn = None
        try:
            import psycopg

            url = db_url.replace("postgresql+psycopg://", "postgresql://")
            conn = psycopg.connect(url, autocommit=True)
            conn.execute("SET ROLE agg_app")

            aud = str(request.base_url).rstrip("/")
            signer_info = authenticate_signer(conn, assertion, aud)

            raw_token, token_hash = create_signer_token()
            _db_signer_token_store(
                conn,
                signer_info["org_id"],
                signer_info["user_id"],
                signer_info["key_id"],
                token_hash,
                signer_info["status"],
            )
            conn.commit()

            return JSONResponse({"token": raw_token})
        except SignerNonceReplay:
            return JSONResponse(
                {"error": "nonce_replay"}, status_code=409
            )
        except EnvelopeError as exc:
            return JSONResponse(
                {"error": str(exc)}, status_code=401
            )
        except Exception as exc:
            return JSONResponse(
                {"error": str(exc)}, status_code=500
            )
        finally:
            if conn is not None:
                conn.close()

    # -- Helper: extract and validate Bearer token -------------------------

    def _auth_from_bearer(
        conn: Any, authorization: str, route: str
    ) -> dict[str, Any]:
        """Parse Bearer token, look up in DB, check scope."""
        if not authorization.startswith("Bearer "):
            raise EnvelopeError("missing Bearer token")
        raw_token = authorization[7:]
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        info = _db_signer_token_lookup(conn, token_hash)
        if info is None:
            raise EnvelopeError("invalid or expired token")
        # Scope check (F5)
        scope = info.get("scope", "")
        token_scope = {"status": scope, "key_id": info.get("key_id", "")}
        check_signer_token_scope(token_scope, route)
        return info

    # -- POST /link (CLI) ---------------------------------------------------
    # Accepts only code + key_id + public_key.  No auth_time, no
    # identity from the body.  user_id and org come from the
    # signer_links row via signer_link_consume (D5.2 security fix).

    @rbac_route(router, "post", "/api/v1/sync/signer/link",
                role="preauth", scope="link-code")
    async def link_route(request: Request):
        body = await request.json()
        code = body.get("code", "")
        key_id_val = body.get("key_id", "")
        public_key = body.get("public_key", "")
        conn = None
        try:
            import psycopg

            url = db_url.replace("postgresql+psycopg://", "postgresql://")
            conn = psycopg.connect(url, autocommit=True)
            conn.execute("SET ROLE agg_app")

            code_hash = hashlib.sha256(code.encode()).hexdigest()

            # Consume via SECURITY DEFINER function (atomic).
            # Checks used_at IS NULL AND expires_at > now().
            # Returns NULL for: not found, already used, or expired.
            # Return 410 Gone (secure: does not leak code existence).
            result = _db_consume_signer_link(conn, code_hash)
            if result is None:
                return JSONResponse(
                    {"error": "code not found, used, or expired"},
                    status_code=410,
                )

            # Bind the key to the link (used_at already set by function)
            conn.execute(
                "SELECT set_config('app.org_id', %s, false)",
                [result["org_id"]],
            )
            conn.execute(
                "UPDATE signer_links SET key_id = %s, public_key = %s "
                "WHERE code_hash = %s AND used_at IS NOT NULL",
                [key_id_val, public_key, code_hash],
            )

            return JSONResponse(
                {
                    "key_id": key_id_val,
                    "org_id": result["org_id"],
                    "user_id": result["user_id"],
                }
            )
        except Exception as exc:
            return JSONResponse(
                {"error": str(exc)}, status_code=500
            )
        finally:
            if conn is not None:
                conn.close()

    # -- GET /pending ------------------------------------------------------

    @rbac_route(router, "get", "/api/v1/sync/signer/pending",
                role="signer", scope="token")
    async def pending_route(
        request: Request,
        org_id: str | None = Query(default=None),
        authorization: str = Header(default=""),
    ):
        conn = None
        try:
            import psycopg

            url = db_url.replace("postgresql+psycopg://", "postgresql://")
            conn = psycopg.connect(url, autocommit=True)
            conn.execute("SET ROLE agg_app")

            info = _auth_from_bearer(conn, authorization, "pending")

            # IDOR: token's org must match requested org
            target_org = org_id or info["org_id"]
            if target_org != info["org_id"]:
                return JSONResponse(
                    {"error": "not found"}, status_code=404
                )

            items = signer_pending(conn, info["org_id"])
            return JSONResponse(items)
        except SignerScopeError:
            return JSONResponse(
                {"error": "scope denied"}, status_code=403
            )
        except EnvelopeError:
            return JSONResponse(
                {"error": "unauthorized"}, status_code=401
            )
        except Exception as exc:
            return JSONResponse(
                {"error": str(exc)}, status_code=500
            )
        finally:
            if conn is not None:
                conn.close()

    # -- POST /signatures --------------------------------------------------

    @rbac_route(router, "post", "/api/v1/sync/signer/signatures",
                role="signer", scope="token")
    async def signatures_route(
        request: Request,
        authorization: str = Header(default=""),
    ):
        conn = None
        auth_conn = None
        try:
            import psycopg

            url = db_url.replace("postgresql+psycopg://", "postgresql://")
            # Auth lookup uses autocommit (SECURITY DEFINER functions)
            auth_conn = psycopg.connect(url, autocommit=True)
            auth_conn.execute("SET ROLE agg_app")
            info = _auth_from_bearer(auth_conn, authorization, "signatures")
            auth_conn.close()
            auth_conn = None

            # Signatures use autocommit=False so store_registry_version
            # can use transaction-local set_config + commit.
            conn = psycopg.connect(url, autocommit=False)
            conn.execute("SET ROLE agg_app")

            body = await request.json()
            target_org = body.get("org_id", info["org_id"])

            # IDOR: token's org must match
            if target_org != info["org_id"]:
                return JSONResponse(
                    {"error": "not found"}, status_code=404
                )

            result = store_signer_signatures(conn, info["org_id"], body)
            return JSONResponse(result)
        except SignerScopeError:
            return JSONResponse(
                {"error": "scope denied"}, status_code=403
            )
        except EnvelopeError:
            return JSONResponse(
                {"error": "unauthorized"}, status_code=401
            )
        except GenesisAlreadyExists:
            return JSONResponse(
                {"error": "genesis already exists"}, status_code=409
            )
        except RegistryError as exc:
            return JSONResponse(
                {"error": str(exc)}, status_code=400
            )
        except Exception as exc:
            return JSONResponse(
                {"error": str(exc)}, status_code=500
            )
        finally:
            if auth_conn is not None:
                auth_conn.close()
            if conn is not None:
                conn.close()

    return router
