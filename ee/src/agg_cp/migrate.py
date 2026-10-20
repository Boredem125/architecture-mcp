"""Bootstrap migration and setup code generation.

``python -m agg_cp.migrate`` runs Alembic ``upgrade head``, then
optionally generates a bootstrap setup code if ``AGG_BOOTSTRAP_ORG_SLUG``
(plus ``_NAME``, ``_ISSUER``, ``_CLIENT_ID``) is set, the org has no
admin binding, and no live (unused, unexpired) code exists.

The plaintext code appears only once in a single JSON line on stdout
(visible in ``docker logs``); the DB stores only sha256.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import secrets
import sys
import uuid

from agg_cp.db import alembic_config


def _sync_conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def main() -> int | None:
    """Run alembic upgrade head, then optionally emit a setup code."""
    from alembic import command as alembic_cmd

    db_url = os.environ.get("AGG_DATABASE_URL", "")
    if not db_url:
        raise RuntimeError("AGG_DATABASE_URL is required")

    cfg = alembic_config(db_url)
    alembic_cmd.upgrade(cfg, "head")

    # Check if bootstrap env vars are set
    slug = os.environ.get("AGG_BOOTSTRAP_ORG_SLUG")
    if not slug:
        return
    from agg_cp.auth import is_valid_slug

    if not is_valid_slug(slug):
        print("AGG_BOOTSTRAP_ORG_SLUG must match [a-z0-9][a-z0-9-]{0,62}",
              file=sys.stderr)
        return 2

    org_name = os.environ.get("AGG_BOOTSTRAP_ORG_NAME", slug)
    org_issuer = os.environ.get("AGG_BOOTSTRAP_ORG_ISSUER")
    org_client_id = os.environ.get("AGG_BOOTSTRAP_ORG_CLIENT_ID")

    if not org_issuer or not org_client_id:
        return

    import psycopg

    conninfo = _sync_conninfo(db_url)

    with psycopg.connect(conninfo) as conn:
        # Check if org exists; create if not
        row = conn.execute(
            "SELECT org_id, issuer, client_id FROM org_login_config(%s)",
            [slug],
        ).fetchone()

        if row is None:
            # Create org + oidc config (as superuser/owner context)
            org_id = uuid.uuid4()
            conn.execute(
                "SELECT set_config('app.org_id', %s, true)", [str(org_id)]
            )
            conn.execute(
                "INSERT INTO orgs (id, org_id, name, slug, created_at) "
                "VALUES (%s, %s, %s, %s, now())",
                [org_id, org_id, org_name, slug],
            )
            conn.execute(
                "INSERT INTO org_oidc_config "
                "(id, org_id, issuer, client_id, created_at) "
                "VALUES (%s, %s, %s, %s, now())",
                [uuid.uuid4(), org_id, org_issuer, org_client_id],
            )
            conn.commit()
        else:
            org_id = row[0]

    # Check if org already has an admin binding
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, true)", [str(org_id)]
        )
        admin = conn.execute(
            "SELECT id FROM role_bindings "
            "WHERE org_id = %s AND role = 'admin' LIMIT 1",
            [org_id],
        ).fetchone()

    if admin is not None:
        # Admin exists -- do not emit code
        return

    # Check if there is already a live (unused, unexpired) code
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, true)", [str(org_id)]
        )
        live = conn.execute(
            "SELECT id FROM setup_codes "
            "WHERE org_id = %s AND used_at IS NULL "
            "AND failed_attempts < 5 AND expires_at > now() "
            "LIMIT 1",
            [org_id],
        ).fetchone()

    if live is not None:
        # Live code already exists -- do not emit another
        return

    # Generate setup code
    code = secrets.token_urlsafe(24)  # 192 bits
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    now = dt.datetime.now(dt.timezone.utc)
    expires_at = now + dt.timedelta(minutes=30)

    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, true)", [str(org_id)]
        )
        conn.execute(
            "INSERT INTO setup_codes "
            "(id, org_id, code_hash, created_at, expires_at) "
            "VALUES (%s, %s, %s, %s, %s)",
            [uuid.uuid4(), org_id, code_hash, now, expires_at],
        )
        conn.commit()

    # Print the one JSON line
    print(json.dumps({
        "event": "setup_code",
        "org": slug,
        "code": code,
        "expires_at": expires_at.isoformat(),
    }))


if __name__ == "__main__":
    sys.exit(main())
