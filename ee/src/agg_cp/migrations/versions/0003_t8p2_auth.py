"""T8 part 2: login_transactions, session/setup_code columns.

Expand-only revision on top of 0002.  Adds:
- ``web_sessions``: ``token_hash``, ``csrf_hash``, ``last_seen_at``, ``revoked_at``
- ``setup_codes``: ``used_at``, ``failed_attempts``
- New ``login_transactions`` table with ENABLE+FORCE RLS, org policy,
  owner ``agg_owner``, grants to ``agg_app`` (SELECT/INSERT/DELETE).

Revision ID: 000000000003
Revises: 000000000002
Create Date: 2026-10-20
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "000000000003"
down_revision: Union[str, None] = "000000000002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # 1. New columns on web_sessions
    # ------------------------------------------------------------------
    op.execute(
        "ALTER TABLE web_sessions "
        "ADD COLUMN token_hash text,"
        "ADD COLUMN csrf_hash text,"
        "ADD COLUMN last_seen_at timestamptz,"
        "ADD COLUMN revoked_at timestamptz"
    )
    # Back-fill any pre-existing rows with a unique placeholder so the
    # NOT NULL + UNIQUE constraints can be added safely.
    op.execute(
        "UPDATE web_sessions SET "
        "token_hash = gen_random_uuid()::text, "
        "csrf_hash = gen_random_uuid()::text, "
        "last_seen_at = created_at "
        "WHERE token_hash IS NULL"
    )
    op.execute(
        "ALTER TABLE web_sessions "
        "ALTER COLUMN token_hash SET NOT NULL, "
        "ALTER COLUMN csrf_hash SET NOT NULL, "
        "ALTER COLUMN last_seen_at SET NOT NULL"
    )
    op.execute(
        "ALTER TABLE web_sessions "
        "ADD CONSTRAINT web_sessions_token_hash_key UNIQUE (token_hash)"
    )

    # ------------------------------------------------------------------
    # 2. New columns on setup_codes
    # ------------------------------------------------------------------
    op.execute(
        "ALTER TABLE setup_codes "
        "ADD COLUMN used_at timestamptz,"
        "ADD COLUMN failed_attempts int NOT NULL DEFAULT 0"
    )

    # ------------------------------------------------------------------
    # 3. New login_transactions table
    # ------------------------------------------------------------------
    op.execute(
        "CREATE TABLE login_transactions ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  state_hash text NOT NULL,"
        "  nonce text NOT NULL,"
        "  pkce_verifier text NOT NULL,"
        "  bootstrap bool NOT NULL DEFAULT false,"
        "  created_at timestamptz NOT NULL DEFAULT now(),"
        "  expires_at timestamptz NOT NULL"
        ")"
    )

    # Ownership
    op.execute("ALTER TABLE login_transactions OWNER TO agg_owner")

    # RLS: ENABLE + FORCE
    op.execute("ALTER TABLE login_transactions ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE login_transactions FORCE ROW LEVEL SECURITY")

    # Org-isolation policy
    op.execute(
        "CREATE POLICY login_transactions_org_isolation "
        "ON login_transactions "
        "USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid) "
        "WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)"
    )

    # Grants to agg_app: SELECT, INSERT, DELETE (no UPDATE)
    op.execute(
        "GRANT SELECT, INSERT, DELETE ON login_transactions TO agg_app"
    )


def downgrade() -> None:
    # Revoke grants
    op.execute("REVOKE ALL ON login_transactions FROM agg_app")

    # Drop login_transactions table
    op.execute("DROP TABLE IF EXISTS login_transactions")

    # Drop new columns on setup_codes
    op.execute("ALTER TABLE setup_codes DROP COLUMN IF EXISTS failed_attempts")
    op.execute("ALTER TABLE setup_codes DROP COLUMN IF EXISTS used_at")

    # Drop new columns on web_sessions (constraint first)
    op.execute(
        "ALTER TABLE web_sessions "
        "DROP CONSTRAINT IF EXISTS web_sessions_token_hash_key"
    )
    op.execute("ALTER TABLE web_sessions DROP COLUMN IF EXISTS revoked_at")
    op.execute("ALTER TABLE web_sessions DROP COLUMN IF EXISTS last_seen_at")
    op.execute("ALTER TABLE web_sessions DROP COLUMN IF EXISTS csrf_hash")
    op.execute("ALTER TABLE web_sessions DROP COLUMN IF EXISTS token_hash")
