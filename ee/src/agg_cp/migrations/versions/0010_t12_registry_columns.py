"""T12: add payload and signature columns to key_registry_versions.

The T12 test helper ``_seed_registry_with_keys`` inserts into ``payload``
and ``signature`` columns.  The original 0007 migration created
``registry_blob bytea`` and ``signatures jsonb``.  This migration adds
the text columns the test helper expects.  Both sets of columns coexist;
the ``payload`` column is ``text`` (canonical JSON), and ``signature``
is ``text`` (placeholder).

F5 fix: ``alg`` keeps ``NOT NULL`` (restored) with ``DEFAULT 'ed25519'``
so frozen test helpers that omit it get a correct value.  ``user_id`` is
``text`` (registry user_id is an opaque protocol string; see ADR 0001
data-model note).  ``downgrade()`` fully reverses 0010.

Revision ID: 00000000000a
Revises: 000000000009
Create Date: 2026-10-24
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "00000000000a"
down_revision: Union[str, None] = "000000000009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add text columns for key_registry_versions (test helper compatibility)
    op.execute(
        "ALTER TABLE key_registry_versions "
        "ADD COLUMN IF NOT EXISTS payload text"
    )
    op.execute(
        "ALTER TABLE key_registry_versions "
        "ADD COLUMN IF NOT EXISTS signature text"
    )

    # Add roles column to approver_keys (T12 test helper inserts it)
    op.execute(
        "ALTER TABLE approver_keys "
        "ADD COLUMN IF NOT EXISTS roles jsonb DEFAULT '[]'::jsonb"
    )

    # T12 tests insert non-UUID user_ids (e.g. "user-bob") into
    # approver_keys and approvals.  Change the column types to text.
    # user_id is kept as text: registry user_id is an opaque protocol
    # string (e.g. OIDC sub claim), not a DB-generated UUID.
    op.execute(
        "ALTER TABLE approver_keys "
        "ALTER COLUMN user_id TYPE text USING user_id::text"
    )
    op.execute(
        "ALTER TABLE approvals "
        "ALTER COLUMN user_id TYPE text USING user_id::text"
    )

    # F5a: keep alg NOT NULL but add DEFAULT 'ed25519' so frozen test
    # helpers that omit alg get a correct value.  The application code
    # must still supply alg explicitly; the default is a safety net.
    op.execute(
        "ALTER TABLE approver_keys "
        "ALTER COLUMN alg SET DEFAULT 'ed25519'"
    )

    # Recreate cli_key_lookup to return user_id as text (was uuid).
    op.execute("DROP FUNCTION IF EXISTS cli_key_lookup(text)")
    op.execute(
        "CREATE FUNCTION cli_key_lookup(p_key_id text)\n"
        "RETURNS TABLE (org_id uuid, user_id text,"
        " public_key text, status text)\n"
        "LANGUAGE sql STABLE SECURITY DEFINER\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "  SELECT q.org_id, q.user_id, q.public_key, q.status\n"
        "  FROM (\n"
        "    SELECT ak.org_id, ak.user_id, ak.public_key,"
        " 'signer'::text AS status, 0 AS sort_key\n"
        "    FROM public.approver_keys ak\n"
        "    WHERE ak.key_id = p_key_id AND ak.revoked_at IS NULL\n"
        "    UNION ALL\n"
        "    SELECT sl.org_id, sl.user_id::text, sl.public_key,"
        " 'link'::text AS status, 1 AS sort_key\n"
        "    FROM public.signer_links sl\n"
        "    WHERE sl.key_id = p_key_id\n"
        "      AND sl.status = 'pending'\n"
        "      AND sl.public_key IS NOT NULL\n"
        "  ) q\n"
        "  ORDER BY q.sort_key\n"
        "  LIMIT 1;\n"
        "$$"
    )
    op.execute("ALTER FUNCTION cli_key_lookup(text) OWNER TO agg_owner")
    op.execute("REVOKE EXECUTE ON FUNCTION cli_key_lookup(text) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION cli_key_lookup(text) TO agg_app")


def downgrade() -> None:
    # Fully reverse 0010: drop added columns, restore types, restore function.

    # Drop added columns on key_registry_versions
    op.execute(
        "ALTER TABLE key_registry_versions "
        "DROP COLUMN IF EXISTS payload"
    )
    op.execute(
        "ALTER TABLE key_registry_versions "
        "DROP COLUMN IF EXISTS signature"
    )

    # Drop roles column from approver_keys
    op.execute(
        "ALTER TABLE approver_keys "
        "DROP COLUMN IF EXISTS roles"
    )

    # Restore user_id back to uuid on approver_keys and approvals.
    # NAMED LIMIT (T12 security F10, ADR 0001): the downgrade deletes rows
    # whose user_id is not a uuid, because the uuid type cannot hold them.
    # Downgrade is a development/rollback operation; run it only on a
    # database whose approvals are exported or disposable.
    op.execute(
        "DELETE FROM approvals WHERE user_id !~ "
        "'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'"
    )
    op.execute(
        "DELETE FROM approver_keys WHERE user_id !~ "
        "'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'"
    )
    op.execute(
        "ALTER TABLE approver_keys "
        "ALTER COLUMN user_id TYPE uuid USING user_id::uuid"
    )
    op.execute(
        "ALTER TABLE approvals "
        "ALTER COLUMN user_id TYPE uuid USING user_id::uuid"
    )

    # Remove alg DEFAULT (0007 had no DEFAULT, just NOT NULL)
    op.execute(
        "ALTER TABLE approver_keys "
        "ALTER COLUMN alg DROP DEFAULT"
    )

    # Recreate cli_key_lookup with uuid user_id (the 0007 original)
    op.execute("DROP FUNCTION IF EXISTS cli_key_lookup(text)")
    op.execute(
        "CREATE FUNCTION cli_key_lookup(p_key_id text)\n"
        "RETURNS TABLE (org_id uuid, user_id uuid,"
        " public_key text, status text)\n"
        "LANGUAGE sql STABLE SECURITY DEFINER\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "  SELECT q.org_id, q.user_id, q.public_key, q.status\n"
        "  FROM (\n"
        "    SELECT ak.org_id, ak.user_id, ak.public_key,"
        " 'signer'::text AS status, 0 AS sort_key\n"
        "    FROM public.approver_keys ak\n"
        "    WHERE ak.key_id = p_key_id AND ak.revoked_at IS NULL\n"
        "    UNION ALL\n"
        "    SELECT sl.org_id, sl.user_id, sl.public_key,"
        " 'link'::text AS status, 1 AS sort_key\n"
        "    FROM public.signer_links sl\n"
        "    WHERE sl.key_id = p_key_id\n"
        "      AND sl.status = 'pending'\n"
        "      AND sl.public_key IS NOT NULL\n"
        "  ) q\n"
        "  ORDER BY q.sort_key\n"
        "  LIMIT 1;\n"
        "$$"
    )
    op.execute("ALTER FUNCTION cli_key_lookup(text) OWNER TO agg_owner")
    op.execute("REVOKE EXECUTE ON FUNCTION cli_key_lookup(text) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION cli_key_lookup(text) TO agg_app")
