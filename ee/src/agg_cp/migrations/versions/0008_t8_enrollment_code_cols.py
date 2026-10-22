"""T8: enrollment_codes code_read_at, nullable code_hash, consume guard.

1. Add ``code_read_at timestamptz`` to enrollment_codes.
2. Make ``code_hash`` nullable (admin inserts NULL; the operator GET
   generates the code and stores only the hash).
3. ``CREATE OR REPLACE`` on ``enrollment_code_consume`` to add
   ``AND code_hash IS NOT NULL`` guard.
4. Column-level UPDATE grant on enrollment_codes to agg_app.

Revision ID: 000000000008
Revises: 000000000007
Create Date: 2026-10-21
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "000000000008"
down_revision: Union[str, None] = "000000000007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add code_read_at column
    op.execute(
        "ALTER TABLE enrollment_codes "
        "ADD COLUMN IF NOT EXISTS code_read_at timestamptz"
    )

    # 2. Make code_hash nullable (admin issue sets NULL; operator GET sets it)
    op.execute(
        "ALTER TABLE enrollment_codes "
        "ALTER COLUMN code_hash DROP NOT NULL"
    )

    # 3. Column-level UPDATE grant: the operator GET route updates
    #    code_hash and code_read_at under normal org RLS.
    op.execute(
        "GRANT UPDATE (code_hash, code_read_at) "
        "ON enrollment_codes TO agg_app"
    )

    # 4. CREATE OR REPLACE enrollment_code_consume with NULL guard.
    #    Same search_path, owner, grants as 0007.
    op.execute(
        "CREATE OR REPLACE FUNCTION enrollment_code_consume(p_code_hash text)\n"
        "RETURNS TABLE (org_id uuid, project_id uuid,"
        " operator_user_id uuid)\n"
        "LANGUAGE sql SECURITY DEFINER\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "  UPDATE public.enrollment_codes\n"
        "  SET used_at = pg_catalog.now()\n"
        "  WHERE code_hash = p_code_hash\n"
        "    AND code_hash IS NOT NULL\n"
        "    AND used_at IS NULL\n"
        "    AND expires_at > pg_catalog.now()\n"
        "  RETURNING org_id, project_id, operator_user_id;\n"
        "$$"
    )
    op.execute(
        "ALTER FUNCTION enrollment_code_consume(text) OWNER TO agg_owner"
    )
    op.execute(
        "REVOKE EXECUTE ON FUNCTION enrollment_code_consume(text) FROM PUBLIC"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION enrollment_code_consume(text) TO agg_app"
    )


def downgrade() -> None:
    # Restore original enrollment_code_consume (without NULL guard)
    op.execute(
        "CREATE OR REPLACE FUNCTION enrollment_code_consume(p_code_hash text)\n"
        "RETURNS TABLE (org_id uuid, project_id uuid,"
        " operator_user_id uuid)\n"
        "LANGUAGE sql SECURITY DEFINER\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "  UPDATE public.enrollment_codes\n"
        "  SET used_at = pg_catalog.now()\n"
        "  WHERE code_hash = p_code_hash\n"
        "    AND used_at IS NULL\n"
        "    AND expires_at > pg_catalog.now()\n"
        "  RETURNING org_id, project_id, operator_user_id;\n"
        "$$"
    )
    op.execute(
        "ALTER FUNCTION enrollment_code_consume(text) OWNER TO agg_owner"
    )
    op.execute(
        "REVOKE EXECUTE ON FUNCTION enrollment_code_consume(text) FROM PUBLIC"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION enrollment_code_consume(text) TO agg_app"
    )

    # Revoke column UPDATE grant
    op.execute(
        "REVOKE UPDATE (code_hash, code_read_at) "
        "ON enrollment_codes FROM agg_app"
    )

    # Codes never read by their operator have no hash and can never be
    # used.  Before NOT NULL comes back, mark them used and give them a
    # value no sha256 hex digest can equal (agg_owner has an UPDATE
    # policy on this table from 0007).
    op.execute(
        "UPDATE enrollment_codes "
        "SET code_hash = 'unissued:' || id::text, "
        "    used_at = COALESCE(used_at, pg_catalog.now()) "
        "WHERE code_hash IS NULL"
    )

    # Restore code_hash NOT NULL
    op.execute(
        "ALTER TABLE enrollment_codes "
        "ALTER COLUMN code_hash SET NOT NULL"
    )

    # Drop code_read_at
    op.execute(
        "ALTER TABLE enrollment_codes DROP COLUMN IF EXISTS code_read_at"
    )
