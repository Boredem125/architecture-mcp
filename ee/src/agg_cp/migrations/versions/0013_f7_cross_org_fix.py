"""F7: narrow check_key_id_cross_org to approver_keys only, add NULL safety.

The 0012 version of check_key_id_cross_org also counted other orgs'
signer_links rows as conflicts.  signer_links rows are unverified
claims (any session user can insert one via the browser-key route), so
a non-admin in org B could block org A's signed registry publish.

Fix:
- check_key_id_cross_org checks ONLY other orgs' live (not-revoked)
  approver_keys rows (signed registry data, not unverified claims).
- The function is STRICT: NULL key_id or NULL org_id returns NULL
  (the caller treats NULL as false), preventing fail-open on NULLs.
- Cross-org signer_links checks happen at link/registration time only
  (in the link route and browser route application code).

Revision ID: 00000000000d
Revises: 00000000000c
Create Date: 2026-10-25
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "00000000000d"
down_revision: Union[str, None] = "00000000000c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS check_key_id_cross_org(text, uuid)")
    op.execute(
        "CREATE FUNCTION check_key_id_cross_org("
        "p_key_id text, p_org_id uuid)\n"
        "RETURNS boolean\n"
        "LANGUAGE sql STABLE STRICT SECURITY DEFINER\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "  SELECT EXISTS(\n"
        "    SELECT 1 FROM public.approver_keys\n"
        "    WHERE key_id = p_key_id\n"
        "      AND org_id IS DISTINCT FROM p_org_id\n"
        "      AND revoked_at IS NULL\n"
        "  );\n"
        "$$"
    )
    op.execute(
        "ALTER FUNCTION check_key_id_cross_org(text, uuid) OWNER TO agg_owner"
    )
    op.execute(
        "REVOKE EXECUTE ON FUNCTION check_key_id_cross_org(text, uuid) "
        "FROM PUBLIC"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION check_key_id_cross_org(text, uuid) "
        "TO agg_app"
    )


def downgrade() -> None:
    # Restore 0012 version (with signer_links check)
    op.execute("DROP FUNCTION IF EXISTS check_key_id_cross_org(text, uuid)")
    op.execute(
        "CREATE FUNCTION check_key_id_cross_org("
        "p_key_id text, p_org_id uuid)\n"
        "RETURNS boolean\n"
        "LANGUAGE sql STABLE SECURITY DEFINER\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "  SELECT EXISTS(\n"
        "    SELECT 1 FROM public.approver_keys\n"
        "    WHERE key_id = p_key_id\n"
        "      AND org_id != p_org_id\n"
        "      AND revoked_at IS NULL\n"
        "  ) OR EXISTS(\n"
        "    SELECT 1 FROM public.signer_links\n"
        "    WHERE key_id = p_key_id\n"
        "      AND org_id != p_org_id\n"
        "      AND public_key IS NOT NULL\n"
        "  );\n"
        "$$"
    )
    op.execute(
        "ALTER FUNCTION check_key_id_cross_org(text, uuid) OWNER TO agg_owner"
    )
    op.execute(
        "REVOKE EXECUTE ON FUNCTION check_key_id_cross_org(text, uuid) "
        "FROM PUBLIC"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION check_key_id_cross_org(text, uuid) "
        "TO agg_app"
    )
