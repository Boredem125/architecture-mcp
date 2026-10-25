"""F2/F5: harden cli_key_lookup against revoked keys and cross-org ambiguity.

F2: the old function falls back to signer_links when the approver_keys row
is revoked (or absent), so a revoked key still gets a pending_link token.
Fix: if the key_id has a revoked approver_keys row, return 'revoked' status
(the token route refuses it).  Only fall back to signer_links if there is
NO approver_keys row at all (the key was never published in any registry).

F5: the old function uses LIMIT 1 by key_id across all orgs, so a key_id
live in two orgs returns an arbitrary one.  Fix: count live rows in
approver_keys and signer_links; return nothing if > 1 (the token route
refuses ambiguous).  Also add check_key_id_cross_org(key_id, org_id) as
SECURITY DEFINER for store_registry_version to call (runs under RLS so
it cannot see other orgs' rows directly).

Revision ID: 00000000000c
Revises: 00000000000b
Create Date: 2026-10-25
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "00000000000c"
down_revision: Union[str, None] = "00000000000b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -- 1. cli_key_lookup: F2 revoked check + F5 ambiguity check ----------
    op.execute("DROP FUNCTION IF EXISTS cli_key_lookup(text)")
    op.execute(
        "CREATE FUNCTION cli_key_lookup(p_key_id text)\n"
        "RETURNS TABLE (org_id uuid, user_id text,"
        " public_key text, status text)\n"
        "LANGUAGE plpgsql STABLE SECURITY DEFINER\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "DECLARE\n"
        "  live_count int;\n"
        "  link_count int;\n"
        "BEGIN\n"
        "  -- F5: refuse ambiguous key_id (live in multiple orgs)\n"
        "  SELECT COUNT(DISTINCT ak2.org_id) INTO live_count\n"
        "    FROM public.approver_keys ak2\n"
        "    WHERE ak2.key_id = p_key_id AND ak2.revoked_at IS NULL;\n"
        "  IF live_count > 1 THEN\n"
        "    RETURN;  -- empty result: ambiguous\n"
        "  END IF;\n"
        "  -- Try live approver_keys first\n"
        "  RETURN QUERY\n"
        "    SELECT ak.org_id, ak.user_id, ak.public_key,"
        " 'signer'::text\n"
        "    FROM public.approver_keys ak\n"
        "    WHERE ak.key_id = p_key_id AND ak.revoked_at IS NULL\n"
        "    LIMIT 1;\n"
        "  IF FOUND THEN RETURN; END IF;\n"
        "  -- F2: if there is a revoked approver_keys row, return 'revoked'\n"
        "  -- (do NOT fall back to signer_links)\n"
        "  RETURN QUERY\n"
        "    SELECT ak.org_id, ak.user_id, ak.public_key,"
        " 'revoked'::text\n"
        "    FROM public.approver_keys ak\n"
        "    WHERE ak.key_id = p_key_id AND ak.revoked_at IS NOT NULL\n"
        "    ORDER BY ak.revoked_at DESC\n"
        "    LIMIT 1;\n"
        "  IF FOUND THEN RETURN; END IF;\n"
        "  -- Fall back to signer_links only if the key was never in any registry\n"
        "  -- F5: refuse if multiple signer_links rows match\n"
        "  SELECT COUNT(DISTINCT sl2.org_id) INTO link_count\n"
        "    FROM public.signer_links sl2\n"
        "    WHERE sl2.key_id = p_key_id\n"
        "      AND sl2.public_key IS NOT NULL;\n"
        "  IF link_count > 1 THEN\n"
        "    RETURN;  -- ambiguous\n"
        "  END IF;\n"
        "  RETURN QUERY\n"
        "    SELECT sl.org_id, sl.user_id::text, sl.public_key,"
        " 'link'::text\n"
        "    FROM public.signer_links sl\n"
        "    WHERE sl.key_id = p_key_id\n"
        "      AND sl.public_key IS NOT NULL\n"
        "    LIMIT 1;\n"
        "END;\n"
        "$$"
    )
    op.execute("ALTER FUNCTION cli_key_lookup(text) OWNER TO agg_owner")
    op.execute("REVOKE EXECUTE ON FUNCTION cli_key_lookup(text) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION cli_key_lookup(text) TO agg_app")

    # -- 2. check_key_id_cross_org: SECURITY DEFINER for publish check -----
    # Returns TRUE if the key_id is live (not revoked) in an org other
    # than p_org_id, or if it is bound in a signer_links row in another org.
    # Called from store_registry_version (which runs under agg_app + RLS).
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

    # F5 defence in depth: check_key_id_cross_org SECURITY DEFINER
    # function is called from the link route and from store_registry_version
    # to prevent cross-org key binding.  A partial unique index on
    # signer_links(key_id) is NOT added because valid same-org re-link
    # scenarios produce multiple rows with the same key_id.  The approver_keys
    # table already has UNIQUE (org_id, key_id) from migration 0011.


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS check_key_id_cross_org(text, uuid)")

    # Restore the 0010 version of cli_key_lookup
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
