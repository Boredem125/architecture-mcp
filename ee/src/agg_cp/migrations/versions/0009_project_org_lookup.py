"""T11: project_org_lookup and sweep_org_ids SECURITY DEFINER functions.

1. ``project_org_lookup(project_id)`` allows agg_app to resolve
   project_id -> org_id without RLS context, for the CLI.
2. ``sweep_org_ids()`` returns SETOF uuid of all org_ids that have
   connectors, so sweep_all_orgs can iterate orgs under FORCE RLS.

Both follow the device_token_lookup pattern in 0007: fixed search_path,
REVOKE ALL FROM PUBLIC, GRANT EXECUTE TO agg_app, owner agg_owner.

Also adds a projects_owner_select policy so project_org_lookup can
read projects despite FORCE RLS (matching connectors_owner_select
in 0007).

Revision ID: 000000000009
Revises: 000000000008
Create Date: 2026-10-23
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "000000000009"
down_revision: Union[str, None] = "000000000008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SIG_PROJECT = "project_org_lookup(uuid)"
_SIG_SWEEP = "sweep_org_ids()"


def upgrade() -> None:
    # -- Owner SELECT policy on projects (for project_org_lookup) --
    op.execute(
        "CREATE POLICY projects_owner_select ON projects "
        "FOR SELECT TO agg_owner USING (true)"
    )

    # -- project_org_lookup(project_id uuid) RETURNS uuid --
    op.execute(
        "CREATE FUNCTION project_org_lookup(p_project_id uuid)\n"
        "RETURNS uuid\n"
        "LANGUAGE sql STABLE SECURITY DEFINER\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "  SELECT p.org_id\n"
        "  FROM public.projects p\n"
        "  WHERE p.id = p_project_id\n"
        "  LIMIT 1;\n"
        "$$"
    )
    op.execute(f"ALTER FUNCTION {_SIG_PROJECT} OWNER TO agg_owner")
    op.execute(f"REVOKE EXECUTE ON FUNCTION {_SIG_PROJECT} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {_SIG_PROJECT} TO agg_app")

    # -- sweep_org_ids() RETURNS SETOF uuid --
    # Returns distinct org_ids from non-revoked connectors.
    # Uses only the connectors table (which has an owner SELECT policy
    # from 0007), not audit_heads (which has FORCE RLS with no owner
    # policy).  sweep_device_silent filters to connectors with
    # checkpoints under RLS.
    op.execute(
        "CREATE FUNCTION sweep_org_ids()\n"
        "RETURNS SETOF uuid\n"
        "LANGUAGE sql STABLE SECURITY DEFINER\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "  SELECT DISTINCT c.org_id\n"
        "  FROM public.connectors c\n"
        "  WHERE c.revoked_at IS NULL;\n"
        "$$"
    )
    op.execute(f"ALTER FUNCTION {_SIG_SWEEP} OWNER TO agg_owner")
    op.execute(f"REVOKE EXECUTE ON FUNCTION {_SIG_SWEEP} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {_SIG_SWEEP} TO agg_app")


def downgrade() -> None:
    op.execute(f"DROP FUNCTION IF EXISTS {_SIG_SWEEP}")
    op.execute(f"DROP FUNCTION IF EXISTS {_SIG_PROJECT}")
    op.execute("DROP POLICY IF EXISTS projects_owner_select ON projects")
