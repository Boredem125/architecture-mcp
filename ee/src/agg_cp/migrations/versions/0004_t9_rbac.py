"""T9: unique index on role_bindings, CHECK constraints.

Expand-only revision on top of 0003.  Adds:
- Unique index on role_bindings (org_id, user_id, scope_type, scope_id, role)
  for idempotent grants (INSERT ... ON CONFLICT DO NOTHING).
- CHECK constraint on role_bindings.scope_type IN ('org', 'project').
- CHECK constraint on role_bindings.role IN ('admin', 'policy_author',
  'approver', 'auditor', 'viewer').
- CHECK constraint on projects.environment IN ('dev', 'staging', 'prod').

Revision ID: 000000000004
Revises: 000000000003
Create Date: 2026-10-20
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "000000000004"
down_revision: Union[str, None] = "000000000003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # 1. Unique index for idempotent grants
    # ------------------------------------------------------------------
    op.execute(
        "CREATE UNIQUE INDEX role_bindings_grant_unique "
        "ON role_bindings (org_id, user_id, scope_type, scope_id, role)"
    )

    # ------------------------------------------------------------------
    # 2. CHECK constraints
    # ------------------------------------------------------------------
    op.execute(
        "ALTER TABLE role_bindings "
        "ADD CONSTRAINT role_bindings_scope_type_check "
        "CHECK (scope_type IN ('org', 'project'))"
    )
    op.execute(
        "ALTER TABLE role_bindings "
        "ADD CONSTRAINT role_bindings_role_check "
        "CHECK (role IN ('admin', 'policy_author', 'approver', "
        "'auditor', 'viewer'))"
    )
    op.execute(
        "ALTER TABLE projects "
        "ADD CONSTRAINT projects_environment_check "
        "CHECK (environment IN ('dev', 'staging', 'prod'))"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE projects "
        "DROP CONSTRAINT IF EXISTS projects_environment_check"
    )
    op.execute(
        "ALTER TABLE role_bindings "
        "DROP CONSTRAINT IF EXISTS role_bindings_role_check"
    )
    op.execute(
        "ALTER TABLE role_bindings "
        "DROP CONSTRAINT IF EXISTS role_bindings_scope_type_check"
    )
    op.execute("DROP INDEX IF EXISTS role_bindings_grant_unique")
