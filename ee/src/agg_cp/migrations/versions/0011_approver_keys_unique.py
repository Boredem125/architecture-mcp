"""T12b-2: UNIQUE (org_id, key_id) on approver_keys (ADR 0010 s8).

The approver_keys table is a projection of the latest verified registry
version.  ``store_registry_version`` upserts on ``(org_id, key_id)``,
which requires a UNIQUE constraint.  This migration refuses to run if
duplicate rows exist (prints them); otherwise it adds the constraint.

Revision ID: 00000000000b
Revises: 00000000000a
Create Date: 2026-10-25
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = "00000000000b"
down_revision: Union[str, None] = "00000000000a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Safety: refuse if duplicate (org_id, key_id) rows exist.
    conn = op.get_bind()
    dupes = conn.execute(text(
        "SELECT org_id, key_id, COUNT(*) AS cnt "
        "FROM approver_keys "
        "GROUP BY org_id, key_id "
        "HAVING COUNT(*) > 1"
    )).fetchall()
    if dupes:
        lines = [f"  org_id={r[0]}, key_id={r[1]}, count={r[2]}" for r in dupes]
        raise RuntimeError(
            "Duplicate (org_id, key_id) rows in approver_keys; "
            "fix before migrating:\n" + "\n".join(lines)
        )

    op.execute(
        "ALTER TABLE approver_keys "
        "ADD CONSTRAINT approver_keys_org_key_unique "
        "UNIQUE (org_id, key_id)"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE approver_keys "
        "DROP CONSTRAINT IF EXISTS approver_keys_org_key_unique"
    )
