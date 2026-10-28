"""T12d: setup_codes.purpose column.

Adds ``purpose`` column to ``setup_codes`` (``admin_bootstrap`` |
``registry_genesis``; existing rows default to ``admin_bootstrap``;
CHECK constraint).

Reversible: downgrade drops the column.

Revision ID: 00000000000e
Revises: 00000000000d
Create Date: 2026-10-26
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "00000000000e"
down_revision: Union[str, None] = "00000000000d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -- setup_codes.purpose ---------------------------------------------------
    op.execute(
        "ALTER TABLE setup_codes "
        "ADD COLUMN purpose text NOT NULL DEFAULT 'admin_bootstrap'"
    )
    op.execute(
        "ALTER TABLE setup_codes "
        "ADD CONSTRAINT setup_codes_purpose_check "
        "CHECK (purpose IN ('admin_bootstrap', 'registry_genesis'))"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE setup_codes "
        "DROP CONSTRAINT IF EXISTS setup_codes_purpose_check"
    )
    op.execute(
        "ALTER TABLE setup_codes "
        "DROP COLUMN IF EXISTS purpose"
    )
