"""T12c: script and script_preview columns on escalations.

Adds ``script`` (jsonb) and ``script_preview`` (jsonb) as separate
columns on the ``escalations`` table (ADR 0010 s9, C-c0-7).
The raw-byte metadata (rel, sha256, size) lives in ``script``;
the scrubbed preview text and its hash live in ``script_preview``.
The server never receives the raw bytes.

Reversible: downgrade drops both columns.

Revision ID: 00000000000f
Revises: 00000000000e
Create Date: 2026-10-28
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "00000000000f"
down_revision: Union[str, None] = "00000000000e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE escalations "
        "ADD COLUMN script jsonb DEFAULT NULL"
    )
    op.execute(
        "ALTER TABLE escalations "
        "ADD COLUMN script_preview jsonb DEFAULT NULL"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE escalations DROP COLUMN IF EXISTS script_preview"
    )
    op.execute(
        "ALTER TABLE escalations DROP COLUMN IF EXISTS script"
    )
