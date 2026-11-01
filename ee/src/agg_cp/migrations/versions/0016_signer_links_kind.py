"""T12d d5: signer_links.kind column (cli|browser).

Adds ``kind`` (text, NOT NULL, DEFAULT 'cli') to ``signer_links``
with a CHECK constraint restricting values to 'cli' and 'browser'.
Backfills existing browser-enrolled rows based on the placeholder
code_hash pattern written by ``browser_keys.py``.

Reversible: downgrade drops the constraint and column.

Revision ID: 000000000010
Revises: 00000000000f
Create Date: 2026-10-31
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "000000000010"
down_revision: Union[str, None] = "00000000000f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE signer_links "
        "ADD COLUMN kind text NOT NULL DEFAULT 'cli'"
    )
    op.execute(
        "ALTER TABLE signer_links "
        "ADD CONSTRAINT signer_links_kind_check "
        "CHECK (kind IN ('cli', 'browser'))"
    )
    # Backfill: browser keys use a placeholder code_hash of the form
    # sha256('browser-' || key_id || '-' || id::text)
    op.execute(
        "UPDATE signer_links SET kind = 'browser' "
        "WHERE key_id IS NOT NULL "
        "AND code_hash = encode("
        "sha256(convert_to('browser-' || key_id || '-' || id::text, 'UTF8')"
        "), 'hex')"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE signer_links "
        "DROP CONSTRAINT IF EXISTS signer_links_kind_check"
    )
    op.execute(
        "ALTER TABLE signer_links DROP COLUMN IF EXISTS kind"
    )
