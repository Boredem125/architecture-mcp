"""T10: grant agg_app SELECT on alembic_version.

Expand-only revision on top of 0004.  The /ready endpoint runs
check_db_ready as agg_app; it needs to read alembic_version.

Revision ID: 000000000005
Revises: 000000000004
Create Date: 2026-10-20
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "000000000005"
down_revision: Union[str, None] = "000000000004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("GRANT SELECT ON alembic_version TO agg_app")


def downgrade() -> None:
    op.execute("REVOKE SELECT ON alembic_version FROM agg_app")
