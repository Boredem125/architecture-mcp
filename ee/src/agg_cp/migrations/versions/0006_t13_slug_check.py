"""T13 F2: org slugs are restricted to [a-z0-9][a-z0-9-]{0,62}.

Expand-only revision on top of 0005.  The slug names the org's OIDC
client-secret file, so it must never carry path characters (T13 F1).
Mirrored in code by ``agg_cp.auth.is_valid_slug``.

Revision ID: 000000000006
Revises: 000000000005
Create Date: 2026-10-20
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "000000000006"
down_revision: Union[str, None] = "000000000005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE orgs ADD CONSTRAINT orgs_slug_format "
        "CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$')"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE orgs DROP CONSTRAINT orgs_slug_format")
