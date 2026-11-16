"""M3 T1: verification column on policy_bundles; body jsonb -> json.

Adds ``verification`` (text, DEFAULT 'm2_unverified') and ``verified_at``
(timestamptz, nullable) to ``policy_bundles`` so the admin bundle-detail
route can show which bundles have been server-verified (D2.3).

CHECK constraint: ``verification IN ('server', 'm2_unverified')`` and
``verified_at`` set exactly when ``verification = 'server'``.  This
enforces that a free-text label cannot appear after the migration lands.

Existing rows get 'm2_unverified'; T4's publish flow writes 'server'.

M2 rows already normalised stay as they are: the ALTER from jsonb to json
succeeds because every valid jsonb value is valid json text.

Adds ``acked_at`` to ``sync_alerts`` so alerts can be acknowledged
(T1 alerts list, T8 alerts page).  No UPDATE grant on sync_alerts is
added: T8 grants it alongside ``acked_by`` and an ``admin_audit`` row.

Alters ``audit_records.body`` from ``jsonb`` to ``json`` so the text is
kept as written and exponent floats, ``-0.0`` and other edge forms do
not change after storage (T1-2).

Downgrade: ``json`` back to ``jsonb``; rows jsonb cannot hold
(the connector may store ``\u0000``) are acceptable to refuse.

Revision ID: 000000000011
Revises: 000000000010
Create Date: 2026-11-05
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "000000000011"
down_revision: Union[str, None] = "000000000010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -- policy_bundles: verification and verified_at --
    op.execute(
        "ALTER TABLE policy_bundles "
        "ADD COLUMN IF NOT EXISTS verification text "
        "NOT NULL DEFAULT 'm2_unverified'"
    )
    op.execute(
        "ALTER TABLE policy_bundles "
        "ADD COLUMN IF NOT EXISTS verified_at timestamptz"
    )
    # CHECK: verification must be one of the two allowed values
    op.execute(
        "ALTER TABLE policy_bundles "
        "ADD CONSTRAINT chk_verification_value "
        "CHECK (verification IN ('server', 'm2_unverified'))"
    )
    # CHECK: verified_at set exactly when verification = 'server'
    op.execute(
        "ALTER TABLE policy_bundles "
        "ADD CONSTRAINT chk_verified_at_coupling "
        "CHECK ("
        "  (verification = 'server' AND verified_at IS NOT NULL)"
        "  OR "
        "  (verification = 'm2_unverified' AND verified_at IS NULL)"
        ")"
    )
    # -- sync_alerts: acked_at for alert acknowledgement --
    op.execute(
        "ALTER TABLE sync_alerts "
        "ADD COLUMN IF NOT EXISTS acked_at timestamptz"
    )
    # No UPDATE grant on sync_alerts: T8 grants it alongside acked_by
    # and an admin_audit row.

    # -- audit_records: body jsonb -> json (T1-2) --
    # json keeps the text as written; jsonb normalises numbers.
    # The ALTER succeeds with the no-update trigger on; the trigger
    # still holds.  M2 rows already normalised stay as they are.
    op.execute(
        "ALTER TABLE audit_records "
        "ALTER COLUMN body TYPE json USING body::json"
    )


def downgrade() -> None:
    # body json -> jsonb (may refuse rows jsonb cannot hold)
    op.execute(
        "ALTER TABLE audit_records "
        "ALTER COLUMN body TYPE jsonb USING body::jsonb"
    )
    op.execute(
        "ALTER TABLE sync_alerts "
        "DROP COLUMN IF EXISTS acked_at"
    )
    op.execute(
        "ALTER TABLE policy_bundles "
        "DROP CONSTRAINT IF EXISTS chk_verified_at_coupling"
    )
    op.execute(
        "ALTER TABLE policy_bundles "
        "DROP CONSTRAINT IF EXISTS chk_verification_value"
    )
    op.execute(
        "ALTER TABLE policy_bundles "
        "DROP COLUMN IF EXISTS verified_at"
    )
    op.execute(
        "ALTER TABLE policy_bundles "
        "DROP COLUMN IF EXISTS verification"
    )
