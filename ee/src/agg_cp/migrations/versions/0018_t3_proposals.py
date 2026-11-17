"""M3 T3: proposal columns on policy_change_requests.

Adds columns that 0007 lacks: payload, sequence, registry_version,
published_bundle_id, published_by, published_at.
Adds CHECK constraints (dropped first for idempotency).
D4: uses proposer_user_id only, no proposed_by.

Revision ID: 000000000012
Revises: 000000000011
Create Date: 2026-11-16
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "000000000012"
down_revision: Union[str, None] = "000000000011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Columns 0007 lacks
    op.execute(
        "ALTER TABLE policy_change_requests "
        "ADD COLUMN IF NOT EXISTS payload bytea NOT NULL DEFAULT ''"
    )
    op.execute(
        "ALTER TABLE policy_change_requests "
        "ADD COLUMN IF NOT EXISTS sequence bigint NOT NULL DEFAULT 1"
    )
    op.execute(
        "ALTER TABLE policy_change_requests "
        "ADD COLUMN IF NOT EXISTS base_sequence bigint NOT NULL DEFAULT 0"
    )
    op.execute(
        "ALTER TABLE policy_change_requests "
        "ADD COLUMN IF NOT EXISTS registry_version integer NOT NULL DEFAULT 0"
    )
    op.execute(
        "ALTER TABLE policy_change_requests "
        "ADD COLUMN IF NOT EXISTS published_bundle_id uuid"
    )
    op.execute(
        "ALTER TABLE policy_change_requests "
        "ADD COLUMN IF NOT EXISTS published_by uuid"
    )
    op.execute(
        "ALTER TABLE policy_change_requests "
        "ADD COLUMN IF NOT EXISTS published_at timestamptz"
    )

    # CHECKs (drop first for idempotency)
    for c in ("chk_payload_size", "chk_new_sha_hex", "chk_base_sha_hex",
              "chk_sequence_base_plus_one", "chk_base_sequence_non_negative",
              "chk_status_values"):
        op.execute(
            f"ALTER TABLE policy_change_requests DROP CONSTRAINT IF EXISTS {c}"
        )

    op.execute(
        "ALTER TABLE policy_change_requests "
        "ADD CONSTRAINT chk_payload_size CHECK (octet_length(payload) <= 1048576)"
    )
    op.execute(
        "ALTER TABLE policy_change_requests "
        "ADD CONSTRAINT chk_new_sha_hex CHECK (new_sha ~ '^[0-9a-f]{64}$')"
    )
    op.execute(
        "ALTER TABLE policy_change_requests "
        "ADD CONSTRAINT chk_base_sha_hex CHECK (base_sha ~ '^[0-9a-f]{64}$')"
    )
    op.execute(
        "ALTER TABLE policy_change_requests "
        "ADD CONSTRAINT chk_sequence_base_plus_one CHECK (sequence = base_sequence + 1)"
    )
    op.execute(
        "ALTER TABLE policy_change_requests "
        "ADD CONSTRAINT chk_base_sequence_non_negative CHECK (base_sequence >= 0)"
    )
    op.execute(
        "ALTER TABLE policy_change_requests "
        "ADD CONSTRAINT chk_status_values CHECK (status IN ('open', 'published'))"
    )

    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_pcr_org_project_created "
        "ON policy_change_requests (org_id, project_id, created_at)"
    )

    # Drop temporary defaults
    for col in ("payload", "sequence", "registry_version", "base_sequence"):
        op.execute(
            f"ALTER TABLE policy_change_requests ALTER COLUMN {col} DROP DEFAULT"
        )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_pcr_org_project_created")
    for c in ("chk_status_values", "chk_base_sequence_non_negative",
              "chk_sequence_base_plus_one", "chk_base_sha_hex",
              "chk_new_sha_hex", "chk_payload_size"):
        op.execute(
            f"ALTER TABLE policy_change_requests DROP CONSTRAINT IF EXISTS {c}"
        )
    for col in ("published_at", "published_by", "published_bundle_id",
                "registry_version", "base_sequence", "sequence", "payload"):
        op.execute(
            f"ALTER TABLE policy_change_requests DROP COLUMN IF EXISTS {col}"
        )
