"""M2 T5: New M2 tables, RLS, append-only audit, SECURITY DEFINER functions.

Creates all M2 tables from ADR 0002 M2 amendments (sections 1 and 2):

Section 1 -- six new tables:
  device_nonces, device_tokens, signer_nonces, signer_tokens,
  signer_links, sync_alerts

Section 2 -- first-cut tables landing in M2:
  connectors, enrollment_codes, key_registry_versions, approver_keys,
  policy_bundles, policy_change_requests, policy_change_approvals,
  escalations, approvals

Section 2 -- append-only audit tables:
  audit_records, audit_heads, audit_quarantine

All tables: ENABLE + FORCE RLS, owner agg_owner, org_isolation
policy on NULLIF(current_setting('app.org_id', true), '')::uuid.
Owner bypass policies on tables that SECURITY DEFINER functions
touch (connectors, enrollment_codes, signer_links, device_nonces,
device_tokens, signer_nonces, signer_tokens, approver_keys).
Least-privilege grants to agg_app; agg_worker nothing.

Eight new SECURITY DEFINER functions (ADR 0002 section 3, rows 1-7):
  device_lookup, device_token_lookup, enrollment_code_consume,
  signer_link_consume, cli_key_lookup, signer_token_lookup,
  device_nonce_insert, signer_nonce_insert.

Audit tables (audit_records, audit_heads, audit_quarantine):
append-only with row triggers (reject UPDATE/DELETE) and a
statement trigger (reject TRUNCATE), same pattern as admin_audit.

Roles are never created in migrations, no passwords.

Revision ID: 000000000007
Revises: 000000000006
Create Date: 2026-10-21
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "000000000007"
down_revision: Union[str, None] = "000000000006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# -- Table groupings --

# Section 2: first-cut tables (app manages)
_SECTION2_CRUD: tuple[str, ...] = (
    "connectors",
    "approver_keys",
    "policy_change_requests",
    "escalations",
)

_SECTION2_LIMITED: tuple[str, ...] = (
    "enrollment_codes",
    "key_registry_versions",
    "policy_bundles",
    "policy_change_approvals",
    "approvals",
)

# Section 1: new M2 tables
_SECTION1_CRUD: tuple[str, ...] = (
    "signer_links",
    "device_tokens",
    "signer_tokens",
)

_SECTION1_LIMITED: tuple[str, ...] = (
    "device_nonces",
    "signer_nonces",
    "sync_alerts",
)

# Append-only audit tables
_AUDIT_TABLES: tuple[str, ...] = (
    "audit_records",
    "audit_heads",
    "audit_quarantine",
)

# All M2 tables (order matters for downgrade)
_ALL_M2_TABLES: tuple[str, ...] = (
    _SECTION2_CRUD + _SECTION2_LIMITED
    + _SECTION1_CRUD + _SECTION1_LIMITED
    + _AUDIT_TABLES
)

# Tables that SECURITY DEFINER functions access (need owner bypass)
_SECDEF_ACCESSED: tuple[str, ...] = (
    "connectors",
    "enrollment_codes",
    "signer_links",
    "device_nonces",
    "device_tokens",
    "signer_nonces",
    "signer_tokens",
    "approver_keys",
)


def upgrade() -> None:
    # ==================================================================
    # 1. Create tables
    # ==================================================================

    # -- connectors (ADR 0002 main + M2 s2.1) --
    op.execute(
        "CREATE TABLE connectors ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  project_id uuid NOT NULL,"
        "  device_public_key text NOT NULL,"
        "  hostname text,"
        "  agent_kinds text[],"
        "  last_seen timestamptz,"
        "  revoked_at timestamptz,"
        "  operator_user_id uuid,"
        "  created_at timestamptz NOT NULL DEFAULT now()"
        ")"
    )

    # -- enrollment_codes (ADR 0002 main + M2 s2.2) --
    op.execute(
        "CREATE TABLE enrollment_codes ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  project_id uuid NOT NULL,"
        "  code_hash text NOT NULL,"
        "  expires_at timestamptz NOT NULL,"
        "  used_at timestamptz,"
        "  operator_user_id uuid,"
        "  created_at timestamptz NOT NULL DEFAULT now()"
        ")"
    )

    # -- key_registry_versions (ADR 0002 main + M2 s2.3) --
    op.execute(
        "CREATE TABLE key_registry_versions ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  version bigint NOT NULL,"
        "  registry_blob bytea,"
        "  signatures jsonb,"
        "  created_at timestamptz NOT NULL,"
        "  UNIQUE (org_id, version)"
        ")"
    )

    # -- approver_keys (ADR 0002 main + M2 s2.4) --
    op.execute(
        "CREATE TABLE approver_keys ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  user_id uuid NOT NULL,"
        "  public_key text NOT NULL,"
        "  alg text NOT NULL,"
        "  kind text NOT NULL,"
        "  key_id text NOT NULL,"
        "  registry_version bigint,"
        "  enrolled_at timestamptz,"
        "  revoked_at timestamptz,"
        "  enrollment_signatures jsonb,"
        "  created_at timestamptz NOT NULL DEFAULT now()"
        ")"
    )

    # -- policy_bundles (ADR 0002 main + M2 s2.5) --
    op.execute(
        "CREATE TABLE policy_bundles ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  project_id uuid NOT NULL,"
        "  sequence bigint NOT NULL,"
        "  bundle_blob bytea,"
        "  server_signature text,"
        "  created_at timestamptz NOT NULL,"
        "  UNIQUE (project_id, sequence)"
        ")"
    )

    # -- policy_change_requests (ADR 0002 main + M2 s2.5) --
    op.execute(
        "CREATE TABLE policy_change_requests ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  project_id uuid NOT NULL,"
        "  base_sha text NOT NULL,"
        "  new_sha text NOT NULL,"
        "  loosened_fields jsonb,"
        "  proposer_user_id uuid NOT NULL,"
        "  status text NOT NULL,"
        "  created_at timestamptz NOT NULL DEFAULT now()"
        ")"
    )

    # -- policy_change_approvals (ADR 0002 main + M2 s2.5) --
    op.execute(
        "CREATE TABLE policy_change_approvals ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  change_request_id uuid NOT NULL,"
        "  user_id uuid NOT NULL,"
        "  key_id text NOT NULL,"
        "  signature text NOT NULL,"
        "  signed_at timestamptz NOT NULL,"
        "  created_at timestamptz NOT NULL DEFAULT now()"
        ")"
    )

    # -- escalations (ADR 0002 main + M2 s2.6) --
    op.execute(
        "CREATE TABLE escalations ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  project_id uuid NOT NULL,"
        "  connector_id uuid NOT NULL,"
        "  request_id text NOT NULL,"
        "  record jsonb,"
        "  risk text,"
        "  requires_dual boolean NOT NULL DEFAULT false,"
        "  status text NOT NULL,"
        "  policy_sequence bigint,"
        "  created_at timestamptz NOT NULL,"
        "  UNIQUE (connector_id, request_id)"
        ")"
    )

    # -- approvals (ADR 0002 main + M2 s2.6) --
    op.execute(
        "CREATE TABLE approvals ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  escalation_id uuid NOT NULL,"
        "  user_id uuid NOT NULL,"
        "  key_id text NOT NULL,"
        "  decision text NOT NULL,"
        "  signed_payload text,"
        "  signature text NOT NULL,"
        "  nonce text NOT NULL UNIQUE,"
        "  not_after timestamptz,"
        "  registry_version bigint,"
        "  kind text,"
        "  created_at timestamptz NOT NULL,"
        "  UNIQUE (escalation_id, user_id)"
        ")"
    )

    # -- device_nonces (ADR 0002 M2 s1) --
    op.execute(
        "CREATE TABLE device_nonces ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  device_id uuid NOT NULL,"
        "  nonce text NOT NULL,"
        "  iat timestamptz NOT NULL,"
        "  created_at timestamptz NOT NULL,"
        "  UNIQUE (device_id, nonce)"
        ")"
    )

    # -- device_tokens (ADR 0002 M2 s1) --
    op.execute(
        "CREATE TABLE device_tokens ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  project_id uuid NOT NULL,"
        "  connector_id uuid NOT NULL,"
        "  token_hash text NOT NULL,"
        "  expires_at timestamptz NOT NULL,"
        "  created_at timestamptz NOT NULL DEFAULT now()"
        ")"
    )

    # -- signer_nonces (ADR 0002 M2 s1) --
    op.execute(
        "CREATE TABLE signer_nonces ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  key_id text NOT NULL,"
        "  nonce text NOT NULL,"
        "  iat timestamptz NOT NULL,"
        "  created_at timestamptz NOT NULL,"
        "  UNIQUE (key_id, nonce)"
        ")"
    )

    # -- signer_tokens (ADR 0002 M2 s1) --
    op.execute(
        "CREATE TABLE signer_tokens ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  user_id uuid NOT NULL,"
        "  key_id text NOT NULL,"
        "  token_hash text NOT NULL,"
        "  expires_at timestamptz NOT NULL,"
        "  scope text NOT NULL,"
        "  created_at timestamptz NOT NULL DEFAULT now()"
        ")"
    )

    # -- signer_links (ADR 0002 M2 s1) --
    op.execute(
        "CREATE TABLE signer_links ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  user_id uuid NOT NULL,"
        "  code_hash text NOT NULL,"
        "  expires_at timestamptz NOT NULL,"
        "  used_at timestamptz,"
        "  public_key text,"
        "  key_id text,"
        "  status text NOT NULL DEFAULT 'pending',"
        "  created_at timestamptz NOT NULL DEFAULT now()"
        ")"
    )

    # -- sync_alerts (ADR 0002 M2 s1) --
    op.execute(
        "CREATE TABLE sync_alerts ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  project_id uuid NOT NULL,"
        "  connector_id uuid,"
        "  kind text NOT NULL,"
        "  detail jsonb,"
        "  created_at timestamptz NOT NULL DEFAULT now()"
        ")"
    )

    # -- audit_records (ADR 0002 main + M2 s2.7) --
    op.execute(
        "CREATE TABLE audit_records ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  connector_id uuid NOT NULL,"
        "  session_id text NOT NULL,"
        "  chain_length bigint NOT NULL,"
        "  previous_hash text NOT NULL,"
        "  record_hash text NOT NULL,"
        "  body jsonb,"
        "  created_at timestamptz NOT NULL,"
        "  UNIQUE (connector_id, session_id, chain_length)"
        ")"
    )

    # -- audit_heads (ADR 0002 main + M2 s2.7) --
    op.execute(
        "CREATE TABLE audit_heads ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  connector_id uuid NOT NULL,"
        "  upload_seq bigint NOT NULL,"
        "  session_list jsonb,"
        "  head_hash text,"
        "  signature text,"
        "  created_at timestamptz NOT NULL,"
        "  UNIQUE (connector_id, upload_seq)"
        ")"
    )

    # -- audit_quarantine (ADR 0002 main + M2 s2.7) --
    op.execute(
        "CREATE TABLE audit_quarantine ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  connector_id uuid NOT NULL,"
        "  kind text NOT NULL,"
        "  detail jsonb,"
        "  created_at timestamptz NOT NULL DEFAULT now()"
        ")"
    )

    # ==================================================================
    # 2. Ownership, RLS, org-isolation policy on every table
    # ==================================================================
    for tbl in _ALL_M2_TABLES:
        op.execute(f"ALTER TABLE {tbl} OWNER TO agg_owner")
        op.execute(f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY {tbl}_org_isolation ON {tbl} "
            "USING (org_id = NULLIF(current_setting('app.org_id', true), "
            "                        '')::uuid) "
            "WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), "
            "                             '')::uuid)"
        )

    # ==================================================================
    # 3. Owner policies for tables touched by SECURITY DEFINER functions
    #    (ADR 0002 M2 s3: "through a policy TO agg_owner … limited to
    #    the command it needs").  Command-specific, matching M1 pattern.
    # ==================================================================

    # SELECT-only: device_lookup, device_token_lookup, cli_key_lookup,
    # signer_token_lookup read these tables.
    for tbl in ("connectors", "device_tokens", "signer_tokens",
                "approver_keys"):
        op.execute(
            f"CREATE POLICY {tbl}_owner_select ON {tbl} "
            "FOR SELECT TO agg_owner USING (true)"
        )

    # SELECT + UPDATE: enrollment_code_consume / signer_link_consume
    # do UPDATE … RETURNING (needs SELECT to find rows + UPDATE to
    # mutate).  INSERT exists only because the frozen T5 tests seed
    # these rows as agg_owner with no app.org_id; no SECURITY DEFINER
    # function and no app code inserts here as agg_owner (agg_app
    # inserts under the org_isolation policy).
    for tbl in ("enrollment_codes", "signer_links"):
        op.execute(
            f"CREATE POLICY {tbl}_owner_select ON {tbl} "
            "FOR SELECT TO agg_owner USING (true)"
        )
        op.execute(
            f"CREATE POLICY {tbl}_owner_update ON {tbl} "
            "FOR UPDATE TO agg_owner USING (true) WITH CHECK (true)"
        )
        op.execute(
            f"CREATE POLICY {tbl}_owner_insert ON {tbl} "
            "FOR INSERT TO agg_owner WITH CHECK (true)"
        )

    # INSERT-only: device_nonce_insert / signer_nonce_insert.
    for tbl in ("device_nonces", "signer_nonces"):
        op.execute(
            f"CREATE POLICY {tbl}_owner_insert ON {tbl} "
            "FOR INSERT TO agg_owner WITH CHECK (true)"
        )

    # ==================================================================
    # 4. Grants to agg_app (least privilege)
    # ==================================================================

    # Full CRUD
    for tbl in _SECTION2_CRUD + _SECTION1_CRUD:
        op.execute(
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON {tbl} TO agg_app"
        )

    # SELECT + INSERT only
    for tbl in _SECTION2_LIMITED + _SECTION1_LIMITED:
        op.execute(f"GRANT SELECT, INSERT ON {tbl} TO agg_app")

    # Audit tables: INSERT, SELECT only (append-only)
    for tbl in _AUDIT_TABLES:
        op.execute(f"GRANT SELECT, INSERT ON {tbl} TO agg_app")

    # ==================================================================
    # 5. SECURITY DEFINER functions (ADR 0002 M2 s3, rows 1-7)
    #    Each: SET search_path = pg_catalog, pg_temp
    #    Schema-qualified identifiers, owner agg_owner, REVOKE PUBLIC,
    #    GRANT agg_app.
    # ==================================================================

    # -- Row 1: device_lookup(device_id) --
    op.execute(
        "CREATE FUNCTION device_lookup(p_device_id uuid)\n"
        "RETURNS TABLE (org_id uuid, project_id uuid, connector_id uuid,"
        " public_key text, revoked_at timestamptz)\n"
        "LANGUAGE sql STABLE SECURITY DEFINER\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "  SELECT c.org_id, c.project_id, c.id, c.device_public_key,"
        " c.revoked_at\n"
        "  FROM public.connectors c\n"
        "  WHERE c.id = p_device_id\n"
        "  LIMIT 1;\n"
        "$$"
    )

    # -- Row 2: device_token_lookup(token_hash) --
    op.execute(
        "CREATE FUNCTION device_token_lookup(p_token_hash text)\n"
        "RETURNS TABLE (org_id uuid, project_id uuid,"
        " connector_id uuid)\n"
        "LANGUAGE sql STABLE SECURITY DEFINER\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "  SELECT dt.org_id, dt.project_id, dt.connector_id\n"
        "  FROM public.device_tokens dt\n"
        "  JOIN public.connectors c ON c.id = dt.connector_id\n"
        "  WHERE dt.token_hash = p_token_hash\n"
        "    AND dt.expires_at > pg_catalog.now()\n"
        "    AND c.revoked_at IS NULL\n"
        "  LIMIT 1;\n"
        "$$"
    )

    # -- Row 3: enrollment_code_consume(code_hash) --
    # Atomic: one UPDATE ... WHERE used_at IS NULL AND expires_at > now()
    # RETURNING.  Exactly 1 winner across concurrent callers.
    op.execute(
        "CREATE FUNCTION enrollment_code_consume(p_code_hash text)\n"
        "RETURNS TABLE (org_id uuid, project_id uuid,"
        " operator_user_id uuid)\n"
        "LANGUAGE sql SECURITY DEFINER\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "  UPDATE public.enrollment_codes\n"
        "  SET used_at = pg_catalog.now()\n"
        "  WHERE code_hash = p_code_hash\n"
        "    AND used_at IS NULL\n"
        "    AND expires_at > pg_catalog.now()\n"
        "  RETURNING org_id, project_id, operator_user_id;\n"
        "$$"
    )

    # -- Row 4: signer_link_consume(code_hash) --
    # Single-use, same atomic pattern.
    op.execute(
        "CREATE FUNCTION signer_link_consume(p_code_hash text)\n"
        "RETURNS TABLE (org_id uuid, user_id uuid)\n"
        "LANGUAGE sql SECURITY DEFINER\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "  UPDATE public.signer_links\n"
        "  SET used_at = pg_catalog.now()\n"
        "  WHERE code_hash = p_code_hash\n"
        "    AND used_at IS NULL\n"
        "    AND expires_at > pg_catalog.now()\n"
        "  RETURNING org_id, user_id;\n"
        "$$"
    )

    # -- Row 5: cli_key_lookup(key_id) --
    # Returns from approver_keys (status='signer') or pending
    # signer_links (status='link') per F5.
    # Wrap in subquery with ORDER BY so 'signer' (0) deterministically
    # wins over 'link' (1) for the same key_id.
    op.execute(
        "CREATE FUNCTION cli_key_lookup(p_key_id text)\n"
        "RETURNS TABLE (org_id uuid, user_id uuid,"
        " public_key text, status text)\n"
        "LANGUAGE sql STABLE SECURITY DEFINER\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "  SELECT q.org_id, q.user_id, q.public_key, q.status\n"
        "  FROM (\n"
        "    SELECT ak.org_id, ak.user_id, ak.public_key,"
        " 'signer'::text AS status, 0 AS sort_key\n"
        "    FROM public.approver_keys ak\n"
        "    WHERE ak.key_id = p_key_id AND ak.revoked_at IS NULL\n"
        "    UNION ALL\n"
        "    SELECT sl.org_id, sl.user_id, sl.public_key,"
        " 'link'::text AS status, 1 AS sort_key\n"
        "    FROM public.signer_links sl\n"
        "    WHERE sl.key_id = p_key_id\n"
        "      AND sl.status = 'pending'\n"
        "      AND sl.public_key IS NOT NULL\n"
        "  ) q\n"
        "  ORDER BY q.sort_key\n"
        "  LIMIT 1;\n"
        "$$"
    )

    # -- Row 6: signer_token_lookup(token_hash) --
    op.execute(
        "CREATE FUNCTION signer_token_lookup(p_token_hash text)\n"
        "RETURNS TABLE (org_id uuid, user_id uuid,"
        " key_id text, scope text)\n"
        "LANGUAGE sql STABLE SECURITY DEFINER\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "  SELECT st.org_id, st.user_id, st.key_id, st.scope\n"
        "  FROM public.signer_tokens st\n"
        "  WHERE st.token_hash = p_token_hash\n"
        "    AND st.expires_at > pg_catalog.now()\n"
        "  LIMIT 1;\n"
        "$$"
    )

    # -- Row 7a: device_nonce_insert(device_id, nonce, iat) --
    # Inserts into device_nonces; unique (device_id, nonce) refuses repeats.
    # org_id looked up from connectors; falls back to zero UUID if unknown.
    op.execute(
        "CREATE FUNCTION device_nonce_insert("
        "p_device_id uuid, p_nonce text, p_iat timestamptz)\n"
        "RETURNS void\n"
        "LANGUAGE sql SECURITY DEFINER\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "  INSERT INTO public.device_nonces"
        " (id, org_id, device_id, nonce, iat, created_at)\n"
        "  SELECT pg_catalog.gen_random_uuid(),\n"
        "         COALESCE(\n"
        "           (SELECT c.org_id FROM public.connectors c"
        " WHERE c.id = p_device_id LIMIT 1),\n"
        "           '00000000-0000-0000-0000-000000000000'::uuid\n"
        "         ),\n"
        "         p_device_id,\n"
        "         p_nonce,\n"
        "         p_iat,\n"
        "         pg_catalog.now();\n"
        "$$"
    )

    # -- Row 7b: signer_nonce_insert(key_id, nonce, iat) --
    # Same pattern; unique (key_id, nonce) refuses repeats.
    op.execute(
        "CREATE FUNCTION signer_nonce_insert("
        "p_key_id text, p_nonce text, p_iat timestamptz)\n"
        "RETURNS void\n"
        "LANGUAGE sql SECURITY DEFINER\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "  INSERT INTO public.signer_nonces"
        " (id, org_id, key_id, nonce, iat, created_at)\n"
        "  SELECT pg_catalog.gen_random_uuid(),\n"
        "         COALESCE(\n"
        "           (SELECT ak.org_id FROM public.approver_keys ak"
        " WHERE ak.key_id = p_key_id LIMIT 1),\n"
        "           '00000000-0000-0000-0000-000000000000'::uuid\n"
        "         ),\n"
        "         p_key_id,\n"
        "         p_nonce,\n"
        "         p_iat,\n"
        "         pg_catalog.now();\n"
        "$$"
    )

    # -- Ownership, REVOKE PUBLIC, GRANT agg_app for each SECDEF fn --
    _SECDEF_SIGS = [
        "device_lookup(uuid)",
        "device_token_lookup(text)",
        "enrollment_code_consume(text)",
        "signer_link_consume(text)",
        "cli_key_lookup(text)",
        "signer_token_lookup(text)",
        "device_nonce_insert(uuid, text, timestamptz)",
        "signer_nonce_insert(text, text, timestamptz)",
    ]
    for sig in _SECDEF_SIGS:
        op.execute(f"ALTER FUNCTION {sig} OWNER TO agg_owner")
        op.execute(
            f"REVOKE EXECUTE ON FUNCTION {sig} FROM PUBLIC"
        )
        op.execute(
            f"GRANT EXECUTE ON FUNCTION {sig} TO agg_app"
        )

    # ==================================================================
    # 6. Append-only audit triggers (ADR 0002 M2 s2.7)
    #    Same pattern as admin_audit in 0002_m1_tables:
    #    - row trigger rejects UPDATE
    #    - row trigger rejects DELETE
    #    - statement trigger rejects TRUNCATE
    # ==================================================================

    # -- Shared trigger functions (use TG_TABLE_NAME for the message) --
    op.execute(
        "CREATE FUNCTION m2_audit_no_update() RETURNS trigger\n"
        "LANGUAGE plpgsql\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "BEGIN\n"
        "  RAISE EXCEPTION 'UPDATE on % is forbidden', TG_TABLE_NAME;\n"
        "END;\n"
        "$$"
    )
    op.execute("ALTER FUNCTION m2_audit_no_update() OWNER TO agg_owner")
    op.execute(
        "REVOKE EXECUTE ON FUNCTION m2_audit_no_update() FROM PUBLIC"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION m2_audit_no_update() TO agg_owner"
    )

    op.execute(
        "CREATE FUNCTION m2_audit_no_delete() RETURNS trigger\n"
        "LANGUAGE plpgsql\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "BEGIN\n"
        "  RAISE EXCEPTION 'DELETE on % is forbidden', TG_TABLE_NAME;\n"
        "END;\n"
        "$$"
    )
    op.execute("ALTER FUNCTION m2_audit_no_delete() OWNER TO agg_owner")
    op.execute(
        "REVOKE EXECUTE ON FUNCTION m2_audit_no_delete() FROM PUBLIC"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION m2_audit_no_delete() TO agg_owner"
    )

    op.execute(
        "CREATE FUNCTION m2_audit_no_truncate() RETURNS trigger\n"
        "LANGUAGE plpgsql\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "BEGIN\n"
        "  RAISE EXCEPTION 'TRUNCATE on % is forbidden', TG_TABLE_NAME;\n"
        "END;\n"
        "$$"
    )
    op.execute("ALTER FUNCTION m2_audit_no_truncate() OWNER TO agg_owner")
    op.execute(
        "REVOKE EXECUTE ON FUNCTION m2_audit_no_truncate() FROM PUBLIC"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION m2_audit_no_truncate() TO agg_owner"
    )

    # Attach triggers to each audit table
    for tbl in _AUDIT_TABLES:
        op.execute(
            f"CREATE TRIGGER trg_{tbl}_no_update "
            f"BEFORE UPDATE ON {tbl} "
            "FOR EACH ROW EXECUTE FUNCTION m2_audit_no_update()"
        )
        op.execute(
            f"CREATE TRIGGER trg_{tbl}_no_delete "
            f"BEFORE DELETE ON {tbl} "
            "FOR EACH ROW EXECUTE FUNCTION m2_audit_no_delete()"
        )
        op.execute(
            f"CREATE TRIGGER trg_{tbl}_no_truncate "
            f"BEFORE TRUNCATE ON {tbl} "
            "FOR EACH STATEMENT EXECUTE FUNCTION m2_audit_no_truncate()"
        )


def downgrade() -> None:
    # -- Drop triggers on audit tables --
    for tbl in _AUDIT_TABLES:
        for name in ("no_update", "no_delete", "no_truncate"):
            op.execute(
                f"DROP TRIGGER IF EXISTS trg_{tbl}_{name} ON {tbl}"
            )

    # -- Drop audit trigger functions --
    op.execute("DROP FUNCTION IF EXISTS m2_audit_no_update()")
    op.execute("DROP FUNCTION IF EXISTS m2_audit_no_delete()")
    op.execute("DROP FUNCTION IF EXISTS m2_audit_no_truncate()")

    # -- Drop SECURITY DEFINER functions --
    op.execute("DROP FUNCTION IF EXISTS device_lookup(uuid)")
    op.execute("DROP FUNCTION IF EXISTS device_token_lookup(text)")
    op.execute("DROP FUNCTION IF EXISTS enrollment_code_consume(text)")
    op.execute("DROP FUNCTION IF EXISTS signer_link_consume(text)")
    op.execute("DROP FUNCTION IF EXISTS cli_key_lookup(text)")
    op.execute("DROP FUNCTION IF EXISTS signer_token_lookup(text)")
    op.execute(
        "DROP FUNCTION IF EXISTS "
        "device_nonce_insert(uuid, text, timestamptz)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS "
        "signer_nonce_insert(text, text, timestamptz)"
    )

    # -- Revoke grants --
    for tbl in _ALL_M2_TABLES:
        op.execute(f"REVOKE ALL ON {tbl} FROM agg_app")

    # -- Drop tables (reverse order) --
    for tbl in reversed(_ALL_M2_TABLES):
        op.execute(f"DROP TABLE IF EXISTS {tbl}")
