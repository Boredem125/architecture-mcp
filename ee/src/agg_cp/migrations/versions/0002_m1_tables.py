"""M1 T7: 8 tables, RLS, admin_audit chain, org_login_config.

Creates the 8 M1 tables (orgs, org_oidc_config, projects, users,
role_bindings, web_sessions, setup_codes, admin_audit) with:

- ENABLE + FORCE ROW LEVEL SECURITY on every table
- Owner agg_owner on every table
- RLS policies on NULLIF(current_setting('app.org_id', true), '')::uuid
  with USING and WITH CHECK
- Grants to agg_app (least-privilege per table; admin_audit: INSERT,
  SELECT only; TRUNCATE revoked)
- agg_worker gets nothing
- SECURITY DEFINER function org_login_config(slug text) returning
  (org_id, issuer, client_id): SET search_path = pg_catalog, pg_temp,
  schema-qualified references, REVOKE EXECUTE FROM PUBLIC, GRANT
  EXECUTE to agg_app, owned by agg_owner (not a superuser)
- admin_audit: append-only row triggers (reject UPDATE/DELETE for
  every role, BEFORE TRUNCATE rejects), BEFORE INSERT trigger
  computes the chain per ADR 0002 item 6
- admin_audit_canonical(admin_audit) SQL function for deterministic
  record hashing
- Unique (org_id, chain_length) and (org_id, previous_hash) on
  admin_audit

Roles are created outside migrations (deploy init / the test fixture)
and never with a password here; this migration only grants.

Revision ID: 000000000002
Revises: 000000000001
Create Date: 2026-10-20
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "000000000002"
down_revision: Union[str, None] = "000000000001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# The 8 M1 tables.
_M1_TABLES: tuple[str, ...] = (
    "orgs",
    "org_oidc_config",
    "projects",
    "users",
    "role_bindings",
    "web_sessions",
    "setup_codes",
    "admin_audit",
)

# Tables that agg_app gets full CRUD on.
_CRUD_TABLES: tuple[str, ...] = (
    "orgs",
    "org_oidc_config",
    "projects",
    "users",
    "role_bindings",
    "web_sessions",
    "setup_codes",
)


def upgrade() -> None:
    # PostgreSQL 16 has built-in sha256(bytea) in pg_catalog;
    # no extension needed.

    # ------------------------------------------------------------------
    # 1. Tables
    # ------------------------------------------------------------------
    op.execute(
        "CREATE TABLE orgs ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  name text NOT NULL,"
        "  slug text NOT NULL UNIQUE,"
        "  created_at timestamptz NOT NULL"
        ")"
    )

    op.execute(
        "CREATE TABLE org_oidc_config ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  issuer text NOT NULL,"
        "  client_id text NOT NULL,"
        "  created_at timestamptz NOT NULL"
        ")"
    )

    op.execute(
        "CREATE TABLE projects ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  name text NOT NULL,"
        "  environment text NOT NULL,"
        "  created_at timestamptz NOT NULL"
        ")"
    )

    op.execute(
        "CREATE TABLE users ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  oidc_issuer text NOT NULL,"
        "  oidc_subject text NOT NULL,"
        "  email text NOT NULL,"
        "  status text NOT NULL,"
        "  created_at timestamptz NOT NULL,"
        "  UNIQUE (oidc_issuer, oidc_subject)"
        ")"
    )

    op.execute(
        "CREATE TABLE role_bindings ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  user_id uuid NOT NULL,"
        "  scope_type text NOT NULL,"
        "  scope_id uuid NOT NULL,"
        "  role text NOT NULL,"
        "  created_at timestamptz NOT NULL"
        ")"
    )

    op.execute(
        "CREATE TABLE web_sessions ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  user_id uuid NOT NULL,"
        "  created_at timestamptz NOT NULL,"
        "  expires_at timestamptz NOT NULL"
        ")"
    )

    op.execute(
        "CREATE TABLE setup_codes ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  code_hash text NOT NULL,"
        "  created_at timestamptz NOT NULL,"
        "  expires_at timestamptz NOT NULL"
        ")"
    )

    op.execute(
        "CREATE TABLE admin_audit ("
        "  id uuid PRIMARY KEY,"
        "  org_id uuid NOT NULL,"
        "  action text NOT NULL,"
        "  detail jsonb,"
        "  chain_length bigint,"
        "  previous_hash text,"
        "  record_hash text,"
        "  created_at timestamptz,"
        "  UNIQUE (org_id, chain_length),"
        "  UNIQUE (org_id, previous_hash)"
        ")"
    )

    # ------------------------------------------------------------------
    # 2. Ownership
    # ------------------------------------------------------------------
    for tbl in _M1_TABLES:
        op.execute(f"ALTER TABLE {tbl} OWNER TO agg_owner")

    # ------------------------------------------------------------------
    # 3. RLS: ENABLE + FORCE + org-isolation policy on every table
    # ------------------------------------------------------------------
    for tbl in _M1_TABLES:
        op.execute(f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY {tbl}_org_isolation ON {tbl} "
            "USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid) "
            "WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)"
        )

    # Owner bypass (SELECT only) on orgs and org_oidc_config so the
    # SECURITY DEFINER function org_login_config can read rows without
    # app.org_id being set.
    op.execute(
        "CREATE POLICY orgs_owner_read ON orgs "
        "FOR SELECT TO agg_owner USING (true)"
    )
    op.execute(
        "CREATE POLICY org_oidc_config_owner_read ON org_oidc_config "
        "FOR SELECT TO agg_owner USING (true)"
    )

    # ------------------------------------------------------------------
    # 4. Grants to agg_app (least privilege)
    # ------------------------------------------------------------------
    for tbl in _CRUD_TABLES:
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {tbl} TO agg_app")

    # admin_audit: INSERT, SELECT only
    op.execute("GRANT INSERT, SELECT ON admin_audit TO agg_app")

    # ------------------------------------------------------------------
    # 5. SECURITY DEFINER function: org_login_config(slug)
    # ------------------------------------------------------------------
    op.execute(
        "CREATE FUNCTION org_login_config(p_slug text)\n"
        "RETURNS TABLE (org_id uuid, issuer text, client_id text)\n"
        "LANGUAGE sql STABLE SECURITY DEFINER\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "  SELECT o.id, c.issuer, c.client_id\n"
        "  FROM public.orgs o\n"
        "  JOIN public.org_oidc_config c ON c.org_id = o.id\n"
        "  WHERE o.slug = p_slug\n"
        "  LIMIT 1;\n"
        "$$"
    )
    op.execute("ALTER FUNCTION org_login_config(text) OWNER TO agg_owner")
    op.execute(
        "REVOKE EXECUTE ON FUNCTION org_login_config(text) FROM PUBLIC"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION org_login_config(text) TO agg_app"
    )

    # ------------------------------------------------------------------
    # 6. admin_audit_canonical(admin_audit) function
    #    ADR 0002 item 6: deterministic text for record hashing.
    #    Includes every column except record_hash (so previous_hash
    #    and chain_length are bound).
    # ------------------------------------------------------------------
    op.execute(
        "CREATE FUNCTION admin_audit_canonical(r admin_audit)\n"
        "RETURNS text\n"
        "LANGUAGE sql IMMUTABLE\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "  SELECT pg_catalog.jsonb_build_object(\n"
        "    'action',        r.action,\n"
        "    'chain_length',  r.chain_length,\n"
        "    'created_at',    pg_catalog.to_char(\n"
        "                       r.created_at AT TIME ZONE 'UTC',\n"
        "                       'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'\n"
        "                     ),\n"
        "    'detail',        r.detail,\n"
        "    'id',            r.id::text,\n"
        "    'org_id',        r.org_id::text,\n"
        "    'previous_hash', r.previous_hash\n"
        "  )::text;\n"
        "$$"
    )
    op.execute(
        "ALTER FUNCTION admin_audit_canonical(admin_audit) OWNER TO agg_owner"
    )
    op.execute(
        "REVOKE EXECUTE ON FUNCTION admin_audit_canonical(admin_audit) FROM PUBLIC"
    )
    # agg_app needs EXECUTE for verify_chain (SELECT admin_audit_canonical(t))
    # and indirectly via the chain trigger.
    op.execute(
        "GRANT EXECUTE ON FUNCTION admin_audit_canonical(admin_audit) TO agg_app"
    )

    # ------------------------------------------------------------------
    # 7. admin_audit triggers: append-only
    # ------------------------------------------------------------------

    # 7a. Reject UPDATE
    op.execute(
        "CREATE FUNCTION admin_audit_no_update() RETURNS trigger\n"
        "LANGUAGE plpgsql\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "BEGIN\n"
        "  RAISE EXCEPTION 'UPDATE on admin_audit is forbidden';\n"
        "END;\n"
        "$$"
    )
    op.execute("ALTER FUNCTION admin_audit_no_update() OWNER TO agg_owner")
    op.execute(
        "REVOKE EXECUTE ON FUNCTION admin_audit_no_update() FROM PUBLIC"
    )
    # Only agg_owner can attempt UPDATE (agg_app has no UPDATE grant);
    # the trigger blocks it.
    op.execute(
        "GRANT EXECUTE ON FUNCTION admin_audit_no_update() TO agg_owner"
    )
    op.execute(
        "CREATE TRIGGER trg_admin_audit_no_update "
        "BEFORE UPDATE ON admin_audit "
        "FOR EACH ROW EXECUTE FUNCTION admin_audit_no_update()"
    )

    # 7b. Reject DELETE
    op.execute(
        "CREATE FUNCTION admin_audit_no_delete() RETURNS trigger\n"
        "LANGUAGE plpgsql\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "BEGIN\n"
        "  RAISE EXCEPTION 'DELETE on admin_audit is forbidden';\n"
        "END;\n"
        "$$"
    )
    op.execute("ALTER FUNCTION admin_audit_no_delete() OWNER TO agg_owner")
    op.execute(
        "REVOKE EXECUTE ON FUNCTION admin_audit_no_delete() FROM PUBLIC"
    )
    # Only agg_owner can attempt DELETE; the trigger blocks it.
    op.execute(
        "GRANT EXECUTE ON FUNCTION admin_audit_no_delete() TO agg_owner"
    )
    op.execute(
        "CREATE TRIGGER trg_admin_audit_no_delete "
        "BEFORE DELETE ON admin_audit "
        "FOR EACH ROW EXECUTE FUNCTION admin_audit_no_delete()"
    )

    # 7c. Reject TRUNCATE
    op.execute(
        "CREATE FUNCTION admin_audit_no_truncate() RETURNS trigger\n"
        "LANGUAGE plpgsql\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "BEGIN\n"
        "  RAISE EXCEPTION 'TRUNCATE on admin_audit is forbidden';\n"
        "END;\n"
        "$$"
    )
    op.execute("ALTER FUNCTION admin_audit_no_truncate() OWNER TO agg_owner")
    op.execute(
        "REVOKE EXECUTE ON FUNCTION admin_audit_no_truncate() FROM PUBLIC"
    )
    # Only agg_owner can attempt TRUNCATE; the trigger blocks it.
    op.execute(
        "GRANT EXECUTE ON FUNCTION admin_audit_no_truncate() TO agg_owner"
    )
    op.execute(
        "CREATE TRIGGER trg_admin_audit_no_truncate "
        "BEFORE TRUNCATE ON admin_audit "
        "FOR EACH STATEMENT EXECUTE FUNCTION admin_audit_no_truncate()"
    )

    # ------------------------------------------------------------------
    # 8. admin_audit chain trigger (ADR 0002 item 6)
    #    BEFORE INSERT: advisory xact lock per org, compute
    #    chain_length, previous_hash, created_at, record_hash.
    # ------------------------------------------------------------------
    op.execute(
        "CREATE FUNCTION admin_audit_chain() RETURNS trigger\n"
        "LANGUAGE plpgsql\n"
        "SET search_path = pg_catalog, pg_temp\n"
        "AS $$\n"
        "DECLARE\n"
        "  last_length bigint;\n"
        "  last_hash   text;\n"
        "BEGIN\n"
        "  -- Advisory xact lock per org\n"
        "  PERFORM pg_catalog.pg_advisory_xact_lock(\n"
        "    pg_catalog.hashtext(NEW.org_id::text)::bigint\n"
        "  );\n"
        "\n"
        "  -- Last row for this org\n"
        "  SELECT a.chain_length, a.record_hash\n"
        "    INTO last_length, last_hash\n"
        "    FROM public.admin_audit a\n"
        "   WHERE a.org_id = NEW.org_id\n"
        "   ORDER BY a.chain_length DESC\n"
        "   LIMIT 1;\n"
        "\n"
        "  IF last_length IS NULL THEN\n"
        "    NEW.chain_length  := 1;\n"
        "    NEW.previous_hash := pg_catalog.repeat('0', 64);\n"
        "  ELSE\n"
        "    NEW.chain_length  := last_length + 1;\n"
        "    NEW.previous_hash := last_hash;\n"
        "  END IF;\n"
        "\n"
        "  NEW.created_at := pg_catalog.now();\n"
        "\n"
        "  NEW.record_hash := pg_catalog.encode(\n"
        "    pg_catalog.sha256(\n"
        "      pg_catalog.convert_to(\n"
        "        public.admin_audit_canonical(NEW), 'UTF8'\n"
        "      )\n"
        "    ),\n"
        "    'hex'\n"
        "  );\n"
        "\n"
        "  RETURN NEW;\n"
        "END;\n"
        "$$"
    )
    op.execute("ALTER FUNCTION admin_audit_chain() OWNER TO agg_owner")
    op.execute(
        "REVOKE EXECUTE ON FUNCTION admin_audit_chain() FROM PUBLIC"
    )
    # agg_app needs EXECUTE because the trigger fires on INSERT.
    op.execute(
        "GRANT EXECUTE ON FUNCTION admin_audit_chain() TO agg_app"
    )
    op.execute(
        "CREATE TRIGGER trg_admin_audit_chain "
        "BEFORE INSERT ON admin_audit "
        "FOR EACH ROW EXECUTE FUNCTION admin_audit_chain()"
    )


def downgrade() -> None:
    # Drop triggers
    op.execute("DROP TRIGGER IF EXISTS trg_admin_audit_chain ON admin_audit")
    op.execute(
        "DROP TRIGGER IF EXISTS trg_admin_audit_no_truncate ON admin_audit"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS trg_admin_audit_no_delete ON admin_audit"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS trg_admin_audit_no_update ON admin_audit"
    )

    # Drop functions (canonical must go before the table, since its
    # signature references the admin_audit composite type)
    op.execute("DROP FUNCTION IF EXISTS admin_audit_chain()")
    op.execute("DROP FUNCTION IF EXISTS admin_audit_no_truncate()")
    op.execute("DROP FUNCTION IF EXISTS admin_audit_no_delete()")
    op.execute("DROP FUNCTION IF EXISTS admin_audit_no_update()")
    op.execute("DROP FUNCTION IF EXISTS admin_audit_canonical(admin_audit)")
    op.execute("DROP FUNCTION IF EXISTS org_login_config(text)")

    # Revoke grants
    for tbl in _M1_TABLES:
        op.execute(f"REVOKE ALL ON {tbl} FROM agg_app")

    # Drop tables (reverse dependency order)
    for tbl in reversed(_M1_TABLES):
        op.execute(f"DROP TABLE IF EXISTS {tbl}")
