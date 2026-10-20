#!/usr/bin/env bash
# ee/deploy/init/00-roles.sh
#
# Mounted into postgres docker-entrypoint-initdb.d/.
# Creates the application roles used by the control plane:
#
#   agg_owner  -- LOGIN; owns schema and tables; runs migrations.
#   agg_app    -- LOGIN, NOSUPERUSER, NOBYPASSRLS; used by the API.
#   agg_worker -- NOLOGIN; reserved for the M2 worker service.
#
# Passwords are read from Docker secrets files and passed to psql via
# -v variables, then bridged into PL/pgSQL via set_config/current_setting
# (psql :'var' quoted-literal interpolation at the top level, then
# format(%L) inside DO blocks).  No shell interpolation into SQL.
#
# Grants mirror the pg_roles fixture in ee/tests/conftest.py.
#
# This script runs as the postgres superuser during initdb (first start
# only; it is skipped on subsequent starts when the data volume exists).
set -euo pipefail

# Read passwords from mounted secrets
OWNER_PASS="$(cat /run/secrets/pg_owner_password)"
APP_PASS="$(cat /run/secrets/pg_app_password)"

# Pass passwords as psql variables -- never interpolated into SQL strings.
# :'var' produces a safely-quoted SQL literal at the psql layer.
# set_config bridges the value into DO-block scope via current_setting.
psql -v ON_ERROR_STOP=1 \
     -v owner_pass="$OWNER_PASS" \
     -v app_pass="$APP_PASS" \
     -v dbname="$POSTGRES_DB" \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" <<'EOSQL'

    -- Bridge psql variables into session GUCs so DO blocks can read them
    SELECT set_config('init.owner_pass', :'owner_pass', false);
    SELECT set_config('init.app_pass',   :'app_pass',   false);

    -- agg_owner: runs migrations, owns schema objects
    DO $$ BEGIN
        EXECUTE format(
            'CREATE ROLE agg_owner WITH LOGIN PASSWORD %L',
            current_setting('init.owner_pass')
        );
    EXCEPTION WHEN duplicate_object THEN NULL;
    END $$;

    -- agg_app: API connections, no superuser, no bypass RLS
    DO $$ BEGIN
        EXECUTE format(
            'CREATE ROLE agg_app WITH LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD %L',
            current_setting('init.app_pass')
        );
    EXCEPTION WHEN duplicate_object THEN NULL;
    END $$;

    -- agg_worker: reserved for M2 worker service (no login for now)
    DO $$ BEGIN
        CREATE ROLE agg_worker WITH NOLOGIN;
    EXCEPTION WHEN duplicate_object THEN NULL;
    END $$;

    -- Clear the password GUCs immediately
    SELECT set_config('init.owner_pass', '', false);
    SELECT set_config('init.app_pass',   '', false);

    -- Database-level grants
    GRANT ALL ON DATABASE :"dbname" TO agg_owner;
    GRANT CONNECT ON DATABASE :"dbname" TO agg_app;

    -- Schema-level grants (public schema)
    GRANT USAGE ON SCHEMA public TO agg_owner;
    GRANT CREATE ON SCHEMA public TO agg_owner;
    GRANT USAGE ON SCHEMA public TO agg_app;

EOSQL

echo "00-roles.sh: roles agg_owner, agg_app, agg_worker created."
