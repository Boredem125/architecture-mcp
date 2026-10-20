"""M1 T13 review findings F1/F2: the org slug can never become a path."""
from __future__ import annotations

import os

import pytest

from agg_cp.auth import is_valid_slug, org_secret_path


@pytest.mark.parametrize("slug", ["acme", "globex", "t9-1a2b", "a", "0org", "a" * 63])
def test_valid_slugs_accepted(slug):
    assert is_valid_slug(slug)


@pytest.mark.parametrize(
    "slug",
    ["", "../etc/passwd", "..", "a/b", "Acme", "acme_corp", "-acme", "a" * 64, "acme\x00", "acme.", "/abs"],
)
def test_bad_slugs_refused(slug):
    assert not is_valid_slug(slug)
    assert org_secret_path("/oidc-secrets", slug) is None


def test_secret_path_stays_in_dir(tmp_path):
    (tmp_path / "acme").write_text("s")
    assert org_secret_path(str(tmp_path), "acme") == os.path.realpath(tmp_path / "acme")


def test_symlink_out_of_dir_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("secret")
    d = tmp_path / "secrets"
    d.mkdir()
    (d / "acme").symlink_to(outside)
    assert org_secret_path(str(d), "acme") is None


@pytest.mark.pg
def test_db_check_refuses_path_slug(pg_url, owner_url, pg_roles):
    import uuid

    import psycopg

    from .t8p2_helpers import ensure_at_head

    ensure_at_head(pg_url)
    conninfo = pg_url.replace("+psycopg", "")
    oid = uuid.uuid4()
    with psycopg.connect(conninfo) as conn:
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO orgs (id, org_id, name, slug, created_at) "
                "VALUES (%s, %s, 'x', '../x', now())",
                [oid, oid],
            )
        conn.rollback()
        ok = uuid.uuid4()
        conn.execute(  # positive control
            "INSERT INTO orgs (id, org_id, name, slug, created_at) "
            "VALUES (%s, %s, 'x', %s, now())",
            [ok, ok, f"t13-{ok.hex[:8]}"],
        )
        conn.rollback()
