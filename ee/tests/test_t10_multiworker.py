"""T10 multi-worker integration tests.

Proves that `uvicorn --workers 4 --factory` on a real Postgres database
works correctly:
- 4 separate worker processes are running.
- A session created on one worker validates on all (shared DB state).
- Concurrent identical role grants are idempotent across workers
  (exactly one role_bindings row, audit rows match the API contract).
- The admin_audit chain remains valid after concurrent writes.

All helpers are local to this file.  No production code is modified.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import psycopg
import pytest

from . import _portable

# ---------------------------------------------------------------------------
# Named exception for real bugs found by T10
# ---------------------------------------------------------------------------

class T10Pending(Exception):
    """T10 multi-worker test found a real product bug."""


# ---------------------------------------------------------------------------
# Helpers local to this file
# ---------------------------------------------------------------------------

_REPO = Path(__file__).resolve().parents[2]  # architecture-mcp root


def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _sha256_hex(value: str) -> str:
    import hashlib
    return hashlib.sha256(value.encode()).hexdigest()


def _free_port() -> int:
    """Bind to port 0 and return the OS-assigned port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _ensure_at_head(pg_url: str) -> None:
    """Run alembic upgrade head (idempotent)."""
    from agg_cp.db import alembic_config
    from alembic import command as alembic_cmd
    cfg = alembic_config(pg_url)
    alembic_cmd.upgrade(cfg, "head")


def _seed_org_with_oidc(owner_url: str, *, slug: str) -> uuid.UUID:
    """Seed an org with OIDC config; return org_id."""
    org_id = uuid.uuid4()
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        conn.execute(
            "INSERT INTO orgs (id, org_id, name, slug, created_at) "
            "VALUES (%s, %s, %s, %s, now())",
            [org_id, org_id, f"Org {slug}", slug],
        )
        conn.execute(
            "INSERT INTO org_oidc_config "
            "(id, org_id, issuer, client_id, created_at) "
            "VALUES (%s, %s, %s, %s, now())",
            [uuid.uuid4(), org_id, "https://idp.example.com", "test-client-id"],
        )
        conn.commit()
    return org_id


def _seed_user(owner_url: str, org_id: uuid.UUID, *,
               email: str = "user@example.com") -> uuid.UUID:
    """Seed a user; return user_id."""
    user_id = uuid.uuid4()
    sub = f"user-{uuid.uuid4().hex[:12]}"
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        conn.execute(
            "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, "
            "email, status, created_at) "
            "VALUES (%s, %s, %s, %s, %s, 'active', now())",
            [user_id, org_id, "https://idp.example.com", sub, email],
        )
        conn.commit()
    return user_id


def _seed_session(
    owner_url: str,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
) -> tuple[str, str, uuid.UUID]:
    """Insert a web_sessions row.  Returns (session_token, csrf_token, session_id)."""
    import base64
    import datetime as dt
    import hashlib
    import hmac
    import secrets

    session_token = secrets.token_urlsafe(32)
    mac = hmac.new(session_token.encode(), b"agg-csrf-v1", hashlib.sha256).digest()
    csrf_token = base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")
    token_hash = _sha256_hex(session_token)
    csrf_hash = _sha256_hex(csrf_token)
    session_id = uuid.uuid4()
    now = dt.datetime.now(dt.timezone.utc)
    expires = now + dt.timedelta(hours=12)

    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        conn.execute(
            "INSERT INTO web_sessions "
            "(id, org_id, user_id, token_hash, csrf_hash, "
            "created_at, expires_at, last_seen_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            [session_id, org_id, user_id, token_hash, csrf_hash,
             now, expires, now],
        )
        conn.commit()

    return session_token, csrf_token, session_id


def _seed_admin_binding(owner_url: str, org_id: uuid.UUID,
                        user_id: uuid.UUID) -> uuid.UUID:
    """Seed an admin role binding; return binding_id."""
    binding_id = uuid.uuid4()
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        conn.execute(
            "INSERT INTO role_bindings "
            "(id, org_id, user_id, scope_type, scope_id, role, created_at) "
            "VALUES (%s, %s, %s, 'org', %s, 'admin', now())",
            [binding_id, org_id, user_id, org_id],
        )
        conn.commit()
    return binding_id


def _seed_project(owner_url: str, org_id: uuid.UUID, *,
                  name: str = "t10-project") -> uuid.UUID:
    """Seed a project; return project_id."""
    project_id = uuid.uuid4()
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        conn.execute(
            "INSERT INTO projects (id, org_id, name, environment, created_at) "
            "VALUES (%s, %s, %s, 'dev', now())",
            [project_id, org_id, name],
        )
        conn.commit()
    return project_id


def _revoke_session(owner_url: str, org_id: uuid.UUID,
                    session_token: str) -> None:
    """Revoke a session by setting revoked_at."""
    import datetime as dt
    token_hash = _sha256_hex(session_token)
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        conn.execute(
            "UPDATE web_sessions SET revoked_at = %s WHERE token_hash = %s",
            [dt.datetime.now(dt.timezone.utc), token_hash],
        )
        conn.commit()


def _child_pids(master_pid: int) -> list[int]:
    """Return the PIDs of child processes of *master_pid* (portable)."""
    return _portable.child_pids(master_pid)


def _wait_ready(base_url: str, *, timeout: float = 30.0) -> None:
    """Poll GET /ready until 200 or timeout."""
    deadline = time.monotonic() + timeout
    last_exc = None
    while time.monotonic() < deadline:
        try:
            r = httpx.get(f"{base_url}/ready", timeout=3.0)
            if r.status_code == 200:
                return
        except Exception as exc:
            last_exc = exc
        time.sleep(0.3)
    raise TimeoutError(
        f"/ready did not return 200 within {timeout}s "
        f"(last exception: {last_exc})"
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def _multiworker_env(pg_url, app_url, owner_url, pg_roles):
    """Start uvicorn --workers 4 and yield env dict, then tear down."""
    _ensure_at_head(pg_url)

    slug = f"t10-{uuid.uuid4().hex[:8]}"
    org_id = _seed_org_with_oidc(owner_url, slug=slug)

    # Admin user
    admin_id = _seed_user(owner_url, org_id, email="admin@t10.test")
    _seed_admin_binding(owner_url, org_id, admin_id)
    admin_token, admin_csrf, admin_sid = _seed_session(owner_url, org_id, admin_id)

    # Target user for member grant tests
    target_id = _seed_user(owner_url, org_id, email="target@t10.test")

    # Project
    project_id = _seed_project(owner_url, org_id, name=f"proj-{slug}")

    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"

    # Build PYTHONPATH: ee/src (for agg_cp) + repo src (for sandbox)
    extra_paths = os.pathsep.join([
        str(_REPO / "ee" / "src"),
        str(_REPO / "src"),
    ])
    existing_pp = os.environ.get("PYTHONPATH", "")
    pythonpath = extra_paths + (os.pathsep + existing_pp if existing_pp else "")

    env = {
        **os.environ,
        "AGG_DATABASE_URL": app_url,
        "AGG_PUBLIC_URL": base_url,
        "PYTHONPATH": pythonpath,
    }

    cmd = [
        sys.executable, "-m", "uvicorn",
        "agg_cp.app:create_app",
        "--factory",
        "--workers", "4",
        "--host", "127.0.0.1",
        "--port", str(port),
    ]

    proc = subprocess.Popen(
        cmd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        # Start a new process group so we can kill the whole tree
        **_portable.popen_kwargs(),
    )
    try:
        _wait_ready(base_url, timeout=30.0)
        yield {
            "base_url": base_url,
            "master_pid": proc.pid,
            "org_id": org_id,
            "slug": slug,
            "admin_id": admin_id,
            "admin_token": admin_token,
            "admin_csrf": admin_csrf,
            "target_id": target_id,
            "project_id": project_id,
            "owner_url": owner_url,
            "app_url": app_url,
            "pg_url": pg_url,
        }
    finally:
        # Kill the entire process group (portable)
        _portable.group_terminate(proc)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _portable.group_kill(proc)
            proc.wait(timeout=5)


# ===================================================================
# Tests
# ===================================================================


@pytest.mark.pg
@pytest.mark.timeout(60)
def test_four_workers_running(_multiworker_env):
    """Prove that 4 worker processes are running under the master."""
    env = _multiworker_env
    master_pid = env["master_pid"]

    # Give workers a moment to fully start
    time.sleep(1.0)

    children = _child_pids(master_pid)
    assert len(children) >= 4, (
        f"Expected 4 worker children of master {master_pid}, "
        f"found {len(children)}: {children}"
    )


@pytest.mark.pg
@pytest.mark.timeout(60)
def test_session_works_across_all_workers(_multiworker_env):
    """Session made on one worker validates on all: 40 requests over
    fresh connections all return 200 with the same user_id."""
    env = _multiworker_env
    base_url = env["base_url"]
    org_id = env["org_id"]
    admin_token = env["admin_token"]
    admin_id = env["admin_id"]

    cookie = f"{org_id}.{admin_token}"

    statuses = []
    user_ids = []

    for _ in range(40):
        # Fresh connection (no keep-alive) by creating a new client each time
        with httpx.Client(
            timeout=10.0,
            cookies={"__Host-agg_session": cookie},
        ) as c:
            r = c.get(f"{base_url}/api/v1/me")
            statuses.append(r.status_code)
            if r.status_code == 200:
                user_ids.append(r.json()["user_id"])

    assert all(s == 200 for s in statuses), (
        f"Expected all 200, got status distribution: "
        f"{dict((s, statuses.count(s)) for s in set(statuses))}"
    )
    unique_users = set(user_ids)
    assert unique_users == {str(admin_id)}, (
        f"Expected single user_id {admin_id}, got {unique_users}"
    )


@pytest.mark.pg
@pytest.mark.timeout(60)
def test_revoked_session_401_all_workers(_multiworker_env):
    """Positive control: a revoked session returns 401 from all workers."""
    env = _multiworker_env
    base_url = env["base_url"]
    org_id = env["org_id"]
    owner_url = env["owner_url"]

    # Create a fresh session, then revoke it
    extra_user_id = _seed_user(owner_url, org_id, email="revoked@t10.test")
    revoked_token, _, _ = _seed_session(owner_url, org_id, extra_user_id)
    _revoke_session(owner_url, org_id, revoked_token)

    cookie = f"{org_id}.{revoked_token}"

    statuses = []
    for _ in range(40):
        with httpx.Client(
            timeout=10.0,
            cookies={"__Host-agg_session": cookie},
        ) as c:
            r = c.get(f"{base_url}/api/v1/me")
            statuses.append(r.status_code)

    assert all(s == 401 for s in statuses), (
        f"Expected all 401 for revoked session, got: "
        f"{dict((s, statuses.count(s)) for s in set(statuses))}"
    )


@pytest.mark.pg
@pytest.mark.timeout(60)
def test_concurrent_role_grants_idempotent(_multiworker_env):
    """20 parallel POST /projects/{id}/members with the same {user_id, role}
    over fresh connections: all 2xx, exactly one role_bindings row, exactly
    one audit row (an audit row records a change, not an attempt).
    """
    env = _multiworker_env
    base_url = env["base_url"]
    org_id = env["org_id"]
    admin_token = env["admin_token"]
    admin_csrf = env["admin_csrf"]
    target_id = env["target_id"]
    project_id = env["project_id"]
    owner_url = env["owner_url"]

    cookie = f"{org_id}.{admin_token}"
    url = f"{base_url}/api/v1/projects/{project_id}/members"

    def _grant():
        with httpx.Client(
            timeout=10.0,
            cookies={"__Host-agg_session": cookie},
            headers={"X-CSRF-Token": admin_csrf},
        ) as c:
            r = c.post(
                url,
                json={"user_id": str(target_id), "role": "viewer"},
            )
            return r.status_code, r.json().get("id")

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = [pool.submit(_grant) for _ in range(20)]
        results = [f.result(timeout=30) for f in futures]
    statuses = [st for st, _ in results]
    returned_ids = {rid for _, rid in results}

    # All should be 2xx (specifically 201)
    non_2xx = [s for s in statuses if s < 200 or s >= 300]
    assert not non_2xx, (
        f"Expected all 2xx, got non-2xx statuses: {non_2xx}. "
        f"Full: {dict((s, statuses.count(s)) for s in set(statuses))}"
    )

    # Exactly one role_bindings row
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        rows = conn.execute(
            "SELECT id FROM role_bindings "
            "WHERE scope_type = 'project' AND scope_id = %s "
            "AND user_id = %s AND role = 'viewer'",
            [project_id, target_id],
        ).fetchall()

    assert len(rows) == 1, (
        f"Expected exactly 1 role_bindings row, got {len(rows)}"
    )
    # Every response, including the 19 no-op ones, names the stored row.
    assert returned_ids == {str(rows[0][0])}, returned_ids

    # Audit: only the real insert produces a role_granted row; the 19
    # duplicate no-ops must NOT create audit entries.
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        audit_count = conn.execute(
            "SELECT count(*) FROM admin_audit "
            "WHERE org_id = %s AND action = 'role_granted' "
            "AND detail::jsonb->>'scope_type' = 'project' "
            "AND detail::jsonb->>'user_id' = %s",
            [org_id, str(target_id)],
        ).fetchone()[0]

    assert audit_count == 1, (
        f"Expected exactly 1 role_granted audit row for the target, got {audit_count}"
    )


@pytest.mark.pg
@pytest.mark.timeout(60)
def test_audit_chain_valid_after_concurrent_writes(_multiworker_env, monkeypatch):
    """After concurrent role grants, `agg_cp.cli.main(["audit","verify","--org",slug])`
    exits 0, proving the admin_audit chain is valid."""
    env = _multiworker_env
    slug = env["slug"]
    app_url = env["app_url"]

    monkeypatch.setenv("AGG_DATABASE_URL", app_url)

    from agg_cp.cli import main as cli_main
    rc = cli_main(["audit", "verify", "--org", slug])
    assert rc == 0, (
        f"audit verify --org {slug} returned {rc} (expected 0): "
        f"chain is broken after concurrent writes"
    )


# ===================================================================
# check_db_ready as agg_app (migration 0005 grants SELECT)
# ===================================================================


@pytest.mark.pg
def test_check_db_ready_as_agg_app(pg_url, app_url, pg_roles):
    """After migration 0005, check_db_ready succeeds as agg_app."""
    _ensure_at_head(pg_url)

    from agg_cp.db import check_db_ready

    ok, reason = check_db_ready(app_url)
    assert ok, f"check_db_ready should succeed as agg_app, got reason={reason!r}"


# ===================================================================
# Module-state lint: positive control that api.py, auth.py, rbac.py
# are in the scanned set
# ===================================================================

def test_module_state_lint_scans_key_files():
    """The existing module-state lint (test_t6_module_state.py) scans
    api.py, auth.py, rbac.py (positive: those files are in its scanned set)."""
    from .test_t6_module_state import EE_SRC

    assert EE_SRC.is_dir(), f"EE_SRC dir does not exist: {EE_SRC}"

    versions_dir = EE_SRC / "migrations" / "versions"
    scanned_files: set[str] = set()
    for py_file in sorted(EE_SRC.rglob("*.py")):
        try:
            py_file.relative_to(versions_dir)
            continue
        except ValueError:
            pass
        scanned_files.add(py_file.name)

    for expected in ("api.py", "auth.py", "rbac.py"):
        assert expected in scanned_files, (
            f"{expected} not in scanned set of module-state lint: "
            f"{sorted(scanned_files)}"
        )

