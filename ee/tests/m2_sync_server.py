"""Shared 4-worker agg_cp server helpers for M2 ee tests.

Extracted from ``test_m2_t7_signer.py`` so that T7 and T8 (and later
T9-T12) can reuse the same ``sync_server`` fixture without duplicating
the startup/teardown logic.

Usage in a test module::

    from .m2_sync_server import make_sync_server

    @pytest.fixture(scope="module")
    def enroll_server(pg_url, app_url, owner_url, pg_roles):
        yield from make_sync_server(pg_url, app_url, owner_url,
                                    org_names=["Enroll Org"])
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx
import psycopg

from . import _portable

_REPO = Path(__file__).resolve().parent.parent.parent


def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_ready(base_url: str, *, timeout: float = 30.0) -> None:
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


def ensure_at_head(pg_url: str) -> None:
    """Run Alembic upgrade to head."""
    from agg_cp.db import alembic_config
    from alembic.command import upgrade
    cfg = alembic_config(pg_url)
    upgrade(cfg, "head")


def create_org(conn, org_id: str, name: str = "Test Org") -> None:
    slug = org_id[:32].replace("-", "")
    conn.execute(
        "INSERT INTO orgs (id, org_id, name, slug, created_at) "
        "VALUES (%s, %s, %s, %s, now()) ON CONFLICT DO NOTHING",
        [org_id, org_id, name, slug],
    )


def create_project(conn, org_id: str, project_id: str,
                   name: str = "Test Project",
                   environment: str = "staging") -> None:
    conn.execute(
        "INSERT INTO projects (id, org_id, name, environment, created_at) "
        "VALUES (%s, %s, %s, %s, now()) ON CONFLICT DO NOTHING",
        [project_id, org_id, name, environment],
    )


def canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign_envelope(kind: str, payload: dict, sk) -> dict:
    """Sign an agg protocol envelope."""
    tag = kind.encode("utf-8")
    canonical = canonical_json(payload)
    msg = tag + b"\x00" + canonical
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    sig = sk.sign(msg).signature.hex()
    return {
        "kind": kind,
        "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": kid, "alg": "ed25519", "sig": sig}],
    }


def keygen():
    """Return (signing_key, pub_bytes, key_id)."""
    from nacl.signing import SigningKey
    sk = SigningKey.generate()
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    return sk, pub, kid


def make_sync_server(pg_url: str, app_url: str, owner_url: str,
                     *, org_names: list[str] | None = None,
                     extra_orgs: int = 0):
    """Generator that starts a 4-worker agg_cp server and yields info.

    Use as ``yield from make_sync_server(...)`` in a module-scoped fixture.
    """
    ensure_at_head(pg_url)

    org_ids = []
    names = org_names or ["Test Org"]
    for n in names:
        oid = str(uuid.uuid4())
        org_ids.append(oid)
        with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)", [oid])
            create_org(conn, oid, n)

    for _ in range(extra_orgs):
        oid = str(uuid.uuid4())
        org_ids.append(oid)
        with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)", [oid])
            create_org(conn, oid, f"Extra Org {oid[:8]}")

    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"

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
        cmd, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        **_portable.popen_kwargs(),
    )
    try:
        _wait_ready(base_url, timeout=30.0)
        info = {
            "base_url": base_url,
            "org_ids": org_ids,
            "org_id": org_ids[0],
            "owner_url": owner_url,
            "app_url": app_url,
            "pg_url": pg_url,
        }
        if len(org_ids) > 1:
            info["org_evil"] = org_ids[1]
        yield info
    finally:
        _portable.group_terminate(proc)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _portable.group_kill(proc)
            proc.wait(timeout=5)
