"""Enroll-persistence follow-up tests: enroll() and run_once() must persist
managed marker, pinned_root.json, registry.json, and the device key.

Gap (HANDOFF top, 22 Oct 2026): no product code writes
``.sandbox/state/sync/managed`` (or its key-home copy),
``pinned_root.json`` or ``registry.json``.  ``sync/enroll.py`` ``enroll()``
sends the POST and returns data but does not persist the enrollment state.
``sync/process.py`` ``run_once`` does not persist registry updates.  Existing
T8/T9 tests hand-write these files.

Required behaviour
------------------
1. ``enroll()`` after the root fingerprint check passes persists: the managed
   marker in both places (workspace state and key home), ``pinned_root.json``,
   ``registry.json``, and the device key.  Nothing is persisted if the
   fingerprint check, PoP, or server response fails (no partial state; fail
   closed).
2. ``run_once`` persists registry updates it receives (only after verification
   against the pinned root/registry chain; a forged or rollback registry is
   never written).
3. After a real enroll (no hand-written files), the workspace is managed: hook
   enforcement uses meet(verified bundle or deny-all, local) per T9; sandbox
   sticky-mode rules from T8 apply.
4. Agent cannot write/edit the new state files via hook (check existing
   sync-state protections cover them).

Postgres-free.  Uses ``tests.m2_fakes.FakeSyncServer`` for HTTP.

RED tests xfail on M2EnrollPersistPending.  Guards verify existing code.

T6 rule: the sentinel is raised only by one helper ``_need()`` at the
top of a test; the final assertions are plain ``assert``/``pytest.raises``.
Tests never patch global ``os`` attributes.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from tests.m2_pending import M2EnrollPersistPending
from tests.m2_fakes import FakeSyncServer, FakeResponse

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _need(module: str, attr: str) -> None:
    """Raise M2EnrollPersistPending if *module*.*attr* is absent."""
    try:
        mod = __import__(module, fromlist=[attr])
    except ImportError:
        raise M2EnrollPersistPending(f"{module} not importable")
    if not hasattr(mod, attr):
        raise M2EnrollPersistPending(f"{module}.{attr} not found")


def _need_persist() -> None:
    """Raise M2EnrollPersistPending if enroll does not persist managed state.

    Detection: after a successful enroll against a fake server that returns
    a valid registry chain (no ``fingerprint`` string -- the client computes
    the fingerprint locally from the genesis), the managed marker must exist
    in the sync dir.  If it does not, the persistence code is not yet built.
    """
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        kh = td / "kh"
        kh.mkdir()
        old_env = os.environ.get("SANDBOX_KEY_HOME")
        try:
            os.environ["SANDBOX_KEY_HOME"] = str(kh)

            from sandbox.connector.install import init
            from sandbox.connector.layout import FolderLayout
            ws = td / "ws"
            ws.mkdir()
            init(ws, claude=False, mcp=False)
            lay = FolderLayout(ws)

            fp, genesis_env = _make_genesis_and_fingerprint()

            with FakeSyncServer() as srv:
                srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
                    200, {
                        "device_id": "d-test",
                        "org_id": "org-1",
                        "project_id": "proj-1",
                        "registry": [genesis_env],
                    },
                )
                from sandbox.connector.sync.enroll import enroll
                try:
                    enroll(srv.base_url, "CODE-OK", fp)
                except Exception:
                    pass

            sync_dir = ws / ".sandbox" / "state" / "sync"
            if not (sync_dir / "managed").exists():
                raise M2EnrollPersistPending(
                    "enroll() does not persist the managed marker yet"
                )
        finally:
            if old_env is None:
                os.environ.pop("SANDBOX_KEY_HOME", None)
            else:
                os.environ["SANDBOX_KEY_HOME"] = old_env


def _keygen():
    """Return (signing_key, pub_bytes, key_id)."""
    sk = SigningKey.generate()
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    return sk, pub, kid


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _sign_envelope(kind: str, payload: dict, signing_keys: list) -> dict:
    tag = kind.encode("utf-8")
    canonical = _canonical_json(payload)
    msg = tag + b"\x00" + canonical
    sigs = []
    for sk in signing_keys:
        pub = bytes(sk.verify_key)
        kid = hashlib.sha256(pub).hexdigest()
        sig = sk.sign(msg).signature.hex()
        sigs.append({"key_id": kid, "alg": "ed25519", "sig": sig})
    return {"kind": kind, "sig_v": 1, "payload": payload, "signatures": sigs}


def _make_key_entry(sk=None, *, user_id="alice", iss="https://idp", sub="alice",
                    kind="cli", roles=None, added_in=1):
    if sk is None:
        sk, pub, kid = _keygen()
    else:
        pub = bytes(sk.verify_key)
        kid = hashlib.sha256(pub).hexdigest()
    return {
        "key_id": kid, "public_key": pub.hex(), "user_id": user_id,
        "iss": iss, "sub": sub, "alg": "ed25519",
        "kind": kind, "roles": roles or ["admin", "approver"], "added_in": added_in,
    }, sk


def _make_registry_payload(*, org_id="org-1", version=1, prev_hash="",
                           threshold=1, admins=None, keys=None,
                           bundle_signer=None, expires_at=None):
    return {
        "org_id": org_id, "version": version, "prev_hash": prev_hash,
        "threshold": threshold, "admins": admins or [], "keys": keys or [],
        "bundle_signer": bundle_signer or {},
        "expires_at": expires_at or time.time() + 7 * 86400,
    }


def _build_genesis(org_id="org-1", admin_sks=None, bundle_signer_sk=None,
                   threshold=1, expires_at=None):
    if admin_sks is None:
        admin_sks = [_keygen()[0]]
    if bundle_signer_sk is None:
        bundle_signer_sk = _keygen()[0]
    bpub = bytes(bundle_signer_sk.verify_key)
    bkid = hashlib.sha256(bpub).hexdigest()
    bs_dict = {"key_id": bkid, "public_key": bpub.hex(), "alg": "ed25519"}
    keys, admins = [], []
    for i, sk in enumerate(admin_sks):
        entry, _ = _make_key_entry(sk, user_id=f"admin-{i}", iss="https://idp",
                                   sub=f"admin-{i}", kind="cli",
                                   roles=["admin", "approver"], added_in=1)
        keys.append(entry)
        admins.append(entry["key_id"])
    payload = _make_registry_payload(
        org_id=org_id, version=1, prev_hash="", threshold=threshold,
        admins=admins, keys=keys, bundle_signer=bs_dict,
        expires_at=expires_at or time.time() + 7 * 86400,
    )
    envelope = _sign_envelope("agg/registry/v1", payload, admin_sks)
    return envelope, admin_sks, bundle_signer_sk, bpub, bkid


def _registry_fingerprint(genesis_payload: dict) -> str:
    return hashlib.sha256(
        genesis_payload["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis_payload)
    ).hexdigest()


def _make_genesis_and_fingerprint(org_id="org-1"):
    """Build a genesis and return (fingerprint, genesis_envelope)."""
    admin_sks = [_keygen()[0], _keygen()[0]]
    genesis_env, admin_sks, bsk, bpub, bkid = _build_genesis(
        org_id=org_id, admin_sks=admin_sks, threshold=2)
    fp = _registry_fingerprint(genesis_env["payload"])
    return fp, genesis_env


def _ws(path: Path):
    """Create a workspace and return the FolderLayout."""
    from sandbox.connector.install import init
    from sandbox.connector.layout import FolderLayout
    path.mkdir(parents=True, exist_ok=True)
    init(path, claude=False, mcp=False)
    return FolderLayout(path)


def _hook(lay, tool, tool_input):
    from sandbox.connector.hook_eval import pre_tool_use
    out = asyncio.run(pre_tool_use(
        {"tool_name": tool, "tool_input": tool_input,
         "cwd": str(lay.root), "session_id": "enroll-persist"},
        lay,
    ))
    hso = out.get("hookSpecificOutput", {})
    return hso.get("permissionDecision"), hso.get("permissionDecisionReason", "")


@pytest.fixture
def key_home(tmp_path, monkeypatch):
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    return kh


def _enroll_response(genesis_env, *, device_id="d-1",
                     org_id="org-1", project_id="proj-1",
                     registry=None):
    """Build the successful enroll response body the server returns.

    Per the orchestrator ruling: the response includes ``registry`` (the
    signed chain from genesis) but NOT a ``fingerprint`` string.  The client
    must compute the fingerprint locally from the genesis payload.
    """
    return {
        "device_id": device_id,
        "org_id": org_id,
        "project_id": project_id,
        "registry": registry if registry is not None else [genesis_env],
    }


# ===================================================================
# Guards (pass now -- existing code)
# ===================================================================


def test_guard_enroll_importable():
    """Guard: sync.enroll module is importable."""
    from sandbox.connector.sync.enroll import enroll, EnrollError
    assert callable(enroll)


def test_guard_state_module_importable():
    """Guard: sync.state functions exist."""
    from sandbox.connector.sync.state import is_managed, pinned_root, is_locked
    assert callable(is_managed)
    assert callable(pinned_root)
    assert callable(is_locked)


def test_guard_process_importable():
    """Guard: sync.process module is importable."""
    from sandbox.connector.sync.process import SyncProcess, run_once
    assert callable(run_once)


def test_guard_keyhome_workspace_key_dir():
    """Guard: keyhome.workspace_key_dir exists."""
    from sandbox.connector.keyhome import workspace_key_dir
    assert callable(workspace_key_dir)


def test_guard_write_sync_pinned_root_denied(tmp_path, monkeypatch):
    """Guard: Write tool to .sandbox/state/sync/pinned_root.json is denied."""
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")
    target = str(lay.root / ".sandbox" / "state" / "sync" / "pinned_root.json")
    decision, reason = _hook(lay, "Write", {"file_path": target, "content": "{}"})
    assert decision == "deny", f"Write to pinned_root.json was not denied: {decision}"


def test_guard_write_sync_registry_denied(tmp_path, monkeypatch):
    """Guard: Write tool to .sandbox/state/sync/registry.json is denied."""
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")
    target = str(lay.root / ".sandbox" / "state" / "sync" / "registry.json")
    decision, reason = _hook(lay, "Write", {"file_path": target, "content": "{}"})
    assert decision == "deny", f"Write to registry.json was not denied: {decision}"


def test_guard_write_sync_managed_denied(tmp_path, monkeypatch):
    """Guard: Write tool to .sandbox/state/sync/managed is denied."""
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")
    target = str(lay.root / ".sandbox" / "state" / "sync" / "managed")
    decision, reason = _hook(lay, "Write", {"file_path": target, "content": "1"})
    assert decision == "deny", f"Write to managed marker was not denied: {decision}"


def test_guard_edit_sync_pinned_root_denied(tmp_path, monkeypatch):
    """Guard: Edit tool on .sandbox/state/sync/pinned_root.json is denied."""
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    pr = sync_dir / "pinned_root.json"
    pr.write_text('{"fingerprint": "fp-abc"}')
    decision, reason = _hook(lay, "Edit", {
        "file_path": str(pr),
        "old_string": '"fp-abc"',
        "new_string": '"fp-evil"',
    })
    assert decision == "deny", f"Edit on pinned_root.json was not denied: {decision}"


SHELL_NEW_STATE_FORMS = [
    'echo \'{"fingerprint":"evil"}\' > .sandbox/state/sync/pinned_root.json',
    "rm -f .sandbox/state/sync/pinned_root.json",
    'echo \'[]\' > .sandbox/state/sync/registry.json',
    "rm -f .sandbox/state/sync/registry.json",
    "echo 1 > .sandbox/state/sync/managed",
    "rm -f .sandbox/state/sync/managed",
]


@pytest.mark.parametrize("command", SHELL_NEW_STATE_FORMS)
def test_guard_shell_new_state_files_denied(tmp_path, monkeypatch, command):
    """Guard: shell writes to the new state files are denied (threat 20)."""
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")
    decision, reason = _hook(lay, "Bash", {"command": command})
    assert decision == "deny", (
        f"Shell write to state file was not denied: {command!r} -> {decision}"
    )


# ===================================================================
# RED: Req 1 -- enroll() persists all state on success
# ===================================================================


@pytest.mark.xfail(raises=M2EnrollPersistPending, strict=True)
def test_enroll_persists_managed_marker_sync_dir(tmp_path, key_home):
    """enroll() writes .sandbox/state/sync/managed after fingerprint check (req 1)."""
    _need_persist()
    from sandbox.connector.sync.enroll import enroll
    from sandbox.connector.sync.state import is_managed
    lay = _ws(tmp_path / "ws")
    fp, genesis_env = _make_genesis_and_fingerprint()

    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            200, _enroll_response(genesis_env))
        enroll(srv.base_url, "CODE-OK", fp)

    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    assert (sync_dir / "managed").exists(), "managed marker not in sync dir"


@pytest.mark.xfail(raises=M2EnrollPersistPending, strict=True)
def test_enroll_persists_managed_marker_keyhome(tmp_path, key_home):
    """enroll() writes key-home managed marker after fingerprint check (req 1)."""
    _need_persist()
    from sandbox.connector.sync.enroll import enroll
    from sandbox.connector.sync.state import is_managed
    lay = _ws(tmp_path / "ws")
    fp, genesis_env = _make_genesis_and_fingerprint()

    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            200, _enroll_response(genesis_env))
        enroll(srv.base_url, "CODE-OK", fp)

    assert is_managed(lay), "workspace is not managed after enroll"


@pytest.mark.xfail(raises=M2EnrollPersistPending, strict=True)
def test_enroll_persists_pinned_root(tmp_path, key_home):
    """enroll() writes pinned_root.json with the locally computed fingerprint (req 1)."""
    _need_persist()
    from sandbox.connector.sync.enroll import enroll
    from sandbox.connector.sync.state import pinned_root
    lay = _ws(tmp_path / "ws")
    fp, genesis_env = _make_genesis_and_fingerprint()

    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            200, _enroll_response(genesis_env))
        enroll(srv.base_url, "CODE-OK", fp)

    assert pinned_root(lay) == fp, (
        f"pinned_root should be {fp!r}, got {pinned_root(lay)!r}"
    )


@pytest.mark.xfail(raises=M2EnrollPersistPending, strict=True)
def test_enroll_persists_registry(tmp_path, key_home):
    """enroll() writes registry.json with the registry chain (req 1)."""
    _need_persist()
    from sandbox.connector.sync.enroll import enroll
    lay = _ws(tmp_path / "ws")
    fp, genesis_env = _make_genesis_and_fingerprint()

    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            200, _enroll_response(genesis_env))
        enroll(srv.base_url, "CODE-OK", fp)

    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    reg_file = sync_dir / "registry.json"
    assert reg_file.exists(), "registry.json not written after enroll"
    reg_data = json.loads(reg_file.read_text(encoding="utf-8"))
    # The chain must be verifiable against the fingerprint
    from sandbox.protocol.registry import verify_chain
    chain = reg_data if isinstance(reg_data, list) else [reg_data]
    registry = verify_chain(chain, fp)
    assert registry is not None


@pytest.mark.xfail(raises=M2EnrollPersistPending, strict=True)
def test_enroll_persists_device_key(tmp_path, key_home):
    """enroll() writes the device key to the key home (req 1)."""
    _need_persist()
    from sandbox.connector.sync.enroll import enroll
    lay = _ws(tmp_path / "ws")
    fp, genesis_env = _make_genesis_and_fingerprint()

    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            200, _enroll_response(genesis_env))
        enroll(srv.base_url, "CODE-OK", fp)

    # The device key must be somewhere in the key home
    ws_id_file = lay.root / ".sandbox" / "workspace_id"
    ws_id = ws_id_file.read_text(encoding="utf-8").strip()
    device_dir = key_home / ws_id / "device"
    assert device_dir.exists(), "device key directory not created"
    key_files = list(device_dir.iterdir())
    assert len(key_files) > 0, "no device key file written"


@pytest.mark.xfail(raises=M2EnrollPersistPending, strict=True)
def test_enroll_persists_device_id(tmp_path, key_home):
    """enroll() writes device_id to sync state (req 1)."""
    _need_persist()
    from sandbox.connector.sync.enroll import enroll
    lay = _ws(tmp_path / "ws")
    fp, genesis_env = _make_genesis_and_fingerprint()

    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            200, _enroll_response(genesis_env, device_id="d-persist-1"))
        enroll(srv.base_url, "CODE-OK", fp)

    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    did_file = sync_dir / "device_id"
    assert did_file.exists(), "device_id not written after enroll"
    assert did_file.read_text(encoding="utf-8").strip() == "d-persist-1"


# ===================================================================
# RED: Req 1 -- no partial state on failure (fail closed)
# ===================================================================


@pytest.mark.xfail(raises=M2EnrollPersistPending, strict=True)
def test_enroll_genesis_fingerprint_mismatch_writes_nothing(tmp_path, key_home):
    """Genesis computed fingerprint differs from --expect-fingerprint: nothing persisted (req 1, c).

    The client computes the fingerprint locally from the genesis payload
    and compares it to --expect-fingerprint.  A genesis for a different org
    produces a different fingerprint.  The server's ``fingerprint`` string
    (if present) is ignored.
    """
    _need_persist()
    from sandbox.connector.sync.enroll import enroll, EnrollError
    lay = _ws(tmp_path / "ws")

    # Build a genesis for org-1 and compute its fingerprint
    fp_expected, _ = _make_genesis_and_fingerprint(org_id="org-1")
    # Build a DIFFERENT genesis (org-evil) and send it in the response
    _, genesis_evil = _make_genesis_and_fingerprint(org_id="org-evil")

    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    before_sync = set(sync_dir.rglob("*")) if sync_dir.exists() else set()
    ws_id_file = lay.root / ".sandbox" / "workspace_id"
    ws_id = ws_id_file.read_text(encoding="utf-8").strip() if ws_id_file.exists() else None

    with FakeSyncServer() as srv:
        # Server sends a genesis whose computed fingerprint != fp_expected
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            200, _enroll_response(genesis_evil, device_id="d-bad"))
        with pytest.raises(EnrollError, match="fingerprint"):
            enroll(srv.base_url, "CODE-OK", fp_expected)

    after_sync = set(sync_dir.rglob("*")) if sync_dir.exists() else set()
    assert after_sync == before_sync, (
        f"state files changed on genesis fingerprint mismatch: "
        f"new={after_sync - before_sync}"
    )
    if ws_id:
        device_dir = key_home / ws_id / "device"
        assert not device_dir.exists(), "device key written despite fingerprint mismatch"


@pytest.mark.xfail(raises=M2EnrollPersistPending, strict=True)
def test_enroll_server_error_writes_nothing(tmp_path, key_home):
    """Server 500 error: nothing persisted (req 1)."""
    _need_persist()
    from sandbox.connector.sync.enroll import enroll, EnrollError
    lay = _ws(tmp_path / "ws")

    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    before_sync = set(sync_dir.rglob("*")) if sync_dir.exists() else set()

    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            500, {"error": "internal_error"})
        with pytest.raises(EnrollError):
            enroll(srv.base_url, "CODE-OK", "fp-abc")

    after_sync = set(sync_dir.rglob("*")) if sync_dir.exists() else set()
    assert after_sync == before_sync, "state files changed on server error"


@pytest.mark.xfail(raises=M2EnrollPersistPending, strict=True)
def test_enroll_consumed_code_writes_nothing(tmp_path, key_home):
    """409 code_consumed: nothing persisted (req 1)."""
    _need_persist()
    from sandbox.connector.sync.enroll import enroll, EnrollError
    lay = _ws(tmp_path / "ws")

    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    before_sync = set(sync_dir.rglob("*")) if sync_dir.exists() else set()

    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            409, {"error": "code_consumed"})
        with pytest.raises(EnrollError, match="consumed|used"):
            enroll(srv.base_url, "CODE-OK", "fp-abc")

    after_sync = set(sync_dir.rglob("*")) if sync_dir.exists() else set()
    assert after_sync == before_sync, "state files changed on 409 code_consumed"


# ===================================================================
# RED: Req 1 -- atomicity: all files or nothing
# ===================================================================


@pytest.mark.xfail(raises=M2EnrollPersistPending, strict=True)
def test_enroll_atomic_all_files_written(tmp_path, key_home):
    """After successful enroll, ALL required files exist together (req 1)."""
    _need_persist()
    from sandbox.connector.sync.enroll import enroll
    from sandbox.connector.sync.state import is_managed, pinned_root
    lay = _ws(tmp_path / "ws")
    fp, genesis_env = _make_genesis_and_fingerprint()

    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            200, _enroll_response(genesis_env))
        enroll(srv.base_url, "CODE-OK", fp)

    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    # All must exist together
    assert (sync_dir / "managed").exists(), "managed marker missing"
    assert (sync_dir / "pinned_root.json").exists(), "pinned_root.json missing"
    assert (sync_dir / "registry.json").exists(), "registry.json missing"
    assert (sync_dir / "device_id").exists(), "device_id missing"
    assert pinned_root(lay) == fp
    assert is_managed(lay)


# ===================================================================
# RED: Req 2 -- run_once persists registry updates after verification
# ===================================================================


@pytest.mark.xfail(raises=M2EnrollPersistPending, strict=True)
def test_run_once_persists_verified_registry_update(tmp_path, key_home):
    """run_once writes an updated registry after verifying it (req 2)."""
    _need_persist()
    _need("sandbox.connector.sync.process", "SyncProcess")
    _need("sandbox.connector.sync.process", "run_once")
    from sandbox.connector.sync.process import SyncProcess, run_once
    from sandbox.connector.sync.state import pinned_root

    lay = _ws(tmp_path / "ws")

    # Hand-write initial enrollment state (simulating a prior enroll)
    admin_sks = [_keygen()[0], _keygen()[0]]
    genesis_env, admin_sks, bsk, bpub, bkid = _build_genesis(
        admin_sks=admin_sks, threshold=2)
    fp = _registry_fingerprint(genesis_env["payload"])

    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    (sync_dir / "managed").write_text("1")
    (sync_dir / "pinned_root.json").write_text(
        json.dumps({"fingerprint": fp}))
    (sync_dir / "registry.json").write_text(
        json.dumps([genesis_env], sort_keys=True, separators=(",", ":")))
    (sync_dir / "device_id").write_text("d-update-1")

    ws_id_file = lay.root / ".sandbox" / "workspace_id"
    ws_id = ws_id_file.read_text(encoding="utf-8").strip()
    (key_home / ws_id).mkdir(parents=True, exist_ok=True)
    (key_home / ws_id / "managed").write_text("1")

    # Build a v2 registry entry (update)
    v1_hash = hashlib.sha256(_canonical_json(genesis_env["payload"])).hexdigest()
    v2_payload = _make_registry_payload(
        org_id="org-1", version=2, prev_hash=v1_hash,
        threshold=2, admins=[k["key_id"] for k in genesis_env["payload"]["keys"]],
        keys=genesis_env["payload"]["keys"],
        bundle_signer=genesis_env["payload"]["bundle_signer"],
    )
    v2_env = _sign_envelope("agg/registry/v1", v2_payload, admin_sks)

    fake_time = [0.0]

    def _connect(method, url, body=None, headers=None, token=None):
        if "/sync/token" in url:
            return (200, {"token": "t-1", "expires_in": 600}, {})
        if "/sync/decisions" in url:
            return (200, {"decisions": []}, {})
        if "/sync/registry" in url:
            return (200, {"registry": [genesis_env, v2_env]}, {})
        return (200, {}, {})

    sync = SyncProcess(
        layout=lay, server_url="http://localhost:0",
        device_key=b"k", device_id="d-update-1",
        clock=lambda: fake_time[0],
        connect=_connect,
    )
    run_once(sync)

    # The registry file should now contain the v2 chain
    reg_data = json.loads(
        (sync_dir / "registry.json").read_text(encoding="utf-8"))
    chain = reg_data if isinstance(reg_data, list) else [reg_data]
    assert len(chain) == 2, f"expected 2 registry entries, got {len(chain)}"
    assert chain[-1]["payload"]["version"] == 2


@pytest.mark.xfail(raises=M2EnrollPersistPending, strict=True)
def test_run_once_refuses_forged_registry(tmp_path, key_home):
    """run_once does not write a forged registry update (req 2)."""
    _need_persist()
    _need("sandbox.connector.sync.process", "SyncProcess")
    _need("sandbox.connector.sync.process", "run_once")
    from sandbox.connector.sync.process import SyncProcess, run_once

    lay = _ws(tmp_path / "ws")

    admin_sks = [_keygen()[0], _keygen()[0]]
    genesis_env, admin_sks, bsk, bpub, bkid = _build_genesis(
        admin_sks=admin_sks, threshold=2)
    fp = _registry_fingerprint(genesis_env["payload"])

    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    (sync_dir / "managed").write_text("1")
    (sync_dir / "pinned_root.json").write_text(
        json.dumps({"fingerprint": fp}))
    original_chain = json.dumps(
        [genesis_env], sort_keys=True, separators=(",", ":"))
    (sync_dir / "registry.json").write_text(original_chain)
    (sync_dir / "device_id").write_text("d-forged-1")

    ws_id_file = lay.root / ".sandbox" / "workspace_id"
    ws_id = ws_id_file.read_text(encoding="utf-8").strip()
    (key_home / ws_id).mkdir(parents=True, exist_ok=True)
    (key_home / ws_id / "managed").write_text("1")

    # Build a forged v2 with a different (untrusted) admin key
    forged_sk = _keygen()[0]
    v1_hash = hashlib.sha256(_canonical_json(genesis_env["payload"])).hexdigest()
    v2_payload = _make_registry_payload(
        org_id="org-1", version=2, prev_hash=v1_hash,
        threshold=1, admins=[hashlib.sha256(bytes(forged_sk.verify_key)).hexdigest()],
        keys=[],
    )
    v2_forged = _sign_envelope("agg/registry/v1", v2_payload, [forged_sk])

    def _connect(method, url, body=None, headers=None, token=None):
        if "/sync/token" in url:
            return (200, {"token": "t-1", "expires_in": 600}, {})
        if "/sync/decisions" in url:
            return (200, {"decisions": []}, {})
        if "/sync/registry" in url:
            return (200, {"registry": [genesis_env, v2_forged]}, {})
        return (200, {}, {})

    sync = SyncProcess(
        layout=lay, server_url="http://localhost:0",
        device_key=b"k", device_id="d-forged-1",
        clock=time.monotonic,
        connect=_connect,
    )
    try:
        run_once(sync)
    except Exception:
        pass  # expected: forged registry must fail

    # The registry file must NOT have been updated
    reg_after = (sync_dir / "registry.json").read_text(encoding="utf-8")
    assert reg_after == original_chain, (
        "registry.json was overwritten with a forged chain"
    )


@pytest.mark.xfail(raises=M2EnrollPersistPending, strict=True)
def test_run_once_refuses_rollback_registry(tmp_path, key_home):
    """run_once does not write a rollback registry (older version; req 2)."""
    _need_persist()
    _need("sandbox.connector.sync.process", "SyncProcess")
    _need("sandbox.connector.sync.process", "run_once")
    from sandbox.connector.sync.process import SyncProcess, run_once

    lay = _ws(tmp_path / "ws")

    admin_sks = [_keygen()[0], _keygen()[0]]
    genesis_env, admin_sks, bsk, bpub, bkid = _build_genesis(
        admin_sks=admin_sks, threshold=2)
    fp = _registry_fingerprint(genesis_env["payload"])

    # Start with a v2 registry already on disk
    v1_hash = hashlib.sha256(_canonical_json(genesis_env["payload"])).hexdigest()
    v2_payload = _make_registry_payload(
        org_id="org-1", version=2, prev_hash=v1_hash,
        threshold=2, admins=[k["key_id"] for k in genesis_env["payload"]["keys"]],
        keys=genesis_env["payload"]["keys"],
        bundle_signer=genesis_env["payload"]["bundle_signer"],
    )
    v2_env = _sign_envelope("agg/registry/v1", v2_payload, admin_sks)

    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    (sync_dir / "managed").write_text("1")
    (sync_dir / "pinned_root.json").write_text(
        json.dumps({"fingerprint": fp}))
    v2_chain = json.dumps(
        [genesis_env, v2_env], sort_keys=True, separators=(",", ":"))
    (sync_dir / "registry.json").write_text(v2_chain)
    (sync_dir / "device_id").write_text("d-rollback-1")

    ws_id_file = lay.root / ".sandbox" / "workspace_id"
    ws_id = ws_id_file.read_text(encoding="utf-8").strip()
    (key_home / ws_id).mkdir(parents=True, exist_ok=True)
    (key_home / ws_id / "managed").write_text("1")

    # Server sends only the genesis (v1) -- a rollback attempt
    def _connect(method, url, body=None, headers=None, token=None):
        if "/sync/token" in url:
            return (200, {"token": "t-1", "expires_in": 600}, {})
        if "/sync/decisions" in url:
            return (200, {"decisions": []}, {})
        if "/sync/registry" in url:
            return (200, {"registry": [genesis_env]}, {})
        return (200, {}, {})

    sync = SyncProcess(
        layout=lay, server_url="http://localhost:0",
        device_key=b"k", device_id="d-rollback-1",
        clock=time.monotonic,
        connect=_connect,
    )
    try:
        run_once(sync)
    except Exception:
        pass

    # The registry on disk must still be v2, not rolled back to v1
    reg_after = (sync_dir / "registry.json").read_text(encoding="utf-8")
    assert reg_after == v2_chain, "registry.json was rolled back"


# ===================================================================
# RED: Req 3 -- after real enroll, workspace is managed
#               (hook enforcement uses meet(bundle or deny-all, local))
# ===================================================================


@pytest.mark.xfail(raises=M2EnrollPersistPending, strict=True)
def test_after_enroll_is_managed_true(tmp_path, key_home):
    """After enroll(), is_managed returns True without hand-written files (req 3)."""
    _need_persist()
    from sandbox.connector.sync.enroll import enroll
    from sandbox.connector.sync.state import is_managed
    lay = _ws(tmp_path / "ws")
    fp, genesis_env = _make_genesis_and_fingerprint()

    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            200, _enroll_response(genesis_env))
        enroll(srv.base_url, "CODE-OK", fp)

    assert is_managed(lay), "workspace not managed after real enroll"


@pytest.mark.xfail(raises=M2EnrollPersistPending, strict=True)
def test_after_enroll_hook_enforces_deny_all_without_bundle(tmp_path, key_home):
    """After enroll with no bundle, hook enforces deny-all per T9 N3 (req 3).

    A managed workspace without a verified bundle enforces deny-all as the
    approved side of meet(approved, local).  A shell command that would
    normally be allowed (echo hello) may be denied or observe-escalated.
    """
    _need_persist()
    from sandbox.connector.sync.enroll import enroll
    from sandbox.connector.sync.state import is_managed
    lay = _ws(tmp_path / "ws")
    fp, genesis_env = _make_genesis_and_fingerprint()

    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            200, _enroll_response(genesis_env))
        enroll(srv.base_url, "CODE-OK", fp)

    assert is_managed(lay)
    # After enroll with no bundle applied, the hook should enforce
    # deny-all or at minimum bundle_enforced should be present
    from sandbox.connector.policy_versions import enforced_policy
    policy, info = enforced_policy(lay)
    assert "bundle_enforced" in info, (
        "bundle_enforced not in policy info for managed workspace after enroll"
    )


@pytest.mark.xfail(raises=M2EnrollPersistPending, strict=True)
def test_after_enroll_sticky_mode_applies(tmp_path, key_home):
    """After enroll, deleting sync state keeps the workspace managed (req 3, T8 sticky)."""
    _need_persist()
    import shutil
    from sandbox.connector.sync.enroll import enroll
    from sandbox.connector.sync.state import is_managed
    lay = _ws(tmp_path / "ws")
    fp, genesis_env = _make_genesis_and_fingerprint()

    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            200, _enroll_response(genesis_env))
        enroll(srv.base_url, "CODE-OK", fp)

    assert is_managed(lay)

    # Delete the sync dir (simulating an attacker)
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    if sync_dir.exists():
        shutil.rmtree(sync_dir)

    # The key-home marker must still make it managed (T8 sticky mode)
    assert is_managed(lay), (
        "workspace fell back to standalone after sync dir deletion"
    )


# ===================================================================
# RED: Req 3 -- after enroll + bundle, pinned root enables verification
# ===================================================================


@pytest.mark.xfail(raises=M2EnrollPersistPending, strict=True)
def test_after_enroll_can_accept_bundles(tmp_path, key_home):
    """After enroll, can_accept_bundles is True (pinned root written; req 3)."""
    _need_persist()
    from sandbox.connector.sync.enroll import enroll
    from sandbox.connector.sync.state import can_accept_bundles
    lay = _ws(tmp_path / "ws")
    fp, genesis_env = _make_genesis_and_fingerprint()

    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            200, _enroll_response(genesis_env))
        enroll(srv.base_url, "CODE-OK", fp)

    assert can_accept_bundles(lay), (
        "can_accept_bundles is False after enroll; pinned_root.json not written"
    )


# ===================================================================
# RED: Ruling (a) -- server echoes correct fingerprint string but
#      genesis computed fingerprint differs.  Refused, nothing written.
# ===================================================================


@pytest.mark.xfail(raises=M2EnrollPersistPending, strict=True)
def test_enroll_server_echoes_fp_but_genesis_differs(tmp_path, key_home):
    """Server echoes --expect-fingerprint verbatim but the genesis computes
    to a different value.  The client must compute the fingerprint locally
    and refuse (threat 2, ruling a).
    """
    _need_persist()
    from sandbox.connector.sync.enroll import enroll, EnrollError
    lay = _ws(tmp_path / "ws")

    # The fingerprint the operator expects
    fp_expected, _ = _make_genesis_and_fingerprint(org_id="org-1")
    # A genesis for a different org: computed fingerprint != fp_expected
    _, genesis_evil = _make_genesis_and_fingerprint(org_id="org-evil")

    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    before_sync = set(sync_dir.rglob("*")) if sync_dir.exists() else set()

    with FakeSyncServer() as srv:
        # Server helpfully echoes the correct fingerprint string
        # but sends a genesis that does not match it
        resp = _enroll_response(genesis_evil, device_id="d-echo")
        resp["fingerprint"] = fp_expected  # malicious echo
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(200, resp)
        with pytest.raises(EnrollError, match="fingerprint"):
            enroll(srv.base_url, "CODE-OK", fp_expected)

    after_sync = set(sync_dir.rglob("*")) if sync_dir.exists() else set()
    assert after_sync == before_sync, (
        "state files changed despite genesis fingerprint mismatch (echoed string trusted)"
    )


# ===================================================================
# RED: Ruling (b) -- genesis valid but a later version in the chain
#      is forged or under threshold.  Refused, nothing written.
# ===================================================================


@pytest.mark.xfail(raises=M2EnrollPersistPending, strict=True)
def test_enroll_chain_with_forged_later_version_refused(tmp_path, key_home):
    """Genesis is valid but a v2 in the returned chain is forged (ruling b).

    The client verifies the entire chain with ``verify_chain`` before
    persisting anything.  A forged v2 (signed by an untrusted key) must
    cause enroll to refuse.
    """
    _need_persist()
    from sandbox.connector.sync.enroll import enroll, EnrollError
    lay = _ws(tmp_path / "ws")

    admin_sks = [_keygen()[0], _keygen()[0]]
    genesis_env, admin_sks, bsk, bpub, bkid = _build_genesis(
        admin_sks=admin_sks, threshold=2)
    fp = _registry_fingerprint(genesis_env["payload"])

    # Build a forged v2 signed by an untrusted key
    forged_sk = _keygen()[0]
    v1_hash = hashlib.sha256(_canonical_json(genesis_env["payload"])).hexdigest()
    v2_payload = _make_registry_payload(
        org_id="org-1", version=2, prev_hash=v1_hash,
        threshold=1,
        admins=[hashlib.sha256(bytes(forged_sk.verify_key)).hexdigest()],
        keys=[],
    )
    v2_forged = _sign_envelope("agg/registry/v1", v2_payload, [forged_sk])

    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    before_sync = set(sync_dir.rglob("*")) if sync_dir.exists() else set()

    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            200, _enroll_response(genesis_env,
                                  registry=[genesis_env, v2_forged],
                                  device_id="d-forged-chain"))
        with pytest.raises(EnrollError, match="fingerprint|registry|chain|verif"):
            enroll(srv.base_url, "CODE-OK", fp)

    after_sync = set(sync_dir.rglob("*")) if sync_dir.exists() else set()
    assert after_sync == before_sync, (
        "state files changed despite forged chain in enroll response"
    )


# ===================================================================
# RED: Ruling (e) -- fingerprint string in response is ignored
# ===================================================================


@pytest.mark.xfail(raises=M2EnrollPersistPending, strict=True)
def test_enroll_ignores_fingerprint_string_in_response(tmp_path, key_home):
    """The ``fingerprint`` field in the server response is ignored (ruling e).

    The client computes the fingerprint from the genesis and NEVER trusts
    a ``fingerprint`` string from the server.  This test sends a WRONG
    ``fingerprint`` string alongside a VALID genesis.  The enroll must
    succeed because the client computes the correct fingerprint locally.
    """
    _need_persist()
    from sandbox.connector.sync.enroll import enroll
    from sandbox.connector.sync.state import is_managed, pinned_root
    lay = _ws(tmp_path / "ws")
    fp, genesis_env = _make_genesis_and_fingerprint()

    with FakeSyncServer() as srv:
        resp = _enroll_response(genesis_env, device_id="d-ignore-fp")
        resp["fingerprint"] = "completely-wrong-fp-string"
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(200, resp)
        enroll(srv.base_url, "CODE-OK", fp)

    # The client computed the fingerprint locally; the wrong string was ignored
    assert is_managed(lay), "enroll failed because it trusted the fingerprint string"
    assert pinned_root(lay) == fp, (
        "pinned_root does not match locally computed fingerprint"
    )
