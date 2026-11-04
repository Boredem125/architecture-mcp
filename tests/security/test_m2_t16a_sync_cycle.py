"""T16a tests-first: one sync cycle in connector/sync/process.py.

Spec (T12B_PLAN.md "T16 triage", T16a row; ADR 0001 A1):

  - A served bundle with 2 valid CLI change approvals is applied in one
    ``run_once`` cycle through the pull path.
  - The 6 gate negatives are refused through the pull path, each audited
    as ``bundle_refused`` plus an alert, never applied.
  - ``sandbox sync --once`` uploads audit with checkpoint, writes
    ``server_time_state.json``, and applies decisions with the
    ``sync_decision_applied`` audit event.
  - Default ``sandbox sync`` loops and exits cleanly on KeyboardInterrupt.
  - A server error never auto-approves.
  - The CLI module no longer has its own ``run_once`` (wrapper only).
  - ADR 0001 A1 item 2: two bundles queued, two cycles apply both in order.

All tests are strict xfail (raises=M2T16Pending).  The sentinel fires at
the top of each test via ``_need()``.  The final assertions are plain
``assert`` / ``pytest.raises`` (T6 rule).

Postgres-free.  Uses ``tests.m2_fakes.FakeSyncServer`` for HTTP.  Reuses
helpers from ``tests.security.test_m2_t12_remote``.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import time
from pathlib import Path

import pytest

from tests.m2_pending import M2T16Pending
from tests.m2_fakes import FakeSyncServer, FakeResponse
from tests.security.test_m2_t12_remote import (
    _keygen,
    _sign_envelope,
    _setup_managed_workspace,
    _make_remote_approval,
    _create_pending_request,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _need_fetch_bundle() -> None:
    """Raise M2T16Pending if process.py has no _fetch_bundle."""
    try:
        import sandbox.connector.sync.process as proc
    except ImportError:
        raise M2T16Pending("sandbox.connector.sync.process not importable")
    if not hasattr(proc, "_fetch_bundle"):
        raise M2T16Pending("process.py has no _fetch_bundle step")


def _need_run_loop() -> None:
    """Raise M2T16Pending if process.py has no run_loop."""
    try:
        import sandbox.connector.sync.process as proc
    except ImportError:
        raise M2T16Pending("sandbox.connector.sync.process not importable")
    if not hasattr(proc, "run_loop"):
        raise M2T16Pending("process.py has no run_loop")


def _need_cli_delegates() -> None:
    """Raise M2T16Pending if the CLI sync still has its own apply_external cycle."""
    import sandbox.cli.sync_cmds as scm
    if hasattr(scm, "run_once"):
        src = inspect.getsource(scm.run_once)
        # Check for an actual call, not just a comment mentioning the name
        for line in src.splitlines():
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if "apply_external" in stripped:
                raise M2T16Pending(
                    "sync_cmds.run_once still calls apply_external; "
                    "should delegate to SyncProcess"
                )


def _make_change_approval(sk, bundle_payload: dict) -> dict:
    """Build and sign an agg/policy-change/v1 envelope over the bundle hash."""
    canonical = json.dumps(
        bundle_payload, sort_keys=True, separators=(",", ":")
    ).encode()
    bh = hashlib.sha256(canonical).hexdigest()
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    payload = {
        "bundle_hash": bh,
        "key_id": kid,
        "approved_at": time.time(),
    }
    return _sign_envelope("agg/policy-change/v1", payload, sk)


def _build_valid_bundle_and_approvals(
    bundle_signer_sk, admin_sks, *,
    org_id="org-1", project_id="proj-1",
    sequence=2, base_sequence=1,
    environment="staging",
):
    """Build a signed bundle envelope plus 2 CLI change approvals.

    Returns (envelope, change_approvals, bundle_payload).
    """
    bundle_payload = {
        "org_id": org_id,
        "project_id": project_id,
        "sequence": sequence,
        "base_sequence": base_sequence,
        "registry_version": 1,
        "environment": environment,
        "folder_policy": {},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {
            "local_fallback": False,
            "allow_requester": False,
        },
        "change_approvals": [],
        "issued_at": time.time(),
        "not_before": time.time() - 60,
        "expires_at": time.time() + 86400,
    }
    envelope = _sign_envelope("agg/bundle/v1", bundle_payload, bundle_signer_sk[0])
    approvals = [
        _make_change_approval(admin_sks[0][0], bundle_payload),
        _make_change_approval(admin_sks[1][0], bundle_payload),
    ]
    return envelope, approvals, bundle_payload


def _make_fake_connect(routes_dict):
    """Build a connect callable from routes_dict.

    Keys: (method, path_prefix).  Values: (status, body_dict, headers) or
    callable(method, url, body, headers, token) -> tuple.
    """
    call_log = []

    def connect(method, url, body=None, headers=None, token=None):
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path
        call_log.append({"method": method, "path": path, "url": url})
        for (m, p), resp in routes_dict.items():
            if m == method and path.startswith(p):
                if callable(resp):
                    return resp(method, url, body, headers, token)
                return resp
        return (404, {"error": "not found"}, {})

    return connect, call_log


# ===================================================================
# T16a-1: bundle applied in one run_once cycle through the pull path
# ===================================================================


def test_bundle_applied_in_one_run_once_cycle(tmp_path, monkeypatch):
    """A served bundle with 2 valid CLI change approvals is applied
    in one run_once cycle through the pull path."""
    _need_fetch_bundle()

    from sandbox.connector.sync.process import SyncProcess, run_once
    from sandbox.connector.sync.state import current_sequence

    admin1, admin2, bsigner = _keygen(), _keygen(), _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch, admin_sks=[admin1, admin2],
        bundle_signer_sk=bsigner, policy_sequence=1,
    )
    lay = ctx["lay"]
    envelope, approvals, _ = _build_valid_bundle_and_approvals(
        bsigner, [admin1, admin2], sequence=2, base_sequence=1,
    )
    routes = {
        ("POST", "/api/v1/sync/token"): (200, {"token": "t", "expires_in": 600}, {"Date": "Mon, 02 Nov 2026 12:00:00 GMT"}),
        ("GET", "/api/v1/sync/bundle"): (200, {"envelope": envelope, "change_approvals": approvals}, {}),
        ("GET", "/api/v1/sync/decisions"): (200, {"decisions": []}, {}),
        ("GET", "/api/v1/sync/registry"): (200, {}, {}),
        ("POST", "/api/v1/sync/escalations"): (200, {}, {}),
    }
    connect, log = _make_fake_connect(routes)
    sync = SyncProcess(lay, "http://127.0.0.1:9999", b"\x00" * 32, "dev-1",
                       connect=connect)
    run_once(sync)
    assert current_sequence(lay) == 2
    bundle_calls = [c for c in log if "/sync/bundle" in c["path"]]
    assert len(bundle_calls) >= 1
    assert "after=" in bundle_calls[0]["url"]


def test_two_bundles_queued_applied_in_order(tmp_path, monkeypatch):
    """Two bundles queued; two run_once cycles apply both in sequence order.

    ADR 0001 A1 item 2: lowest sequence > after, not the newest.
    """
    _need_fetch_bundle()

    from sandbox.connector.sync.process import SyncProcess, run_once
    from sandbox.connector.sync.state import current_sequence

    admin1, admin2, bsigner = _keygen(), _keygen(), _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch, admin_sks=[admin1, admin2],
        bundle_signer_sk=bsigner, policy_sequence=1,
    )
    lay = ctx["lay"]
    env2, appr2, _ = _build_valid_bundle_and_approvals(
        bsigner, [admin1, admin2], sequence=2, base_sequence=1,
    )
    env3, appr3, _ = _build_valid_bundle_and_approvals(
        bsigner, [admin1, admin2], sequence=3, base_sequence=2,
    )

    def bundle_handler(method, url, body, headers, token):
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(url).query)
        after = int(qs.get("after", ["0"])[0])
        if after < 2:
            return (200, {"envelope": env2, "change_approvals": appr2}, {})
        if after < 3:
            return (200, {"envelope": env3, "change_approvals": appr3}, {})
        return (204, {}, {})

    routes = {
        ("POST", "/api/v1/sync/token"): (200, {"token": "t", "expires_in": 600}, {}),
        ("GET", "/api/v1/sync/bundle"): bundle_handler,
        ("GET", "/api/v1/sync/decisions"): (200, {"decisions": []}, {}),
        ("GET", "/api/v1/sync/registry"): (200, {}, {}),
        ("POST", "/api/v1/sync/escalations"): (200, {}, {}),
    }
    connect, log = _make_fake_connect(routes)
    sync = SyncProcess(lay, "http://127.0.0.1:9999", b"\x00" * 32, "dev-1",
                       connect=connect)
    run_once(sync)
    assert current_sequence(lay) == 2
    run_once(sync)
    assert current_sequence(lay) == 3
    bundle_calls = [c for c in log if "/sync/bundle" in c["path"]]
    assert len(bundle_calls) >= 2
    assert "after=1" in bundle_calls[0]["url"]
    assert "after=2" in bundle_calls[1]["url"]


def test_bundle_204_nothing_applied(tmp_path, monkeypatch):
    """GET /sync/bundle returning 204 applies nothing."""
    _need_fetch_bundle()

    from sandbox.connector.sync.process import SyncProcess, run_once
    from sandbox.connector.sync.state import current_sequence

    ctx = _setup_managed_workspace(tmp_path, monkeypatch, policy_sequence=1)
    lay = ctx["lay"]
    routes = {
        ("POST", "/api/v1/sync/token"): (200, {"token": "t", "expires_in": 600}, {}),
        ("GET", "/api/v1/sync/bundle"): (204, {}, {}),
        ("GET", "/api/v1/sync/decisions"): (200, {"decisions": []}, {}),
        ("GET", "/api/v1/sync/registry"): (200, {}, {}),
        ("POST", "/api/v1/sync/escalations"): (200, {}, {}),
    }
    connect, _ = _make_fake_connect(routes)
    sync = SyncProcess(lay, "http://127.0.0.1:9999", b"\x00" * 32, "dev-1",
                       connect=connect)
    run_once(sync)
    assert current_sequence(lay) == 1


# ===================================================================
# T16a-2: the 6 gate negatives refused through the pull path
# ===================================================================


def test_byteflipped_bundle_refused_and_audited(tmp_path, monkeypatch):
    """A byte-flipped bundle is refused via the pull path and audited
    as bundle_refused with an alert."""
    _need_fetch_bundle()

    from sandbox.connector.sync.process import SyncProcess, run_once
    from sandbox.connector.sync.state import current_sequence

    admin1, admin2, bsigner = _keygen(), _keygen(), _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch, admin_sks=[admin1, admin2],
        bundle_signer_sk=bsigner, policy_sequence=1,
    )
    lay = ctx["lay"]
    envelope, approvals, _ = _build_valid_bundle_and_approvals(
        bsigner, [admin1, admin2], sequence=2, base_sequence=1,
    )
    bad_env = json.loads(json.dumps(envelope))
    sig = bad_env["signatures"][0]["sig"]
    # XOR bit 0 of byte 0: guaranteed to change the bytes (a fixed "ff"
    # splice is a no-op when the random signature already has "ff" there).
    sig_bytes = bytearray(bytes.fromhex(sig))
    sig_bytes[0] ^= 0x01
    bad_env["signatures"][0]["sig"] = sig_bytes.hex()
    assert bad_env["signatures"][0]["sig"] != sig
    assert len(bad_env["signatures"][0]["sig"]) == len(sig)

    routes = {
        ("POST", "/api/v1/sync/token"): (200, {"token": "t", "expires_in": 600}, {}),
        ("GET", "/api/v1/sync/bundle"): (200, {"envelope": bad_env, "change_approvals": approvals}, {}),
        ("GET", "/api/v1/sync/decisions"): (200, {"decisions": []}, {}),
        ("GET", "/api/v1/sync/registry"): (200, {}, {}),
        ("POST", "/api/v1/sync/escalations"): (200, {}, {}),
    }
    connect, _ = _make_fake_connect(routes)
    sync = SyncProcess(lay, "http://127.0.0.1:9999", b"\x00" * 32, "dev-1",
                       connect=connect)
    run_once(sync)
    assert current_sequence(lay) == 1

    # "and audited": the local bundle_refused audit record must exist
    from sandbox.connector.audit import FolderAudit
    audit = FolderAudit(lay.audit_dir, session_id="sync")
    entries = audit.list_records(limit=50)
    refused = [e for e in entries if e.get("event") == "bundle_refused"]
    assert len(refused) >= 1, f"no bundle_refused audit event; events: {[e.get('event') for e in entries]}"


def test_replay_old_sequence_refused(tmp_path, monkeypatch):
    """A bundle with sequence <= current is refused."""
    _need_fetch_bundle()

    from sandbox.connector.sync.process import SyncProcess, run_once
    from sandbox.connector.sync.state import current_sequence

    admin1, admin2, bsigner = _keygen(), _keygen(), _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch, admin_sks=[admin1, admin2],
        bundle_signer_sk=bsigner, policy_sequence=1,
    )
    lay = ctx["lay"]
    envelope, approvals, _ = _build_valid_bundle_and_approvals(
        bsigner, [admin1, admin2], sequence=1, base_sequence=0,
    )
    routes = {
        ("POST", "/api/v1/sync/token"): (200, {"token": "t", "expires_in": 600}, {}),
        ("GET", "/api/v1/sync/bundle"): (200, {"envelope": envelope, "change_approvals": approvals}, {}),
        ("GET", "/api/v1/sync/decisions"): (200, {"decisions": []}, {}),
        ("GET", "/api/v1/sync/registry"): (200, {}, {}),
        ("POST", "/api/v1/sync/escalations"): (200, {}, {}),
    }
    connect, _ = _make_fake_connect(routes)
    sync = SyncProcess(lay, "http://127.0.0.1:9999", b"\x00" * 32, "dev-1",
                       connect=connect)
    run_once(sync)
    assert current_sequence(lay) == 1


def test_server_signed_loosening_no_approvals_refused(tmp_path, monkeypatch):
    """A loosening bundle with zero change approvals is refused."""
    _need_fetch_bundle()

    from sandbox.connector.sync.process import SyncProcess, run_once
    from sandbox.connector.sync.state import current_sequence

    admin1, admin2, bsigner = _keygen(), _keygen(), _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch, admin_sks=[admin1, admin2],
        bundle_signer_sk=bsigner, policy_sequence=1,
    )
    lay = ctx["lay"]
    envelope, _, _ = _build_valid_bundle_and_approvals(
        bsigner, [admin1, admin2], sequence=2, base_sequence=1,
    )
    routes = {
        ("POST", "/api/v1/sync/token"): (200, {"token": "t", "expires_in": 600}, {}),
        ("GET", "/api/v1/sync/bundle"): (200, {"envelope": envelope, "change_approvals": []}, {}),
        ("GET", "/api/v1/sync/decisions"): (200, {"decisions": []}, {}),
        ("GET", "/api/v1/sync/registry"): (200, {}, {}),
        ("POST", "/api/v1/sync/escalations"): (200, {}, {}),
    }
    connect, _ = _make_fake_connect(routes)
    sync = SyncProcess(lay, "http://127.0.0.1:9999", b"\x00" * 32, "dev-1",
                       connect=connect)
    run_once(sync)
    assert current_sequence(lay) == 1


def test_one_approval_loosening_refused(tmp_path, monkeypatch):
    """A loosening with only 1 approval (needs 2) is refused."""
    _need_fetch_bundle()

    from sandbox.connector.sync.process import SyncProcess, run_once
    from sandbox.connector.sync.state import current_sequence

    admin1, admin2, bsigner = _keygen(), _keygen(), _keygen()
    # Current bundle has local_fallback=False (default).
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch, admin_sks=[admin1, admin2],
        bundle_signer_sk=bsigner, policy_sequence=1,
    )
    lay = ctx["lay"]

    # Build a loosening bundle: local_fallback False->True triggers
    # _loosened_approval, so the change needs 2 approvals.
    loosening_payload = {
        "org_id": "org-1",
        "project_id": "proj-1",
        "sequence": 2,
        "base_sequence": 1,
        "registry_version": 1,
        "environment": "staging",
        "folder_policy": {},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {
            "local_fallback": True,   # <-- loosening
            "allow_requester": False,
        },
        "change_approvals": [],
        "issued_at": time.time(),
        "not_before": time.time() - 60,
        "expires_at": time.time() + 86400,
    }
    envelope = _sign_envelope("agg/bundle/v1", loosening_payload, bsigner[0])
    appr1 = _make_change_approval(admin1[0], loosening_payload)

    routes = {
        ("POST", "/api/v1/sync/token"): (200, {"token": "t", "expires_in": 600}, {}),
        ("GET", "/api/v1/sync/bundle"): (200, {"envelope": envelope, "change_approvals": [appr1]}, {}),
        ("GET", "/api/v1/sync/decisions"): (200, {"decisions": []}, {}),
        ("GET", "/api/v1/sync/registry"): (200, {}, {}),
        ("POST", "/api/v1/sync/escalations"): (200, {}, {}),
    }
    connect, _ = _make_fake_connect(routes)
    sync = SyncProcess(lay, "http://127.0.0.1:9999", b"\x00" * 32, "dev-1",
                       connect=connect)
    run_once(sync)
    assert current_sequence(lay) == 1


def test_project_mismatch_bundle_refused(tmp_path, monkeypatch):
    """A bundle for project-B is refused on a project-A connector."""
    _need_fetch_bundle()

    from sandbox.connector.sync.process import SyncProcess, run_once
    from sandbox.connector.sync.state import current_sequence

    admin1, admin2, bsigner = _keygen(), _keygen(), _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch, admin_sks=[admin1, admin2],
        bundle_signer_sk=bsigner, policy_sequence=1, project_id="proj-1",
    )
    lay = ctx["lay"]
    envelope, approvals, _ = _build_valid_bundle_and_approvals(
        bsigner, [admin1, admin2], sequence=2, base_sequence=1,
        project_id="proj-B",
    )
    routes = {
        ("POST", "/api/v1/sync/token"): (200, {"token": "t", "expires_in": 600}, {}),
        ("GET", "/api/v1/sync/bundle"): (200, {"envelope": envelope, "change_approvals": approvals}, {}),
        ("GET", "/api/v1/sync/decisions"): (200, {"decisions": []}, {}),
        ("GET", "/api/v1/sync/registry"): (200, {}, {}),
        ("POST", "/api/v1/sync/escalations"): (200, {}, {}),
    }
    connect, _ = _make_fake_connect(routes)
    sync = SyncProcess(lay, "http://127.0.0.1:9999", b"\x00" * 32, "dev-1",
                       connect=connect)
    run_once(sync)
    assert current_sequence(lay) == 1


def test_first_bundle_one_approval_refused(tmp_path, monkeypatch):
    """The first bundle needs 2 approvals; 1 is refused."""
    _need_fetch_bundle()

    from sandbox.connector.sync.process import SyncProcess, run_once
    from sandbox.connector.sync.state import current_sequence

    admin1, admin2, bsigner = _keygen(), _keygen(), _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch, admin_sks=[admin1, admin2],
        bundle_signer_sk=bsigner, policy_sequence=1,
    )
    lay = ctx["lay"]

    # Remove the seed bundle so last_valid_bundle returns None -> is_first=True.
    # A first bundle needs 2 approvals (deny-all base, N3).
    seed_bundle = lay.root / ".sandbox" / "state" / "sync" / "bundle.json"
    if seed_bundle.exists():
        seed_bundle.unlink()

    seq_before = current_sequence(lay)  # None (no bundle on disk)

    envelope, approvals, _ = _build_valid_bundle_and_approvals(
        bsigner, [admin1, admin2], sequence=2, base_sequence=1,
    )
    routes = {
        ("POST", "/api/v1/sync/token"): (200, {"token": "t", "expires_in": 600}, {}),
        ("GET", "/api/v1/sync/bundle"): (200, {"envelope": envelope, "change_approvals": [approvals[0]]}, {}),
        ("GET", "/api/v1/sync/decisions"): (200, {"decisions": []}, {}),
        ("GET", "/api/v1/sync/registry"): (200, {}, {}),
        ("POST", "/api/v1/sync/escalations"): (200, {}, {}),
    }
    connect, _ = _make_fake_connect(routes)
    sync = SyncProcess(lay, "http://127.0.0.1:9999", b"\x00" * 32, "dev-1",
                       connect=connect)
    run_once(sync)
    assert current_sequence(lay) == seq_before, (
        "first-bundle with only 1 approval must not advance the sequence"
    )


# ===================================================================
# T16a-3: CLI sync --once delegates to SyncProcess (audit, server_time,
#          decision apply)
# ===================================================================


def test_cli_sync_once_delegates_to_sync_process():
    """``sandbox sync --once`` should delegate to SyncProcess, not have
    its own apply_external cycle."""
    _need_cli_delegates()
    # If _need_cli_delegates did not raise, the CLI is already fixed.
    assert True


def test_sync_decision_applied_audit_event(tmp_path, monkeypatch):
    """After applying a decision through SyncProcess, a
    ``sync_decision_applied`` audit event is written."""
    _need_fetch_bundle()  # gates on the unified cycle

    from sandbox.connector.sync.process import SyncProcess, run_once
    from sandbox.connector.audit import FolderAudit

    admin1, admin2, bsigner = _keygen(), _keygen(), _keygen()
    bob_sk, bob_pub, bob_kid = _keygen()
    carol_sk, carol_pub, carol_kid = _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch, admin_sks=[admin1, admin2],
        bundle_signer_sk=bsigner,
        approver_sks=[
            (bob_sk, bob_pub, bob_kid, "user-bob", "cli"),
            (carol_sk, carol_pub, carol_kid, "user-carol", "cli"),
        ],
    )
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-d1")
    rid, fp = rec["request_id"], rec["fingerprint"]
    appr_bob = _make_remote_approval(
        bob_sk, request_id="req-d1", command="echo test",
        fingerprint=fp, user_id="user-bob",
    )
    appr_carol = _make_remote_approval(
        carol_sk, request_id="req-d1", command="echo test",
        fingerprint=fp, user_id="user-carol",
    )
    decisions_resp = [
        {"request_id": "req-d1", "signed_payload": appr_bob["payload"],
         "key_id": bob_kid, "sig": appr_bob["signatures"][0]["sig"]},
        {"request_id": "req-d1", "signed_payload": appr_carol["payload"],
         "key_id": carol_kid, "sig": appr_carol["signatures"][0]["sig"]},
    ]
    routes = {
        ("POST", "/api/v1/sync/token"): (200, {"token": "t", "expires_in": 600}, {}),
        ("GET", "/api/v1/sync/decisions"): (200, {"decisions": decisions_resp}, {}),
        ("GET", "/api/v1/sync/bundle"): (204, {}, {}),
        ("GET", "/api/v1/sync/registry"): (200, {}, {}),
        ("POST", "/api/v1/sync/escalations"): (200, {}, {}),
    }
    connect, _ = _make_fake_connect(routes)
    sync = SyncProcess(lay, "http://127.0.0.1:9999", b"\x00" * 32, "dev-1",
                       connect=connect)
    run_once(sync)
    audit = FolderAudit(lay.audit_dir, session_id="sync")
    entries = audit.list_records(limit=50)
    applied = [e for e in entries if e.get("event") == "sync_decision_applied"]
    assert len(applied) >= 1
    assert applied[0].get("request_id") == "req-d1"


# ===================================================================
# T16a-4: sandbox sync loops and exits on KeyboardInterrupt
# ===================================================================


def test_sync_loop_exits_on_keyboard_interrupt(tmp_path, monkeypatch):
    """Default ``sandbox sync`` loops and exits cleanly on KeyboardInterrupt."""
    _need_run_loop()

    from sandbox.connector.sync.process import SyncProcess, run_loop

    ctx = _setup_managed_workspace(tmp_path, monkeypatch)
    lay = ctx["lay"]
    call_count = 0

    def counting_connect(method, url, body=None, headers=None, token=None):
        nonlocal call_count
        call_count += 1
        if call_count >= 3:
            raise KeyboardInterrupt()
        return (200, {"token": "t", "expires_in": 600}, {})

    sync = SyncProcess(lay, "http://127.0.0.1:9999", b"\x00" * 32, "dev-1",
                       connect=counting_connect)
    run_loop(sync)
    assert call_count >= 2


# ===================================================================
# T16a-5: server error never auto-approves
# ===================================================================


def test_server_error_on_bundle_never_auto_approves(tmp_path, monkeypatch):
    """A 500 from GET /sync/bundle must not apply any bundle."""
    _need_fetch_bundle()

    from sandbox.connector.sync.process import SyncProcess, run_once
    from sandbox.connector.sync.state import current_sequence

    ctx = _setup_managed_workspace(tmp_path, monkeypatch, policy_sequence=1)
    lay = ctx["lay"]
    routes = {
        ("POST", "/api/v1/sync/token"): (200, {"token": "t", "expires_in": 600}, {}),
        ("GET", "/api/v1/sync/bundle"): (500, {"error": "internal"}, {}),
        ("GET", "/api/v1/sync/decisions"): (200, {"decisions": []}, {}),
        ("GET", "/api/v1/sync/registry"): (200, {}, {}),
        ("POST", "/api/v1/sync/escalations"): (200, {}, {}),
    }
    connect, _ = _make_fake_connect(routes)
    sync = SyncProcess(lay, "http://127.0.0.1:9999", b"\x00" * 32, "dev-1",
                       connect=connect)
    try:
        run_once(sync)
    except Exception:
        pass
    assert current_sequence(lay) == 1


# ===================================================================
# F1: /sync/token must reject a body without a valid device assertion;
#     missing or short device key raises ClickException (no zero seed)
# ===================================================================


def test_f1_refresh_token_sends_device_assert(tmp_path, monkeypatch):
    """_refresh_token sends a signed agg/device-assert/v1 envelope to
    POST /sync/token.  The fake rejects bodies without a valid assertion."""
    _need_fetch_bundle()

    from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
    from nacl.signing import SigningKey, VerifyKey
    from sandbox.protocol.domains import DEVICE_ASSERT
    from sandbox.protocol.envelope import canonical_bytes

    sk = SigningKey.generate()
    device_key = bytes(sk._seed)

    ctx = _setup_managed_workspace(tmp_path, monkeypatch, policy_sequence=1)
    lay = ctx["lay"]

    assertion_received = []

    def token_route(method, url, body, headers, token):
        """Accept only if body has a valid agg/device-assert/v1 assertion
        whose iat is within 300 s of wall-clock time."""
        if not isinstance(body, dict):
            return (400, {"error": "missing_assertion"}, {})
        assertion = body.get("assertion")
        if not assertion or not isinstance(assertion, dict):
            return (400, {"error": "missing_assertion"}, {})
        if assertion.get("kind") != "agg/device-assert/v1":
            return (400, {"error": "bad_assertion_kind"}, {})
        payload = assertion.get("payload", {})
        sigs = assertion.get("signatures", [])
        if not sigs or not payload.get("device_id"):
            return (400, {"error": "incomplete_assertion"}, {})
        # Reject iat too far from wall-clock time (the real server does this)
        iat = payload.get("iat", 0)
        if abs(iat - time.time()) > 300:
            return (401, {"error": "iat_expired"}, {})
        # Verify the signature against the device pubkey
        sig_hex = sigs[0].get("sig", "")
        try:
            vk = VerifyKey(bytes(sk.verify_key))
            msg = canonical_bytes(DEVICE_ASSERT, payload)
            vk.verify(msg, bytes.fromhex(sig_hex))
        except Exception:
            return (400, {"error": "bad_signature"}, {})
        assertion_received.append(assertion)
        return (200, {"token": "tok-f1", "expires_in": 600}, {})

    routes = {
        ("POST", "/api/v1/sync/token"): token_route,
        ("GET", "/api/v1/sync/decisions"): (200, {"decisions": []}, {}),
        ("GET", "/api/v1/sync/bundle"): (204, {}, {}),
        ("GET", "/api/v1/sync/registry"): (200, {}, {}),
        ("POST", "/api/v1/sync/escalations"): (200, {}, {}),
    }
    connect, _ = _make_fake_connect(routes)
    sync = SyncProcess(lay, "http://127.0.0.1:9999", device_key, "dev-f1",
                       connect=connect)
    run_once(sync)
    assert len(assertion_received) == 1
    assert assertion_received[0]["kind"] == "agg/device-assert/v1"


def test_f1_short_device_key_raises():
    """A device key shorter than 32 bytes raises ClickException in _load_device_key."""
    _need_fetch_bundle()

    from sandbox.cli.sync_cmds import _load_device_key
    import click

    # _load_device_key reads from key home; test via SyncProcess which
    # calls SigningKey(device_key) in _refresh_token.
    from sandbox.connector.sync.process import SyncProcess, run_once, SyncError

    sync = SyncProcess(None, "http://127.0.0.1:9999", b"short", "dev-f1",
                       connect=lambda *a, **k: (200, {}, {}))
    with pytest.raises(SyncError, match="32"):
        run_once(sync)


def test_f1_no_zero_seed_fallback():
    """_load_device_key never falls back to b'\\x00' * 32 as a seed."""
    _need_fetch_bundle()

    from sandbox.cli.sync_cmds import _load_device_key
    import click

    # Create a workspace with no device key at all
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        from sandbox.connector.install import init
        from sandbox.connector.layout import FolderLayout
        ws = Path(td) / "ws"
        ws.mkdir()
        init(ws, claude=False, mcp=False)
        lay = FolderLayout(ws)
        with pytest.raises(click.ClickException):
            _load_device_key(lay)


def test_f1_monotonic_clock_iat_still_accepted(tmp_path, monkeypatch):
    """A monotonic clock (value ~1000) would produce an iat far from
    wall-clock time, causing the server to return 401 iat_expired.
    With the fix (time.time()), a SyncProcess whose clock is monotonic
    still gets a valid token because _refresh_token uses time.time()
    for the iat, not sync._clock()."""
    _need_fetch_bundle()

    from sandbox.connector.sync.process import SyncProcess, run_once
    from nacl.signing import SigningKey, VerifyKey
    from sandbox.protocol.domains import DEVICE_ASSERT
    from sandbox.protocol.envelope import canonical_bytes

    sk = SigningKey.generate()
    device_key = bytes(sk._seed)

    ctx = _setup_managed_workspace(tmp_path, monkeypatch, policy_sequence=1)
    lay = ctx["lay"]

    token_ok = []

    def strict_token_route(method, url, body, headers, token):
        """Reject iat more than 300 s from wall-clock time."""
        if not isinstance(body, dict):
            return (400, {"error": "missing_assertion"}, {})
        assertion = body.get("assertion", {})
        payload = assertion.get("payload", {})
        iat = payload.get("iat", 0)
        if abs(iat - time.time()) > 300:
            return (401, {"error": "iat_expired"}, {})
        sigs = assertion.get("signatures", [])
        if not sigs:
            return (400, {"error": "no_sig"}, {})
        sig_hex = sigs[0].get("sig", "")
        try:
            vk = VerifyKey(bytes(sk.verify_key))
            msg = canonical_bytes(DEVICE_ASSERT, payload)
            vk.verify(msg, bytes.fromhex(sig_hex))
        except Exception:
            return (400, {"error": "bad_signature"}, {})
        token_ok.append(True)
        return (200, {"token": "tok-mono", "expires_in": 600}, {})

    routes = {
        ("POST", "/api/v1/sync/token"): strict_token_route,
        ("GET", "/api/v1/sync/decisions"): (200, {"decisions": []}, {}),
        ("GET", "/api/v1/sync/bundle"): (204, {}, {}),
        ("GET", "/api/v1/sync/registry"): (200, {}, {}),
        ("POST", "/api/v1/sync/escalations"): (200, {}, {}),
    }
    connect, _ = _make_fake_connect(routes)

    # Use a monotonic-like clock that returns ~1000 (far from epoch)
    sync = SyncProcess(lay, "http://127.0.0.1:9999", device_key, "dev-f1-mono",
                       clock=lambda: 1000.0, connect=connect)
    run_once(sync)
    assert len(token_ok) == 1, (
        "token route was not reached or rejected the iat; "
        "_refresh_token may still use sync._clock() for iat"
    )


# ===================================================================
# F2: scrub exception skips the record (nothing uploaded for it)
# ===================================================================


def test_f2_scrub_exception_skips_record(tmp_path, monkeypatch):
    """When scrub_text raises on a pending record, the record is skipped
    entirely (nothing uploaded for it)."""
    _need_fetch_bundle()

    from sandbox.connector.sync.process import SyncProcess, run_once
    from nacl.signing import SigningKey

    ctx = _setup_managed_workspace(tmp_path, monkeypatch, policy_sequence=1)
    lay = ctx["lay"]

    pending_dir = lay.pending_dir
    pending_dir.mkdir(parents=True, exist_ok=True)
    (pending_dir / "req-scrub-fail.json").write_text(json.dumps({
        "request_id": "req-scrub-fail",
        "tool": "Bash",
        "command": "echo scrub-will-fail",
        "status": "pending",
        "bundle_sequence": 1,
    }))
    (pending_dir / "req-scrub-ok.json").write_text(json.dumps({
        "request_id": "req-scrub-ok",
        "tool": "Bash",
        "command": "echo safe",
        "status": "pending",
        "bundle_sequence": 1,
    }))

    uploaded_rids = []

    def fake_connect(method, url, body=None, headers=None, token=None):
        if "/sync/token" in url:
            return (200, {"token": "t", "expires_in": 600}, {})
        if "/sync/decisions" in url:
            return (200, {"decisions": []}, {})
        if "/sync/bundle" in url:
            return (204, {}, {})
        if "/sync/registry" in url:
            return (200, {}, {})
        if "/sync/escalations" in url and method == "POST":
            if isinstance(body, dict):
                uploaded_rids.append(body.get("request_id"))
            return (200, {}, {})
        return (200, {}, {})

    # Patch scrub_text to raise on the problematic record
    import sandbox.connector.scrub as scrub_mod
    original_scrub = scrub_mod.scrub_text

    def failing_scrub(text):
        if "scrub-will-fail" in text:
            raise RuntimeError("scrub engine crash")
        return original_scrub(text)

    monkeypatch.setattr(scrub_mod, "scrub_text", failing_scrub)

    sk = SigningKey.generate()
    sync = SyncProcess(lay, "http://127.0.0.1:9999", sk._seed, "dev-f2",
                       connect=fake_connect)
    run_once(sync)

    # req-scrub-fail must NOT have been uploaded
    assert "req-scrub-fail" not in uploaded_rids
    # req-scrub-ok should have been uploaded
    assert "req-scrub-ok" in uploaded_rids


# ===================================================================
# F4: byte-flip bundle test asserts bundle_refused audit event + alert
# ===================================================================


def test_f4_byteflipped_bundle_audited_and_alerted(tmp_path, monkeypatch):
    """A byte-flipped bundle must be audited as bundle_refused and trigger
    an alert via the alerts path."""
    _need_fetch_bundle()

    from sandbox.connector.sync.process import SyncProcess, run_once
    from sandbox.connector.sync.state import current_sequence
    from sandbox.connector.audit import FolderAudit
    from nacl.signing import SigningKey

    admin1, admin2, bsigner = _keygen(), _keygen(), _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch, admin_sks=[admin1, admin2],
        bundle_signer_sk=bsigner, policy_sequence=1,
    )
    lay = ctx["lay"]
    envelope, approvals, _ = _build_valid_bundle_and_approvals(
        bsigner, [admin1, admin2], sequence=2, base_sequence=1,
    )
    bad_env = json.loads(json.dumps(envelope))
    sig = bad_env["signatures"][0]["sig"]
    # XOR bit 0 of byte 0: guaranteed to change the bytes (a fixed "ff"
    # splice is a no-op when the random signature already has "ff" there).
    sig_bytes = bytearray(bytes.fromhex(sig))
    sig_bytes[0] ^= 0x01
    bad_env["signatures"][0]["sig"] = sig_bytes.hex()
    assert bad_env["signatures"][0]["sig"] != sig
    assert len(bad_env["signatures"][0]["sig"]) == len(sig)

    routes = {
        ("POST", "/api/v1/sync/token"): (200, {"token": "t", "expires_in": 600}, {}),
        ("GET", "/api/v1/sync/bundle"): (200, {"envelope": bad_env, "change_approvals": approvals}, {}),
        ("GET", "/api/v1/sync/decisions"): (200, {"decisions": []}, {}),
        ("GET", "/api/v1/sync/registry"): (200, {}, {}),
        ("POST", "/api/v1/sync/escalations"): (200, {}, {}),
    }
    connect, _ = _make_fake_connect(routes)
    sk = SigningKey.generate()
    sync = SyncProcess(lay, "http://127.0.0.1:9999", sk._seed, "dev-f4",
                       connect=connect)
    run_once(sync)
    assert current_sequence(lay) == 1

    # Check audit: must have a bundle_refused event
    audit = FolderAudit(lay.audit_dir, session_id="sync")
    entries = audit.list_records(limit=50)
    refused = [e for e in entries if e.get("event") == "bundle_refused"]
    assert len(refused) >= 1, f"no bundle_refused audit event; events: {[e.get('event') for e in entries]}"

    # Check alert: alerts.jsonl must have a bundle_refused alert
    alerts_file = lay.root / ".sandbox" / "logs" / "alerts.jsonl"
    assert alerts_file.exists(), "alerts.jsonl not created"
    alert_lines = alerts_file.read_text(encoding="utf-8").strip().splitlines()
    alert_records = [json.loads(line) for line in alert_lines]
    bundle_alerts = [a for a in alert_records if a.get("kind") == "bundle_refused"]
    assert len(bundle_alerts) >= 1, f"no bundle_refused alert; alerts: {alert_records}"


# ===================================================================
# F5: registry fetch happens before decisions fetch in run_once
# ===================================================================


def test_f5_registry_fetched_before_decisions(tmp_path, monkeypatch):
    """In run_once, the registry fetch must happen before the decisions
    fetch (D4-1 step-5: verify registry before applying decisions)."""
    _need_fetch_bundle()

    from sandbox.connector.sync.process import SyncProcess, run_once
    from nacl.signing import SigningKey

    ctx = _setup_managed_workspace(tmp_path, monkeypatch, policy_sequence=1)
    lay = ctx["lay"]

    call_order = []

    def ordered_connect(method, url, body=None, headers=None, token=None):
        if "/sync/token" in url:
            return (200, {"token": "t", "expires_in": 600}, {})
        if "/sync/registry" in url:
            call_order.append("registry")
            return (200, {}, {})
        if "/sync/decisions" in url:
            call_order.append("decisions")
            return (200, {"decisions": []}, {})
        if "/sync/bundle" in url:
            return (204, {}, {})
        if "/sync/escalations" in url:
            return (200, {}, {})
        return (200, {}, {})

    sk = SigningKey.generate()
    sync = SyncProcess(lay, "http://127.0.0.1:9999", sk._seed, "dev-f5",
                       connect=ordered_connect)
    run_once(sync)

    assert "registry" in call_order, "registry was never fetched"
    assert "decisions" in call_order, "decisions were never fetched"
    reg_idx = call_order.index("registry")
    dec_idx = call_order.index("decisions")
    assert reg_idx < dec_idx, (
        f"registry fetch (index {reg_idx}) must come before decisions "
        f"(index {dec_idx}); call order: {call_order}"
    )


# ===================================================================
# F7: 200 with non-dict body or missing envelope -> bundle_refused
#     malformed_response, nothing applied
# ===================================================================


def test_f7_non_dict_body_bundle_refused(tmp_path, monkeypatch):
    """A 200 from GET /sync/bundle with a non-dict body (e.g. a string)
    is audited as bundle_refused with reason malformed_response."""
    _need_fetch_bundle()

    from sandbox.connector.sync.process import SyncProcess, run_once
    from sandbox.connector.sync.state import current_sequence
    from sandbox.connector.audit import FolderAudit
    from nacl.signing import SigningKey

    ctx = _setup_managed_workspace(tmp_path, monkeypatch, policy_sequence=1)
    lay = ctx["lay"]

    routes = {
        ("POST", "/api/v1/sync/token"): (200, {"token": "t", "expires_in": 600}, {}),
        ("GET", "/api/v1/sync/bundle"): (200, "not a dict", {}),
        ("GET", "/api/v1/sync/decisions"): (200, {"decisions": []}, {}),
        ("GET", "/api/v1/sync/registry"): (200, {}, {}),
        ("POST", "/api/v1/sync/escalations"): (200, {}, {}),
    }
    connect, _ = _make_fake_connect(routes)
    sk = SigningKey.generate()
    sync = SyncProcess(lay, "http://127.0.0.1:9999", sk._seed, "dev-f7a",
                       connect=connect)
    run_once(sync)
    assert current_sequence(lay) == 1

    audit = FolderAudit(lay.audit_dir, session_id="sync")
    entries = audit.list_records(limit=50)
    refused = [e for e in entries if e.get("event") == "bundle_refused"]
    assert len(refused) >= 1
    assert refused[0].get("reason") == "malformed_response"


def test_f7_missing_envelope_bundle_refused(tmp_path, monkeypatch):
    """A 200 from GET /sync/bundle with a dict that has no 'envelope' key
    is audited as bundle_refused with reason malformed_response."""
    _need_fetch_bundle()

    from sandbox.connector.sync.process import SyncProcess, run_once
    from sandbox.connector.sync.state import current_sequence
    from sandbox.connector.audit import FolderAudit
    from nacl.signing import SigningKey

    ctx = _setup_managed_workspace(tmp_path, monkeypatch, policy_sequence=1)
    lay = ctx["lay"]

    routes = {
        ("POST", "/api/v1/sync/token"): (200, {"token": "t", "expires_in": 600}, {}),
        ("GET", "/api/v1/sync/bundle"): (200, {"change_approvals": []}, {}),
        ("GET", "/api/v1/sync/decisions"): (200, {"decisions": []}, {}),
        ("GET", "/api/v1/sync/registry"): (200, {}, {}),
        ("POST", "/api/v1/sync/escalations"): (200, {}, {}),
    }
    connect, _ = _make_fake_connect(routes)
    sk = SigningKey.generate()
    sync = SyncProcess(lay, "http://127.0.0.1:9999", sk._seed, "dev-f7b",
                       connect=connect)
    run_once(sync)
    assert current_sequence(lay) == 1

    audit = FolderAudit(lay.audit_dir, session_id="sync")
    entries = audit.list_records(limit=50)
    refused = [e for e in entries if e.get("event") == "bundle_refused"]
    assert len(refused) >= 1
    assert refused[0].get("reason") == "malformed_response"
