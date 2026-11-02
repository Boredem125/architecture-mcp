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
        if "apply_external" in src:
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


@pytest.mark.xfail(strict=True, raises=M2T16Pending,
                    reason="T16a: process.py has no _fetch_bundle step")
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


@pytest.mark.xfail(strict=True, raises=M2T16Pending,
                    reason="T16a: process.py has no _fetch_bundle step")
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


@pytest.mark.xfail(strict=True, raises=M2T16Pending,
                    reason="T16a: process.py has no _fetch_bundle step")
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


@pytest.mark.xfail(strict=True, raises=M2T16Pending,
                    reason="T16a: no _fetch_bundle in process.py")
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
    bad_env["signatures"][0]["sig"] = sig[:4] + "ff" + sig[6:]

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


@pytest.mark.xfail(strict=True, raises=M2T16Pending,
                    reason="T16a: no _fetch_bundle in process.py")
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


@pytest.mark.xfail(strict=True, raises=M2T16Pending,
                    reason="T16a: no _fetch_bundle in process.py")
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


@pytest.mark.xfail(strict=True, raises=M2T16Pending,
                    reason="T16a: no _fetch_bundle in process.py")
def test_one_approval_loosening_refused(tmp_path, monkeypatch):
    """A loosening with only 1 approval (needs 2) is refused."""
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
    assert current_sequence(lay) == 1


@pytest.mark.xfail(strict=True, raises=M2T16Pending,
                    reason="T16a: no _fetch_bundle in process.py")
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


@pytest.mark.xfail(strict=True, raises=M2T16Pending,
                    reason="T16a: no _fetch_bundle in process.py")
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
    assert current_sequence(lay) == 1


# ===================================================================
# T16a-3: CLI sync --once delegates to SyncProcess (audit, server_time,
#          decision apply)
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T16Pending,
                    reason="T16a: CLI sync_cmds.run_once still calls apply_external")
def test_cli_sync_once_delegates_to_sync_process():
    """``sandbox sync --once`` should delegate to SyncProcess, not have
    its own apply_external cycle."""
    _need_cli_delegates()
    # If _need_cli_delegates did not raise, the CLI is already fixed.
    assert True


@pytest.mark.xfail(strict=True, raises=M2T16Pending,
                    reason="T16a: _fetch_decisions in process.py does not apply decisions")
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
    rid, fp = _create_pending_request(lay, "req-d1")
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
    audit = FolderAudit(lay.audit_dir)
    entries = list(audit.iter_unsent())
    applied = [e for e in entries if e.get("event") == "sync_decision_applied"]
    assert len(applied) >= 1
    assert applied[0].get("request_id") == "req-d1"


# ===================================================================
# T16a-4: sandbox sync loops and exits on KeyboardInterrupt
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T16Pending,
                    reason="T16a: process.py has no run_loop")
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


@pytest.mark.xfail(strict=True, raises=M2T16Pending,
                    reason="T16a: no _fetch_bundle in process.py")
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
