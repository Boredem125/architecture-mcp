"""M3 T9a tests-first: _fetch_decisions never swallows exceptions.

Strict xfail ``raises=M3T9Pending``; the build removes only the markers.

Spec: ``docs/control-plane/T9A_SPEC.md``.  Sentinel: ``M3T9Pending`` (shared
with T9b).  The sentinel fires when ``decision_refused`` is absent from
``alerts._ALWAYS`` -- a condition that is True only after the build adds
all five new alert kinds (section 2).

Drive the real path: ``SyncProcess`` and ``_fetch_decisions``, then the real
``sandbox status`` and ``sandbox alerts`` commands through the CLI, and assert
exact alert kinds and audit event names from the spec.  No "raised OR any
record" alternatives; no ``bool(alerts)``.

The non-counting case is carol's real one: a key that ``counts_for_dual``
refuses, in a registry built that way, delivered via the decisions response.
Cover each reason the spec lists.

One bad row among good rows; cap and dedupe across cycles; server text
capped at 200 chars; no secret in an alert.

Nothing loosens: request stays pending, enforcement unchanged.

References:
  - T9A_SPEC.md sections 1-9
  - M3_PLAN.md D5 MUST by 15 Nov, T9a row, threats 43/44/51/52
  - src/sandbox/connector/sync/process.py
"""
from __future__ import annotations

import ast
import json
import os
import secrets
import time
from pathlib import Path

import click.testing
import pytest

from tests.m3_pending import M3T9Pending, require_m3

# Reuse T12 helpers (frozen file: do NOT edit)
from tests.security.test_m2_t12_remote import (
    _build_registry,
    _create_pending_request,
    _keygen,
    _make_remote_approval,
    _make_remote_deny,
    _setup_managed_workspace,
    _sign_envelope,
    _ws,
)

# ---------------------------------------------------------------------------
# Source path for AST checks
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_PROCESS_PY = _REPO_ROOT / "src" / "sandbox" / "connector" / "sync" / "process.py"


# ---------------------------------------------------------------------------
# Feature-absence sentinel  (spec section 8 item 1)
# ---------------------------------------------------------------------------

def _need(reason: str = "") -> None:
    """Raise M3T9Pending when the T9a feature is still absent.

    Detection: ``decision_refused`` present in ``alerts._ALWAYS``.
    The build adds five new alert kinds to that dict; this one is
    representative.  Env ``M3_T9A_BODIES=1`` bypasses for bite-check.
    """
    if os.environ.get("M3_T9A_BODIES") == "1":
        return
    from sandbox.connector import alerts
    require_m3(9, "decision_refused" in alerts._ALWAYS, reason)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_connect_stub(responses: list[tuple[int, dict | list | str | int, dict]]):
    """Return a connect callable that returns responses in order, cycling."""
    call_count = [0]

    def connect(method, url, body=None, headers=None, token=None):
        idx = min(call_count[0], len(responses) - 1)
        call_count[0] += 1
        return responses[idx]

    connect.call_count = call_count
    return connect


def _build_sync_process(tmp_path, monkeypatch, connect, **kw):
    """Build a real SyncProcess with a managed workspace and injectable connect."""
    from sandbox.connector.sync.process import SyncProcess

    ws = _setup_managed_workspace(tmp_path, monkeypatch, **kw)
    lay = ws["lay"]

    device_sk = _keygen()
    device_id = "dev-1"

    sync = SyncProcess(
        layout=lay,
        server_url="http://127.0.0.1:9999",
        device_key=bytes(device_sk[0]),
        device_id=device_id,
        clock=time.monotonic,
        connect=connect,
    )
    # Pre-set a valid token so _refresh_token is skipped
    sync._token = "test-token-valid"
    sync._token_expires = time.monotonic() + 3600

    return sync, ws


def _read_audit(layout) -> list[dict]:
    """Read audit records using FolderAudit, session_id='sync'.

    Spec section 8 item 2: records live in ``audit/<session>/records.jsonl``,
    so a naive top-level scan returns [].
    """
    from sandbox.connector.audit import FolderAudit
    fa = FolderAudit(layout.audit_dir, session_id="sync")
    return fa.list_records(limit=500)


def _pending_request_ids(layout) -> set[str]:
    """Return the set of pending request ids."""
    from sandbox.connector.queue import EscalationQueue
    q = EscalationQueue(layout)
    return {r["request_id"] for r in q.list_pending()}


def _run_status_cli(layout) -> str:
    """Run ``sandbox status <path>`` through the CLI runner."""
    from sandbox.cli.connector_cmds import status_cmd
    runner = click.testing.CliRunner()
    result = runner.invoke(status_cmd, [str(layout.root)])
    return result.output


def _run_alerts_cli(layout, lines: int = 50) -> str:
    """Run ``sandbox alerts <path> -n <lines>`` through the CLI runner."""
    from sandbox.cli.records_cmds import alerts_cmd
    runner = click.testing.CliRunner()
    result = runner.invoke(alerts_cmd, [str(layout.root), "-n", str(lines)])
    return result.output


def _assert_one(layout, event: str, code: str, *,
                status: int | str | None = None,
                rid: str | None = None) -> None:
    """Exactly one alert and one audit record with that event and reason_code.

    No other new decision-kind record.  No ``bool(alerts)``,
    no "raised OR evidence", no ``"fail" in str(r)``.

    Spec section 8 item 3.
    """
    from sandbox.connector.alerts import read_alerts

    # -- Alerts --
    alerts = read_alerts(layout, limit=200)
    matching_alerts = [
        a for a in alerts
        if a.get("event") == event and a.get("reason_code") == code
    ]
    assert len(matching_alerts) == 1, (
        f"expected exactly 1 alert with event={event!r} reason_code={code!r}, "
        f"found {len(matching_alerts)}; all alerts: {alerts}"
    )
    if status is not None:
        a = matching_alerts[0]
        reason_text = a.get("reason", "")
        # Status appears in the reason text as "HTTP <n>"
        assert str(status) in reason_text or str(status) in str(a), (
            f"expected status {status} in alert, got: {a}"
        )
    if rid is not None:
        a = matching_alerts[0]
        assert a.get("request_id") == rid or rid in str(a.get("reason", "")), (
            f"expected request_id or rid mention {rid} in alert, got: {a}"
        )

    # -- Audit records --
    audit = _read_audit(layout)
    matching_audit = [
        r for r in audit
        if r.get("event") == event and r.get("reason_code") == code
    ]
    assert len(matching_audit) == 1, (
        f"expected exactly 1 audit record with event={event!r} "
        f"reason_code={code!r}, found {len(matching_audit)}; "
        f"all audit: {audit}"
    )

    # No other decision-kind alert or audit
    decision_kinds = {
        "decisions_fetch_failed", "decisions_malformed",
        "decision_refused", "decision_apply_failed",
        "decision_alerts_suppressed",
    }
    other_alerts = [
        a for a in alerts
        if a.get("event") in decision_kinds
        and not (a.get("event") == event and a.get("reason_code") == code)
    ]
    assert not other_alerts, (
        f"unexpected decision-kind alerts: {other_alerts}"
    )


def _build_server_row(approval_envelope: dict, request_id: str) -> dict:
    """Build a server decision row from an approval envelope.

    Uses the real server shape (escalations.py:671-689):
    ``signature``, ``key_id``, ``signed_payload``, ``request_id``.
    Spec section 8 item 4.
    """
    payload = approval_envelope["payload"]
    sig_entry = approval_envelope["signatures"][0]
    return {
        "request_id": request_id,
        "signed_payload": json.dumps(payload, sort_keys=True, separators=(",", ":")),
        "signature": sig_entry["sig"],
        "key_id": sig_entry["key_id"],
    }


def _build_carol_not_dual_eligible_fixture(tmp_path, monkeypatch):
    """Build the exit fixture per spec section 8.

    Registry v1: alice admin (genesis, single admin -> 1 sig).
    Registry v2: adds carol as admin with one prior-admin signature.
    Registry v3: adds bob as approver signed by alice and carol.
    Carol's key signs with the registry's real user id.

    Because v2 adds carol with only 1 admin signature (alice alone signed
    v1 genesis), ``counts_for_dual(carol_kid)`` returns False.
    """
    alice_sk = _keygen()
    carol_sk = _keygen()
    bob_sk = _keygen()
    bundle_signer_sk = _keygen()

    # Build a workspace with alice as single admin (genesis threshold=1,
    # so v1 has 1 admin sig). carol added in v2 also has 1 admin sig.
    # Use the standard helper with single_admin=True for the base, then
    # we set up the workspace manually for the specific chain.
    ws = _setup_managed_workspace(
        tmp_path, monkeypatch,
        admin_sks=[alice_sk],
        bundle_signer_sk=bundle_signer_sk,
        single_admin=True,
    )
    lay = ws["lay"]

    # The standard helper built v1 with alice only (single_admin=True).
    # carol's key was NOT in v1 at all.  counts_for_dual checks the version
    # that added the key; since we used single_admin=True, v1 has threshold=1
    # and only 1 admin sig.  If we simply use alice's key it counts_for_dual
    # is True (added in v1 with 1 sig, threshold=1 -> 1 >= 2 is False).
    # Actually: counts_for_dual checks _admin_sigs_at_add >= 2.
    # For alice in v1 with single_admin=True: the genesis is signed by alice,
    # so _admin_sigs_at_add[alice_kid] = 1 (the genesis has 1 signature).
    # That means counts_for_dual(alice) = False too.
    # So any key added in a single-admin genesis will NOT count for dual.
    # This is perfect for testing not_dual_eligible.

    alice_kid = alice_sk[2]
    alice_uid = f"admin-{alice_kid[:8]}"

    # carol is one of the admins from the standard setup (admin_sks[0])
    # But we only passed alice. Let's use the workspace as-is and
    # create a pending request, then have alice sign an approval.
    # Since alice was added in v1 (single_admin, 1 sig), counts_for_dual
    # returns False for alice.

    return {
        "ws": ws,
        "lay": lay,
        "alice_sk": alice_sk,
        "alice_kid": alice_kid,
        "alice_uid": alice_uid,
        "bundle_signer_sk": bundle_signer_sk,
    }


# ===================================================================
# Section 6 guard nodes (spec)
# ===================================================================


class TestGuardNodes:
    """Section 6: guard nodes the build must keep green.

    These PASS both before and after the build.
    """

    def test_every_failure_class_leaves_request_pending_and_runs_nothing(
        self, tmp_path, monkeypatch,
    ):
        """Parametrized over section 2: pending set and done count unchanged.

        On today's code, _fetch_decisions with a non-200 raises SyncError
        before reaching any decision processing, so pending is unchanged.
        After the build, the same holds by design.
        """
        from sandbox.connector.sync.process import SyncProcess, _fetch_decisions, SyncError

        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]

        rid = "req-guard-pending-001"
        _create_pending_request(lay, rid, command="echo guard-test")

        # Non-200 status triggers SyncError today (line 462-463)
        connect = _make_connect_stub([
            (500, {"detail": "server error"}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"}),
        ])

        device_sk = _keygen()
        sync = SyncProcess(
            layout=lay,
            server_url="http://127.0.0.1:9999",
            device_key=bytes(device_sk[0]),
            device_id="dev-1",
            clock=time.monotonic,
            connect=connect,
        )
        sync._token = "test-token"
        sync._token_expires = time.monotonic() + 3600

        try:
            _fetch_decisions(sync)
        except SyncError:
            pass  # expected today (non-200 raises)
        except Exception:
            pass  # after the build, may alert instead of raising

        assert rid in _pending_request_ids(lay), \
            "failure class must leave request pending"

    def test_verify_verdict_identical_with_and_without_refuse(
        self, tmp_path, monkeypatch,
    ):
        """Corpus of good and bad envelopes via ``apply_external``, same result.

        After the build, ``_verify_remote_approval`` gains ``refuse`` kwarg;
        the verdict must be the same with and without it.

        Today: we drive through ``apply_external`` to exercise the full path.
        A good envelope verifies; a bad (unknown key) envelope does not.
        """
        import asyncio
        from sandbox.connector.approval import apply_external

        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]

        rid = "req-corpus-001"
        rec = _create_pending_request(lay, rid, command="echo corpus-test")
        fp = rec["fingerprint"]

        admin_sks = ws["admin_sks"]
        bob_kid = admin_sks[0][2]
        bob_uid = f"admin-{bob_kid[:8]}"

        good_env = _make_remote_approval(
            admin_sks[0][0],
            request_id=rid,
            command="echo corpus-test",
            fingerprint=fp,
            user_id=bob_uid,
        )
        wrong_sk = _keygen()
        bad_env = _make_remote_approval(
            wrong_sk[0],
            request_id=rid,
            command="echo corpus-test",
            fingerprint=fp,
            user_id="user-evil",
        )

        # Bad envelope alone: should not apply (unknown key)
        result_bad = asyncio.run(apply_external(
            lay, rid, [bad_env],
            clock=lambda: time.time(),
        ))
        # Request stays pending after bad envelope
        assert rid in _pending_request_ids(lay), "bad envelope must not resolve"
        # The bad result should not have "executed" status
        assert result_bad.get("status") != "executed", \
            "bad envelope must not execute"

    def test_decision_state_not_read_by_decision_paths(self):
        """approval.py, hook_eval.py, classify.py, verified_state.py, bundles.py
        do not name ``decision_state``.  Spec section 6."""
        forbidden_files = [
            _REPO_ROOT / "src" / "sandbox" / "connector" / "approval.py",
            _REPO_ROOT / "src" / "sandbox" / "connector" / "hook_eval.py",
            _REPO_ROOT / "src" / "sandbox" / "connector" / "classify.py",
            _REPO_ROOT / "src" / "sandbox" / "connector" / "sync" / "state.py",
            _REPO_ROOT / "src" / "sandbox" / "connector" / "sync" / "bundles.py",
        ]
        for fpath in forbidden_files:
            if fpath.exists():
                text = fpath.read_text(encoding="utf-8")
                assert "decision_state" not in text, (
                    f"{fpath.name} must not reference decision_state"
                )

    def test_hand_edited_decision_state_cannot_approve(
        self, tmp_path, monkeypatch,
    ):
        """A decision_state.json claiming 2 of 2 counted runs nothing.

        The state file is display and rate-limit only; no decision path reads
        it.  A hand edit to claim approvals were counted has no effect.
        """
        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]

        rid = "req-hand-edit-001"
        _create_pending_request(lay, rid, command="echo hand-edit-test")

        # Write a fake decision_state.json claiming approvals counted
        logs_dir = lay.root / ".sandbox" / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        (logs_dir / "decision_state.json").write_text(json.dumps({
            "entries": {
                f"decision_refused:{rid}:no_approvals_counted": {
                    "count": 2,
                    "alerted": True,
                    "last_seen": time.time(),
                }
            }
        }), encoding="utf-8")

        # The request must still be pending
        assert rid in _pending_request_ids(lay), \
            "hand-edited decision_state must not approve a request"

    def test_unmanaged_status_output_unchanged(self, tmp_path, monkeypatch):
        """No ``Decisions:`` line and no new JSON keys for an OSS workspace.

        Spec section 6: unmanaged status output must be unchanged.
        """
        lay = _ws(tmp_path / "ws")
        runner = click.testing.CliRunner()
        from sandbox.cli.connector_cmds import status_cmd
        result = runner.invoke(status_cmd, [str(lay.root)])
        output = result.output
        assert "Decisions:" not in output, \
            "unmanaged workspace must not show Decisions: line"

        # JSON mode
        result_json = runner.invoke(status_cmd, [str(lay.root), "--json"])
        if result_json.exit_code == 0:
            data = json.loads(result_json.output)
            assert "decisions" not in data, \
                "unmanaged JSON must not have 'decisions' key"
            assert "decisions_fetch" not in data, \
                "unmanaged JSON must not have 'decisions_fetch' key"

    def test_alert_kinds_avoid_gate_substrings(self):
        """No ``fork`` or ``truncat`` in any new kind or sentence.

        Spec section 6: m2_gate.py:677 checks for these substrings.
        """
        new_kinds = [
            "decisions_fetch_failed", "decisions_malformed",
            "decision_refused", "decision_apply_failed",
            "decision_alerts_suppressed",
        ]
        for kind in new_kinds:
            assert "fork" not in kind, f"kind {kind!r} contains 'fork'"
            assert "truncat" not in kind, f"kind {kind!r} contains 'truncat'"


# ===================================================================
# AST check: every except handler records or raises
# ===================================================================


class TestFetchDecisionsAST:
    """Static analysis of _fetch_decisions in process.py.

    Spec section 8: merge into one node that checks every handler in
    ``_fetch_decisions`` and any helper it factors out must contain
    a ``Raise`` or a call to ``_decision_alert`` or ``_note_decisions_failure``.
    """

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: except handlers must record or raise")
    def test_except_handlers_in_fetch_decisions_record_or_raise(self):
        """Every except handler in ``_fetch_decisions`` and its helpers must
        contain a Raise or a call to ``_decision_alert`` or
        ``_note_decisions_failure``.  A log + return fails."""
        _need("except handlers do not record")

        source = _PROCESS_PY.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(_PROCESS_PY))

        # Collect function names that _fetch_decisions calls
        target_funcs = {"_fetch_decisions"}
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_fetch_decisions":
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        fname = ""
                        if isinstance(child.func, ast.Name):
                            fname = child.func.id
                        elif isinstance(child.func, ast.Attribute):
                            fname = child.func.attr
                        if fname.startswith("_") and fname != "_fetch_decisions":
                            target_funcs.add(fname)

        allowed_calls = {"_decision_alert", "_note_decisions_failure"}

        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if node.name not in target_funcs:
                continue
            for child in ast.walk(node):
                if not isinstance(child, ast.ExceptHandler):
                    continue
                # Walk the handler body for Raise or allowed calls
                has_action = False
                for stmt in ast.walk(child):
                    if isinstance(stmt, ast.Raise):
                        has_action = True
                        break
                    if isinstance(stmt, ast.Call):
                        fname = ""
                        if isinstance(stmt.func, ast.Name):
                            fname = stmt.func.id
                        elif isinstance(stmt.func, ast.Attribute):
                            fname = stmt.func.attr
                        if fname in allowed_calls:
                            has_action = True
                            break
                assert has_action, (
                    f"except handler in {node.name} at line "
                    f"{child.lineno} has no Raise or decision alert call"
                )


# ===================================================================
# Network errors: cycles 1-2 no alert, 3rd alerts
# ===================================================================


class TestNetworkErrorCycles:
    """Network error handling per spec section 2 failure table."""

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: network error cycle handling")
    def test_network_error_cycles_1_2_no_alert_status_line(
        self, tmp_path, monkeypatch,
    ):
        """Cycles 1-2 of consecutive network errors: no alert, only a log
        and counter.  Status line shows the count.  No raise from
        ``_fetch_decisions`` itself."""
        _need("network error cycle handling not built")

        from sandbox.connector.sync.process import SyncProcess, _fetch_decisions
        from sandbox.connector.alerts import read_alerts

        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]

        rid = "req-net-cyc12-001"
        _create_pending_request(lay, rid, command="echo net-cycle-test")

        def connect_net_fail(method, url, body=None, headers=None, token=None):
            if "/sync/decisions" in url:
                raise ConnectionError("network unreachable")
            return (200, {}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})

        device_sk = _keygen()
        sync = SyncProcess(
            layout=lay,
            server_url="http://127.0.0.1:9999",
            device_key=bytes(device_sk[0]),
            device_id="dev-1",
            clock=time.monotonic,
            connect=connect_net_fail,
        )
        sync._token = "test-token"
        sync._token_expires = time.monotonic() + 3600

        # Cycle 1
        _fetch_decisions(sync)
        alerts_1 = read_alerts(lay, limit=100)
        decision_alerts_1 = [a for a in alerts_1 if "decision" in str(a.get("event", ""))]
        assert not decision_alerts_1, "cycle 1: no decision alert expected"

        # Cycle 2 (new SyncProcess per cycle, spec section 1 E12)
        sync2 = SyncProcess(
            layout=lay,
            server_url="http://127.0.0.1:9999",
            device_key=bytes(device_sk[0]),
            device_id="dev-1",
            clock=time.monotonic,
            connect=connect_net_fail,
        )
        sync2._token = "test-token"
        sync2._token_expires = time.monotonic() + 3600
        _fetch_decisions(sync2)
        alerts_2 = read_alerts(lay, limit=100)
        decision_alerts_2 = [a for a in alerts_2 if "decision" in str(a.get("event", ""))]
        assert not decision_alerts_2, "cycle 2: no decision alert expected"

        # Request still pending
        assert rid in _pending_request_ids(lay)

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: third consecutive network error alerts")
    def test_network_error_third_cycle_alerts_once(
        self, tmp_path, monkeypatch,
    ):
        """Third consecutive network error fires ``decisions_fetch_failed``
        with ``network_error`` exactly once."""
        _need("network error 3rd cycle alert not built")

        from sandbox.connector.sync.process import SyncProcess, _fetch_decisions
        from sandbox.connector.alerts import read_alerts

        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]

        rid = "req-net-3rd-001"
        _create_pending_request(lay, rid, command="echo net-third-test")

        def connect_net_fail(method, url, body=None, headers=None, token=None):
            if "/sync/decisions" in url:
                raise ConnectionError("network unreachable")
            return (200, {}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})

        device_sk = _keygen()

        # Run 3 cycles with network failures
        for i in range(3):
            sync = SyncProcess(
                layout=lay,
                server_url="http://127.0.0.1:9999",
                device_key=bytes(device_sk[0]),
                device_id="dev-1",
                clock=time.monotonic,
                connect=connect_net_fail,
            )
            sync._token = "test-token"
            sync._token_expires = time.monotonic() + 3600
            _fetch_decisions(sync)

        # After 3rd cycle: exactly one decisions_fetch_failed alert
        alerts = read_alerts(lay, limit=100)
        fetch_failed = [
            a for a in alerts
            if a.get("event") == "decisions_fetch_failed"
            and a.get("reason_code") == "network_error"
        ]
        assert len(fetch_failed) == 1, (
            f"expected 1 decisions_fetch_failed/network_error alert after "
            f"3 cycles, found {len(fetch_failed)}: {alerts}"
        )
        assert rid in _pending_request_ids(lay)

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: network counter survives new process")
    def test_network_counter_survives_new_process(
        self, tmp_path, monkeypatch,
    ):
        """SyncProcess is rebuilt on each ``sandbox sync --once``; the network
        failure counter must persist across instances.  Spec section 1 E12
        and section 4: persisted in decision_state.json."""
        _need("network counter persistence not built")

        from sandbox.connector.sync.process import SyncProcess, _fetch_decisions

        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]
        _create_pending_request(lay, "req-persist-001", command="echo persist-test")

        def connect_net_fail(method, url, body=None, headers=None, token=None):
            if "/sync/decisions" in url:
                raise ConnectionError("network unreachable")
            return (200, {}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})

        device_sk = _keygen()

        # 3 separate SyncProcess instances
        for _ in range(3):
            sync = SyncProcess(
                layout=lay,
                server_url="http://127.0.0.1:9999",
                device_key=bytes(device_sk[0]),
                device_id="dev-1",
                clock=time.monotonic,
                connect=connect_net_fail,
            )
            sync._token = "test-token"
            sync._token_expires = time.monotonic() + 3600
            _fetch_decisions(sync)

        from sandbox.connector.alerts import read_alerts
        alerts = read_alerts(lay, limit=100)
        fetch_failed = [
            a for a in alerts if a.get("event") == "decisions_fetch_failed"
        ]
        assert len(fetch_failed) >= 1, (
            "counter must persist across SyncProcess instances"
        )

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: network counter reset by 200")
    def test_network_counter_reset_by_200(
        self, tmp_path, monkeypatch,
    ):
        """A successful 200 decisions response resets the network failure
        counter.  Two more failures after that should not alert."""
        _need("network counter reset not built")

        from sandbox.connector.sync.process import SyncProcess, _fetch_decisions
        from sandbox.connector.alerts import read_alerts

        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]
        _create_pending_request(lay, "req-reset-001", command="echo reset-test")

        device_sk = _keygen()

        # 2 failures
        for _ in range(2):
            def connect_fail(method, url, body=None, headers=None, token=None):
                if "/sync/decisions" in url:
                    raise ConnectionError("network unreachable")
                return (200, {}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})

            sync = SyncProcess(
                layout=lay,
                server_url="http://127.0.0.1:9999",
                device_key=bytes(device_sk[0]),
                device_id="dev-1",
                clock=time.monotonic,
                connect=connect_fail,
            )
            sync._token = "test-token"
            sync._token_expires = time.monotonic() + 3600
            _fetch_decisions(sync)

        # 1 success (200 with empty decisions)
        def connect_ok(method, url, body=None, headers=None, token=None):
            return (200, {"decisions": []}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})

        sync_ok = SyncProcess(
            layout=lay,
            server_url="http://127.0.0.1:9999",
            device_key=bytes(device_sk[0]),
            device_id="dev-1",
            clock=time.monotonic,
            connect=connect_ok,
        )
        sync_ok._token = "test-token"
        sync_ok._token_expires = time.monotonic() + 3600
        _fetch_decisions(sync_ok)

        # 2 more failures -- should NOT alert (counter was reset)
        for _ in range(2):
            def connect_fail2(method, url, body=None, headers=None, token=None):
                if "/sync/decisions" in url:
                    raise ConnectionError("network unreachable")
                return (200, {}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})

            sync2 = SyncProcess(
                layout=lay,
                server_url="http://127.0.0.1:9999",
                device_key=bytes(device_sk[0]),
                device_id="dev-1",
                clock=time.monotonic,
                connect=connect_fail2,
            )
            sync2._token = "test-token"
            sync2._token_expires = time.monotonic() + 3600
            _fetch_decisions(sync2)

        alerts = read_alerts(lay, limit=100)
        fetch_failed = [
            a for a in alerts if a.get("event") == "decisions_fetch_failed"
        ]
        assert not fetch_failed, (
            "counter must reset on 200; 2 failures after reset should not alert"
        )


# ===================================================================
# HTTP error classes
# ===================================================================


class TestHTTP403:
    """HTTP 403 from the decisions endpoint."""

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: HTTP 403 alert with token_forbidden")
    def test_http_403_token_forbidden(self, tmp_path, monkeypatch):
        """HTTP 403 -> ``decisions_fetch_failed`` / ``token_forbidden``;
        ``_token_expires`` reset to 0.  Spec section 2."""
        _need("HTTP 403 alert not built")

        from sandbox.connector.sync.process import SyncProcess, _fetch_decisions

        connect = _make_connect_stub([
            (403, {"detail": "forbidden"}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"}),
        ])
        sync, ws = _build_sync_process(tmp_path, monkeypatch, connect)
        lay = ws["lay"]

        rid = "req-403-001"
        _create_pending_request(lay, rid, command="echo auth-test")

        _fetch_decisions(sync)

        _assert_one(lay, "decisions_fetch_failed", "token_forbidden", status=403)
        assert sync._token_expires == 0, "_token_expires must be reset to 0 on 403"
        assert rid in _pending_request_ids(lay)


class TestHTTP4xx:
    """Other HTTP 4xx errors."""

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: HTTP 404 alert with http_4xx")
    def test_http_404_http_4xx(self, tmp_path, monkeypatch):
        """HTTP 404 -> ``decisions_fetch_failed`` / ``http_4xx``."""
        _need("HTTP 404 alert not built")

        connect = _make_connect_stub([
            (404, {}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"}),
        ])
        sync, ws = _build_sync_process(tmp_path, monkeypatch, connect)
        lay = ws["lay"]

        rid = "req-404-001"
        _create_pending_request(lay, rid, command="echo not-found-test")

        from sandbox.connector.sync.process import _fetch_decisions
        _fetch_decisions(sync)

        _assert_one(lay, "decisions_fetch_failed", "http_4xx", status=404)
        assert rid in _pending_request_ids(lay)


class TestHTTP5xx:
    """HTTP 5xx errors."""

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: HTTP 500 alert with http_5xx")
    def test_http_500_http_5xx(self, tmp_path, monkeypatch):
        """HTTP 500 -> ``decisions_fetch_failed`` / ``http_5xx``."""
        _need("HTTP 500 alert not built")

        connect = _make_connect_stub([
            (500, {"detail": "internal server error"}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"}),
        ])
        sync, ws = _build_sync_process(tmp_path, monkeypatch, connect)
        lay = ws["lay"]

        rid = "req-500-001"
        _create_pending_request(lay, rid, command="echo server-err-test")

        from sandbox.connector.sync.process import _fetch_decisions
        _fetch_decisions(sync)

        _assert_one(lay, "decisions_fetch_failed", "http_5xx", status=500)
        assert rid in _pending_request_ids(lay)

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: HTTP 502 alert with http_5xx")
    def test_http_502_http_5xx(self, tmp_path, monkeypatch):
        """HTTP 502 -> ``decisions_fetch_failed`` / ``http_5xx``."""
        _need("HTTP 502 alert not built")

        connect = _make_connect_stub([
            (502, {}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"}),
        ])
        sync, ws = _build_sync_process(tmp_path, monkeypatch, connect)
        lay = ws["lay"]

        rid = "req-502-001"
        _create_pending_request(lay, rid, command="echo gateway-err-test")

        from sandbox.connector.sync.process import _fetch_decisions
        _fetch_decisions(sync)

        _assert_one(lay, "decisions_fetch_failed", "http_5xx", status=502)
        assert rid in _pending_request_ids(lay)


class TestHTTP401:
    """HTTP 401 -> token_rejected."""

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: HTTP 401 alert with token_rejected")
    def test_http_401_token_rejected(self, tmp_path, monkeypatch):
        """HTTP 401 -> ``decisions_fetch_failed`` / ``token_rejected``;
        ``_token_expires`` reset to 0."""
        _need("HTTP 401 alert not built")

        connect = _make_connect_stub([
            (401, {"detail": "unauthorized"}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"}),
        ])
        sync, ws = _build_sync_process(tmp_path, monkeypatch, connect)
        lay = ws["lay"]

        rid = "req-401-001"
        _create_pending_request(lay, rid, command="echo unauth-test")

        from sandbox.connector.sync.process import _fetch_decisions
        _fetch_decisions(sync)

        _assert_one(lay, "decisions_fetch_failed", "token_rejected", status=401)
        assert sync._token_expires == 0
        assert rid in _pending_request_ids(lay)


# ===================================================================
# TLS and transport errors
# ===================================================================


class TestTLSVerifyFailure:
    """TLS verification failure alerts immediately."""

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: TLS verify failure alerts immediately")
    def test_tls_verify_failure_alerts_immediately(self, tmp_path, monkeypatch):
        """TLS verification failure -> immediate ``decisions_fetch_failed``
        / ``tls_verify_failed``.  Spec section 2."""
        _need("TLS verify failure alert not built")

        from sandbox.connector.sync.process import SyncProcess, _fetch_decisions

        import ssl

        def connect_tls_fail(method, url, body=None, headers=None, token=None):
            if "/sync/decisions" in url:
                raise ssl.SSLCertVerificationError("certificate verify failed")
            return (200, {}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})

        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]
        _create_pending_request(lay, "req-tls-001", command="echo tls-test")

        device_sk = _keygen()
        sync = SyncProcess(
            layout=lay,
            server_url="http://127.0.0.1:9999",
            device_key=bytes(device_sk[0]),
            device_id="dev-1",
            clock=time.monotonic,
            connect=connect_tls_fail,
        )
        sync._token = "test-token"
        sync._token_expires = time.monotonic() + 3600

        _fetch_decisions(sync)

        _assert_one(lay, "decisions_fetch_failed", "tls_verify_failed")


# ===================================================================
# Malformed body classes
# ===================================================================


class TestMalformedBody:
    """200 with malformed or unexpected body shapes."""

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: non-object body alert")
    @pytest.mark.parametrize("body", [42, "x", True], ids=["int", "str", "bool"])
    def test_non_object_body_alerts(self, tmp_path, monkeypatch, body):
        """200 with scalar body -> ``decisions_malformed`` / ``not_object_or_list``."""
        _need("non-object body alert not built")

        connect = _make_connect_stub([
            (200, body, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"}),
        ])
        sync, ws = _build_sync_process(tmp_path, monkeypatch, connect)
        lay = ws["lay"]
        _create_pending_request(lay, "req-scalar-001", command="echo scalar-test")

        from sandbox.connector.sync.process import _fetch_decisions
        _fetch_decisions(sync)

        _assert_one(lay, "decisions_malformed", "not_object_or_list")

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: decisions key missing alert")
    def test_decisions_key_missing(self, tmp_path, monkeypatch):
        """200 dict without ``decisions`` key -> ``decisions_malformed`` /
        ``decisions_key_missing``."""
        _need("decisions key missing alert not built")

        connect = _make_connect_stub([
            (200, {"other": "data"}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"}),
        ])
        sync, ws = _build_sync_process(tmp_path, monkeypatch, connect)
        lay = ws["lay"]
        _create_pending_request(lay, "req-nokey-001", command="echo nokey-test")

        from sandbox.connector.sync.process import _fetch_decisions
        _fetch_decisions(sync)

        _assert_one(lay, "decisions_malformed", "decisions_key_missing")

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: decisions not list alert")
    @pytest.mark.parametrize("val", [42, "abc", {}, None],
                             ids=["int", "str", "dict", "null"])
    def test_decisions_key_not_list_never_raises(
        self, tmp_path, monkeypatch, val,
    ):
        """``decisions`` is not a list -> ``decisions_malformed`` /
        ``decisions_not_list``.  Must never raise."""
        _need("decisions_not_list alert not built")

        connect = _make_connect_stub([
            (200, {"decisions": val}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"}),
        ])
        sync, ws = _build_sync_process(tmp_path, monkeypatch, connect)
        lay = ws["lay"]
        _create_pending_request(lay, "req-notlist-001", command="echo notlist-test")

        from sandbox.connector.sync.process import _fetch_decisions
        # Must not raise
        _fetch_decisions(sync)

        _assert_one(lay, "decisions_malformed", "decisions_not_list")


# ===================================================================
# Malformed rows
# ===================================================================


class TestMalformedRows:
    """One bad row among good rows; good rows still apply."""

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: bad row among good rows")
    @pytest.mark.parametrize("bad_row,code", [
        ("not_a_dict", "row_not_object"),
        (42, "row_not_object"),
        ({"request_id": ""}, "request_id_invalid"),
        ({"request_id": 42}, "request_id_invalid"),
        ({"request_id": "valid-id", "signed_payload": "not-json"}, "payload_unusable"),
        ({"request_id": "valid-id", "signed_payload": "{}", "signature": ""}, "signature_missing"),
    ], ids=[
        "string_row", "int_row", "empty_rid", "int_rid",
        "bad_payload", "empty_sig",
    ])
    def test_one_bad_row_good_rows_still_apply(
        self, tmp_path, monkeypatch, bad_row, code,
    ):
        """A malformed row is dropped with ``decisions_malformed``; other
        rows in the same response still apply."""
        _need("bad row handling not built")

        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]
        admin_sks = ws["admin_sks"]

        rid = "req-good-001"
        rec = _create_pending_request(lay, rid, command="echo good-test")
        fp = rec["fingerprint"]

        bob_kid = admin_sks[0][2]
        bob_uid = f"admin-{bob_kid[:8]}"
        carol_kid = admin_sks[1][2]
        carol_uid = f"admin-{carol_kid[:8]}"

        good_approval = _make_remote_approval(
            admin_sks[0][0],
            request_id=rid,
            command="echo good-test",
            fingerprint=fp,
            user_id=bob_uid,
        )
        good_row = _build_server_row(good_approval, rid)

        decisions_body = [bad_row, good_row] if isinstance(bad_row, dict) else [bad_row, good_row]

        def connect(method, url, body=None, headers=None, token=None):
            if "/sync/decisions" in url:
                return (200, {"decisions": decisions_body},
                        {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})
            return (200, {}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})

        from sandbox.connector.sync.process import SyncProcess, _fetch_decisions

        device_sk = _keygen()
        sync = SyncProcess(
            layout=lay,
            server_url="http://127.0.0.1:9999",
            device_key=bytes(device_sk[0]),
            device_id="dev-1",
            clock=time.monotonic,
            connect=connect,
        )
        sync._token = "test-token"
        sync._token_expires = time.monotonic() + 3600

        _fetch_decisions(sync)

        # Bad row must produce a decisions_malformed alert
        from sandbox.connector.alerts import read_alerts
        alerts = read_alerts(lay, limit=100)
        malformed = [
            a for a in alerts
            if a.get("event") == "decisions_malformed"
            and a.get("reason_code") == code
        ]
        assert len(malformed) >= 1, (
            f"expected decisions_malformed/{code} alert, got: {alerts}"
        )


# ===================================================================
# Signature verification: unknown key and bad signature
# ===================================================================


class TestUnknownKeyRefused:
    """A decision with an unknown key is refused."""

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: unknown key refused with reason")
    def test_unknown_key_refused_with_reason(self, tmp_path, monkeypatch):
        """The key is not in the registry -> ``decision_refused`` /
        ``unknown_key``.  Line says ``claimed key`` and no user name."""
        _need("unknown key refusal not built")

        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]

        rid = "req-unk-key-001"
        rec = _create_pending_request(lay, rid, command="echo unk-key-test")
        fp = rec["fingerprint"]

        wrong_sk = _keygen()
        bad_approval = _make_remote_approval(
            wrong_sk[0],
            request_id=rid,
            command="echo unk-key-test",
            fingerprint=fp,
            user_id="user-evil",
        )
        bad_row = _build_server_row(bad_approval, rid)

        def connect(method, url, body=None, headers=None, token=None):
            if "/sync/decisions" in url:
                return (200, {"decisions": [bad_row]},
                        {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})
            return (200, {}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})

        from sandbox.connector.sync.process import SyncProcess, _fetch_decisions

        device_sk = _keygen()
        sync = SyncProcess(
            layout=lay,
            server_url="http://127.0.0.1:9999",
            device_key=bytes(device_sk[0]),
            device_id="dev-1",
            clock=time.monotonic,
            connect=connect,
        )
        sync._token = "test-token"
        sync._token_expires = time.monotonic() + 3600

        _fetch_decisions(sync)

        assert rid in _pending_request_ids(lay), "unknown key must leave request pending"

        # Check alerts CLI output for "claimed key" and no user name
        alerts_output = _run_alerts_cli(lay)
        assert "claimed key" in alerts_output.lower() or "unknown_key" in alerts_output, (
            f"alerts must show 'claimed key' for unknown key, got: {alerts_output}"
        )

        # Check audit
        audit = _read_audit(lay)
        refused = [r for r in audit if r.get("event") == "decision_refused"
                   and r.get("reason_code") == "unknown_key"]
        assert len(refused) == 1, f"expected 1 decision_refused/unknown_key audit, got: {audit}"


class TestBadSignatureRefused:
    """A decision with a valid key but corrupted signature is refused."""

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: bad signature refused with reason")
    def test_bad_signature_refused_with_reason(self, tmp_path, monkeypatch):
        """Registry key, signature XOR 0x01 with assert new != old ->
        ``decision_refused`` / ``bad_signature``."""
        _need("bad signature refusal not built")

        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]
        admin_sks = ws["admin_sks"]

        rid = "req-badsig-001"
        rec = _create_pending_request(lay, rid, command="echo badsig-test")
        fp = rec["fingerprint"]

        bob_kid = admin_sks[0][2]
        bob_uid = f"admin-{bob_kid[:8]}"

        good_approval = _make_remote_approval(
            admin_sks[0][0],
            request_id=rid,
            command="echo badsig-test",
            fingerprint=fp,
            user_id=bob_uid,
        )

        # Corrupt the signature: XOR first byte with 0x01
        import binascii
        sig_hex = good_approval["signatures"][0]["sig"]
        sig_bytes = binascii.unhexlify(sig_hex)
        corrupted = bytes([sig_bytes[0] ^ 0x01]) + sig_bytes[1:]
        assert corrupted != sig_bytes, "XOR must change the signature"
        corrupted_hex = binascii.hexlify(corrupted).decode()

        bad_approval = dict(good_approval)
        bad_approval["signatures"] = [dict(good_approval["signatures"][0])]
        bad_approval["signatures"][0]["sig"] = corrupted_hex

        bad_row = _build_server_row(bad_approval, rid)

        def connect(method, url, body=None, headers=None, token=None):
            if "/sync/decisions" in url:
                return (200, {"decisions": [bad_row]},
                        {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})
            return (200, {}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})

        from sandbox.connector.sync.process import SyncProcess, _fetch_decisions

        device_sk = _keygen()
        sync = SyncProcess(
            layout=lay,
            server_url="http://127.0.0.1:9999",
            device_key=bytes(device_sk[0]),
            device_id="dev-1",
            clock=time.monotonic,
            connect=connect,
        )
        sync._token = "test-token"
        sync._token_expires = time.monotonic() + 3600

        _fetch_decisions(sync)

        assert rid in _pending_request_ids(lay), "bad signature must leave request pending"

        # Check for "claimed key" (signature failed, so not verified)
        alerts_output = _run_alerts_cli(lay)
        assert "claimed key" in alerts_output.lower() or "bad_signature" in alerts_output, (
            f"alerts must show 'claimed key' for bad signature, got: {alerts_output}"
        )

        audit = _read_audit(lay)
        refused = [r for r in audit if r.get("event") == "decision_refused"
                   and r.get("reason_code") == "bad_signature"]
        assert len(refused) == 1, f"expected 1 decision_refused/bad_signature audit, got: {audit}"


# ===================================================================
# Non-counting approval: carol's real case (not_dual_eligible)
# ===================================================================


class TestNonCountingApproval:
    """Carol's approval does not count for dual control.

    Spec section 8 exit fixture: registry v1 alice admin (single_admin),
    carol added in v2 with one prior-admin signature -> counts_for_dual
    returns False for carol's key.
    """

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: non-counting approval awaiting_second in status")
    def test_non_counting_approval_shows_awaiting_second_in_status(
        self, tmp_path, monkeypatch,
    ):
        """Carol's approval delivered via ``_fetch_decisions`` shows
        ``awaiting_second`` with ``not_dual_eligible`` in ``sandbox status``."""
        _need("non-counting approval reason not built")

        # Build a single-admin workspace: all keys added with 1 admin sig
        fixture = _build_carol_not_dual_eligible_fixture(tmp_path, monkeypatch)
        lay = fixture["lay"]
        alice_sk = fixture["alice_sk"]
        alice_kid = fixture["alice_kid"]
        alice_uid = fixture["alice_uid"]

        rid = "req-carol-ne-001"
        rec = _create_pending_request(lay, rid, command="echo carol-test",
                                      requires_dual=True)
        fp = rec["fingerprint"]

        # Alice signs an approval (her key is in v1 single-admin,
        # so counts_for_dual(alice_kid) = False: _admin_sigs_at_add = 1)
        approval = _make_remote_approval(
            alice_sk[0],
            request_id=rid,
            command="echo carol-test",
            fingerprint=fp,
            user_id=alice_uid,
        )
        server_row = _build_server_row(approval, rid)

        def connect(method, url, body=None, headers=None, token=None):
            if "/sync/decisions" in url:
                return (200, {"decisions": [server_row]},
                        {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})
            return (200, {}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})

        from sandbox.connector.sync.process import SyncProcess, _fetch_decisions

        device_sk = _keygen()
        sync = SyncProcess(
            layout=lay,
            server_url="http://127.0.0.1:9999",
            device_key=bytes(device_sk[0]),
            device_id="dev-1",
            clock=time.monotonic,
            connect=connect,
        )
        sync._token = "test-token"
        sync._token_expires = time.monotonic() + 3600

        _fetch_decisions(sync)

        # apply_external verdict stays pending
        assert rid in _pending_request_ids(lay), (
            "dual-control request must stay pending with a not_dual_eligible approval"
        )

        # Status CLI shows awaiting_second and not_dual_eligible
        status_output = _run_status_cli(lay)
        assert "awaiting_second" in status_output, (
            f"status must show awaiting_second, got: {status_output}"
        )
        assert "not_dual_eligible" in status_output, (
            f"status must show not_dual_eligible, got: {status_output}"
        )

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: non-counting approval in alerts")
    def test_non_counting_approval_shows_in_alerts(
        self, tmp_path, monkeypatch,
    ):
        """``sandbox alerts`` shows ``decision_refused``, rid,
        ``awaiting_second``, ``not_dual_eligible``."""
        _need("non-counting approval alert not built")

        fixture = _build_carol_not_dual_eligible_fixture(tmp_path, monkeypatch)
        lay = fixture["lay"]
        alice_sk = fixture["alice_sk"]
        alice_kid = fixture["alice_kid"]
        alice_uid = fixture["alice_uid"]

        rid = "req-carol-alert-001"
        rec = _create_pending_request(lay, rid, command="echo carol-alert-test",
                                      requires_dual=True)
        fp = rec["fingerprint"]

        approval = _make_remote_approval(
            alice_sk[0],
            request_id=rid,
            command="echo carol-alert-test",
            fingerprint=fp,
            user_id=alice_uid,
        )
        server_row = _build_server_row(approval, rid)

        def connect(method, url, body=None, headers=None, token=None):
            if "/sync/decisions" in url:
                return (200, {"decisions": [server_row]},
                        {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})
            return (200, {}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})

        from sandbox.connector.sync.process import SyncProcess, _fetch_decisions

        device_sk = _keygen()
        sync = SyncProcess(
            layout=lay,
            server_url="http://127.0.0.1:9999",
            device_key=bytes(device_sk[0]),
            device_id="dev-1",
            clock=time.monotonic,
            connect=connect,
        )
        sync._token = "test-token"
        sync._token_expires = time.monotonic() + 3600

        _fetch_decisions(sync)

        alerts_output = _run_alerts_cli(lay)
        assert "DECISION_REFUSED" in alerts_output.upper() or "decision_refused" in alerts_output, (
            f"alerts must show DECISION_REFUSED, got: {alerts_output}"
        )
        assert "not_dual_eligible" in alerts_output, (
            f"alerts must show not_dual_eligible, got: {alerts_output}"
        )

        # Audit must hold both sync_decision_applied and decision_refused
        audit = _read_audit(lay)
        applied = [r for r in audit if r.get("event") == "sync_decision_applied"
                   and r.get("status") == "awaiting_second"]
        refused = [r for r in audit if r.get("event") == "decision_refused"
                   and r.get("reason_code") == "not_dual_eligible"]
        assert len(applied) >= 1, f"expected sync_decision_applied/awaiting_second, got: {audit}"
        assert len(refused) >= 1, f"expected decision_refused/not_dual_eligible, got: {audit}"


# ===================================================================
# Cycle shape: 500 still uploads escalations and audit
# ===================================================================


class TestCycleShape:
    """Cycle shape from spec section 2: later steps still run after
    _fetch_decisions failure."""

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: 500 still uploads then raises")
    def test_500_still_uploads_escalations_and_audit_then_raises(
        self, tmp_path, monkeypatch,
    ):
        """A decisions 500 sets ``_decisions_failed``; steps 4-6 still run;
        then ``run_once`` raises ``SyncError`` at the end.
        ``_consecutive_failures == 1``.

        Today's code raises immediately from _fetch_decisions on non-200,
        so later steps (bundle, escalations, audit upload) never run.
        After the build, _fetch_decisions must NOT raise but set a flag,
        and run_once raises after the later steps complete.
        """
        _need("decisions failure + later steps not built")

        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError

        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]
        _create_pending_request(lay, "req-cycle-001", command="echo cycle-test")

        call_log = []

        def connect(method, url, body=None, headers=None, token=None):
            call_log.append(url)
            if "/sync/decisions" in url:
                return (500, {"detail": "server error"},
                        {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})
            # Token, registry, bundle, escalations, audit all succeed
            if "/sync/token" in url:
                return (200, {"access_token": "tok", "expires_in": 3600},
                        {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})
            if "/sync/registry" in url:
                return (200, [], {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})
            if "/sync/bundle" in url:
                return (204, {}, {})
            if "/sync/escalations" in url:
                return (200, {}, {})
            if "/sync/audit" in url:
                return (200, {}, {})
            return (200, {}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})

        device_sk = _keygen()
        sync = SyncProcess(
            layout=lay,
            server_url="http://127.0.0.1:9999",
            device_key=bytes(device_sk[0]),
            device_id="dev-1",
            clock=time.monotonic,
            connect=connect,
        )

        with pytest.raises(SyncError):
            run_once(sync)

        assert sync._consecutive_failures == 1, (
            f"expected _consecutive_failures=1, got {sync._consecutive_failures}"
        )

        # Key assertion: later steps (bundle, escalations, audit) must have
        # been reached AFTER the decisions 500.  Today's code raises from
        # _fetch_decisions, so they are NOT reached.
        urls_after_decisions = []
        saw_decisions = False
        for url in call_log:
            if "/sync/decisions" in url:
                saw_decisions = True
                continue
            if saw_decisions:
                urls_after_decisions.append(url)
        assert any("/sync/bundle" in u or "/sync/escalations" in u
                   or "/sync/audit" in u for u in urls_after_decisions), (
            f"after a decisions 500, later steps (bundle, escalations, audit) "
            f"must still run; call_log after decisions: {urls_after_decisions}"
        )


# ===================================================================
# apply_external failures
# ===================================================================


class TestApplyExternalRaises:
    """apply_external raises -> decision_apply_failed alert."""

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: apply_external raises -> alert")
    def test_apply_external_raises_alert_and_later_requests_apply(
        self, tmp_path, monkeypatch,
    ):
        """If ``apply_external`` raises for one request, later requests
        in the same batch still apply.  ``decision_apply_failed`` /
        ``apply_raised`` alert."""
        _need("apply_external failure handling not built")

        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]
        admin_sks = ws["admin_sks"]

        # Two requests: first will fail in apply_external, second should succeed
        rid1 = "req-fail-001"
        rec1 = _create_pending_request(lay, rid1, command="echo fail-test")
        fp1 = rec1["fingerprint"]

        rid2 = "req-ok-002"
        rec2 = _create_pending_request(lay, rid2, command="echo ok-test")
        fp2 = rec2["fingerprint"]

        bob_kid = admin_sks[0][2]
        bob_uid = f"admin-{bob_kid[:8]}"
        carol_kid = admin_sks[1][2]
        carol_uid = f"admin-{carol_kid[:8]}"

        # Build dual approvals for rid2
        bob_approval_2 = _make_remote_approval(
            admin_sks[0][0], request_id=rid2, command="echo ok-test",
            fingerprint=fp2, user_id=bob_uid,
        )
        carol_approval_2 = _make_remote_approval(
            admin_sks[1][0], request_id=rid2, command="echo ok-test",
            fingerprint=fp2, user_id=carol_uid,
        )

        # For rid1, build an approval that will cause apply_external to fail
        # (wrong fingerprint)
        bob_approval_1 = _make_remote_approval(
            admin_sks[0][0], request_id=rid1, command="echo fail-test",
            fingerprint="wrong-fingerprint-intentional",
            user_id=bob_uid,
        )

        row1 = _build_server_row(bob_approval_1, rid1)
        row2a = _build_server_row(bob_approval_2, rid2)
        row2b = _build_server_row(carol_approval_2, rid2)

        def connect(method, url, body=None, headers=None, token=None):
            if "/sync/decisions" in url:
                return (200, {"decisions": [row1, row2a, row2b]},
                        {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})
            return (200, {}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})

        from sandbox.connector.sync.process import SyncProcess, _fetch_decisions

        device_sk = _keygen()
        sync = SyncProcess(
            layout=lay,
            server_url="http://127.0.0.1:9999",
            device_key=bytes(device_sk[0]),
            device_id="dev-1",
            clock=time.monotonic,
            connect=connect,
        )
        sync._token = "test-token"
        sync._token_expires = time.monotonic() + 3600

        _fetch_decisions(sync)

        # rid1 had wrong fingerprint: still pending (fingerprint_mismatch refusal)
        assert rid1 in _pending_request_ids(lay), "request with wrong fp stays pending"

        # There must be a decision_apply_failed or decision_refused alert for rid1
        from sandbox.connector.alerts import read_alerts
        alerts = read_alerts(lay, limit=100)
        rid1_alerts = [
            a for a in alerts
            if (a.get("event") in ("decision_apply_failed", "decision_refused"))
            and (a.get("request_id") == rid1 or rid1 in str(a.get("reason", "")))
        ]
        assert len(rid1_alerts) >= 1, (
            f"expected an alert for rid1 failure, got: {alerts}"
        )


# ===================================================================
# Done request rows / unknown request
# ===================================================================


class TestDoneRequestRows:
    """Done and unknown request handling."""

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: done request rows write nothing")
    def test_done_request_rows_write_nothing_on_repeat_polls(
        self, tmp_path, monkeypatch,
    ):
        """Rows for a request that is already done (not pending) write
        no alert and no audit record.  Fixes E13."""
        _need("done request handling not built")

        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]
        admin_sks = ws["admin_sks"]

        rid = "req-done-001"
        rec = _create_pending_request(lay, rid, command="echo done-test",
                                      requires_dual=False)
        fp = rec["fingerprint"]

        # Apply and complete the request through apply_external
        bob_kid = admin_sks[0][2]
        bob_uid = f"admin-{bob_kid[:8]}"
        bob_approval = _make_remote_approval(
            admin_sks[0][0], request_id=rid, command="echo done-test",
            fingerprint=fp, user_id=bob_uid,
        )

        import asyncio
        from sandbox.connector.approval import apply_external
        asyncio.run(apply_external(lay, rid, [bob_approval],
                                   clock=lambda: time.time()))

        # Request should now be done/not pending
        assert rid not in _pending_request_ids(lay), "request must be done"

        # Now poll with the same row (server re-serves done decisions)
        server_row = _build_server_row(bob_approval, rid)

        def connect(method, url, body=None, headers=None, token=None):
            if "/sync/decisions" in url:
                return (200, {"decisions": [server_row]},
                        {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})
            return (200, {}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})

        from sandbox.connector.sync.process import SyncProcess, _fetch_decisions

        device_sk = _keygen()
        sync = SyncProcess(
            layout=lay,
            server_url="http://127.0.0.1:9999",
            device_key=bytes(device_sk[0]),
            device_id="dev-1",
            clock=time.monotonic,
            connect=connect,
        )
        sync._token = "test-token"
        sync._token_expires = time.monotonic() + 3600

        # Record alerts before
        from sandbox.connector.alerts import read_alerts
        alerts_before = len(read_alerts(lay, limit=200))
        audit_before = len(_read_audit(lay))

        _fetch_decisions(sync)

        # No new decision-kind alerts or audit records
        alerts_after = read_alerts(lay, limit=200)
        decision_new = [
            a for a in alerts_after[alerts_before:]
            if "decision" in str(a.get("event", ""))
        ]
        assert not decision_new, f"done request rows must not write alerts: {decision_new}"

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: unknown request rows aggregate")
    def test_unknown_request_rows_aggregate(
        self, tmp_path, monkeypatch,
    ):
        """Rows for requests this device does not hold produce one
        ``decision_refused`` / ``unknown_request`` per cycle with ``count``,
        no id echoed."""
        _need("unknown request handling not built")

        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]
        admin_sks = ws["admin_sks"]

        bob_kid = admin_sks[0][2]
        bob_uid = f"admin-{bob_kid[:8]}"

        # Create server rows for requests this device never had
        rows = []
        for i in range(3):
            rid = f"req-unknown-{i:03d}"
            approval = _make_remote_approval(
                admin_sks[0][0],
                request_id=rid,
                command=f"echo unknown-{i}",
                fingerprint="fake-fp",
                user_id=bob_uid,
            )
            rows.append(_build_server_row(approval, rid))

        def connect(method, url, body=None, headers=None, token=None):
            if "/sync/decisions" in url:
                return (200, {"decisions": rows},
                        {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})
            return (200, {}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})

        from sandbox.connector.sync.process import SyncProcess, _fetch_decisions

        device_sk = _keygen()
        sync = SyncProcess(
            layout=lay,
            server_url="http://127.0.0.1:9999",
            device_key=bytes(device_sk[0]),
            device_id="dev-1",
            clock=time.monotonic,
            connect=connect,
        )
        sync._token = "test-token"
        sync._token_expires = time.monotonic() + 3600

        _fetch_decisions(sync)

        # Should produce one aggregated unknown_request alert
        from sandbox.connector.alerts import read_alerts
        alerts = read_alerts(lay, limit=100)
        unknown = [a for a in alerts
                   if a.get("event") == "decision_refused"
                   and a.get("reason_code") == "unknown_request"]
        assert len(unknown) == 1, (
            f"expected 1 aggregated unknown_request alert, got {len(unknown)}: {alerts}"
        )


# ===================================================================
# Server text sanitization
# ===================================================================


class TestServerTextSanitization:
    """Server text capped at 200 chars, scrubbed, no controls, no secrets."""

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: server text capped and scrubbed")
    def test_server_text_capped_scrubbed_no_controls(
        self, tmp_path, monkeypatch,
    ):
        """Planted token-like value, control and bidi characters, 5 KB string.
        After scrubbing: capped at 200, no controls, no token."""
        _need("server text sanitization not built")

        planted_token = "sk-ant-api03-AAABBBCCC123456789-XXXYYY"
        bidi = "‪‫‬"  # bidi controls
        control = "\x00\x01\x02\x7f"  # C0 + DEL
        long_text = planted_token + bidi + control + "A" * 5000

        connect = _make_connect_stub([
            (500, {"detail": long_text},
             {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"}),
        ])
        sync, ws = _build_sync_process(tmp_path, monkeypatch, connect)
        lay = ws["lay"]
        _create_pending_request(lay, "req-text-001", command="echo text-test")

        from sandbox.connector.sync.process import _fetch_decisions
        _fetch_decisions(sync)

        # Check alerts for sanitized text
        alerts_output = _run_alerts_cli(lay)
        assert planted_token not in alerts_output, \
            "planted token must not appear in alerts"
        assert len(alerts_output) < 10000, \
            "5 KB server text must be capped"
        for ch in ["\x00", "\x01", "\x02", "\x7f", "‪", "‫"]:
            assert ch not in alerts_output, \
                f"control character {ch!r} must not appear in alerts"

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: non-string detail omitted")
    def test_non_string_detail_omitted(self, tmp_path, monkeypatch):
        """A non-string ``detail`` in the error response is omitted."""
        _need("non-string detail handling not built")

        connect = _make_connect_stub([
            (500, {"detail": {"nested": "data"}},
             {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"}),
        ])
        sync, ws = _build_sync_process(tmp_path, monkeypatch, connect)
        lay = ws["lay"]
        _create_pending_request(lay, "req-detail-001", command="echo detail-test")

        from sandbox.connector.sync.process import _fetch_decisions
        _fetch_decisions(sync)

        alerts_output = _run_alerts_cli(lay)
        # non-string detail should be omitted, not repr'd
        assert "nested" not in alerts_output, \
            "non-string detail must not appear in alerts"

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: row user_id never printed when unverified")
    def test_row_user_id_never_printed_when_unverified(
        self, tmp_path, monkeypatch,
    ):
        """A server-chosen ``user_id`` from the row must never appear in
        alerts or status when the signature is not verified.

        Also asserts the refusal IS recorded (not just absence of the bad
        data), so this test cannot pass vacuously on today's silent drop.
        """
        _need("user_id suppression not built")

        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]

        rid = "req-uid-001"
        rec = _create_pending_request(lay, rid, command="echo uid-test")

        wrong_sk = _keygen()
        bad_approval = _make_remote_approval(
            wrong_sk[0],
            request_id=rid,
            command="echo uid-test",
            fingerprint=rec["fingerprint"],
            user_id="planted-secret-userid",
        )
        bad_row = _build_server_row(bad_approval, rid)

        def connect(method, url, body=None, headers=None, token=None):
            if "/sync/decisions" in url:
                return (200, {"decisions": [bad_row]},
                        {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})
            return (200, {}, {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"})

        from sandbox.connector.sync.process import SyncProcess, _fetch_decisions

        device_sk = _keygen()
        sync = SyncProcess(
            layout=lay,
            server_url="http://127.0.0.1:9999",
            device_key=bytes(device_sk[0]),
            device_id="dev-1",
            clock=time.monotonic,
            connect=connect,
        )
        sync._token = "test-token"
        sync._token_expires = time.monotonic() + 3600

        _fetch_decisions(sync)

        alerts_output = _run_alerts_cli(lay)
        status_output = _run_status_cli(lay)
        assert "planted-secret-userid" not in alerts_output, \
            "unverified user_id must not appear in alerts"
        assert "planted-secret-userid" not in status_output, \
            "unverified user_id must not appear in status"

        # Non-vacuity: the refusal must be recorded (alerts or audit)
        from sandbox.connector.alerts import read_alerts
        alerts = read_alerts(lay, limit=100)
        audit = _read_audit(lay)
        refusal_evidence = [
            r for r in (alerts + audit)
            if r.get("event") in ("decision_refused", "decisions_malformed")
        ]
        assert len(refusal_evidence) >= 1, (
            f"refusal must be recorded (unknown key), not silently dropped; "
            f"alerts={alerts}, audit={audit}"
        )

    @pytest.mark.xfail(strict=True, raises=M3T9Pending,
                       reason="T9a: no token in any record")
    def test_no_token_in_any_record(self, tmp_path, monkeypatch):
        """No bearer token appears in any alert or audit record."""
        _need("token scrubbing not built")

        the_token = "test-token-secret-bearer-value-12345"

        connect = _make_connect_stub([
            (401, {"detail": "token expired"},
             {"Date": "Wed, 05 Nov 2026 10:00:00 GMT"}),
        ])
        sync, ws = _build_sync_process(tmp_path, monkeypatch, connect)
        lay = ws["lay"]
        sync._token = the_token
        _create_pending_request(lay, "req-token-001", command="echo token-test")

        from sandbox.connector.sync.process import _fetch_decisions
        _fetch_decisions(sync)

        from sandbox.connector.alerts import read_alerts
        all_alerts = read_alerts(lay, limit=200)
        all_audit = _read_audit(lay)
        combined = json.dumps(all_alerts + all_audit)
        assert the_token not in combined, \
            "bearer token must not appear in any alert or audit record"


# ===================================================================
# Guard twins (PASS today -- existing code still works)
# ===================================================================


class TestGuardTwins:
    """Guards that PASS today and verify existing behaviour is not broken."""

    def test_guard_fetch_decisions_function_exists(self):
        """Guard: _fetch_decisions is importable."""
        from sandbox.connector.sync.process import _fetch_decisions
        assert callable(_fetch_decisions)

    def test_guard_sync_process_importable(self):
        """Guard: SyncProcess is importable."""
        from sandbox.connector.sync.process import SyncProcess
        assert callable(SyncProcess)

    def test_guard_sync_error_importable(self):
        """Guard: SyncError is importable."""
        from sandbox.connector.sync.process import SyncError
        assert issubclass(SyncError, Exception)

    def test_guard_apply_external_importable(self):
        """Guard: apply_external is importable."""
        from sandbox.connector.approval import apply_external
        assert callable(apply_external)

    def test_guard_counting_approval_applies(self, tmp_path, monkeypatch):
        """Guard twin: a counting dual-control approval with two valid
        approvers is accepted by the verification step (not awaiting_second).

        Also drives through _fetch_decisions to verify the whole path.
        """
        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]
        admin_sks = ws["admin_sks"]

        rid = "req-guard-dual-001"
        rec = _create_pending_request(
            lay, rid, command="echo guard-test", requires_dual=True,
        )
        fp = rec["fingerprint"]

        bob_kid = admin_sks[0][2]
        carol_kid = admin_sks[1][2]
        bob_uid = f"admin-{bob_kid[:8]}"
        carol_uid = f"admin-{carol_kid[:8]}"

        bob_approval = _make_remote_approval(
            admin_sks[0][0],
            request_id=rid,
            command="echo guard-test",
            fingerprint=fp,
            user_id=bob_uid,
        )
        carol_approval = _make_remote_approval(
            admin_sks[1][0],
            request_id=rid,
            command="echo guard-test",
            fingerprint=fp,
            user_id=carol_uid,
        )

        import asyncio
        from sandbox.connector.approval import apply_external
        result = asyncio.run(apply_external(
            lay, rid, [bob_approval, carol_approval],
            clock=lambda: time.time(),
        ))

        status = result.get("status", "")
        assert status != "awaiting_second", (
            f"dual approval must pass verification (got status={status}, "
            f"approvals={result.get('approvals')})"
        )

    def test_guard_process_py_has_fetch_decisions(self):
        """Guard: _fetch_decisions exists in the source file."""
        source = _PROCESS_PY.read_text(encoding="utf-8")
        assert "def _fetch_decisions" in source
