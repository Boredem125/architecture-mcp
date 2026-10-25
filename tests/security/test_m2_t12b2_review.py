"""T12b-2 security review round 2, connector side (security-engineer, leader tier).

S2 (Medium, C9 items 3 and 8, WYSIWYS): ``sandbox signer approve|deny``
echoes server-supplied strings (command, request_id, ids, fingerprint) raw
to the approver's terminal.  The command is chosen by the agent, so it can
carry ANSI/VT control sequences (ESC [ 2K, carriage return, cursor moves)
that redraw the "Command:" line as something harmless.  The human approves
what the terminal shows, the signature binds the real command, and the
connector runs the real command.  Control characters must be escaped or the
signer must refuse to sign.

ADR 0010 s7: deny stays allowed when a field has control characters (deny
only stops an action).  The escaped values are shown.

Strict xfail, ``raises=T12b2Finding``: any other failure (setup, network)
does not match and fails the run.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from tests.m2_fakes import FakeSyncServer, FakeResponse
from tests.security.test_m2_t12_remote import _keygen, _setup_managed_workspace


class T12b2Finding(AssertionError):
    """Raised while an open T12b-2 review finding is still exploitable."""


_SPOOF = "rm -rf ~/prod-backups\r\x1b[2K\x1b[1ACommand:         echo hello"


def test_s2_signer_display_escapes_control_sequences(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from sandbox.cli.sync_cmds import signer_approve
    from sandbox.connector.keyhome import key_home_root, workspace_id as _wsid

    bob = _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[(bob[0], bob[1], bob[2], "user-bob", "cli")],
    )
    lay = ctx["lay"]
    ws_dir = key_home_root() / _wsid(lay, create=True)
    ws_dir.mkdir(parents=True, exist_ok=True)
    (ws_dir / f"{bob[2][:16]}.seed").write_bytes(bytes(bob[0]))

    esc_id = "esc-s2-1"
    detail = {
        "escalation_id": esc_id,
        "request_id": "req-s2-1",
        "command": _SPOOF,
        "fingerprint": hashlib.sha256(_SPOOF.encode()).hexdigest(),
        "device_id": ctx.get("device_id", "dev-1"),
        "project_id": ctx.get("project_id", "proj-1"),
        "org_id": ctx.get("org_id", "org-1"),
        "policy_sequence": ctx["policy_sequence"],
        "requires_dual": True,
        "status": "pending",
    }
    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/signer/token")] = FakeResponse(
            200, {"token": "fake-signer-token-s2"},  # gitleaks:allow
        )
        srv.routes[("GET", f"/api/v1/sync/escalations/{esc_id}")] = FakeResponse(
            200, detail,
        )
        srv.routes[("POST", f"/api/v1/sync/escalations/{esc_id}/approvals")] = (
            FakeResponse(200, {"approval_id": "appr-s2"})
        )
        monkeypatch.chdir(str(lay.root))
        result = CliRunner().invoke(
            signer_approve, [esc_id, "--server", srv.base_url, "--yes"],
        )
        posted = [r for r in srv.requests
                  if r["method"] == "POST" and r["path"].endswith("/approvals")]

    assert result.exception is None or isinstance(result.exception, SystemExit), (
        f"signer approve crashed: {result.exception!r}\n{result.output}"
    )
    if "\x1b" in result.output or "\r" in result.output:
        raise T12b2Finding(
            "signer echoed raw control sequences from the server-supplied "
            f"command and {'signed' if posted else 'did not sign'} it: "
            f"{json.dumps(result.output)[:300]}"
        )


def test_s2_signer_approve_refuses_control_chars(tmp_path, monkeypatch):
    """ADR 0010 s7: signer approve MUST refuse when fields contain
    control characters.  Exit non-zero, no approval POST.
    """
    from click.testing import CliRunner

    from sandbox.cli.sync_cmds import signer_approve
    from sandbox.connector.keyhome import key_home_root, workspace_id as _wsid

    bob = _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[(bob[0], bob[1], bob[2], "user-bob", "cli")],
    )
    lay = ctx["lay"]
    ws_dir = key_home_root() / _wsid(lay, create=True)
    ws_dir.mkdir(parents=True, exist_ok=True)
    (ws_dir / f"{bob[2][:16]}.seed").write_bytes(bytes(bob[0]))

    esc_id = "esc-approve-ctrl"
    detail = {
        "escalation_id": esc_id,
        "request_id": "req-approve-ctrl",
        "command": _SPOOF,
        "fingerprint": hashlib.sha256(_SPOOF.encode()).hexdigest(),
        "device_id": ctx.get("device_id", "dev-1"),
        "project_id": ctx.get("project_id", "proj-1"),
        "org_id": ctx.get("org_id", "org-1"),
        "policy_sequence": ctx["policy_sequence"],
        "requires_dual": True,
        "status": "pending",
    }
    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/signer/token")] = FakeResponse(
            200, {"token": "fake-signer-token-appctrl"},  # gitleaks:allow
        )
        srv.routes[("GET", f"/api/v1/sync/escalations/{esc_id}")] = FakeResponse(
            200, detail,
        )
        srv.routes[("POST", f"/api/v1/sync/escalations/{esc_id}/approvals")] = (
            FakeResponse(200, {"approval_id": "appr-appctrl"})
        )
        monkeypatch.chdir(str(lay.root))
        result = CliRunner().invoke(
            signer_approve, [esc_id, "--server", srv.base_url, "--yes"],
        )
        posted = [r for r in srv.requests
                  if r["method"] == "POST" and r["path"].endswith("/approvals")]

    # approve must exit non-zero (refuse)
    assert result.exit_code != 0, (
        f"signer approve should refuse control chars, but exited {result.exit_code}"
    )
    # No approval should have been posted
    assert len(posted) == 0, (
        "signer approve should not POST an approval when control chars are present"
    )


def test_s2_signer_deny_allowed_with_control_chars(tmp_path, monkeypatch):
    """ADR 0010 s7: signer deny MUST be allowed even when fields contain
    control characters (deny only stops an action).  The escaped values
    are shown, and the deny envelope is POSTed.
    """
    from click.testing import CliRunner

    from sandbox.cli.sync_cmds import signer_deny
    from sandbox.connector.keyhome import key_home_root, workspace_id as _wsid

    bob = _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[(bob[0], bob[1], bob[2], "user-bob", "cli")],
    )
    lay = ctx["lay"]
    ws_dir = key_home_root() / _wsid(lay, create=True)
    ws_dir.mkdir(parents=True, exist_ok=True)
    (ws_dir / f"{bob[2][:16]}.seed").write_bytes(bytes(bob[0]))

    esc_id = "esc-deny-ctrl"
    detail = {
        "escalation_id": esc_id,
        "request_id": "req-deny-ctrl",
        "command": _SPOOF,
        "fingerprint": hashlib.sha256(_SPOOF.encode()).hexdigest(),
        "device_id": ctx.get("device_id", "dev-1"),
        "project_id": ctx.get("project_id", "proj-1"),
        "org_id": ctx.get("org_id", "org-1"),
        "policy_sequence": ctx["policy_sequence"],
        "requires_dual": True,
        "status": "pending",
    }
    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/signer/token")] = FakeResponse(
            200, {"token": "fake-signer-token-denyctrl"},  # gitleaks:allow
        )
        srv.routes[("GET", f"/api/v1/sync/escalations/{esc_id}")] = FakeResponse(
            200, detail,
        )
        srv.routes[("POST", f"/api/v1/sync/escalations/{esc_id}/approvals")] = (
            FakeResponse(200, {"approval_id": "appr-denyctrl"})
        )
        monkeypatch.chdir(str(lay.root))
        result = CliRunner().invoke(
            signer_deny, [esc_id, "--server", srv.base_url, "--yes"],
        )
        posted = [r for r in srv.requests
                  if r["method"] == "POST" and r["path"].endswith("/approvals")]

    # deny must succeed (exit 0)
    assert result.exit_code == 0, (
        f"signer deny should allow control chars, but exited {result.exit_code}: "
        f"{result.output}"
    )
    # The deny envelope should have been POSTed
    assert len(posted) == 1, (
        "signer deny should POST the deny envelope even with control chars"
    )
    # Verify the output shows escaped values (no raw control sequences)
    assert "\x1b" not in result.output, (
        "signer deny should show escaped values, not raw control sequences"
    )
    assert "\r" not in result.output, (
        "signer deny should show escaped values, not raw carriage returns"
    )
    # Verify the output mentions "WARNING" for the control characters
    assert "WARNING" in result.output or "control" in result.output.lower(), (
        "signer deny should warn about control characters"
    )
