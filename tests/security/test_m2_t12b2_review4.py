"""T12b-2 security re-review round 3, connector side (security-engineer, leader tier).

F8 (Low, ADR 0010 s7, WYSIWYS; residual of round-2 F3): the server now
returns kind, tool_name and bundle_sequence in GET detail, but
``sandbox signer approve`` (and ``deny``) never print them.  s7 says the
signer shows every field the binding fingerprint covers (kind, tool,
command, exec_cwd, root, requires_dual, bundle_sequence, request_id)
before a human signs.  The fingerprint still binds the real values, so
nothing other than the recorded action can run; the gap is that the human
approves an MCP tool call while the CLI shows only "Command: ...".  The
web inbox shows them (binding details cell).

Strict xfail, ``raises=T12b2R4Finding``: any other failure (setup, crash)
does not match and fails the run.
"""
from __future__ import annotations

import hashlib

import pytest

from tests.m2_fakes import FakeSyncServer, FakeResponse
from tests.security.test_m2_t12_remote import _keygen, _setup_managed_workspace


class T12b2R4Finding(AssertionError):
    """Raised while an open T12b-2 round-3 re-review finding is exploitable."""


_TOOL = "mcp__payments__refund"


def test_f8_signer_approve_shows_kind_tool_bundle_sequence(tmp_path, monkeypatch):
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

    esc_id = "esc-r4-f8"
    command = '{"amount": 40000}'
    detail = {
        "escalation_id": esc_id,
        "request_id": "req-r4-f8",
        "command": command,
        "fingerprint": hashlib.sha256(command.encode()).hexdigest(),
        "device_id": ctx.get("device_id", "dev-1"),
        "project_id": ctx.get("project_id", "proj-1"),
        "org_id": ctx.get("org_id", "org-1"),
        "policy_sequence": ctx["policy_sequence"],
        "requires_dual": True,
        "status": "pending",
        "exec_cwd": "/srv/repo",
        "root": "/srv/repo",
        "kind": "tool_call",
        "tool_name": _TOOL,
        "bundle_sequence": 4242,
    }
    from sandbox.connector.approval import _binding_fingerprint
    detail["fingerprint"] = _binding_fingerprint(detail)
    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/signer/token")] = FakeResponse(
            200, {"token": "fake-signer-token-r4f8"},  # gitleaks:allow
        )
        srv.routes[("GET", f"/api/v1/sync/escalations/{esc_id}")] = FakeResponse(
            200, detail,
        )
        srv.routes[("POST", f"/api/v1/sync/escalations/{esc_id}/approvals")] = (
            FakeResponse(200, {"approval_id": "appr-r4f8"})
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
    assert posted, f"proof is vacuous: nothing was posted\n{result.output}"
    missing = [v for v in ("tool_call", _TOOL, "4242") if v not in result.output]
    if missing:
        raise T12b2R4Finding(
            f"signer approve signed and posted without showing {missing}: "
            f"{result.output!r}"
        )


def test_guard_signer_approve_refuses_fingerprint_mismatch(tmp_path, monkeypatch):
    """Guard (round 4): the CLI recomputes the binding fingerprint from the
    fields it displays and refuses, signing and posting nothing, when the
    server's fingerprint does not match (a server showing one command while
    passing the fingerprint of another)."""
    from click.testing import CliRunner

    from sandbox.cli.sync_cmds import signer_approve
    from sandbox.connector.approval import _binding_fingerprint
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

    esc_id = "esc-r4-guard"
    real = {"kind": "bash", "tool_name": "Bash", "command": "rm -rf ~/prod",
            "exec_cwd": "/srv/repo", "root": "/srv/repo", "requires_dual": True,
            "bundle_sequence": 1, "request_id": "req-r4-guard"}
    shown = dict(real, command="echo hello")
    detail = dict(shown, escalation_id=esc_id,
                  fingerprint=_binding_fingerprint(real),
                  device_id="dev-1", project_id="proj-1", org_id="org-1",
                  policy_sequence=ctx["policy_sequence"], status="pending")
    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/signer/token")] = FakeResponse(
            200, {"token": "fake-signer-token-r4g"},  # gitleaks:allow
        )
        srv.routes[("GET", f"/api/v1/sync/escalations/{esc_id}")] = FakeResponse(
            200, detail,
        )
        srv.routes[("POST", f"/api/v1/sync/escalations/{esc_id}/approvals")] = (
            FakeResponse(200, {"approval_id": "appr-r4g"})
        )
        monkeypatch.chdir(str(lay.root))
        result = CliRunner().invoke(
            signer_approve, [esc_id, "--server", srv.base_url, "--yes"],
        )
        posted = [r for r in srv.requests
                  if r["method"] == "POST" and r["path"].endswith("/approvals")]

    assert result.exit_code != 0, result.output
    assert not posted, "signed and posted despite a fingerprint mismatch"
    assert "echo hello" not in result.output, "mismatched command was displayed"
