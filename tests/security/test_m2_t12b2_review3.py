"""T12b-2 security re-review round 2, connector side (security-engineer, leader tier).

F1 (Medium, ADR 0010 s7, WYSIWYS): ``sandbox signer approve`` checks only
some server-supplied fields for control characters (request_id, command,
ids, fingerprint, root, exec_cwd).  It then prints ``requires_dual`` and
``policy_sequence`` from the server response raw.  ``requires_dual`` is not
signed and not bound by the connector, so a compromised server can put
ANSI/VT sequences there that move the cursor up and redraw the
"Command:" line as something harmless.  The signer still signs the real
command, the server binding check and the connector both accept it (it
matches the pending record), and the broker runs it.  ADR 0010 s7 covers
"every other server-supplied string it displays or signs".

Strict xfail, ``raises=T12b2R3Finding``: any other failure (setup, crash)
does not match and fails the run.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from tests.m2_fakes import FakeSyncServer, FakeResponse
from tests.security.test_m2_t12_remote import _keygen, _setup_managed_workspace


class T12b2R3Finding(AssertionError):
    """Raised while an open T12b-2 round-2 re-review finding is exploitable."""


_REAL_COMMAND = "rm -rf ~/prod-backups"
# Move the cursor up over Fingerprint/Policy sequence/Device.../Command,
# erase the line and draw a harmless command in its place.
_ESC_IN_UNCHECKED_FIELD = (
    "\x1b[8A\x1b[2KCommand:         echo hello\x1b[8B\rRequires dual:   True"
)


def test_f1_signer_approve_checks_every_displayed_field(tmp_path, monkeypatch):
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

    esc_id = "esc-r3-f1"
    detail = {
        "escalation_id": esc_id,
        "request_id": "req-r3-f1",
        "command": _REAL_COMMAND,
        "fingerprint": hashlib.sha256(_REAL_COMMAND.encode()).hexdigest(),
        "device_id": ctx.get("device_id", "dev-1"),
        "project_id": ctx.get("project_id", "proj-1"),
        "org_id": ctx.get("org_id", "org-1"),
        "policy_sequence": ctx["policy_sequence"],
        "requires_dual": _ESC_IN_UNCHECKED_FIELD,
        "status": "pending",
        "exec_cwd": "/srv/repo",
        "root": "/srv/repo",
        # T12c c2 named test-setup edit: fp_v 2 and script fields
        "fp_v": 2,
        "script": None,
        "script_unbound": "",
        "script_preview": None,
    }
    # Round 3: a consistent server fingerprint, so the round-4 local
    # recompute does not refuse first and the display check stays live.
    from sandbox.connector.approval import _binding_fingerprint
    detail["fingerprint"] = _binding_fingerprint(detail)
    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/signer/token")] = FakeResponse(
            200, {"token": "fake-signer-token-r3f1"},  # gitleaks:allow
        )
        srv.routes[("GET", f"/api/v1/sync/escalations/{esc_id}")] = FakeResponse(
            200, detail,
        )
        srv.routes[("POST", f"/api/v1/sync/escalations/{esc_id}/approvals")] = (
            FakeResponse(200, {"approval_id": "appr-r3f1"})
        )
        monkeypatch.chdir(str(lay.root))
        result = CliRunner().invoke(
            signer_approve, [esc_id, "--server", srv.base_url, "--yes"],
            color=True,  # a real terminal: click keeps ANSI on a TTY
        )
        posted = [r for r in srv.requests
                  if r["method"] == "POST" and r["path"].endswith("/approvals")]

    assert result.exception is None or isinstance(result.exception, SystemExit), (
        f"signer approve crashed: {result.exception!r}\n{result.output}"
    )
    assert posted, f"proof is vacuous: nothing was posted\n{result.output}"
    if posted and "\x1b" in result.output:
        signed_cmd = ""
        try:
            signed_cmd = json.loads(posted[0]["body"])["payload"]["command"]
        except Exception:  # noqa: BLE001 -- only for the message
            pass
        raise T12b2R3Finding(
            "signer approve echoed raw ESC sequences from requires_dual and "
            f"signed command {signed_cmd!r}: {json.dumps(result.output)[:300]}"
        )
