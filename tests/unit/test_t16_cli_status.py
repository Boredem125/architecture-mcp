"""T16c-1 (F-4): sandbox status surfaces managed / locked (moved out of the frozen test_cli_connector.py)."""
from __future__ import annotations

from click.testing import CliRunner

from sandbox.cli.main import cli



# ---------------------------------------------------------------------------
# T16c-1: status_cmd must surface managed / locked from sync/state.py
# ---------------------------------------------------------------------------
# Product gap: status_cmd does not yet call is_managed / is_locked.
# These strict-xfail tests prove that once it does, the output contains
# the expected fields in both text and --json modes.

import json as _json
import pytest


class M2T16StatusPending(Exception):
    """Raised when status_cmd does not yet include managed/locked fields."""


def _make_managed(tmp_path):
    """Create a .sandbox workspace that is_managed() recognises as managed."""
    runner = CliRunner()
    r = runner.invoke(cli, ["init", str(tmp_path), "--no-claude"])
    assert r.exit_code == 0, r.output
    # Write the sync-dir managed marker so is_managed() returns True
    sync_dir = tmp_path / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    (sync_dir / "managed").write_text("1", encoding="utf-8")
    return runner


def test_t16_status_text_shows_managed(tmp_path):
    """Text output must contain a 'Managed: yes' (or similar) line."""
    runner = _make_managed(tmp_path)
    r = runner.invoke(cli, ["status", str(tmp_path)])
    assert r.exit_code == 0, r.output
    lower = r.output.lower()
    if "managed" not in lower:
        raise M2T16StatusPending("text output lacks 'managed' field")
    assert "yes" in lower or "true" in lower, f"managed present but not affirmative: {r.output}"


def test_t16_status_json_shows_managed(tmp_path):
    """JSON output must contain a 'managed' key set to true."""
    runner = _make_managed(tmp_path)
    r = runner.invoke(cli, ["status", str(tmp_path), "--json"])
    assert r.exit_code == 0, r.output
    data = _json.loads(r.output)
    if "managed" not in data:
        raise M2T16StatusPending("JSON output lacks 'managed' key")
    assert data["managed"] is True, f"managed key present but not True: {data}"


def test_t16_status_text_shows_locked(tmp_path):
    """Text output must contain a 'Locked: yes' line when managed + no bundle."""
    runner = _make_managed(tmp_path)
    # managed marker exists but NO bundle.json and NO policy_history
    # so is_locked() returns True
    r = runner.invoke(cli, ["status", str(tmp_path)])
    assert r.exit_code == 0, r.output
    lower = r.output.lower()
    if "locked" not in lower:
        raise M2T16StatusPending("text output lacks 'locked' field")
    assert "yes" in lower or "true" in lower, f"locked present but not affirmative: {r.output}"


def test_t16_status_json_shows_locked(tmp_path):
    """JSON output must contain a 'locked' key set to true when managed + no bundle."""
    runner = _make_managed(tmp_path)
    r = runner.invoke(cli, ["status", str(tmp_path), "--json"])
    assert r.exit_code == 0, r.output
    data = _json.loads(r.output)
    if "locked" not in data:
        raise M2T16StatusPending("JSON output lacks 'locked' key")
    assert data["locked"] is True, f"locked key present but not True: {data}"


def test_t16_status_unmanaged_no_managed_field(tmp_path):
    """Guard twin: unmanaged workspace must NOT claim managed in --json."""
    runner = CliRunner()
    r = runner.invoke(cli, ["init", str(tmp_path), "--no-claude"])
    assert r.exit_code == 0, r.output
    r2 = runner.invoke(cli, ["status", str(tmp_path), "--json"])
    assert r2.exit_code == 0, r2.output
    data = _json.loads(r2.output)
    # managed may be absent or False; must not be True
    assert data.get("managed") is not True, f"unmanaged workspace claims managed: {data}"
