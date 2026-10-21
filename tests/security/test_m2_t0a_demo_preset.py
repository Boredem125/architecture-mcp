"""T0a: pin the ``steal-env`` demo preset as the M2 dual-control demo preset.

The preset already sets ``requires_dual: true`` with the semantic service
absent, via the deterministic exfil detector (``.env`` sensitive source +
``curl -d`` egress).  This test locks that property so it cannot regress
before the M2 demo (step 5) exercises live dual control with it.
"""
from __future__ import annotations

import asyncio
import importlib
import socket
from pathlib import Path

import pytest

from sandbox.connector.hook_eval import pre_tool_use
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import load_policy, save_policy
from sandbox.connector.queue import EscalationQueue

# ---------------------------------------------------------------------------
# The frozen preset: steal-env
# ---------------------------------------------------------------------------

PRESET_NAME = "steal-env"


def _load_presets() -> dict:
    """Import demo/try.py and return its PRESETS dict."""
    spec = importlib.util.spec_from_file_location(
        "demo_try", Path(__file__).resolve().parents[2] / "demo" / "try.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.PRESETS


PRESETS = _load_presets()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def layout(tmp_path):
    init(tmp_path, claude=False, mcp=False)
    layout = FolderLayout(tmp_path)
    policy = load_policy(layout.policy_file)
    # Semantic service absent: disabled and unreachable.
    policy.semantic.enabled = False
    policy.semantic.url = f"http://127.0.0.1:{_free_port()}"
    policy.escalation_timeout_seconds = 1
    save_policy(policy, layout.policy_file)
    return layout


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_steal_env_preset_exists():
    """The preset must exist in demo/try.py."""
    assert PRESET_NAME in PRESETS, f"preset {PRESET_NAME!r} not found in demo/try.py PRESETS"


def test_steal_env_preset_is_a_bash_command():
    kind, target, _extra = PRESETS[PRESET_NAME]
    assert kind == "bash", f"expected kind='bash', got {kind!r}"
    assert target, "target must not be empty"


def test_steal_env_escalates_as_dual_control(layout):
    """The preset must set requires_dual=True through the exfil detector."""
    kind, target, _extra = PRESETS[PRESET_NAME]
    assert kind == "bash"
    out = asyncio.run(pre_tool_use(
        {"tool_name": "Bash", "tool_input": {"command": target},
         "cwd": str(layout.root), "session_id": "t0a-preset"},
        layout,
    ))["hookSpecificOutput"]
    # Escalated (returned as "deny" with the queue populated).
    assert out["permissionDecision"] == "deny", "preset must escalate"
    pending = EscalationQueue(layout).list_pending()
    assert len(pending) == 1, f"expected exactly 1 pending, got {len(pending)}"
    rec = pending[0]
    assert rec["requires_dual"] is True, "preset must set requires_dual"
    assert rec["reason_code"] == "EXFIL", f"expected EXFIL, got {rec.get('reason_code')}"


def test_steal_env_risk_band_is_critical(layout):
    """The exfil detector pushes risk to critical."""
    _kind, target, _extra = PRESETS[PRESET_NAME]
    asyncio.run(pre_tool_use(
        {"tool_name": "Bash", "tool_input": {"command": target},
         "cwd": str(layout.root), "session_id": "t0a-risk"},
        layout,
    ))
    rec = EscalationQueue(layout).list_pending()[0]
    assert rec["risk"]["band"] == "critical"
    assert any(f["name"] == "exfiltration" for f in rec["risk"]["factors"])


def test_steal_env_exfil_detection_is_deterministic():
    """The exfil detection is pattern-based, not model-based."""
    from sandbox.safety.exfil import detect

    _kind, target, _extra = PRESETS[PRESET_NAME]
    finding = detect(target)
    assert finding is not None, "exfil detector must find the pattern"
    assert ".env" in finding.sensitive or "env" in finding.sensitive
    assert finding.egress, "must identify an egress technique"
