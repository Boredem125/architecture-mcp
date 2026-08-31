"""FolderPolicy defaults + the non-removable .sandbox self-protection."""
from __future__ import annotations

import json

from sandbox.connector.policy import default_policy, load_policy, save_policy


def test_defaults_have_protections(tmp_path):
    p = default_policy()
    assert ".sandbox/**" in p.write.deny_globs
    assert any("sandbox" in pat for pat in p.shell.deny_patterns)


def test_protection_reinjected_even_if_removed(tmp_path):
    path = tmp_path / "policy.json"
    save_policy(default_policy(), path)

    # Agent tampers: strip the self-protection from the file.
    data = json.loads(path.read_text())
    data["write"]["deny_globs"] = []
    data["shell"]["deny_patterns"] = []
    path.write_text(json.dumps(data), encoding="utf-8")

    # load_policy must put them back.
    reloaded = load_policy(path)
    assert ".sandbox/**" in reloaded.write.deny_globs
    assert any("sandbox" in pat for pat in reloaded.shell.deny_patterns)


def test_malformed_policy_falls_back_to_defaults(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text("{ not valid json", encoding="utf-8")
    p = load_policy(path)
    assert p.mode == "enforce"
    assert ".sandbox/**" in p.write.deny_globs


def test_missing_policy_is_safe_default(tmp_path):
    p = load_policy(tmp_path / "nope.json")
    assert p.fail_mode == "closed"
    assert p.triggers.shell == "escalate"
