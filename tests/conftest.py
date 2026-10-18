from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture
def tmp_audit_dir(tmp_path):
    audit_dir = tmp_path / "audit_logs"
    audit_dir.mkdir()
    return str(audit_dir)


@pytest.fixture(autouse=True)
def _isolated_key_home(tmp_path_factory, monkeypatch):
    """M1 T2 (ADR 0007): signing keys live in a key home outside every workspace. Point it at a
    per-test directory so no test writes the real user directory. Sets only SANDBOX_KEY_HOME."""
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(tmp_path_factory.mktemp("keyhome")))
