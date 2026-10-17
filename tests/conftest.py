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
