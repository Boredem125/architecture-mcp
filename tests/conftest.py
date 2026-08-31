from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture
def session_token() -> str:
    from sandbox.crypto.tokens import TokenIssuer

    issuer = TokenIssuer(secret="test-secret-key-for-testing-only")
    return issuer.issue_token(
        agent_id="test-agent",
        session_id="test-session-001",
        allowed_actions=["READ", "WRITE"],
        workspace_root="/tmp/workspace",
        expires_in_seconds=3600,
    )


@pytest.fixture
def token_issuer() -> object:
    from sandbox.crypto.tokens import TokenIssuer

    return TokenIssuer(secret="test-secret-key-for-testing-only")


@pytest.fixture
def tmp_audit_dir(tmp_path):
    audit_dir = tmp_path / "audit_logs"
    audit_dir.mkdir()
    return str(audit_dir)
