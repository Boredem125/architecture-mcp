"""AgentIdentity resolution from payload + session.json."""
from __future__ import annotations

import json

from sandbox.connector.identity import AgentIdentity, from_payload
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout


def test_from_payload_resolves_session_and_project(tmp_path):
    init(tmp_path, claude=False, mcp=False)
    layout = FolderLayout(tmp_path)
    session = json.loads(layout.session_file.read_text())

    payload = {
        "tool_name": "Bash",
        "session_id": "agent-sess-1",
        "agent": {"kind": "claude-code", "model": "claude-opus-4-8"},
    }
    ident = from_payload(payload, layout)
    assert ident.agent_type == "claude-code"
    assert ident.model == "claude-opus-4-8"
    assert ident.project == tmp_path.name
    # session_id prefers the payload's agent session id
    assert ident.session_id == "agent-sess-1"


def test_from_payload_defaults_when_sparse(tmp_path):
    init(tmp_path, claude=False, mcp=False)
    layout = FolderLayout(tmp_path)
    ident = from_payload({"tool_name": "Read"}, layout)
    assert ident.agent_type == "claude-code"  # default surface
    assert ident.trust_level == "standard"
    assert ident.agent_id  # never empty


def test_label_is_compact():
    ident = AgentIdentity(agent_type="codex", model="gpt-x", user="alice")
    assert ident.label() == "codex(gpt-x)/alice"


def test_to_dict_roundtrips():
    ident = AgentIdentity(agent_id="a", agent_type="mcp", user="bob")
    d = ident.to_dict()
    assert d["agent_id"] == "a"
    assert d["user"] == "bob"
    assert d["trust_level"] == "standard"
