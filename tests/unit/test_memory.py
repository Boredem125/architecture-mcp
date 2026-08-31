"""DecisionMemory — remembered decisions with session invalidation."""
from __future__ import annotations

import json

import pytest

from sandbox.connector.memory import DecisionMemory


def test_once_is_not_stored(tmp_path):
    mem = DecisionMemory(tmp_path / "remembered.json", "s-1")
    mem.remember("once", "anything")
    assert mem.entries() == []


def test_command_scope_exact_match(tmp_path):
    path = tmp_path / "remembered.json"
    mem = DecisionMemory(path, "s-1")
    mem.remember("command", "npm install -g typescript")

    # Re-load (simulate a new hook process).
    mem2 = DecisionMemory(path, "s-1")
    assert mem2.recall(command="npm install -g typescript") is not None
    assert mem2.recall(command="npm install -g react") is None


def test_prefix_scope_two_tokens(tmp_path):
    mem = DecisionMemory(tmp_path / "remembered.json", "s-1")
    mem.remember("prefix", "npm run")
    assert mem.recall(command="npm run build") is not None
    assert mem.recall(command="npm test") is None


def test_prefix_single_token_refused(tmp_path):
    mem = DecisionMemory(tmp_path / "remembered.json", "s-1")
    with pytest.raises(ValueError):
        mem.remember("prefix", "git")


def test_host_scope(tmp_path):
    mem = DecisionMemory(tmp_path / "remembered.json", "s-1")
    mem.remember("host", "api.github.com")
    assert mem.recall(host="api.github.com") is not None
    assert mem.recall(host="evil.com") is None


def test_session_change_invalidates(tmp_path):
    path = tmp_path / "remembered.json"
    mem = DecisionMemory(path, "s-1")
    mem.remember("command", "some command")

    # A new session must not see the old entries.
    mem2 = DecisionMemory(path, "s-2")
    assert mem2.entries() == []
    assert mem2.recall(command="some command") is None


def test_forget_all(tmp_path):
    path = tmp_path / "remembered.json"
    mem = DecisionMemory(path, "s-1")
    mem.remember("command", "cmd1")
    mem.remember("command", "cmd2")
    mem.forget_all()
    assert DecisionMemory(path, "s-1").entries() == []
