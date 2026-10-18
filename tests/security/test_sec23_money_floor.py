"""SEC-23 (M1 task 0): a money-moving call must not run when its governance
clauses cannot be evaluated (M0_SECURITY_SIGNOFF.md, SEC-23 ruling (b) 2-4).

Before the fix, with the optional jev-os service down, erroring or timing out,
``governance.evaluate`` returns [] and ``hook_eval._tool_governance`` swallows
every exception, so an allowlisted ``mcp__stripe__create_transfer`` (the
``move-money`` / ``move-more-money`` presets, up to 9,000,000) runs with no
approval and no audit record. ``FolderPolicy.fail_mode = "closed"`` is read
nowhere.

Required after the fix, through the real ``hook_eval.pre_tool_use``:
1. gated clauses exist and the service gives no result -> escalate (a pending
   approve-then-retry request), or deny if any gated clause's action is deny;
2. an audit record ``governance_unevaluated`` names the tool and the clauses;
3. ``fail_mode="closed"`` is honoured;
4. deterministic floor: an allowlisted call tagged ``moves_money`` escalates
   whatever the model says (also with the service disabled or answering "no").

Each RED test raises ``Sec23Open`` for the stated reason only; the strict
xfail accepts that exception and nothing else. The fix commit deletes the
decorator. The guards at the bottom pass today and must keep passing.
"""
from __future__ import annotations

import asyncio
import json
import socket

import httpx
import pytest

from sandbox.connector import tool_grants
from sandbox.connector.hook_eval import pre_tool_use
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import load_policy, save_policy
from sandbox.connector.queue import EscalationQueue
from sandbox.governance.policy import example_policy_path
from sandbox.semantic import client as semantic_client
from sandbox.semantic.client import SemanticClient, SemanticResult

# demo/try.py presets
MOVE_MONEY = ("mcp__stripe__create_transfer",
              {"amount": 250000, "currency": "usd", "destination": "acct_external_991"})
MOVE_MORE_MONEY = ("mcp__stripe__create_transfer",
                   {"amount": 9000000, "currency": "usd", "destination": "acct_external_991"})
LIST_CHARGES = ("mcp__stripe__list_charges", {"limit": 10})  # allowlisted, moves nothing


class Sec23Open(AssertionError):
    """The money call was not stopped, or nothing recorded why (SEC-23 open)."""


RED_SEC23 = pytest.mark.xfail(
    raises=Sec23Open, strict=True,
    reason="SEC-23 open: unevaluable governance fails open; no money floor; fail_mode unread",
)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _folder(tmp_path, *, semantic=True, allowlist=("stripe",), governance=None, fail_mode=None):
    init(tmp_path, claude=False, mcp=False)
    layout = FolderLayout(tmp_path)
    policy = load_policy(layout.policy_file)
    policy.semantic.enabled = semantic
    policy.semantic.url = f"http://127.0.0.1:{_free_port()}"  # nothing listens here
    policy.semantic.timeout_seconds = 3.0
    policy.semantic.governance_policy = str(governance or example_policy_path())
    policy.network.allow_mcp_servers = list(allowlist)
    if fail_mode is not None:
        policy.fail_mode = fail_mode
    save_policy(policy, layout.policy_file)
    return layout


def _call(layout, name, args):
    out = asyncio.run(pre_tool_use({"tool_name": name, "tool_input": args,
                                    "cwd": str(layout.root), "session_id": "sec23"}, layout))
    hso = out.get("hookSpecificOutput", {})
    return hso.get("permissionDecision"), hso.get("permissionDecisionReason", "")


def _pending_for(layout, name, args):
    fp = tool_grants.fingerprint(name, args)
    return [r for r in EscalationQueue(layout).list_pending()
            if r.get("kind") == "tool_call" and r.get("fingerprint") == fp]


def _audit(layout) -> list[dict]:
    recs = []
    for f in layout.audit_dir.rglob("*.jsonl"):
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                recs.append(json.loads(line))
    return recs


def _unevaluated_records(layout, tool):
    return [r for r in _audit(layout)
            if json.dumps(r).count("governance_unevaluated") and tool in json.dumps(r)]


def _require_escalated(layout, call, decision, reason):
    name, args = call
    if decision in (None, "allow"):
        raise Sec23Open(f"{name} {args.get('amount')} was let through ({decision!r}): {reason!r}")
    pending = _pending_for(layout, name, args)
    if len(pending) != 1:
        raise Sec23Open(f"{name}: expected exactly one pending approve-then-retry request, got {len(pending)}")
    assert decision == "deny" and "retry exactly the same call" in reason, (decision, reason)


def _require_unevaluated_audit(layout, tool, clause="no_payments"):
    recs = _unevaluated_records(layout, tool)
    if not recs:
        raise Sec23Open(f"no 'governance_unevaluated' audit record for {tool}")
    if not any(clause in json.dumps(r) for r in recs):
        raise Sec23Open(f"'governance_unevaluated' for {tool} does not name clause {clause}: {recs}")


# --- the service gives no result: 4 ways it fails ------------------------------------

def _service_refused(monkeypatch):
    pass  # the real client against a port nothing listens on


def _service_500(monkeypatch):
    monkeypatch.setattr(semantic_client.httpx, "post",
                        lambda *a, **k: httpx.Response(500, request=httpx.Request("POST", a[0])))


def _service_timeout(monkeypatch):
    def boom(*a, **k):
        raise httpx.ReadTimeout("timed out", request=httpx.Request("POST", a[0]))
    monkeypatch.setattr(semantic_client.httpx, "post", boom)


def _client_raises(monkeypatch):
    class Broken:
        def ask(self, *a, **k):
            raise RuntimeError("client bug")
    monkeypatch.setattr(SemanticClient, "from_policy", classmethod(lambda cls, p: Broken()))


FAILURES = {"refused": _service_refused, "http_500": _service_500,
            "timeout": _service_timeout, "client_raises": _client_raises}


@RED_SEC23
@pytest.mark.parametrize("failure", sorted(FAILURES))
@pytest.mark.parametrize("call", [MOVE_MORE_MONEY, MOVE_MONEY], ids=["move-more-money", "move-money"])
def test_money_call_escalates_and_is_audited_when_clauses_cannot_be_evaluated(tmp_path, monkeypatch,
                                                                              failure, call):
    layout = _folder(tmp_path)
    FAILURES[failure](monkeypatch)
    decision, reason = _call(layout, *call)
    _require_escalated(layout, call, decision, reason)
    _require_unevaluated_audit(layout, call[0])


@RED_SEC23
def test_explicit_fail_mode_closed_is_honoured(tmp_path):
    layout = _folder(tmp_path, fail_mode="closed")
    assert load_policy(layout.policy_file).fail_mode == "closed"
    decision, reason = _call(layout, *MOVE_MORE_MONEY)
    _require_escalated(layout, MOVE_MORE_MONEY, decision, reason)
    _require_unevaluated_audit(layout, MOVE_MORE_MONEY[0])


@RED_SEC23
def test_unevaluable_deny_clause_denies_without_queueing(tmp_path):
    gov = json.loads(example_policy_path().read_text(encoding="utf-8"))
    for c in gov["clauses"]:
        if c["id"] == "no_payments":
            c["action"] = "deny"
    path = tmp_path / "gov-deny.json"
    path.write_text(json.dumps(gov), encoding="utf-8")
    layout = _folder(tmp_path / "ws", governance=path)
    decision, reason = _call(layout, *MOVE_MORE_MONEY)
    if decision in (None, "allow"):
        raise Sec23Open(f"deny clause unevaluable, call let through ({decision!r})")
    if _pending_for(layout, *MOVE_MORE_MONEY):
        raise Sec23Open("a deny clause that cannot be evaluated must deny, not queue for approval")
    assert decision == "deny"
    _require_unevaluated_audit(layout, MOVE_MORE_MONEY[0])


# --- SEC-23 (b) 4: deterministic floor, whatever the model says ------------------------

@RED_SEC23
def test_floor_allowlisted_money_call_escalates_with_semantic_disabled(tmp_path):
    layout = _folder(tmp_path, semantic=False)
    decision, reason = _call(layout, *MOVE_MORE_MONEY)
    _require_escalated(layout, MOVE_MORE_MONEY, decision, reason)


@RED_SEC23
def test_floor_allowlisted_money_call_escalates_when_the_model_says_no(tmp_path, monkeypatch):
    class SaysNo:
        def ask(self, text, checks):
            return SemanticResult({k: 0.01 for k in checks}, "fake", 1.0)
    monkeypatch.setattr(SemanticClient, "from_policy", classmethod(lambda cls, p: SaysNo()))
    layout = _folder(tmp_path)
    decision, reason = _call(layout, *MOVE_MORE_MONEY)
    _require_escalated(layout, MOVE_MORE_MONEY, decision, reason)


# --- guards: pass today, must keep passing ---------------------------------------------

@pytest.mark.parametrize("failure", sorted(FAILURES))
def test_guard_allowlisted_non_money_call_is_unchanged(tmp_path, monkeypatch, failure):
    layout = _folder(tmp_path)
    FAILURES[failure](monkeypatch)
    decision, _ = _call(layout, *LIST_CHARGES)
    assert decision in (None, "allow")
    assert not _pending_for(layout, *LIST_CHARGES)
    assert not _unevaluated_records(layout, LIST_CHARGES[0])


def test_guard_non_allowlisted_money_server_still_escalates(tmp_path):
    layout = _folder(tmp_path, allowlist=())
    decision, reason = _call(layout, *MOVE_MORE_MONEY)
    assert decision == "deny" and "retry exactly the same call" in reason
    assert len(_pending_for(layout, *MOVE_MORE_MONEY)) == 1


def test_guard_clause_that_fires_still_escalates(tmp_path, monkeypatch):
    class SaysYes:
        def ask(self, text, checks):
            return SemanticResult({k: 0.95 for k in checks}, "fake", 1.0)
    monkeypatch.setattr(SemanticClient, "from_policy", classmethod(lambda cls, p: SaysYes()))
    layout = _folder(tmp_path)
    decision, reason = _call(layout, *MOVE_MORE_MONEY)
    assert decision == "deny" and "GOVERNANCE" in reason
    (rec,) = _pending_for(layout, *MOVE_MORE_MONEY)
    assert "no_payments" in {v["clause_id"] for v in rec["governance"]}
