"""Governance on non-shell tool calls: what a call does, the clause gate, and
"approve, then retry" grants."""
from __future__ import annotations

import asyncio
import json
import time

import pytest

from sandbox.connector import tool_grants
from sandbox.connector.broker import FolderBroker
from sandbox.connector.hook_eval import pre_tool_use
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import load_policy, save_policy
from sandbox.connector.queue import EscalationQueue
from sandbox.connector.signing import sign_record, verify_record
from sandbox.governance.evaluate import evaluate
from sandbox.governance.policy import example_policy_path, load
from sandbox.safety.tool_actions import describe_call, render
from sandbox.semantic.client import SemanticClient, SemanticResult

REFUND = ("mcp__stripe__create_refund", {"charge": "ch_123", "amount": 4900, "reason": "requested_by_customer"})
LIST = ("mcp__stripe__list_charges", {"limit": 10})


def tags(name, args):
    return {t for t, _ in describe_call(name, args)}


# --- what a call does ----------------------------------------------------------

def test_money_moving_calls_are_tagged_and_reads_are_not():
    assert {"moves_money", "sends_data"} <= tags(*REFUND)
    assert tags("mcp__bank_api__send_transfer", {"to_iban": "X", "amount": 10}) >= {"moves_money"}
    assert not tags(*LIST)
    assert not tags("mcp__stripe__retrieve_invoice", {"id": "in_1"})


def test_prod_change_needs_a_mutation_and_no_nonprod_environment():
    assert "prod_change" in tags("mcp__kubernetes__scale_deployment", {"namespace": "prod", "replicas": 3})
    # An unspecified environment counts as production (conservative).
    assert "prod_change" in tags("mcp__vercel__deploy", {"project": "web"})
    assert "prod_change" not in tags("mcp__vercel__deploy", {"project": "web", "target": "preview"})
    assert "prod_change" not in tags("mcp__db_migrate__run_migrations", {"database": "dev_mirror"})
    assert "prod_change" not in tags("mcp__k8s__describe_deployment", {"environment": "production"})


def test_webfetch_with_data_in_the_query_sends_data():
    assert "sends_data" in tags("WebFetch", {"url": "https://ingest.example.com/t?customer_email=a%40b.example", "prompt": "x"})
    assert not tags("WebFetch", {"url": "https://docs.example.com/guide?page=2", "prompt": "summarise"})


def test_render_names_the_server_and_action():
    assert render(*REFUND).startswith("Calls the stripe tool create_refund with arguments")


# --- the clause gate --------------------------------------------------------------

class FakeClient:
    """Every clause it is asked about scores high: the gate alone decides what's asked."""

    def __init__(self, down: bool = False) -> None:
        self.asked: list[set[str]] = []
        self.down = down

    def ask(self, text, checks):
        self.asked.append(set(checks))
        return None if self.down else SemanticResult({k: 0.95 for k in checks}, "fake", 1.0)


def test_only_clauses_matching_the_call_are_checked():
    gov = load(example_policy_path())
    fake = FakeClient()
    v = evaluate(gov, "", fake, tool_call=REFUND)
    assert {x.clause_id for x in v} == {"no_payments", "no_external_data"}
    assert fake.asked == [{"no_payments", "no_external_data"}]


def test_a_read_call_never_reaches_the_service():
    fake = FakeClient()
    assert evaluate(load(example_policy_path()), "", fake, tool_call=LIST) == []
    assert fake.asked == []


def test_clause_without_tool_actions_is_not_applied_to_tool_calls():
    gov = load(example_policy_path())
    for c in gov.clauses:
        c.requires_tool_actions = []
    assert evaluate(gov, "", FakeClient(), tool_call=REFUND) == []


# --- the hook: approve, then retry --------------------------------------------------

@pytest.fixture
def folder(tmp_path, monkeypatch):
    init(tmp_path, claude=False, mcp=False)
    layout = FolderLayout(tmp_path)
    policy = load_policy(layout.policy_file)
    policy.semantic.enabled = True
    policy.semantic.governance_policy = str(example_policy_path())
    policy.network.allow_mcp_servers = ["stripe"]  # allowlisted: before this, it ran silently
    save_policy(policy, layout.policy_file)
    fake = FakeClient()
    monkeypatch.setattr(SemanticClient, "from_policy", classmethod(lambda cls, p: fake))
    return layout


def call(layout, name, args):
    return asyncio.run(pre_tool_use({"tool_name": name, "tool_input": args, "cwd": str(layout.root)}, layout))


def decision(out):
    return out["hookSpecificOutput"].get("permissionDecision"), out["hookSpecificOutput"].get("permissionDecisionReason", "")


def approve(layout, request_id):
    queue = EscalationQueue(layout)
    rec = queue.claim(request_id, "cli")
    queue.finish(request_id, asyncio.run(FolderBroker().execute(rec, "cli", "ok")))


def pending_ids(layout):
    return [r["request_id"] for r in EscalationQueue(layout).list_pending() if r.get("kind") == "tool_call"]


def test_allowlisted_payment_call_now_escalates(folder):
    d, why = decision(call(folder, *REFUND))
    assert d == "deny" and "GOVERNANCE" in why and "retry exactly the same call" in why
    (rec,) = EscalationQueue(folder).list_pending()
    assert rec["kind"] == "tool_call" and rec["fingerprint"] == tool_grants.fingerprint(*REFUND)
    assert {v["clause_id"] for v in rec["governance"]} == {"no_payments", "no_external_data"}


def test_a_repeated_call_does_not_queue_duplicates(folder):
    call(folder, *REFUND)
    call(folder, *REFUND)
    assert len(pending_ids(folder)) == 1


def test_approved_call_is_allowed_once(folder):
    call(folder, *REFUND)
    (rid,) = pending_ids(folder)
    approve(folder, rid)
    assert decision(call(folder, *REFUND))[0] == "allow"
    # Used up: the next identical call needs a new approval.
    assert decision(call(folder, *REFUND))[0] == "deny"
    assert len(pending_ids(folder)) == 1


def test_grant_does_not_cover_different_arguments(folder):
    call(folder, *REFUND)
    approve(folder, pending_ids(folder)[0])
    bigger = (REFUND[0], {**REFUND[1], "amount": 490000})
    assert decision(call(folder, *bigger))[0] == "deny"


def test_expired_grant_is_ignored(folder):
    call(folder, *REFUND)
    approve(folder, pending_ids(folder)[0])
    fp = tool_grants.fingerprint(*REFUND)
    assert tool_grants.find_grant(folder, fp) is not None
    assert tool_grants.find_grant(folder, fp, now=time.time() + tool_grants.GRANT_TTL_SECONDS + 1) is None


def test_grant_signed_by_another_key_is_ignored(folder, tmp_path_factory):
    # A done-record that verifies against its own embedded key, but isn't the
    # folder's approver key (e.g. forged by something that could write done/).
    other = FolderLayout(tmp_path_factory.mktemp("other"))
    init(other.root, claude=False, mcp=False)
    fp = tool_grants.fingerprint(*REFUND)
    forged = {"request_id": "forged1", "kind": "tool_call", "decision": "approved", "state": "approved",
              "fingerprint": fp, "reviewer_id": "cli", "decided_at": time.time()}
    sign_record(other, "cli", forged)
    assert verify_record(forged)
    sign_record(folder, "cli", {"request_id": "warmup"})  # make sure the folder has its own key
    (folder.done_dir / "forged1.json").write_text(json.dumps(forged), encoding="utf-8")
    assert tool_grants.find_grant(folder, fp) is None


def test_read_call_on_allowlisted_server_still_runs(folder):
    out = call(folder, *LIST)
    assert decision(out)[0] != "deny"
    assert not pending_ids(folder)


def test_service_down_adds_no_scrutiny(folder, monkeypatch):
    monkeypatch.setattr(SemanticClient, "from_policy", classmethod(lambda cls, p: FakeClient(down=True)))
    assert decision(call(folder, *REFUND))[0] != "deny"


def test_no_governance_policy_changes_nothing(folder):
    policy = load_policy(folder.policy_file)
    policy.semantic.governance_policy = ""
    save_policy(policy, folder.policy_file)
    assert decision(call(folder, *REFUND))[0] != "deny"


def test_records_signed_before_fingerprint_was_added_still_verify(tmp_path):
    from sandbox.connector import signing

    init(tmp_path, claude=False, mcp=False)
    layout = FolderLayout(tmp_path)
    old_fields = [f for f in signing._SIGNED_FIELDS if f != "fingerprint"]
    rec = {"request_id": "r1", "command": "echo hi", "decision": "approved"}
    key = signing._load_or_create_key(layout, "cli")
    rec["signer_public_key"] = bytes(key.verify_key).hex()
    rec["signed_fields"] = old_fields
    rec["signature"] = signing.sign_message(signing._canonical(rec, old_fields), key)
    assert verify_record(rec)
