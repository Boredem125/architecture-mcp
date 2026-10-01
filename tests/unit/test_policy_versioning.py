"""Policy versioning, change control and drift handling (connector/policy_versions.py)."""
from __future__ import annotations

import asyncio
import hashlib
import json
import shutil

import pytest
from click.testing import CliRunner

from sandbox.cli.main import cli
from sandbox.connector import policy_versions as pv
from sandbox.connector.audit import FolderAudit
from sandbox.connector.broker import FolderBroker
from sandbox.connector.hook_eval import pre_tool_use
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import load_policy, save_policy
from sandbox.connector.queue import EscalationQueue
from sandbox.connector.signing import verify_record
from sandbox.governance.policy import example_policy_path
from sandbox.governance.policy import load as gov_load

SLACK = ("mcp__slack__post_message", {"channel": "#general", "text": "build passed"})


@pytest.fixture
def layout(tmp_path):
    init(tmp_path, claude=False, mcp=False)
    lay = FolderLayout(tmp_path)
    pv.baseline(lay, "alice", "initial")
    return lay


def call(layout, name, args):
    return asyncio.run(pre_tool_use({"tool_name": name, "tool_input": args, "cwd": str(layout.root)}, layout))


def decision(out):
    return out["hookSpecificOutput"].get("permissionDecision")


def records(layout):
    session_id = json.loads(layout.session_file.read_text())["session_id"]
    return FolderAudit(layout.audit_dir, session_id).list_records(limit=1000)


def edit_on_disk(layout, fn):
    """A human (or another process) editing .sandbox/policy.json out of band."""
    policy = load_policy(layout.policy_file)
    fn(policy)
    save_policy(policy, layout.policy_file)


# --- content-addressed history ---------------------------------------------

def test_history_is_content_addressed(layout):
    head = pv.read_head(layout)
    sha = head["folder"]
    obj = pv.object_path(layout, sha)
    assert obj.name == f"{sha}.json"
    assert hashlib.sha256(obj.read_bytes()).hexdigest() == sha
    assert pv.load_object(layout, sha) == pv.folder_content(layout)
    # Same content, same object: storing it again writes nothing new.
    before = sorted(p.name for p in pv.history_dir(layout).glob("*.json"))
    assert pv.store(layout, pv.folder_content(layout)) == sha
    assert sorted(p.name for p in pv.history_dir(layout).glob("*.json")) == before
    (entry,) = pv.read_log(layout)
    assert entry["version"] == sha[:12] and entry["by"] == "alice" and entry["previous"] is None
    assert pv.verify_entry(entry)
    assert pv.version_info(layout) == {"folder": sha[:12], "governance": None, "state": "approved"}


def test_baseline_only_once(layout):
    with pytest.raises(ValueError):
        pv.baseline(layout, "bob", "again")


# --- every decision records the version -------------------------------------

def test_hook_decisions_and_escalations_carry_the_version(layout, tmp_path_factory):
    version = pv.short(pv.read_head(layout)["folder"])
    outside = tmp_path_factory.mktemp("outside") / "notes.txt"
    outside.write_text("x")
    call(layout, "Read", {"file_path": str(outside)})  # observe → audited
    observed = [r for r in records(layout) if r.get("event") == "observed"]
    assert observed and observed[-1]["policy_version"]["folder"] == version
    assert observed[-1]["policy_version"]["state"] == "approved"

    assert decision(call(layout, *SLACK)) == "deny"  # escalated: approve, then retry
    (rec,) = EscalationQueue(layout).list_pending()
    assert rec["policy_version"]["folder"] == version

    queue = EscalationQueue(layout)
    claimed = queue.claim(rec["request_id"], "bob")
    queue.finish(rec["request_id"], asyncio.run(FolderBroker().execute(claimed, "bob", "ok")))
    done = queue.get(rec["request_id"])
    assert done["policy_version"]["folder"] == version
    assert "policy_version" in done["signed_fields"] and verify_record(done)
    done["policy_version"] = {"folder": "000000000000", "state": "approved"}
    assert not verify_record(done)  # the version is covered by the signature


def test_unversioned_folder_behaves_as_before(tmp_path):
    init(tmp_path, claude=False, mcp=False)
    lay = FolderLayout(tmp_path)
    edit_on_disk(lay, lambda p: p.network.allow_mcp_servers.append("slack"))
    assert decision(call(lay, *SLACK)) != "deny"  # the file is enforced as-is
    assert pv.version_info(lay)["state"] == "unversioned"


# --- change control ----------------------------------------------------------

def _loosened(layout):
    policy = load_policy(layout.policy_file)
    policy.network.allow_mcp_servers.append("slack")
    return policy.model_dump()


def test_proposer_cannot_approve_own_change(layout):
    before = layout.policy_file.read_text()
    change = pv.propose(layout, pv.FOLDER, _loosened(layout), "alice", "let the bot post build results")
    assert change["loosens"] == ["network.allow_mcp_servers"]
    assert pv.verify_proposal(change)

    assert pv.approve_change(layout, change["change_id"], "alice")["status"] == "same_reviewer"
    assert layout.policy_file.read_text() == before  # nothing applied
    assert pv.load_change(layout, change["change_id"])["status"] == "open"

    out = pv.approve_change(layout, change["change_id"], "bob", "checked the channel")
    assert out["status"] == "applied"
    assert "slack" in load_policy(layout.policy_file).network.allow_mcp_servers
    assert pv.read_head(layout)["folder"] == change["new_sha256"]
    assert pv.version_info(layout)["state"] == "approved"
    # Approved again by someone else: it is no longer open.
    assert pv.approve_change(layout, change["change_id"], "carol")["status"] == "not_open"


def test_signed_approval_verifies_and_tampering_breaks_it(layout):
    change = pv.propose(layout, pv.FOLDER, _loosened(layout), "alice", "post build results")
    pv.approve_change(layout, change["change_id"], "bob")
    approved = pv.load_change(layout, change["change_id"])
    assert approved["approval"]["reviewer_id"] == "bob"
    assert approved["approval"]["fingerprint"] == change["new_sha256"]
    assert pv.verify_change(approved)

    entry = pv.read_log(layout)[-1]
    assert entry["how"] == "change" and pv.verify_entry(entry)

    swapped = dict(approved, new_sha256="f" * 64)  # claim the approval covered other content
    assert not pv.verify_change(swapped)
    assert not pv.verify_entry(dict(entry, sha256="f" * 64))
    assert not pv.verify_change(dict(approved, reason="something else"))  # proposal signature
    # An approval by the proposer's own key never verifies as a change.
    assert not pv.verify_change(dict(approved, proposer="bob"))


def test_stale_change_is_refused(layout):
    a = pv.propose(layout, pv.FOLDER, _loosened(layout), "alice", "first")
    other = load_policy(layout.policy_file)
    other.network.allow_hosts.append("example.org")
    b = pv.propose(layout, pv.FOLDER, other.model_dump(), "alice", "second")
    assert pv.approve_change(layout, a["change_id"], "bob")["status"] == "applied"
    assert pv.approve_change(layout, b["change_id"], "bob")["status"] == "stale"


def test_identical_proposal_is_rejected(layout):
    with pytest.raises(ValueError):
        pv.propose(layout, pv.FOLDER, pv.folder_content(layout), "alice", "no-op")


def test_tightening_edit_applies_loosening_edit_proposes(layout):
    tighter = load_policy(layout.policy_file)
    tighter.triggers.read_outside = "escalate"
    out = pv.apply_edit(layout, tighter, "alice", "policy set-trigger read_outside escalate")
    assert out["status"] == "applied"
    assert load_policy(layout.policy_file).triggers.read_outside == "escalate"
    assert pv.read_log(layout)[-1]["how"] == "tightening"

    looser = load_policy(layout.policy_file)
    looser.shell.allow_patterns.append(r"^curl\b")
    out = pv.apply_edit(layout, looser, "alice", "policy allow-shell ^curl")
    assert out["status"] == "proposed" and out["loosens"] == ["shell.allow_patterns"]
    assert r"^curl\b" not in load_policy(layout.policy_file).shell.allow_patterns


def test_meet_and_only_tightens():
    from sandbox.connector.policy import default_policy

    base = default_policy().model_dump()
    tight = default_policy()
    tight.triggers.network = "deny"
    tight.shell.deny_patterns.append("rm -rf")
    tight.shell.allow_patterns = tight.shell.allow_patterns[:1]
    assert pv.only_tightens(base, tight.model_dump())

    loose = default_policy()
    loose.triggers.network = "allow"
    loose.semantic.url = "http://attacker.invalid"
    loose.auto_allow = True
    assert not pv.only_tightens(base, loose.model_dump())
    m = pv.meet(base, loose.model_dump())
    assert m["triggers"]["network"] == "escalate"
    assert m["semantic"]["url"] == base["semantic"]["url"] and m["auto_allow"] is False
    assert sorted(pv.loosened_fields(base, loose.model_dump())) == ["auto_allow", "semantic.url", "triggers.network"]


# --- drift ---------------------------------------------------------------------

def test_drift_cannot_loosen_and_is_audited_once(layout):
    edit_on_disk(layout, lambda p: p.network.allow_mcp_servers.append("slack"))
    info = pv.version_info(layout)
    assert info["state"] == "drift" and info["drift"] == ["folder"]
    assert info["approved"]["folder"] == pv.short(pv.read_head(layout)["folder"])

    assert decision(call(layout, *SLACK)) == "deny"  # still escalated: the approved policy wins
    (rec,) = EscalationQueue(layout).list_pending()
    assert rec["policy_version"]["state"] == "drift"
    call(layout, *SLACK)
    drift_events = [r for r in records(layout) if r.get("event") == "policy_drift"]
    assert len(drift_events) == 1  # one event per distinct drift, not per call
    assert "POLICY DRIFT" in (layout.logs_dir / "activity.log").read_text()


def test_drift_that_tightens_is_enforced(layout, tmp_path_factory):
    edit_on_disk(layout, lambda p: setattr(p.triggers, "read_outside", "deny"))
    outside = tmp_path_factory.mktemp("outside") / "notes.txt"
    outside.write_text("x")
    assert decision(call(layout, "Read", {"file_path": str(outside)})) == "deny"


def test_re_approving_the_drifted_file_ends_drift(layout):
    edit_on_disk(layout, lambda p: p.network.allow_mcp_servers.append("slack"))
    change = pv.propose(layout, pv.FOLDER, pv.folder_content(layout), "alice", "adopt the hand edit")
    assert pv.approve_change(layout, change["change_id"], "bob")["status"] == "applied"
    assert pv.version_info(layout)["state"] == "approved"
    assert decision(call(layout, *SLACK)) != "deny"


def _with_governance(tmp_path):
    """A versioned folder whose governance policy lives in the workspace (agent-writable)."""
    init(tmp_path, claude=False, mcp=False)
    lay = FolderLayout(tmp_path)
    gov_file = tmp_path / "governance.json"
    shutil.copy(example_policy_path(), gov_file)
    edit_on_disk(lay, lambda p: setattr(p.semantic, "governance_policy", str(gov_file)))
    pv.baseline(lay, "alice", "initial")
    return lay, gov_file


def test_governance_drift_keeps_the_approved_clauses(tmp_path):
    lay, gov_file = _with_governance(tmp_path)
    approved_ids = {c.id for c in gov_load(gov_file).clauses}
    assert pv.read_head(lay)["governance"] and pv.version_info(lay)["state"] == "approved"

    # Something in the workspace strips the clauses and adds a new one.
    data = json.loads(gov_file.read_text())
    extra = dict(data["clauses"][0], id="no_friday_deploys")
    gov_file.write_text(json.dumps({"name": data["name"], "clauses": [extra]}))

    policy, info = pv.enforced_policy(lay)
    assert info["state"] == "drift" and info["drift"] == ["governance"]
    enforced_ids = {c.id for c in gov_load(policy.semantic.governance_policy).clauses}
    assert approved_ids | {"no_friday_deploys"} <= enforced_ids  # union: only more scrutiny


def test_governance_change_control(tmp_path):
    lay, gov_file = _with_governance(tmp_path)
    data = json.loads(gov_file.read_text())
    data["clauses"] = data["clauses"][:1]
    change = pv.propose(lay, pv.GOVERNANCE, data, "alice", "retire the other clauses")
    assert pv.approve_change(lay, change["change_id"], "alice")["status"] == "same_reviewer"
    assert pv.approve_change(lay, change["change_id"], "bob")["status"] == "applied"
    assert len(gov_load(gov_file).clauses) == 1
    assert pv.version_info(lay)["state"] == "approved"


def test_pointing_at_a_new_governance_file_approves_its_content(layout, tmp_path):
    gov_file = tmp_path / "gov.json"
    shutil.copy(example_policy_path(), gov_file)
    policy = load_policy(layout.policy_file)
    policy.semantic.governance_policy = str(gov_file)
    out = pv.apply_edit(layout, policy, "alice", "governance use gov.json")
    assert out["status"] == "proposed"
    change = pv.load_change(layout, out["change_id"])
    assert change["governance_sha256"]
    assert pv.approve_change(layout, change["change_id"], "bob")["status"] == "applied"
    head = pv.read_head(layout)
    assert head["governance"] == change["governance_sha256"]
    assert pv.version_info(layout)["state"] == "approved"


# --- CLI -------------------------------------------------------------------------

def test_cli_init_propose_approve_history_diff(tmp_path):
    runner = CliRunner()
    root = str(tmp_path)
    r = runner.invoke(cli, ["init", root, "--no-claude", "--no-mcp"], env={"SANDBOX_REVIEWER": "alice"})
    assert r.exit_code == 0, r.output
    assert "baseline, recorded by alice" in r.output
    lay = FolderLayout(tmp_path)
    v1 = pv.short(pv.read_head(lay)["folder"])

    # A loosening direct edit becomes a proposal; the file is untouched.
    r = runner.invoke(cli, ["policy", "allow-host", "example.org", root], env={"SANDBOX_REVIEWER": "alice"})
    assert r.exit_code == 0, r.output
    assert "Not applied" in r.output and "network.allow_hosts" in r.output
    assert "example.org" not in load_policy(lay.policy_file).network.allow_hosts
    (change,) = pv.list_changes(lay, "open")

    # A tightening direct edit applies at once and is recorded.
    r = runner.invoke(cli, ["policy", "set-trigger", "read_outside", "deny", root], env={"SANDBOX_REVIEWER": "alice"})
    assert r.exit_code == 0 and "Set trigger read_outside = deny" in r.output
    # ...which makes the earlier proposal stale.
    r = runner.invoke(cli, ["policy", "approve-change", change["change_id"], root, "--reviewer", "bob"])
    assert r.exit_code == 1 and "Propose it again" in r.output

    new = load_policy(lay.policy_file)
    new.network.allow_hosts.append("example.org")
    proposal = tmp_path / "proposal.json"
    proposal.write_text(json.dumps(new.model_dump()))
    r = runner.invoke(cli, ["policy", "propose", str(proposal), root, "--reason", "docs site", "--proposer", "alice"])
    assert r.exit_code == 0, r.output
    assert "network.allow_hosts" in r.output and '+      "example.org"' in r.output, r.output
    change_id = r.output.split("Proposed change ", 1)[1].split(":", 1)[0]

    r = runner.invoke(cli, ["policy", "approve-change", change_id, root, "--reviewer", "alice"])
    assert r.exit_code == 1 and "Refused" in r.output
    r = runner.invoke(cli, ["policy", "approve-change", change_id, root, "--reviewer", "bob"])
    assert r.exit_code == 0, r.output
    assert "example.org" in load_policy(lay.policy_file).network.allow_hosts

    r = runner.invoke(cli, ["policy", "history", root])
    assert r.exit_code == 0, r.output
    assert "proposed by alice, approved by bob (two reviewers verified)" in r.output
    assert "SIGNATURE INVALID" not in r.output and "(approved)" in r.output

    v_now = pv.short(pv.read_head(lay)["folder"])
    r = runner.invoke(cli, ["policy", "diff", v1, v_now, root])
    assert r.exit_code == 0, r.output
    assert '+      "example.org"' in r.output and '"read_outside": "deny"' in r.output
    assert "# looser or changed without a stricter direction: network.allow_hosts" in r.output
    r = runner.invoke(cli, ["policy", "diff", "approved", "current", root])
    assert r.output.strip() == "No differences."

    edit_on_disk(lay, lambda p: p.network.allow_hosts.append("evil.invalid"))
    r = runner.invoke(cli, ["status", root])
    assert "DRIFT" in r.output
    r = runner.invoke(cli, ["policy", "diff", "approved", "current", root])
    assert '+      "evil.invalid"' in r.output
