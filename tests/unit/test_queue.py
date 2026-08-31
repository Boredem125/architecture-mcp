"""EscalationQueue: atomic submit, claim race, wait, crash-restart survival."""
from __future__ import annotations

import asyncio

import pytest

from sandbox.connector.layout import FolderLayout
from sandbox.connector.queue import EscalationQueue


@pytest.fixture
def queue(tmp_path):
    layout = FolderLayout(tmp_path)
    return EscalationQueue(layout)


def test_submit_and_list(queue):
    rid = queue.submit({"command": "npm -v", "trigger": ["shell"]})
    pending = queue.list_pending()
    assert len(pending) == 1
    assert pending[0]["request_id"] == rid
    assert queue.status(rid) == "pending"


def test_submit_preserves_request_id(queue):
    rid = queue.submit({"request_id": "fixed123", "command": "x"})
    assert rid == "fixed123"
    assert queue.get("fixed123")["command"] == "x"


def test_claim_moves_to_claimed(queue):
    rid = queue.submit({"command": "x"})
    rec = queue.claim(rid, "reviewer-a")
    assert rec is not None
    assert rec["reviewer_id"] == "reviewer-a"
    assert queue.status(rid) == "claimed"
    assert queue.list_pending() == []


def test_claim_race_single_winner(queue):
    rid = queue.submit({"command": "x"})
    first = queue.claim(rid, "a")
    second = queue.claim(rid, "b")
    assert first is not None
    assert second is None  # exactly one winner


def test_finish_writes_done_and_out(queue):
    rid = queue.submit({"command": "echo hi"})
    queue.claim(rid, "a")
    queue.finish(rid, {
        "state": "executed", "decision": "approved",
        "exit_code": 0, "stdout": "hi\n", "stderr": "",
    })
    assert queue.status(rid) == "done"
    rec = queue.get(rid)
    assert rec["exit_code"] == 0
    out_txt = (queue._layout.out_dir / f"{rid}.txt").read_text()
    assert "EXIT_CODE: 0" in out_txt
    assert "hi" in out_txt


async def test_wait_resolves_on_finish(queue):
    rid = queue.submit({"command": "x"})

    async def approve_later():
        await asyncio.sleep(0.2)
        queue.claim(rid, "a")
        queue.finish(rid, {"state": "executed", "exit_code": 0, "stdout": "", "stderr": ""})

    task = asyncio.create_task(approve_later())
    rec = await queue.wait(rid, timeout=5.0)
    await task
    assert rec is not None
    assert rec["state"] == "executed"


async def test_wait_times_out(queue):
    rid = queue.submit({"command": "x"})
    rec = await queue.wait(rid, timeout=0.3)
    assert rec is None
    assert queue.status(rid) == "pending"  # still alive on disk


def test_crash_restart_survival(tmp_path):
    # First "process" submits.
    q1 = EscalationQueue(FolderLayout(tmp_path))
    rid = q1.submit({"command": "survives"})
    # Second "process" — brand-new queue object over the same folder.
    q2 = EscalationQueue(FolderLayout(tmp_path))
    assert q2.status(rid) == "pending"
    assert q2.get(rid)["command"] == "survives"
