"""PrivilegeBroker exec_cwd + recorder_factory (bugs 4 & 5)."""
from __future__ import annotations

import sys

import pytest

from sandbox.broker.privilege_broker import BrokerRequestState, PrivilegeBroker


def _print_cwd_cmd() -> str:
    # Portable "print the current directory".
    return f'{sys.executable} -c "import os;print(os.getcwd())"'


async def test_approved_command_runs_in_exec_cwd(tmp_path):
    jail = tmp_path / "jail"
    work = tmp_path / "work"
    jail.mkdir()
    work.mkdir()
    broker = PrivilegeBroker()
    req = await broker.submit_request(
        session_id="s1", run_id="r1", agent_id="a1",
        command=_print_cwd_cmd(), jail_dir=str(jail), exec_cwd=str(work),
    )
    result = await broker.approve(req.request_id, "reviewer")
    assert result.state == BrokerRequestState.EXECUTED
    assert result.exit_code == 0
    assert str(work) in result.stdout


async def test_exec_cwd_defaults_to_jail(tmp_path):
    jail = tmp_path / "jail"
    jail.mkdir()
    broker = PrivilegeBroker()
    req = await broker.submit_request(
        session_id="s1", run_id="r1", agent_id="a1",
        command=_print_cwd_cmd(), jail_dir=str(jail),
    )
    result = await broker.approve(req.request_id, "reviewer")
    assert str(jail) in result.stdout


async def test_recorder_factory_invoked_per_jail(tmp_path):
    calls: list[str] = []

    class FakeRecorder:
        def __init__(self, jail_dir: str) -> None:
            self.jail_dir = jail_dir
            calls.append(jail_dir)

        def log_action(self, **kwargs):  # noqa: ANN003
            pass

    def factory(jail_dir: str) -> FakeRecorder:
        return FakeRecorder(jail_dir)

    jail = tmp_path / "jail"
    jail.mkdir()
    broker = PrivilegeBroker(recorder_factory=factory)
    req = await broker.submit_request(
        session_id="s1", run_id="r1", agent_id="a1",
        command=f'{sys.executable} -c "pass"', jail_dir=str(jail),
    )
    await broker.approve(req.request_id, "reviewer")
    # One recorder built for this jail, reused across submit + approve.
    assert calls == [str(jail)]


async def test_configurable_exec_timeout(tmp_path):
    jail = tmp_path / "jail"
    jail.mkdir()
    broker = PrivilegeBroker(exec_timeout=1)
    req = await broker.submit_request(
        session_id="s1", run_id="r1", agent_id="a1",
        command=f'{sys.executable} -c "import time;time.sleep(5)"',
        jail_dir=str(jail),
    )
    result = await broker.approve(req.request_id, "reviewer")
    assert result.state == BrokerRequestState.FAILED
    assert "timed out" in result.stderr.lower()
