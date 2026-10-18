"""M1 T1 (D1, SEC-10): the `?root=` allowlist. Tests written before the fix.

Roots come only from `sandbox serve --root` / `SANDBOX_CONNECTOR_ROOTS`; no
roots = every connector call 403; pure-string match after auth; 400 for bad
string shape (NUL, > 1024 chars, non-absolute) with no filesystem access; 403
for unlisted input, with no filesystem access and no echo; the route then uses
the stored configured root. Also D1.5 (loopback default) and D1.7
(`is_agent_route` path-boundary match). See M1_PLAN.md D1 and "Tests" item 1.

RED tests raise ``RootAllowlistOpen`` for the stated reason only; the strict
xfail accepts nothing else. The fix commit deletes the decorator. Guards pass
today and must keep passing.
"""
from __future__ import annotations

import errno
import json
import os
import pathlib
import socket
import subprocess
import sys
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from sandbox.api import auth
from sandbox.api.app import create_app
from sandbox.connector.install import init

AGENT, APPROVER = "agent-t1", "approver-t1"
ROOTS_ENV = "SANDBOX_CONNECTOR_ROOTS"
WINDOWS = os.name == "nt"


class RootAllowlistOpen(AssertionError):
    """The connector API still trusts the request's `root` (SEC-10 open)."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise RootAllowlistOpen(msg)


@pytest.fixture
def ws(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    init(root, claude=False, mcp=False)
    return root


@pytest.fixture
def other(tmp_path):
    root = tmp_path / "other"
    root.mkdir()
    init(root, claude=False, mcp=False)
    return root


def _client(monkeypatch, roots, token=APPROVER) -> TestClient:
    monkeypatch.setenv(auth.AGENT_ENV, AGENT)
    monkeypatch.setenv(auth.APPROVER_ENV, APPROVER)
    if roots is None:
        monkeypatch.delenv(ROOTS_ENV, raising=False)
    else:
        monkeypatch.setenv(ROOTS_ENV, os.pathsep.join(str(r) for r in roots))
    return TestClient(create_app(), raise_server_exceptions=False,
                      headers={"Authorization": f"Bearer {token}"} if token else {})


def _status(c: TestClient, root) -> httpx.Response:
    return c.get("/api/v1/connector/status", params={"root": str(root)})


# --- fail closed and exact match ------------------------------------------------------

def test_no_roots_configured_means_403(monkeypatch, ws):
    r = _status(_client(monkeypatch, None), ws)
    _require(r.status_code == 403, f"no roots configured, initialized folder -> {r.status_code}, want 403")


def test_guard_listed_root_answers(monkeypatch, ws):
    r = _status(_client(monkeypatch, [ws]), ws)
    assert r.status_code == 200, r.text


def test_unlisted_initialized_folder_is_403(monkeypatch, ws, other):
    r = _status(_client(monkeypatch, [ws]), other)
    _require(r.status_code == 403, f"unlisted folder -> {r.status_code}, want 403")


def test_subfolder_of_a_listed_root_is_403(monkeypatch, ws):
    sub = ws / "pkg"
    sub.mkdir()
    init(sub, claude=False, mcp=False)
    r = _status(_client(monkeypatch, [ws]), sub)
    _require(r.status_code == 403, f"subfolder of a listed root -> {r.status_code}, want 403")


def test_dotdot_escape_from_a_listed_root_is_403(monkeypatch, ws, other):
    escape = str(ws) + os.sep + ".." + os.sep + other.name
    r = _status(_client(monkeypatch, [ws]), escape)
    _require(r.status_code == 403, f"{escape!r} -> {r.status_code}, want 403")


def test_guard_dotdot_that_normalizes_to_the_listed_root_is_accepted(monkeypatch, ws):
    same = str(ws) + os.sep + "pkg" + os.sep + ".."
    r = _status(_client(monkeypatch, [ws]), same)
    assert r.status_code == 200, r.text


def test_case_variant_matches_only_where_the_os_folds_case(monkeypatch, ws):
    variant = str(ws).upper() if str(ws) != str(ws).upper() else str(ws).lower()
    r = _status(_client(monkeypatch, [ws]), variant)
    want = 200 if WINDOWS else 403
    _require(r.status_code == want, f"case variant on {os.name} -> {r.status_code}, want {want}")
    if WINDOWS:
        # D1.3: after a match the route uses the stored configured root, never the request string.
        stored = os.path.normcase(os.path.realpath(ws))
        _require(os.path.normcase(r.json()["root"]) == stored and r.json()["root"] != variant,
                 f"route used the request string {r.json()['root']!r}, not the configured root")


def test_symlink_or_junction_alias_of_a_listed_root_is_403(monkeypatch, ws, tmp_path):
    alias = tmp_path / "alias"
    if WINDOWS:
        rc = subprocess.run(["cmd", "/c", "mklink", "/J", str(alias), str(ws)], capture_output=True).returncode
        assert rc == 0 and alias.exists(), "could not create a junction"
    else:
        os.symlink(ws, alias, target_is_directory=True)
    r = _status(_client(monkeypatch, [ws]), alias)
    _require(r.status_code == 403, f"alias {alias} of a listed root -> {r.status_code}, want 403")


# --- 400 on string shape, no filesystem access, no echo --------------------------------

def test_relative_root_is_400_never_resolved_against_the_server_cwd(monkeypatch, ws):
    monkeypatch.chdir(ws)
    for rel in (".", "ws", "./"):
        r = _status(_client(monkeypatch, [ws]), rel)
        _require(r.status_code == 400, f"relative root {rel!r} -> {r.status_code}, want 400")


def test_guard_nul_byte_is_400(monkeypatch, ws):
    r = _status(_client(monkeypatch, [ws]), str(ws) + "\x00x")
    assert r.status_code == 400, r.text


def test_length_limit_is_1024(monkeypatch, ws):
    c = _client(monkeypatch, [ws])
    anchor = os.path.splitdrive(str(ws))[0] + os.sep
    long_1025 = anchor + "a" * (1025 - len(anchor))
    long_1024 = anchor + "a" * (1024 - len(anchor))
    r = _status(c, long_1025)
    _require(r.status_code == 400, f"1025-character root -> {r.status_code}, want 400")
    r = _status(c, long_1024)
    _require(r.status_code == 403, f"1024-character unlisted root -> {r.status_code}, want 403")


def test_unlisted_root_touches_no_filesystem_and_is_not_echoed(monkeypatch, ws, tmp_path):
    probe = str(tmp_path / "probe-target-7f3a")
    seen: list[str] = []
    real = {name: getattr(pathlib.Path, name) for name in ("stat", "exists", "is_dir", "resolve")}
    real_os_stat = os.stat

    def spy(name):
        def wrapper(self, *a, **k):
            if "probe-target-7f3a" in str(self):
                seen.append(f"Path.{name}({self})")
            return real[name](self, *a, **k)
        return wrapper

    def os_stat(path, *a, **k):
        if "probe-target-7f3a" in str(path):
            seen.append(f"os.stat({path})")
        return real_os_stat(path, *a, **k)

    c = _client(monkeypatch, [ws])
    for name in real:
        monkeypatch.setattr(pathlib.Path, name, spy(name))
    monkeypatch.setattr(os, "stat", os_stat)
    r = _status(c, probe)
    _require(r.status_code == 403, f"unlisted root -> {r.status_code}, want 403")
    _require(not seen, f"the filesystem was touched for unlisted input: {seen}")
    _require("probe-target-7f3a" not in r.text, "the 403 body echoes the requested path")


def test_guard_listed_root_whose_stat_fails_is_400_not_500(monkeypatch, ws):
    c = _client(monkeypatch, [ws])

    def too_long(self, *a, **k):
        raise OSError(errno.ENAMETOOLONG, "File name too long")
    monkeypatch.setattr(pathlib.Path, "is_dir", too_long)
    monkeypatch.setattr(pathlib.Path, "exists", too_long)
    assert _status(c, ws).status_code == 400


def test_guard_listed_root_without_sandbox_is_404(monkeypatch, tmp_path):
    bare = tmp_path / "bare"
    bare.mkdir()
    assert _status(_client(monkeypatch, [bare]), bare).status_code == 404


# --- auth stays first -------------------------------------------------------------

def test_guard_agent_token_is_403_on_a_listed_root(monkeypatch, ws):
    c = _client(monkeypatch, [ws], token=AGENT)
    assert _status(c, ws).status_code == 403
    assert c.post("/api/v1/connector/x/approve", params={"root": str(ws)}, json={}).status_code == 403


def test_guard_no_token_is_401_on_a_listed_root(monkeypatch, ws):
    assert _status(_client(monkeypatch, [ws], token=None), ws).status_code == 401


# --- fuzz with a listed root (Q1): the walkers now stop at 403 ---------------------
# Found while writing this test (18 Oct 2026): `request_id` is not validated.
# A NUL byte gives 500 (os.rename ValueError in queue.claim), and on Windows a
# backslash request_id ("..\..\..\..\victim") walks out of
# .sandbox/escalations and deletes an arbitrary *.json file via /deny. Reported
# to security-engineer and lead; RED until fixed.


class RequestIdUnvalidated(AssertionError):
    """`request_id` reaches the filesystem unvalidated (NUL -> 500, backslash traversal on Windows)."""


JUNK = ["zap", "../../../../etc/passwd", "-1", "99999999999999999999", "' OR '1'='1", "%00", "x" * 300]


def test_junk_values_on_a_listed_root_never_5xx(monkeypatch, ws):
    c = _client(monkeypatch, [ws])
    crashes = []
    for path, ops in c.app.openapi()["paths"].items():
        if not path.startswith("/api/v1/connector"):
            continue
        for method in ops:
            for value in JUNK:
                url = path.replace("{request_id}", value.replace("/", "%2F"))
                for body in (None, {}, {"reason": value}, [value]):
                    r = c.request(method.upper(), url, params={"root": str(ws), "limit": value},
                                  **({} if body is None else {"json": body}))
                    if r.status_code >= 500:
                        crashes.append(f"{method.upper()} {url} {body!r} -> {r.status_code}")
    if crashes:
        raise RequestIdUnvalidated(f"{len(crashes)} server errors with a listed root: {crashes[:6]}")


def test_request_id_cannot_reach_files_outside_the_queue(monkeypatch, ws, tmp_path):
    victim = tmp_path / "victim.json"
    body = json.dumps({"request_id": "victim", "command": "echo x"})
    victim.write_text(body, encoding="utf-8")
    c = _client(monkeypatch, [ws])
    back = "%5C"  # a backslash: a path separator on Windows, a plain character on POSIX
    hostile = [back.join(["..", "..", "..", "..", "victim"]), "..", ".", "%00", "a%00b"]
    bad = []
    for rid in hostile:
        for action in ("deny", "approve"):
            r = c.post(f"/api/v1/connector/{rid}/{action}", params={"root": str(ws)}, json={"reason": "t"})
            if r.status_code >= 500 or r.status_code == 200:
                bad.append(f"{action} {rid!r} -> {r.status_code}")
            if not victim.exists() or victim.read_text(encoding="utf-8") != body:
                raise RequestIdUnvalidated(f"{action} with request_id {rid!r} moved or rewrote {victim}")
    if bad:
        raise RequestIdUnvalidated(f"hostile request ids were not refused with a 4xx: {bad}")


# --- D1.7: is_agent_route uses a path boundary -------------------------------------

def test_is_agent_route_matches_on_a_path_boundary(monkeypatch):
    monkeypatch.setattr(auth, "AGENT_ROUTES", (("POST", "/api/v1/sync"),))
    assert auth.is_agent_route("POST", "/api/v1/sync")
    assert auth.is_agent_route("POST", "/api/v1/sync/push")
    assert not auth.is_agent_route("GET", "/api/v1/sync")
    _require(not auth.is_agent_route("POST", "/api/v1/syncX"),
             "a planted agent route /api/v1/sync also grants /api/v1/syncX (raw prefix match)")


# --- D1.5: loopback by default ------------------------------------------------------

def test_guard_serve_binds_loopback_by_default_and_refuses_open_bind_without_tokens(monkeypatch):
    from sandbox.cli.main import serve

    host = next(p for p in serve.params if p.name == "host")
    assert host.default == "127.0.0.1"
    monkeypatch.delenv(auth.AGENT_ENV, raising=False)
    monkeypatch.delenv(auth.APPROVER_ENV, raising=False)
    with pytest.raises(SystemExit):
        auth.check_bind("0.0.0.0")


# --- Q6: a real `sandbox serve --root X --workers 2` --------------------------------

def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_real_serve_with_root_and_two_workers(ws, other, tmp_path):
    port = _free_port()
    env = {**os.environ, auth.AGENT_ENV: AGENT, auth.APPROVER_ENV: APPROVER,
           "PYTHONPATH": str(pathlib.Path(__file__).resolve().parents[2] / "src")}
    env.pop(ROOTS_ENV, None)
    log = (tmp_path / "serve.log").open("wb")
    launcher = "import sys; from sandbox.cli.main import cli; sys.argv = ['sandbox', *sys.argv[1:]]; cli()"
    proc = subprocess.Popen([sys.executable, "-c", launcher, "serve", "--host", "127.0.0.1",
                             "--port", str(port), "--workers", "2", "--root", str(ws)],
                            cwd=tmp_path, env=env, stdout=log, stderr=subprocess.STDOUT,
                            **({} if WINDOWS else {"start_new_session": True}))
    try:
        base = f"http://127.0.0.1:{port}"
        up = False
        for _ in range(60):
            if proc.poll() is not None:
                break
            try:
                up = httpx.get(f"{base}/health", timeout=1).status_code == 200
            except httpx.HTTPError:
                up = False
            if up:
                break
            time.sleep(0.5)
        if not up:
            log.close()
            raise RootAllowlistOpen("`sandbox serve --root X --workers 2` did not come up: "
                                    + (tmp_path / "serve.log").read_text(errors="replace")[-400:])
        h = {"Authorization": f"Bearer {APPROVER}"}
        codes = set()
        for _ in range(8):  # several requests, so both workers are likely to answer
            codes.add((httpx.get(f"{base}/api/v1/connector/status", params={"root": str(ws)}, headers=h).status_code,
                       httpx.get(f"{base}/api/v1/connector/status", params={"root": str(other)}, headers=h).status_code))
        _require(codes == {(200, 403)}, f"listed root / other root gave {sorted(codes)}, want {{(200, 403)}}")
    finally:
        _kill_tree(proc)
        log.close()


def _kill_tree(proc: subprocess.Popen) -> None:
    """Stop the server and its worker processes."""
    if proc.poll() is None:
        if WINDOWS:
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
        else:
            import signal

            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
