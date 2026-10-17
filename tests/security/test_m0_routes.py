"""M0 route tests written before any deletion (REVIEW_QA.md section 3, R3 and R7).

R3 replaces test_api_auth.py::test_agent_can_submit_but_not_approve and R7
replaces test_api_connector.py::test_m1_routes_still_exist. The old tests stay
until T4, which deletes them together with the legacy routes.

Each test has two parts:
1. Properties that already hold today. They are plain asserts: a failure here
   is a real regression and fails the run.
2. Properties that only hold once T4 has removed the legacy routes. A breach
   raises ``LegacyStillPresent``. The strict xfail accepts that exception and
   nothing else, so the test is "RED for the stated reason only". When T4
   lands, the test passes, the strict xfail turns that into a failure, and the
   decorator must be deleted (a one-line strengthening, nothing else changes).

Legacy URLs are never requested while their routes are still mounted: with
the approver or agent token, POST /e2b/v1/sandboxes reaches the Windows Job
Object code that crashes the interpreter (M0_INVENTORY.md section 0).
"""
from __future__ import annotations

import sys

import pytest
from fastapi.testclient import TestClient

from sandbox.api import auth
from sandbox.api.app import create_app
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.queue import EscalationQueue

AGENT = "agent-token-m0"
APPROVER = "approver-token-m0"


class LegacyStillPresent(AssertionError):
    """A legacy route or the agent role is still mounted (expected until T4)."""


RED_UNTIL_T4 = pytest.mark.xfail(
    raises=LegacyStillPresent, strict=True,
    reason="RED until T4 deletes the legacy routes and empties AGENT_ROUTES",
)

# R7 allowlist: the only paths the API may serve after M0.
ALLOWED_EXACT = {"/health", "/ready"}
ALLOWED_PREFIX = "/api/v1/connector/"
# FastAPI's own schema and docs routes (public, no handlers of ours).
DOCS_ROUTES = {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}

# Concrete legacy URLs (method, path) that must be 404 after T4.
LEGACY_URLS = [
    ("POST", "/api/v1/launch"),
    ("GET", "/api/v1/launch/x"),
    ("POST", "/api/v1/hook/evaluate"),
    ("POST", "/api/v1/hook/audit"),
    ("POST", "/api/v1/hook/connect"),
    ("POST", "/api/v1/hook/disconnect/x"),
    ("GET", "/api/v1/broker/pending"),
    ("POST", "/api/v1/broker/request"),
    ("POST", "/api/v1/broker/x/approve"),
    ("POST", "/e2b/v1/sandboxes"),
    ("GET", "/e2b/v1/sandboxes"),
    ("POST", "/api/v1/runtime/spawn"),
    ("GET", "/api/v1/hitl/pending"),
    ("GET", "/api/v1/hitl-mem/pending"),
    ("POST", "/api/v1/translate"),
    ("POST", "/api/v1/agents/oauth2/token"),
    ("POST", "/oauth2/token"),
    ("GET", "/api/v1/sessions"),
    ("GET", "/api/v1/requests/"),
    ("GET", "/api/v1/policies"),
    ("GET", "/api/v1/security/score"),
    ("GET", "/api/v1/dashboard/stats"),
    ("GET", "/api/v1/audit/sessions/x"),
    ("GET", "/ws/events"),
]
LEGACY_PREFIXES = ("/api/v1/launch", "/api/v1/hook", "/api/v1/broker", "/e2b/v1",
                   "/api/v1/runtime", "/api/v1/hitl", "/api/v1/translate", "/api/v1/agents",
                   "/oauth2/token", "/ws/events", "/api/v1/sessions", "/api/v1/requests",
                   "/api/v1/policies", "/api/v1/security", "/api/v1/dashboard", "/api/v1/audit")


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv(auth.AGENT_ENV, AGENT)
    monkeypatch.setenv(auth.APPROVER_ENV, APPROVER)
    return create_app()


def _client(app, token: str | None) -> TestClient:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return TestClient(app, raise_server_exceptions=False, headers=headers)


def _operations(app):
    for path, ops in sorted(app.openapi()["paths"].items()):
        for method in sorted(ops):
            yield method.upper(), path


def _fill(path: str, rid: str = "r1") -> str:
    return path.replace("{request_id}", rid).replace("{", "").replace("}", "")


def _route_paths(app) -> set[str]:
    """Every mounted path, HTTP and WebSocket (OpenAPI omits WebSockets).

    Newer FastAPI keeps included routers as wrapper objects in
    ``app.router.routes`` (path ""), so walk into them.
    """
    found: set[str] = set()

    def walk(routes, prefix: str) -> None:
        for r in routes:
            inner = getattr(r, "original_router", None)
            if inner is not None:
                ctx = getattr(r, "include_context", None)
                walk(inner.routes, prefix + (getattr(ctx, "prefix", "") or ""))
                continue
            path = getattr(r, "path", None)
            if path is None:
                raise AssertionError(f"unknown route type {type(r)!r}")
            found.add(prefix + path)

    walk(app.router.routes, "")
    return found


def _allowed(path: str) -> bool:
    return path in ALLOWED_EXACT or path.startswith(ALLOWED_PREFIX)


def _audit_lines(layout: FolderLayout) -> list[str]:
    lines: list[str] = []
    if layout.audit_dir.exists():
        for f in layout.audit_dir.rglob("*.jsonl"):
            lines += f.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines


# --- R3 -----------------------------------------------------------------------

def test_r3_agent_token_cannot_decide_or_read(app, tmp_path):
    """R3: with a queued escalation, the agent token gets 403 on approve, deny,
    pending, audit and status; the request stays pending and nothing runs; the
    agent token gets 403 on every non-public OpenAPI path; AGENT_ROUTES == ()."""
    init(tmp_path, claude=False, mcp=False)
    layout = FolderLayout(tmp_path)
    queue = EscalationQueue(layout)
    marker = tmp_path / "side_effect.txt"
    rid = queue.submit({
        "root": str(tmp_path), "origin": "hook", "trigger": ["shell"],
        "command": f'"{sys.executable}" -c "open(\'side_effect.txt\', \'w\').write(\'ran\')"',
        "exec_cwd": str(tmp_path), "kind": "command",
    })
    assert queue.status(rid) == "pending"
    audit_before = _audit_lines(layout)

    agent = _client(app, AGENT)
    root = {"root": str(tmp_path)}
    decision = {"reason": "the agent approving its own request"}
    calls = {
        "approve": agent.post(f"/api/v1/connector/{rid}/approve", params=root, json=decision),
        "deny": agent.post(f"/api/v1/connector/{rid}/deny", params=root, json=decision),
        "pending": agent.get("/api/v1/connector/pending", params=root),
        "audit": agent.get("/api/v1/connector/audit", params=root),
        "status": agent.get("/api/v1/connector/status", params=root),
    }
    assert {k: r.status_code for k, r in calls.items()} == {k: 403 for k in calls}

    # Nothing moved and nothing ran.
    assert queue.status(rid) == "pending"
    assert [r["request_id"] for r in queue.list_pending()] == [rid]
    assert not marker.exists()
    assert not (layout.done_dir / f"{rid}.json").exists()
    assert not (layout.out_dir / f"{rid}.txt").exists()
    new_audit = _audit_lines(layout)[len(audit_before):]
    assert not [line for line in new_audit if "executed" in line], new_audit

    # 403 on every non-public OpenAPI path outside AGENT_ROUTES (holds today).
    # Paths inside AGENT_ROUTES are not requested: today they include
    # /e2b/v1/*, which executes commands and crashes the interpreter.
    agent_reachable, not_403 = [], []
    for method, path in _operations(app):
        if auth.is_public(path):
            continue
        if auth.is_agent_route(method, path):
            agent_reachable.append(f"{method} {path}")
            continue
        r = agent.request(method, _fill(path), params=root, json={})
        if r.status_code != 403:
            not_403.append(f"{method} {path} -> {r.status_code}")
    assert not not_403, not_403
    assert queue.status(rid) == "pending" and not marker.exists()

    # Positive control: the same request, approved by the approver, does run,
    # so the side-effect check above can see an execution.
    r = _client(app, APPROVER).post(f"/api/v1/connector/{rid}/approve", params=root,
                                    json={"reason": "R3 positive control"})
    assert r.status_code == 200, r.text
    assert r.json()["state"] in ("executed", "awaiting_second_approval")
    if r.json()["state"] == "executed":
        assert marker.read_text() == "ran"

    # After T4: the agent role grants nothing.
    if auth.AGENT_ROUTES or agent_reachable:
        raise LegacyStillPresent(
            f"AGENT_ROUTES={auth.AGENT_ROUTES!r}; agent-reachable paths: {agent_reachable}")


# --- R7 -----------------------------------------------------------------------

def test_r7_only_health_and_connector_routes_exist(app):
    """R7: OpenAPI paths are a subset of {/health, /ready, /api/v1/connector/*};
    the legacy paths are absent and get 404 with the approver token. Also keeps
    the properties of the deleted unconfigured_redis and install_or_remove_hooks
    tests."""
    approver = _client(app, APPROVER)
    agent = _client(app, AGENT)

    # Holds today: health is public, the connector view is mounted.
    assert approver.get("/health").status_code == 200
    spec_paths = set(app.openapi()["paths"])
    for p in ("/api/v1/connector/status", "/api/v1/connector/pending",
              "/api/v1/connector/{request_id}/approve", "/api/v1/connector/{request_id}/deny"):
        assert p in spec_paths, p
    # Holds today (was test_unconfigured_redis_review_api_is_not_mounted).
    assert approver.get("/api/v1/hitl/pending").status_code == 404
    assert not any(p.startswith("/api/v1/hitl/") for p in spec_paths)
    # Holds today (was test_agent_cannot_install_or_remove_hooks): the agent
    # token never reaches hook install/remove. The middleware answers 403
    # before routing today; after T4 the route is gone (403 or 404).
    assert agent.post("/api/v1/hook/connect", json={}).status_code in (403, 404)
    assert agent.post("/api/v1/hook/disconnect/x").status_code in (403, 404)

    # After T4: nothing outside the allowlist is mounted.
    extra_spec = sorted(p for p in spec_paths if not _allowed(p))
    extra_routes = sorted(p for p in _route_paths(app)
                          if p not in DOCS_ROUTES and not _allowed(p))
    legacy_mounted = sorted(p for p in _route_paths(app) if p.startswith(LEGACY_PREFIXES))
    if extra_spec or extra_routes or legacy_mounted:
        raise LegacyStillPresent(
            f"OpenAPI paths outside the allowlist: {extra_spec}; mounted routes outside "
            f"the allowlist: {extra_routes}; legacy routes mounted: {legacy_mounted}")

    # Only reached once no legacy route is mounted, so no legacy handler can run.
    wrong = []
    for method, url in LEGACY_URLS:
        for c, name in ((approver, "approver"), (agent, "agent")):
            r = c.request(method, url, json={})
            want = (404,) if name == "approver" else (403, 404)
            if r.status_code not in want:
                wrong.append(f"{name} {method} {url} -> {r.status_code}")
    assert not wrong, wrong
