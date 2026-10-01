"""The API must not crash on malformed input, and must not leak internals.

From the ZAP API scan in CI: 255 server errors (every /api/v1/hitl route
crashed because its Redis queue was never configured), error responses read
as error disclosure, and missing security headers. This walks every route in
the OpenAPI spec with malformed path, query and body values, the way ZAP
does, from a throwaway working directory (some routes write files there).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sandbox.api import auth
from sandbox.api.app import create_app

VALUES = ["zap", "../../../../etc/passwd", "-1", "99999999999999999999", "' OR '1'='1"]
RAW_BODIES = [b'{"broken": ', bytes([0xFF, 0xFE]), b"<xml/>"]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(auth.AGENT_ENV, "agent-t")
    monkeypatch.setenv(auth.APPROVER_ENV, "approver-t")
    app = create_app()
    return TestClient(app, raise_server_exceptions=False, headers={"Authorization": "Bearer approver-t"})


def _requests(spec):
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            for value in VALUES:
                url, query = path, {}
                for p in op.get("parameters", []):
                    if p["in"] == "path":
                        url = url.replace("{" + p["name"] + "}", value.replace("/", "%2F"))
                    elif p["in"] == "query":
                        query[p["name"]] = value
                if "requestBody" in op:
                    for body in ({}, {"x": value}, [value]):
                        yield method.upper(), url, query, {"json": body}
                    for raw in RAW_BODIES:
                        yield method.upper(), url, query, {"content": raw, "headers": {"Content-Type": "application/json"}}
                else:
                    yield method.upper(), url, query, {}


def test_no_route_crashes_on_malformed_input(client):
    crashes = []
    for method, url, query, kwargs in _requests(client.app.openapi()):
        r = client.request(method, url, params=query, **kwargs)
        if r.status_code >= 500:
            crashes.append(f"{method} {url} -> {r.status_code}")
    assert not crashes, crashes[:10]


def _schema_valid_bodies(spec, op):
    """Bodies that match the request schema's shape with junk values: what ZAP
    sends, and what got past FastAPI's own validation into the route code
    (hook/connect, runtime/spawn and e2b sandboxes crashed on them)."""
    content = (op.get("requestBody") or {}).get("content", {}).get("application/json", {})
    schema = content.get("schema", {})
    if "$ref" in schema:
        schema = spec["components"]["schemas"][schema["$ref"].split("/")[-1]]
    props = schema.get("properties", {})

    def resolve(node):
        return spec["components"]["schemas"][node["$ref"].split("/")[-1]] if "$ref" in node else node

    def enum_value(node):
        node = resolve(node)
        return node["enum"][0] if node.get("enum") else None

    for text, number in (("zap", 10**12), ("-1", -1)):
        body = {}
        for name, prop in props.items():
            prop = resolve(prop)
            # A valid enum value where the schema has one, as ZAP does: junk
            # there is rejected by validation and never reaches the route code
            # (which is how runtime/spawn's NameError hid from this test).
            if enum_value(prop) is not None:
                body[name] = enum_value(prop)
                continue
            if prop.get("type") == "array" and enum_value(prop.get("items", {})) is not None:
                body[name] = [enum_value(prop["items"])]
                continue
            kind = prop.get("type") or next((a.get("type") for a in prop.get("anyOf", []) if a.get("type")), "string")
            body[name] = {"string": text, "integer": number, "number": float(number), "boolean": True,
                          "array": [text], "object": {"k": text}}.get(kind, text)
        yield body


def test_schema_valid_bodies_with_junk_values_do_not_crash(client):
    spec = client.app.openapi()
    crashes = []
    for path, ops in spec["paths"].items():
        if "{" in path:
            continue
        for method, op in ops.items():
            for body in _schema_valid_bodies(spec, op) if "requestBody" in op else []:
                r = client.request(method.upper(), path, json=body)
                if r.status_code >= 500:
                    crashes.append(f"{method.upper()} {path} {body} -> {r.status_code}")
    assert not crashes, crashes[:10]


def test_spawn_reaches_the_toolkit(client, monkeypatch):
    # runtime/spawn raised NameError ('docker_sandbox') on every call. The
    # agent's own run is replaced by a no-op so nothing real starts.
    from sandbox.agents.runtime import AgentRuntime

    async def no_run(self, run, toolkit, *args, **kwargs):
        return None

    monkeypatch.setattr(AgentRuntime, "_run_generic_agent", no_run)
    r = client.post("/api/v1/runtime/spawn", json={"agent_type": "custom", "task": "t", "workspace_root": "ws"})
    assert r.status_code == 200, r.text
    assert client.post("/api/v1/runtime/spawn", json={"agent_type": "zap", "task": "t"}).status_code == 422


def test_hook_connect_rejects_a_bad_workspace_without_leaking_paths(client, tmp_path):
    from sandbox.api.app import get_session_manager

    before = len(get_session_manager()._sessions) if hasattr(get_session_manager(), "_sessions") else None
    bad = tmp_path / "not-a-dir.txt"
    bad.write_text("x")
    r = client.post("/api/v1/hook/connect", json={"workspace_root": str(bad)})
    assert r.status_code == 400 and str(tmp_path) not in r.text
    if before is not None:
        assert len(get_session_manager()._sessions) == before


def test_e2b_template_must_be_allowlisted(client, monkeypatch):
    r = client.post("/e2b/v1/sandboxes", json={"template": "attacker/miner:latest"})
    assert r.status_code == 422
    monkeypatch.setenv("E2B_TEMPLATES", "python:3.12-slim,node:22-slim")
    from sandbox.api.routes.e2b import CreateSandboxRequest

    assert CreateSandboxRequest(template="node:22-slim").template == "node:22-slim"


def test_unconfigured_redis_review_api_is_not_mounted(client):
    assert client.get("/api/v1/hitl/pending").status_code == 404
    assert not any(p.startswith("/api/v1/hitl/") for p in client.app.openapi()["paths"])


def test_security_headers_on_every_response(client):
    for r in (client.get("/health"), client.get("/api/v1/broker/pending"),
              TestClient(client.app).get("/api/v1/broker/pending")):  # 401 path too
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["cross-origin-resource-policy"] == "same-origin"
        assert r.headers["cache-control"] == "no-store"


def test_unexpected_errors_reveal_nothing(client):
    @client.app.get("/api/v1/_boom_for_test")
    async def boom():
        raise RuntimeError("secret internal detail at C:\\\\path\\\\file.py")

    r = client.get("/api/v1/_boom_for_test")
    assert r.status_code == 500
    body = r.json()
    assert body["detail"] == "Internal error" and len(body["error_id"]) == 12
    assert "secret" not in r.text and "RuntimeError" not in r.text and "Traceback" not in r.text
