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
