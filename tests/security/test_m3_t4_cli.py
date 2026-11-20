"""M3 T4 root CLI tests: deny-all base, _safe_str sanitisation.

Spec: T4_SPEC.md section 3.4.  Four nodes, two guards.
"""
from __future__ import annotations

import ast
import hashlib
import importlib
import json
import os
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import click
import pytest

from tests.m3_pending import M3T4Pending, require_m3

_SRC = Path(__file__).resolve().parent.parent.parent / "src"
_BUNDLES_PATH = _SRC / "sandbox" / "connector" / "sync" / "bundles.py"
_CHANGE_CMDS_PATH = _SRC / "sandbox" / "cli" / "change_cmds.py"


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------

def _connector_deny_all_literal() -> dict:
    """Extract the deny-all dict literal from verify_and_apply's no-bundle branch."""
    source = _BUNDLES_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name != "verify_and_apply":
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name) and target.id == "enforced":
                        if isinstance(child.value, ast.Dict):
                            return ast.literal_eval(child.value)
    raise AssertionError("could not find the enforced dict in verify_and_apply")


def _cli_deny_all_literal() -> dict:
    """Extract the deny-all dict from change_cmds.py via AST or callable.

    Handles both a module-level DENY_ALL_BASE dict (today) and a
    deny_all_base() function returning a dict literal (after T4).
    """
    source = _CHANGE_CMDS_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    # Try module-level dict assignment
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "DENY_ALL_BASE":
                    if isinstance(node.value, ast.Dict):
                        return ast.literal_eval(node.value)
        # Try function that returns a dict literal
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in ("deny_all_base", "DENY_ALL_BASE"):
                for child in ast.walk(node):
                    if isinstance(child, ast.Return) and child.value is not None:
                        if isinstance(child.value, ast.Dict):
                            return ast.literal_eval(child.value)
    # Fallback: call it if callable
    mod = importlib.import_module("sandbox.cli.change_cmds")
    obj = getattr(mod, "deny_all_base", None) or getattr(mod, "DENY_ALL_BASE", None)
    if callable(obj):
        return obj()
    if isinstance(obj, dict):
        return dict(obj)
    raise AssertionError(
        "could not find deny-all dict in change_cmds.py "
        "(neither a module-level dict, a function returning a dict, "
        "nor a callable)"
    )


def _propose_fstrings_use_safe_str() -> bool:
    """Check whether the 'server dropped section' and 'server altered'
    f-strings in propose_bundle wrap their values in _safe_str."""
    source = _CHANGE_CMDS_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    propose_fn = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "propose_bundle":
            propose_fn = node
            break
    if propose_fn is None:
        return False
    prefixes = {"server dropped section": False, "server altered": False}
    for child in ast.walk(propose_fn):
        if not isinstance(child, ast.JoinedStr):
            continue
        for prefix in prefixes:
            has_prefix = any(
                isinstance(v, ast.Constant) and isinstance(v.value, str)
                and prefix in v.value
                for v in child.values
            )
            if not has_prefix:
                continue
            for val in child.values:
                if not isinstance(val, ast.FormattedValue):
                    continue
                inner = val.value
                if not isinstance(inner, ast.Call):
                    return False
                fname = None
                if isinstance(inner.func, ast.Name):
                    fname = inner.func.id
                elif isinstance(inner.func, ast.Attribute):
                    fname = inner.func.attr
                if fname != "_safe_str":
                    return False
            prefixes[prefix] = True
    return all(prefixes.values())


# ------------------------------------------------------------------
# helpers for behavioural tests
# ------------------------------------------------------------------

class _FakeResponse:
    """Minimal stand-in for an httpx.Response."""
    def __init__(self, status_code, body=None, headers=None):
        self.status_code = status_code
        self._body = body or {}
        self.headers = headers or {"content-type": "application/json"}

    def json(self):
        return self._body


class _FakeClient:
    """A context-manager httpx.Client that returns canned responses."""
    def __init__(self, routes=None, **kwargs):
        self._routes = routes or {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def get(self, url, **kw):
        for pattern, resp in self._routes.items():
            if pattern in url:
                return resp
        return _FakeResponse(404)

    def post(self, url, **kw):
        for pattern, resp in self._routes.items():
            if pattern in url:
                return resp
        return _FakeResponse(404)


def _make_key_file(tmp_path):
    """Create a signing key file and return (path, sk, kid)."""
    from nacl.signing import SigningKey
    sk = SigningKey.generate()
    seed = bytes(sk)
    kf = tmp_path / "test_key.seed"
    kf.write_bytes(seed)
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    return str(kf), sk, kid


# ------------------------------------------------------------------
# guard: CLI deny-all matches the connector literal
# ------------------------------------------------------------------

def test_cli_deny_all_base_matches_connector_literal():
    """ast pin: the CLI's deny-all base equals the connector step-10 literal."""
    cli_literal = _cli_deny_all_literal()
    connector_literal = _connector_deny_all_literal()
    assert cli_literal == connector_literal, (
        f"CLI deny-all {cli_literal} != connector {connector_literal}"
    )


# ------------------------------------------------------------------
# SHOULD: deny-all base is fresh per call (no module-level dict)
# ------------------------------------------------------------------

@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_cli_deny_all_base_fresh_per_call():
    """change_cmds has no module-level DENY_ALL_BASE dict; two calls
    return equal, distinct objects."""
    from sandbox.cli import change_cmds as _cm
    require_m3(
        4,
        not isinstance(getattr(_cm, "DENY_ALL_BASE", None), dict),
        "DENY_ALL_BASE is still a module-level dict (T4 converts it to a function)",
    )

    source = _CHANGE_CMDS_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    # Check that there is no module-level assignment to DENY_ALL_BASE
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = []
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, ast.AnnAssign) and node.target:
                targets = [node.target]
            for t in targets:
                if isinstance(t, ast.Name) and t.id == "DENY_ALL_BASE":
                    raise AssertionError(
                        "DENY_ALL_BASE is a module-level dict; must be a function"
                    )
    # Verify two calls return equal, distinct objects
    fn = getattr(_cm, "deny_all_base", None) or getattr(_cm, "DENY_ALL_BASE", None)
    if callable(fn):
        a = fn()
        b = fn()
        assert a == b, "two calls must return equal dicts"
        assert a is not b, "two calls must return distinct objects"
    else:
        raise AssertionError("DENY_ALL_BASE is not a callable; must be a function")


# ------------------------------------------------------------------
# guard: approve-change ESC in loosened error sanitised (behavioural)
# ------------------------------------------------------------------

def test_approve_change_esc_in_loosened_error_no_raw_esc(tmp_path, monkeypatch):
    """Behavioural: a base payload that makes loosened raise with an ESC in
    the message -- the ClickException message holds no raw ESC (\\x1b).
    Passes today because _safe_str wraps the exception at change_cmds.py:466.
    Bites when _safe_str is removed at that call site."""
    from sandbox.cli import change_cmds
    from sandbox.connector.sync.bundles import _bundle_hash
    from sandbox.protocol.envelope import canonical_bytes
    from nacl.signing import SigningKey as SK

    key_file, sk, kid = _make_key_file(tmp_path)

    # Build a minimal registry chain so verify_chain passes.
    admin_sk = sk
    admin_pub = bytes(admin_sk.verify_key)
    admin_kid = hashlib.sha256(admin_pub).hexdigest()
    org_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    bs_sk = SK.generate()
    bs_pub = bytes(bs_sk.verify_key)
    bs_kid = hashlib.sha256(bs_pub).hexdigest()
    keys_list = [{
        "key_id": admin_kid,
        "public_key": admin_pub.hex(),
        "user_id": str(uuid.uuid4()),
        "iss": "test", "sub": "s-test",
        "alg": "ed25519",
        "kind": "cli",
        "roles": ["admin", "approver"],
        "added_in": 1,
    }]
    genesis_payload = {
        "org_id": org_id, "version": 1, "prev_hash": "",
        "threshold": 1,
        "admins": [admin_kid],
        "keys": keys_list,
        "bundle_signer": {
            "key_id": bs_kid,
            "public_key": bs_pub.hex(),
            "alg": "ed25519",
        },
        "expires_at": 9_999_999_999.0,
    }
    msg = canonical_bytes("agg/registry/v1", genesis_payload)
    sig = admin_sk.sign(msg).signature.hex()
    genesis_env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": genesis_payload,
        "signatures": [{"key_id": admin_kid, "alg": "ed25519", "sig": sig}],
    }
    fp = hashlib.sha256(
        org_id.encode() + b":" +
        json.dumps(genesis_payload, sort_keys=True,
                   separators=(",", ":")).encode()
    ).hexdigest()

    # Build the proposal bundle (base_sequence=0, so base = DENY_ALL_BASE)
    proposal_bundle = {
        "org_id": org_id,
        "project_id": project_id,
        "sequence": 1,
        "base_sequence": 0,
        "registry_version": 1,
        "issued_at": 1_700_000_000,
        "not_before": 1_700_000_000,
        "folder_policy": {"shell": {"blocklist_action": "allow"}},
    }
    phash = _bundle_hash(proposal_bundle)

    # Build canned HTTP responses
    token_resp = _FakeResponse(200, {"token": "fake-token-abc"})
    registry_resp = _FakeResponse(200, [genesis_env])
    detail_resp = _FakeResponse(200, {
        "bundle": proposal_bundle,
        "bundle_hash": phash,
    })

    routes = {
        "/api/v1/sync/signer/token": token_resp,
        "/api/v1/sync/signer/registry": registry_resp,
        "/api/v1/admin/bundle-proposals/": detail_resp,
    }
    fake_client = _FakeClient(routes=routes)

    # Monkeypatch loosened to raise with ESC in the message
    esc_msg = "\x1b[31mmalicious terminal escape\x1b[0m"

    def _loosened_raises(base, new):
        raise ValueError(esc_msg)

    monkeypatch.setattr(change_cmds, "loosened", _loosened_raises)

    # Monkeypatch httpx.Client to use our fake
    import httpx
    monkeypatch.setattr(httpx, "Client", lambda **kw: fake_client)

    # Drive the real code path: call approve_change's callback directly
    # and catch the ClickException to inspect its message.
    with pytest.raises(click.ClickException) as exc_info:
        change_cmds.approve_change.callback(
            proposal_id="00000000-0000-0000-0000-000000000001",
            server="http://localhost:9999",
            key_file=key_file,
            expect_fingerprint=fp,
            yes=True,
        )

    exc_message = exc_info.value.message
    assert "loosened error" in exc_message, (
        f"expected 'loosened error' in exception: {exc_message!r}"
    )
    assert "\x1b" not in exc_message, (
        f"raw ESC (\\x1b) found in ClickException message: {exc_message!r}"
    )


# ------------------------------------------------------------------
# SHOULD: propose-bundle local key messages sanitised (behavioural)
# ------------------------------------------------------------------

@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_propose_bundle_local_key_messages_sanitised(tmp_path, monkeypatch):
    """Behavioural: a bundle file key containing ESC where a stub server
    drops or alters it -- the ClickException message holds no raw ESC.
    Gate: the _safe_str wrapping on 'server dropped section' and
    'server altered' in propose_bundle (not present today)."""
    # Gate: check whether _safe_str wrapping is in place (no agg_cp reference)
    require_m3(
        4,
        _propose_fstrings_use_safe_str(),
        "propose-bundle 'server dropped/altered' messages not yet "
        "wrapped in _safe_str (T4)",
    )

    from sandbox.cli import change_cmds
    from sandbox.connector.sync.bundles import _bundle_hash
    import httpx

    key_file, sk, kid = _make_key_file(tmp_path)

    # Build a bundle with an ESC-containing key
    esc_key = "\x1b[31mevil"
    bundle = {
        "org_id": str(uuid.uuid4()),
        "project_id": str(uuid.uuid4()),
        "sequence": 1,
        "base_sequence": 0,
        "registry_version": 1,
        "issued_at": 1_700_000_000,
        "not_before": 1_700_000_000,
        esc_key: "some-value",
    }
    bundle_file = tmp_path / "bundle.json"
    bundle_file.write_text(json.dumps(bundle), encoding="utf-8")

    # Server response drops the ESC key
    server_bundle = {k: v for k, v in bundle.items() if k != esc_key}
    server_hash = _bundle_hash(server_bundle)

    token_resp = _FakeResponse(200, {"token": "fake-token-abc"})
    post_resp = _FakeResponse(201, {
        "id": str(uuid.uuid4()),
        "bundle": server_bundle,
        "bundle_hash": server_hash,
    })
    routes = {
        "/api/v1/sync/signer/token": token_resp,
        "/api/v1/admin/bundle-proposals": post_resp,
    }
    fake_client = _FakeClient(routes=routes)
    monkeypatch.setattr(httpx, "Client", lambda **kw: fake_client)

    # Test 1: server drops the ESC key
    with pytest.raises(click.ClickException) as exc_info:
        change_cmds.propose_bundle.callback(
            server="http://localhost:9999",
            project=bundle["project_id"],
            bundle_file=str(bundle_file),
            key_file=key_file,
        )

    msg1 = exc_info.value.message
    assert "server dropped section" in msg1.lower(), (
        f"expected 'server dropped section' in: {msg1!r}"
    )
    assert "\x1b" not in msg1, (
        f"raw ESC in 'server dropped' message: {msg1!r}"
    )

    # Test 2: server alters the ESC key
    server_bundle_alt = dict(bundle)
    server_bundle_alt[esc_key] = "altered-value"
    server_hash_alt = _bundle_hash(server_bundle_alt)
    post_resp_alt = _FakeResponse(201, {
        "id": str(uuid.uuid4()),
        "bundle": server_bundle_alt,
        "bundle_hash": server_hash_alt,
    })
    routes_alt = {
        "/api/v1/sync/signer/token": token_resp,
        "/api/v1/admin/bundle-proposals": post_resp_alt,
    }
    fake_client_alt = _FakeClient(routes=routes_alt)
    monkeypatch.setattr(httpx, "Client", lambda **kw: fake_client_alt)

    with pytest.raises(click.ClickException) as exc_info:
        change_cmds.propose_bundle.callback(
            server="http://localhost:9999",
            project=bundle["project_id"],
            bundle_file=str(bundle_file),
            key_file=key_file,
        )

    msg2 = exc_info.value.message
    assert "server altered" in msg2.lower(), (
        f"expected 'server altered' in: {msg2!r}"
    )
    assert "\x1b" not in msg2, (
        f"raw ESC in 'server altered' message: {msg2!r}"
    )
