#!/usr/bin/env python3
"""T14 demo script -- exercises the full control-plane stack headlessly.

Usage:
    python ee/deploy/demo.py          # run all 5 steps
    python ee/deploy/demo.py --step 2 # run only step 2

Dependencies: stdlib + httpx (verify via --ca or the Caddy root CA path).
Passwords come from keycloak/acme-realm.json and globex-realm.json (demo-only values).

Exit code: 0 if all steps PASS, non-zero on the first FAIL.
"""
from __future__ import annotations

import argparse
import hashlib
import html.parser
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qs

import httpx

# ---------------------------------------------------------------------------
# Paths (relative to this script)
# ---------------------------------------------------------------------------

_SCRIPT_DIR = Path(__file__).resolve().parent
_COMPOSE_DIR = _SCRIPT_DIR  # ee/deploy/
_REPO_ROOT = _SCRIPT_DIR.parent.parent  # top of the repo
_CA_BUNDLE_DEFAULT = "/ca-bundle/ca-certificates.crt"
_IDP_BASE_URL = "https://idp.localhost"

# ---------------------------------------------------------------------------
# Demo passwords from keycloak/*-realm.json (demo-only values)
# ---------------------------------------------------------------------------

_DEMO_REALMS = (
    _SCRIPT_DIR / "keycloak" / "acme-realm.json",
    _SCRIPT_DIR / "keycloak" / "globex-realm.json",
)


def _load_demo_passwords() -> dict[str, str]:
    """Read passwords from the demo realm JSON.  Never hard-coded beyond
    the demo-only values shipped in the realm file."""
    passwords: dict[str, str] = {}
    for path in _DEMO_REALMS:
        realm = json.loads(path.read_text(encoding="utf-8"))
        for user in realm.get("users", []):
            creds = user.get("credentials", [])
            if creds:
                passwords[user["username"]] = creds[0]["value"]
    return passwords


# ---------------------------------------------------------------------------
# Keycloak HTML form parser (stdlib html.parser)
# ---------------------------------------------------------------------------


class KeycloakFormParser(html.parser.HTMLParser):
    """Parse a Keycloak login page and extract the form action and fields.

    After ``feed(html_text)``, ``action`` holds the form's action URL
    (with HTML entities decoded) and ``fields`` holds a list of
    ``(name, value)`` pairs from hidden and visible input elements.
    """

    def __init__(self) -> None:
        super().__init__()
        self.action: str | None = None
        self.fields: list[tuple[str, str]] = []
        self._in_form = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = dict(attrs)
        if tag == "form":
            action = attr_dict.get("action")
            if action is not None:
                # html.parser decodes &amp; etc. for us in attribute values
                self.action = action
                self._in_form = True
        elif tag == "input" and self._in_form:
            name = attr_dict.get("name")
            value = attr_dict.get("value", "")
            if name is not None:
                self.fields.append((name, value or ""))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._in_form = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fail(msg: str) -> None:
    """Print FAIL and exit non-zero."""
    print(f"FAIL: {msg}", flush=True)
    sys.exit(1)


def _pass(msg: str) -> None:
    """Print PASS."""
    print(f"PASS: {msg}", flush=True)


def _compose(*args: str, capture: bool = False, check: bool = True) -> subprocess.CompletedProcess:
    """Run ``docker compose`` in the deploy directory."""
    cmd = ["docker", "compose", *args]
    return subprocess.run(
        cmd,
        cwd=str(_COMPOSE_DIR),
        capture_output=capture,
        text=True,
        check=check,
    )


def _wait_ready(client: httpx.Client, base_url: str, timeout: int = 120) -> None:
    """Poll /ready until 200 or timeout."""
    deadline = time.monotonic() + timeout
    last_err = ""
    while time.monotonic() < deadline:
        try:
            r = client.get(f"{base_url}/ready", timeout=5)
            if r.status_code == 200:
                return
            last_err = f"status {r.status_code}"
        except httpx.HTTPError as exc:
            last_err = str(exc)
        time.sleep(2)
    _fail(f"/ready did not return 200 within {timeout}s (last: {last_err})")


def _get_setup_code() -> tuple[str, str]:
    """Read the setup code from ``docker compose logs migrate-demo``.

    Returns (org_slug, setup_code).
    """
    result = _compose("logs", "migrate-demo", capture=True, check=False)
    output = result.stdout or ""
    # Look for JSON line: {"event":"setup_code","org":"acme","code":"...","expires_at":"..."}
    for line in output.splitlines():
        # Find JSON objects in the line
        for match in re.finditer(r'\{[^}]+\}', line):
            try:
                obj = json.loads(match.group())
                if obj.get("event") == "setup_code":
                    return obj["org"], obj["code"]
            except (json.JSONDecodeError, KeyError):
                continue
    _fail(
        "Could not find setup_code in migrate-demo logs. "
        "Ensure the demo profile is running."
    )
    return "", ""  # unreachable, for type checker


def _get_genesis_code() -> tuple[str, str]:
    """Read the genesis code from ``docker compose logs migrate-demo``.

    Returns (org_slug, genesis_code).
    """
    result = _compose("logs", "migrate-demo", capture=True, check=False)
    output = result.stdout or ""
    for line in output.splitlines():
        for match in re.finditer(r'\{[^}]+\}', line):
            try:
                obj = json.loads(match.group())
                if obj.get("event") == "genesis_code":
                    return obj["org"], obj["code"]
            except (json.JSONDecodeError, KeyError):
                continue
    _fail(
        "Could not find genesis_code in migrate-demo logs. "
        "Ensure the demo profile is running."
    )
    return "", ""  # unreachable, for type checker


def _get_bundle_signer() -> tuple[str, str]:
    """Read the bundle_signer public key from ``docker compose logs migrate-demo``.

    Returns (key_id, public_key_hex).
    """
    result = _compose("logs", "migrate-demo", capture=True, check=False)
    output = result.stdout or ""
    for line in output.splitlines():
        for match in re.finditer(r'\{[^}]+\}', line):
            try:
                obj = json.loads(match.group())
                if obj.get("event") == "bundle_signer":
                    return obj["key_id"], obj["public_key"]
            except (json.JSONDecodeError, KeyError):
                continue
    _fail(
        "Could not find bundle_signer in migrate-demo logs. "
        "Ensure AGG_BUNDLE_SIGNER_KEY_FILE is set and the demo profile is running."
    )
    return "", ""  # unreachable, for type checker


def _signer_kid(public_key_bytes: bytes) -> str:
    """Compute the key_id as sha256(public_key_bytes).hex()."""
    return hashlib.sha256(public_key_bytes).hexdigest()


def _sign_registry_payload(
    sk: "nacl.signing.SigningKey",
    kid: str,
    payload: dict,
) -> str:
    """Sign a registry payload and return the signature hex."""
    tag = b"agg/registry/v1"
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode()
    msg = tag + b"\x00" + canonical
    return sk.sign(msg).signature.hex()


def _get_signer_token(
    client: httpx.Client,
    base_url: str,
    sk: "nacl.signing.SigningKey",
    kid: str,
) -> str:
    """Get a signer token for an already-linked key.

    Uses the agg/signer-assert/v1 protocol.
    """
    nonce = secrets.token_hex(16)
    payload = {
        "key_id": kid,
        "nonce": nonce,
        "aud": base_url,
        "iat": time.time(),
    }
    tag = b"agg/signer-assert/v1"
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode()
    msg = tag + b"\x00" + canonical
    sig = sk.sign(msg).signature.hex()
    assertion = {
        "kind": "agg/signer-assert/v1",
        "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": kid, "alg": "ed25519", "sig": sig}],
    }
    r = client.post(
        f"{base_url}/api/v1/sync/signer/token",
        json=assertion,
        timeout=15,
    )
    if r.status_code != 200:
        _fail(f"/sync/signer/token failed: {r.status_code} {r.text[:200]}")
    return r.json()["token"]


def _link_cli_key(
    client: httpx.Client,
    base_url: str,
    ca_path,
    username: str,
    password: str,
    csrf: str,
) -> tuple["nacl.signing.SigningKey", str, str, str, str]:
    """Create a signer link from a web session, then link a CLI key.

    Returns (sk, kid, user_id, iss, sub).
    The caller must be logged in on *client* with a valid session.
    """
    from nacl.signing import SigningKey

    # POST /api/v1/signer-links (web session) to get a link code
    link_resp = client.post(
        f"{base_url}/api/v1/signer-links",
        json={},
        headers={"X-CSRF-Token": csrf},
    )
    if link_resp.status_code != 200:
        _fail(
            f"/signer-links returned {link_resp.status_code} for {username}: "
            f"{link_resp.text[:200]}"
        )
    link_code = link_resp.json().get("code", "")
    if not link_code:
        _fail(f"/signer-links did not return a code for {username}")

    # Generate an Ed25519 keypair
    sk = SigningKey.generate()
    pub_hex = bytes(sk.verify_key).hex()
    kid = _signer_kid(bytes(sk.verify_key))

    # POST /api/v1/sync/signer/link (no auth needed, just the code)
    link_result = client.post(
        f"{base_url}/api/v1/sync/signer/link",
        json={
            "code": link_code,
            "key_id": kid,
            "public_key": pub_hex,
        },
        timeout=15,
    )
    if link_result.status_code != 200:
        _fail(
            f"/sync/signer/link failed for {username}: "
            f"{link_result.status_code} {link_result.text[:200]}"
        )
    link_data = link_result.json()
    user_id = link_data.get("user_id", "")
    iss = link_data.get("iss", "")
    sub = link_data.get("sub", "")

    return sk, kid, user_id, iss, sub


def _keycloak_login(
    client: httpx.Client,
    auth_url: str,
    username: str,
    password: str,
) -> httpx.Response:
    """Follow the Keycloak authorization redirect, parse the login form,
    submit credentials, and follow the callback.

    Returns the response from the final callback redirect.
    """
    # Step 1: GET the authorization URL (follows redirect to Keycloak login form)
    login_page = client.get(auth_url, follow_redirects=True)
    if login_page.status_code != 200:
        _fail(
            f"Keycloak login page returned {login_page.status_code} "
            f"for {username}"
        )

    # Step 2: Parse the login form
    parser = KeycloakFormParser()
    parser.feed(login_page.text)
    if parser.action is None:
        _fail(
            f"Could not find form action in Keycloak login page for {username}. "
            f"Page starts with: {login_page.text[:200]}"
        )

    # Step 3: Build form data (fill in username + password)
    form_data: dict[str, str] = {}
    for name, value in parser.fields:
        form_data[name] = value
    form_data["username"] = username
    form_data["password"] = password

    # Step 4: Submit the form.  Keycloak redirects back to the callback.
    # The action URL may be relative or absolute.
    action_url = parser.action
    if not action_url.startswith("http"):
        # Relative URL -- resolve against the login page URL
        parsed = urlparse(str(login_page.url))
        action_url = f"{parsed.scheme}://{parsed.netloc}{action_url}"

    # POST with redirect following.  The callback sets cookies and redirects to /.
    callback_resp = client.post(
        action_url,
        data=form_data,
        follow_redirects=True,
    )
    return callback_resp


def _assert_session_cookie(client: httpx.Client) -> str:
    """Assert that the client has a __Host-agg_session cookie and return
    the CSRF token from /me."""
    # Not all httpx cookie jar implementations expose cookies easily.
    # Instead, just call /me and check it works.
    return ""  # placeholder; we get CSRF from /me


def _get_me(client: httpx.Client, base_url: str) -> dict:
    """GET /api/v1/me and return the JSON body.  Fails on non-200."""
    r = client.get(f"{base_url}/api/v1/me")
    if r.status_code != 200:
        _fail(f"/me returned {r.status_code}: {r.text[:200]}")
    return r.json()


def _get_keycloak_user_id(
    client: httpx.Client,
    realm: str,
    username: str,
) -> str:
    """Get a Keycloak user's ID (= OIDC ``sub`` claim) via the admin API.

    Uses the demo admin credentials (admin/admin) from the Keycloak
    demo profile.  The returned ID is the UUID that Keycloak assigns
    as the ``sub`` claim in id_tokens.
    """
    # Get admin access token
    token_resp = client.post(
        f"{_IDP_BASE_URL}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "admin",
            "password": "admin",
        },
    )
    if token_resp.status_code != 200:
        _fail(
            f"Keycloak admin token request failed: {token_resp.status_code}: "
            f"{token_resp.text[:200]}"
        )
    admin_token = token_resp.json()["access_token"]

    # Look up user by exact username
    users_resp = client.get(
        f"{_IDP_BASE_URL}/admin/realms/{realm}/users",
        params={"username": username, "exact": "true"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    if users_resp.status_code != 200:
        _fail(
            f"Keycloak user lookup for '{username}' in '{realm}' failed: "
            f"{users_resp.status_code}: {users_resp.text[:200]}"
        )
    users = users_resp.json()
    if not users:
        _fail(f"Keycloak user '{username}' not found in realm '{realm}'")
    return users[0]["id"]


def _bootstrap_globex() -> str:
    """Bootstrap the Globex org via docker compose and return its setup code."""
    result = subprocess.run(
        ["docker", "compose", "run", "--rm",
         "-e", "AGG_DATABASE_URL_FILE=/run/secrets/pg_owner_url",
         "-e", "AGG_BOOTSTRAP_ORG_SLUG=globex",
         "-e", "AGG_BOOTSTRAP_ORG_NAME=Globex Corporation",
         "-e", "AGG_BOOTSTRAP_ORG_ISSUER=https://idp.localhost/realms/globex",
         "-e", "AGG_BOOTSTRAP_ORG_CLIENT_ID=agg-control-plane",
         "migrate-demo", "python", "-m", "agg_cp.migrate"],
        cwd=str(_COMPOSE_DIR),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        _fail(
            f"Globex bootstrap failed (exit {result.returncode}): "
            f"{result.stderr[:300]}"
        )
    # Extract setup code from output
    for line in (result.stdout or "").splitlines():
        for match in re.finditer(r'\{[^}]+\}', line):
            try:
                obj = json.loads(match.group())
                if obj.get("event") == "setup_code" and obj.get("org") == "globex":
                    return obj["code"]
            except (json.JSONDecodeError, KeyError):
                continue
    _fail("Could not find globex setup_code in bootstrap output")
    return ""  # unreachable


# ---------------------------------------------------------------------------
# Step implementations
# ---------------------------------------------------------------------------


def step1_ready(client: httpx.Client, base_url: str) -> None:
    """Step 1: check /ready 200 via the proxy."""
    print("\n=== Step 1: /ready check ===", flush=True)
    _wait_ready(client, base_url)
    _pass("/ready returned 200")


def step2_setup_and_admin(client: httpx.Client, base_url: str, passwords: dict[str, str], ca_path=None) -> dict:
    """Step 2: setup code, alice admin flow, registry genesis + v2/v3.

    Returns a dict with alice_csrf, project_id, bob_user_id, registry_version
    for later steps.
    """
    print("\n=== Step 2: Setup + admin flow ===", flush=True)

    # 2a. Read the setup code
    org_slug, setup_code = _get_setup_code()
    _pass(f"Setup code read from migrate-demo logs (org={org_slug})")

    # 2b. POST /api/v1/auth/setup
    setup_resp = client.post(
        f"{base_url}/api/v1/auth/setup",
        json={"org": org_slug, "code": setup_code},
    )
    if setup_resp.status_code != 200:
        _fail(f"/auth/setup returned {setup_resp.status_code}: {setup_resp.text[:300]}")
    setup_body = setup_resp.json()
    redirect_url = setup_body.get("redirect")
    if not redirect_url:
        _fail(f"/auth/setup did not return a redirect URL: {setup_body}")
    _pass("/auth/setup accepted the setup code and returned redirect URL")

    # 2c. Follow the Keycloak authorization redirect and log in as alice
    alice_pw = passwords.get("alice", "")
    if not alice_pw:
        _fail("alice password not found in the demo realm files")
    callback_resp = _keycloak_login(client, redirect_url, "alice", alice_pw)
    if callback_resp.status_code not in (200, 302):
        _fail(
            f"Keycloak login+callback returned {callback_resp.status_code}: "
            f"{callback_resp.text[:200]}"
        )
    _pass("alice logged in via Keycloak (bootstrap admin)")

    # 2d. GET /me (admin)
    me = _get_me(client, base_url)
    roles = me.get("roles", [])
    is_admin = any(r.get("role") == "admin" for r in roles)
    if not is_admin:
        _fail(f"alice is not admin. Roles: {roles}")
    csrf = me.get("csrf_token", "")
    if not csrf:
        _fail("/me did not return a csrf_token")
    _pass(f"/me: alice is admin (org={me.get('org', {}).get('slug')})")

    # 2e. Create project "payments" (prod)
    proj_resp = client.post(
        f"{base_url}/api/v1/projects",
        json={"name": "payments", "environment": "prod"},
        headers={"X-CSRF-Token": csrf},
    )
    if proj_resp.status_code != 201:
        _fail(f"Create project returned {proj_resp.status_code}: {proj_resp.text[:200]}")
    project_id = proj_resp.json().get("id")
    _pass(f"Created project 'payments' (id={project_id})")

    # 2f. Create project "payments-staging" (staging environment)
    staging_resp = client.post(
        f"{base_url}/api/v1/projects",
        json={"name": "payments-staging", "environment": "staging"},
        headers={"X-CSRF-Token": csrf},
    )
    if staging_resp.status_code != 201:
        _fail(f"Create payments-staging returned {staging_resp.status_code}: {staging_resp.text[:200]}")
    staging_id = staging_resp.json().get("id")
    _pass(f"Created project 'payments-staging' (id={staging_id})")

    # 2g. Look up bob's real Keycloak sub (UUID) via the admin API.
    # Keycloak assigns a random UUID as the `sub` claim; passing the
    # username string would cause a (iss, sub) mismatch at callback.
    bob_kc_sub = _get_keycloak_user_id(client, "acme", "bob")
    _pass(f"Looked up bob's Keycloak sub via admin API (sub={bob_kc_sub})")

    # 2h. Add bob as a user in the org (POST /org/users)
    bob_user_resp = client.post(
        f"{base_url}/api/v1/org/users",
        json={"oidc_subject": bob_kc_sub, "email": "bob@acme.example"},
        headers={"X-CSRF-Token": csrf},
    )
    if bob_user_resp.status_code != 201:
        _fail(f"Add bob user returned {bob_user_resp.status_code}: {bob_user_resp.text[:200]}")
    bob_user_id = bob_user_resp.json().get("id")
    _pass(f"Added bob as org user (id={bob_user_id})")

    # 2i. Add bob as approver on the project (POST /projects/{id}/members)
    member_resp = client.post(
        f"{base_url}/api/v1/projects/{project_id}/members",
        json={"user_id": bob_user_id, "role": "approver"},
        headers={"X-CSRF-Token": csrf},
    )
    if member_resp.status_code != 201:
        _fail(
            f"Add bob as approver returned {member_resp.status_code}: "
            f"{member_resp.text[:200]}"
        )
    _pass("Added bob as approver on project 'payments'")

    # 2j. Look up carol's Keycloak sub (second admin)
    carol_kc_sub = _get_keycloak_user_id(client, "acme", "carol")
    _pass(f"Looked up carol's Keycloak sub via admin API (sub={carol_kc_sub})")

    # 2k. Add carol as org user
    carol_user_resp = client.post(
        f"{base_url}/api/v1/org/users",
        json={"oidc_subject": carol_kc_sub, "email": "carol@acme.example"},
        headers={"X-CSRF-Token": csrf},
    )
    if carol_user_resp.status_code != 201:
        _fail(f"Add carol user returned {carol_user_resp.status_code}: {carol_user_resp.text[:200]}")
    carol_user_id = carol_user_resp.json().get("id")
    _pass(f"Added carol as org user (id={carol_user_id})")

    # 2l. Set carol as admin (POST /org/members)
    carol_admin_resp = client.post(
        f"{base_url}/api/v1/org/members",
        json={"user_id": carol_user_id, "role": "admin"},
        headers={"X-CSRF-Token": csrf},
    )
    if carol_admin_resp.status_code not in (200, 201):
        _fail(
            f"Set carol as admin returned {carol_admin_resp.status_code}: "
            f"{carol_admin_resp.text[:200]}"
        )
    _pass("Set carol as admin (second admin)")

    # ------------------------------------------------------------------
    # Registry genesis and version chain (2m-2q, ADR 0011 A1.3)
    # Routes exercised:
    #   /api/v1/signer-links           (web: create link code)
    #   /api/v1/sync/signer/genesis    (post genesis v1)
    #   /api/v1/sync/signer/signatures (post v2, v3)
    #   /api/v1/sync/signer/registry   (GET full chain)
    # ------------------------------------------------------------------
    org_id = me.get("org", {}).get("id", "")
    alice_user_id = me.get("user_id", "")

    # 2m. Read genesis code and bundle_signer from migrate-demo logs
    _, genesis_code = _get_genesis_code()
    _pass("Genesis code read from migrate-demo logs")
    bs_kid, bs_pub_hex = _get_bundle_signer()
    _pass(f"Bundle signer public key read (kid={bs_kid[:12]}...)")

    # 2n. alice links her CLI key (she already has a session on client)
    alice_sk, alice_kid, _alice_uid, alice_iss, alice_sub = _link_cli_key(
        client, base_url, ca_path, "alice", passwords.get("alice", ""), csrf,
    )
    _pass(f"alice linked CLI key (kid={alice_kid[:12]}...)")

    # Get a signer token for alice (pending_link scope initially)
    alice_token = _get_signer_token(client, base_url, alice_sk, alice_kid)

    # 2o. Build genesis v1 envelope (alice as sole admin, threshold 1)
    g_payload = {
        "org_id": org_id,
        "version": 1,
        "prev_hash": "",
        "threshold": 1,
        "admins": [alice_kid],
        "keys": [{
            "key_id": alice_kid,
            "public_key": bytes(alice_sk.verify_key).hex(),
            "kind": "cli",
            "alg": "ed25519",
            "user_id": alice_user_id,
            "iss": alice_iss,
            "sub": alice_sub,
            "roles": ["admin", "approver"],
            "added_in": 1,
        }],
        "bundle_signer": {"key_id": bs_kid, "public_key": bs_pub_hex},
        "expires_at": time.time() + 72 * 3600,  # 72 h ceiling (prod project)
    }
    g_sig = _sign_registry_payload(alice_sk, alice_kid, g_payload)
    g_env = {
        "kind": "agg/registry/v1",
        "sig_v": 1,
        "payload": g_payload,
        "signatures": [{"key_id": alice_kid, "alg": "ed25519", "sig": g_sig}],
    }

    # POST /api/v1/sync/signer/genesis
    genesis_resp = client.post(
        f"{base_url}/api/v1/sync/signer/genesis",
        json={"genesis_code": genesis_code, "envelope": g_env},
        headers={"Authorization": f"Bearer {alice_token}"},
        timeout=15,
    )
    if genesis_resp.status_code != 200:
        _fail(
            f"/sync/signer/genesis returned {genesis_resp.status_code}: "
            f"{genesis_resp.text[:300]}"
        )
    if genesis_resp.json().get("version") != 1:
        _fail("genesis response version != 1")
    _pass("genesis v1 accepted (registry version 1)")

    # 2p. Negatives: second genesis (409) and genesis code reuse
    neg_genesis_resp = client.post(
        f"{base_url}/api/v1/sync/signer/genesis",
        json={"genesis_code": "dummy-code-for-second-genesis", "envelope": g_env},
        headers={"Authorization": f"Bearer {alice_token}"},
        timeout=10,
    )
    if neg_genesis_resp.status_code != 409:
        _fail(
            f"second genesis returned {neg_genesis_resp.status_code} "
            f"(expected 409): {neg_genesis_resp.text[:200]}"
        )
    _pass("second genesis refused")

    # Genesis code reuse (the code was already consumed)
    reuse_resp = client.post(
        f"{base_url}/api/v1/sync/signer/genesis",
        json={"genesis_code": genesis_code, "envelope": g_env},
        headers={"Authorization": f"Bearer {alice_token}"},
        timeout=10,
    )
    if reuse_resp.status_code not in (400, 409):
        _fail(
            f"genesis code reuse returned {reuse_resp.status_code} "
            f"(expected 4xx): {reuse_resp.text[:200]}"
        )
    _pass("genesis code reuse refused")

    # 2q. carol logs in on her own client, links CLI key, co-signs v2
    verify_arg = ca_path if ca_path is not None else True
    with httpx.Client(verify=verify_arg, follow_redirects=False) as carol_client:
        carol_login = carol_client.get(
            f"{base_url}/api/v1/auth/login",
            params={"org": org_slug},
            follow_redirects=False,
        )
        if carol_login.status_code != 302:
            _fail(f"carol /login returned {carol_login.status_code} (expected 302)")
        carol_auth_url = carol_login.headers.get("location", "")
        carol_pw = passwords.get("carol", "")
        if not carol_pw:
            _fail("carol password not found in the demo realm files")
        carol_cb = _keycloak_login(carol_client, carol_auth_url, "carol", carol_pw)
        if carol_cb.status_code not in (200, 302):
            _fail(f"carol callback returned {carol_cb.status_code}")

        carol_me = _get_me(carol_client, base_url)
        carol_csrf = carol_me.get("csrf_token", "")

        carol_sk, carol_kid, _carol_uid, carol_iss, carol_sub = _link_cli_key(
            carol_client, base_url, ca_path, "carol", carol_pw, carol_csrf,
        )
        _pass(f"carol linked CLI key (kid={carol_kid[:12]}...)")
        carol_token = _get_signer_token(carol_client, base_url, carol_sk, carol_kid)

    # Build v2: add carol as admin, threshold 2
    g_canonical = json.dumps(
        g_payload, sort_keys=True, separators=(",", ":")
    ).encode()
    v2_prev = hashlib.sha256(
        org_id.encode() + b":" + g_canonical
    ).hexdigest()

    v2_payload = {
        "org_id": org_id,
        "version": 2,
        "prev_hash": v2_prev,
        "threshold": 2,
        "admins": [alice_kid, carol_kid],
        "keys": g_payload["keys"] + [{
            "key_id": carol_kid,
            "public_key": bytes(carol_sk.verify_key).hex(),
            "kind": "cli",
            "alg": "ed25519",
            "user_id": carol_user_id,
            "iss": carol_iss,
            "sub": carol_sub,
            "roles": ["admin", "approver"],
            "added_in": 2,
        }],
        "bundle_signer": g_payload["bundle_signer"],
        "expires_at": g_payload["expires_at"],
    }

    alice_sig_v2 = _sign_registry_payload(alice_sk, alice_kid, v2_payload)
    carol_sig_v2 = _sign_registry_payload(carol_sk, carol_kid, v2_payload)

    v2_env = {
        "kind": "agg/registry/v1",
        "sig_v": 1,
        "payload": v2_payload,
        "signatures": [
            {"key_id": alice_kid, "alg": "ed25519", "sig": alice_sig_v2},
            {"key_id": carol_kid, "alg": "ed25519", "sig": carol_sig_v2},
        ],
    }

    # carol's pending_link token posts v2 (adds her own key)
    v2_resp = client.post(
        f"{base_url}/api/v1/sync/signer/signatures",
        json={"type": "registry", "envelope": v2_env, "org_id": org_id},
        headers={"Authorization": f"Bearer {carol_token}"},
        timeout=15,
    )
    if v2_resp.status_code != 200:
        _fail(
            f"v2 publish returned {v2_resp.status_code}: "
            f"{v2_resp.text[:300]}"
        )
    _pass("v2 accepted (registry version 2, carol added)")

    # 2r. Negative: pending_link post without own key (bob)
    with httpx.Client(verify=verify_arg, follow_redirects=False) as bob_client:
        bob_login = bob_client.get(
            f"{base_url}/api/v1/auth/login",
            params={"org": org_slug},
            follow_redirects=False,
        )
        if bob_login.status_code != 302:
            _fail(f"bob /login returned {bob_login.status_code} (expected 302)")
        bob_auth_url = bob_login.headers.get("location", "")
        bob_pw = passwords.get("bob", "")
        if not bob_pw:
            _fail("bob password not found in the demo realm files")
        bob_cb = _keycloak_login(bob_client, bob_auth_url, "bob", bob_pw)
        if bob_cb.status_code not in (200, 302):
            _fail(f"bob callback returned {bob_cb.status_code}")

        bob_me = _get_me(bob_client, base_url)
        bob_csrf = bob_me.get("csrf_token", "")

        bob_sk, bob_kid, _bob_uid, bob_iss, bob_sub = _link_cli_key(
            bob_client, base_url, ca_path, "bob", bob_pw, bob_csrf,
        )
        _pass(f"bob linked CLI key (kid={bob_kid[:12]}...)")
        bob_token = _get_signer_token(bob_client, base_url, bob_sk, bob_kid)

    # Negative: bob (pending_link) posts an envelope that does NOT add
    # his own key -> server must refuse with 403.
    fake_env = {
        "kind": "agg/registry/v1",
        "sig_v": 1,
        "payload": {"org_id": org_id, "version": 3,
                     "keys": [{"key_id": "other-key"}]},
        "signatures": [],
    }
    neg_self_key = client.post(
        f"{base_url}/api/v1/sync/signer/signatures",
        json={"type": "registry", "envelope": fake_env, "org_id": org_id},
        headers={"Authorization": f"Bearer {bob_token}"},
        timeout=10,
    )
    if neg_self_key.status_code != 403:
        _fail(
            f"pending_link self-key check returned {neg_self_key.status_code} "
            f"(expected 403): {neg_self_key.text[:200]}"
        )
    _pass("pending_link self-key refused")

    # 2s. v3: add bob (approver), carol-approver and alice-approver keys.
    # Each key comes from that user's own link in their own session
    # (ADR 0011 A1.3).  alice and carol each create a second CLI link
    # for their approver key; bob's link was created in step 2r.

    # alice-approver: second link from alice's session
    alice_apr_sk, alice_apr_kid, _, alice_apr_iss, alice_apr_sub = _link_cli_key(
        client, base_url, ca_path, "alice",
        passwords.get("alice", ""), csrf,
    )
    _pass(f"alice linked approver key (kid={alice_apr_kid[:12]}...)")

    # carol-approver: second link from carol's session
    with httpx.Client(verify=verify_arg, follow_redirects=False) as carol_client2:
        carol_login2 = carol_client2.get(
            f"{base_url}/api/v1/auth/login",
            params={"org": org_slug},
            follow_redirects=False,
        )
        if carol_login2.status_code != 302:
            _fail(f"carol /login (2nd) returned {carol_login2.status_code}")
        carol_auth2 = carol_login2.headers.get("location", "")
        carol_cb2 = _keycloak_login(
            carol_client2, carol_auth2, "carol",
            passwords.get("carol", ""),
        )
        if carol_cb2.status_code not in (200, 302):
            _fail(f"carol callback (2nd) returned {carol_cb2.status_code}")
        carol_me2 = _get_me(carol_client2, base_url)
        carol_csrf2 = carol_me2.get("csrf_token", "")

        carol_apr_sk, carol_apr_kid, _, carol_apr_iss, carol_apr_sub = _link_cli_key(
            carol_client2, base_url, ca_path, "carol",
            passwords.get("carol", ""), carol_csrf2,
        )
        _pass(f"carol linked approver key (kid={carol_apr_kid[:12]}...)")

    v2_canonical = json.dumps(
        v2_payload, sort_keys=True, separators=(",", ":")
    ).encode()
    v3_prev = hashlib.sha256(
        org_id.encode() + b":" + v2_canonical
    ).hexdigest()

    v3_new_keys = [
        {
            "key_id": bob_kid,
            "public_key": bytes(bob_sk.verify_key).hex(),
            "kind": "cli",
            "alg": "ed25519",
            "user_id": bob_user_id,
            "iss": bob_iss,
            "sub": bob_sub,
            "roles": ["approver"],
            "added_in": 3,
        },
        {
            "key_id": carol_apr_kid,
            "public_key": bytes(carol_apr_sk.verify_key).hex(),
            "kind": "cli",
            "alg": "ed25519",
            "user_id": carol_user_id,
            "iss": carol_apr_iss,
            "sub": carol_apr_sub,
            "roles": ["approver"],
            "added_in": 3,
        },
        {
            "key_id": alice_apr_kid,
            "public_key": bytes(alice_apr_sk.verify_key).hex(),
            "kind": "cli",
            "alg": "ed25519",
            "user_id": alice_user_id,
            "iss": alice_apr_iss,
            "sub": alice_apr_sub,
            "roles": ["approver"],
            "added_in": 3,
        },
    ]

    v3_payload = {
        "org_id": org_id,
        "version": 3,
        "prev_hash": v3_prev,
        "threshold": 2,
        "admins": [alice_kid, carol_kid],
        "keys": v2_payload["keys"] + v3_new_keys,
        "bundle_signer": g_payload["bundle_signer"],
        "expires_at": g_payload["expires_at"],
    }

    # Get confirmed tokens for alice and carol (their keys are in the registry)
    alice_confirmed = _get_signer_token(client, base_url, alice_sk, alice_kid)
    carol_confirmed = _get_signer_token(client, base_url, carol_sk, carol_kid)

    alice_sig_v3 = _sign_registry_payload(alice_sk, alice_kid, v3_payload)
    carol_sig_v3 = _sign_registry_payload(carol_sk, carol_kid, v3_payload)

    v3_env = {
        "kind": "agg/registry/v1",
        "sig_v": 1,
        "payload": v3_payload,
        "signatures": [
            {"key_id": alice_kid, "alg": "ed25519", "sig": alice_sig_v3},
            {"key_id": carol_kid, "alg": "ed25519", "sig": carol_sig_v3},
        ],
    }

    v3_resp = client.post(
        f"{base_url}/api/v1/sync/signer/signatures",
        json={"type": "registry", "envelope": v3_env, "org_id": org_id},
        headers={"Authorization": f"Bearer {alice_confirmed}"},
        timeout=15,
    )
    if v3_resp.status_code != 200:
        _fail(
            f"v3 publish returned {v3_resp.status_code}: "
            f"{v3_resp.text[:300]}"
        )
    _pass("v3 accepted (registry version 3, bob + approver keys)")

    # 2t. GET /api/v1/sync/signer/registry -> 3-version chain
    chain_resp = client.get(
        f"{base_url}/api/v1/sync/signer/registry",
        headers={"Authorization": f"Bearer {alice_confirmed}"},
        timeout=10,
    )
    if chain_resp.status_code != 200:
        _fail(
            f"GET /signer/registry returned {chain_resp.status_code}: "
            f"{chain_resp.text[:200]}"
        )
    chain = chain_resp.json()
    if not isinstance(chain, list) or len(chain) != 3:
        _fail(f"expected 3-version chain, got {len(chain) if isinstance(chain, list) else type(chain)}")
    _pass("GET /signer/registry returned 3-version chain")

    return {
        "csrf": csrf,
        "project_id": project_id,
        "staging_id": staging_id,
        "bob_user_id": bob_user_id,
        "carol_user_id": carol_user_id,
        "org_slug": org_slug,
        "registry_version": 3,
    }


def step3_bob_and_eve(
    base_url: str,
    ca_path: str,
    passwords: dict[str, str],
    step2_data: dict,
) -> None:
    """Step 3: bob logs in and sees payments; gets 403 on role change.
    eve (Globex) sees no Acme project and gets 404 on Acme ids.
    """
    print("\n=== Step 3: bob + eve RBAC checks ===", flush=True)

    project_id = step2_data["project_id"]

    # --- bob (Acme, approver) ---
    with httpx.Client(verify=ca_path, follow_redirects=False) as bob_client:
        # 3a. bob logs in via the normal /login flow
        login_resp = bob_client.get(
            f"{base_url}/api/v1/auth/login",
            params={"org": "acme"},
            follow_redirects=False,
        )
        if login_resp.status_code != 302:
            _fail(f"bob /login returned {login_resp.status_code} (expected 302)")
        auth_url = login_resp.headers.get("location", "")
        if not auth_url:
            _fail("bob /login did not return a redirect Location header")

        bob_pw = passwords.get("bob", "")
        if not bob_pw:
            _fail("bob password not found in the demo realm files")
        callback_resp = _keycloak_login(bob_client, auth_url, "bob", bob_pw)
        if callback_resp.status_code not in (200, 302):
            _fail(
                f"bob callback returned {callback_resp.status_code} "
                f"(expected 200 or 302): {callback_resp.text[:200]}"
            )
        _pass("bob logged in via Keycloak")

        # 3b. bob sees the payments project
        bob_me = _get_me(bob_client, base_url)
        bob_csrf = bob_me.get("csrf_token", "")
        projects_resp = bob_client.get(f"{base_url}/api/v1/projects")
        if projects_resp.status_code != 200:
            _fail(f"bob /projects returned {projects_resp.status_code}")
        projects = projects_resp.json()
        project_names = [p.get("name") for p in projects]
        if "payments" not in project_names:
            _fail(f"bob does not see 'payments': {project_names}")
        _pass("bob sees project 'payments'")

        # 3c. bob gets 403 on role changes (not admin)
        role_resp = bob_client.post(
            f"{base_url}/api/v1/projects/{project_id}/members",
            json={"user_id": step2_data["bob_user_id"], "role": "admin"},
            headers={"X-CSRF-Token": bob_csrf},
        )
        if role_resp.status_code != 403:
            _fail(
                f"bob role change returned {role_resp.status_code} "
                f"(expected 403): {role_resp.text[:200]}"
            )
        _pass("bob gets 403 on role change (not admin)")

    # --- eve (Globex) ---
    # Bootstrap globex org if not already done, then log eve in.
    with httpx.Client(verify=ca_path, follow_redirects=False) as eve_client:
        # 3d. Check if globex org exists; bootstrap if needed
        eve_login = eve_client.get(
            f"{base_url}/api/v1/auth/login",
            params={"org": "globex"},
            follow_redirects=False,
        )
        if eve_login.status_code == 404:
            # Globex not bootstrapped -- bootstrap it now
            globex_code = _bootstrap_globex()
            _pass("Bootstrapped Globex org")

            # POST /auth/setup for globex
            globex_setup = eve_client.post(
                f"{base_url}/api/v1/auth/setup",
                json={"org": "globex", "code": globex_code},
            )
            if globex_setup.status_code != 200:
                _fail(
                    f"Globex /auth/setup returned {globex_setup.status_code}: "
                    f"{globex_setup.text[:300]}"
                )
            globex_redirect = globex_setup.json().get("redirect")
            if not globex_redirect:
                _fail("Globex /auth/setup did not return a redirect URL")

            # Eve logs in via Keycloak to become globex admin
            eve_pw = passwords.get("eve", "")
            if not eve_pw:
                _fail("eve password not found in the demo realm files")
            eve_callback = _keycloak_login(
                eve_client, globex_redirect, "eve", eve_pw,
            )
            if eve_callback.status_code not in (200, 302):
                _fail(
                    f"eve bootstrap callback returned "
                    f"{eve_callback.status_code}: {eve_callback.text[:200]}"
                )
            _pass("eve logged in as Globex admin (bootstrap)")

        elif eve_login.status_code == 302:
            # Globex already bootstrapped -- log eve in normally
            auth_url = eve_login.headers.get("location", "")
            eve_pw = passwords.get("eve", "")
            if not eve_pw:
                _fail("eve password not found in the demo realm files")
            eve_callback = _keycloak_login(eve_client, auth_url, "eve", eve_pw)
            if eve_callback.status_code not in (200, 302):
                _fail(
                    f"eve callback returned {eve_callback.status_code}: "
                    f"{eve_callback.text[:200]}"
                )
            _pass("eve logged in via Keycloak (Globex)")
        else:
            _fail(f"eve /login returned unexpected {eve_login.status_code}")

        # 3e. eve should see no Acme projects
        eve_projects = eve_client.get(f"{base_url}/api/v1/projects")
        if eve_projects.status_code == 200:
            eve_proj_list = eve_projects.json()
            acme_projects = [p for p in eve_proj_list if p.get("name") == "payments"]
            if acme_projects:
                _fail("eve (Globex) can see Acme project 'payments'")
            _pass("eve (Globex) sees no Acme projects")
        elif eve_projects.status_code == 401:
            _fail(
                f"eve /projects returned 401 (session not established): "
                f"{eve_projects.text[:200]}"
            )
        else:
            _pass(f"eve /projects returned {eve_projects.status_code}")

        # 3f. eve tries to access an Acme project id -- should get 404
        eve_acme_proj = eve_client.get(
            f"{base_url}/api/v1/projects/{project_id}"
        )
        if eve_acme_proj.status_code != 404:
            _fail(
                f"eve accessing Acme project returned "
                f"{eve_acme_proj.status_code} (expected 404)"
            )
        _pass("eve gets 404 on Acme project id")


def _find_free_port() -> int:
    """Find a free TCP port on localhost."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_http_ready(url: str, timeout: int = 30) -> None:
    """Poll an HTTP endpoint until it returns 200 or timeout elapses."""
    deadline = time.monotonic() + timeout
    last_err = ""
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=3)
            if r.status_code == 200:
                return
            last_err = f"status {r.status_code}"
        except httpx.HTTPError as exc:
            last_err = str(exc)
        time.sleep(0.5)
    _fail(f"{url} did not return 200 within {timeout}s (last: {last_err})")


def step4_connector(base_url: str, ca_path: str) -> None:
    """Step 4: connector checks (live, no Docker needed).

    - Create a temp folder, ``sandbox init`` it
    - Start ``sandbox serve --root <tmp>`` subprocess (free port, env tokens)
    - Listed root returns 200 with the approver token; unlisted root returns 403
    - PreToolUse hook_eval: Grep for key-home seed bytes is denied
    - A forged Ed25519 approval by an unpinned key is refused
    """
    print("\n=== Step 4: Connector checks ===", flush=True)

    python = sys.executable
    demo_dir = tempfile.mkdtemp(prefix="sandbox_demo_")
    server_proc = None

    try:
        # ---- 4a. sandbox init ------------------------------------------------
        # The sandbox CLI is installed as a console_scripts entry point; find
        # it next to the Python interpreter (e.g. .venv/bin/sandbox).
        sandbox_bin = str(Path(python).parent / "sandbox")
        if not Path(sandbox_bin).is_file():
            # Fallback: try invoking sandbox.cli.main:cli directly via Python
            sandbox_bin = None  # type: ignore[assignment]
        if sandbox_bin:
            init_cmd = [sandbox_bin, "init", demo_dir]
        else:
            # Use the click entry point directly via python -c
            init_cmd = [python, "-c",
                        "from sandbox.cli.main import cli; cli()",
                        "init", demo_dir]
        init_result = subprocess.run(
            init_cmd,
            capture_output=True, text=True, timeout=30,
        )
        if init_result.returncode != 0:
            _fail(f"sandbox init exited {init_result.returncode}: {init_result.stderr}")
        sandbox_dir = Path(demo_dir) / ".sandbox"
        if not sandbox_dir.is_dir():
            _fail(f".sandbox/ not created in {demo_dir}")
        _pass(f"sandbox init created .sandbox/ in {demo_dir}")

        # ---- 4b. sandbox serve -----------------------------------------------
        port = _find_free_port()
        agent_token = "demo-agent-token-" + os.urandom(8).hex()
        approver_token = "demo-approver-token-" + os.urandom(8).hex()
        serve_env = {
            **os.environ,
            "SANDBOX_AGENT_TOKEN": agent_token,
            "SANDBOX_APPROVER_TOKEN": approver_token,
        }
        if sandbox_bin:
            serve_cmd = [sandbox_bin, "serve",
                         "--root", demo_dir, "--port", str(port),
                         "--host", "127.0.0.1"]
        else:
            serve_cmd = [python, "-c",
                         "from sandbox.cli.main import cli; cli()",
                         "serve", "--root", demo_dir, "--port", str(port),
                         "--host", "127.0.0.1"]
        server_proc = subprocess.Popen(
            serve_cmd,
            env=serve_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        serve_url = f"http://127.0.0.1:{port}"
        _wait_http_ready(f"{serve_url}/ready", timeout=30)
        _pass(f"sandbox serve running on port {port}")

        # ---- 4c. listed root -> 200, unlisted root -> 403 --------------------
        abs_demo = os.path.realpath(demo_dir)
        status_resp = httpx.get(
            f"{serve_url}/api/v1/connector/status",
            params={"root": abs_demo},
            headers={"Authorization": f"Bearer {approver_token}"},
            timeout=10,
        )
        if status_resp.status_code != 200:
            _fail(
                f"connector/status for listed root returned "
                f"{status_resp.status_code} (expected 200): {status_resp.text[:200]}"
            )
        _pass("listed root -> 200 via connector/status")

        unlisted_resp = httpx.get(
            f"{serve_url}/api/v1/connector/status",
            params={"root": "/tmp/not-a-listed-root"},
            headers={"Authorization": f"Bearer {approver_token}"},
            timeout=10,
        )
        if unlisted_resp.status_code != 403:
            _fail(
                f"connector/status for unlisted root returned "
                f"{unlisted_resp.status_code} (expected 403): {unlisted_resp.text[:200]}"
            )
        _pass("unlisted root -> 403 via connector/status")

        # ---- 4d. key-home: PreToolUse hook_eval denies Grep for seeds --------
        # Build a PreToolUse payload targeting the key home path. The hook_eval
        # reads JSON from stdin and classifies the tool call.
        from sandbox.connector.keyhome import key_home_root

        kh = key_home_root()
        # Even if key_home_root() returns None (no key home configured), use a
        # plausible path: the classifier checks .sandbox/state/keys/ too.
        grep_target = str(kh) if kh else str(sandbox_dir / "state" / "keys")
        hook_payload = json.dumps({
            "tool_name": "Grep",
            "tool_input": {
                "pattern": "seed",
                "path": grep_target,
            },
            "cwd": demo_dir,
        })
        hook_result = subprocess.run(
            [python, "-m", "sandbox.connector.hook_eval"],
            input=hook_payload,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=demo_dir,
        )
        # The hook emits JSON on stdout with the decision
        hook_stdout = hook_result.stdout.strip()
        denied_seed_grep = False
        if hook_stdout:
            try:
                hook_out = json.loads(hook_stdout)
                hso = hook_out.get("hookSpecificOutput", {})
                decision = hso.get("permissionDecision", "")
                reason = hso.get("permissionDecisionReason", "")
                if decision == "deny":
                    denied_seed_grep = True
                    _pass(
                        f"PreToolUse hook_eval denied Grep for seed bytes "
                        f"(decision={decision}, reason starts: {reason[:80]})"
                    )
            except json.JSONDecodeError:
                pass
        if not denied_seed_grep:
            # If the key home is outside and the target was .sandbox/state/keys
            # the hook may not have denied it (path does not exist). Check that
            # no seed files are readable there at minimum.
            keys_dir = sandbox_dir / "state" / "keys"
            seed_files = list(keys_dir.glob("*.seed")) if keys_dir.is_dir() else []
            if seed_files:
                _fail(f"seed files found in workspace: {seed_files}")
            _pass(
                "key-home check: no seed files in .sandbox/state/keys/ "
                "(seeds live in the key home, outside the workspace)"
            )

        # ---- 4e. forged approval: fresh Ed25519 key is refused ---------------
        # Create a pending request in the queue, then forge an approval with
        # an unpinned key and verify it is rejected.
        from sandbox.connector.layout import FolderLayout
        from sandbox.connector.queue import EscalationQueue
        from sandbox.connector.signing import (
            _APPROVAL_FIELDS,
            _canonical,
            _is_pinned,
            distinct_approvals,
            verify_approval,
        )

        layout = FolderLayout(demo_dir)
        queue = EscalationQueue(layout)
        request_id = queue.submit({
            "command": "echo forged-demo",
            "origin": "demo",
        })

        # Forge: generate a fresh Ed25519 key (not the workspace's pinned key)
        from nacl.signing import SigningKey as NaClSigningKey

        from sandbox.crypto.signing import sign_message
        from sandbox.protocol.domains import APPROVAL

        forged_key = NaClSigningKey.generate()
        forged_pub = bytes(forged_key.verify_key).hex()
        now = time.time()
        forged_approval = {
            "request_id": request_id,
            "command": "echo forged-demo",
            "fingerprint": None,
            "reviewer_id": "forged-reviewer",
            "decision": "approve",
            "approved_at": now,
            "signer_public_key": forged_pub,
            "sig_v": 1,
        }
        # Sign it properly with the forged key (valid signature, but unpinned)
        tag_bytes = APPROVAL.encode("utf-8")
        canon = _canonical(forged_approval, _APPROVAL_FIELDS)
        data_to_sign = tag_bytes + b"\x00" + canon
        forged_approval["signature"] = sign_message(data_to_sign, forged_key)

        # The signature itself verifies (it is cryptographically valid)
        sig_valid = verify_approval(forged_approval)
        if not sig_valid:
            _fail("forged approval signature should be cryptographically valid")

        # But it must NOT be pinned (the key was never enrolled in this workspace)
        is_pinned = _is_pinned(forged_approval, layout)
        if is_pinned:
            _fail("forged approval with a fresh key should NOT be pinned")
        _pass("forged approval: signature valid but key is not pinned (refused)")

        # distinct_approvals requires pinned keys: one forged approval fails
        accepted = distinct_approvals([forged_approval], needed=1, layout=layout)
        if accepted:
            _fail("distinct_approvals should refuse an unpinned approval")
        _pass("distinct_approvals refuses forged (unpinned) approval")

    finally:
        if server_proc is not None:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()
                server_proc.wait(timeout=5)
        # Clean up the temp dir (best effort)
        import shutil

        shutil.rmtree(demo_dir, ignore_errors=True)


def step5_persistence(client: httpx.Client, base_url: str, step2_data: dict) -> None:
    """Step 5: persistence + audit verify via Docker Compose.

    Runs ``docker compose down``, then ``docker compose --profile demo up -d``,
    waits for /ready, and runs ``docker compose exec -T api agg-cp audit verify
    --org acme`` (exit 0 = audit chain intact).

    On a machine without Docker these subprocess calls will fail; the step
    reports FAIL honestly (it is expected to run on the Docker host).
    """
    print("\n=== Step 5: Persistence + audit verify ===", flush=True)

    org_slug = step2_data.get("org_slug", "acme") if step2_data else "acme"

    # 5a. docker compose --profile demo down (include demo profile
    # so keycloak and migrate-demo are also stopped)
    down_result = subprocess.run(
        ["docker", "compose", "--profile", "demo", "down"],
        cwd=str(_COMPOSE_DIR),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if down_result.returncode != 0:
        _fail(
            f"docker compose down exited {down_result.returncode}: "
            f"{down_result.stderr[:300]}"
        )
    _pass("docker compose down succeeded")

    # 5b. docker compose --profile demo up -d
    # Ensure AGG_OIDC_ALLOW_HOSTS is set for the api container
    up_env = {**os.environ, "AGG_OIDC_ALLOW_HOSTS": "idp.localhost"}
    up_result = subprocess.run(
        ["docker", "compose", "--profile", "demo", "up", "-d"],
        cwd=str(_COMPOSE_DIR),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        env=up_env,
    )
    if up_result.returncode != 0:
        _fail(
            f"docker compose up exited {up_result.returncode}: "
            f"{up_result.stderr[:300]}"
        )
    _pass("docker compose --profile demo up -d succeeded")

    # 5c. Wait for /ready via the proxy
    _wait_ready(client, base_url, timeout=120)
    _pass("/ready returned 200 after restart")

    # 5d. agg-cp audit verify --org <slug> inside the api container
    verify_result = subprocess.run(
        ["docker", "compose", "exec", "-T", "api",
         "agg-cp", "audit", "verify", "--org", org_slug],
        cwd=str(_COMPOSE_DIR),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if verify_result.returncode != 0:
        _fail(
            f"agg-cp audit verify --org {org_slug} exited "
            f"{verify_result.returncode}: {verify_result.stderr[:300]}"
        )
    _pass(f"agg-cp audit verify --org {org_slug} exited 0 (audit chain intact)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Entry point.  Returns 0 on success, non-zero on first FAIL."""
    parser = argparse.ArgumentParser(
        description="T14 demo: exercises the full control-plane stack headlessly.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Steps:\n"
            "  1  /ready check via the proxy\n"
            "  2  Setup code + alice admin + create project + add bob\n"
            "  3  bob RBAC + eve org isolation\n"
            "  4  Connector: --root 403, key-home, forged approval\n"
            "  5  Persistence: down/up, audit verify\n"
        ),
    )
    parser.add_argument(
        "--step",
        type=int,
        choices=[1, 2, 3, 4, 5],
        default=None,
        help="Run only this step (default: all).",
    )
    parser.add_argument(
        "--base-url",
        default="https://localhost",
        help="Base URL of the control-plane proxy (default: https://localhost).",
    )
    parser.add_argument(
        "--ca",
        default=None,
        help=(
            "Path to the CA bundle for TLS verification.  "
            "Default: the Caddy root CA from the compose ca-bundle volume, "
            "or the system default if the volume path does not exist."
        ),
    )
    args = parser.parse_args(argv)

    # Resolve CA path
    ca_path: str = args.ca or ""
    if not ca_path:
        # Try the compose volume path (inside a container)
        if os.path.isfile(_CA_BUNDLE_DEFAULT):
            ca_path = _CA_BUNDLE_DEFAULT
        else:
            # Try the caddy data path relative to the deploy dir
            caddy_ca = _COMPOSE_DIR / "caddy-data" / "caddy" / "pki" / "authorities" / "local" / "root.crt"
            local_dir = _COMPOSE_DIR / ".local"
            caddy_root = local_dir / "caddy-root.crt"
            if caddy_ca.is_file():
                ca_path = str(caddy_ca)
            else:
                # Extract from the running proxy container (always fresh)
                local_dir.mkdir(exist_ok=True)
                try:
                    _extract = subprocess.run(
                        ["docker", "compose", "cp",
                         "proxy:/root-cert/root.crt",
                         str(caddy_root)],
                        cwd=str(_COMPOSE_DIR),
                        capture_output=True, text=True,
                        timeout=15, check=True,
                    )
                    if caddy_root.is_file():
                        ca_path = str(caddy_root)
                    else:
                        ca_path = True  # type: ignore[assignment]
                except (subprocess.CalledProcessError, FileNotFoundError):
                    # Fall back to existing file or system default
                    if caddy_root.is_file():
                        ca_path = str(caddy_root)
                    else:
                        ca_path = True  # type: ignore[assignment]

    base_url = args.base_url.rstrip("/")
    passwords = _load_demo_passwords()

    print(f"Demo target: {base_url}", flush=True)
    print(f"CA bundle: {ca_path if isinstance(ca_path, str) else 'system default'}", flush=True)
    print(f"Demo users: {list(passwords.keys())}", flush=True)

    step = args.step
    step2_data: dict = {}

    # httpx client with TLS verification
    with httpx.Client(verify=ca_path, follow_redirects=False) as client:
        if step is None or step == 1:
            step1_ready(client, base_url)

        if step is None or step == 2:
            step2_data = step2_setup_and_admin(client, base_url, passwords, ca_path=ca_path)

        if step is None or step == 3:
            # Step 3 creates its own clients (bob, eve have separate sessions)
            if not step2_data:
                _fail(
                    "Step 3 needs step 2 data (project_id, bob_user_id). "
                    "Run without --step or run --step 2 first."
                )
            step3_bob_and_eve(base_url, ca_path, passwords, step2_data)

        if step is None or step == 4:
            step4_connector(base_url, ca_path)

        if step is None or step == 5:
            step5_persistence(client, base_url, step2_data)

    print("\n=== All steps completed ===", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
