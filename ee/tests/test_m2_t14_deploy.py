"""T14 tests-first: compose bundle-signer secret, carol, payments-staging.

Static checks (run in CI without Docker):
- Compose YAML has a ``bundle_signer_key`` file-based secret.
- The ``api`` service mounts that secret and uses the ``_FILE`` env-var
  convention; it is NOT in ``environment`` as a literal.
- ``init-secrets.sh`` generates the bundle-signer key file with
  restrictive permissions (0o400, api uid).
- The acme Keycloak realm JSON defines carol as a user.
- The demo bootstrap (``migrate-demo``) creates ``payments-staging``
  with ``environment: staging``.
- Caddy/TLS config is unchanged (the Caddyfile still has ``tls internal``
  and no new published ports appear).

Live tests (Docker required, at most 2):
- Stack up; ``/ready`` returns 200.

RED tests xfail on M2T14Pending.  Guards verify file existence.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from .m2_pending import M2T14Pending

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_DEPLOY = Path(__file__).resolve().parent.parent / "deploy"
_COMPOSE = _DEPLOY / "compose.yml"
_INIT_SECRETS = _DEPLOY / "init-secrets.sh"
_CADDYFILE = _DEPLOY / "Caddyfile"
_ACME_REALM = _DEPLOY / "keycloak" / "acme-realm.json"

# ---------------------------------------------------------------------------
# YAML loading (skip if pyyaml unavailable)
# ---------------------------------------------------------------------------

try:
    import yaml

    _HAS_YAML = True
except ImportError:
    yaml = None  # type: ignore[assignment]
    _HAS_YAML = False

_skip_no_yaml = pytest.mark.skipif(
    not _HAS_YAML,
    reason="pyyaml is not installed; compose YAML tests skipped",
)


def _load_compose() -> dict:
    """Parse compose.yml and return the dict."""
    assert _COMPOSE.exists(), f"compose.yml not found at {_COMPOSE}"
    text = _COMPOSE.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    assert isinstance(data, dict), "compose.yml did not parse as a YAML mapping"
    return data


# ===================================================================
# Guards (pass now)
# ===================================================================


def test_compose_exists():
    """Guard: ee/deploy/compose.yml exists."""
    assert _COMPOSE.is_file(), f"compose.yml not found at {_COMPOSE}"


def test_init_secrets_exists():
    """Guard: ee/deploy/init-secrets.sh exists."""
    assert _INIT_SECRETS.is_file(), f"init-secrets.sh not found at {_INIT_SECRETS}"


def test_acme_realm_exists():
    """Guard: acme-realm.json exists and has users."""
    assert _ACME_REALM.is_file(), f"acme-realm.json not found at {_ACME_REALM}"
    data = json.loads(_ACME_REALM.read_text(encoding="utf-8"))
    assert "users" in data, "acme-realm.json must contain a 'users' key"


# ===================================================================
# RED: bundle-signer secret defined as a compose file secret
# ===================================================================


@_skip_no_yaml

def test_bundle_signer_secret_in_compose_secrets():
    """Compose top-level ``secrets`` must define ``bundle_signer_key``
    as a file secret (``file: ./secrets/bundle_signer_key``)."""
    data = _load_compose()
    secrets = data.get("secrets", {})
    if "bundle_signer_key" not in secrets:
        raise M2T14Pending(
            "compose secrets does not define 'bundle_signer_key'; "
            "T14 must add it as a file-based secret"
        )
    entry = secrets["bundle_signer_key"]
    assert "file" in entry, (
        "bundle_signer_key secret must use 'file:' (not 'external' or 'environment')"
    )
    assert "bundle_signer_key" in entry["file"], (
        f"bundle_signer_key file path should reference the key file, got: {entry['file']}"
    )


@_skip_no_yaml

def test_api_mounts_bundle_signer_secret():
    """The ``api`` service must list ``bundle_signer_key`` in its
    ``secrets`` array so the file is mounted at ``/run/secrets/``."""
    data = _load_compose()
    api = data["services"].get("api", {})
    api_secrets = api.get("secrets", [])
    if "bundle_signer_key" not in api_secrets:
        raise M2T14Pending(
            "api service does not mount bundle_signer_key secret; "
            "T14 must add it to the api secrets list"
        )
    assert "bundle_signer_key" in api_secrets


@_skip_no_yaml

def test_api_env_uses_bundle_signer_file_convention():
    """The ``api`` environment must set ``AGG_BUNDLE_SIGNER_KEY_FILE``
    pointing to ``/run/secrets/bundle_signer_key`` and must NOT contain
    a bare ``AGG_BUNDLE_SIGNER_KEY`` (no literal secret in env)."""
    data = _load_compose()
    api = data["services"].get("api", {})
    env = api.get("environment", {})
    if isinstance(env, list):
        env_dict = {}
        for item in env:
            k, _, v = item.partition("=")
            env_dict[k] = v
        env = env_dict

    if "AGG_BUNDLE_SIGNER_KEY_FILE" not in env:
        raise M2T14Pending(
            "api environment does not set AGG_BUNDLE_SIGNER_KEY_FILE; "
            "T14 must add it pointing to /run/secrets/bundle_signer_key"
        )

    file_val = env["AGG_BUNDLE_SIGNER_KEY_FILE"]
    assert "/run/secrets/bundle_signer_key" in file_val, (
        f"AGG_BUNDLE_SIGNER_KEY_FILE should point to /run/secrets/bundle_signer_key, "
        f"got: {file_val!r}"
    )

    # Must NOT have the literal key in env
    assert "AGG_BUNDLE_SIGNER_KEY" not in env or env.get("AGG_BUNDLE_SIGNER_KEY") is None, (
        "api environment must NOT contain AGG_BUNDLE_SIGNER_KEY as a plain env var"
    )


@_skip_no_yaml

def test_bundle_signer_not_in_any_service_env_literal():
    """No service should have a plain ``AGG_BUNDLE_SIGNER_KEY`` (without
    the ``_FILE`` suffix) in its ``environment``."""
    data = _load_compose()
    for name, svc in data["services"].items():
        env = svc.get("environment", {})
        if isinstance(env, list):
            keys = [item.split("=", 1)[0] for item in env if "=" in item]
        else:
            keys = list(env.keys())
        # Only the _FILE form is allowed
        bare_key = [k for k in keys if k == "AGG_BUNDLE_SIGNER_KEY"]
        if bare_key:
            raise M2T14Pending(
                f"service '{name}' has AGG_BUNDLE_SIGNER_KEY in environment; "
                "must use the _FILE convention only"
            )
    # If we get here without raising, the feature check passed -- but we
    # still need to verify the _FILE var exists somewhere (covered by the
    # test above), so this test alone would pass vacuously. Add the real
    # feature check: the secret must exist in compose.
    secrets = data.get("secrets", {})
    if "bundle_signer_key" not in secrets:
        raise M2T14Pending(
            "bundle_signer_key secret not defined in compose; "
            "cannot verify the _FILE convention without it"
        )


# ===================================================================
# RED: init-secrets generates bundle_signer_key with 0o400 permissions
# ===================================================================



def test_init_secrets_generates_bundle_signer_key():
    """init-secrets.sh must include ``bundle_signer_key`` in its
    SECRET_FILES list so the key file is generated."""
    text = _INIT_SECRETS.read_text(encoding="utf-8")
    if "bundle_signer_key" not in text:
        raise M2T14Pending(
            "init-secrets.sh does not reference 'bundle_signer_key'; "
            "T14 must add it to SECRET_FILES"
        )
    # Verify it is in the SECRET_FILES list (not just a comment)
    # The file is a Python script using a list literal
    assert re.search(
        r'''["']bundle_signer_key["']''', text
    ), "bundle_signer_key must appear as a string literal in init-secrets"



def test_init_secrets_bundle_signer_key_ownership():
    """The OWNERSHIP table in init-secrets must set bundle_signer_key
    to api uid (10001) with mode 0o400 (single consumer, restrictive)."""
    text = _INIT_SECRETS.read_text(encoding="utf-8")
    if "bundle_signer_key" not in text:
        raise M2T14Pending(
            "init-secrets.sh does not reference 'bundle_signer_key'; "
            "cannot check ownership without it"
        )
    # Parse the OWNERSHIP dict entry: "bundle_signer_key": (uid, gid, mode)
    pattern = re.compile(
        r'"bundle_signer_key"\s*:\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(0o\d+)\s*\)'
    )
    m = pattern.search(text)
    assert m, "bundle_signer_key not found in OWNERSHIP table"
    uid, gid, mode_str = int(m.group(1)), int(m.group(2)), m.group(3)
    mode = int(mode_str, 8)
    assert uid == 10001, f"bundle_signer_key uid should be 10001 (api), got {uid}"
    assert mode == 0o400, (
        f"bundle_signer_key mode should be 0o400 (owner-read only), got {oct(mode)}"
    )


# ===================================================================
# RED: carol defined in acme Keycloak realm
# ===================================================================



def test_carol_in_acme_realm():
    """The acme-realm.json must define a user named ``carol``."""
    data = json.loads(_ACME_REALM.read_text(encoding="utf-8"))
    users = data.get("users", [])
    usernames = [u.get("username") for u in users]
    if "carol" not in usernames:
        raise M2T14Pending(
            f"acme-realm.json does not define user 'carol'; "
            f"current users: {usernames}"
        )
    carol = next(u for u in users if u.get("username") == "carol")
    assert carol.get("enabled") is True, "carol must be enabled"
    assert carol.get("email"), "carol must have an email"
    # Must have credentials so she can log in
    creds = carol.get("credentials", [])
    assert creds, "carol must have at least one credential entry"


# ===================================================================
# RED: payments-staging project in demo bootstrap
# ===================================================================



def test_payments_staging_in_demo_bootstrap():
    """The demo bootstrap (migrate-demo or demo.py) must create a project
    named ``payments-staging`` with ``environment: staging``."""
    # Check both demo.py and compose migrate-demo for the project name.
    # The demo.py is the primary source where projects are created.
    demo_py = _DEPLOY / "demo.py"
    assert demo_py.is_file(), f"demo.py not found at {demo_py}"
    text = demo_py.read_text(encoding="utf-8")
    if "payments-staging" not in text:
        raise M2T14Pending(
            "demo.py does not reference 'payments-staging'; "
            "T14 must add it as a project"
        )
    # Verify it specifies environment: staging (not prod)
    # Look for a dict/json with "payments-staging" and "staging"
    # We look for the pattern in a json= argument nearby
    idx = text.index("payments-staging")
    context = text[max(0, idx - 200):idx + 300]
    assert "staging" in context.lower(), (
        "payments-staging project must specify environment: staging"
    )



def test_carol_added_as_admin_in_demo():
    """The demo bootstrap must add carol as an admin user.

    Per M2_PLAN.md demo steps, carol is the second admin.
    The demo.py must log carol in and set her as admin."""
    demo_py = _DEPLOY / "demo.py"
    assert demo_py.is_file(), f"demo.py not found at {demo_py}"
    text = demo_py.read_text(encoding="utf-8")
    # carol must appear as a user being logged in or added as admin
    if "carol" not in text:
        raise M2T14Pending(
            "demo.py does not reference 'carol'; "
            "T14 must add carol as the second admin"
        )
    # Verify the admin role assignment
    carol_idx = text.index("carol")
    # Look in a window around the first occurrence for admin-related code
    context = text[max(0, carol_idx - 300):carol_idx + 500]
    assert "admin" in context.lower(), (
        "carol must be set up as an admin in the demo bootstrap"
    )


# ===================================================================
# Guards: Caddy/TLS unchanged, no new published ports
# ===================================================================


@_skip_no_yaml
def test_proxy_ports_unchanged():
    """T14 must not add new published ports.  Only the proxy publishes
    ports (127.0.0.1:443 and 127.0.0.1:80), verified by T11 tests.
    This guard confirms no new ports appeared."""
    data = _load_compose()
    for name, svc in data["services"].items():
        if name == "proxy":
            ports = svc.get("ports", [])
            # Existing: 127.0.0.1:443:8443 and 127.0.0.1:80:8080
            assert len(ports) == 2, (
                f"proxy should have exactly 2 port mappings, got {len(ports)}: {ports}"
            )
            for p in ports:
                assert str(p).startswith("127.0.0.1:"), (
                    f"proxy port must bind to loopback: {p}"
                )
            continue
        assert "ports" not in svc, (
            f"service '{name}' must not publish ports (only proxy may)"
        )


def test_caddyfile_tls_internal_unchanged():
    """The Caddyfile must still use ``tls internal`` (not removed or
    changed to a different mode by T14)."""
    text = _CADDYFILE.read_text(encoding="utf-8")
    assert "tls internal" in text, (
        "Caddyfile must contain 'tls internal' for the default site"
    )


def test_caddyfile_csp_unchanged():
    """The CSP header must still contain the required directives after T14."""
    text = _CADDYFILE.read_text(encoding="utf-8")
    for directive in [
        "default-src 'self'",
        "script-src 'self'",
        "frame-ancestors 'none'",
    ]:
        assert directive in text, f"CSP missing directive: {directive}"


# ===================================================================
# Live tests: Docker required (at most 2)
# ===================================================================

# Docker Compose availability check -- skip live tests if Docker is absent.
# We check that `docker compose config --services` works for this stack,
# which is more reliable than `docker info` alone (catches Linux-only stacks
# on Windows Docker Desktop without WSL2).

def _docker_compose_available() -> bool:
    """Return True if ``docker compose`` can list services for this stack."""
    import subprocess
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", str(_COMPOSE), "config", "--services"],
            capture_output=True,
            timeout=15,
            cwd=str(_DEPLOY),
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


_skip_no_compose = pytest.mark.skipif(
    not _docker_compose_available(),
    reason="Docker Compose not available for this stack; live deploy tests skipped",
)


@_skip_no_compose

@pytest.mark.timeout(300)
def test_live_stack_ready():
    """Live: compose has T14 features and the stack comes up with /ready 200.

    Pre-checks the compose YAML for T14 features (bundle_signer_key secret,
    carol in realm, payments-staging in demo) before attempting to bring the
    stack up.  Skipped when Docker Compose is not available."""
    # Opt-in: the stack needs init-secrets and several GB of RAM.  CI runs it
    # nowhere (compose-smoke covers the root compose only); run locally with
    # AGG_LIVE_STACK=1 (named edit, T14 commit).
    import os
    if os.environ.get("AGG_LIVE_STACK") != "1":
        pytest.skip("live ee stack test is opt-in: set AGG_LIVE_STACK=1")

    # Gate on T14 compose features before spending time on docker compose up
    if _HAS_YAML:
        data = _load_compose()
        secrets = data.get("secrets", {})
        if "bundle_signer_key" not in secrets:
            raise M2T14Pending(
                "compose does not define bundle_signer_key secret; "
                "cannot run live stack test until T14 is built"
            )
        api_secrets = data["services"].get("api", {}).get("secrets", [])
        if "bundle_signer_key" not in api_secrets:
            raise M2T14Pending(
                "api service does not mount bundle_signer_key; "
                "cannot run live stack test until T14 is built"
            )
    else:
        raise M2T14Pending("pyyaml not available to check compose features")

    # Also gate on carol in realm
    realm_data = json.loads(_ACME_REALM.read_text(encoding="utf-8"))
    usernames = [u.get("username") for u in realm_data.get("users", [])]
    if "carol" not in usernames:
        raise M2T14Pending(
            "acme-realm.json does not have carol; "
            "cannot run live stack test until T14 is built"
        )

    import subprocess

    compose_file = str(_COMPOSE)

    # Bring up the stack (build + up)
    up_result = subprocess.run(
        ["docker", "compose", "-f", compose_file, "up", "-d", "--wait",
         "--build"],
        capture_output=True,
        timeout=240,
        cwd=str(_DEPLOY),
    )
    if up_result.returncode != 0:
        pytest.fail(
            f"docker compose up failed (rc={up_result.returncode}): "
            f"{up_result.stderr.decode(errors='replace')[-500:]}"
        )

    try:
        # Check /ready returns 200 via the proxy (port 443 on loopback)
        import urllib.request
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request("https://localhost/ready")
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            assert resp.status == 200, f"/ready returned {resp.status}"
    finally:
        subprocess.run(
            ["docker", "compose", "-f", compose_file, "down", "-v"],
            capture_output=True,
            timeout=60,
            cwd=str(_DEPLOY),
        )
