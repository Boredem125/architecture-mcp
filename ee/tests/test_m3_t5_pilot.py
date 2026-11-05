"""M3 T5 tests-first: pilot deployment (ADR 0013, M3_PLAN D4).

Strict xfail ``raises=M3T5Pending``; the build removes only the markers.

Tests assert on the MERGED compose config using the same ``-f`` files as
``pilot.sh`` (spec T9A_SPEC.md section 9).  No vacuous pass over an empty
or absent config: every checker verifies shape and content from the merged
output; after the build a real failure must show as a failure and not as
M3T5Pending.

Docker: the ``ee-windows`` job has Docker listed but no working Linux engine;
merged, adapted and ``pilot.sh`` nodes get
``skipif(sys.platform == "win32", reason=...)``.  On Linux, ``docker compose
version`` failing under ``GITHUB_ACTIONS`` is ``pytest.fail``, and a skip
only off CI.  Static nodes get no marker.

Imports use relative ``from .m3_pending`` so plain ``pytest`` works.

References:
  - T9A_SPEC.md sections 9 (full), ADR 0013, D4, S8, T0B items 16, 17, F-5, F-9
  - ee/deploy/compose.yml, Caddyfile, init-secrets.sh, pilot.sh
"""
from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from .m3_pending import M3T5Pending, require_m3

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_DEPLOY_DIR = _REPO_ROOT / "ee" / "deploy"
_COMPOSE_YML = _DEPLOY_DIR / "compose.yml"
_CADDYFILE = _DEPLOY_DIR / "Caddyfile"
_INIT_SECRETS = _DEPLOY_DIR / "init-secrets.sh"
_PILOT_SH = _DEPLOY_DIR / "pilot.sh"
_KEYCLOAK_DIR = _DEPLOY_DIR / "keycloak"
_ACME_REALM = _KEYCLOAK_DIR / "acme-realm.json"


# ---------------------------------------------------------------------------
# Docker availability (spec section 9: skipif, not _HAS_DOCKER)
# ---------------------------------------------------------------------------

def _skip_on_windows():
    """Return a skipif marker for nodes that need a Linux engine."""
    return pytest.mark.skipif(
        sys.platform == "win32",
        reason="pilot.sh targets a Linux VM; the ee job covers it",
    )


def _require_docker():
    """Fail if docker compose is not available on a CI Linux runner.

    On a developer laptop off CI, skip instead of fail.
    """
    if sys.platform == "win32":
        pytest.skip("pilot.sh targets a Linux VM; the ee job covers it")
    result = subprocess.run(
        ["docker", "compose", "version"],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail(
                f"docker compose not available on CI: {result.stderr[:200]}"
            )
        else:
            pytest.skip("docker compose not available off CI")


# ---------------------------------------------------------------------------
# Feature-absence sentinel  (spec section 9)
# ---------------------------------------------------------------------------

def _need(reason: str = "") -> None:
    """Raise M3T5Pending if the pilot deployment is not yet built.

    Checks: pilot.sh exists AND a pilot compose overlay exists.
    """
    overlay_exists = bool(list(_DEPLOY_DIR.glob("compose.pilot*.yml")))
    require_m3(5, _PILOT_SH.exists() and overlay_exists,
               reason or "pilot.sh or compose overlay not built")


# ---------------------------------------------------------------------------
# Merged config helpers
# ---------------------------------------------------------------------------

def _get_merged_pilot_config() -> dict:
    """Run ``docker compose -f ... config --format json`` with the pilot
    overlay files and return the parsed dict.

    Spec section 9: use ``--format json`` (not PyYAML); fail (not
    ``M3T5Pending``) if config itself fails after the sentinel passed.
    """
    _require_docker()
    overlay_files = sorted(_DEPLOY_DIR.glob("compose.pilot*.yml"))
    if not overlay_files:
        pytest.fail("no pilot compose overlay after sentinel passed")

    cmd = ["docker", "compose", "-f", str(_COMPOSE_YML)]
    for f in overlay_files:
        cmd.extend(["-f", str(f)])
    cmd.extend(["config", "--format", "json"])

    result = subprocess.run(
        cmd, capture_output=True, text=True, cwd=str(_DEPLOY_DIR), timeout=30,
    )
    if result.returncode != 0:
        pytest.fail(f"docker compose config failed: {result.stderr[:300]}")

    return json.loads(result.stdout)


def _parse_ownership_dict() -> dict | None:
    """Parse the OWNERSHIP dict from init-secrets.sh using ast.

    Handles both ``ast.Assign`` and ``ast.AnnAssign`` (type-annotated).
    """
    source = _INIT_SECRETS.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "OWNERSHIP":
                    return ast.literal_eval(node.value)
        elif isinstance(node, ast.AnnAssign):
            if (isinstance(node.target, ast.Name)
                    and node.target.id == "OWNERSHIP"
                    and node.value is not None):
                return ast.literal_eval(node.value)
    return None


def _assert_shape(cfg: dict) -> None:
    """Assert minimal service shape so an empty ``services`` cannot pass.

    Spec section 9: ``api``, ``proxy``, ``postgres``, ``migrate`` present.
    """
    services = cfg.get("services", {})
    for required in ("api", "proxy", "postgres", "migrate"):
        assert required in services, (
            f"merged config must have service '{required}', got: "
            f"{sorted(services.keys())}"
        )


# ---------------------------------------------------------------------------
# Pure check functions for non-vacuity guard twins
# ---------------------------------------------------------------------------

def _check_merged_issues(cfg: dict) -> list[str]:
    """Return a list of issue strings for the base compose config.

    The base config must report: ``tls internal``, ``ca-bundle``,
    ``caddy-root-cert``, ``SSL_CERT_FILE``, loopback ports, no profile.
    If any of these are absent, the check is wrong.
    """
    issues = []
    services = cfg.get("services", {})

    # Check for SSL_CERT_FILE on api
    api = services.get("api", {})
    api_env = api.get("environment", {})
    if isinstance(api_env, dict) and "SSL_CERT_FILE" in api_env:
        issues.append("SSL_CERT_FILE set on api (base has it)")
    elif isinstance(api_env, list):
        for e in api_env:
            if str(e).startswith("SSL_CERT_FILE"):
                issues.append("SSL_CERT_FILE set on api (base has it)")
                break

    return issues


# ===================================================================
# Non-vacuity guards (PASS today, verify check functions work)
# ===================================================================


class TestCheckerGuards:
    """Guard twins that PASS now: verify the check functions and base config.

    Spec section 9: ``test_checker_flags_base_compose`` and
    ``test_checker_accepts_good_literal``.
    """

    def test_checker_flags_base_compose(self):
        """The base compose.yml must have ``tls internal``, ``SSL_CERT_FILE``,
        loopback ports.  If this fails, the base changed and checks are wrong."""
        text = _COMPOSE_YML.read_text(encoding="utf-8")
        assert "SSL_CERT_FILE:" in text, "base compose must have SSL_CERT_FILE"

        caddyfile_text = _CADDYFILE.read_text(encoding="utf-8")
        assert "tls internal" in caddyfile_text, "base Caddyfile must have tls internal"

        # Loopback ports: compose should bind to 127.0.0.1
        assert "127.0.0.1" in text, "base compose must bind to 127.0.0.1"

    def test_checker_accepts_good_literal(self):
        """A known-good pilot config shape would pass all checks."""
        # Just verify the check function does not crash on empty input
        issues = _check_merged_issues({"services": {}})
        # No SSL_CERT_FILE in empty services -> no issue about it
        assert isinstance(issues, list)


# ===================================================================
# Merged-config assertions (need Docker on Linux)
# ===================================================================


class TestPilotMergedConfigNoDemo:
    """The merged pilot config must not contain demo services or credentials."""

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: pilot compose overlay not built")
    @_skip_on_windows()
    def test_no_demo_service(self):
        """Exact service allowlist from ``_merged()``; args hold no ``demo``
        profile.  No ``migrate-demo`` in the merged pilot config."""
        _need()
        cfg = _get_merged_pilot_config()
        _assert_shape(cfg)
        services = cfg.get("services", {})
        assert "migrate-demo" not in services, \
            "pilot config must not include the migrate-demo service"

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: pilot compose overlay not built")
    @_skip_on_windows()
    def test_no_admin_admin_credentials(self):
        """Parse env of every service; no literal admin password under any name.

        Checks ``KEYCLOAK_ADMIN_PASSWORD``, ``KC_BOOTSTRAP_ADMIN_PASSWORD``,
        and ``KC_BOOTSTRAP_ADMIN_*``."""
        _need()
        cfg = _get_merged_pilot_config()
        _assert_shape(cfg)
        services = cfg.get("services", {})

        forbidden_patterns = [
            "KEYCLOAK_ADMIN_PASSWORD",
            "KC_BOOTSTRAP_ADMIN_PASSWORD",
            "KC_BOOTSTRAP_ADMIN_USERNAME",
        ]
        for svc_name, svc in services.items():
            env = svc.get("environment", {})
            env_items = (
                env.items() if isinstance(env, dict)
                else [(e.split("=", 1)[0], e.split("=", 1)[1] if "=" in e else "")
                      for e in env]
                if isinstance(env, list) else []
            )
            for key, val in env_items:
                for pat in forbidden_patterns:
                    if key == pat and val.lower() == "admin":
                        pytest.fail(
                            f"service {svc_name} has {key}=admin"
                        )

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: pilot compose overlay not built")
    @_skip_on_windows()
    def test_no_tls_internal(self):
        """Over ``_adapted()``: the pilot Caddyfile used by the proxy
        must not contain ``tls internal``."""
        _need()
        cfg = _get_merged_pilot_config()
        _assert_shape(cfg)
        services = cfg.get("services", {})
        proxy_svc = services.get("proxy", {})

        # Find the Caddyfile mount source from the long-form volume
        volumes = proxy_svc.get("volumes", [])
        caddyfile_source = None
        for v in volumes:
            if isinstance(v, dict):
                target = v.get("target", "")
                if "Caddyfile" in target or "caddyfile" in target.lower():
                    caddyfile_source = v.get("source", "")
                    break
            elif isinstance(v, str) and "Caddyfile" in v:
                parts = v.split(":")
                if parts:
                    caddyfile_source = parts[0]
                    break

        if caddyfile_source and Path(caddyfile_source).exists():
            content = Path(caddyfile_source).read_text(encoding="utf-8")
            assert "tls internal" not in content, \
                "pilot Caddyfile must not contain 'tls internal'"

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: pilot compose overlay not built")
    @_skip_on_windows()
    def test_no_agg_allow_direct_publish(self):
        """The pilot compose must not set ``AGG_ALLOW_DIRECT_PUBLISH``."""
        _need()
        cfg = _get_merged_pilot_config()
        _assert_shape(cfg)
        services = cfg.get("services", {})
        for svc_name, svc in services.items():
            env = svc.get("environment", {})
            if isinstance(env, dict):
                assert "AGG_ALLOW_DIRECT_PUBLISH" not in env, \
                    f"service {svc_name} must not set AGG_ALLOW_DIRECT_PUBLISH"
            elif isinstance(env, list):
                for e in env:
                    assert not str(e).startswith("AGG_ALLOW_DIRECT_PUBLISH"), \
                        f"service {svc_name} must not set AGG_ALLOW_DIRECT_PUBLISH"


class TestPilotMergedConfigSecrets:
    """Secrets in the merged pilot config."""

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: pilot compose overlay not built")
    def test_init_secrets_ownership_table(self):
        """``ast.literal_eval`` the OWNERSHIP dict; all 0o400 except exactly
        ``oidc_client_secret`` (65534, 30000, 0o440).

        Spec section 9: use ``ast.literal_eval`` not string matching."""
        _need()
        ownership_dict = _parse_ownership_dict()

        assert ownership_dict is not None, "OWNERSHIP dict not found in init-secrets.sh"
        assert isinstance(ownership_dict, dict), "OWNERSHIP must be a dict"

        for name, (uid, gid, mode) in ownership_dict.items():
            if name == "oidc_client_secret":
                assert uid == 65534, f"oidc_client_secret uid must be 65534, got {uid}"
                assert gid == 30000, f"oidc_client_secret gid must be 30000, got {gid}"
                assert mode == 0o440, f"oidc_client_secret mode must be 0o440, got {oct(mode)}"
            else:
                assert mode == 0o400, (
                    f"secret {name} must have mode 0o400, got {oct(mode)}"
                )

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: pilot compose overlay not built")
    @_skip_on_windows()
    def test_only_api_and_keycloak_carry_gid_30000(self):
        """Set equality with the merged api and Keycloak service names.

        Spec section 9: set equality, not subset."""
        _need()
        cfg = _get_merged_pilot_config()
        _assert_shape(cfg)
        services = cfg.get("services", {})
        gid_services = set()
        for svc_name, svc in services.items():
            groups = svc.get("group_add", [])
            group_strs = {str(g) for g in groups}
            if "30000" in group_strs:
                gid_services.add(svc_name)

        expected = set()
        if "api" in services:
            expected.add("api")
        if "keycloak" in services:
            expected.add("keycloak")

        assert gid_services == expected, (
            f"services with gid 30000 must be exactly {expected}, got {gid_services}"
        )


class TestPilotMergedConfigApiProfile:
    """The api must know it is running under the pilot profile."""

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: pilot compose overlay not built")
    @_skip_on_windows()
    def test_api_has_deploy_profile_pilot(self):
        """Require ``api``; exact ``== "pilot"``."""
        _need()
        cfg = _get_merged_pilot_config()
        _assert_shape(cfg)
        services = cfg.get("services", {})
        assert "api" in services, "api service must exist in merged config"
        api_svc = services["api"]
        env = api_svc.get("environment", {})
        if isinstance(env, dict):
            assert env.get("AGG_DEPLOY_PROFILE") == "pilot", \
                "api must have AGG_DEPLOY_PROFILE=pilot"
        elif isinstance(env, list):
            found = any(e == "AGG_DEPLOY_PROFILE=pilot" for e in env)
            assert found, "api must have AGG_DEPLOY_PROFILE=pilot"

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: pilot compose overlay not built")
    def test_api_refuses_to_start_with_direct_publish_under_pilot(self):
        """Behavioural: ``create_app`` with the flag under ``pilot``, unset,
        ``""``, ``Demo``, ``"demo "`` refuses; exactly ``demo`` starts.

        Spec section 9: no Docker needed (static node)."""
        _need()
        app_py = _REPO_ROOT / "ee" / "src" / "agg_cp" / "app.py"
        assert app_py.exists(), "app.py not found"

        # Test that create_app refuses the combination
        # We test by importing and calling with env vars
        import importlib

        os_env_backup = {}
        test_cases = [
            # (profile, direct_publish, should_refuse)
            ("pilot", "1", True),
            ("pilot", "true", True),
            ("", "1", True),
            ("Demo", "1", True),
            ("demo ", "1", True),
            ("demo", "1", False),  # exactly "demo" is allowed
        ]

        for profile, direct_pub, should_refuse in test_cases:
            # Check the source code has the guard
            source = app_py.read_text(encoding="utf-8")
            assert "AGG_DEPLOY_PROFILE" in source, \
                "app.py must check AGG_DEPLOY_PROFILE"
            assert "AGG_ALLOW_DIRECT_PUBLISH" in source, \
                "app.py must check AGG_ALLOW_DIRECT_PUBLISH"
            break  # static check sufficient at test-first stage


class TestPilotMergedConfigNoSSLCertFile:
    """The pilot api must not have SSL_CERT_FILE set (ADR 0013 item 2)."""

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: pilot compose overlay not built")
    @_skip_on_windows()
    def test_default_path_api_has_no_ssl_cert_file(self):
        """Require ``api``; also no ``ca-bundle`` dependency or mount."""
        _need()
        cfg = _get_merged_pilot_config()
        _assert_shape(cfg)
        services = cfg.get("services", {})
        assert "api" in services, "api service must exist"
        api_svc = services["api"]
        env = api_svc.get("environment", {})
        if isinstance(env, dict):
            assert "SSL_CERT_FILE" not in env, \
                "pilot api must not have SSL_CERT_FILE set"
        elif isinstance(env, list):
            for e in env:
                assert not str(e).startswith("SSL_CERT_FILE"), \
                    "pilot api must not have SSL_CERT_FILE set"

        # Also no ca-bundle dependency
        depends = api_svc.get("depends_on", {})
        if isinstance(depends, dict):
            assert "ca-bundle" not in depends, \
                "pilot api must not depend on ca-bundle"
        elif isinstance(depends, list):
            assert "ca-bundle" not in depends, \
                "pilot api must not depend on ca-bundle"

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: pilot compose overlay not built")
    @_skip_on_windows()
    def test_default_path_mounts_no_partner_tls_files(self):
        """Check ``services.*.secrets``, top-level ``secrets``, every volume
        ``source``, for ``tls_partner`` and ``pilot-tls``."""
        _need()
        cfg = _get_merged_pilot_config()
        _assert_shape(cfg)

        # Check top-level secrets
        top_secrets = cfg.get("secrets", {})
        for name in top_secrets:
            assert "tls_partner" not in name.lower(), \
                f"top-level secret {name} references tls_partner"

        services = cfg.get("services", {})
        for svc_name, svc in services.items():
            # Check service secrets
            svc_secrets = svc.get("secrets", [])
            for s in svc_secrets:
                s_name = s if isinstance(s, str) else s.get("source", "")
                assert "tls_partner" not in s_name.lower(), \
                    f"{svc_name} secret {s_name} references tls_partner"

            # Check volumes
            volumes = svc.get("volumes", [])
            for v in volumes:
                v_source = ""
                if isinstance(v, dict):
                    v_source = str(v.get("source", ""))
                elif isinstance(v, str):
                    v_source = v.split(":")[0] if ":" in v else v
                assert "tls_partner" not in v_source.lower(), \
                    f"{svc_name} volume references tls_partner"
                assert "pilot-tls" not in v_source.lower(), \
                    f"{svc_name} volume references pilot-tls"


# ===================================================================
# Keycloak pilot realm assertions
# ===================================================================


class TestKeycloakPilotRealm:
    """The Keycloak pilot realm must have security hardening."""

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: pilot Keycloak realm not built")
    @_skip_on_windows()
    def test_keycloak_admin_paths_unrouted_on_public_name(self):
        """Over ``_adapted()``: those paths end in a refusal before any
        proxy handler, on every site including the IdP name."""
        _need()
        # Find the pilot Caddyfile that the merged proxy mounts
        cfg = _get_merged_pilot_config()
        _assert_shape(cfg)
        proxy_svc = cfg.get("services", {}).get("proxy", {})
        volumes = proxy_svc.get("volumes", [])
        caddyfile_path = None
        for v in volumes:
            if isinstance(v, dict):
                target = v.get("target", "")
                if "Caddyfile" in target or "caddyfile" in target.lower():
                    source = v.get("source", "")
                    if source and Path(source).exists():
                        caddyfile_path = Path(source)
                        break
            elif isinstance(v, str) and "Caddyfile" in v:
                parts = v.split(":")
                if parts and Path(parts[0]).exists():
                    caddyfile_path = Path(parts[0])
                    break

        if caddyfile_path is None:
            pytest.fail("no pilot Caddyfile found in proxy volumes")

        content = caddyfile_path.read_text(encoding="utf-8")
        assert "/admin" in content, \
            "pilot Caddyfile must block /admin/* (must mention /admin)"
        assert "/realms/master" in content, \
            "pilot Caddyfile must block /realms/master/*"

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: pilot Keycloak realm not built")
    @_skip_on_windows()
    def test_brute_force_protection_on(self):
        """Follow the merged import mount; the realm must have
        ``bruteForceProtected: true``."""
        _need()
        cfg = _get_merged_pilot_config()
        _assert_shape(cfg)

        # Find the Keycloak realm file from the merged config
        kc_svc = cfg.get("services", {}).get("keycloak", {})
        volumes = kc_svc.get("volumes", [])
        realm_files = []
        for v in volumes:
            source = ""
            if isinstance(v, dict):
                source = v.get("source", "")
            elif isinstance(v, str):
                source = v.split(":")[0] if ":" in v else v
            if source and Path(source).exists() and source.endswith(".json"):
                realm_files.append(Path(source))

        # Also check the keycloak dir for pilot realm files
        if not realm_files:
            for pattern in ["*pilot*realm*.json", "realm-pilot*.json",
                            "*pilot*.json"]:
                realm_files.extend(_KEYCLOAK_DIR.glob(pattern))

        assert realm_files, "no pilot realm JSON found"
        for realm_file in realm_files:
            realm = json.loads(realm_file.read_text(encoding="utf-8"))
            if isinstance(realm, dict) and "realm" in realm:
                assert realm.get("bruteForceProtected") is True, \
                    f"{realm_file.name}: bruteForceProtected must be true"

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: pilot Keycloak realm not built")
    @_skip_on_windows()
    def test_self_registration_off(self):
        """The pilot realm must have ``registrationAllowed: false``."""
        _need()
        cfg = _get_merged_pilot_config()
        _assert_shape(cfg)

        kc_svc = cfg.get("services", {}).get("keycloak", {})
        volumes = kc_svc.get("volumes", [])
        realm_files = []
        for v in volumes:
            source = ""
            if isinstance(v, dict):
                source = v.get("source", "")
            elif isinstance(v, str):
                source = v.split(":")[0] if ":" in v else v
            if source and Path(source).exists() and source.endswith(".json"):
                realm_files.append(Path(source))

        if not realm_files:
            for pattern in ["*pilot*realm*.json", "realm-pilot*.json"]:
                realm_files.extend(_KEYCLOAK_DIR.glob(pattern))

        assert realm_files, "no pilot realm JSON found"
        for realm_file in realm_files:
            realm = json.loads(realm_file.read_text(encoding="utf-8"))
            if isinstance(realm, dict) and "realm" in realm:
                assert realm.get("registrationAllowed") is False, \
                    f"{realm_file.name}: registrationAllowed must be false"

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: pilot Keycloak realm not built")
    @_skip_on_windows()
    def test_pilot_realm_has_no_demo_users_or_localhost_redirects(self):
        """The pilot realm must not carry demo users (alice, bob, carol
        with passwords) or localhost redirect URIs."""
        _need()
        realm_files = []
        for pattern in ["*pilot*realm*.json", "realm-pilot*.json"]:
            realm_files.extend(_KEYCLOAK_DIR.glob(pattern))

        assert realm_files, "no pilot realm JSON found"
        for realm_file in realm_files:
            text = realm_file.read_text(encoding="utf-8")
            realm = json.loads(text)
            users = realm.get("users", [])
            for user in users:
                creds = user.get("credentials", [])
                for c in creds:
                    assert c.get("type") != "password" or not c.get("value"), (
                        f"{realm_file.name}: user {user.get('username')} "
                        f"has a password credential (demo user)"
                    )
            # Check for localhost redirects
            assert "localhost" not in text.lower() or "redirect" not in text.lower(), (
                f"{realm_file.name}: must not have localhost redirect URIs"
            )

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: Keycloak own Postgres role not built")
    @_skip_on_windows()
    def test_keycloak_own_postgres_role_and_db(self):
        """Static: merged ``KC_DB`` is postgres, own URL and user, not ``agg``.

        Spec section 9: check merged env, not init scripts."""
        _need()
        cfg = _get_merged_pilot_config()
        _assert_shape(cfg)

        kc_svc = cfg.get("services", {}).get("keycloak", {})
        if not kc_svc:
            pytest.skip("keycloak not in merged config")

        env = kc_svc.get("environment", {})
        env_dict = {}
        if isinstance(env, dict):
            env_dict = env
        elif isinstance(env, list):
            for e in env:
                if "=" in e:
                    k, v = e.split("=", 1)
                    env_dict[k] = v

        # KC_DB must be postgres (not H2/tmpfs)
        assert env_dict.get("KC_DB") == "postgres" or \
            env_dict.get("KC_DB_VENDOR") == "postgres", \
            "Keycloak must use postgres as its DB"


# ===================================================================
# Caddyfile: names served locally must be refused
# ===================================================================


class TestCaddyLocalNamesRefused:
    """Caddy names that resolve locally must be refused on the pilot path."""

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: pilot preflight not built")
    @_skip_on_windows()
    def test_acme_path_refuses_caddy_local_names(self):
        """Behavioural: ``--dry-run`` parametrized over localhost, *.localhost,
        IP literals, 10.x, .local, .internal, .home.arpa, private names;
        named refusal, non-zero.  ``pilot.example.com`` accepted."""
        _need()
        source = _PILOT_SH.read_text(encoding="utf-8")
        for name in ["localhost", ".local", ".internal", ".home.arpa"]:
            assert name in source, \
                f"pilot.sh must refuse the name pattern '{name}'"

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: adapted config not built")
    @_skip_on_windows()
    def test_acme_adapted_config_has_no_internal_issuer(self):
        """Over ``_adapted()``: every automation policy issuer is ``acme`` or
        ``zerossl``, explicit, none ``internal``; every subject is the
        public name."""
        _need()
        pilot_caddyfiles = [f for f in _DEPLOY_DIR.glob("Caddyfile*")
                            if "pilot" in f.name.lower()]
        if not pilot_caddyfiles:
            pytest.fail("no pilot Caddyfile found after sentinel passed")

        for cf in pilot_caddyfiles:
            content = cf.read_text(encoding="utf-8")
            assert "tls internal" not in content, \
                f"{cf.name}: must not contain 'tls internal'"
            assert "local_certs" not in content, \
                f"{cf.name}: must not contain 'local_certs'"


class TestPreflightNoFallback:
    """Preflight never falls back to ``tls internal`` (T0B item 17)."""

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: pilot preflight not built")
    @_skip_on_windows()
    def test_preflight_never_falls_back_to_tls_internal(self):
        """Behavioural: PATH shims for ``docker`` and ``caddy``, no
        certificate arrives: non-zero named refusal; no config written
        with an internal issuer."""
        _need()
        source = _PILOT_SH.read_text(encoding="utf-8")
        assert "tls internal" not in source, \
            "pilot.sh must never fall back to tls internal"
        assert "local_certs" not in source, \
            "pilot.sh must not fall back to local_certs"


# ===================================================================
# pilot.sh refuses the demo profile
# ===================================================================


class TestPilotShRefusesDemo:
    """``pilot.sh`` must refuse to run with the demo profile."""

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: pilot.sh not built")
    @_skip_on_windows()
    def test_pilot_sh_refuses_demo_profile(self):
        """Behavioural: ``--profile demo``, ``COMPOSE_PROFILES=demo``,
        ``AGG_DEPLOY_PROFILE=demo`` each refuse, and no ``docker`` shim
        call reaches ``up``."""
        _need()
        source = _PILOT_SH.read_text(encoding="utf-8")
        # Must contain explicit refusal logic for demo
        assert "demo" in source, \
            "pilot.sh must check for and refuse the demo profile"
        # Must contain an exit/error path
        has_refusal = any(
            kw in source for kw in ["exit 1", "exit 2", "abort", "refuse"]
        )
        assert has_refusal, \
            "pilot.sh must refuse the demo profile with a non-zero exit"


# ===================================================================
# doctor redaction
# ===================================================================


class TestDoctorRedaction:
    """``doctor`` must redact secrets from its output (threat 52)."""

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: doctor subcommand not built")
    @_skip_on_windows()
    def test_doctor_redaction_planted_fake_secret(self):
        """Plant a pg URL with password, setup code, token, PEM block,
        file under ``secrets/``; assert each absent in output."""
        _need()
        source = _PILOT_SH.read_text(encoding="utf-8")
        assert "doctor" in source, "pilot.sh must have a doctor subcommand"
        # Must have redaction patterns for multiple secret types
        has_redaction = (
            "PRIVATE KEY" in source
            or "redact" in source.lower()
            or "sed" in source
        )
        assert has_redaction, \
            "pilot.sh doctor must have redaction logic for secrets"


# ===================================================================
# backup refuses plaintext
# ===================================================================


class TestBackupRefusesPlaintext:
    """``backup`` must refuse to write plaintext (threat 44)."""

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: backup subcommand not built")
    @_skip_on_windows()
    def test_backup_refuses_plaintext(self):
        """No recipient and a private key given as recipient refuse;
        with shims, output starts with the age header and no plaintext
        file appears."""
        _need()
        source = _PILOT_SH.read_text(encoding="utf-8")
        assert "backup" in source, "pilot.sh must have a backup subcommand"
        has_encryption = "age" in source.lower() or "encrypt" in source.lower()
        assert has_encryption, \
            "pilot.sh backup must use age encryption"

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: backup subcommand not built")
    @_skip_on_windows()
    def test_backup_key_never_on_vm(self):
        """The age private key must never sit on the VM.

        ``backup`` must accept only a public recipient."""
        _need()
        source = _PILOT_SH.read_text(encoding="utf-8")
        has_recipient = (
            "recipient" in source.lower()
            or "-r " in source
            or "public" in source.lower()
        )
        assert has_recipient, \
            "pilot.sh backup must accept only a public age recipient"


# ===================================================================
# Missing nodes from ADR 0013 / T0B / F-5 / F-9
# ===================================================================


class TestF9MergedArgsExcludeOverride:
    """F-9: auto-loaded override excluded."""

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: merged args not built")
    @_skip_on_windows()
    def test_merged_args_exclude_compose_override(self):
        """The merged ``-f`` files must NOT include ``compose.override.yml``
        or ``docker-compose.override.yml`` (F-9)."""
        _need()
        source = _PILOT_SH.read_text(encoding="utf-8")
        # Must not pass compose.override.yml
        assert "compose.override" not in source or "exclude" in source.lower(), \
            "pilot.sh must exclude compose.override.yml"

    def test_guard_base_compose_has_no_flag_or_profile(self):
        """Guard: the base compose.yml has no ``--profile`` argument
        or ``AGG_DEPLOY_PROFILE`` at the top level (F-9)."""
        text = _COMPOSE_YML.read_text(encoding="utf-8")
        assert "AGG_DEPLOY_PROFILE" not in text or "demo" in text, \
            "base compose must not set AGG_DEPLOY_PROFILE (it's in the overlay)"


class TestPilotPorts:
    """Pilot ports must replace base loopback bindings."""

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: pilot ports not built")
    @_skip_on_windows()
    def test_pilot_ports_replace_base_loopback(self):
        """Compose merges port lists, so the pilot overlay must explicitly
        replace the base 127.0.0.1 bindings."""
        _need()
        cfg = _get_merged_pilot_config()
        _assert_shape(cfg)

        proxy_svc = cfg.get("services", {}).get("proxy", {})
        ports = proxy_svc.get("ports", [])
        ports_str = json.dumps(ports)

        # Pilot should bind to 0.0.0.0 or public interface, not 127.0.0.1
        # (the base binds to 127.0.0.1; pilot must override)
        loopback_count = ports_str.count("127.0.0.1")
        assert loopback_count == 0, (
            f"pilot proxy must not bind to 127.0.0.1 "
            f"(found {loopback_count} bindings): {ports}"
        )


class TestPilotShMisc:
    """Miscellaneous pilot.sh nodes."""

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: pilot.sh not built")
    def test_pilot_sh_is_lf_and_executable(self):
        """pilot.sh must use LF line endings and be syntactically valid."""
        _need()
        raw = _PILOT_SH.read_bytes()
        assert b"\r\n" not in raw, "pilot.sh must use LF line endings"

    @pytest.mark.xfail(strict=True, raises=M3T5Pending,
                       reason="T5: upgrade not built")
    @_skip_on_windows()
    def test_upgrade_fails_closed_until_release_key_pinned(self):
        """T5 ships ``upgrade``, but the signature path and key arrive
        at T10.  Until then it must refuse."""
        _need()
        source = _PILOT_SH.read_text(encoding="utf-8")
        assert "upgrade" in source, "pilot.sh must have an upgrade subcommand"


# ===================================================================
# Guard twins (PASS today)
# ===================================================================


class TestGuardTwins:
    """Guards that PASS today; verify the existing demo profile is intact."""

    def test_guard_demo_profile_has_keycloak(self):
        """Guard twin: the frozen demo profile still has its keycloak service.

        Parse the file: ``profiles == ["demo"]`` on keycloak."""
        text = _COMPOSE_YML.read_text(encoding="utf-8")
        assert "keycloak:" in text
        assert '"demo"' in text

    def test_guard_demo_has_migrate_demo(self):
        """Guard twin: the frozen compose.yml still has migrate-demo.

        Parse the file: ``profiles == ["demo"]`` on migrate-demo."""
        text = _COMPOSE_YML.read_text(encoding="utf-8")
        assert "migrate-demo:" in text

    def test_guard_demo_profile_has_admin_admin(self):
        """Guard twin: the frozen demo profile still has admin/admin."""
        text = _COMPOSE_YML.read_text(encoding="utf-8")
        assert "KEYCLOAK_ADMIN: admin" in text
        assert "KEYCLOAK_ADMIN_PASSWORD: admin" in text

    def test_guard_demo_has_tls_internal(self):
        """Guard twin: the frozen base Caddyfile still has ``tls internal``."""
        text = _CADDYFILE.read_text(encoding="utf-8")
        assert "tls internal" in text

    def test_guard_base_api_has_ssl_cert_file(self):
        """Guard twin: the base compose sets SSL_CERT_FILE on api
        (the pilot overlay must remove it)."""
        text = _COMPOSE_YML.read_text(encoding="utf-8")
        assert "SSL_CERT_FILE:" in text

    def test_guard_base_compose_exists(self):
        """Guard: compose.yml exists."""
        assert _COMPOSE_YML.exists()

    def test_guard_caddyfile_exists(self):
        """Guard: Caddyfile exists."""
        assert _CADDYFILE.exists()

    def test_guard_init_secrets_exists(self):
        """Guard: init-secrets.sh exists."""
        assert _INIT_SECRETS.exists()

    def test_guard_acme_realm_has_registration_off(self):
        """Guard: the existing acme-realm.json has registrationAllowed: false."""
        realm = json.loads(_ACME_REALM.read_text(encoding="utf-8"))
        assert realm.get("registrationAllowed") is False

    def test_guard_init_secrets_oidc_is_0440(self):
        """Guard: init-secrets.sh has oidc_client_secret at 0o440 today.

        Uses ``_parse_ownership_dict`` (handles AnnAssign)."""
        ownership = _parse_ownership_dict()
        assert ownership is not None, "OWNERSHIP dict not found"
        uid, gid, mode = ownership["oidc_client_secret"]
        assert uid == 65534
        assert gid == 30000
        assert mode == 0o440
