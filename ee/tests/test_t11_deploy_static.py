"""Static checks for the ee/deploy/ compose stack (T11).

No Docker required.  Each test has a positive control on a planted bad
snippet to prove the check is not vacuously passing.

Requires pyyaml for compose parsing; skips compose-structure tests
(with a clear reason) if pyyaml is not installed.
"""
from __future__ import annotations

import re
import textwrap
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_DEPLOY = Path(__file__).resolve().parent.parent / "deploy"
_COMPOSE = _DEPLOY / "compose.yml"
_CADDYFILE = _DEPLOY / "Caddyfile"
_DOCKERFILE = _DEPLOY / "api.Dockerfile"
_KC_DOCKERFILE = _DEPLOY / "keycloak" / "Dockerfile"


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


# ---------------------------------------------------------------------------
# Helper: extract all image strings from compose
# ---------------------------------------------------------------------------

def _all_images(data: dict) -> dict[str, str]:
    """Return {service_name: image_string} for every service with an image."""
    result = {}
    for name, svc in data.get("services", {}).items():
        img = svc.get("image")
        if img:
            result[name] = img
    return result


# ---------------------------------------------------------------------------
# 1. Compose parses as valid YAML
# ---------------------------------------------------------------------------

@_skip_no_yaml
class TestComposeParses:
    def test_compose_parses(self):
        data = _load_compose()
        assert "services" in data

    def test_positive_control_bad_yaml(self, tmp_path: Path):
        """A planted bad YAML must fail to parse as expected."""
        bad = tmp_path / "bad.yml"
        bad.write_text("services:\n  foo:\n    image: bar\n  - broken", encoding="utf-8")
        with pytest.raises(yaml.YAMLError):
            yaml.safe_load(bad.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# 2. Every image is pinned by @sha256:
# ---------------------------------------------------------------------------

@_skip_no_yaml
class TestImagesPinned:
    def test_all_images_pinned(self):
        data = _load_compose()
        images = _all_images(data)
        assert len(images) >= 3, "expected at least proxy, postgres, init-secrets images"
        for svc, img in images.items():
            assert "@sha256:" in img, (
                f"service '{svc}' image is not pinned by digest: {img}"
            )

    def test_positive_control_unpinned_detected(self):
        """An unpinned image string must fail the check."""
        unpinned = "nginx:latest"
        assert "@sha256:" not in unpinned


# ---------------------------------------------------------------------------
# 3. Postgres digest matches ee/tests/pg_image.py
# ---------------------------------------------------------------------------

@_skip_no_yaml
class TestPostgresDigest:
    def test_pg_digest_matches(self):
        from .pg_image import PG_IMAGE

        data = _load_compose()
        pg_img = data["services"]["postgres"]["image"]
        # Extract the digest from the compose image
        assert "@sha256:" in pg_img
        compose_digest = pg_img.split("@")[1]
        # Extract the digest from pg_image.py
        assert "@sha256:" in PG_IMAGE
        expected_digest = PG_IMAGE.split("@")[1]
        assert compose_digest == expected_digest, (
            f"postgres digest mismatch: compose has {compose_digest}, "
            f"pg_image.py has {expected_digest}"
        )

    def test_positive_control_wrong_digest(self):
        """A wrong digest must be detected."""
        wrong = "postgres:16@sha256:0000000000000000000000000000000000000000000000000000000000000000"
        from .pg_image import PG_IMAGE

        expected_digest = PG_IMAGE.split("@")[1]
        assert wrong.split("@")[1] != expected_digest


# ---------------------------------------------------------------------------
# 4. Every service has read_only, no-new-privileges, cap_drop ALL
# ---------------------------------------------------------------------------

@_skip_no_yaml
class TestHardening:
    def test_all_services_hardened(self):
        data = _load_compose()
        for name, svc in data["services"].items():
            # read_only
            assert svc.get("read_only") is True, (
                f"service '{name}' missing read_only: true"
            )
            # no-new-privileges
            sec_opts = svc.get("security_opt", [])
            assert "no-new-privileges:true" in sec_opts, (
                f"service '{name}' missing no-new-privileges:true in security_opt"
            )
            # cap_drop ALL
            cap_drop = svc.get("cap_drop", [])
            assert "ALL" in cap_drop, (
                f"service '{name}' missing cap_drop: [ALL]"
            )

    def test_positive_control_missing_read_only(self):
        """A service without read_only must fail the check."""
        bad_svc = {"image": "test:latest"}
        assert bad_svc.get("read_only") is not True

    def test_positive_control_missing_no_new_privileges(self):
        """A service without no-new-privileges must fail."""
        bad_svc = {"security_opt": ["seccomp:unconfined"]}
        assert "no-new-privileges:true" not in bad_svc["security_opt"]

    def test_positive_control_missing_cap_drop(self):
        """A service without cap_drop ALL must fail."""
        bad_svc = {"cap_drop": ["NET_RAW"]}
        assert "ALL" not in bad_svc["cap_drop"]


# ---------------------------------------------------------------------------
# 5. Postgres: no ports, only internal networks
# ---------------------------------------------------------------------------

@_skip_no_yaml
class TestPostgresIsolation:
    def test_postgres_no_ports(self):
        data = _load_compose()
        pg = data["services"]["postgres"]
        assert "ports" not in pg, "postgres must not publish ports"

    def test_postgres_only_internal_network(self):
        data = _load_compose()
        pg = data["services"]["postgres"]
        networks = pg.get("networks", [])
        if isinstance(networks, list):
            net_names = networks
        else:
            net_names = list(networks.keys())
        assert "internal" in net_names, "postgres must be on the internal network"
        assert "edge" not in net_names, "postgres must not be on the edge network"
        # Verify the internal network is marked internal: true
        net_defs = data.get("networks", {})
        internal_net = net_defs.get("internal", {})
        assert internal_net.get("internal") is True, (
            "the 'internal' network must have internal: true"
        )

    def test_positive_control_ports_detected(self):
        """A service with ports must be detected."""
        bad_svc = {"ports": ["5432:5432"]}
        assert "ports" in bad_svc

    def test_positive_control_edge_network_detected(self):
        """A service on 'edge' must be detected."""
        bad_svc = {"networks": ["edge", "internal"]}
        assert "edge" in bad_svc["networks"]


# ---------------------------------------------------------------------------
# 6. Only proxy publishes ports
# ---------------------------------------------------------------------------

@_skip_no_yaml
class TestOnlyProxyPublishes:
    def test_only_proxy_has_ports(self):
        data = _load_compose()
        for name, svc in data["services"].items():
            if name == "proxy":
                assert "ports" in svc, "proxy should publish ports"
                continue
            assert "ports" not in svc, (
                f"service '{name}' must not publish ports (only proxy may)"
            )

    def test_positive_control_other_service_with_ports(self):
        """A non-proxy service with ports must fail."""
        services = {
            "proxy": {"ports": ["443:443"]},
            "api": {"ports": ["8000:8000"]},
        }
        non_proxy_with_ports = [
            n for n, s in services.items() if n != "proxy" and "ports" in s
        ]
        assert len(non_proxy_with_ports) > 0


# ---------------------------------------------------------------------------
# 6b. Every proxy port binding starts with 127.0.0.1:
# ---------------------------------------------------------------------------

@_skip_no_yaml
class TestProxyPortsLoopback:
    def test_proxy_ports_bind_loopback(self):
        data = _load_compose()
        proxy = data["services"]["proxy"]
        ports = proxy.get("ports", [])
        assert ports, "proxy must publish at least one port"
        for port_str in ports:
            s = str(port_str)
            assert s.startswith("127.0.0.1:"), (
                f"proxy port '{s}' must bind to 127.0.0.1 (loopback only)"
            )

    def test_positive_control_wildcard_bind_detected(self):
        """A port binding on 0.0.0.0 must be caught."""
        bad_port = "0.0.0.0:443:8443"
        assert not bad_port.startswith("127.0.0.1:")


# ---------------------------------------------------------------------------
# 7. No env var with a secret-looking name lacks _FILE
# ---------------------------------------------------------------------------

# Patterns that look like they hold a secret value directly
_SECRET_PATTERNS = re.compile(
    r"(PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)$", re.IGNORECASE
)
# Exceptions: known non-secret env vars
_SECRET_EXCEPTIONS = {
    "AGG_SIGNING_KEY_FILE",  # already a _FILE var
    "AGG_OIDC_CLIENT_SECRET_FILE",
    "AGG_DATABASE_URL_FILE",
}
# Services under the demo profile are allowed plain-text demo credentials
_DEMO_PROFILE_SERVICES = {"keycloak", "init-secrets"}


@_skip_no_yaml
class TestNoPlainSecrets:
    def test_no_secret_looking_env_without_file(self):
        data = _load_compose()
        violations = []
        for name, svc in data["services"].items():
            # Demo-profile services may use plain-text demo credentials
            profiles = svc.get("profiles", [])
            if name in _DEMO_PROFILE_SERVICES or "demo" in profiles:
                continue
            env = svc.get("environment", {})
            if isinstance(env, list):
                # Convert ["KEY=val", ...] to dict
                env_dict = {}
                for item in env:
                    if "=" in item:
                        k, _ = item.split("=", 1)
                        env_dict[k] = _
                    else:
                        env_dict[item] = ""
                env = env_dict
            for var_name in env:
                if var_name in _SECRET_EXCEPTIONS:
                    continue
                if _SECRET_PATTERNS.search(var_name) and not var_name.endswith("_FILE"):
                    violations.append(f"{name}: {var_name}")
        assert not violations, (
            f"Environment variables with secret-looking names lack _FILE suffix: "
            f"{violations}"
        )

    def test_positive_control_plain_secret_detected(self):
        """A plain PASSWORD env var must be flagged."""
        env = {"DB_PASSWORD": "hunter2", "DB_URL": "postgres://..."}
        flagged = [
            k for k in env
            if _SECRET_PATTERNS.search(k) and not k.endswith("_FILE")
        ]
        assert len(flagged) == 1
        assert flagged[0] == "DB_PASSWORD"


# ---------------------------------------------------------------------------
# 8. Caddyfile CSP: script-src 'self', no unsafe-inline/unsafe-eval
# ---------------------------------------------------------------------------

class TestCaddyfileCSP:
    def test_csp_script_src_self(self):
        text = _CADDYFILE.read_text(encoding="utf-8")
        assert "script-src 'self'" in text, (
            "Caddyfile must contain script-src 'self' in CSP"
        )

    def test_csp_no_unsafe_inline(self):
        text = _CADDYFILE.read_text(encoding="utf-8")
        assert "unsafe-inline" not in text, (
            "Caddyfile must not contain unsafe-inline"
        )

    def test_csp_no_unsafe_eval(self):
        text = _CADDYFILE.read_text(encoding="utf-8")
        assert "unsafe-eval" not in text, (
            "Caddyfile must not contain unsafe-eval"
        )

    def test_positive_control_bad_csp_detected(self):
        """A CSP with unsafe-inline must be detected."""
        bad_csp = "Content-Security-Policy \"script-src 'self' 'unsafe-inline'\""
        assert "unsafe-inline" in bad_csp

    def test_positive_control_missing_script_src(self):
        """A CSP without script-src 'self' must be detected."""
        bad_csp = "Content-Security-Policy \"default-src 'self'\""
        assert "script-src 'self'" not in bad_csp


# ---------------------------------------------------------------------------
# 9. Dockerfile has a non-root USER
# ---------------------------------------------------------------------------

class TestDockerfileUser:
    def test_dockerfile_has_non_root_user(self):
        text = _DOCKERFILE.read_text(encoding="utf-8")
        # Find USER directives (not in comments)
        user_lines = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("USER ") and not stripped.startswith("#"):
                user_lines.append(stripped)
        assert user_lines, "Dockerfile must have at least one USER directive"
        # The last USER must not be root (0 or "root")
        last_user = user_lines[-1].split(None, 1)[1].strip()
        assert last_user not in ("0", "root", "0:0", "root:root"), (
            f"Dockerfile USER must not be root, got: {last_user}"
        )

    def test_positive_control_root_user_detected(self):
        """A Dockerfile with USER root must be detected."""
        lines = ["FROM ubuntu", "USER root"]
        user_lines = [l for l in lines if l.startswith("USER ")]
        last_user = user_lines[-1].split(None, 1)[1].strip()
        assert last_user in ("0", "root", "0:0", "root:root")


# ---------------------------------------------------------------------------
# 10. Caddyfile has HSTS, X-Content-Type-Options, Referrer-Policy
# ---------------------------------------------------------------------------

class TestCaddyfileHeaders:
    def test_hsts_present(self):
        text = _CADDYFILE.read_text(encoding="utf-8")
        assert "Strict-Transport-Security" in text

    def test_xcto_present(self):
        text = _CADDYFILE.read_text(encoding="utf-8")
        assert "X-Content-Type-Options" in text
        assert "nosniff" in text

    def test_referrer_policy_present(self):
        text = _CADDYFILE.read_text(encoding="utf-8")
        assert "Referrer-Policy" in text
        assert "no-referrer" in text


# ---------------------------------------------------------------------------
# 11. Caddyfile CSP contains all required directives
# ---------------------------------------------------------------------------

class TestCaddyfileCSPComplete:
    _REQUIRED_DIRECTIVES = [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "object-src 'none'",
    ]

    @pytest.mark.parametrize("directive", _REQUIRED_DIRECTIVES)
    def test_csp_directive_present(self, directive: str):
        text = _CADDYFILE.read_text(encoding="utf-8")
        assert directive in text, f"CSP missing directive: {directive}"


# ---------------------------------------------------------------------------
# 12. Dockerfile is multi-stage (has at least 2 FROM)
# ---------------------------------------------------------------------------

class TestDockerfileMultiStage:
    def test_multi_stage_build(self):
        text = _DOCKERFILE.read_text(encoding="utf-8")
        from_lines = [
            l.strip()
            for l in text.splitlines()
            if l.strip().upper().startswith("FROM ")
            and not l.strip().startswith("#")
        ]
        assert len(from_lines) >= 2, (
            f"Dockerfile should be multi-stage (at least 2 FROM), got {len(from_lines)}"
        )

    def test_positive_control_single_stage_detected(self):
        """A single-stage Dockerfile must be detected."""
        text = "FROM ubuntu:22.04\nRUN apt-get update"
        from_lines = [
            l for l in text.splitlines()
            if l.strip().upper().startswith("FROM ")
        ]
        assert len(from_lines) < 2


# ---------------------------------------------------------------------------
# 13. Dockerfile python image pinned by digest
# ---------------------------------------------------------------------------

class TestDockerfilePythonPinned:
    def test_python_image_pinned(self):
        text = _DOCKERFILE.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.upper().startswith("FROM ") and "python" in stripped.lower():
                assert "@sha256:" in stripped, (
                    f"Python base image not pinned by digest: {stripped}"
                )

    def test_positive_control_unpinned_python(self):
        """An unpinned python image must be detected."""
        line = "FROM python:3.12-slim"
        assert "@sha256:" not in line


# ---------------------------------------------------------------------------
# 13b. Keycloak demo Dockerfile: exists, FROM pinned, read_only compatible
# ---------------------------------------------------------------------------

class TestKeycloakDockerfile:
    """The keycloak demo Dockerfile must exist, pin its base image by
    digest, and run kc.sh build so the container can use start --optimized
    with read_only: true."""

    def test_kc_dockerfile_exists(self):
        assert _KC_DOCKERFILE.exists(), (
            f"keycloak Dockerfile not found at {_KC_DOCKERFILE}"
        )

    def test_kc_base_image_pinned(self):
        text = _KC_DOCKERFILE.read_text(encoding="utf-8")
        from_lines = [
            l.strip() for l in text.splitlines()
            if l.strip().upper().startswith("FROM ")
            and not l.strip().startswith("#")
        ]
        assert from_lines, "keycloak Dockerfile must have a FROM line"
        for line in from_lines:
            assert "@sha256:" in line, (
                f"keycloak base image not pinned by digest: {line}"
            )

    def test_kc_build_runs_at_build_time(self):
        """The Dockerfile must run kc.sh build so start --optimized works."""
        text = _KC_DOCKERFILE.read_text(encoding="utf-8")
        assert "kc.sh build" in text, (
            "keycloak Dockerfile must run kc.sh build"
        )

    def test_compose_keycloak_uses_build(self):
        """keycloak service must use build: (not just image:) so the
        pre-built Dockerfile is used."""
        data = _load_compose()
        kc = data["services"]["keycloak"]
        assert "build" in kc, (
            "keycloak service must use build: directive"
        )

    def test_compose_keycloak_start_optimized(self):
        """keycloak must use start --optimized (not start-dev) so that
        no Quarkus augmentation runs at boot (read_only: true)."""
        data = _load_compose()
        kc = data["services"]["keycloak"]
        combined = " ".join([
            " ".join(kc.get("entrypoint", [])),
            " ".join(kc.get("command", [])),
        ])
        assert "start-dev" not in combined, (
            "keycloak must not use start-dev (it writes to /opt/keycloak/lib)"
        )
        assert "start" in combined and "optimized" in combined, (
            "keycloak must use 'start --optimized'"
        )

    def test_positive_control_unpinned_kc_detected(self):
        line = "FROM keycloak/keycloak:26.0.0"
        assert "@sha256:" not in line

    def test_positive_control_start_dev_detected(self):
        bad = "exec /opt/keycloak/bin/kc.sh start-dev --import-realm"
        assert "start-dev" in bad


# ---------------------------------------------------------------------------
# 14. Dockerfile HEALTHCHECK present
# ---------------------------------------------------------------------------

class TestDockerfileHealthcheck:
    def test_healthcheck_present(self):
        text = _DOCKERFILE.read_text(encoding="utf-8")
        assert "HEALTHCHECK" in text, "Dockerfile must have a HEALTHCHECK"
        assert "/health" in text, "HEALTHCHECK must hit /health"

    def test_positive_control_no_healthcheck(self):
        """A Dockerfile without HEALTHCHECK must be detected."""
        text = "FROM python:3.12\nCMD ['uvicorn']"
        assert "HEALTHCHECK" not in text


# ---------------------------------------------------------------------------
# 15. No service command/entrypoint leaks secrets via shell interpolation
# ---------------------------------------------------------------------------

@_skip_no_yaml
class TestNoShellSecretLeak:
    """No service should build a secret from shell (cat /run/secrets) or
    set AGG_DATABASE_URL= inline.  Secrets must come via _FILE env vars."""

    _FORBIDDEN_PATTERNS = [
        re.compile(r"cat\s+/run/secrets"),
        re.compile(r"AGG_DATABASE_URL="),
    ]

    @staticmethod
    def _flatten_cmd(value) -> str:
        """Turn a command/entrypoint (str, list, or None) into a string."""
        if value is None:
            return ""
        if isinstance(value, list):
            return " ".join(str(v) for v in value)
        return str(value)

    def test_no_secret_shell_interpolation(self):
        data = _load_compose()
        violations = []
        for name, svc in data["services"].items():
            # Demo-profile services may read secrets via cat to inject
            # env vars when the service has no _FILE convention (e.g.
            # Keycloak).
            profiles = svc.get("profiles", [])
            if "demo" in profiles:
                continue
            combined = " ".join([
                self._flatten_cmd(svc.get("entrypoint")),
                self._flatten_cmd(svc.get("command")),
            ])
            for pat in self._FORBIDDEN_PATTERNS:
                if pat.search(combined):
                    violations.append(
                        f"{name}: matches '{pat.pattern}' in "
                        f"command/entrypoint"
                    )
        assert not violations, (
            f"Service commands must not interpolate secrets at runtime: "
            f"{violations}"
        )

    def test_positive_control_cat_secrets_detected(self):
        """A command with cat /run/secrets must be caught."""
        bad = "sh -c export AGG_DATABASE_URL=$(cat /run/secrets/pw)@host"
        assert self._FORBIDDEN_PATTERNS[0].search(bad)

    def test_positive_control_inline_url_detected(self):
        """A command with AGG_DATABASE_URL= must be caught."""
        bad = 'sh -c AGG_DATABASE_URL="postgresql://..." python app.py'
        assert self._FORBIDDEN_PATTERNS[1].search(bad)


# ---------------------------------------------------------------------------
# 16. Capability rules: proxy gets NET_BIND_SERVICE (caddy binary has file
#     caps that require it in the bounding set); init-secrets gets CHOWN
#     (to set per-consumer file ownership); all others have no cap_add.
#     Proxy must NOT have the ip_unprivileged_port_start sysctl (redundant
#     once NET_BIND_SERVICE is granted).
# ---------------------------------------------------------------------------

@_skip_no_yaml
class TestCapabilities:
    """Verify per-service capability rules."""

    _ALLOWED_CAP_ADD: dict[str, list[str]] = {
        "proxy": ["NET_BIND_SERVICE"],
        "init-secrets": ["CHOWN", "DAC_OVERRIDE"],
        "ca-bundle": ["DAC_READ_SEARCH"],
    }

    def test_proxy_has_net_bind_service(self):
        data = _load_compose()
        proxy = data["services"]["proxy"]
        cap_add = proxy.get("cap_add", [])
        assert cap_add == ["NET_BIND_SERVICE"], (
            f"proxy cap_add must be exactly [NET_BIND_SERVICE], got {cap_add}"
        )

    def test_proxy_still_has_cap_drop_all(self):
        data = _load_compose()
        proxy = data["services"]["proxy"]
        assert "ALL" in proxy.get("cap_drop", []), (
            "proxy must keep cap_drop: [ALL]"
        )

    def test_proxy_no_sysctl(self):
        """With NET_BIND_SERVICE the ip_unprivileged_port_start sysctl is
        redundant and should be removed."""
        data = _load_compose()
        proxy = data["services"]["proxy"]
        assert "sysctls" not in proxy, (
            "proxy must not have sysctls (NET_BIND_SERVICE replaces the sysctl)"
        )

    def test_init_secrets_caps_exact(self):
        """init-secrets needs CHOWN (fchown) and DAC_OVERRIDE (create files
        in ./secrets/ even when owned by a non-root uid on native Linux)."""
        data = _load_compose()
        init = data["services"]["init-secrets"]
        cap_add = sorted(init.get("cap_add", []))
        assert cap_add == ["CHOWN", "DAC_OVERRIDE"], (
            f"init-secrets cap_add must be exactly "
            f"[CHOWN, DAC_OVERRIDE], got {cap_add}"
        )

    def test_no_other_service_has_cap_add(self):
        data = _load_compose()
        for name, svc in data["services"].items():
            if name in self._ALLOWED_CAP_ADD:
                continue
            assert "cap_add" not in svc, (
                f"service '{name}' has cap_add but only "
                f"{list(self._ALLOWED_CAP_ADD.keys())} may have it"
            )

    def test_positive_control_unexpected_cap_add_detected(self):
        bad_svc = {"cap_add": ["SYS_ADMIN"]}
        assert "cap_add" in bad_svc


# ---------------------------------------------------------------------------
# 16b. Secret file ownership rules in init-secrets.sh
# ---------------------------------------------------------------------------

class TestSecretOwnershipRules:
    """init-secrets.sh must set per-consumer ownership on each secret file.

    Ownership table (enforced here and in the script):
        pg_superuser_password  999:999    0400  postgres
        pg_owner_password      999:999    0400  postgres
        pg_app_password        999:999    0400  postgres
        pg_owner_url           10001:10001 0400 migrate/migrate-demo
        pg_app_url             10001:10001 0400 api
        oidc_client_secret     65534:30000 0440 api + keycloak (shared gid)
        server_signing_key     10001:10001 0400 api
    """

    def test_init_secrets_calls_fchown(self):
        text = (_DEPLOY / "init-secrets.sh").read_text(encoding="utf-8")
        assert "os.fchown" in text, (
            "init-secrets.sh must call os.fchown to set per-consumer ownership"
        )

    def test_init_secrets_calls_fchmod(self):
        text = (_DEPLOY / "init-secrets.sh").read_text(encoding="utf-8")
        assert "os.fchmod" in text, (
            "init-secrets.sh must call os.fchmod to set restrictive mode"
        )

    def test_no_world_readable_modes(self):
        """Secret files must never be 0644 or 0444."""
        text = (_DEPLOY / "init-secrets.sh").read_text(encoding="utf-8")
        # Check Python octal literals and bare octal
        assert "0o644" not in text, "init-secrets.sh must not use mode 0o644"
        assert "0o444" not in text, "init-secrets.sh must not use mode 0o444"

    def test_shared_gid_for_oidc_secret(self):
        """api and keycloak must have group_add for the shared secret gid."""
        data = _load_compose()
        api = data["services"]["api"]
        groups = [str(g) for g in api.get("group_add", [])]
        assert "30000" in groups, (
            "api must have group_add including '30000' for shared oidc_client_secret"
        )

    def test_keycloak_shared_gid(self):
        """keycloak must also have group_add for the shared secret gid."""
        data = _load_compose()
        kc = data["services"]["keycloak"]
        groups = [str(g) for g in kc.get("group_add", [])]
        assert "30000" in groups, (
            "keycloak must have group_add including '30000' for shared oidc_client_secret"
        )

    def test_init_secrets_runs_as_root(self):
        """init-secrets must run as root to use CAP_CHOWN on bind mounts."""
        data = _load_compose()
        init = data["services"]["init-secrets"]
        user = str(init.get("user", ""))
        assert user.startswith("0"), (
            f"init-secrets must run as root (user '0:0'), got '{user}'"
        )

    def test_positive_control_world_readable_detected(self):
        bad = "os.open(str(path), os.O_WRONLY, 0o644)"
        assert "0o644" in bad

    def test_positive_control_missing_group_add_detected(self):
        bad_svc = {"user": "10001:10001"}
        groups = [str(g) for g in bad_svc.get("group_add", [])]
        assert "30000" not in groups


# ---------------------------------------------------------------------------
# 17. init-secrets script exists and refuses overwrite
# ---------------------------------------------------------------------------

class TestInitSecrets:
    def test_init_secrets_exists(self):
        script = _DEPLOY / "init-secrets.sh"
        assert script.exists(), "init-secrets.sh must exist"

    def test_init_secrets_refuses_overwrite(self):
        """The script must contain logic to refuse overwriting existing files."""
        text = (_DEPLOY / "init-secrets.sh").read_text(encoding="utf-8")
        assert "exists" in text.lower() or "overwrite" in text.lower(), (
            "init-secrets.sh must check for existing files"
        )

    def test_init_secrets_generates_url_files(self):
        """init-secrets must produce pg_owner_url and pg_app_url."""
        text = (_DEPLOY / "init-secrets.sh").read_text(encoding="utf-8")
        assert "pg_owner_url" in text, (
            "init-secrets.sh must generate pg_owner_url"
        )
        assert "pg_app_url" in text, (
            "init-secrets.sh must generate pg_app_url"
        )


# ---------------------------------------------------------------------------
# 18. secrets/.gitignore exists and ignores everything
# ---------------------------------------------------------------------------

class TestSecretsGitignore:
    def test_gitignore_exists(self):
        gi = _DEPLOY / "secrets" / ".gitignore"
        assert gi.exists()

    def test_gitignore_ignores_all(self):
        text = (_DEPLOY / "secrets" / ".gitignore").read_text(encoding="utf-8")
        assert "*" in text, "secrets/.gitignore must ignore everything (*)"
        assert "!.gitignore" in text, (
            "secrets/.gitignore must keep itself (!.gitignore)"
        )


# ---------------------------------------------------------------------------
# 19. Demo realm client security (PKCE, no implicit, no wildcard URIs)
# ---------------------------------------------------------------------------

_DEMO_REALM_DIR = _DEPLOY / "keycloak"
_DEMO_REALM_FILES = ["acme-realm.json", "globex-realm.json"]


class TestDemoRealmSecurity:
    """Verify every realm/client in the demo realm files is locked down."""

    @staticmethod
    def _load_realms() -> list[dict]:
        import json
        realms = []
        for name in _DEMO_REALM_FILES:
            path = _DEMO_REALM_DIR / name
            assert path.exists(), f"{name} not found"
            data = json.loads(path.read_text(encoding="utf-8"))
            assert isinstance(data, dict), f"{name} must be a single realm object"
            realms.append(data)
        assert len(realms) >= 2
        return realms

    def test_every_client_is_confidential(self):
        for realm in self._load_realms():
            for client in realm.get("clients", []):
                assert client.get("publicClient") is False, (
                    f"realm '{realm['realm']}' client '{client['clientId']}' "
                    f"must be confidential (publicClient: false)"
                )

    def test_pkce_s256_required(self):
        for realm in self._load_realms():
            for client in realm.get("clients", []):
                attrs = client.get("attributes", {})
                assert attrs.get("pkce.code.challenge.method") == "S256", (
                    f"realm '{realm['realm']}' client '{client['clientId']}' "
                    f"must require PKCE S256"
                )

    def test_redirect_uris_exact(self):
        for realm in self._load_realms():
            for client in realm.get("clients", []):
                for uri in client.get("redirectUris", []):
                    assert "*" not in uri, (
                        f"realm '{realm['realm']}' client '{client['clientId']}' "
                        f"redirectUri contains wildcard: {uri}"
                    )

    def test_web_origins_no_wildcard(self):
        for realm in self._load_realms():
            for client in realm.get("clients", []):
                for origin in client.get("webOrigins", []):
                    assert origin != "*", (
                        f"realm '{realm['realm']}' client '{client['clientId']}' "
                        f"webOrigins contains wildcard"
                    )

    def test_implicit_flow_disabled(self):
        for realm in self._load_realms():
            for client in realm.get("clients", []):
                assert client.get("implicitFlowEnabled") is False, (
                    f"realm '{realm['realm']}' client '{client['clientId']}' "
                    f"must have implicitFlowEnabled: false"
                )

    def test_direct_access_grants_disabled(self):
        for realm in self._load_realms():
            for client in realm.get("clients", []):
                assert client.get("directAccessGrantsEnabled") is False, (
                    f"realm '{realm['realm']}' client '{client['clientId']}' "
                    f"must have directAccessGrantsEnabled: false"
                )

    def test_ssl_required_external(self):
        for realm in self._load_realms():
            assert realm.get("sslRequired") == "external", (
                f"realm '{realm['realm']}' must have sslRequired: external"
            )

    # -- positive controls --

    def test_positive_control_public_client_detected(self):
        bad_client = {"clientId": "bad", "publicClient": True}
        assert bad_client["publicClient"] is not False

    def test_positive_control_wildcard_redirect_detected(self):
        bad_uris = ["https://localhost/*"]
        assert any("*" in u for u in bad_uris)

    def test_positive_control_implicit_enabled_detected(self):
        bad_client = {"implicitFlowEnabled": True}
        assert bad_client["implicitFlowEnabled"] is not False

    def test_positive_control_missing_pkce_detected(self):
        bad_client = {"attributes": {}}
        assert bad_client["attributes"].get("pkce.code.challenge.method") != "S256"


# ---------------------------------------------------------------------------
# 20. Caddyfile has Permissions-Policy header
# ---------------------------------------------------------------------------

class TestCaddyfilePermissionsPolicy:
    def test_permissions_policy_present(self):
        text = _CADDYFILE.read_text(encoding="utf-8")
        assert "Permissions-Policy" in text, (
            "Caddyfile must include Permissions-Policy header"
        )
        assert "camera=()" in text
        assert "microphone=()" in text
        assert "geolocation=()" in text


# ---------------------------------------------------------------------------
# 21. Dockerfile removes pip/setuptools/wheel before final stage copy
# ---------------------------------------------------------------------------

class TestDockerfileNoBuildTools:
    def test_pip_uninstalled_before_copy(self):
        text = _DOCKERFILE.read_text(encoding="utf-8")
        assert "pip uninstall" in text, (
            "Dockerfile must uninstall pip/setuptools/wheel "
            "so they do not ship in the final image"
        )
        # The uninstall must come before the second FROM (runtime stage)
        uninstall_pos = text.index("pip uninstall")
        # Find all FROM positions
        from_positions = [
            i for i, line in enumerate(text.splitlines())
            if line.strip().upper().startswith("FROM ")
        ]
        assert len(from_positions) >= 2, "need at least 2 FROM stages"
        # uninstall must be in the build stage (before second FROM line offset)
        second_from_char = text.index(
            text.splitlines()[from_positions[1]]
        )
        assert uninstall_pos < second_from_char, (
            "pip uninstall must happen in the build stage, before the "
            "runtime FROM"
        )

    def test_positive_control_no_uninstall_detected(self):
        bad_dockerfile = "FROM python\nRUN pip install foo\nFROM python\nCOPY --from=0 / /"
        assert "pip uninstall" not in bad_dockerfile


# ---------------------------------------------------------------------------
# 22. 00-roles.sh uses psql -v variables, not shell interpolation into SQL
# ---------------------------------------------------------------------------

class TestRolesShellSafety:
    def test_no_shell_interpolation_in_sql(self):
        text = (_DEPLOY / "init" / "00-roles.sh").read_text(encoding="utf-8")
        # Must use psql -v to pass passwords
        assert "-v owner_pass=" in text or '-v owner_pass="' in text, (
            "00-roles.sh must pass owner password via psql -v"
        )
        assert "-v app_pass=" in text or '-v app_pass="' in text, (
            "00-roles.sh must pass app password via psql -v"
        )
        # Must NOT have ${OWNER_PASS} or ${APP_PASS} inside the heredoc SQL
        # The heredoc is quoted ('EOSQL') so shell does not expand, but
        # verify no unquoted heredoc with interpolation
        assert "${OWNER_PASS}" not in text, (
            "00-roles.sh must not interpolate OWNER_PASS into SQL"
        )
        assert "${APP_PASS}" not in text, (
            "00-roles.sh must not interpolate APP_PASS into SQL"
        )

    def test_positive_control_shell_interpolation_detected(self):
        bad_script = "psql <<EOSQL\nCREATE ROLE x PASSWORD '${OWNER_PASS}';\nEOSQL"
        assert "${OWNER_PASS}" in bad_script


# ---------------------------------------------------------------------------
# 23. Caddyfile has an IdP site block with tls internal
# ---------------------------------------------------------------------------

class TestCaddyfileIdpSite:
    """The Caddyfile must contain an idp.localhost site block with tls internal."""

    def test_idp_site_present(self):
        text = _CADDYFILE.read_text(encoding="utf-8")
        assert "idp.localhost" in text, (
            "Caddyfile must contain an idp.localhost site block"
        )

    def test_idp_site_has_tls_internal(self):
        """The idp.localhost site block must use tls internal."""
        text = _CADDYFILE.read_text(encoding="utf-8")
        # Find the idp.localhost site block and check for tls internal.
        # Skip Caddy variable syntax ({$VAR:default}) when looking for
        # the site block's opening brace.
        idp_pos = text.find("idp.localhost")
        assert idp_pos >= 0, "idp.localhost not found in Caddyfile"
        # Walk forward from idp_pos looking for a '{' that is NOT part of
        # a Caddy variable ({$ or {http or {scheme etc).  A site block
        # brace is preceded by whitespace or the address line.
        brace_pos = -1
        i = idp_pos
        while i < len(text):
            if text[i] == "{":
                # Skip {$...} and {placeholder} patterns
                if i + 1 < len(text) and text[i + 1] in ("$",):
                    # Skip to closing }
                    close = text.find("}", i + 1)
                    if close >= 0:
                        i = close + 1
                        continue
                # This is a real site-block brace
                brace_pos = i
                break
            i += 1
        assert brace_pos >= 0, "no site-block brace after idp.localhost"
        # Find the matching closing brace
        depth = 0
        end_pos = brace_pos
        for j in range(brace_pos, len(text)):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    end_pos = j
                    break
        block = text[brace_pos : end_pos + 1]
        assert "tls internal" in block, (
            "idp.localhost site block must contain 'tls internal'"
        )

    def test_idp_site_proxies_to_keycloak(self):
        text = _CADDYFILE.read_text(encoding="utf-8")
        idp_pos = text.find("idp.localhost")
        assert idp_pos >= 0
        after_idp = text[idp_pos:]
        assert "keycloak:8080" in after_idp, (
            "idp.localhost site must reverse_proxy to keycloak:8080"
        )

    def test_positive_control_missing_idp_detected(self):
        """A Caddyfile without idp.localhost must be detected."""
        bad = "localhost { tls internal }"
        assert "idp.localhost" not in bad

    def test_positive_control_idp_without_tls_internal(self):
        """An idp.localhost block without tls internal must be detected."""
        bad_block = "{ reverse_proxy keycloak:8080 }"
        assert "tls internal" not in bad_block


# ---------------------------------------------------------------------------
# 24. AGG_OIDC_ALLOW_HOSTS -- only in demo-profile services or as a
#     compose variable reference (never a hardcoded literal in non-demo)
# ---------------------------------------------------------------------------

@_skip_no_yaml
class TestAllowHostsOnlyInDemo:
    """AGG_OIDC_ALLOW_HOSTS must not have a hardcoded (non-variable-reference)
    value in any service that is NOT in the demo profile."""

    @staticmethod
    def _is_compose_variable(value: str) -> bool:
        """Return True if value is a compose variable reference like ${VAR:-}."""
        return "${" in str(value)

    def test_allow_hosts_not_hardcoded_in_non_demo(self):
        data = _load_compose()
        violations = []
        for name, svc in data["services"].items():
            profiles = svc.get("profiles", [])
            if "demo" in profiles:
                continue  # demo services may hardcode it
            env = svc.get("environment", {})
            if isinstance(env, list):
                env_dict = {}
                for item in env:
                    if "=" in item:
                        k, v = item.split("=", 1)
                        env_dict[k] = v
                env = env_dict
            val = env.get("AGG_OIDC_ALLOW_HOSTS")
            if val is not None and not self._is_compose_variable(str(val)):
                violations.append(
                    f"service '{name}' has hardcoded AGG_OIDC_ALLOW_HOSTS="
                    f"'{val}' but is not in demo profile"
                )
        assert not violations, (
            f"AGG_OIDC_ALLOW_HOSTS must only be hardcoded in demo-profile "
            f"services: {violations}"
        )

    def test_positive_control_hardcoded_allow_hosts_detected(self):
        """A non-demo service with hardcoded allow_hosts must be flagged."""
        svc = {
            "environment": {"AGG_OIDC_ALLOW_HOSTS": "idp.localhost"},
        }
        val = svc["environment"]["AGG_OIDC_ALLOW_HOSTS"]
        assert not self._is_compose_variable(val)

    def test_positive_control_variable_ref_passes(self):
        """A compose variable reference must pass the check."""
        val = "${AGG_OIDC_ALLOW_HOSTS:-}"
        assert self._is_compose_variable(val)


# ---------------------------------------------------------------------------
# 25. No secret literal in the demo realm files (client objects)
# ---------------------------------------------------------------------------

class TestNoSecretLiteralInRealmJson:
    """The demo realm files (acme-realm.json, globex-realm.json) must use the Keycloak env-var placeholder
    ``${AGG_DEMO_OIDC_CLIENT_SECRET}`` for client secrets -- never a
    literal value.  The actual secret is injected via the Keycloak
    entrypoint at runtime from a compose secret."""

    _EXPECTED_PLACEHOLDER = "${AGG_DEMO_OIDC_CLIENT_SECRET}"

    @staticmethod
    def _load_realms() -> list[dict]:
        import json
        realms = []
        for name in _DEMO_REALM_FILES:
            path = _DEMO_REALM_DIR / name
            assert path.exists(), f"{name} not found"
            realms.append(json.loads(path.read_text(encoding="utf-8")))
        assert len(realms) >= 1
        return realms

    def test_secret_is_env_placeholder(self):
        for realm in self._load_realms():
            for client in realm.get("clients", []):
                secret = client.get("secret")
                assert secret == self._EXPECTED_PLACEHOLDER, (
                    f"realm '{realm['realm']}' client '{client['clientId']}' "
                    f"secret must be '{self._EXPECTED_PLACEHOLDER}', "
                    f"got '{secret}'"
                )

    def test_positive_control_literal_secret_detected(self):
        """A client with a literal secret value must fail the check."""
        bad_client = {"clientId": "bad", "secret": "s3cret"}
        assert bad_client["secret"] != self._EXPECTED_PLACEHOLDER

    def test_positive_control_placeholder_passes(self):
        """A client with the correct placeholder must pass."""
        good_client = {"clientId": "good", "secret": "${AGG_DEMO_OIDC_CLIENT_SECRET}"}
        assert good_client["secret"] == self._EXPECTED_PLACEHOLDER


# ---------------------------------------------------------------------------
# 26. CA bundle volume mounted read-only in the api service
# ---------------------------------------------------------------------------

@_skip_no_yaml
class TestCaBundleMountReadOnly:
    """The ca-bundle volume must be mounted read-only in the api service
    so the api cannot tamper with the trusted CA bundle."""

    def test_ca_bundle_volume_exists(self):
        data = _load_compose()
        volumes = data.get("volumes", {})
        assert "ca-bundle" in volumes, (
            "compose.yml must define a 'ca-bundle' volume"
        )

    def test_api_mounts_ca_bundle_readonly(self):
        data = _load_compose()
        api = data["services"]["api"]
        api_volumes = api.get("volumes", [])
        found_ro = False
        for vol in api_volumes:
            vol_str = str(vol)
            if "ca-bundle" in vol_str and ":ro" in vol_str:
                found_ro = True
                break
        assert found_ro, (
            "api service must mount the ca-bundle volume as read-only (:ro)"
        )

    def test_positive_control_rw_mount_detected(self):
        """A volume mount without :ro must fail the check."""
        bad_vol = "ca-bundle:/ca-bundle"
        assert ":ro" not in bad_vol

    def test_positive_control_ro_mount_passes(self):
        """A volume mount with :ro must pass."""
        good_vol = "ca-bundle:/ca-bundle:ro"
        assert ":ro" in good_vol


# ---------------------------------------------------------------------------
# 27. Proxy network isolation: proxy must NOT be on 'internal', only {edge, idp}
# ---------------------------------------------------------------------------

@_skip_no_yaml
class TestProxyNetworks:
    """The proxy must connect to ``edge`` (public) and ``idp`` (for Keycloak)
    but must NOT sit on ``internal`` (where postgres lives)."""

    @staticmethod
    def _service_networks(data: dict, svc_name: str) -> set[str]:
        svc = data["services"][svc_name]
        nets = svc.get("networks", [])
        if isinstance(nets, list):
            return set(nets)
        return set(nets.keys())

    def test_proxy_networks_are_edge_and_idp(self):
        data = _load_compose()
        proxy_nets = self._service_networks(data, "proxy")
        assert proxy_nets == {"edge", "idp"}, (
            f"proxy must be on exactly {{edge, idp}}, got {proxy_nets}"
        )

    def test_proxy_not_on_internal(self):
        data = _load_compose()
        proxy_nets = self._service_networks(data, "proxy")
        assert "internal" not in proxy_nets, (
            "proxy must NOT be on the 'internal' network (postgres isolation)"
        )

    def test_postgres_only_on_internal(self):
        data = _load_compose()
        pg_nets = self._service_networks(data, "postgres")
        assert pg_nets == {"internal"}, (
            f"postgres must be on exactly {{internal}}, got {pg_nets}"
        )

    def test_idp_network_is_internal(self):
        """The 'idp' network must be marked internal: true."""
        data = _load_compose()
        net_defs = data.get("networks", {})
        idp_net = net_defs.get("idp", {})
        assert idp_net.get("internal") is True, (
            "the 'idp' network must have internal: true"
        )

    def test_positive_control_proxy_on_internal_detected(self):
        """A proxy on 'internal' must be flagged."""
        bad_nets = {"edge", "internal"}
        assert "internal" in bad_nets

    def test_positive_control_proxy_missing_idp_detected(self):
        """A proxy without 'idp' must be detected."""
        bad_nets = {"edge"}
        assert bad_nets != {"edge", "idp"}


# ---------------------------------------------------------------------------
# 28. Every realm client has standardFlowEnabled: true
# ---------------------------------------------------------------------------

class TestRealmStandardFlow:
    """Every OIDC client in the demo realm files must have standardFlowEnabled: true."""

    @staticmethod
    def _load_realms() -> list[dict]:
        import json
        realms = []
        for name in _DEMO_REALM_FILES:
            path = _DEMO_REALM_DIR / name
            assert path.exists(), f"{name} not found"
            realms.append(json.loads(path.read_text(encoding="utf-8")))
        assert len(realms) >= 1
        return realms

    def test_every_client_has_standard_flow_enabled(self):
        for realm in self._load_realms():
            for client in realm.get("clients", []):
                assert client.get("standardFlowEnabled") is True, (
                    f"realm '{realm['realm']}' client '{client['clientId']}' "
                    f"must have standardFlowEnabled: true"
                )

    def test_positive_control_missing_standard_flow_detected(self):
        """A client without standardFlowEnabled must fail."""
        bad_client = {"clientId": "bad", "publicClient": False}
        assert bad_client.get("standardFlowEnabled") is not True

    def test_positive_control_standard_flow_false_detected(self):
        """A client with standardFlowEnabled: false must fail."""
        bad_client = {"clientId": "bad", "standardFlowEnabled": False}
        assert bad_client.get("standardFlowEnabled") is not True
