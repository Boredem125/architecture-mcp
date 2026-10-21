"""T3 tests-first: Caddy CA volume and ca-bundle hardening.

Static analysis over ee/deploy/compose.yml and Caddyfile:
- Caddy exports only root.crt to its own volume (not the private key).
- ca-bundle mounts only the Caddy CA volume (caddy-data or a
  dedicated root-cert volume), not caddy-config or any secret.
- ca-bundle has NO DAC_READ_SEARCH capability after the fix.

RED tests xfail on M2T3Pending.  Guards verify file existence.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from .m2_pending import M2T3Pending, require_m2

_DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
_COMPOSE = _DEPLOY / "compose.yml"
_CADDYFILE = _DEPLOY / "Caddyfile"


# ===================================================================
# Guards (pass now)
# ===================================================================


def test_compose_file_exists():
    """Guard: ee/deploy/compose.yml exists."""
    assert _COMPOSE.is_file(), f"compose.yml not found at {_COMPOSE}"


def test_caddyfile_exists():
    """Guard: ee/deploy/Caddyfile exists."""
    assert _CADDYFILE.is_file(), f"Caddyfile not found at {_CADDYFILE}"


# ===================================================================
# RED: ca-bundle drops DAC_READ_SEARCH
# ===================================================================


def test_ca_bundle_no_dac_read_search():
    """ca-bundle service must not have DAC_READ_SEARCH capability."""
    text = _COMPOSE.read_text(encoding="utf-8")

    # Parse YAML to find the ca-bundle service
    try:
        import yaml
    except ImportError:
        # Fall back to text search
        _do_text_check(text)
        return

    data = yaml.safe_load(text)
    services = data.get("services", {})
    ca_bundle = services.get("ca-bundle")
    if ca_bundle is None:
        raise M2T3Pending("ca-bundle service not found in compose.yml")

    cap_add = ca_bundle.get("cap_add", [])
    if "DAC_READ_SEARCH" in cap_add:
        raise M2T3Pending(
            "ca-bundle still has DAC_READ_SEARCH; T3 should remove it"
        )
    # After the fix, ca-bundle should not need DAC_READ_SEARCH
    assert "DAC_READ_SEARCH" not in cap_add


def _do_text_check(text: str):
    """Fallback text-based check when PyYAML is not available."""
    # Find the ca-bundle service block and check for DAC_READ_SEARCH
    lines = text.split("\n")
    in_ca_bundle = False
    indent = 0
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith("ca-bundle:"):
            in_ca_bundle = True
            indent = len(line) - len(stripped)
            continue
        if in_ca_bundle:
            if stripped and not line[0].isspace():
                break  # left the service block
            cur_indent = len(line) - len(stripped)
            if cur_indent <= indent and stripped and not stripped.startswith("#"):
                break
            if "DAC_READ_SEARCH" in line:
                raise M2T3Pending(
                    "ca-bundle still has DAC_READ_SEARCH in compose.yml"
                )


# ===================================================================
# RED: ca-bundle mounts only the root cert volume
# ===================================================================


def test_ca_bundle_mounts_only_root_cert_volume():
    """ca-bundle should mount a volume with only root.crt, not caddy-data."""
    text = _COMPOSE.read_text(encoding="utf-8")

    try:
        import yaml
    except ImportError:
        pytest.skip("PyYAML needed for structured compose parse")
        return

    data = yaml.safe_load(text)
    services = data.get("services", {})
    ca_bundle = services.get("ca-bundle")
    if ca_bundle is None:
        raise M2T3Pending("ca-bundle service not found")

    volumes = ca_bundle.get("volumes", [])
    vol_strs = [str(v) if isinstance(v, str) else str(v.get("source", ""))
                for v in volumes]

    # After T3: ca-bundle should NOT mount caddy-data (which holds the
    # private key).  It should mount a dedicated root-cert volume that
    # Caddy populates with only root.crt.
    mounts_caddy_data = any("caddy-data" in v for v in vol_strs)
    if mounts_caddy_data:
        raise M2T3Pending(
            "ca-bundle still mounts caddy-data (contains Caddy private key); "
            "T3 should change it to a dedicated root-cert-only volume"
        )


# ===================================================================
# RED: Caddy exports only root.crt to a dedicated volume
# ===================================================================


def test_caddy_exports_only_root_crt():
    """Caddy proxy service should export root.crt to a volume that
    does not contain the private key."""
    text = _COMPOSE.read_text(encoding="utf-8")

    try:
        import yaml
    except ImportError:
        pytest.skip("PyYAML needed for structured compose parse")
        return

    data = yaml.safe_load(text)
    services = data.get("services", {})
    proxy = services.get("proxy")
    if proxy is None:
        raise M2T3Pending("proxy service not found in compose.yml")

    volumes = proxy.get("volumes", [])
    vol_strs = [str(v) for v in volumes]

    # After T3, the proxy should have a volume mount that makes only
    # root.crt available (e.g. a named volume or bind mount for the cert).
    # Check for a volume mapping that targets root.crt specifically.
    has_root_cert_export = any("root.crt" in v or "caddy-root-cert" in v
                               for v in vol_strs)
    if not has_root_cert_export:
        raise M2T3Pending(
            "Caddy proxy does not export root.crt to a dedicated volume"
        )
