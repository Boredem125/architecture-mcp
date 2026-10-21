"""T4 tests-first: slim api base image (static analysis over Dockerfile).

After T4:
- The final base is Chainguard Python pinned by ``@sha256:`` digest.
- A non-root USER directive exists.
- No shell in the final stage (no RUN in the final stage, no /bin/sh
  copied in).

These are static-only tests over ee/deploy/api.Dockerfile, so they
run in CI without Docker and add 0 to the ee skip count.

RED tests xfail on M2T4Pending.  Guards verify file existence.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from .m2_pending import M2T4Pending, require_m2

_DOCKERFILE = Path(__file__).resolve().parents[1] / "deploy" / "api.Dockerfile"


# ===================================================================
# Guards (pass now)
# ===================================================================


def test_dockerfile_exists():
    """Guard: ee/deploy/api.Dockerfile exists."""
    assert _DOCKERFILE.is_file(), f"api.Dockerfile not found at {_DOCKERFILE}"


def test_dockerfile_has_from():
    """Guard: Dockerfile has at least one FROM."""
    text = _DOCKERFILE.read_text(encoding="utf-8")
    assert "FROM " in text


# ===================================================================
# RED: final base is Chainguard Python pinned by digest
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T4Pending)
def test_final_base_is_chainguard():
    """The final FROM must reference cgr.dev/chainguard/python pinned by digest."""
    text = _DOCKERFILE.read_text(encoding="utf-8")

    # Find all FROM directives
    froms = re.findall(r"^FROM\s+(\S+)", text, re.MULTILINE)
    assert len(froms) >= 2, "Expected at least 2 stages (build + runtime)"

    final_base = froms[-1]

    if "chainguard" not in final_base.lower():
        raise M2T4Pending(
            f"Final base is not Chainguard: {final_base!r}; "
            "T4 should switch to cgr.dev/chainguard/python"
        )

    if "@sha256:" not in final_base:
        raise M2T4Pending(
            f"Final base is not pinned by digest: {final_base!r}"
        )

    assert "cgr.dev/chainguard/python" in final_base.lower() or \
           "chainguard" in final_base.lower()
    assert "@sha256:" in final_base


# ===================================================================
# RED: non-root USER
# ===================================================================


def test_nonroot_user():
    """Guard: the final stage has a USER directive that is not root (0)."""
    text = _DOCKERFILE.read_text(encoding="utf-8")

    # Split into stages
    stages = re.split(r"^FROM\s+", text, flags=re.MULTILINE)
    assert len(stages) >= 3, "Expected at least 2 stages"

    final_stage = stages[-1]

    # Find USER directives in the final stage
    users = re.findall(r"^USER\s+(.+)", final_stage, re.MULTILINE)
    assert users, "No USER directive in the final stage"

    last_user = users[-1].strip()
    assert last_user not in ("0", "root", "0:0", "root:root"), (
        f"Final stage USER is root: {last_user!r}"
    )


# ===================================================================
# RED: no shell in the final stage
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T4Pending)
def test_no_shell_in_final_stage():
    """No RUN instruction in the final stage, no /bin/sh copied."""
    text = _DOCKERFILE.read_text(encoding="utf-8")

    # Split into stages
    stages = re.split(r"^FROM\s+", text, flags=re.MULTILINE)
    if len(stages) < 3:
        raise M2T4Pending("Expected at least 2 stages")

    final_stage = stages[-1]

    # After T4 (Chainguard distroless), the final stage should not:
    # 1. Have RUN instructions (no shell to run them)
    # 2. Copy /bin/sh from the build stage
    runs = re.findall(r"^RUN\s+", final_stage, re.MULTILINE)
    if runs:
        raise M2T4Pending(
            f"Final stage has {len(runs)} RUN instruction(s); "
            "Chainguard distroless has no shell"
        )

    # Check for explicit shell copy
    if "/bin/sh" in final_stage or "/bin/bash" in final_stage:
        raise M2T4Pending("Final stage copies a shell binary")
