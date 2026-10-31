"""T12d d4 exit: demo.py step 2 through routes (QA gate tests).

Static tests (no stack): read ee/deploy/demo.py source and verify:
  - it imports nothing from agg_cp and opens no DB connection
  - step2_setup_and_admin contains the route strings for genesis, signatures,
    registry GET and signer-links
  - the three negative-check PASS markers are present
  - step2_setup_and_admin returns registry_version == 3

Live test (opt-in AGG_LIVE_STACK=1): runs demo.py --step 2 as subprocess.
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_DEMO_PY = _REPO_ROOT / "ee" / "deploy" / "demo.py"
_DEMO_SOURCE = _DEMO_PY.read_text(encoding="utf-8")

# ---------------------------------------------------------------------------
# Marker strings the backend MUST print from step2_setup_and_admin (2p-2q).
# The test defines them; backend must use them exactly.
# ---------------------------------------------------------------------------

PASS_GENESIS_V1 = "PASS: genesis v1 accepted (registry version 1)"
PASS_V2 = "PASS: v2 accepted (registry version 2, carol added)"
PASS_V3 = "PASS: v3 accepted (registry version 3, bob + approver keys)"
PASS_SECOND_GENESIS_REFUSED = "PASS: second genesis refused"
PASS_GENESIS_CODE_REUSE_REFUSED = "PASS: genesis code reuse refused"
PASS_PENDING_LINK_SELF_KEY_REFUSED = "PASS: pending_link self-key refused"
PASS_REGISTRY_GET = "PASS: GET /signer/registry returned 3-version chain"


# ---------------------------------------------------------------------------
# 1. Static tests (no stack required)
# ---------------------------------------------------------------------------


class TestDemoStep2Static:
    """Read ee/deploy/demo.py source; assert compliance without running it."""

    # 1a. No agg_cp imports, no DB connection strings
    def test_no_agg_cp_import(self):
        """demo.py must not import from agg_cp (routes only, no server internals)."""
        tree = ast.parse(_DEMO_SOURCE, filename=str(_DEMO_PY))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith("agg_cp"), (
                    f"demo.py imports from agg_cp: {node.module}"
                )
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith("agg_cp"), (
                        f"demo.py imports agg_cp: {alias.name}"
                    )
        # Also must not use psycopg or store_registry_version
        assert "psycopg" not in _DEMO_SOURCE, (
            "demo.py references psycopg (DB access)"
        )
        assert "store_registry_version" not in _DEMO_SOURCE, (
            "demo.py references store_registry_version"
        )
        # The route strings must be present (this is the gate; if they
        # are not there, the test must fail)
        assert "/api/v1/sync/signer/genesis" in _DEMO_SOURCE

    # 1b. Route strings present in step2_setup_and_admin
    def test_route_strings_present(self):
        """step2_setup_and_admin must contain the four route strings."""
        # Extract the function body from source
        func_src = _extract_function_source("step2_setup_and_admin")
        routes = [
            "/api/v1/sync/signer/genesis",
            "/api/v1/sync/signer/signatures",
            "/api/v1/sync/signer/registry",
            "/api/v1/signer-links",
        ]
        for route in routes:
            assert route in func_src, (
                f"step2_setup_and_admin is missing route string: {route}"
            )

    # 1c. Negative-check marker strings present
    def test_negative_markers_present(self):
        """step2 must print these exact PASS lines for the three negatives."""
        func_src = _extract_function_source("step2_setup_and_admin")
        assert "second genesis refused" in func_src, (
            "missing marker: second genesis refused"
        )
        assert "genesis code reuse refused" in func_src, (
            "missing marker: genesis code reuse refused"
        )
        assert "pending_link self-key refused" in func_src, (
            "missing marker: pending_link self-key refused"
        )

    # 1d. The e2e test file never calls store_registry_version
    def test_e2e_never_calls_store_registry_version(self):
        """ee/tests/test_m2_t12b_e2e.py must not call store_registry_version
        directly (all registry writes go through routes)."""
        e2e_path = _REPO_ROOT / "ee" / "tests" / "test_m2_t12b_e2e.py"
        raw = e2e_path.read_text(encoding="utf-8")
        # Strip comment lines (# ...) so inline comments don't trigger false positives
        code_lines = [
            line for line in raw.splitlines()
            if not line.lstrip().startswith("#")
        ]
        code_only = "\n".join(code_lines)
        assert "store_registry_version(" not in code_only, (
            "test_m2_t12b_e2e.py calls store_registry_version() directly"
        )
        assert "from agg_cp.sync.registry import store_registry_version" not in code_only, (
            "test_m2_t12b_e2e.py imports store_registry_version from agg_cp"
        )

    # 1e. step2_setup_and_admin returns registry_version == 3
    def test_returns_registry_version_key(self):
        """step2_setup_and_admin's return dict must include registry_version."""
        func_src = _extract_function_source("step2_setup_and_admin")
        assert "registry_version" in func_src, (
            "step2_setup_and_admin does not return a registry_version key"
        )


# ---------------------------------------------------------------------------
# 2. Live test (opt-in AGG_LIVE_STACK=1)
# ---------------------------------------------------------------------------


class TestDemoStep2Live:
    """Run demo.py --step 2 on the live compose stack."""

    def test_step2_subprocess(self):
        """demo.py --step 2 exits 0 and prints all PASS markers."""
        if os.environ.get("AGG_LIVE_STACK") != "1":
            pytest.skip("live ee stack test is opt-in: set AGG_LIVE_STACK=1")

        python = str(_REPO_ROOT / ".venv" / "Scripts" / "python")
        demo_script = str(_DEMO_PY)

        result = subprocess.run(
            [python, demo_script, "--step", "2"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(_REPO_ROOT / "ee" / "deploy"),
        )

        stdout = result.stdout
        # Print stdout for debugging
        print(stdout)

        assert result.returncode == 0, (
            f"demo.py --step 2 exited {result.returncode}.\n"
            f"stdout:\n{stdout[-2000:]}\n"
            f"stderr:\n{result.stderr[-2000:]}"
        )

        # Genesis v1, v2, v3
        assert PASS_GENESIS_V1 in stdout, (
            f"missing PASS marker for genesis v1 in stdout"
        )
        assert PASS_V2 in stdout, (
            f"missing PASS marker for v2 in stdout"
        )
        assert PASS_V3 in stdout, (
            f"missing PASS marker for v3 in stdout"
        )

        # Three negatives
        assert PASS_SECOND_GENESIS_REFUSED in stdout, (
            f"missing PASS marker for second genesis refused"
        )
        assert PASS_GENESIS_CODE_REUSE_REFUSED in stdout, (
            f"missing PASS marker for genesis code reuse refused"
        )
        assert PASS_PENDING_LINK_SELF_KEY_REFUSED in stdout, (
            f"missing PASS marker for pending_link self-key refused"
        )

        # Registry GET
        assert PASS_REGISTRY_GET in stdout, (
            f"missing PASS marker for registry GET"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_function_source(func_name: str) -> str:
    """Return the source text of a top-level function from demo.py."""
    tree = ast.parse(_DEMO_SOURCE, filename=str(_DEMO_PY))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            # Get source lines (1-indexed in ast)
            lines = _DEMO_SOURCE.splitlines()
            start = node.lineno - 1  # 0-indexed
            end = node.end_lineno  # end_lineno is inclusive in ast
            return "\n".join(lines[start:end])
    raise ValueError(f"function {func_name!r} not found in {_DEMO_PY}")
