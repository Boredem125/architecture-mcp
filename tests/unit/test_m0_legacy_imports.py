"""M0 import tests written before any deletion (REVIEW_QA.md section 3, N1 and N2).

N1: an AST walk of src/sandbox; no kept module imports a deleted module.
N2: in a fresh interpreter, importing the connector entry points loads no
legacy package (this catches the package ``__init__`` re-exports).

N1 is RED until T3 (recorder move) and T5 (package deletions). A breach
raises ``LegacyStillPresent``; the strict xfail accepts that exception and
nothing else, so any other failure (a parse error, a missing core module)
fails the run. Once T5 lands N1 passes, strict xfail reports that as a
failure, and the decorator must be deleted.

N2 is GREEN today, contrary to REVIEW_QA.md's prediction: measured at
c411c35, the three entry points load no legacy package at import time,
because hook_eval imports connector.recorder (and so launcher/) lazily,
inside functions. N1 sees that lazy edge. N2 is a regression guard for
T3-T5: a package ``__init__`` edited badly, or an eager import added,
turns it red.

The deleted set is M0_PLAN.md "Delete" plus the founder's orphan answer
(17 Oct 2026): keep anomaly/ and audit/sink.py; delete rollback/,
models/{messages,session,security}.py, crypto/tokens.py, api/websocket.py.
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src"
PKG = SRC / "sandbox"

DELETED_PACKAGES = (
    "sandbox.pipeline", "sandbox.agents", "sandbox.launcher", "sandbox.hitl",
    "sandbox.translate", "sandbox.transport", "sandbox.policy", "sandbox.containment",
    "sandbox.executor", "sandbox.rollback",
)
DELETED_MODULES = (
    "sandbox.crypto.tokens",
    "sandbox.models.messages", "sandbox.models.session", "sandbox.models.security",
    "sandbox.api.websocket",
) + tuple(f"sandbox.api.routes.{name}" for name in (
    "agents", "agent_runtime", "e2b", "launcher", "hook", "sessions", "requests",
    "policies", "security", "dashboard", "audit", "hitl",
))
DELETED = DELETED_PACKAGES + DELETED_MODULES

# N2: exactly the set REVIEW_QA.md section 3 names.
N2_ENTRY_POINTS = ("sandbox.connector.hook_eval", "sandbox.connector.mcp_server", "sandbox.cli.main")
N2_FORBIDDEN = ("sandbox.launcher", "sandbox.executor", "sandbox.pipeline",
                "sandbox.agents", "sandbox.hitl", "sandbox.containment")


class LegacyStillPresent(AssertionError):
    """A kept module still reaches legacy code (expected until T3/T5)."""


RED_UNTIL_T5 = pytest.mark.xfail(
    raises=LegacyStillPresent, strict=True,
    reason="RED until T3 moves launcher/recorder.py and T5 deletes the legacy packages",
)


def _is_deleted(module: str) -> bool:
    return any(module == d or module.startswith(d + ".") for d in DELETED)


def _module_name(path: Path) -> str:
    parts = list(path.relative_to(SRC).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _imported(tree: ast.AST, module: str, is_pkg: bool) -> set[str]:
    """Every module an AST imports: top-level and lazy, relative resolved,
    ``from pkg import sub`` counted as ``pkg.sub``, plus constant-string
    ``importlib.import_module`` / ``__import__`` calls."""
    package = module if is_pkg else module.rpartition(".")[0]
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".")
                base = base[: len(base) - (node.level - 1)]
                target = ".".join(base + ([node.module] if node.module else []))
            else:
                target = node.module or ""
            found.add(target)
            found.update(f"{target}.{a.name}" for a in node.names if a.name != "*")
        elif isinstance(node, ast.Call) and node.args:
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            arg = node.args[0]
            if name in ("import_module", "__import__") and isinstance(arg, ast.Constant) \
                    and isinstance(arg.value, str):
                found.add(arg.value)
    return found


@RED_UNTIL_T5
def test_n1_no_kept_module_imports_a_deleted_module():
    kept = [p for p in sorted(PKG.rglob("*.py")) if not _is_deleted(_module_name(p))]
    # Sanity (holds today): the connector core is there and every file parses.
    names = {_module_name(p) for p in kept}
    for core in ("sandbox.connector.hook_eval", "sandbox.connector.classify",
                 "sandbox.connector.audit", "sandbox.cli.main", "sandbox.api.app"):
        assert core in names, core
    offenders = []
    for path in kept:
        mod = _module_name(path)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for target in sorted(_imported(tree, mod, path.name == "__init__.py")):
            if _is_deleted(target):
                offenders.append(f"{mod} -> {target}")
    if offenders:
        raise LegacyStillPresent(f"{len(offenders)} kept->deleted imports: {offenders}")


def test_n2_connector_entry_points_load_no_legacy_package(tmp_path):
    script = (
        "import importlib, json, sys\n"
        f"for m in {N2_ENTRY_POINTS!r}:\n"
        "    importlib.import_module(m)\n"
        f"bad = sorted(k for k in sys.modules if k.startswith({N2_FORBIDDEN!r}))\n"
        "print(json.dumps(bad))\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([sys.executable, "-c", script], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=120)
    # Sanity (must hold before and after M0): the entry points import cleanly.
    assert proc.returncode == 0, proc.stderr[-2000:]
    loaded = json.loads(proc.stdout.strip().splitlines()[-1])
    if loaded:
        raise LegacyStillPresent(f"legacy modules loaded: {loaded}")
