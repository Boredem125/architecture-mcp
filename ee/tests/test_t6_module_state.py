"""M1 T6: module-level mutable state lint test.

Design: AST scan of ``ee/src/agg_cp`` (excluding ``migrations/versions``)
rejects module-level assignments whose value is a list/dict/set literal or
comprehension, or a call to ``list``, ``dict``, ``set``, ``defaultdict``,
``OrderedDict``, ``deque``, ``Counter``.  Tuples, frozensets, constants
are allowed.

Positive controls: planted ``_cache = {}`` and ``x = defaultdict(list)``
are flagged.

These tests pass now (no violations in current code).
"""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest


EE_SRC = Path(__file__).resolve().parents[1] / "src" / "agg_cp"

# Calls that create mutable containers
_MUTABLE_CALLS = frozenset({
    "list", "dict", "set",
    "defaultdict", "OrderedDict", "deque", "Counter",
})


def _scan_file_for_mutable_state(source: str, filename: str = "<string>") -> list[str]:
    """Return a list of violation descriptions for module-level mutable state."""
    violations: list[str] = []
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError:
        return violations

    for node in tree.body:  # Only top-level statements
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue

        # Get the value expression
        if isinstance(node, ast.Assign):
            value = node.value
            targets = [_target_name(t) for t in node.targets]
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            value = node.value
            targets = [_target_name(node.target)]
        else:
            continue

        target_str = ", ".join(t for t in targets if t) or "<expr>"

        if _is_mutable_value(value):
            violations.append(
                f"{filename}:{node.lineno}: module-level mutable state: "
                f"{target_str} = {ast.dump(value)[:80]}"
            )

    return violations


def _target_name(node: ast.expr) -> str:
    """Extract the name from an assignment target."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return ast.dump(node)
    return "<complex>"


def _is_mutable_value(node: ast.expr) -> bool:
    """Return True if the AST node represents a mutable container."""
    # List, Dict, Set literals
    if isinstance(node, (ast.List, ast.Dict, ast.Set)):
        return True

    # List/Dict/Set comprehensions
    if isinstance(node, (ast.ListComp, ast.DictComp, ast.SetComp)):
        return True

    # Calls to mutable-container constructors
    if isinstance(node, ast.Call):
        func = node.func
        # Direct call: list(), dict(), set()
        if isinstance(func, ast.Name) and func.id in _MUTABLE_CALLS:
            return True
        # Attribute call: collections.defaultdict(), collections.OrderedDict(), etc.
        if isinstance(func, ast.Attribute) and func.attr in _MUTABLE_CALLS:
            return True

    return False


def _scan_agg_cp_for_mutable_state() -> list[str]:
    """Scan all .py files under ee/src/agg_cp (excluding migrations/versions)."""
    violations: list[str] = []
    if not EE_SRC.is_dir():
        return violations  # Nothing to scan

    versions_dir = EE_SRC / "migrations" / "versions"
    for py_file in sorted(EE_SRC.rglob("*.py")):
        # Exclude migrations/versions
        try:
            py_file.relative_to(versions_dir)
            continue  # Inside versions dir, skip
        except ValueError:
            pass  # Not inside versions dir, scan it

        try:
            source = py_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        rel = py_file.relative_to(EE_SRC.parent.parent)
        violations.extend(_scan_file_for_mutable_state(source, str(rel)))

    return violations


# ---------------------------------------------------------------------------
# Lint test
# ---------------------------------------------------------------------------

def test_no_module_level_mutable_state_in_agg_cp():
    """AST scan of ee/src/agg_cp (excluding migrations/versions) rejects
    module-level mutable container assignments."""
    violations = _scan_agg_cp_for_mutable_state()
    assert violations == [], (
        "Module-level mutable state found (use function-local or frozen containers):\n"
        + "\n".join(f"  {v}" for v in violations)
    )


# ---------------------------------------------------------------------------
# Positive controls
# ---------------------------------------------------------------------------

def test_positive_control_empty_dict_flagged():
    """Positive control: planted module-level ``_cache = {}`` is flagged."""
    source = textwrap.dedent("""\
        _cache = {}
    """)
    violations = _scan_file_for_mutable_state(source, "planted.py")
    assert len(violations) > 0, "_cache = {} was not flagged"
    assert any("_cache" in v for v in violations), f"Expected _cache violation: {violations}"


def test_positive_control_defaultdict_flagged():
    """Positive control: planted ``x = defaultdict(list)`` is flagged."""
    source = textwrap.dedent("""\
        from collections import defaultdict
        x = defaultdict(list)
    """)
    violations = _scan_file_for_mutable_state(source, "planted.py")
    assert len(violations) > 0, "defaultdict(list) was not flagged"


def test_positive_control_list_literal_flagged():
    """Positive control: planted ``items = [1, 2, 3]`` is flagged."""
    source = "items = [1, 2, 3]\n"
    violations = _scan_file_for_mutable_state(source, "planted.py")
    assert len(violations) > 0, "[1, 2, 3] was not flagged"


def test_positive_control_set_call_flagged():
    """Positive control: planted ``s = set()`` is flagged."""
    source = "s = set()\n"
    violations = _scan_file_for_mutable_state(source, "planted.py")
    assert len(violations) > 0, "set() was not flagged"


def test_positive_control_list_comprehension_flagged():
    """Positive control: planted ``xs = [x for x in range(10)]`` is flagged."""
    source = "xs = [x for x in range(10)]\n"
    violations = _scan_file_for_mutable_state(source, "planted.py")
    assert len(violations) > 0, "list comprehension was not flagged"


def test_positive_control_tuple_allowed():
    """Positive control: a module-level tuple is NOT flagged."""
    source = "ITEMS = (1, 2, 3)\n"
    violations = _scan_file_for_mutable_state(source, "planted.py")
    assert len(violations) == 0, f"Tuple was incorrectly flagged: {violations}"


def test_positive_control_frozenset_allowed():
    """Positive control: a module-level frozenset() call is NOT flagged."""
    source = "ITEMS = frozenset({1, 2, 3})\n"
    violations = _scan_file_for_mutable_state(source, "planted.py")
    assert len(violations) == 0, f"frozenset was incorrectly flagged: {violations}"


def test_positive_control_constant_allowed():
    """Positive control: module-level string/int constants are NOT flagged."""
    source = textwrap.dedent("""\
        VERSION = "1.0.0"
        MAX_RETRIES = 3
        DEBUG = False
    """)
    violations = _scan_file_for_mutable_state(source, "planted.py")
    assert len(violations) == 0, f"Constants were incorrectly flagged: {violations}"


def test_positive_control_collections_deque_flagged():
    """Positive control: planted ``q = deque()`` is flagged."""
    source = textwrap.dedent("""\
        from collections import deque
        q = deque()
    """)
    violations = _scan_file_for_mutable_state(source, "planted.py")
    assert len(violations) > 0, "deque() was not flagged"


def test_positive_control_counter_flagged():
    """Positive control: planted ``c = Counter()`` is flagged."""
    source = textwrap.dedent("""\
        from collections import Counter
        c = Counter()
    """)
    violations = _scan_file_for_mutable_state(source, "planted.py")
    assert len(violations) > 0, "Counter() was not flagged"


def test_positive_control_ordered_dict_flagged():
    """Positive control: planted ``d = OrderedDict()`` is flagged."""
    source = textwrap.dedent("""\
        from collections import OrderedDict
        d = OrderedDict()
    """)
    violations = _scan_file_for_mutable_state(source, "planted.py")
    assert len(violations) > 0, "OrderedDict() was not flagged"
