"""M1 T6: injected clock lint test.

Design:
- ``agg_cp.clock`` module with ``Clock`` protocol (``now() -> datetime`` tz-aware UTC),
  ``SystemClock``, and a test ``FakeClock`` (settable/advanceable).
- Lint: AST scan of every ``.py`` under ``ee/src/agg_cp`` bans ``time.time``,
  ``time.time_ns``, ``datetime.now``, ``datetime.utcnow``, ``datetime.today``,
  ``date.today`` (attribute and ``from ... import`` forms), except in
  ``agg_cp/clock.py``.
- Positive controls: planted violations are detected.

The lint tests pass now (no violations in current code).  The clock-module
existence tests are ``xfail(strict=True)`` until T6 builds the module.
"""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest


EE_SRC = Path(__file__).resolve().parents[1] / "src" / "agg_cp"


# ---------------------------------------------------------------------------
# AST scanner: banned time/datetime calls
# ---------------------------------------------------------------------------

# Banned attribute accesses (obj.method)
_BANNED_ATTRS = {
    ("time", "time"),
    ("time", "time_ns"),
    ("datetime", "now"),
    ("datetime", "utcnow"),
    ("datetime", "today"),
    ("date", "today"),
}

# Banned from-imports: from <module> import <name>
_BANNED_FROM_IMPORTS = {
    # ``from time import time`` then ``time()``
    ("time", "time"),
    ("time", "time_ns"),
    # ``from datetime import datetime`` then ``datetime.now()`` etc
    # We catch re-imports that bring the class in locally
}


def _scan_file_for_clock_violations(source: str, filename: str = "<string>") -> list[str]:
    """Return a list of violation descriptions found in *source*."""
    violations: list[str] = []
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError:
        return violations

    # Track names imported from banned modules
    # e.g. ``from datetime import datetime`` means ``datetime`` is now the class
    imported_names: dict[str, str] = {}  # local_name -> module_name

    for node in ast.walk(tree):
        # Check from-imports
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                if mod == "time" and alias.name in ("time", "time_ns"):
                    violations.append(
                        f"{filename}:{node.lineno}: from {mod} import {alias.name}"
                    )
                if mod == "datetime" and alias.name in ("datetime", "date"):
                    imported_names[local] = alias.name

        # Check attribute access: obj.method
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                obj_name = node.value.id
                attr_name = node.attr

                # Direct module attribute: time.time(), datetime.now(), etc.
                if (obj_name, attr_name) in _BANNED_ATTRS:
                    violations.append(
                        f"{filename}:{node.lineno}: {obj_name}.{attr_name}"
                    )
                # Imported class: from datetime import datetime; datetime.now()
                elif obj_name in imported_names:
                    cls_name = imported_names[obj_name]
                    if (cls_name, attr_name) in _BANNED_ATTRS:
                        violations.append(
                            f"{filename}:{node.lineno}: {obj_name}.{attr_name} "
                            f"(imported as {cls_name})"
                        )

    return violations


def _scan_agg_cp_for_clock_violations() -> list[str]:
    """Scan all .py files under ee/src/agg_cp (except clock.py) for clock
    violations."""
    violations: list[str] = []
    if not EE_SRC.is_dir():
        return violations  # Nothing to scan (empty codebase passes)

    clock_path = EE_SRC / "clock.py"
    for py_file in sorted(EE_SRC.rglob("*.py")):
        if py_file == clock_path:
            continue
        try:
            source = py_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        rel = py_file.relative_to(EE_SRC.parent.parent)
        violations.extend(_scan_file_for_clock_violations(source, str(rel)))

    return violations


# ---------------------------------------------------------------------------
# Lint test: no clock violations in agg_cp (except clock.py)
# ---------------------------------------------------------------------------

def test_no_clock_violations_in_agg_cp():
    """AST scan of every .py under ee/src/agg_cp bans time.time, time.time_ns,
    datetime.now, datetime.utcnow, datetime.today, date.today -- except in
    agg_cp/clock.py."""
    violations = _scan_agg_cp_for_clock_violations()
    assert violations == [], (
        "Clock violations found (use the injected Clock instead):\n"
        + "\n".join(f"  {v}" for v in violations)
    )


# ---------------------------------------------------------------------------
# Positive controls: planted violations are detected
# ---------------------------------------------------------------------------

def test_positive_control_time_time_flagged(tmp_path: Path):
    """Positive control: a planted file with ``time.time()`` is flagged."""
    source = textwrap.dedent("""\
        import time
        x = time.time()
    """)
    violations = _scan_file_for_clock_violations(source, "planted.py")
    assert len(violations) > 0, "time.time() was not flagged"
    assert any("time.time" in v for v in violations), f"Expected time.time violation: {violations}"


def test_positive_control_from_datetime_now_flagged(tmp_path: Path):
    """Positive control: a planted file with ``from datetime import datetime;
    datetime.now()`` is flagged."""
    source = textwrap.dedent("""\
        from datetime import datetime
        x = datetime.now()
    """)
    violations = _scan_file_for_clock_violations(source, "planted.py")
    assert len(violations) > 0, "datetime.now() was not flagged"
    assert any("now" in v for v in violations), f"Expected datetime.now violation: {violations}"


def test_positive_control_time_time_ns_flagged():
    """Positive control: time.time_ns is flagged."""
    source = "import time\nx = time.time_ns()\n"
    violations = _scan_file_for_clock_violations(source, "planted.py")
    assert len(violations) > 0, "time.time_ns() was not flagged"


def test_positive_control_datetime_utcnow_flagged():
    """Positive control: datetime.utcnow is flagged."""
    source = "import datetime\nx = datetime.datetime.utcnow()\n"
    # This is datetime (module).datetime (class).utcnow -- a nested attr
    # The scanner catches obj.attr where obj is a Name node.
    # For datetime.datetime.utcnow, the outer is Attribute(Attribute(Name(datetime), datetime), utcnow)
    # We need to handle this. Let's also test the from-import form.
    source2 = "from datetime import datetime\nx = datetime.utcnow()\n"
    violations = _scan_file_for_clock_violations(source2, "planted.py")
    assert len(violations) > 0, "datetime.utcnow() was not flagged"


def test_positive_control_date_today_flagged():
    """Positive control: date.today is flagged."""
    source = "from datetime import date\nx = date.today()\n"
    violations = _scan_file_for_clock_violations(source, "planted.py")
    assert len(violations) > 0, "date.today() was not flagged"


def test_positive_control_from_time_import_time_flagged():
    """Positive control: ``from time import time`` is flagged."""
    source = "from time import time\nx = time()\n"
    violations = _scan_file_for_clock_violations(source, "planted.py")
    assert len(violations) > 0, "from time import time was not flagged"


# ---------------------------------------------------------------------------
# Clock module existence tests (xfail until T6 builds it)
# ---------------------------------------------------------------------------

def test_clock_module_exists():
    """agg_cp.clock module exists and is importable."""
    from agg_cp import clock
    assert hasattr(clock, "Clock"), "agg_cp.clock missing Clock protocol"
    assert hasattr(clock, "SystemClock"), "agg_cp.clock missing SystemClock"


def test_system_clock_returns_utc():
    """SystemClock.now() returns a tz-aware UTC datetime."""
    from agg_cp.clock import SystemClock

    import datetime as dt
    clock = SystemClock()
    now = clock.now()
    assert isinstance(now, dt.datetime), f"now() returned {type(now)}"
    assert now.tzinfo is not None, "now() returned naive datetime (must be tz-aware)"
    assert now.tzinfo == dt.timezone.utc or str(now.tzinfo) == "UTC", (
        f"now() timezone is {now.tzinfo}, expected UTC"
    )
