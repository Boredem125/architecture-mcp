"""M3 T4 static tests (no pg): AST guards, flag matrix, subprocess exit,
import and definition checks.

Spec: T4_SPEC.md section 3.3.  19 functions, 46 node ids.
Guard twins PASS today.
"""
from __future__ import annotations

import ast
import importlib
import importlib.util
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from .m3_pending import M3T4Pending, require_m3

_EE_SRC = Path(__file__).resolve().parent.parent / "src" / "agg_cp"
_SRC = Path(__file__).resolve().parent.parent.parent / "src"
_DEPLOY = Path(__file__).resolve().parent.parent / "deploy"

# Measured at tests-first by AST scan (spec 2.7):
_WITH_BLOCK_TX_COUNT = 70
_ASSIGN_SITE_COUNT = 3  # create_link_code_route:409, signatures_route:744, genesis_route:1137

# ---------------------------------------------------------------------------
# AST visitor: await inside a transaction (spec 2.7, MUST 8)
# ---------------------------------------------------------------------------

_TX_NAMES = frozenset({
    "_conn", "_app_conn", "connect", "connection", "transaction", "begin",
})


def _call_name(call_node: ast.Call) -> str | None:
    """Return the function/method name of a Call, or None."""
    if isinstance(call_node.func, ast.Name):
        return call_node.func.id
    if isinstance(call_node.func, ast.Attribute):
        return call_node.func.attr
    return None


def _has_autocommit_true(call_node: ast.Call) -> bool:
    """True when ``autocommit=True`` is in the call's keyword args."""
    for kw in call_node.keywords:
        if kw.arg == "autocommit":
            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
    return False


def _walk_no_inner_funcs(node):
    """Yield all descendants of *node*, skipping nested function/class defs."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                              ast.ClassDef)):
            continue
        yield child
        yield from _walk_no_inner_funcs(child)


def _is_close_on_var(stmt, var_name: str) -> bool:
    """True when *stmt* is an ``Expr`` of ``<var_name>.close()``."""
    return (isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Call)
            and isinstance(stmt.value.func, ast.Attribute)
            and stmt.value.func.attr == "close"
            and isinstance(stmt.value.func.value, ast.Name)
            and stmt.value.func.value.id == var_name)


def _scan_sources(sources):
    """Return (with_block_count, assign_site_count, violations).

    *sources*: iterable of ``(name, source_text)`` pairs.

    Form 1 (with-block): a ``with`` or ``async with`` whose context call
    is a TX name, containing an ``Await`` anywhere.

    Form 2 (assignment): in an ``async def``, a plain assignment from a
    TX-named call without ``autocommit=True``, followed by an ``Await``
    before that variable's ``.close()`` call at the same statement level
    or in a ``finally`` block.  A ``.close()`` inside an ``If`` or
    ``Try`` handler that also contains a ``Return`` does not end the
    window (the ``await`` is still reachable on the other branch).
    Only a ``.close()`` on the site's own variable counts.
    """
    with_count = 0
    assign_site_count = 0
    violations = []

    for name, source in sources:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue

        # Form 1: with/async with block containing Await
        for node in ast.walk(tree):
            if isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    call = item.context_expr
                    if isinstance(call, ast.Call):
                        cname = _call_name(call)
                        if cname and cname in _TX_NAMES:
                            with_count += 1
                            for child in ast.walk(node):
                                if isinstance(child, ast.Await):
                                    violations.append(
                                        (name, node.lineno,
                                         child.lineno, "with")
                                    )
                                    break

        # Form 2: assignment form in async functions -- find assignments
        # at any depth (inside try/if/for/with blocks), skipping nested
        # defs.  The window extends through the rest of the assignment's
        # block plus the rest of every enclosing block up to the function
        # body.  It ends at var.close() at any of those levels, or in an
        # enclosing finally.  Only a close on the site's own variable
        # counts.
        for node in ast.walk(tree):
            if not isinstance(node, ast.AsyncFunctionDef):
                continue

            def _find_assign_sites(stmts, parents=None):
                """Yield (stmt, idx, containing_stmts, parents).

                *parents* is a list of ``(enclosing_stmts, stmt_idx)``
                tuples from outermost to innermost.
                """
                if parents is None:
                    parents = []
                for idx, stmt in enumerate(stmts):
                    if isinstance(stmt, (ast.FunctionDef,
                                         ast.AsyncFunctionDef,
                                         ast.ClassDef)):
                        continue
                    if isinstance(stmt, ast.Assign):
                        if (len(stmt.targets) == 1
                                and isinstance(stmt.targets[0], ast.Name)
                                and isinstance(stmt.value, ast.Call)):
                            cn = _call_name(stmt.value)
                            if cn and cn in _TX_NAMES:
                                if not _has_autocommit_true(stmt.value):
                                    yield (stmt, idx, stmts,
                                           list(parents))
                    # Recurse into compound statements
                    for block in _compound_bodies(stmt):
                        yield from _find_assign_sites(
                            block, parents + [(stmts, idx)])

            def _compound_bodies(stmt):
                """Yield the body lists of compound statements."""
                if isinstance(stmt, (ast.If, ast.While)):
                    yield stmt.body
                    yield stmt.orelse
                elif isinstance(stmt, (ast.For, ast.AsyncFor)):
                    yield stmt.body
                    yield stmt.orelse
                elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                    yield stmt.body
                elif isinstance(stmt, ast.Try):
                    yield stmt.body
                    for h in stmt.handlers:
                        yield h.body
                    yield stmt.orelse
                    yield stmt.finalbody
                # TryStar (Python 3.11; merged into Try in 3.12+)
                elif hasattr(ast, "TryStar") and isinstance(
                        stmt, getattr(ast, "TryStar")):
                    yield stmt.body
                    for h in stmt.handlers:
                        yield h.body
                    yield stmt.orelse
                    yield stmt.finalbody

            for assign_stmt, idx, containing, parents in \
                    _find_assign_sites(node.body):
                var_name = assign_stmt.targets[0].id
                assign_line = assign_stmt.lineno
                assign_site_count += 1

                # Build remaining statements: assignment's own block,
                # then each enclosing block from innermost to outermost.
                # When climbing out of a Try whose body held the
                # assignment, also include its handler bodies, orelse
                # and finalbody (up to the close, which ends the
                # window).
                remaining_seqs = [containing[idx + 1:]]
                prev_block = containing
                for pstmts, pidx in reversed(parents):
                    parent_stmt = pstmts[pidx]
                    if (isinstance(parent_stmt, ast.Try)
                            and prev_block is parent_stmt.body):
                        for h in parent_stmt.handlers:
                            remaining_seqs.append(h.body)
                        if parent_stmt.orelse:
                            remaining_seqs.append(
                                parent_stmt.orelse)
                        if parent_stmt.finalbody:
                            remaining_seqs.append(
                                parent_stmt.finalbody)
                    remaining_seqs.append(pstmts[pidx + 1:])
                    prev_block = pstmts

                all_remaining = []
                for seq in remaining_seqs:
                    all_remaining.extend(seq)

                # Find close: at any level or in an enclosing finally
                close_line = None
                for sub in all_remaining:
                    if _is_close_on_var(sub, var_name):
                        close_line = sub.lineno
                        break
                    if isinstance(sub, ast.Try) and sub.finalbody:
                        for fb in sub.finalbody:
                            if _is_close_on_var(fb, var_name):
                                close_line = fb.lineno
                                break
                        if close_line is not None:
                            break

                # Check for awaits between assignment and close
                found_violation = False
                for sub in all_remaining:
                    if (close_line is not None
                            and sub.lineno >= close_line):
                        break
                    for child in _walk_no_inner_funcs(sub):
                        if isinstance(child, ast.Await):
                            violations.append(
                                (name, assign_line, child.lineno,
                                 "assign"))
                            found_violation = True
                            break
                    if found_violation:
                        break

    return with_count, assign_site_count, violations


def _scan_await_violations(root_dir: Path):
    """Scan all .py files under *root_dir* for await-inside-transaction."""
    sources = []
    for pyfile in root_dir.rglob("*.py"):
        if "migrations" in str(pyfile):
            continue
        try:
            text = pyfile.read_text(encoding="utf-8")
            sources.append((str(pyfile.relative_to(root_dir)), text))
        except (SyntaxError, UnicodeDecodeError):
            continue
    return _scan_sources(sources)


# ===================================================================
# Flag-profile matrix (spec 2.5, 12 cases: 9 refuse + 3 build)
# ===================================================================

_xfail_t4 = pytest.mark.xfail(strict=True, raises=M3T4Pending)

_FLAG_MATRIX = [
    # (profile_env, flag_env, should_refuse)
    # -- 9 refuse cases (xfail until T4 build adds flag check) --
    pytest.param("pilot", "1", True, marks=_xfail_t4,
                 id="refuse-pilot-1"),
    pytest.param("pilot", "true", True, marks=_xfail_t4,
                 id="refuse-pilot-true"),
    pytest.param("", "1", True, marks=_xfail_t4,
                 id="refuse-empty-1"),
    pytest.param(None, "1", True, marks=_xfail_t4,
                 id="refuse-unset-1"),
    pytest.param("Demo", "1", True, marks=_xfail_t4,
                 id="refuse-Demo-1"),
    pytest.param("demo ", "1", True, marks=_xfail_t4,
                 id="refuse-demospace-1"),
    pytest.param("demo", "true", True, marks=_xfail_t4,
                 id="refuse-demo-true"),
    pytest.param("demo", "", True, marks=_xfail_t4,
                 id="refuse-demo-empty"),
    pytest.param("demo", "0", True, marks=_xfail_t4,
                 id="refuse-demo-0"),
    # -- 3 build cases (guards: pass today) --
    pytest.param("demo", "1", False, id="build-demo-1"),
    pytest.param(None, None, False, id="build-unset-unset"),
    pytest.param("pilot", None, False, id="build-pilot-unset"),
]


@pytest.mark.parametrize("profile,flag,should_refuse", _FLAG_MATRIX)
def test_create_app_flag_profile_matrix(profile, flag, should_refuse, monkeypatch):
    """create_app refuses or builds per the profile/flag matrix."""
    if should_refuse:
        require_m3(
            4,
            importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
            "publish_verify module missing (T4)",
        )

    # Set/unset env vars
    if profile is not None:
        monkeypatch.setenv("AGG_DEPLOY_PROFILE", profile)
    else:
        monkeypatch.delenv("AGG_DEPLOY_PROFILE", raising=False)

    if flag is not None:
        monkeypatch.setenv("AGG_ALLOW_DIRECT_PUBLISH", flag)
    else:
        monkeypatch.delenv("AGG_ALLOW_DIRECT_PUBLISH", raising=False)

    from agg_cp.app import create_app
    if should_refuse:
        with pytest.raises(RuntimeError):
            create_app()
    else:
        # Must not raise -- we do not need a DB for this, just the app object
        try:
            app = create_app()
            assert app is not None
        except RuntimeError as exc:
            if "AGG_ALLOW_DIRECT_PUBLISH" in str(exc):
                raise
            # Other RuntimeErrors (e.g. DB-related) are acceptable


# ===================================================================
# Subprocess exit (MUST 10)
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_uvicorn_factory_exits_with_flag_under_pilot():
    """python -m uvicorn agg_cp.app:create_app --factory with
    AGG_DEPLOY_PROFILE=pilot and AGG_ALLOW_DIRECT_PUBLISH=1 exits
    non-zero within 15 s and nothing answers on the port."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )

    # Find a free port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    env = {
        **os.environ,
        "AGG_DEPLOY_PROFILE": "pilot",
        "AGG_ALLOW_DIRECT_PUBLISH": "1",
    }
    # Remove DB URL so we don't need a real database
    env.pop("AGG_DATABASE_URL", None)
    env.pop("AGG_DATABASE_URL_FILE", None)

    extra_paths = os.pathsep.join([
        str(_EE_SRC.parent.parent / "src"),
        str(_SRC),
    ])
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = extra_paths + (os.pathsep + existing_pp
                                       if existing_pp else "")

    cmd = [
        sys.executable, "-m", "uvicorn",
        "agg_cp.app:create_app",
        "--factory",
        "--host", "127.0.0.1",
        "--port", str(port),
    ]

    proc = None
    try:
        proc = subprocess.Popen(
            cmd, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        # Use communicate to drain pipes and wait up to 15 s
        try:
            out, err = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate(timeout=5)
            raise AssertionError("process did not exit within 15 s")
        ret = proc.returncode
        assert ret != 0, f"process exited 0, expected non-zero"
        assert (b"AGG_ALLOW_DIRECT_PUBLISH requires AGG_DEPLOY_PROFILE=demo"
                in err), (
            f"expected startup refusal in stderr, got: {err[:500]}"
        )

        # Verify nothing answers on the port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex(("127.0.0.1", port))
            assert result != 0, "something is listening on the port"
    finally:
        if proc is not None:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=5)
            except Exception:
                pass


# ===================================================================
# Direct publish: no DB before flag check
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_direct_publish_no_db_before_flag_check(monkeypatch):
    """create_app with an unreachable DB URL, no flag, POST with no cookie: 410
    within 2 s."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )

    from agg_cp.app import create_app
    from starlette.testclient import TestClient

    monkeypatch.delenv("AGG_ALLOW_DIRECT_PUBLISH", raising=False)
    monkeypatch.delenv("AGG_DEPLOY_PROFILE", raising=False)
    # Use an unreachable DB URL
    app = create_app(db_url="postgresql+psycopg://nope:nope@192.0.2.1:1/nope")
    t0 = time.monotonic()
    tc = TestClient(app, raise_server_exceptions=False)
    r = tc.post("/api/v1/admin/bundles", json={})
    elapsed = time.monotonic() - t0
    assert r.status_code == 410, (
        f"expected 410, got {r.status_code}: {r.text[:200]}"
    )
    assert elapsed < 2, f"410 took {elapsed:.1f}s, expected < 2 s"


# ===================================================================
# AST: flag check is first statement of admin_create_bundle
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_direct_publish_flag_check_is_first_statement():
    """AST: walk admin_create_bundle.body up to the first If whose body
    returns direct_publish_gone (410).  No statement up to and including
    it may contain Await, With, AsyncWith, or a call to _conn/connect.
    One of them must call _direct_publish_enabled.

    Accepts the spec 2.5 form:
        try: on = _direct_publish_enabled(os.environ)
        except RuntimeError: on = False
        if not on: return ...
    """
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )

    bundles_path = _EE_SRC / "sync" / "bundles.py"
    source = bundles_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    func = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            if node.name == "admin_create_bundle":
                func = node
                break
    assert func is not None, "admin_create_bundle not found in sync/bundles.py"

    # Walk body statements until we find the If whose body returns
    # direct_publish_gone or 410.  An If that returns something else
    # (e.g. an unrelated guard) must NOT stop the walk.
    found_flag_if = False
    calls_flag_fn = False
    forbidden_before = set()

    def _is_flag_if(stmt):
        """True when *stmt* is an If that returns direct_publish_gone/410."""
        if not isinstance(stmt, ast.If):
            return False
        has_gone_constant = False
        for child in ast.walk(stmt):
            if isinstance(child, ast.Constant):
                if child.value in ("direct_publish_gone", 410):
                    has_gone_constant = True
        return has_gone_constant

    for stmt in func.body:
        if _is_flag_if(stmt):
            found_flag_if = True
            break

        # Before the flag If, no Await, With, AsyncWith, or DB call
        for child in ast.walk(stmt):
            if isinstance(child, ast.Await):
                forbidden_before.add("Await")
            if isinstance(child, (ast.With, ast.AsyncWith)):
                forbidden_before.add("With")
            if isinstance(child, ast.Call):
                cn = _call_name(child)
                if cn and cn in ("_conn", "_app_conn", "connect"):
                    forbidden_before.add(f"call to {cn}")
                if cn == "_direct_publish_enabled":
                    calls_flag_fn = True

    assert found_flag_if, (
        "admin_create_bundle has no If that returns direct_publish_gone/410"
    )
    assert not forbidden_before, (
        f"statements before the flag check contain: {forbidden_before}"
    )
    assert calls_flag_fn, (
        "no call to _direct_publish_enabled before the flag If"
    )


# ===================================================================
# No await inside transaction (MUST 8, spec 2.7)
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_no_await_inside_transaction_anywhere():
    """The 2.7 visitor over ee/src/agg_cp (minus migrations): zero violations;
    with-block count is 70 and assignment-site count is 3."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )

    with_count, assign_count, violations = _scan_await_violations(_EE_SRC)
    assert with_count >= _WITH_BLOCK_TX_COUNT, (
        f"expected at least {_WITH_BLOCK_TX_COUNT} with-blocks, got {with_count}"
    )
    assert assign_count >= _ASSIGN_SITE_COUNT, (
        f"expected at least {_ASSIGN_SITE_COUNT} assign sites, "
        f"got {assign_count}"
    )
    assert len(violations) == 0, (
        f"found {len(violations)} await-inside-transaction violations: "
        + "; ".join(f"{v[0]}:{v[1]}->{v[2]} ({v[3]})" for v in violations)
    )


# ===================================================================
# Synthetic violation guards (MUST 8)
# ===================================================================

_WITH_SNIPPET = """\
async def f():
    async with _conn() as c:
        x = await some_call()
"""

_ASSIGN_SNIPPET = """\
async def f():
    conn = connect(url, autocommit=False)
    result = await request.json()
    conn.close()
"""

_ASSIGN_AUTOCOMMIT_SNIPPET = """\
async def f():
    conn = connect(url, autocommit=True)
    result = await request.json()
    conn.close()
"""

# False-negative snippets: a close on a different variable and an
# early-return close inside an if.  Both must give 1 violation.
_EARLY_CLOSE_DIFFERENT_VAR = """\
async def f():
    conn = connect(url, autocommit=False)
    cur.close()
    result = await request.json()
    conn.close()
"""

_IF_RETURN_CLOSE = """\
async def f():
    conn = connect(url, autocommit=False)
    if bad:
        conn.close()
        return
    result = await request.json()
    conn.close()
"""

# Real shape: assignment nested inside try: (all three signer.py sites)
_ASSIGN_IN_TRY_SNIPPET = """\
async def f():
    conn = None
    try:
        conn = connect(url, autocommit=False)
        x = await request.json()
    finally:
        if conn:
            conn.close()
"""

# Enclosing-block snippets: the assignment is inside try or if, and the
# await is AFTER that block in the enclosing function body.  Each must
# give 1 violation when the window extends through enclosing blocks.
_ASSIGN_TRY_EXCEPT_ENCLOSING = """\
async def f():
    try:
        conn = connect(url, autocommit=False)
    except Exception:
        return
    x = await request.json()
    conn.close()
"""

_ASSIGN_IF_ENCLOSING = """\
async def f():
    if cond:
        conn = connect(url, autocommit=False)
    x = await request.json()
    conn.close()
"""

# F4: await in the enclosing try's except handler before the close
_AWAIT_IN_EXCEPT_HANDLER = """\
async def f():
    try:
        conn = connect(url, autocommit=False)
    except Exception:
        x = await request.json()
    finally:
        conn.close()
"""

# F4: await in the enclosing try's finally before the close
_AWAIT_IN_FINALLY_BEFORE_CLOSE = """\
async def f():
    try:
        conn = connect(url, autocommit=False)
    finally:
        x = await request.json()
        conn.close()
"""

# F4: assignment inside async for
_ASSIGN_IN_ASYNC_FOR = """\
async def f():
    async for item in stream:
        conn = connect(url, autocommit=False)
        x = await request.json()
        conn.close()
"""


@pytest.mark.parametrize("snippet,expected", [
    (_WITH_SNIPPET, 1),
    (_ASSIGN_SNIPPET, 1),
], ids=["with", "assign"])
def test_await_guard_flags_synthetic_violation(snippet, expected):
    """The SAME visitor function the real scan uses flags a with-block
    violation and an assign-then-await violation, and passes the
    autocommit=True version.  Also checks the two false-negative
    snippets (close on another variable; close inside if-return)."""
    _, _, violations = _scan_sources([("snippet", snippet)])
    assert len(violations) == expected, (
        f"expected {expected} violation(s), got {len(violations)}: {violations}"
    )
    # Autocommit gives 0
    _, _, v2 = _scan_sources([("snippet", _ASSIGN_AUTOCOMMIT_SNIPPET)])
    assert len(v2) == 0, f"autocommit snippet gave {len(v2)} violation(s)"
    # Early close on different variable gives 1
    _, _, v3 = _scan_sources([("snippet", _EARLY_CLOSE_DIFFERENT_VAR)])
    assert len(v3) == 1, (
        f"early-close-different-var snippet: expected 1 violation, got {len(v3)}"
    )
    # If-return-close gives 1
    _, _, v4 = _scan_sources([("snippet", _IF_RETURN_CLOSE)])
    assert len(v4) == 1, (
        f"if-return-close snippet: expected 1 violation, got {len(v4)}"
    )
    # Assign nested in try (the real signer.py shape) gives 1
    _, _, v5 = _scan_sources([("snippet", _ASSIGN_IN_TRY_SNIPPET)])
    assert len(v5) == 1, (
        f"assign-in-try snippet: expected 1 violation, got {len(v5)}"
    )
    # Assignment inside try, await after the try block (enclosing) gives 1
    _, _, v6 = _scan_sources([("snippet", _ASSIGN_TRY_EXCEPT_ENCLOSING)])
    assert len(v6) == 1, (
        f"try-except-enclosing snippet: expected 1 violation, got {len(v6)}"
    )
    # Assignment inside if, await after the if block (enclosing) gives 1
    _, _, v7 = _scan_sources([("snippet", _ASSIGN_IF_ENCLOSING)])
    assert len(v7) == 1, (
        f"if-enclosing snippet: expected 1 violation, got {len(v7)}"
    )
    # F4: await in enclosing try's except handler gives 1
    _, _, v8 = _scan_sources([("snippet", _AWAIT_IN_EXCEPT_HANDLER)])
    assert len(v8) == 1, (
        f"await-in-except-handler snippet: expected 1 violation, got {len(v8)}"
    )
    # F4: await in enclosing try's finally before close gives 1
    _, _, v9 = _scan_sources([("snippet", _AWAIT_IN_FINALLY_BEFORE_CLOSE)])
    assert len(v9) == 1, (
        f"await-in-finally-before-close snippet: expected 1 violation, "
        f"got {len(v9)}"
    )
    # F4: assignment inside async for gives 1
    _, _, v10 = _scan_sources([("snippet", _ASSIGN_IN_ASYNC_FOR)])
    assert len(v10) == 1, (
        f"assign-in-async-for snippet: expected 1 violation, got {len(v10)}"
    )


# ===================================================================
# is_project_admin single definition (spec item 11)
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_is_project_admin_single_definition():
    """Exactly one function named is_project_admin or _is_project_admin
    in ee/src/agg_cp, in rbac.py; the joined SQL fragment occurs once
    (counted over ast.Constant string values, not source.count)."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )

    definitions = []
    sql_fragment = "scope_type = 'project' AND scope_id = %s AND role = 'admin'"
    fragment_count = 0

    for pyfile in _EE_SRC.rglob("*.py"):
        if "migrations" in str(pyfile):
            continue
        source = pyfile.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name in ("is_project_admin", "_is_project_admin"):
                    rel = str(pyfile.relative_to(_EE_SRC))
                    definitions.append(f"{rel}:{node.lineno}")
            # Count SQL fragment over ast.Constant string values
            # (handles implicitly joined string literals)
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if sql_fragment in node.value:
                    fragment_count += 1

    assert len(definitions) == 1, (
        f"expected 1 definition of is_project_admin, found {len(definitions)}: "
        + ", ".join(definitions)
    )
    assert "rbac.py" in definitions[0], (
        f"definition must be in rbac.py, found in {definitions[0]}"
    )
    assert fragment_count == 1, (
        f"SQL fragment occurs {fragment_count} times, expected 1"
    )


# ===================================================================
# Server imports connector by name only (guard, SHOULD 15)
# ===================================================================

def test_server_imports_connector_by_name_only():
    """Every ImportFrom of sandbox.connector.sync.bundles or .process in
    ee/src has asname is None and names within the spec list; no ast.Import
    of either module; no ImportFrom of their parent packages naming
    bundles/process/sync; no string constant equal to a dotted module name."""
    allowed_bundles = frozenset({
        "BUNDLE_FIELDS", "BUNDLE_MAX_BYTES", "BundleError",
        "_bundle_hash", "_canonical_json_bytes", "loosened",
        "_verify_change_approvals", "_verify_envelope_structure",
        "_verify_signature", "_verify_bundle_signer_in_registry",
    })
    allowed_process = frozenset({"_bundle_signer_pub"})
    target_modules = {
        "sandbox.connector.sync.bundles": allowed_bundles,
        "sandbox.connector.sync.process": allowed_process,
    }
    # Parent packages that could reach the target via module imports
    parent_packages = {"sandbox.connector.sync", "sandbox.connector"}
    # Names that must not be imported from parent packages
    forbidden_names = frozenset({"bundles", "process", "sync"})
    # Dotted module name strings that must not appear as constants
    forbidden_strings = frozenset({
        "sandbox.connector.sync.bundles",
        "sandbox.connector.sync.process",
    })

    for pyfile in _EE_SRC.rglob("*.py"):
        if "migrations" in str(pyfile):
            continue
        source = pyfile.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        rel = str(pyfile.relative_to(_EE_SRC))
        for node in ast.walk(tree):
            # No bare `import sandbox.connector.sync.bundles`
            if isinstance(node, ast.Import):
                for alias in node.names:
                    for mod in target_modules:
                        assert mod not in alias.name, (
                            f"{rel}:{node.lineno}: bare import of {alias.name}"
                        )
            if isinstance(node, ast.ImportFrom):
                # Direct module imports
                if node.module in target_modules:
                    allowed = target_modules[node.module]
                    for alias in node.names:
                        assert alias.asname is None, (
                            f"{rel}:{node.lineno}: alias on {alias.name} "
                            f"as {alias.asname}"
                        )
                        assert alias.name in allowed, (
                            f"{rel}:{node.lineno}: {alias.name} not in "
                            f"allowed set for {node.module}"
                        )
                # Parent package imports naming module objects
                if node.module in parent_packages:
                    for alias in node.names:
                        assert alias.name not in forbidden_names, (
                            f"{rel}:{node.lineno}: from {node.module} "
                            f"import {alias.name} reaches connector module"
                        )
            # No string constant equal to a target module name
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert node.value not in forbidden_strings, (
                    f"{rel}:{node.lineno}: string constant "
                    f"{node.value!r} names a connector module"
                )


# ===================================================================
# verify_and_apply never referenced in ee/src (guard)
# ===================================================================

def test_verify_and_apply_never_referenced_in_server():
    """No Name or Attribute 'verify_and_apply' in ee/src."""
    for pyfile in _EE_SRC.rglob("*.py"):
        if "migrations" in str(pyfile):
            continue
        source = pyfile.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        rel = str(pyfile.relative_to(_EE_SRC))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == "verify_and_apply":
                raise AssertionError(
                    f"{rel}:{node.lineno}: Name 'verify_and_apply'"
                )
            if (isinstance(node, ast.Attribute)
                    and node.attr == "verify_and_apply"):
                raise AssertionError(
                    f"{rel}:{node.lineno}: Attribute 'verify_and_apply'"
                )


# ===================================================================
# Publish route calls shared verifier (AST)
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_route_calls_shared_verifier():
    """AST: publish_proposal calls verify_publish and sign_and_check;
    no function in proposals.py except approve_proposal calls
    _verify_change_approvals."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )

    proposals_path = _EE_SRC / "sync" / "proposals.py"
    source = proposals_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    # Find publish_proposal
    publish_fn = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == "publish_proposal":
                publish_fn = node
                break
    assert publish_fn is not None, "publish_proposal not found"

    # publish_proposal must call verify_publish and sign_and_check
    # (as Name or Attribute)
    calls_verify_publish = False
    calls_sign_and_check = False
    for child in ast.walk(publish_fn):
        if isinstance(child, ast.Call):
            if isinstance(child.func, ast.Name):
                if child.func.id == "verify_publish":
                    calls_verify_publish = True
                if child.func.id == "sign_and_check":
                    calls_sign_and_check = True
            if isinstance(child.func, ast.Attribute):
                if child.func.attr == "verify_publish":
                    calls_verify_publish = True
                if child.func.attr == "sign_and_check":
                    calls_sign_and_check = True

    assert calls_verify_publish, "publish_proposal must call verify_publish"
    assert calls_sign_and_check, "publish_proposal must call sign_and_check"

    # Walk every function in proposals.py except approve_proposal:
    # _verify_change_approvals must not be called (as Name or Attribute).
    # Use _walk_no_inner_funcs so we don't descend into nested defs
    # (proposals_router contains approve_proposal as a nested def).
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name == "approve_proposal":
            continue
        for child in _walk_no_inner_funcs(node):
            if isinstance(child, ast.Call):
                called_name = None
                if isinstance(child.func, ast.Name):
                    called_name = child.func.id
                elif isinstance(child.func, ast.Attribute):
                    called_name = child.func.attr
                assert called_name != "_verify_change_approvals", (
                    f"{node.name} calls _verify_change_approvals directly "
                    "(only approve_proposal may)"
                )


# ===================================================================
# Counting roles match connector (AST pin)
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_server_counting_roles_match_connector():
    """The set literal in _verify_change_approvals equals
    publish_verify.COUNTING_ROLES."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )

    # Extract the set literal from the connector's _verify_change_approvals
    bundles_path = _SRC / "sandbox" / "connector" / "sync" / "bundles.py"
    source = bundles_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    connector_roles = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name != "_verify_change_approvals":
                continue
            # Find the set literal inside: roles.intersection({...})
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    if (isinstance(child.func, ast.Attribute)
                            and child.func.attr == "intersection"):
                        if child.args and isinstance(child.args[0], ast.Set):
                            connector_roles = ast.literal_eval(child.args[0])
                            break
    assert connector_roles is not None, (
        "could not extract counting roles set from _verify_change_approvals"
    )

    from agg_cp.sync.publish_verify import COUNTING_ROLES
    assert COUNTING_ROLES == frozenset(connector_roles), (
        f"COUNTING_ROLES {COUNTING_ROLES} != connector {connector_roles}"
    )


# ===================================================================
# verify_publish refusal codes (MUST 7, 16 cases)
# ===================================================================

_REFUSAL_CODES = [
    "bad_payload_duplicate",
    "bad_payload_nan",
    "hash_mismatch",
    "too_large",
    "unknown_fields_extra",
    "unknown_fields_change_approvals",
    "binding_mismatch_org",
    "binding_mismatch_project",
    "binding_mismatch_base",
    "binding_mismatch_sequence",
    "registry_version_stale_str",
    "registry_version_stale_bool",
    "registry_version_stale_lower",
    "not_yet_valid",
    "expired",
    "invalid_bundle",
]


def _build_valid_registry():
    """Build a valid registry with two admin keys and a separate bundle signer.

    Returns (registry, org_id, sk1, sk2, sk_bundle, kid1, kid2, kid_bundle,
    u1, u2).  Threshold 2 with both admin signatures; bundle_signer key id
    is distinct from all keys in the registry.
    """
    import hashlib
    import json
    import time
    import uuid
    from nacl.signing import SigningKey
    from sandbox.protocol.envelope import canonical_bytes
    from sandbox.protocol.registry import verify_chain

    org_id = str(uuid.uuid4())
    sk1 = SigningKey.generate()
    sk2 = SigningKey.generate()
    sk_bundle = SigningKey.generate()

    pub1 = bytes(sk1.verify_key)
    pub2 = bytes(sk2.verify_key)
    pub_bundle = bytes(sk_bundle.verify_key)

    kid1 = hashlib.sha256(pub1).hexdigest()
    kid2 = hashlib.sha256(pub2).hexdigest()
    kid_bundle = hashlib.sha256(pub_bundle).hexdigest()

    u1 = str(uuid.uuid4())
    u2 = str(uuid.uuid4())

    genesis_payload = {
        "org_id": org_id,
        "version": 1,
        "prev_hash": "",
        "threshold": 2,
        "admins": [kid1, kid2],
        "keys": [
            {
                "key_id": kid1,
                "public_key": pub1.hex(),
                "user_id": u1,
                "iss": "test", "sub": "s1",
                "alg": "ed25519",
                "kind": "cli",
                "roles": ["admin", "approver"],
                "added_in": 1,
            },
            {
                "key_id": kid2,
                "public_key": pub2.hex(),
                "user_id": u2,
                "iss": "test", "sub": "s2",
                "alg": "ed25519",
                "kind": "cli",
                "roles": ["admin", "approver"],
                "added_in": 1,
            },
        ],
        "bundle_signer": {
            "key_id": kid_bundle,
            "public_key": pub_bundle.hex(),
            "alg": "ed25519",
        },
        "expires_at": time.time() + 86400,
    }

    genesis_msg = canonical_bytes("agg/registry/v1", genesis_payload)
    genesis_sig1 = sk1.sign(genesis_msg).signature.hex()
    genesis_sig2 = sk2.sign(genesis_msg).signature.hex()

    genesis_env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": genesis_payload,
        "signatures": [
            {"key_id": kid1, "alg": "ed25519", "sig": genesis_sig1},
            {"key_id": kid2, "alg": "ed25519", "sig": genesis_sig2},
        ],
    }

    fp = hashlib.sha256(
        org_id.encode() + b":" +
        json.dumps(genesis_payload, sort_keys=True,
                   separators=(",", ":")).encode()
    ).hexdigest()

    registry = verify_chain([genesis_env], fp)
    return (registry, org_id, sk1, sk2, sk_bundle,
            kid1, kid2, kid_bundle, u1, u2)


@pytest.mark.parametrize("case", _REFUSAL_CODES, ids=_REFUSAL_CODES)
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_verify_publish_refusal_codes(case):
    """verify_publish raises PublishRefused with the named code."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )

    from agg_cp.sync.publish_verify import (
        PublishRefused, verify_publish, deny_all_base,
    )
    import hashlib
    import json
    import time
    import uuid

    from nacl.signing import SigningKey
    from sandbox.connector.sync.bundles import (
        _bundle_hash, _canonical_json_bytes, BUNDLE_MAX_BYTES,
    )
    from sandbox.protocol.envelope import canonical_bytes

    (registry, org_id, sk1, sk2, sk_bundle,
     kid1, kid2, kid_bundle, u1, u2) = _build_valid_registry()

    project_id = str(uuid.uuid4())

    base_payload = deny_all_base()
    base_payload["org_id"] = org_id
    base_payload["project_id"] = project_id
    base_payload["sequence"] = 0
    base_payload["base_sequence"] = 0
    base_payload["registry_version"] = 1
    base_payload["issued_at"] = int(time.time())
    base_payload["not_before"] = int(time.time()) - 60
    base_payload["environment"] = "prod"

    good_payload = dict(base_payload)
    good_payload["sequence"] = 1
    good_payload["base_sequence"] = 0

    payload_bytes = json.dumps(good_payload, sort_keys=True,
                               separators=(",", ":")).encode()
    stored_hash = _bundle_hash(good_payload)
    now = int(time.time())

    # Build a valid approval signed by kid1
    bh = _bundle_hash(good_payload)
    a_payload = {"bundle_hash": bh}
    a_msg = canonical_bytes("agg/policy-change/v1", a_payload)
    a_sig1 = sk1.sign(a_msg).signature.hex()
    approval_env1 = {
        "kind": "agg/policy-change/v1", "sig_v": 1,
        "payload": a_payload,
        "signatures": [{"key_id": kid1, "alg": "ed25519", "sig": a_sig1}],
    }
    # Second approval signed by kid2
    a_sig2 = sk2.sign(a_msg).signature.hex()
    approval_env2 = {
        "kind": "agg/policy-change/v1", "sig_v": 1,
        "payload": a_payload,
        "signatures": [{"key_id": kid2, "alg": "ed25519", "sig": a_sig2}],
    }

    base_kwargs = dict(
        payload_bytes=payload_bytes,
        stored_hash=stored_hash,
        org_id=org_id,
        project_id=project_id,
        base_sequence=0,
        sequence=1,
        approvals=[(approval_env1, now), (approval_env2, now)],
        registry=registry,
        server_base=None,
        head=None,
        proposer_id=u2,
        publisher_id=u2,
        now=now,
    )

    def _call(**overrides):
        kw = {**base_kwargs, **overrides}
        return verify_publish(**kw)

    if case == "bad_payload_duplicate":
        dup_bytes = b'{"folder_policy": {}, "folder_policy": {}}'
        with pytest.raises(PublishRefused) as exc_info:
            _call(payload_bytes=dup_bytes,
                  stored_hash=hashlib.sha256(dup_bytes).hexdigest())
        assert exc_info.value.code == "bad_payload"
    elif case == "bad_payload_nan":
        nan_bytes = b'{"rate": NaN}'
        with pytest.raises(PublishRefused) as exc_info:
            _call(payload_bytes=nan_bytes,
                  stored_hash=hashlib.sha256(nan_bytes).hexdigest())
        assert exc_info.value.code == "bad_payload"
    elif case == "hash_mismatch":
        with pytest.raises(PublishRefused) as exc_info:
            _call(stored_hash="0" * 64)
        assert exc_info.value.code == "hash_mismatch"
    elif case == "too_large":
        big = {"data": "x" * (BUNDLE_MAX_BYTES + 100)}
        big_bytes = json.dumps(big, sort_keys=True,
                               separators=(",", ":")).encode()
        with pytest.raises(PublishRefused) as exc_info:
            _call(payload_bytes=big_bytes,
                  stored_hash=_bundle_hash(big))
        assert exc_info.value.code == "too_large"
    elif case == "unknown_fields_extra":
        bad = dict(good_payload, UNKNOWN_FIELD=True)
        bad_bytes = json.dumps(bad, sort_keys=True,
                               separators=(",", ":")).encode()
        with pytest.raises(PublishRefused) as exc_info:
            _call(payload_bytes=bad_bytes,
                  stored_hash=_bundle_hash(bad))
        assert exc_info.value.code == "unknown_fields"
    elif case == "unknown_fields_change_approvals":
        bad = dict(good_payload, change_approvals=[])
        bad_bytes = json.dumps(bad, sort_keys=True,
                               separators=(",", ":")).encode()
        with pytest.raises(PublishRefused) as exc_info:
            _call(payload_bytes=bad_bytes,
                  stored_hash=_bundle_hash(bad))
        assert exc_info.value.code == "unknown_fields"
    elif case == "binding_mismatch_org":
        with pytest.raises(PublishRefused) as exc_info:
            _call(org_id=str(uuid.uuid4()))
        assert exc_info.value.code == "binding_mismatch"
    elif case == "binding_mismatch_project":
        with pytest.raises(PublishRefused) as exc_info:
            _call(project_id=str(uuid.uuid4()))
        assert exc_info.value.code == "binding_mismatch"
    elif case == "binding_mismatch_base":
        with pytest.raises(PublishRefused) as exc_info:
            _call(base_sequence=99)
        assert exc_info.value.code == "binding_mismatch"
    elif case == "binding_mismatch_sequence":
        # payload.sequence=3, row sequence=3, base_sequence=0 -> 3 != 0+1
        bad = dict(good_payload, sequence=3)
        bad_bytes = json.dumps(bad, sort_keys=True,
                               separators=(",", ":")).encode()
        with pytest.raises(PublishRefused) as exc_info:
            _call(payload_bytes=bad_bytes,
                  stored_hash=_bundle_hash(bad),
                  sequence=3, base_sequence=0)
        assert exc_info.value.code == "binding_mismatch"
    elif case == "registry_version_stale_str":
        bad = dict(good_payload, registry_version="1")
        bad_bytes = json.dumps(bad, sort_keys=True,
                               separators=(",", ":")).encode()
        with pytest.raises(PublishRefused) as exc_info:
            _call(payload_bytes=bad_bytes,
                  stored_hash=_bundle_hash(bad))
        assert exc_info.value.code == "registry_version_stale"
    elif case == "registry_version_stale_bool":
        bad = dict(good_payload, registry_version=True)
        bad_bytes = json.dumps(bad, sort_keys=True,
                               separators=(",", ":")).encode()
        with pytest.raises(PublishRefused) as exc_info:
            _call(payload_bytes=bad_bytes,
                  stored_hash=_bundle_hash(bad))
        assert exc_info.value.code == "registry_version_stale"
    elif case == "registry_version_stale_lower":
        bad = dict(good_payload, registry_version=0)
        bad_bytes = json.dumps(bad, sort_keys=True,
                               separators=(",", ":")).encode()
        with pytest.raises(PublishRefused) as exc_info:
            _call(payload_bytes=bad_bytes,
                  stored_hash=_bundle_hash(bad))
        assert exc_info.value.code == "registry_version_stale"
    elif case == "not_yet_valid":
        bad = dict(good_payload, not_before=now + 9999)
        bad_bytes = json.dumps(bad, sort_keys=True,
                               separators=(",", ":")).encode()
        with pytest.raises(PublishRefused) as exc_info:
            _call(payload_bytes=bad_bytes,
                  stored_hash=_bundle_hash(bad))
        assert exc_info.value.code == "not_yet_valid"
    elif case == "expired":
        bad = dict(good_payload, expires_at=now - 9999)
        bad_bytes = json.dumps(bad, sort_keys=True,
                               separators=(",", ":")).encode()
        with pytest.raises(PublishRefused) as exc_info:
            _call(payload_bytes=bad_bytes,
                  stored_hash=_bundle_hash(bad))
        assert exc_info.value.code == "expired"
    elif case == "invalid_bundle":
        bad = dict(good_payload)
        bad["folder_policy"] = "not_a_dict"
        bad_bytes = json.dumps(bad, sort_keys=True,
                               separators=(",", ":")).encode()
        with pytest.raises(PublishRefused) as exc_info:
            _call(payload_bytes=bad_bytes,
                  stored_hash=_bundle_hash(bad))
        assert exc_info.value.code == "invalid_bundle"
    else:
        raise AssertionError(f"unknown case: {case}")


# ===================================================================
# sign_and_check wrong signer refused (MUST 7)
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_sign_and_check_wrong_signer_refused():
    """sign_and_check with a signing key not the registry's bundle signer:
    signer_not_in_registry.  Uses a separate bundle-signer key so
    verify_chain succeeds before sign_and_check runs."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )

    import hashlib
    import json
    import time
    import uuid
    from nacl.signing import SigningKey
    from sandbox.protocol.envelope import canonical_bytes
    from sandbox.protocol.registry import verify_chain

    from agg_cp.sync.publish_verify import PublishRefused, sign_and_check

    org_id = str(uuid.uuid4())
    sk_admin = SigningKey.generate()
    sk_bundle = SigningKey.generate()
    sk_wrong = SigningKey.generate()

    pub_admin = bytes(sk_admin.verify_key)
    pub_bundle = bytes(sk_bundle.verify_key)
    kid_admin = hashlib.sha256(pub_admin).hexdigest()
    kid_bundle = hashlib.sha256(pub_bundle).hexdigest()

    genesis_payload = {
        "org_id": org_id,
        "version": 1,
        "prev_hash": "",
        "threshold": 1,
        "admins": [kid_admin],
        "keys": [{
            "key_id": kid_admin,
            "public_key": pub_admin.hex(),
            "user_id": str(uuid.uuid4()),
            "iss": "test", "sub": "s1",
            "alg": "ed25519",
            "kind": "cli",
            "roles": ["admin"],
            "added_in": 1,
        }],
        "bundle_signer": {
            "key_id": kid_bundle,
            "public_key": pub_bundle.hex(),
            "alg": "ed25519",
        },
        "expires_at": time.time() + 86400,
    }
    genesis_msg = canonical_bytes("agg/registry/v1", genesis_payload)
    genesis_sig = sk_admin.sign(genesis_msg).signature.hex()
    genesis_env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": genesis_payload,
        "signatures": [{"key_id": kid_admin, "alg": "ed25519",
                         "sig": genesis_sig}],
    }
    fp = hashlib.sha256(
        org_id.encode() + b":" +
        json.dumps(genesis_payload, sort_keys=True,
                   separators=(",", ":")).encode()
    ).hexdigest()
    registry = verify_chain([genesis_env], fp)

    payload = {"folder_policy": {}, "org_id": org_id}

    with pytest.raises(PublishRefused) as exc_info:
        sign_and_check(payload, sk_wrong, registry)
    assert exc_info.value.code == "signer_not_in_registry"


# ===================================================================
# S2 guard: operator refusal ignores server rows (MUST 9)
# ===================================================================

def test_operator_refusal_ignores_server_rows():
    """sync/escalations.py and web/escalations.py hold no SQL naming
    policy_bundles and read no allow_requester."""
    esc_path = _EE_SRC / "sync" / "escalations.py"
    web_esc_path = _EE_SRC / "web" / "escalations.py"
    for p in (esc_path, web_esc_path):
        if not p.exists():
            continue
        source = p.read_text(encoding="utf-8")
        # No SQL mentioning policy_bundles
        assert "policy_bundles" not in source, (
            f"{p.name} mentions policy_bundles"
        )
        # allow_requester only in comments
        lines = source.split("\n")
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if "allow_requester" in stripped and not stripped.startswith("#"):
                raise AssertionError(
                    f"{p.name}:{i}: allow_requester in non-comment code"
                )


# ===================================================================
# Publish DB error mapping (MUST 14, AST)
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_db_error_mapping():
    """AST: in publish_proposal, the UniqueViolation handler (handler i)
    has a Compare between Attribute(attr='constraint_name') and the
    pinned Constant, and returns stale_base.  A later handler j > i
    (type psycopg.Error, DatabaseError, Exception, or a tuple thereof)
    calls rollback, _audit_refused with internal_error, and returns 500."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )

    proposals_path = _EE_SRC / "sync" / "proposals.py"
    source = proposals_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    # Find publish_proposal
    publish_fn = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == "publish_proposal":
                publish_fn = node
                break
    assert publish_fn is not None, "publish_proposal not found"

    _PINNED_CONSTRAINT = "policy_bundles_project_id_sequence_key"

    # Find the Try statement whose handlers include UniqueViolation
    target_try = None
    for child in ast.walk(publish_fn):
        if not isinstance(child, ast.Try):
            continue
        handler_types = []
        for h in child.handlers:
            if h.type is None:
                handler_types.append(("bare", h))
                continue
            # Unpack tuples: except (A, B)
            if isinstance(h.type, ast.Tuple):
                for elt in h.type.elts:
                    tn = elt.attr if isinstance(elt, ast.Attribute) else (
                        elt.id if isinstance(elt, ast.Name) else "")
                    handler_types.append((tn, h))
            else:
                tn = h.type.attr if isinstance(h.type, ast.Attribute) else (
                    h.type.id if isinstance(h.type, ast.Name) else "")
                handler_types.append((tn, h))
        names = [t[0] for t in handler_types]
        if "UniqueViolation" in names:
            target_try = child
            break

    assert target_try is not None, (
        "publish_proposal has no try with a UniqueViolation handler"
    )

    # Collect handlers with their index for order checking
    uv_idx = None
    generic_idx = None
    generic_names = {"Exception", "Error", "DatabaseError",
                     "OperationalError", "BaseException", "psycopg.Error"}

    for idx, handler in enumerate(target_try.handlers):
        # Determine all type names for this handler (including tuple members)
        htype_names = set()
        if handler.type is None:
            htype_names.add("bare")
        elif isinstance(handler.type, ast.Tuple):
            for elt in handler.type.elts:
                if isinstance(elt, ast.Attribute):
                    htype_names.add(elt.attr)
                elif isinstance(elt, ast.Name):
                    htype_names.add(elt.id)
        else:
            if isinstance(handler.type, ast.Attribute):
                htype_names.add(handler.type.attr)
            elif isinstance(handler.type, ast.Name):
                htype_names.add(handler.type.id)

        if "UniqueViolation" in htype_names:
            uv_idx = idx
            # Check: a single Compare node contains BOTH
            # Attribute(attr='constraint_name') AND
            # Constant(value=_PINNED_CONSTRAINT).
            has_compare = False
            has_stale_base = False
            for n in ast.walk(handler):
                if isinstance(n, ast.Compare):
                    has_attr = False
                    has_const = False
                    for child_node in ast.walk(n):
                        if (isinstance(child_node, ast.Attribute)
                                and child_node.attr == "constraint_name"):
                            has_attr = True
                        if (isinstance(child_node, ast.Constant)
                                and child_node.value == _PINNED_CONSTRAINT):
                            has_const = True
                    if has_attr and has_const:
                        has_compare = True
                if isinstance(n, ast.Constant) and n.value == "stale_base":
                    has_stale_base = True
            assert has_compare, (
                "UniqueViolation handler does not compare "
                f"constraint_name to '{_PINNED_CONSTRAINT}'"
            )
            assert has_stale_base, (
                "UniqueViolation handler does not return stale_base"
            )

        if htype_names & generic_names:
            generic_idx = idx
            handler_src = ast.get_source_segment(source, handler) or ""
            assert "rollback" in handler_src, (
                "generic DB error handler does not call rollback"
            )
            assert "_audit_refused" in handler_src, (
                "generic DB error handler does not call _audit_refused"
            )
            assert "internal_error" in handler_src, (
                "generic DB error handler does not use 'internal_error'"
            )
            assert "500" in handler_src, (
                "generic DB error handler does not return 500"
            )

    assert uv_idx is not None, "UniqueViolation handler not found"
    assert generic_idx is not None, "generic DB error handler not found"
    assert generic_idx > uv_idx, (
        f"generic handler (idx {generic_idx}) must come after "
        f"UniqueViolation handler (idx {uv_idx})"
    )


# ===================================================================
# Server label insert only in publish (SHOULD 3)
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_server_label_insert_only_in_publish():
    """Exactly one INSERT INTO policy_bundles naming 'server' in ee/src,
    inside publish_proposal; no UPDATE or DELETE of policy_bundles in ee/src.
    Uses AST to check string constants (handles joined literals)."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )

    server_inserts = []  # (file, enclosing_func)
    update_count = 0
    delete_count = 0

    for pyfile in _EE_SRC.rglob("*.py"):
        if "migrations" in str(pyfile):
            continue
        source = pyfile.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        rel = str(pyfile.relative_to(_EE_SRC))

        # Collect all string constants for UPDATE/DELETE checks
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val_lower = node.value.lower()
                if "update policy_bundles" in val_lower:
                    update_count += 1
                if "delete from policy_bundles" in val_lower:
                    delete_count += 1

        # For INSERT INTO policy_bundles with 'server': attribute to
        # the INNERMOST function using _walk_no_inner_funcs (so a router
        # function containing nested defs is not counted for a child's
        # insert).  Count as server when the SQL literal holds 'server'
        # OR a "server" string constant is among the Call's args.
        for func_node in ast.walk(tree):
            if not isinstance(func_node, (ast.FunctionDef,
                                          ast.AsyncFunctionDef)):
                continue
            found_server_insert = False
            for child in _walk_no_inner_funcs(func_node):
                if not isinstance(child, ast.Call):
                    continue
                # Look for a string constant in this Call's arguments
                # that contains INSERT INTO policy_bundles
                sql_const = None
                for arg in ast.walk(child):
                    if (isinstance(arg, ast.Constant)
                            and isinstance(arg.value, str)
                            and "INSERT INTO policy_bundles" in arg.value):
                        sql_const = arg.value
                        break
                if sql_const is None:
                    continue
                # Check if 'server' is in the SQL or among the args
                has_server = "'server'" in sql_const
                if not has_server:
                    for arg in ast.walk(child):
                        if (isinstance(arg, ast.Constant)
                                and arg.value == "server"):
                            has_server = True
                            break
                if has_server:
                    found_server_insert = True
                    break
            if found_server_insert:
                server_inserts.append((rel, func_node.name))

    assert len(server_inserts) == 1, (
        f"expected 1 INSERT INTO policy_bundles with 'server', "
        f"found {len(server_inserts)}: {server_inserts}"
    )
    assert server_inserts[0][1] == "publish_proposal", (
        f"server INSERT must be in publish_proposal, found in "
        f"{server_inserts[0][1]} ({server_inserts[0][0]})"
    )
    assert update_count == 0, (
        f"found {update_count} UPDATE policy_bundles in ee/src"
    )
    assert delete_count == 0, (
        f"found {delete_count} DELETE FROM policy_bundles in ee/src"
    )


# ===================================================================
# Direct publish uses shared body reader (SHOULD 5)
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_direct_publish_uses_shared_body_reader():
    """sync/bundles.py defines no capped reader and imports
    _read_body_capped and _strict_json_parse from sync/proposals.py."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )

    bundles_path = _EE_SRC / "sync" / "bundles.py"
    source = bundles_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    # Must NOT define _read_body_capped or _strict_json_parse
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            assert node.name not in ("_read_body_capped", "_strict_json_parse"), (
                f"bundles.py defines {node.name} -- must import from proposals"
            )

    # Must import both from proposals
    imports_reader = False
    imports_parser = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module and "proposals" in node.module:
                for alias in node.names:
                    if alias.name == "_read_body_capped":
                        imports_reader = True
                    if alias.name == "_strict_json_parse":
                        imports_parser = True
    assert imports_reader, "bundles.py must import _read_body_capped from proposals"
    assert imports_parser, "bundles.py must import _strict_json_parse from proposals"


# ===================================================================
# compose.override.yml content (SHOULD 12)
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_compose_override_only_flag_env():
    """ee/deploy/compose.override.yml parses to exactly
    {services: {api: {environment: {AGG_DEPLOY_PROFILE: demo,
     AGG_ALLOW_DIRECT_PUBLISH: "1"}}}}."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )

    import yaml
    override_path = _DEPLOY / "compose.override.yml"
    assert override_path.exists(), "compose.override.yml does not exist"
    content = yaml.safe_load(override_path.read_text(encoding="utf-8"))
    expected = {
        "services": {
            "api": {
                "environment": {
                    "AGG_DEPLOY_PROFILE": "demo",
                    "AGG_ALLOW_DIRECT_PUBLISH": "1",
                }
            }
        }
    }
    assert content == expected, (
        f"compose.override.yml content mismatch:\n"
        f"  got: {content}\n  expected: {expected}"
    )


# ===================================================================
# Cursor naive read as UTC (SHOULD, SQ-4)
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_cursor_naive_read_as_utc():
    """proposals._parse_cursor("2026-11-18T10:00") is aware UTC;
    a |<id> part that is not a canonical UUID is refused."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )

    from datetime import datetime, timezone
    from agg_cp.sync.proposals import _parse_cursor
    import uuid

    # Naive timestamp should be read as UTC.
    # Spec: _parse_cursor returns (aware UTC datetime, id or None).
    result = _parse_cursor("2026-11-18T10:00")
    assert isinstance(result, tuple), (
        f"_parse_cursor must return a tuple, got {type(result).__name__}"
    )
    ts, cursor_id = result
    assert ts == datetime(2026, 11, 18, 10, 0, tzinfo=timezone.utc), (
        f"naive cursor must be 2026-11-18T10:00 UTC, got {ts!r}"
    )
    assert cursor_id is None, (
        f"cursor without |<id> must have None as second element, "
        f"got {cursor_id!r}"
    )

    # A |<id> with a good canonical UUID should work
    good_id = str(uuid.uuid4())
    result2 = _parse_cursor(f"2026-11-18T10:00|{good_id}")
    assert isinstance(result2, tuple)
    ts2, cid2 = result2
    assert ts2 == datetime(2026, 11, 18, 10, 0, tzinfo=timezone.utc)
    assert cid2 == good_id, (
        f"cursor id must be {good_id!r}, got {cid2!r}"
    )

    # Non-canonical UUID (braced) must be refused
    with pytest.raises(ValueError):
        _parse_cursor(f"2026-11-18T10:00|{{{good_id}}}")

    # Uppercase UUID must be refused
    with pytest.raises(ValueError):
        _parse_cursor(f"2026-11-18T10:00|{good_id.upper()}")

    # urn form must be refused
    with pytest.raises(ValueError):
        _parse_cursor(f"2026-11-18T10:00|urn:uuid:{good_id}")

    # Unparseable time must be refused
    with pytest.raises(ValueError):
        _parse_cursor("not-a-timestamp")

    # Aware cursors whose UTC conversion overflows must raise ValueError
    # (spec 2.9: never 500).
    with pytest.raises(ValueError):
        _parse_cursor("9999-12-31T23:59:59-23:59")
    with pytest.raises(ValueError):
        _parse_cursor("0001-01-01T00:00:00+23:59")
