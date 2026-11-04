"""T17 quickstart smoke: the two first-run problems the clean-checkout follow hit.

1. ``demo/try.py`` prints non-ASCII glyphs; with stdout piped on Windows the
   default encoding is cp1252 and the first print raised ``UnicodeEncodeError``.
   It must survive a cp1252 stdout and still print the decision.
2. ``sandbox init`` printed ``SyntaxWarning: invalid escape sequence`` (a backslash-s in an f-string) from
   ``src/sandbox/cli/connector_cmds.py`` on first compile. The module must compile
   with SyntaxWarning promoted to an error.
"""
from __future__ import annotations

import os
import subprocess
import sys
import warnings
from pathlib import Path

from click.testing import CliRunner

from sandbox.cli.main import cli

REPO = Path(__file__).resolve().parents[2]
TRY_PY = REPO / "demo" / "try.py"


def test_try_py_survives_cp1252_piped_stdout(tmp_path):
    r = CliRunner().invoke(cli, ["init", str(tmp_path), "--no-claude", "--no-mcp"])
    assert r.exit_code == 0, r.output
    env = dict(os.environ, PYTHONIOENCODING="cp1252", PYTHONUTF8="0")
    # The preset's target is a Windows path; on POSIX it would be a relative file inside the
    # project (allowed), so use an absolute path outside the root there. The encoding is
    # forced to cp1252 on both, which is what the fix is for.
    call = ["preset", "write-outside"] if os.name == "nt" else ["write", "/etc/evil.txt", "x"]
    proc = subprocess.run(
        [sys.executable, str(TRY_PY), *call, "--dir", str(tmp_path)],
        cwd=str(tmp_path), env=env, capture_output=True, timeout=120,
    )
    out = proc.stdout.decode("utf-8", errors="replace")
    err = proc.stderr.decode("utf-8", errors="replace")
    assert "UnicodeEncodeError" not in err, err[-600:]
    assert proc.returncode == 0, (proc.returncode, err[-600:])
    assert "WRITE_OUTSIDE" in out, out[-600:]


def test_connector_cmds_compiles_without_syntax_warning():
    import sandbox.cli.connector_cmds as mod

    src = Path(mod.__file__).read_text(encoding="utf-8")
    with warnings.catch_warnings():
        warnings.simplefilter("error", SyntaxWarning)
        compile(src, mod.__file__, "exec")
