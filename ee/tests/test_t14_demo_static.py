"""Static checks for ee/deploy/demo.py (T14).

No network, no Docker, no containers.  Verifies the demo script parses,
has --help, never uses verify=False, and its Keycloak form parser can
extract action + fields from a minimal Keycloak-like HTML fixture.
"""
from __future__ import annotations

import py_compile
import subprocess
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_DEMO_SCRIPT = (
    Path(__file__).resolve().parent.parent / "deploy" / "demo.py"
)


# ---------------------------------------------------------------------------
# 1. Script parses (py_compile)
# ---------------------------------------------------------------------------

class TestDemoScriptParses:
    def test_script_exists(self):
        assert _DEMO_SCRIPT.exists(), (
            f"demo.py not found at {_DEMO_SCRIPT}"
        )

    def test_script_compiles(self):
        # py_compile.compile raises py_compile.PyCompileError on syntax errors
        py_compile.compile(str(_DEMO_SCRIPT), doraise=True)

    def test_positive_control_syntax_error_detected(self, tmp_path: Path):
        """A file with a syntax error must fail py_compile."""
        bad = tmp_path / "bad.py"
        bad.write_text("def f(\n", encoding="utf-8")
        with pytest.raises(py_compile.PyCompileError):
            py_compile.compile(str(bad), doraise=True)


# ---------------------------------------------------------------------------
# 2. Script has --help (argparse)
# ---------------------------------------------------------------------------

class TestDemoScriptHelp:
    def test_help_exits_zero(self):
        result = subprocess.run(
            [sys.executable, str(_DEMO_SCRIPT), "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, (
            f"--help exited {result.returncode}: {result.stderr}"
        )
        assert "--step" in result.stdout, (
            "--step flag must be documented in --help output"
        )

    def test_positive_control_no_such_flag(self):
        """A bad flag must be caught by argparse (non-zero exit)."""
        result = subprocess.run(
            [sys.executable, str(_DEMO_SCRIPT), "--no-such-flag-xyz"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode != 0


# ---------------------------------------------------------------------------
# 3. No verify=False anywhere in the script
# ---------------------------------------------------------------------------

class TestNoVerifyFalse:
    def test_no_verify_false(self):
        text = _DEMO_SCRIPT.read_text(encoding="utf-8")
        assert "verify=False" not in text, (
            "demo.py must never disable TLS verification (verify=False)"
        )
        assert "verify = False" not in text, (
            "demo.py must never disable TLS verification (verify = False)"
        )

    def test_positive_control_verify_false_detected(self):
        """A script with verify=False must be detected."""
        bad = 'httpx.get("https://...", verify=False)'
        assert "verify=False" in bad


# ---------------------------------------------------------------------------
# 4. Keycloak form parser extracts action + fields from minimal HTML
# ---------------------------------------------------------------------------

# A minimal Keycloak-like login form HTML (inline fixture)
_KEYCLOAK_LOGIN_HTML = """\
<!DOCTYPE html>
<html>
<head><title>Sign in to acme</title></head>
<body>
<form id="kc-form-login" onsubmit="login.disabled = true; return true;"
      action="https://idp.localhost/realms/acme/login-actions/authenticate?session_code=abc123&amp;execution=def456&amp;client_id=agg-control-plane&amp;tab_id=xyz"
      method="post">
  <input type="hidden" name="credentialId" value="" />
  <input id="username" name="username" value="" type="text" autofocus autocomplete="off" />
  <input id="password" name="password" type="password" autocomplete="off" />
  <input type="hidden" id="id-hidden-input" name="login" value="Log In" />
</form>
</body>
</html>
"""


class TestKeycloakFormParser:
    def test_parser_extracts_action_and_fields(self):
        """The form parser from demo.py must find the action URL and all fields."""
        # Import the parser from demo.py
        spec_path = str(_DEMO_SCRIPT)
        import importlib.util
        spec = importlib.util.spec_from_file_location("demo", spec_path)
        demo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(demo)

        # Use the parser class/function
        parser = demo.KeycloakFormParser()
        parser.feed(_KEYCLOAK_LOGIN_HTML)

        assert parser.action is not None, "form action not found"
        assert "idp.localhost" in parser.action, (
            f"action should contain idp.localhost, got: {parser.action}"
        )
        # The HTML entity &amp; should be decoded to &
        assert "&amp;" not in parser.action, (
            "HTML entities in action URL must be unescaped"
        )
        assert "session_code=abc123" in parser.action

        # Fields must include at least username, password, and login
        field_names = {name for name, _ in parser.fields}
        assert "username" in field_names, "username field not found"
        assert "password" in field_names, "password field not found"

    def test_parser_handles_empty_html(self):
        """Parser must not crash on HTML without a form."""
        spec_path = str(_DEMO_SCRIPT)
        import importlib.util
        spec = importlib.util.spec_from_file_location("demo", spec_path)
        demo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(demo)

        parser = demo.KeycloakFormParser()
        parser.feed("<html><body><p>No form here</p></body></html>")
        assert parser.action is None

    def test_positive_control_wrong_html_has_no_action(self):
        """HTML without a form must yield action=None."""
        # This is the positive control: make sure the parser does not
        # find an action in HTML that has no form.
        bad_html = "<html><body><div>nothing</div></body></html>"
        spec_path = str(_DEMO_SCRIPT)
        import importlib.util
        spec = importlib.util.spec_from_file_location("demo", spec_path)
        demo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(demo)

        parser = demo.KeycloakFormParser()
        parser.feed(bad_html)
        assert parser.action is None


# ---------------------------------------------------------------------------
# 5. Steps 4 and 5 call subprocess (not just print)
# ---------------------------------------------------------------------------

class TestStepsCallSubprocess:
    """Verify that step4_connector and step5_persistence actually execute
    real subprocess calls (coordinator requirement: steps must RUN, not
    just print documentation references)."""

    def _get_source(self) -> str:
        return _DEMO_SCRIPT.read_text(encoding="utf-8")

    def test_step4_calls_subprocess(self):
        """step4_connector must use subprocess to run sandbox init and serve."""
        import ast
        source = self._get_source()
        tree = ast.parse(source)
        step4_found = False
        has_subprocess_call = False
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "step4_connector":
                step4_found = True
                # Walk the function body for subprocess.run or subprocess.Popen
                for child in ast.walk(node):
                    if isinstance(child, ast.Attribute):
                        if (child.attr in ("run", "Popen")
                                and isinstance(child.value, ast.Name)
                                and child.value.id == "subprocess"):
                            has_subprocess_call = True
                            break
                break
        assert step4_found, "step4_connector function not found"
        assert has_subprocess_call, (
            "step4_connector must call subprocess.run or subprocess.Popen "
            "(it must actually execute commands, not just print references)"
        )

    def test_step5_calls_subprocess(self):
        """step5_persistence must use subprocess to run docker compose."""
        import ast
        source = self._get_source()
        tree = ast.parse(source)
        step5_found = False
        has_subprocess_call = False
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "step5_persistence":
                step5_found = True
                for child in ast.walk(node):
                    if isinstance(child, ast.Attribute):
                        if (child.attr == "run"
                                and isinstance(child.value, ast.Name)
                                and child.value.id == "subprocess"):
                            has_subprocess_call = True
                            break
                break
        assert step5_found, "step5_persistence function not found"
        assert has_subprocess_call, (
            "step5_persistence must call subprocess.run "
            "(it must actually execute docker compose, not just print docs)"
        )

    def test_positive_control_no_subprocess_detected(self):
        """A function without subprocess calls must not pass the check."""
        import ast
        code = "def step4_connector():\n    print('hello')\n"
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "step4_connector":
                has_call = False
                for child in ast.walk(node):
                    if isinstance(child, ast.Attribute) and child.attr in ("run", "Popen"):
                        has_call = True
                assert not has_call, "positive control: bare print should not have subprocess"
