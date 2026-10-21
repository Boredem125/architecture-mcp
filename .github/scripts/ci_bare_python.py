"""Pytest plugin: wire a CI-provided bare Python to sys._base_executable.

SEC-27/28 tests need a dependency-free interpreter.  On CI Windows the
embeddable CPython zip fills that role.  Setting BARE_PYTHON in the
environment and loading this plugin with ``-p ci_bare_python`` injects
the path before test modules are imported (pytest_configure runs before
collection), so the frozen skipif at module level sees the bare
interpreter.
"""
from __future__ import annotations

import os
import sys


def pytest_configure(config):  # noqa: ARG001 – pytest hook
    bare = os.environ.get("BARE_PYTHON")
    if bare and os.path.isfile(bare):
        sys._base_executable = bare
