"""ee/ test configuration.

Mirrors the root conftest's key-home isolation so ee/ tests that touch
the connector's signing layer do not write the real user directory.
"""
from __future__ import annotations

import os
import sys

import pytest

# Ensure src/ is importable (for the sandbox package) when running
# ee/tests in isolation.
_ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "src")
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
