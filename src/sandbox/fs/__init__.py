"""Filesystem primitives shared across the sandbox.

Currently exposes the one true path-containment check used by the jail,
the agent toolkit, the process sandbox, and the folder connector.
"""
from __future__ import annotations

from sandbox.fs.containment import (
    ContainmentError,
    has_reparse_point,
    is_contained,
    resolve_under,
)

__all__ = [
    "ContainmentError",
    "has_reparse_point",
    "is_contained",
    "resolve_under",
]
