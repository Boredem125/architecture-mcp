"""Tests for the path-containment primitive (sandbox.fs.containment).

These cover the exact escapes the old prefix-compare checks missed.
"""
from __future__ import annotations

import os
import sys

import pytest

from sandbox.fs.containment import is_contained, resolve_under

_WINDOWS = sys.platform == "win32"


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "jail"
    r.mkdir()
    return r


def test_simple_child_is_contained(root):
    assert is_contained(root, "file.txt")
    assert is_contained(root, "sub/deep/file.txt")


def test_existing_child_resolves(root):
    (root / "a").mkdir()
    (root / "a" / "b.txt").write_text("x", encoding="utf-8")
    resolved = resolve_under(root, "a/b.txt")
    assert resolved is not None
    assert resolved.name == "b.txt"


def test_parent_traversal_escapes(root):
    assert not is_contained(root, "../secret.txt")
    assert not is_contained(root, "../../etc/passwd")
    assert not is_contained(root, "a/../../escape.txt")


def test_prefix_aliasing_is_not_containment(root, tmp_path):
    # A sibling dir sharing a name prefix must NOT count as inside.
    sibling = tmp_path / "jail-evil"
    sibling.mkdir()
    assert not is_contained(root, str(sibling / "x.txt"))


def test_absolute_outside_rejected(root, tmp_path):
    outside = tmp_path / "other" / "f.txt"
    assert not is_contained(root, str(outside))


def test_root_itself_is_contained(root):
    assert is_contained(root, ".")
    assert resolve_under(root, ".") is not None


def test_base_join_for_relative(root):
    (root / "cwd").mkdir()
    # relative target joined against base=cwd stays inside
    assert is_contained(root, "note.txt", base=root / "cwd")
    # but climbing out of base past root is caught
    assert not is_contained(root, "../../x", base=root / "cwd")


@pytest.mark.skipif(not _WINDOWS, reason="Windows case-insensitivity")
def test_case_insensitive_containment(root):
    weird = str(root).upper() + os.sep + "File.TXT"
    assert is_contained(root, weird)


@pytest.mark.skipif(not _WINDOWS, reason="Windows-specific path forms")
@pytest.mark.parametrize(
    "bad",
    [
        r"\\server\share\x.txt",   # UNC
        r"\\?\C:\Windows\x.txt",   # device namespace
        r"\\.\PhysicalDrive0",      # device namespace
        "C:relative.txt",           # drive-relative
        "file.txt:hidden",          # alternate data stream
    ],
)
def test_windows_exotic_paths_rejected(root, bad):
    assert not is_contained(root, bad)


@pytest.mark.skipif(not _WINDOWS, reason="junctions need Windows")
def test_junction_ancestor_escape_rejected(root, tmp_path):
    """A junction inside the jail pointing outside must not grant access."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("s", encoding="utf-8")
    link = root / "link"
    rc = os.system(f'cmd /c mklink /J "{link}" "{outside}" >nul 2>nul')
    if rc != 0 or not link.exists():
        pytest.skip("could not create junction (needs privilege)")
    # Target technically resolves under root by string, but crosses a junction.
    assert not is_contained(root, "link/secret.txt")
