"""FolderRecorder — content-addressed snapshot storage."""
from __future__ import annotations

from pathlib import Path

from sandbox.connector.recorder import FolderRecorder


def test_snapshot_creates_original(tmp_path):
    """Snapshot a file and store its original."""
    jail = tmp_path / "jail"
    jail.mkdir()
    originals = tmp_path / "originals"

    # Create a file to snapshot
    (jail / "app.py").write_text("print('hello')")

    recorder = FolderRecorder(jail, session_id="s-test", originals_dir=originals)
    snapshot = recorder.snapshot_file("app.py", reason="test snapshot")

    assert snapshot is not None
    assert snapshot["rel_path"] == "app.py"
    assert snapshot["size"] > 0
    assert snapshot["sha256"]
    assert snapshot["original_hash"]

    # Verify the original was stored
    assert (originals / snapshot["original_hash"].split("/")[0]).exists()


def test_snapshot_deduplicates_by_hash(tmp_path):
    """Same file content stored once, not duplicated."""
    jail = tmp_path / "jail"
    jail.mkdir()
    originals = tmp_path / "originals"

    # Create two files with identical content
    (jail / "a.py").write_text("x = 1")
    (jail / "b.py").write_text("x = 1")

    recorder = FolderRecorder(jail, originals_dir=originals)
    snap_a = recorder.snapshot_file("a.py")
    snap_b = recorder.snapshot_file("b.py")

    # Both should have the same hash
    assert snap_a["sha256"] == snap_b["sha256"]
    # And point to the same original
    assert snap_a["original_hash"] == snap_b["original_hash"]


def test_finalize_detects_modification(tmp_path):
    """Re-stat a file after edit to detect modifications."""
    jail = tmp_path / "jail"
    jail.mkdir()
    originals = tmp_path / "originals"

    (jail / "app.py").write_text("v1")

    recorder = FolderRecorder(jail, originals_dir=originals)
    snap_before = recorder.snapshot_file("app.py")
    assert snap_before is not None
    sha_before = snap_before["sha256"]

    # Edit the file
    (jail / "app.py").write_text("v1 updated")

    snap_after = recorder.finalize_file("app.py")
    assert snap_after["verdict"] == "modified"
    assert snap_after["sha256"] != sha_before


def test_finalize_detects_deletion(tmp_path):
    """Finalize detects a deleted file."""
    jail = tmp_path / "jail"
    jail.mkdir()

    (jail / "app.py").write_text("content")
    recorder = FolderRecorder(jail)

    # Delete the file
    (jail / "app.py").unlink()

    final = recorder.finalize_file("app.py")
    assert final["verdict"] == "deleted"
    assert "sha256" not in final


def test_snapshot_respects_containment(tmp_path):
    """Snapshot rejects paths outside the jail."""
    jail = tmp_path / "jail"
    jail.mkdir()
    (tmp_path / "outside.txt").write_text("secret")

    recorder = FolderRecorder(jail)
    result = recorder.snapshot_file("../outside.txt")

    # Should fail containment
    assert result is None
