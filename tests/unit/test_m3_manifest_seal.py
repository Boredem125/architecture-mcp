"""M3 manifest seal test: pins the T0a frozen manifest.

Asserts:
1. ``M3_T0A_MANIFEST.sha256`` sha256 (over LF-normalised bytes) equals a
   constant.
2. Every sealed line appears **unchanged** in ``M3_FROZEN_MANIFEST.sha256``.
3. A tampered copy of a sealed line is detected: xor 0x01 on one hash byte,
   ``assert new != old``.
4. The current manifest has no duplicate paths.

Works in ``pytest``, ``ee``-less ``connector-standalone`` (``ee/`` removed;
``docs/`` stays) and on Windows CRLF working copies.  This is NOT a sentinel
test; it passes now.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CONTROL = REPO / "docs" / "control-plane"
SEAL = CONTROL / "M3_T0A_MANIFEST.sha256"
MANIFEST = CONTROL / "M3_FROZEN_MANIFEST.sha256"

# Precomputed over LF-normalised bytes of the 203-line T0a manifest.
# Regenerate: git show c15aba3:docs/control-plane/M3_FROZEN_MANIFEST.sha256 | sha256sum
EXPECTED_SEAL_SHA256 = (
    "965f9343333bd79c2898fd6bdfcd0b73700780215b7b87c0503d702706dd951e"
)


def _lf_bytes(path: Path) -> bytes:
    """Read *path* and normalise to LF line endings.

    Handles Windows CRLF working copies so the hash is stable.
    """
    raw = path.read_bytes()
    return raw.replace(b"\r\n", b"\n")


def _parse_lines(text: str) -> list[str]:
    """Return non-empty stripped lines from sha256sum-format text."""
    return [l.strip() for l in text.splitlines() if l.strip()]


def _parse_path(line: str) -> str:
    """Extract the file path from a sha256sum-format line."""
    parts = line.split("  ", 1)
    return parts[1] if len(parts) == 2 else ""


# ---------------------------------------------------------------------------
# 1. Seal sha256 equals a constant
# ---------------------------------------------------------------------------


class TestSealHash:
    """The seal file's sha256 over LF bytes equals the pinned constant."""

    def test_seal_exists(self) -> None:
        assert SEAL.is_file(), f"Missing seal file: {SEAL}"

    def test_seal_sha256(self) -> None:
        lf = _lf_bytes(SEAL)
        actual = hashlib.sha256(lf).hexdigest()
        assert actual == EXPECTED_SEAL_SHA256, (
            f"Seal sha256 mismatch:\n"
            f"  expected: {EXPECTED_SEAL_SHA256}\n"
            f"  actual:   {actual}\n"
            f"If this is intentional, update EXPECTED_SEAL_SHA256."
        )

    def test_seal_line_count(self) -> None:
        lf = _lf_bytes(SEAL).decode("utf-8")
        lines = _parse_lines(lf)
        assert len(lines) == 203, f"Seal must have 203 lines, got {len(lines)}"


# ---------------------------------------------------------------------------
# 2. Every sealed line unchanged in the current manifest
# ---------------------------------------------------------------------------


class TestSealedLinesUnchanged:
    """Every line in the seal appears byte-identical in the current manifest."""

    def test_manifest_exists(self) -> None:
        assert MANIFEST.is_file(), f"Missing manifest: {MANIFEST}"

    def test_every_sealed_line_in_manifest(self) -> None:
        seal_text = _lf_bytes(SEAL).decode("utf-8")
        manifest_text = _lf_bytes(MANIFEST).decode("utf-8")

        seal_lines = set(_parse_lines(seal_text))
        manifest_lines = set(_parse_lines(manifest_text))

        missing = seal_lines - manifest_lines
        assert not missing, (
            f"{len(missing)} sealed lines missing or changed in manifest:\n"
            + "\n".join(sorted(missing)[:10])
        )

    def test_manifest_is_superset_of_seal(self) -> None:
        """The manifest may have more lines (new tasks) but never fewer sealed ones."""
        seal_text = _lf_bytes(SEAL).decode("utf-8")
        manifest_text = _lf_bytes(MANIFEST).decode("utf-8")

        seal_count = len(_parse_lines(seal_text))
        manifest_count = len(_parse_lines(manifest_text))
        assert manifest_count >= seal_count, (
            f"Manifest ({manifest_count} lines) must be >= seal ({seal_count} lines)"
        )


# ---------------------------------------------------------------------------
# 3. Tamper detection: xor 0x01 on one hash byte
# ---------------------------------------------------------------------------


class TestTamperDetection:
    """Verify the checker catches a single-byte alteration."""

    def test_tampered_line_detected(self) -> None:
        """Take the first sealed line, xor 0x01 on byte 0 of the hash,
        assert new != old, then confirm it is NOT in the manifest."""
        seal_text = _lf_bytes(SEAL).decode("utf-8")
        manifest_text = _lf_bytes(MANIFEST).decode("utf-8")

        seal_lines = _parse_lines(seal_text)
        manifest_set = set(_parse_lines(manifest_text))

        assert len(seal_lines) > 0, "Seal file is empty"
        original_line = seal_lines[0]

        # Extract the hash portion (first 64 hex chars)
        hash_hex = original_line[:64]
        rest = original_line[64:]

        # XOR first byte
        hash_bytes = bytearray(bytes.fromhex(hash_hex))
        old_byte = hash_bytes[0]
        hash_bytes[0] = hash_bytes[0] ^ 0x01
        assert hash_bytes[0] != old_byte, "xor 0x01 must change the byte"

        tampered_hex = hash_bytes.hex()
        tampered_line = tampered_hex + rest

        assert tampered_line != original_line, (
            "Tampered line must differ from original"
        )
        assert tampered_line not in manifest_set, (
            "Tampered line must NOT appear in the manifest"
        )

    def test_tampered_hash_differs_from_original(self) -> None:
        """Explicitly show that the tampered hash is a different value."""
        seal_text = _lf_bytes(SEAL).decode("utf-8")
        seal_lines = _parse_lines(seal_text)
        assert len(seal_lines) > 0

        original_line = seal_lines[0]
        original_hash = original_line[:64]

        tampered_bytes = bytearray(bytes.fromhex(original_hash))
        old = tampered_bytes[0]
        tampered_bytes[0] ^= 0x01
        new = tampered_bytes[0]
        assert new != old, "xor 0x01 must change the byte value"

        tampered_hash = tampered_bytes.hex()
        assert tampered_hash != original_hash, (
            f"Tampered hash must differ: {tampered_hash} vs {original_hash}"
        )


# ---------------------------------------------------------------------------
# 4. No duplicate paths in the current manifest
# ---------------------------------------------------------------------------


class TestNoDuplicatePaths:
    """The current manifest must not have duplicate file paths."""

    def test_no_duplicate_paths(self) -> None:
        manifest_text = _lf_bytes(MANIFEST).decode("utf-8")
        lines = _parse_lines(manifest_text)

        paths = [_parse_path(l) for l in lines]
        seen: dict[str, int] = {}
        dupes: list[str] = []
        for p in paths:
            if not p:
                continue
            seen[p] = seen.get(p, 0) + 1
            if seen[p] == 2:
                dupes.append(p)

        assert not dupes, (
            f"{len(dupes)} duplicate path(s) in manifest: "
            + ", ".join(dupes[:10])
        )
