"""Secret pattern matching per AGENT_04 spec.

Scans text for credentials, tokens, private keys, connection strings,
JWTs, and high-entropy strings that may be secrets.  Provides both
detection and redaction capabilities.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import TypedDict


class SecretMatch(TypedDict):
    """A single detected secret occurrence."""

    type: str
    position: int
    length: int


# ---------------------------------------------------------------------------
# Secret patterns
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class _SecretPattern:
    """Compiled regex plus metadata for one secret type."""

    name: str
    pattern: re.Pattern[str]


_SECRET_PATTERNS: list[_SecretPattern] = [
    # AWS Access Key IDs (always start with AKIA)
    _SecretPattern(
        name="aws_access_key",
        pattern=re.compile(r"(?<![A-Za-z0-9/+=])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])"),
    ),
    # AWS Secret Access Keys (40-char base64-ish after an access key context)
    _SecretPattern(
        name="aws_secret_key",
        pattern=re.compile(
            r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"
        ),
    ),
    # GitHub personal access tokens (classic: ghp_, OAuth: gho_)
    _SecretPattern(
        name="github_token",
        pattern=re.compile(r"(?<!\w)ghp_[A-Za-z0-9]{36,}(?!\w)"),
    ),
    _SecretPattern(
        name="github_token",
        pattern=re.compile(r"(?<!\w)gho_[A-Za-z0-9]{36,}(?!\w)"),
    ),
    # GitHub fine-grained PATs
    _SecretPattern(
        name="github_pat",
        pattern=re.compile(r"(?<!\w)github_pat_[A-Za-z0-9_]{22,}(?!\w)"),
    ),
    # Private key blocks (PEM format)
    _SecretPattern(
        name="private_key",
        pattern=re.compile(
            r"-----BEGIN\s[A-Z\s]*PRIVATE\sKEY-----"
            r"[\s\S]*?"
            r"-----END\s[A-Z\s]*PRIVATE\sKEY-----",
        ),
    ),
    # Connection strings with embedded passwords  (scheme://user:pass@host)
    _SecretPattern(
        name="connection_string",
        pattern=re.compile(
            r"[a-zA-Z][a-zA-Z0-9+\-.]*://[^:@\s]+:[^@\s]+@[^\s]+"
        ),
    ),
    # JWT tokens  (three dot-separated base64url segments)
    _SecretPattern(
        name="jwt_token",
        pattern=re.compile(
            r"(?<!\w)"
            r"eyJ[A-Za-z0-9_-]{10,}"     # header (always starts eyJ)
            r"\."
            r"[A-Za-z0-9_-]{10,}"         # payload
            r"\."
            r"[A-Za-z0-9_-]{10,}"         # signature
            r"(?!\w)",
        ),
    ),
]

# High-entropy threshold for generic secret detection.
_ENTROPY_THRESHOLD: float = 4.5
_ENTROPY_MIN_LENGTH: int = 32

# Tokens to skip in generic entropy scan (common encodings, UUIDs, hashes).
_ENTROPY_SKIP_PATTERN = re.compile(
    r"^(?:"
    r"[0-9a-fA-F]{32,}"       # hex hashes
    r"|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"  # UUIDs
    r")$",
)


class SecretScanner:
    """Scans text for embedded secrets and credentials.

    Combines specific regex patterns for known credential formats with
    a generic high-entropy string detector for unknown secret types.
    """

    def scan(self, text: str) -> tuple[bool, list[SecretMatch]]:
        """Scan *text* for secrets.

        Returns:
            A 2-tuple ``(has_secrets, matches)`` where *matches* is a
            list of :class:`SecretMatch` dicts describing each finding.
        """
        matches: list[SecretMatch] = []
        covered_ranges: list[tuple[int, int]] = []

        # 1. Known-format patterns
        for sp in _SECRET_PATTERNS:
            for m in sp.pattern.finditer(text):
                start, end = m.start(), m.end()
                # Skip if this range is already covered by a prior pattern.
                if any(s <= start and end <= e for s, e in covered_ranges):
                    continue
                matches.append(
                    SecretMatch(type=sp.name, position=start, length=end - start)
                )
                covered_ranges.append((start, end))

        # 2. Generic high-entropy strings
        for token_match in re.finditer(r"\S{32,}", text):
            token = token_match.group()
            start = token_match.start()
            length = len(token)

            # Skip if already flagged by a specific pattern.
            if any(s <= start and start + length <= e for s, e in covered_ranges):
                continue

            # Skip known non-secret patterns (hex hashes, UUIDs).
            if _ENTROPY_SKIP_PATTERN.match(token):
                continue

            if self._compute_entropy(token) > _ENTROPY_THRESHOLD:
                matches.append(
                    SecretMatch(type="high_entropy_string", position=start, length=length)
                )
                covered_ranges.append((start, start + length))

        # Sort by position for deterministic output.
        matches.sort(key=lambda m: m["position"])

        return (len(matches) > 0, matches)

    def redact(self, text: str, replacement_template: str = "[REDACTED:{type}:{hash}]") -> tuple[str, int]:
        """Replace detected secrets with redaction placeholders.

        Each secret is replaced with a tag containing its type and a
        truncated SHA-256 hash of the original value for correlation.

        Returns:
            A 2-tuple ``(redacted_text, redaction_count)``.
        """
        has_secrets, matches = self.scan(text)
        if not has_secrets:
            return (text, 0)

        # Process matches in reverse order so positions stay valid.
        result = text
        for match in reversed(matches):
            start = match["position"]
            end = start + match["length"]
            original = text[start:end]

            hash_prefix = hashlib.sha256(original.encode("utf-8", errors="replace")).hexdigest()[:8]
            tag = replacement_template.format(type=match["type"], hash=hash_prefix)

            result = result[:start] + tag + result[end:]

        return (result, len(matches))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_entropy(text: str) -> float:
        """Compute Shannon entropy in bits per character."""
        if not text:
            return 0.0
        length = len(text)
        counts = Counter(text)
        entropy = 0.0
        for count in counts.values():
            prob = count / length
            if prob > 0:
                entropy -= prob * math.log2(prob)
        return entropy
