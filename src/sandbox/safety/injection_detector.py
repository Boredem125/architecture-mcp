"""Prompt injection detection per AGENT_04 spec.

Scans text for known injection patterns, structural anomalies,
and shell metacharacter abuse in non-command contexts.
"""

from __future__ import annotations

import base64
import math
import re
from collections import Counter
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Pattern library
# ---------------------------------------------------------------------------

# Each entry: (compiled regex, human-readable flag label)
_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Direct instruction override attempts
    (
        re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+"
            r"(instructions|prompts|rules|guidelines|directives)",
            re.IGNORECASE,
        ),
        "instruction_override",
    ),
    (
        re.compile(
            r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+"
            r"(instructions|prompts|rules|guidelines|directives)",
            re.IGNORECASE,
        ),
        "instruction_override",
    ),
    (
        re.compile(
            r"forget\s+(all\s+)?(previous|prior|above|earlier)\s+"
            r"(instructions|prompts|rules|guidelines|directives)",
            re.IGNORECASE,
        ),
        "instruction_override",
    ),
    # Identity manipulation
    (
        re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
        "identity_manipulation",
    ),
    (
        re.compile(r"act\s+as\s+(a\s+|an\s+)?", re.IGNORECASE),
        "identity_manipulation",
    ),
    (
        re.compile(r"pretend\s+(you\s+are|to\s+be)\s+", re.IGNORECASE),
        "identity_manipulation",
    ),
    (
        re.compile(r"from\s+now\s+on,?\s+you\s+(are|will)\s+", re.IGNORECASE),
        "identity_manipulation",
    ),
    # System/role prompt injection markers
    (
        re.compile(r"^system\s*:", re.IGNORECASE | re.MULTILINE),
        "system_prompt_injection",
    ),
    (
        re.compile(r"\[INST\]", re.IGNORECASE),
        "llm_format_injection",
    ),
    (
        re.compile(r"<\|im_start\|>", re.IGNORECASE),
        "llm_format_injection",
    ),
    (
        re.compile(r"<\|im_end\|>", re.IGNORECASE),
        "llm_format_injection",
    ),
    (
        re.compile(r"^###\s*(system|user|assistant)\s*$", re.IGNORECASE | re.MULTILINE),
        "llm_format_injection",
    ),
    # DAN / jailbreak patterns
    (
        re.compile(
            r"\bDAN\b.*\b(mode|prompt|jailbreak)\b"
            r"|\b(jailbreak|developer)\s+mode\b",
            re.IGNORECASE,
        ),
        "jailbreak_attempt",
    ),
    (
        re.compile(
            r"do\s+anything\s+now",
            re.IGNORECASE,
        ),
        "jailbreak_attempt",
    ),
    (
        re.compile(
            r"(enable|activate|enter)\s+(developer|god|sudo|admin|unrestricted)\s+mode",
            re.IGNORECASE,
        ),
        "jailbreak_attempt",
    ),
]

# Shell metacharacters that should not appear in non-command parameters.
_SHELL_META_PATTERN = re.compile(
    r"(?:"
    r"\$\(.*?\)"     # $() command substitution
    r"|`[^`]+`"      # backtick substitution
    r"|\|\|"         # logical OR
    r"|&&"           # logical AND
    r"|\|"           # pipe
    r"|;\s*\S"       # semicolon followed by another command
    r")",
)

# Base64 blob: 50+ base64 chars (may include padding) as a contiguous string.
_BASE64_BLOB_PATTERN = re.compile(
    r"(?<!\w)[A-Za-z0-9+/]{50,}={0,2}(?!\w)",
)

# Nested JSON inside a string value (heuristic: looks like {"key": ...}).
_NESTED_JSON_PATTERN = re.compile(
    r'(?<=["\'])\s*\{["\']?\w+["\']?\s*:\s*',
)


@dataclass(frozen=True, slots=True)
class _AnomalyResult:
    """Internal result from structural anomaly checks."""

    detected: bool
    flags: list[str] = field(default_factory=list)


class InjectionDetector:
    """Detects prompt-injection attempts in arbitrary text.

    Combines a regex pattern library with structural anomaly detection
    (base64 blobs, high-entropy strings, nested JSON) and shell
    metacharacter scanning.
    """

    # Entropy threshold (Shannon bits/char) for flagging high-entropy strings.
    ENTROPY_THRESHOLD: float = 4.5
    # Minimum string length to consider for entropy analysis.
    ENTROPY_MIN_LENGTH: int = 32
    # Minimum base64 blob length to flag.
    BASE64_MIN_LENGTH: int = 50

    def scan(self, text: str) -> tuple[bool, list[str]]:
        """Scan *text* for injection indicators.

        Returns:
            A 2-tuple ``(is_injection, flags)`` where *flags* lists every
            detection category that matched (deduplicated, deterministic
            order).
        """
        flags: list[str] = []

        # 1. Regex pattern library
        flags.extend(self._scan_patterns(text))

        # 2. Structural anomalies
        anomaly = self._scan_anomalies(text)
        flags.extend(anomaly.flags)

        # 3. Shell metacharacters
        if self._has_shell_metacharacters(text):
            flags.append("shell_metacharacter")

        # Deduplicate while preserving first-seen order.
        seen: set[str] = set()
        unique_flags: list[str] = []
        for f in flags:
            if f not in seen:
                seen.add(f)
                unique_flags.append(f)

        return (len(unique_flags) > 0, unique_flags)

    # ------------------------------------------------------------------
    # Pattern matching
    # ------------------------------------------------------------------

    @staticmethod
    def _scan_patterns(text: str) -> list[str]:
        """Match the text against the known injection pattern library."""
        hits: list[str] = []
        for pattern, label in _INJECTION_PATTERNS:
            if pattern.search(text):
                hits.append(label)
        return hits

    # ------------------------------------------------------------------
    # Structural anomaly detection
    # ------------------------------------------------------------------

    def _scan_anomalies(self, text: str) -> _AnomalyResult:
        flags: list[str] = []

        # Base64 blobs
        for match in _BASE64_BLOB_PATTERN.finditer(text):
            blob = match.group()
            if len(blob) >= self.BASE64_MIN_LENGTH and self._is_plausible_base64(blob):
                flags.append("base64_blob")
                break  # one flag is enough

        # High-entropy strings (scan contiguous non-whitespace tokens)
        for token in text.split():
            if len(token) >= self.ENTROPY_MIN_LENGTH:
                entropy = self._compute_entropy(token)
                if entropy > self.ENTROPY_THRESHOLD:
                    flags.append("high_entropy_string")
                    break

        # Nested JSON in string fields
        if _NESTED_JSON_PATTERN.search(text):
            flags.append("nested_json_in_string")

        return _AnomalyResult(detected=len(flags) > 0, flags=flags)

    # ------------------------------------------------------------------
    # Shell metacharacter detection
    # ------------------------------------------------------------------

    @staticmethod
    def _has_shell_metacharacters(text: str) -> bool:
        return bool(_SHELL_META_PATTERN.search(text))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_entropy(text: str) -> float:
        """Compute Shannon entropy in bits per character.

        Returns 0.0 for empty strings.
        """
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

    @staticmethod
    def _is_plausible_base64(blob: str) -> bool:
        """Return True if *blob* decodes as valid base64."""
        try:
            # Pad to multiple of 4 if needed.
            padded = blob + "=" * (-len(blob) % 4)
            base64.b64decode(padded, validate=True)
            return True
        except Exception:
            return False
