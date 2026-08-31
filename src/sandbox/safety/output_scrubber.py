"""Output scrubbing per AGENT_04 spec.

Cleans Zone 3 agent output by stripping secrets, neutralising
injection patterns, and producing an integrity hash of the
scrubbed result.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from sandbox.safety.injection_detector import InjectionDetector
from sandbox.safety.secret_scanner import SecretScanner


# ---------------------------------------------------------------------------
# LLM formatting characters that could carry injection payload.
# ---------------------------------------------------------------------------

_LLM_FORMAT_CHARS: dict[str, str] = {
    "<|": "&lt;|",
    "|>": "|&gt;",
    "[INST]": "[_INST_]",
    "[/INST]": "[/_INST_]",
    "###": "\\#\\#\\#",
}

_LLM_FORMAT_PATTERN = re.compile(
    "|".join(re.escape(k) for k in _LLM_FORMAT_CHARS),
)

# Patterns to strip entirely from output (injection content that should
# not survive into downstream processing at all).
_STRIP_PATTERNS: list[re.Pattern[str]] = [
    # System prompt injection markers
    re.compile(r"^system\s*:.*$", re.IGNORECASE | re.MULTILINE),
    # Identity manipulation directives
    re.compile(
        r"(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+"
        r"(?:instructions|prompts|rules|guidelines|directives)[.!]?",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:you\s+are\s+now|from\s+now\s+on,?\s+you\s+(?:are|will))\s+.*?[.!;\n]",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:act\s+as|pretend\s+(?:you\s+are|to\s+be))\s+.*?[.!;\n]",
        re.IGNORECASE,
    ),
    # DAN / jailbreak activation phrases
    re.compile(
        r"(?:enable|activate|enter)\s+(?:developer|god|sudo|admin|unrestricted)\s+mode[.!]?",
        re.IGNORECASE,
    ),
    re.compile(r"\bdo\s+anything\s+now\b", re.IGNORECASE),
]


@dataclass(frozen=True, slots=True)
class ScrubResult:
    """Immutable result of an output-scrubbing operation.

    Attributes:
        scrubbed_text: The cleaned output text.
        redaction_count: Number of secrets that were redacted.
        injection_neutralized: Whether injection content was found and
            neutralised.
        output_hash: SHA-256 hex digest of *scrubbed_text* for
            integrity verification.
    """

    scrubbed_text: str
    redaction_count: int
    injection_neutralized: bool
    output_hash: str


class OutputScrubber:
    """Scrubs secrets and injection content from agent output.

    Combines :class:`SecretScanner` for credential redaction with
    :class:`InjectionDetector` for prompt-injection neutralisation,
    then hashes the clean output for audit integrity.
    """

    def __init__(
        self,
        secret_scanner: SecretScanner,
        injection_detector: InjectionDetector,
    ) -> None:
        self._secret_scanner = secret_scanner
        self._injection_detector = injection_detector

    def scrub(self, text: str) -> ScrubResult:
        """Scrub *text* and return a :class:`ScrubResult`.

        Processing order:
          1. Redact secrets via :pymethod:`SecretScanner.redact`.
          2. Detect injection patterns.
          3. Strip recognised injection directives.
          4. Escape residual LLM formatting characters.
          5. Compute SHA-256 of the final scrubbed text.
        """
        # 1. Secret redaction
        scrubbed, redaction_count = self._secret_scanner.redact(text)

        # 2. Injection detection (on post-redaction text)
        is_injection, _flags = self._injection_detector.scan(scrubbed)

        # 3. Strip injection directives
        injection_neutralized = False
        if is_injection:
            scrubbed = self._strip_injection_content(scrubbed)
            injection_neutralized = True

        # 4. Escape LLM formatting characters regardless of detection
        scrubbed = self._escape_llm_formatting(scrubbed)

        # 5. Integrity hash
        output_hash = self._compute_output_hash(scrubbed)

        return ScrubResult(
            scrubbed_text=scrubbed,
            redaction_count=redaction_count,
            injection_neutralized=injection_neutralized,
            output_hash=output_hash,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _strip_injection_content(text: str) -> str:
        """Remove recognised injection directives from *text*."""
        result = text
        for pattern in _STRIP_PATTERNS:
            result = pattern.sub("", result)
        # Collapse multiple blank lines left by stripping.
        result = re.sub(r"\n{3,}", "\n\n", result)
        return result.strip()

    @staticmethod
    def _escape_llm_formatting(text: str) -> str:
        """Escape LLM-specific formatting tokens."""
        return _LLM_FORMAT_PATTERN.sub(
            lambda m: _LLM_FORMAT_CHARS[m.group()],
            text,
        )

    @staticmethod
    def _compute_output_hash(text: str) -> str:
        """SHA-256 hex digest of the scrubbed output."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
