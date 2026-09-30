"""Strip personal data and secrets from text before it leaves the machine.

Used before anything is sent to an external labeller. Each match becomes a
typed placeholder (``[EMAIL_1]``, ``[SECRET_2]``...), numbered per text so the
labeller can still tell two different values apart. Placeholders keep the
shape of the text, which is all an injection judgement needs.

Deliberately over-eager: a false redaction costs a little labelling context,
a missed one leaks data.
"""
from __future__ import annotations

import re

# Order matters: specific secret formats before generic ones, URLs with
# credentials before plain emails.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S)),
    ("SECRET", re.compile(
        r"\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_\-]{16,}"      # OpenAI / Anthropic style
        r"|gsk_[A-Za-z0-9]{20,}|xai-[A-Za-z0-9]{20,}"     # Groq / xAI
        r"|hf_[A-Za-z0-9]{20,}"                           # Hugging Face
        r"|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
        r"|glpat-[A-Za-z0-9_\-]{20,}"
        r"|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}"
        r"|xox[abprs]-[A-Za-z0-9\-]{10,}"
        r"|AIza[0-9A-Za-z_\-]{35}"
        r"|(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("URL_CREDENTIALS", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s/:@]+:[^\s/@]+@", re.I)),
    # KEY=value / "password": "value" style assignments of anything secret-sounding.
    ("SECRET", re.compile(
        r"(?i)(?:[A-Z0-9_]*(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?)[A-Z0-9_]*)"
        r"[\"']?\s*[:=]\s*[\"']?(?!\[)([^\s\"',;]{6,})")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("IP", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("CARD", re.compile(r"\b(?:\d[ \-]?){13,19}\b")),
    ("PHONE", re.compile(r"(?<![\w.])\+?\d{1,3}[\s.\-]?\(?\d{2,4}\)?[\s.\-]\d{3,4}[\s.\-]?\d{3,4}\b")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    # Long opaque tokens (hex / base64) that no rule above named.
    ("SECRET", re.compile(r"\b(?=[A-Za-z0-9+/_\-]*\d)(?=[A-Za-z0-9+/_\-]*[A-Za-z])[A-Za-z0-9+/_\-]{32,}={0,2}")),
]


def redact(text: str) -> str:
    """Return ``text`` with secrets and personal data replaced by placeholders."""
    counters: dict[str, dict[str, int]] = {}

    def placeholder(kind: str, value: str) -> str:
        seen = counters.setdefault(kind, {})
        if value not in seen:
            seen[value] = len(seen) + 1
        return f"[{kind}_{seen[value]}]"

    for kind, pattern in _PATTERNS:
        if pattern.groups:  # replace only the captured value, keep the key name
            def sub(m: re.Match[str], kind: str = kind) -> str:
                s, e = m.span(1)
                return m.group(0)[: s - m.start()] + placeholder(kind, m.group(1)) + m.group(0)[e - m.start():]
        else:
            def sub(m: re.Match[str], kind: str = kind) -> str:
                return placeholder(kind, m.group(0))
        text = pattern.sub(sub, text)
    return text
