"""Summarize what a shell command actually does, in plain labels.

For the approver panel (threat model Goal 6: a misleading description). The
agent supplies a `description`; a human who trusts it can be steered into
approving something else. Rather than judge "does the description match?"
(unreliable with a zero-shot model — measured), the gateway shows the human
what the command *actually* does, next to the agent's words, so they can see
the gap themselves.

Deterministic and best-effort: it recognises common impactful shapes, not all.
"""
from __future__ import annotations

import re

from sandbox.safety.exfil import detect as _detect_exfil

_F = re.IGNORECASE | re.VERBOSE

# (tag, human label, regex). Order = display order.
_ACTIONS: list[tuple[str, str, re.Pattern[str]]] = [
    ("download_exec", "downloads and runs a script", re.compile(
        r"(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|;&]*\|\s*(?:ba)?sh\b"
        r"| \b(?:iex|Invoke-Expression)\b[^;&]*(?:DownloadString|curl|wget|iwr|irm)", _F)),
    ("privilege", "runs with elevated privilege", re.compile(
        r"(?:^|[\s|;&])(sudo|doas|runas)\b | Start-Process[^|;&]*-Verb\s+RunAs", _F)),
    ("delete", "deletes files", re.compile(
        r"(?:^|[\s|;&])(rm|rmdir|del|Remove-Item|rd)\b"
        r"| \bgit\b[^|;&]*\b(clean\s+-[a-z]*f|reset\s+--hard)\b", _F)),
    ("overwrite_shell_cfg", "edits shell startup or config files", re.compile(
        r"(>>?|tee|Add-Content|Set-Content)\s*[^\n|;&]*(\.bashrc|\.zshrc|\.profile|\.bash_profile|authorized_keys|/etc/)", _F)),
    ("network", "accesses the network", re.compile(
        r"(?:^|[\s|;&])(curl|wget|nc|ncat|netcat|scp|sftp|rsync|ssh|ftp|telnet|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b"
        r"| \b(?:pip|npm|pnpm|yarn|apt|apt-get|brew|gh|aws|gcloud|az)\b", _F)),
    ("package_install", "installs software", re.compile(
        r"\b(pip\s+install|npm\s+(?:i|install|add)|pnpm\s+(?:i|install|add)|yarn\s+add"
        r"|apt(?:-get)?\s+install|brew\s+install|gem\s+install|cargo\s+install)\b", _F)),
]


def describe(command: str) -> list[tuple[str, str]]:
    """List of (tag, label) for the impactful things a command does."""
    if not command:
        return []
    found: list[tuple[str, str]] = []
    exfil = _detect_exfil(command)
    if exfil is not None:
        found.append(("exfiltration", f"sends a sensitive file out ({exfil.sensitive})"))
    for tag, label, pattern in _ACTIONS:
        if pattern.search(command):
            found.append((tag, label))
    # De-dup while keeping order (exfil implies network; show the specific one).
    seen: set[str] = set()
    out = []
    for tag, label in found:
        if tag not in seen:
            seen.add(tag)
            out.append((tag, label))
    return out


# Actions worth putting in front of a human even when the command would escalate
# anyway — the ones an innocent-sounding description tends to hide.
IMPACTFUL = {"exfiltration", "download_exec", "privilege", "delete", "overwrite_shell_cfg"}


def impactful_actions(command: str) -> list[tuple[str, str]]:
    return [(t, l) for t, l in describe(command) if t in IMPACTFUL]
