"""Keep secrets out of what the gateway stores and hands back (AIUC-1 A008.5).

When ``output.scrub_secrets`` is on (the default), credentials are replaced
by placeholders such as ``[SECRET_1]`` in:

- the output of approved commands, fetches and file reads, before it is
  signed into the done-record and returned to the agent (so a token printed
  by an approved command never lands in the conversation history);
- audit-chain records (command, reason, target fields);
- the human-readable activity log.

Only credentials are matched (named key formats, KEY=value assignments,
JWTs, URL credentials, private keys); emails, IPs and git hashes in ordinary
output are left alone. Pending and done escalation records keep the exact
command, because the approvers' signatures cover it and the broker runs it.
"""
from __future__ import annotations

from typing import Any

from sandbox.connector.layout import FolderLayout
from sandbox.semantic.redact import SECRET_KINDS, redact

# Fields scrubbed in audit records. Hashes, ids and fingerprints are never
# touched, so the chain and the approval signatures still verify.
AUDIT_FIELDS = ("command", "reason", "target", "described_as")
OUTPUT_FIELDS = ("stdout", "stderr")


def scrub_text(text: str) -> str:
    return redact(text, SECRET_KINDS) if text else text


def scrub_fields(record: dict[str, Any], fields: tuple[str, ...]) -> int:
    """Scrub the named string fields of *record* in place; return how many changed."""
    changed = 0
    for key in fields:
        value = record.get(key)
        if isinstance(value, str) and value:
            clean = scrub_text(value)
            if clean != value:
                record[key] = clean
                changed += 1
    return changed


def enabled(layout: FolderLayout) -> bool:
    """The enforced policy's ``output.scrub_secrets``; on if it can't be read."""
    try:
        from sandbox.connector.policy_versions import enforced_policy

        return bool(enforced_policy(layout)[0].output.scrub_secrets)
    except Exception:  # noqa: BLE001 — fail toward scrubbing
        return True
