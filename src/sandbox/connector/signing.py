"""Cryptographic maker-checker — every approval is signed and verifiable.

An examiner-grade audit needs *non-repudiation*: proof that a specific human
approver authorized a specific agent action under a specific policy, and that
the record has not been altered since. We reuse the repo's Ed25519 primitives
([crypto/signing.py](src/sandbox/crypto/signing.py)) to sign a canonical bundle
binding:

    identity → action → policy_version → decision → outcome hash

The signed bundle and the approver's public key are written into the done-record,
so anyone can verify it later with no shared secret.

Key custody (ADR 0007, see docs/TCB.md): the approver's seed lives in the key home,
outside every workspace (``connector/keyhome.py``), one folder per workspace id. If
the key home cannot be used there is no signing. In a bank this key would be a
per-human credential in an HSM / smartcard; the signing *interface* is the part that
transfers, the custody is not.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey, VerifyKey

from sandbox.connector import keyhome
from sandbox.crypto.signing import sign_message, verify_signature

# The fields that are bound into the signature. Anything not listed is
# presentation-only and not covered — keep the security-relevant fields here.
_SIGNED_FIELDS = (
    "request_id",
    "identity",
    "command",
    "path",
    "url",
    "trigger",
    "reason_code",
    "policy_version",
    "decision",
    "state",
    "reviewer_id",
    "exit_code",
    "fingerprint",  # tool-call grants: binds the approval to one exact call
    "approvals",    # dual control: each approver's own signed approval
)


def _canonical(record: dict[str, Any], fields: list[str] | tuple[str, ...] = _SIGNED_FIELDS) -> bytes:
    bundle = {k: record.get(k) for k in fields}
    return json.dumps(bundle, sort_keys=True, separators=(",", ":"), default=str).encode()


def _safe_name(reviewer_id: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in reviewer_id) or "cli"


def _seed_path(layout, reviewer_id: str, *, create: bool = True) -> Path:
    """The reviewer's seed in the key home. Raises KeyHomeError when there is none to use:
    never a path under the workspace, the cwd or a relative path (ADR 0007 1.3)."""
    return keyhome.workspace_key_dir(layout, create=create) / f"{_safe_name(reviewer_id)}.seed"


def _legacy_seed(layout, reviewer_id: str) -> Path:
    """Pre-M1 in-tree location. Read only to retire it; never used to sign, never moved."""
    return layout.state_dir / "keys" / f"{_safe_name(reviewer_id)}.seed"


def _audit_heads(layout) -> dict[str, dict[str, Any]]:
    """Per-session audit chain head at this moment (what a legacy record must be under)."""
    from sandbox.connector.audit import session_ids, verify_records_bytes

    heads: dict[str, dict[str, Any]] = {}
    for sid in session_ids(layout.audit_dir):
        res = verify_records_bytes((layout.audit_dir / sid / "records.jsonl").read_bytes())
        heads[sid] = {"records": res["records"], "head_hash": res["head_hash"], "chain_ok": res["ok"]}
    return heads


def _audit_rotation(layout, reviewer_id: str, new_pub: str) -> None:
    """Audit `key_rotated` before the new key exists. Strict: no audit record, no key."""
    import json as _json
    import time

    from sandbox.connector.audit import FolderAudit

    legacy = _legacy_seed(layout, reviewer_id)
    if not legacy.is_file():
        return
    retired_pub = None
    try:
        retired_pub = bytes(SigningKey(legacy.read_bytes()).verify_key).hex()
    except Exception:  # noqa: BLE001 - an unreadable legacy seed is still retired
        pass
    try:
        session_id = _json.loads(layout.session_file.read_text(encoding="utf-8")).get("session_id", "")
    except (OSError, ValueError, AttributeError):
        session_id = ""
    try:
        record = {"event": "key_rotated", "ts": time.time(), "reviewer_id": reviewer_id,
                  "reason": "pre_m1_in_tree_seed_retired", "retired_public_key": retired_pub,
                  "retired_at": time.time(), "new_public_key": new_pub,
                  "retired_seed_path": str(legacy), "audit_heads": _audit_heads(layout)}
        FolderAudit(layout.audit_dir, session_id).append(record)
    except Exception as exc:  # noqa: BLE001
        raise keyhome.KeyHomeError(f"cannot record key_rotated in the audit chain: {exc}") from exc


def _write_seed(path: Path, key: SigningKey) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(bytes(key))
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass


def _load_or_create_key(layout, reviewer_id: str) -> SigningKey:
    """The reviewer's key from the key home, created on first use.

    Fail closed: raises :class:`keyhome.KeyHomeError` when the key home cannot be
    resolved or written, or a stored seed is unreadable (it is never silently replaced).
    A pre-M1 in-tree seed counts as exposed: it is retired in place (audited
    `key_rotated`, with the audit-chain heads at that moment) and a new key is made.
    """
    path = _seed_path(layout, reviewer_id)
    for _ in range(2):
        try:
            return SigningKey(path.read_bytes())
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            raise keyhome.KeyHomeError(f"the seed for {reviewer_id!r} is unreadable: {exc}") from exc
        key = SigningKey.generate()
        _audit_rotation(layout, reviewer_id, bytes(key.verify_key).hex())
        try:
            _write_seed(path, key)
            return key
        except FileExistsError:
            continue  # another process created it first: use theirs
        except OSError as exc:
            raise keyhome.KeyHomeError(f"cannot write the seed in the key home: {exc}") from exc
    raise keyhome.KeyHomeError("cannot create the seed in the key home")


def ensure_signing_key(layout, reviewer_id: str) -> str:
    """Make sure `reviewer_id` can sign; returns the public key hex. Raises KeyHomeError."""
    return bytes(_load_or_create_key(layout, reviewer_id).verify_key).hex()


def sign_record(layout, reviewer_id: str, record: dict[str, Any]) -> dict[str, Any]:
    """Sign a terminal (done) record in place; returns the same dict.

    Adds ``signature`` (hex), ``signer_public_key`` (hex), and ``signed_fields``
    so a verifier knows exactly what was covered.
    """
    key = _load_or_create_key(layout, reviewer_id)
    record["signer_public_key"] = bytes(key.verify_key).hex()
    record["signed_fields"] = list(_SIGNED_FIELDS)
    record["signature"] = sign_message(_canonical(record), key)
    return record


def verify_record(record: dict[str, Any]) -> bool:
    """Verify a signed done-record against its embedded public key."""
    sig = record.get("signature")
    pub = record.get("signer_public_key")
    if not sig or not pub:
        return False
    try:
        vk = VerifyKey(bytes.fromhex(pub))
    except (ValueError, TypeError):
        return False
    # Verify over the fields the record says were signed, so records signed
    # before a field was added still verify.
    fields = record.get("signed_fields") or _SIGNED_FIELDS
    return verify_signature(_canonical(record, fields), sig, vk)


_APPROVAL_FIELDS = ("request_id", "command", "fingerprint", "reviewer_id", "decision", "approved_at")


def sign_approval(layout, reviewer_id: str, record: dict[str, Any], approved_at: float) -> dict[str, Any]:
    """One approver's signed approval of a pending request (dual control).

    Signed with that reviewer's own key, over what they approved (request,
    command, fingerprint) and when, so each of the two approvals is separately
    verifiable later.
    """
    key = _load_or_create_key(layout, reviewer_id)
    approval = {"request_id": record.get("request_id"), "command": record.get("command"),
                "fingerprint": record.get("fingerprint"), "reviewer_id": reviewer_id,
                "decision": "approve", "approved_at": approved_at}
    approval["signer_public_key"] = bytes(key.verify_key).hex()
    approval["signature"] = sign_message(_canonical(approval, _APPROVAL_FIELDS), key)
    return approval


def verify_approval(approval: dict[str, Any]) -> bool:
    try:
        vk = VerifyKey(bytes.fromhex(approval.get("signer_public_key", "")))
    except (ValueError, TypeError):
        return False
    return verify_signature(_canonical(approval, _APPROVAL_FIELDS), approval.get("signature", ""), vk)


def distinct_approvals(approvals: list[dict[str, Any]], needed: int = 2) -> bool:
    """At least `needed` valid approvals by distinct reviewers with distinct keys."""
    valid = [a for a in approvals or [] if verify_approval(a)]
    return (len({a["reviewer_id"] for a in valid}) >= needed
            and len({a["signer_public_key"] for a in valid}) >= needed)


def reviewer_public_key(layout, reviewer_id: str = "cli") -> str | None:
    """Hex public key of this folder's approver key, or None if there is none (or no key home)."""
    try:
        path = _seed_path(layout, reviewer_id, create=False)
        return bytes(SigningKey(path.read_bytes()).verify_key).hex()
    except (keyhome.KeyHomeError, OSError, ValueError):
        return None
