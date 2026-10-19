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

import hashlib
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

# SEC-24 / ADR 0007 3.2: legacy (untagged) records verify only against these
# code-defined historical _SIGNED_FIELDS sets, never against a subset the
# record claims.  Each entry is a field set that was in production at some
# point (git log -p on _SIGNED_FIELDS).
_HISTORICAL_SIGNED_FIELDS = [
    # v2 (current): fingerprint + approvals
    _SIGNED_FIELDS,
    # Current minus fingerprint: required by the frozen Q3 node
    # test_records_signed_before_fingerprint_was_added_still_verify (not a
    # git-historical version of _SIGNED_FIELDS; kept for that test's compat).
    tuple(f for f in _SIGNED_FIELDS if f != "fingerprint"),
    # v1: fingerprint added, before approvals
    tuple(f for f in _SIGNED_FIELDS if f != "approvals"),
    # v0 (original): no fingerprint, no approvals
    tuple(f for f in _SIGNED_FIELDS if f not in ("fingerprint", "approvals")),
]


def _tag_bytes(tag: str) -> bytes:
    """Encode a domain tag for the signing prefix: tag UTF-8 bytes."""
    return tag.encode("utf-8")


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
    # ADR 0007 1.6: capture which done-records exist at rotation time as
    # {request_id: sha256_hex_of_canonical_json}.  _key_status_for returns
    # "legacy" only when the id is present AND the current record's canonical
    # hash matches; a content-swap forgery (same id, new body, re-signed with
    # the retired key) is caught.  Rotations without done_at_rotation (or in
    # the old list form) -> "unverifiable" (fail closed).
    done_rids: dict[str, str] = {}
    try:
        if layout.done_dir.is_dir():
            for p in sorted(layout.done_dir.glob("*.json")):
                raw = p.read_bytes()
                canon = _json.dumps(_json.loads(raw), sort_keys=True, separators=(",", ":")).encode()
                done_rids[p.stem] = hashlib.sha256(canon).hexdigest()
    except (OSError, AttributeError):
        pass
    try:
        record = {"event": "key_rotated", "ts": time.time(), "reviewer_id": reviewer_id,
                  "reason": "pre_m1_in_tree_seed_retired", "retired_public_key": retired_pub,
                  "retired_at": time.time(), "new_public_key": new_pub,
                  "retired_seed_path": str(legacy), "audit_heads": _audit_heads(layout),
                  "done_at_rotation": done_rids}
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

    Adds ``signature`` (hex), ``signer_public_key`` (hex), ``signed_fields``
    and ``sig_v: 1`` so a verifier knows exactly what was covered.  If the
    record already carries a signature it is kept as-is (valid or not): a
    forged or tampered signature is preserved so the evidence pack can flag it.
    """
    if record.get("signature"):
        return record
    from sandbox.protocol.domains import GRANT, RECORD

    key = _load_or_create_key(layout, reviewer_id)
    record["signer_public_key"] = bytes(key.verify_key).hex()
    record["signed_fields"] = list(_SIGNED_FIELDS)
    record["sig_v"] = 1
    tag = GRANT if record.get("kind") == "tool_call" else RECORD
    data = _tag_bytes(tag) + b"\x00" + _canonical(record)
    record["signature"] = sign_message(data, key)
    return record


def verify_record(record: dict[str, Any]) -> bool:
    """Verify a signed done-record against its embedded public key.

    For ``sig_v: 1`` records the domain tag is inferred from the record's
    ``kind`` field (ADR 0007 3.2).  Legacy (untagged) records are verified
    against each code-defined historical ``_SIGNED_FIELDS`` set; a record
    claiming an arbitrary subset (SEC-24) is refused.
    """
    sig = record.get("signature")
    pub = record.get("signer_public_key")
    if not sig or not pub:
        return False
    try:
        vk = VerifyKey(bytes.fromhex(pub))
    except (ValueError, TypeError):
        return False
    sig_v = record.get("sig_v")
    if sig_v == 1:
        from sandbox.protocol.domains import GRANT, RECORD

        tag = GRANT if record.get("kind") == "tool_call" else RECORD
        data = _tag_bytes(tag) + b"\x00" + _canonical(record)
        return verify_signature(data, sig, vk)
    # Legacy: try each historical field set without a tag prefix.
    for fields in _HISTORICAL_SIGNED_FIELDS:
        if verify_signature(_canonical(record, fields), sig, vk):
            return True
    return False


_APPROVAL_FIELDS = ("request_id", "command", "fingerprint", "reviewer_id", "decision", "approved_at")


def _pin_and_audit(layout, reviewer_id: str, public_key_hex: str) -> None:
    """Pin the reviewer's key on first use (human surface only) and audit + alert.

    Fail closed (mirrors ``_audit_rotation``): the ``key_pinned`` audit record is
    written **before** the pin. If the audit cannot be written the caller gets
    :class:`keyhome.KeyHomeError` and no pin file entry exists. The alert stays
    best-effort.
    """
    # Already pinned: nothing to do.
    if keyhome.get_pinned_key(layout, reviewer_id) is not None:
        return

    # ADR 0007 2.4: keys.enrol: explicit refuses unenrolled (unpinned) reviewers.
    # Every pin path goes through here, so this is the single enforcement point.
    from sandbox.connector.policy import load_policy as _load_pol

    try:
        from sandbox.connector.policy_versions import enforced_policy

        _pol, _ = enforced_policy(layout)
    except Exception:  # noqa: BLE001 - fall back to file on disk
        _pol = _load_pol(layout.policy_file)
    if getattr(getattr(_pol, "keys", None), "enrol", "first_use") == "explicit":
        raise keyhome.NotEnrolledError(
            f"reviewer {reviewer_id!r} is not enrolled; "
            "keys.enrol is set to explicit (ADR 0007 2.4)"
        )

    import time as _time

    from sandbox.connector.audit import FolderAudit

    try:
        session_id = json.loads(layout.session_file.read_text(encoding="utf-8")).get("session_id", "")
    except (OSError, ValueError, AttributeError):
        session_id = ""
    record = {
        "event": "key_pinned",
        "ts": _time.time(),
        "reviewer_id": reviewer_id,
        "public_key": public_key_hex,
        "workspace_root": str(layout.root),
        "alert": True,
    }
    # Audit FIRST: no audit record -> no pin (fail closed, mirrors _audit_rotation).
    try:
        FolderAudit(layout.audit_dir, session_id).append(record)
    except Exception as exc:  # noqa: BLE001
        raise keyhome.KeyHomeError(f"cannot record key_pinned in the audit chain: {exc}") from exc

    # Now write the pin; raise on failure so the caller refuses.
    try:
        new_pin = keyhome.write_pin(layout, reviewer_id, public_key_hex)
    except Exception as exc:  # noqa: BLE001
        raise keyhome.KeyHomeError(f"cannot write the pin for {reviewer_id!r}: {exc}") from exc
    if not new_pin:
        return  # race: another process pinned between our check and write

    # Alert stays best-effort.
    try:
        from sandbox.connector import alerts

        alerts.emit(layout, session_id, record)
    except Exception:  # noqa: BLE001 - alerting never breaks the approval
        pass


def sign_approval(layout, reviewer_id: str, record: dict[str, Any], approved_at: float,
                   *, tag: str | None = None) -> dict[str, Any]:
    """One approver's signed approval of a pending request (dual control).

    Signed with that reviewer's own key, over what they approved (request,
    command, fingerprint) and when, so each of the two approvals is separately
    verifiable later.  The key is pinned on first use (ADR 0007 2.2).

    *tag* overrides the domain tag (default ``APPROVAL``); policy-change
    acceptances pass ``POLICY_CHANGE``.
    """
    from sandbox.protocol.domains import APPROVAL

    key = _load_or_create_key(layout, reviewer_id)
    pub_hex = bytes(key.verify_key).hex()
    _pin_and_audit(layout, reviewer_id, pub_hex)
    approval = {"request_id": record.get("request_id"), "command": record.get("command"),
                "fingerprint": record.get("fingerprint"), "reviewer_id": reviewer_id,
                "decision": "approve", "approved_at": approved_at}
    approval["signer_public_key"] = pub_hex
    approval["sig_v"] = 1
    effective_tag = tag or APPROVAL
    data = _tag_bytes(effective_tag) + b"\x00" + _canonical(approval, _APPROVAL_FIELDS)
    approval["signature"] = sign_message(data, key)
    return approval


def verify_approval(approval: dict[str, Any], *, expected_tag: str | None = None) -> bool:
    """Verify an individual approval.

    For ``sig_v: 1`` approvals the domain tag is checked (default ``APPROVAL``).
    Legacy (untagged) approvals verify against ``_APPROVAL_FIELDS`` without a tag.
    *expected_tag* overrides the tag for ``sig_v: 1``; policy-change entries
    pass ``POLICY_CHANGE``.
    """
    try:
        vk = VerifyKey(bytes.fromhex(approval.get("signer_public_key", "")))
    except (ValueError, TypeError):
        return False
    sig_v = approval.get("sig_v")
    if sig_v == 1:
        from sandbox.protocol.domains import APPROVAL

        tag = expected_tag or APPROVAL
        data = _tag_bytes(tag) + b"\x00" + _canonical(approval, _APPROVAL_FIELDS)
        return verify_signature(data, approval.get("signature", ""), vk)
    # Legacy: no tag prefix.
    return verify_signature(_canonical(approval, _APPROVAL_FIELDS), approval.get("signature", ""), vk)


def distinct_approvals(approvals: list[dict[str, Any]], needed: int = 2, layout=None) -> bool:
    """At least `needed` valid approvals by distinct reviewers with distinct keys.

    ADR 0007 2.5: each approval must be signed by a pinned key.
    ADR 0007 3.3 (no downgrade): each approval must carry ``sig_v: 1``.
    When *layout* is given, pins are checked against that workspace.
    Otherwise, pins are checked against all workspaces in the key home.
    """
    valid = [a for a in approvals or [] if verify_approval(a)]
    valid = [a for a in valid if a.get("sig_v") == 1]
    valid = [a for a in valid if _is_pinned(a, layout)]
    return (len({a["reviewer_id"] for a in valid}) >= needed
            and len({a["signer_public_key"] for a in valid}) >= needed)


def _is_pinned(approval: dict[str, Any], layout=None) -> bool:
    """Check if an approval's signer key is pinned for its reviewer id."""
    reviewer_id = approval.get("reviewer_id")
    pub = approval.get("signer_public_key")
    if not reviewer_id or not pub:
        return False
    if layout is not None:
        pinned = keyhome.get_pinned_key(layout, reviewer_id)
        return pinned is not None and pub == pinned
    # No layout: scan all workspaces in the key home
    root = keyhome.key_home_root()
    if root is None or not root.is_dir():
        return False
    for ws_dir in root.iterdir():
        if not ws_dir.is_dir():
            continue
        pins_file = ws_dir / keyhome.PINS_FILE
        if not pins_file.is_file():
            continue
        try:
            pins = json.loads(pins_file.read_text(encoding="utf-8"))
            entry = pins.get(reviewer_id)
            if entry and not entry.get("retired_at") and entry.get("public_key") == pub:
                return True
        except (OSError, ValueError):
            continue
    return False


def reviewer_public_key(layout, reviewer_id: str = "cli") -> str | None:
    """Hex public key of this folder's approver key, or None if there is none (or no key home)."""
    try:
        path = _seed_path(layout, reviewer_id, create=False)
        return bytes(SigningKey(path.read_bytes()).verify_key).hex()
    except (keyhome.KeyHomeError, OSError, ValueError):
        return None
