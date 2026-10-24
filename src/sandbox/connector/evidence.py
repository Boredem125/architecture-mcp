"""Auditor evidence pack: export a folder's decisions and audit, verify it offline.

``export_evidence`` collects, from a folder's ``.sandbox/`` control plane:

- every audit chain (``audit/<session>/records.jsonl``) byte for byte, with the
  result of re-verifying it (links, lengths, and each record's own hash);
- every signed done-record (``escalations/done/``) byte for byte, with
  per-record checks: the signature verifies, the signer is the folder's key
  for that reviewer, and dual-control approvals are valid, bound to the
  request, signed by the folder's key for each approver, and distinct;
- the folder policy and the governance policy files as they are at export;
- the reviewers' public keys (never the seeds);
- a summary (decisions by outcome and reviewer, governance clause hits by
  clause and framework reference, failed checks);
- ``manifest.json``: the sha256 of every file, signed with a dedicated Ed25519
  exporter key kept in the key home (ADR 0007), as ``evidence-exporter.seed``.

``verify_evidence`` needs only the pack: it checks the manifest signature,
every file hash, that no file was added, every record's checks, and every
audit chain.

What the pack proves, and what it does not, is in docs/EVIDENCE.md. In short:
integrity relative to the keys in the control plane, not the identity of the
humans who hold them.
"""
from __future__ import annotations

import hashlib
import json
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from nacl.signing import VerifyKey

from sandbox.connector.layout import FolderLayout

FORMAT = "sandbox-evidence/1"
EXPORTER_KEY = "evidence-exporter"
MANIFEST = "manifest.json"
SUMMARY = "summary.json"
DECISIONS_INDEX = "decisions/index.json"
CHAINS_FILE = "audit/chains.json"
REVIEWER_KEYS = "keys/reviewers.json"
AIUC1_INDEX = "aiuc1/controls.json"
ALERTS_FILE = "alerts/alerts.jsonl"

# A record's signature must at least cover these, or it does not bind who
# decided what.
_CORE_SIGNED = ("request_id", "reviewer_id", "decision", "command")
# Fields added by FolderAudit.append; record_hash covers everything else.
_CHAIN_FIELDS = ("previous_hash", "chain_length", "record_hash")

LIMITS = [
    "Signatures prove a record was signed by a key in this folder's control plane "
    "(.sandbox/state/keys/). They do not prove which human held the key.",
    "Policy files are copied as they are at export time. Done-records do not bind a "
    "policy version, so the pack does not show the policy in force at each decision.",
    "Reviewer keys are the folder's current keys. A key that was replaced after a "
    "decision makes that decision fail the signer check; there is no key history.",
    "The manifest is signed with a key from the same control plane. Pin the exporter "
    "public key out of band (verify-evidence --exporter-key) to detect a re-signed pack.",
    "Audit chains are exported whole; the --since/--until window applies to decisions only.",
]


class EvidenceError(Exception):
    """The pack could not be written or read."""


class _DecisionsView(dict):
    """A dict that also supports iteration over a per-decision detail list.

    Backward compatible: ``d["total"]`` and ``d["by_outcome"]`` work (frozen
    tests). Forward compatible: ``for item in d:`` yields per-decision dicts
    with ``request_id`` and ``key_status`` (T3 tests).
    """

    def __init__(self, stats: dict[str, Any], detail: list[dict[str, Any]]):
        super().__init__(stats)
        self._detail = detail

    def __iter__(self):  # type: ignore[override]
        return iter(self._detail)


# --- small helpers -------------------------------------------------------

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _canonical_record_hash(rec: dict[str, Any]) -> str:
    """SHA-256 of the canonical JSON form of a record.

    This is the same canonical form used by ``signing._audit_rotation`` (write
    side) and ``_key_status_for`` / ``check_decision`` (read side).  Both sides
    share this one helper so the hash is never computed with diverging params.
    """
    return hashlib.sha256(
        json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _check_legacy_key(
    reviewer_id: str,
    signer_pub: str,
    request_id: str | None,
    rec: dict[str, Any],
    audit_records: list[dict[str, Any]],
) -> tuple[str, str]:
    """Check if a record signed by *signer_pub* qualifies as legacy.

    Searches *audit_records* (from **verified** chains only) for a
    ``key_rotated`` event whose ``retired_public_key`` matches *signer_pub*
    and whose ``done_at_rotation`` dict maps *request_id* to a canonical
    SHA-256 that matches the current record content.

    Returns ``(status, detail)`` where *status* is one of:

    * ``"legacy"`` -- the record is verified as legacy.
    * ``"not_rotated"`` -- no ``key_rotated`` event for this reviewer.
    * ``"not_covered"`` -- the request is not in ``done_at_rotation``.
    * ``"hash_mismatch"`` -- content changed since rotation.
    * ``"unverifiable"`` -- ``done_at_rotation`` is malformed.
    """
    rotation_events = [
        e for e in audit_records
        if e.get("event") == "key_rotated" and e.get("reviewer_id") == reviewer_id
    ]

    # Try each rotation event that retired this exact key.
    for rot in rotation_events:
        if rot.get("retired_public_key") != signer_pub:
            continue
        done_at = rot.get("done_at_rotation")
        if not isinstance(done_at, dict):
            return ("unverifiable", "done_at_rotation is missing or not a dict")
        if not request_id or request_id not in done_at:
            return (
                "not_covered",
                f"request_id {request_id!r} is not in done_at_rotation",
            )
        current_hash = _canonical_record_hash(rec)
        if current_hash != done_at[request_id]:
            return (
                "hash_mismatch",
                f"content hash does not match done_at_rotation for {request_id!r}",
            )
        return ("legacy", "")

    # No rotation event retired this key (or none at all).
    return (
        "not_rotated",
        f"reviewer {reviewer_id!r}: pre-M1 key has not been rotated; "
        f"run an approval or sandbox signing command as {reviewer_id!r} "
        f"on the source folder, then re-export",
    )


def _pretty(obj: Any) -> bytes:
    return (json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False, default=str) + "\n").encode("utf-8")


def _iso(ts: Any) -> str | None:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def parse_time(value: str | None) -> float | None:
    """ISO 8601 date or datetime → epoch seconds. A naive value is read as UTC."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"not an ISO 8601 date/time: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


# --- audit chain ---------------------------------------------------------

def verify_chain_bytes(data: bytes) -> dict[str, Any]:
    """Re-verify one ``records.jsonl`` (links and each record's hash); the same
    check ``sandbox verify`` runs (connector/audit.py verify_records_bytes)."""
    from sandbox.connector.audit import verify_records_bytes

    return verify_records_bytes(data)


# --- per-record checks ---------------------------------------------------

def _rid(value: Any) -> str:
    """A reviewer id as a dict key. Missing → "cli", as the queue signs it;
    a non-string (a malformed record) → a key no folder has."""
    if value is None or value == "":
        return "cli"
    return value if isinstance(value, str) else f"<invalid:{type(value).__name__}>"


def _approvals(rec: dict[str, Any]) -> list[Any]:
    a = rec.get("approvals")
    return a if isinstance(a, list) else []


def _check(name: str, ok: bool, detail: str = "") -> dict[str, Any]:
    return {"check": name, "ok": bool(ok), "detail": detail}


def _reverify_remote_approvals(
    envelopes: list[dict[str, Any]],
    done_rec: dict[str, Any],
    registry_keys: dict[str, dict[str, Any]] | None,
) -> set[str]:
    """Re-verify each remote approval envelope offline and return the set of
    verified registry user_ids.

    R2 (C8, C9 item 9): each envelope is cryptographically verified against
    the pinned registry in the pack, and re-bound to the done-record's
    request_id and command.  The ``connector:`` prefix is never counted.
    """
    verified_users: set[str] = set()
    if not registry_keys:
        return verified_users
    # S2: tag fixed in code (never trust env["kind"])
    FIXED_TAG = "agg/remote-approval/v1"
    for env in envelopes:
        if not isinstance(env, dict):
            continue
        payload = env.get("payload")
        if not isinstance(payload, dict):
            continue
        # S2: require decision == "approve" (a deny must not count)
        if payload.get("decision") != "approve":
            continue
        # S2: re-bind to the done-record (all binding fields)
        if payload.get("request_id") != done_rec.get("request_id"):
            continue
        if payload.get("command") != done_rec.get("command"):
            continue
        sigs = env.get("signatures", [])
        if not isinstance(sigs, list) or not sigs:
            continue
        sig_entry = sigs[0]
        if not isinstance(sig_entry, dict):
            continue
        key_id_val = sig_entry.get("key_id", "")
        key_entry = registry_keys.get(key_id_val)
        if key_entry is None:
            continue
        user_id = key_entry.get("user_id", "")
        if user_id.startswith("connector:"):
            continue
        pub_hex = key_entry.get("public_key", "")
        if not pub_hex:
            continue
        try:
            from nacl.signing import VerifyKey as _VK
            vk = _VK(bytes.fromhex(pub_hex))
            # S2: tag fixed in code, never env["kind"]
            canonical = json.dumps(
                payload, sort_keys=True, separators=(",", ":")
            ).encode()
            msg = FIXED_TAG.encode("utf-8") + b"\x00" + canonical
            sig_bytes = bytes.fromhex(sig_entry.get("sig", ""))
            vk.verify(msg, sig_bytes)
            verified_users.add(user_id)
        except Exception:
            continue
    return verified_users


def check_decision(
    rec: Any,
    stem: str,
    reviewer_keys: dict[str, str | None],
    audit_records: list[dict[str, Any]] | None = None,
    registry_keys: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """The checks for one done-record. ``reviewer_keys`` maps reviewer id to the
    folder's public key for it (None if the folder has none).

    When *audit_records* is provided (from **verified** audit chains in the
    pack), the check can accept a legacy record signed by a retired pre-M1 key
    if a ``key_rotated`` event covers it (ADR 0007 Decision 1.6).  Without
    *audit_records* the behaviour is unchanged (export side).
    """
    from sandbox.connector.signing import distinct_approvals, verify_approval, verify_record

    if not isinstance(rec, dict):
        return [_check("parse", False, "not a JSON object")]
    checks = [_check("request_id_matches_file", rec.get("request_id") == stem,
                     "" if rec.get("request_id") == stem else f"request_id is {rec.get('request_id')!r}")]

    if not rec.get("signature"):
        checks.append(_check("signature", False, "record is not signed"))
        return checks
    sig_ok = verify_record(rec)
    checks.append(_check("signature", sig_ok, "" if sig_ok else "signature does not verify"))

    covered = rec.get("signed_fields")
    missing = [f for f in _CORE_SIGNED if covered is not None and f not in covered]
    checks.append(_check("signed_fields", not missing,
                         f"not covered by the signature: {', '.join(missing)}" if missing else ""))

    reviewer = _rid(rec.get("reviewer_id"))
    expected = reviewer_keys.get(reviewer)
    signer_pub = rec.get("signer_public_key")

    # Signer-is-folder-key: current key match, or legacy via key_rotated.
    if expected is not None and signer_pub == expected:
        checks.append(_check("signer_is_folder_key", True))
    elif audit_records is not None and signer_pub:
        status, detail = _check_legacy_key(
            reviewer, str(signer_pub), rec.get("request_id"), rec, audit_records,
        )
        if status == "legacy":
            checks.append(_check("signer_is_folder_key", True,
                                 "legacy: signed by retired pre-M1 key"))
        elif expected is not None:
            # The folder has a current key but the record's signer does not
            # match and is not legacy.
            checks.append(_check("signer_is_folder_key", False,
                                 f"signed by key {str(signer_pub)[:16]}..., "
                                 f"not the folder's key for reviewer {reviewer!r}; "
                                 f"legacy check: {detail}"))
        else:
            checks.append(_check("signer_is_folder_key", False, detail))
    elif expected is None:
        checks.append(_check("signer_is_folder_key", False,
                             f"the folder has no key for reviewer {reviewer!r}"))
    else:
        checks.append(_check("signer_is_folder_key", False,
                             f"signed by key {str(signer_pub)[:16]}..., "
                             f"not the folder's key for reviewer {reviewer!r}"))

    if rec.get("requires_dual") and (rec.get("decision") == "approved"
                                      or rec.get("state") == "executed"):
        problems: list[str] = []
        strict_good: list[dict[str, Any]] = []
        legacy_good: list[dict[str, Any]] = []
        # R2 (T12b): re-verify each remote approval envelope against the
        # pinned registry, re-bind it to the done-record, and recompute
        # approved_by.  Never trust the unsigned approved_by list.
        remote_approvals = rec.get("remote_approvals", [])
        if isinstance(remote_approvals, list) and remote_approvals:
            verified_users = _reverify_remote_approvals(
                remote_approvals, rec, registry_keys)
            if len(verified_users) >= 2:
                checks.append(_check("dual_control", True,
                                     f"remote dual control: {len(verified_users)} "
                                     f"verified approvers: {sorted(verified_users)}"))
            else:
                problems.append(
                    f"{len(verified_users)} verified remote approver(s); 2 required")
                checks.append(_check("dual_control", False, "; ".join(problems)))
            return checks
        for n, a in enumerate(_approvals(rec), start=1):
            if not isinstance(a, dict):
                problems.append(f"approval {n}: not an object")
                continue
            who = _rid(a.get("reviewer_id"))
            if not verify_approval(a):
                problems.append(f"approval {n} ({who}): signature does not verify")
            elif any(a.get(k) != rec.get(k) for k in ("request_id", "command", "fingerprint")):
                problems.append(f"approval {n} ({who}): approves a different request or command")
            else:
                a_pub = a.get("signer_public_key")
                a_expected = reviewer_keys.get(who)
                if a_expected is not None and a_pub == a_expected:
                    strict_good.append(a)
                elif audit_records is not None and a_pub:
                    a_status, a_detail = _check_legacy_key(
                        who, str(a_pub), rec.get("request_id"), rec,
                        audit_records,
                    )
                    if a_status == "legacy":
                        legacy_good.append(a)
                    elif a_expected is not None:
                        # The folder has a current key for this reviewer but the
                        # approval's key does not match it and is not legacy.
                        problems.append(f"approval {n} ({who}): not signed by the folder's key for {who!r}")
                    else:
                        problems.append(f"approval {n} ({who}): {a_detail}")
                elif a_pub != a_expected:
                    problems.append(f"approval {n} ({who}): not signed by the folder's key for {who!r}")
                else:
                    strict_good.append(a)
        good = strict_good + legacy_good
        has_legacy = bool(legacy_good)
        # Legacy approvals pre-date sig_v and key pinning (M0 era);
        # ``distinct_approvals`` requires both, so use a per-approval
        # validity check when any approval is legacy-verified: each
        # counted approval must be legacy-valid or strict-valid (matching
        # the folder's current key AND sig_v 1).
        if has_legacy:
            counted: list[dict[str, Any]] = list(legacy_good)
            for a in strict_good:
                if a.get("sig_v") == 1:
                    counted.append(a)
            distinct_ok = (
                len({_rid(a.get("reviewer_id")) for a in counted}) >= 2
                and len({a.get("signer_public_key") for a in counted}) >= 2
            )
        else:
            distinct_ok = distinct_approvals(good)
        if not distinct_ok:
            problems.append(f"{len(good)} valid approval(s) by distinct reviewers and keys; 2 required")
        checks.append(_check("dual_control", not problems, "; ".join(problems)))
    return checks


def _checks_for(
    rec: Any,
    stem: str,
    reviewer_keys: dict[str, str | None],
    audit_records: list[dict[str, Any]] | None = None,
    registry_keys: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    if rec is None:
        return [_check("parse", False, "not valid JSON")]
    return check_decision(rec, stem, reviewer_keys, audit_records=audit_records,
                          registry_keys=registry_keys)


def _reviewer_ids(records: list[dict[str, Any]]) -> set[str]:
    ids: set[str] = set()
    for rec in records:
        ids.add(_rid(rec.get("reviewer_id")))
        for a in _approvals(rec):
            if isinstance(a, dict):
                ids.add(_rid(a.get("reviewer_id")))
    return ids


# --- governance ----------------------------------------------------------

def _hits(obj: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for key in ("governance", "governance_violations"):
        vals = obj.get(key)
        for v in vals if isinstance(vals, list) else []:
            if isinstance(v, dict) and isinstance(v.get("clause_id"), str) and v["clause_id"]:
                out.append(v)
    return out


def _governance_summary(clauses: list[dict[str, Any]], decisions: list[dict[str, Any]],
                        audit_records: list[dict[str, Any]]) -> dict[str, Any]:
    by_clause: dict[str, dict[str, Any]] = {}

    def entry(v: dict[str, Any]) -> dict[str, Any]:
        cid = v["clause_id"]
        if cid not in by_clause:
            by_clause[cid] = {"title": v.get("title", ""), "action": v.get("action", ""),
                              "framework_refs": list(v.get("framework_refs") or []),
                              "in_policy": False, "hits_in_decisions": 0, "hits_in_audit": {}}
        return by_clause[cid]

    for c in clauses:
        e = entry({"clause_id": c.get("id"), "title": c.get("title"), "action": c.get("action"),
                   "framework_refs": c.get("framework_refs")})
        e["in_policy"] = True
    for rec in decisions:
        for cid in {v["clause_id"] for v in _hits(rec)}:
            entry(next(v for v in _hits(rec) if v["clause_id"] == cid))["hits_in_decisions"] += 1
    for rec in audit_records:
        event = str(rec.get("event") or "unknown")
        for cid in {v["clause_id"] for v in _hits(rec)}:
            e = entry(next(v for v in _hits(rec) if v["clause_id"] == cid))
            e["hits_in_audit"][event] = e["hits_in_audit"].get(event, 0) + 1

    by_ref: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"clauses": [], "hits_in_decisions": 0, "hits_in_audit": 0})
    for cid, e in sorted(by_clause.items()):
        for ref in e["framework_refs"] or ["(no framework reference)"]:
            r = by_ref[ref]
            r["clauses"].append(cid)
            r["hits_in_decisions"] += e["hits_in_decisions"]
            r["hits_in_audit"] += sum(e["hits_in_audit"].values())
    return {
        "note": ("hits_in_decisions counts done-records in the window carrying the clause; "
                 "hits_in_audit counts audit events (all sessions, whole chains) by event type. "
                 "One escalation can appear in both, and a tool call's retry is a second event."),
        "by_clause": dict(sorted(by_clause.items())),
        "by_framework_ref": dict(sorted(by_ref.items())),
    }


# --- export --------------------------------------------------------------

def _read_json(data: bytes) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _governance_file(layout: FolderLayout, ref: str) -> Path | None:
    p = Path(ref)
    for cand in ([p] if p.is_absolute() else [layout.root / p, Path.cwd() / p]):
        if cand.is_file():
            return cand
    return None


def _runners_at(layout: FolderLayout, when: float | None) -> list[str] | None:
    """`shell.allow_runners` of the approved folder version in force at *when* (None if the
    period has no start, [] if no version existed yet)."""
    if when is None:
        return None
    try:
        from sandbox.connector import policy_versions as pv

        entries = [e for e in pv.read_log(layout) if e.get("kind") == pv.FOLDER and (e.get("at") or 0) <= when]
        if not entries:
            return []
        content = pv.load_object(layout, entries[-1]["sha256"]) or {}
        return list((content.get("shell") or {}).get("allow_runners") or [])
    except Exception:  # noqa: BLE001 — unknown is reported as such, never as "none"
        return None


def build_pack(layout: FolderLayout, since: float | None = None, until: float | None = None) -> dict[str, bytes]:
    """All pack files except the manifest, as {pack path: bytes}."""
    from sandbox.connector.policy import load_policy
    from sandbox.connector.signing import reviewer_public_key

    files: dict[str, bytes] = {}
    notes: list[str] = []

    # Audit chains, whole.
    chains: dict[str, Any] = {}
    audit_records: list[dict[str, Any]] = []
    audit_by_file: dict[str, list[dict[str, Any]]] = {}
    if layout.audit_dir.is_dir():
        for d in sorted(p for p in layout.audit_dir.iterdir() if p.is_dir()):
            f = d / "records.jsonl"
            if not f.is_file():
                continue
            data = f.read_bytes()
            path = f"audit/{d.name}/records.jsonl"
            files[path] = data
            chains[d.name] = {"file": path, **verify_chain_bytes(data)}
            audit_by_file[path] = []
            for line in data.split(b"\n"):
                rec = _read_json(line) if line.strip() else None
                if isinstance(rec, dict):
                    audit_records.append(rec)
                    audit_by_file[path].append(rec)
    files[CHAINS_FILE] = _pretty(chains)

    # Verified audit records for legacy key checks (export == verify).
    verified_audit_records: list[dict[str, Any]] = []
    for _d_name, _chain_info in chains.items():
        if _chain_info.get("ok"):
            _chain_path = _chain_info.get("file", "")
            verified_audit_records.extend(audit_by_file.get(_chain_path, []))

    # Done-records in the window.
    raw: list[tuple[str, bytes, Any]] = []
    excluded = 0
    if layout.done_dir.is_dir():
        for f in sorted(layout.done_dir.glob("*.json")):
            data = f.read_bytes()
            rec = _read_json(data)
            if since is not None or until is not None:
                ts = rec.get("decided_at") if isinstance(rec, dict) else None
                try:
                    ts = float(ts)
                except (TypeError, ValueError):
                    excluded += 1
                    continue
                if (since is not None and ts < since) or (until is not None and ts > until):
                    excluded += 1
                    continue
            raw.append((f.stem, data, rec))
    if excluded:
        notes.append(f"{excluded} done-record(s) outside the window (or without decided_at) were left out.")

    decisions = [rec for _, _, rec in raw if isinstance(rec, dict)]
    reviewer_keys = {rid: (None if rid.startswith("<invalid:") else reviewer_public_key(layout, rid))
                     for rid in sorted(_reviewer_ids(decisions))}
    files[REVIEWER_KEYS] = _pretty(reviewer_keys)

    # T12b R2: include the pinned registry chain and root for offline
    # re-verification of remote approval envelopes.
    sync_dir = layout.root / ".sandbox" / "state" / "sync"
    _reg_file = sync_dir / "registry.json"
    _pr_file = sync_dir / "pinned_root.json"
    if _reg_file.is_file():
        files["keys/registry.json"] = _reg_file.read_bytes()
    if _pr_file.is_file():
        files["keys/pinned_root.json"] = _pr_file.read_bytes()

    # R2: load registry keys for remote approval re-verification
    _pack_reg_keys: dict[str, dict[str, Any]] | None = None
    try:
        if _reg_file.is_file():
            _reg_data = json.loads(_reg_file.read_bytes())
            _reg_chain = _reg_data if isinstance(_reg_data, list) else [_reg_data]
            if _pr_file.is_file():
                _pr_data = json.loads(_pr_file.read_bytes())
                _pr_fp = _pr_data.get("fingerprint", "")
                if _pr_fp:
                    from sandbox.protocol.registry import verify_chain as _vc
                    _verified_reg = _vc(_reg_chain, _pr_fp)
                    _pack_reg_keys = _verified_reg._keys
    except Exception:  # noqa: BLE001
        pass

    index, failed = [], []
    for stem, data, rec in raw:
        path = f"decisions/{stem}.json"
        files[path] = data
        checks = _checks_for(rec, stem, reviewer_keys, audit_records=verified_audit_records,
                              registry_keys=_pack_reg_keys)
        ok = all(c["ok"] for c in checks)
        r = rec if isinstance(rec, dict) else {}
        index.append({
            "file": path, "request_id": r.get("request_id"), "kind": r.get("kind", "command"),
            "command": r.get("command"), "decision": r.get("decision"), "state": r.get("state"),
            "reviewer_id": r.get("reviewer_id"), "decided_at": _iso(r.get("decided_at")),
            "reason": r.get("reason"), "reason_code": r.get("reason_code"),
            "requires_dual": bool(r.get("requires_dual")),
            "approvers": [a.get("reviewer_id") for a in _approvals(r) if isinstance(a, dict)],
            "governance_clauses": sorted({v["clause_id"] for v in _hits(r)}),
            "checks": checks, "ok": ok,
        })
        failed += [{"file": path, "request_id": r.get("request_id"), "check": c["check"], "detail": c["detail"]}
                   for c in checks if not c["ok"]]
    files[DECISIONS_INDEX] = _pretty(index)

    # Policies as they are now.
    policies = []
    gov_clauses: list[dict[str, Any]] = []
    if layout.policy_file.is_file():
        data = layout.policy_file.read_bytes()
        files["policy/policy.json"] = data
        policies.append({"role": "folder_policy", "source": str(layout.policy_file),
                         "file": "policy/policy.json", "sha256": _sha256(data)})
    else:
        notes.append("No .sandbox/policy.json: the folder runs on the default policy.")
    gov_ref = load_policy(layout.policy_file).semantic.governance_policy
    if gov_ref:
        gp = _governance_file(layout, gov_ref)
        if gp is None:
            notes.append(f"Governance policy {gov_ref!r} is set but the file was not found.")
        else:
            data = gp.read_bytes()
            files["policy/governance_policy.json"] = data
            policies.append({"role": "governance_policy", "source": str(gp.resolve()),
                             "file": "policy/governance_policy.json", "sha256": _sha256(data)})
            parsed = _read_json(data)
            if isinstance(parsed, dict):
                gov_clauses = [c for c in parsed.get("clauses") or [] if isinstance(c, dict)]

    # Alerts (B006.2 evidence), as they are at export.
    alert_rows: list[dict[str, Any]] = []
    alerts_path = layout.logs_dir / "alerts.jsonl"
    if alerts_path.is_file():
        data = alerts_path.read_bytes()
        files[ALERTS_FILE] = data
        for line in data.split(b"\n"):
            row = _read_json(line) if line.strip() else None
            if isinstance(row, dict):
                alert_rows.append(row)

    # AIUC-1 index: which control each record is evidence for.
    from sandbox.connector import aiuc1

    try:
        from sandbox.connector.policy_versions import enforced_policy

        enforced = enforced_policy(layout)[0]
    except Exception:  # noqa: BLE001 — fall back to the file as it is
        enforced = load_policy(layout.policy_file)
    aiuc1_index = aiuc1.build_index(
        audit_by_file,
        {f"decisions/{stem}.json": rec for stem, _, rec in raw if isinstance(rec, dict)},
        alert_rows,
        all(c["ok"] for c in chains.values()),
        enforced,
    )
    files[AIUC1_INDEX] = _pretty(aiuc1_index)

    # Summary.
    by_reviewer: dict[str, Counter] = defaultdict(Counter)
    approvals_by_reviewer: Counter = Counter()
    for r in decisions:
        by_reviewer[_rid(r.get("reviewer_id"))][str(r.get("decision") or "unknown")] += 1
        for a in _approvals(r):
            if isinstance(a, dict):
                approvals_by_reviewer[_rid(a.get("reviewer_id"))] += 1
    dual = [i for i in index if i["requires_dual"] and i["decision"] == "approved"]
    exporter_pub = reviewer_public_key(layout, EXPORTER_KEY)
    if exporter_pub and exporter_pub in reviewer_keys.values():
        notes.append("The exporter key is also a reviewer key; the manifest signature then adds nothing.")

    summary = {
        "format": FORMAT,
        "source_root": str(layout.root),
        "window": {"since": _iso(since), "until": _iso(until), "applies_to": "decisions (decided_at)"},
        "decisions": {
            "total": len(index),
            "by_outcome": dict(Counter(str(i["state"] or i["decision"] or "unknown") for i in index)),
            "by_decision": dict(Counter(str(i["decision"] or "unknown") for i in index)),
            "by_reviewer": {k: dict(v) for k, v in sorted(by_reviewer.items())},
            "dual_control_approvals_by_reviewer": dict(sorted(approvals_by_reviewer.items())),
            "dual_control": {"approved_requiring_dual": len(dual),
                             "passing_all_checks": sum(1 for i in dual if i["ok"])},
            "passing_all_checks": sum(1 for i in index if i["ok"]),
        },
        "open_requests": {
            "pending": len(list(layout.pending_dir.glob("*.json"))) if layout.pending_dir.is_dir() else 0,
            "claimed": len(list(layout.claimed_dir.glob("*.json"))) if layout.claimed_dir.is_dir() else 0,
        },
        "audit": {"sessions": len(chains), "records": sum(c["records"] for c in chains.values()),
                  "all_chains_valid": all(c["ok"] for c in chains.values()),
                  "chains": chains},
        "governance": _governance_summary(gov_clauses, decisions, audit_records),
        "aiuc1": {"release": aiuc1_index["release"], "file": AIUC1_INDEX, "note": aiuc1_index["note"],
                  "by_requirement": aiuc1_index["by_requirement"]},
        "alerts": {"file": ALERTS_FILE if ALERTS_FILE in files else None, "count": len(alert_rows)},
        # ADR 0009: whether workspace code runners could run without a human, and when that changed.
        "runners": {
            "allow_runners": list(enforced.shell.allow_runners),
            "allow_runners_at_since": _runners_at(layout, since),
            "opt_in_changes": [
                {"at": _iso(r.get("ts")), "change_id": r.get("change_id"), "runners": r.get("runners"),
                 "proposer": r.get("proposer"), "reviewer": r.get("reviewer")}
                for r in audit_records if r.get("event") == "runners_allowed"
                and (since is None or (r.get("ts") or 0) >= since) and (until is None or (r.get("ts") or 0) <= until)],
            "runner_allowed_events": sum(
                1 for r in audit_records if r.get("event") == "runner_allowed"
                and (since is None or (r.get("ts") or 0) >= since) and (until is None or (r.get("ts") or 0) <= until)),
        },
        "policies": policies,
        "failed_checks": failed + [{"file": c["file"], "check": "audit_chain", "detail": c["message"]}
                                   for c in chains.values() if not c["ok"]],
        "notes": notes,
        "limits": LIMITS,
    }
    files[SUMMARY] = _pretty(summary)
    return files


def sign_manifest(layout: FolderLayout, files: dict[str, bytes], meta: dict[str, Any]) -> bytes:
    from sandbox.connector.signing import _load_or_create_key, _tag_bytes
    from sandbox.crypto.signing import sign_message
    from sandbox.protocol.domains import EVIDENCE

    key = _load_or_create_key(layout, EXPORTER_KEY)
    body = {**meta, "format": FORMAT, "files": {p: _sha256(b) for p, b in sorted(files.items())},
            "exporter_public_key": bytes(key.verify_key).hex(),
            "sig_v": 1}
    # SEC-31: sign with EVIDENCE domain tag || 0x00 || canonical JSON.
    unsigned = {k: v for k, v in body.items() if k != "signature"}
    tagged_data = _tag_bytes(EVIDENCE) + b"\x00" + _canon(unsigned)
    body["signature"] = sign_message(tagged_data, key)
    return _pretty(body)


def _key_status_for(rec: dict[str, Any], layout: FolderLayout, audit_records: list[dict[str, Any]]) -> str:
    """Determine the key_status for a done-record: 'pinned', 'legacy' or 'unverifiable'.

    - 'pinned': the signer's key is pinned for this reviewer in this workspace.
    - 'legacy': the record was signed with a now-retired pre-M1 key AND its
      done-record file existed at rotation time (ADR 0007 1.6).
    - 'unverifiable': anything else.

    Delegates the legacy check to :func:`_check_legacy_key` (the same helper
    ``check_decision`` uses on the verify side) so the canonical hash and
    ``done_at_rotation`` logic is never duplicated.
    """
    from sandbox.connector import keyhome
    from sandbox.connector.signing import verify_record

    if not isinstance(rec, dict) or not verify_record(rec):
        return "unverifiable"
    reviewer_id = rec.get("reviewer_id")
    pub = rec.get("signer_public_key")
    if not reviewer_id or not pub:
        return "unverifiable"
    # Check if pinned
    try:
        pinned = keyhome.get_pinned_key(layout, reviewer_id)
        if pinned and pub == pinned:
            return "pinned"
    except keyhome.KeyHomeError:
        pass
    # Check if legacy via shared helper
    status, _ = _check_legacy_key(reviewer_id, pub, rec.get("request_id"), rec, audit_records)
    return status if status == "legacy" else "unverifiable"


def _label_decisions(layout: FolderLayout, index: list[dict[str, Any]],
                     files: dict[str, bytes]) -> list[dict[str, Any]]:
    """Add ``key_status`` and ``new_key_approval`` to each decision entry."""
    from sandbox.connector import keyhome

    # Gather audit records for key_rotated and key_pinned events
    audit_records: list[dict[str, Any]] = []
    for path, data in files.items():
        if path.startswith("audit/") and path.endswith("/records.jsonl"):
            for line in data.split(b"\n"):
                if line.strip():
                    try:
                        audit_records.append(json.loads(line))
                    except (ValueError, UnicodeDecodeError):
                        pass

    # Build pin timing: when each reviewer was first pinned
    pin_times: dict[str, float] = {}
    for e in audit_records:
        if e.get("event") == "key_pinned":
            rid = e.get("reviewer_id", "")
            ts = e.get("ts", 0)
            if rid and (rid not in pin_times or ts < pin_times[rid]):
                pin_times[rid] = ts

    result = []
    for entry in index:
        entry = dict(entry)  # shallow copy
        # Load the actual record for key_status check
        rec_path = entry.get("file", "")
        rec = None
        if rec_path in files:
            try:
                rec = json.loads(files[rec_path].decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                pass
        if rec is not None:
            entry["key_status"] = _key_status_for(rec, layout, audit_records)
        else:
            entry["key_status"] = "unverifiable"
        # Check for new-key approval in dual control
        if entry.get("requires_dual") and rec is not None:
            approvals = rec.get("approvals") or []
            request_queued_at = rec.get("created_at") or 0
            new_key_flags = []
            for a in approvals:
                if isinstance(a, dict):
                    a_reviewer = a.get("reviewer_id", "")
                    pinned_at = pin_times.get(a_reviewer)
                    if pinned_at is not None:
                        try:
                            if float(pinned_at) > float(request_queued_at):
                                new_key_flags.append(a_reviewer)
                        except (TypeError, ValueError):
                            pass
            if new_key_flags:
                entry["new_key_approval"] = new_key_flags
        result.append(entry)
    return result


def export_evidence(layout: FolderLayout, out: str | Path, since: str | None = None,
                    until: str | None = None) -> dict[str, Any]:
    """Write the pack to *out* (a new or empty directory, or a new ``.zip``).
    Returns the summary plus ``out`` and ``exporter_public_key``."""
    s, u = parse_time(since), parse_time(until)
    if s is not None and u is not None and s > u:
        raise EvidenceError("--since is after --until")
    out = Path(out)
    is_zip = out.suffix.lower() == ".zip"
    if is_zip and out.exists():
        raise EvidenceError(f"{out} already exists; choose a new file")
    if not is_zip and out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise EvidenceError(f"{out} exists and is not an empty directory")
    try:
        if out.resolve().is_relative_to(layout.base.resolve()):
            raise EvidenceError("write the pack outside .sandbox/")
    except OSError:
        pass

    files = build_pack(layout, s, u)
    meta = {"created_at": datetime.now(timezone.utc).isoformat(), "source_root": str(layout.root),
            "window": {"since": _iso(s), "until": _iso(u)}}
    files[MANIFEST] = sign_manifest(layout, files, meta)

    if is_zip:
        out.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(out, "x", compression=zipfile.ZIP_DEFLATED) as z:
            for p, data in sorted(files.items()):
                z.writestr(p, data)
    else:
        for p, data in sorted(files.items()):
            dest = out.joinpath(*PurePosixPath(p).parts)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)

    summary = json.loads(files[SUMMARY].decode("utf-8"))
    summary["out"] = str(out)
    summary["exporter_public_key"] = json.loads(files[MANIFEST].decode("utf-8"))["exporter_public_key"]
    summary["file_count"] = len(files)

    # ADR 0007 T3: add per-decision key_status and new-key-approval flags.
    # The SUMMARY file keeps its schema (frozen tests); the returned dict gets
    # extra keys for T3 consumers (evidence pack, ``sandbox verify``).
    index_data = json.loads(files.get(DECISIONS_INDEX, b"[]").decode("utf-8"))
    if isinstance(index_data, list):
        decision_detail = _label_decisions(layout, index_data, files)
        summary["checks"] = decision_detail
        # Keep summary["decisions"] as a dict (backward compat for frozen tests)
        # but also make it iterable as per-decision dicts through a wrapper.
        summary["decisions"] = _DecisionsView(summary["decisions"], decision_detail)
    return summary


# --- verify --------------------------------------------------------------

def read_pack(path: str | Path) -> dict[str, bytes]:
    p = Path(path)
    if p.is_dir():
        return {f.relative_to(p).as_posix(): f.read_bytes() for f in sorted(p.rglob("*")) if f.is_file()}
    if p.is_file():
        try:
            with zipfile.ZipFile(p) as z:
                return {n: z.read(n) for n in z.namelist() if not n.endswith("/")}
        except (zipfile.BadZipFile, OSError) as exc:
            raise EvidenceError(f"{p} is not a readable zip: {exc}") from exc
    raise EvidenceError(f"{p} not found")


def _safe(path: str) -> bool:
    pp = PurePosixPath(path)
    return bool(path) and "\\" not in path and not pp.is_absolute() and ".." not in pp.parts and ":" not in path


def verify_evidence(path: str | Path, exporter_key: str | None = None,
                    expected_root: str | None = None) -> dict[str, Any]:
    """Re-verify a pack offline. ``ok`` is False if anything fails; each entry
    of ``failures`` says what and where.

    S3: *expected_root* is the pinned-root fingerprint supplied out of band.
    If absent, remote dual-control results are UNVERIFIED (never ok).
    If it differs from the pack's ``keys/pinned_root.json``, fail.
    """
    from sandbox.crypto.signing import verify_signature

    files = read_pack(path)
    failures: list[str] = []
    result: dict[str, Any] = {"ok": False, "failures": failures, "files": 0, "decisions": 0,
                              "sessions": 0, "exporter_public_key": None}

    manifest = _read_json(files.get(MANIFEST, b""))
    if not isinstance(manifest, dict):
        failures.append(f"{MANIFEST}: missing or not valid JSON")
        return result
    if manifest.get("format") != FORMAT:
        failures.append(f"{MANIFEST}: unknown format {manifest.get('format')!r}")
    pub = manifest.get("exporter_public_key")
    result["exporter_public_key"] = pub
    try:
        vk = VerifyKey(bytes.fromhex(str(pub)))
        body = {k: v for k, v in manifest.items() if k != "signature"}
        sig_v = manifest.get("sig_v")
        if sig_v == 1:
            # SEC-31: sig_v: 1 manifest must verify on the tagged path only (no downgrade).
            from sandbox.connector.signing import _tag_bytes
            from sandbox.protocol.domains import EVIDENCE

            tagged_data = _tag_bytes(EVIDENCE) + b"\x00" + _canon(body)
            if not verify_signature(tagged_data, str(manifest.get("signature", "")), vk):
                failures.append(f"{MANIFEST}: signature does not verify (the manifest was changed after export)")
            result["manifest_tagged"] = True
        else:
            # Legacy: untagged manifest (pre-T4 backward compatibility).
            if not verify_signature(_canon(body), str(manifest.get("signature", "")), vk):
                failures.append(f"{MANIFEST}: signature does not verify (the manifest was changed after export)")
            result["manifest_tagged"] = False
    except (ValueError, TypeError):
        failures.append(f"{MANIFEST}: exporter_public_key is not a valid Ed25519 key")
    if exporter_key and str(pub).lower() != exporter_key.strip().lower():
        failures.append(f"{MANIFEST}: signed by exporter key {str(pub)[:16]}..., "
                        f"not the expected key {exporter_key[:16]}...")

    listed = manifest.get("files")
    if not isinstance(listed, dict):
        failures.append(f"{MANIFEST}: no file list")
        listed = {}
    for p, digest in sorted(listed.items()):
        if not _safe(p):
            failures.append(f"{MANIFEST}: unsafe path {p!r}")
        elif p not in files:
            failures.append(f"{p}: listed in the manifest but missing from the pack")
        elif _sha256(files[p]) != digest:
            failures.append(f"{p}: sha256 does not match the manifest (file changed after export)")
    for p in sorted(set(files) - set(listed) - {MANIFEST}):
        failures.append(f"{p}: not listed in the manifest (file added after export)")
    result["files"] = len(listed)

    # What export recorded, to say whether a failure is new.
    index = _read_json(files.get(DECISIONS_INDEX, b"[]"))
    index = index if isinstance(index, list) else []
    failed_at_export = {i.get("file") for i in index if isinstance(i, dict) and not i.get("ok")}
    chains = _read_json(files.get(CHAINS_FILE, b"{}"))
    chains = list(chains.values()) if isinstance(chains, dict) else []
    broken_at_export = {c.get("file") for c in chains if isinstance(c, dict) and not c.get("ok")}

    reviewer_keys = _read_json(files.get(REVIEWER_KEYS, b"")) if REVIEWER_KEYS in files else None
    if not isinstance(reviewer_keys, dict):
        failures.append(f"{REVIEWER_KEYS}: missing or not valid JSON; signer checks cannot run")
        reviewer_keys = {}

    # Pre-verify audit chains: extract records only from chains that verify
    # (ADR 0007 1.6 contract: "that chain verifies").  Broken chains are
    # reported below; their records are never used for legacy key checks.
    verified_audit_records: list[dict[str, Any]] = []
    chain_results: dict[str, dict[str, Any]] = {}
    for p in sorted(files):
        if p.startswith("audit/") and p.endswith("/records.jsonl"):
            result["sessions"] += 1
            r = verify_chain_bytes(files[p])
            chain_results[p] = r
            if r["ok"]:
                for line in files[p].split(b"\n"):
                    if line.strip():
                        try:
                            verified_audit_records.append(json.loads(line))
                        except (ValueError, UnicodeDecodeError):
                            pass

    # S3/R2: load registry keys from the pack for remote approval re-verification.
    # If expected_root is provided, verify the pack's pinned root matches it.
    # If expected_root is absent, remote dual-control is UNVERIFIED (never ok).
    _verify_reg_keys: dict[str, dict[str, Any]] | None = None
    _root_verified = False
    try:
        _v_reg_raw = files.get("keys/registry.json")
        _v_pr_raw = files.get("keys/pinned_root.json")
        if _v_reg_raw and _v_pr_raw:
            _v_reg_data = json.loads(_v_reg_raw)
            _v_pr_data = json.loads(_v_pr_raw)
            _v_pr_fp = _v_pr_data.get("fingerprint", "")
            if expected_root is not None:
                # S3: out-of-band root check
                if _v_pr_fp != expected_root:
                    failures.append(
                        f"pinned_root fingerprint {_v_pr_fp[:16]}... does not "
                        f"match expected root {expected_root[:16]}...")
                    _v_pr_fp = ""  # do not trust the pack's registry
                else:
                    _root_verified = True
            if _v_pr_fp:
                _v_chain = _v_reg_data if isinstance(_v_reg_data, list) else [_v_reg_data]
                from sandbox.protocol.registry import verify_chain as _vc2
                _v_verified = _vc2(_v_chain, _v_pr_fp)
                _verify_reg_keys = _v_verified._keys
    except Exception:  # noqa: BLE001
        pass
    # S3 (security round 4, Q2): the pack's own pinned root proves nothing
    # about who approved, because the device holder made the pack.  A pack
    # with remote-approved decisions verifies only against a root supplied
    # out of band; without one the result is not ok.
    def _has_remote(raw: Any) -> bool:
        try:
            data = raw if isinstance(raw, str) else bytes(raw).decode("utf-8")
            return bool(json.loads(data).get("remote_approvals"))
        except Exception:  # noqa: BLE001
            return False

    _pack_has_remote = any(
        p.startswith("decisions/") and p.endswith(".json") and p != DECISIONS_INDEX
        and _has_remote(files[p])
        for p in files
    )
    if _pack_has_remote and not _root_verified:
        result["remote_root_unverified"] = True
        failures.append(
            "remote dual control UNVERIFIED: pass --expect-root with the "
            "registry root fingerprint obtained out of band")

    legacy_count = 0
    decisions_detail: list[dict[str, Any]] = []

    for p in sorted(files):
        if not (p.startswith("decisions/") and p.endswith(".json")) or p == DECISIONS_INDEX:
            continue
        result["decisions"] += 1
        rec = _read_json(files[p])
        stem = PurePosixPath(p).stem
        checks = _checks_for(rec, stem, reviewer_keys, audit_records=verified_audit_records,
                              registry_keys=_verify_reg_keys)
        tag = " (already failing at export)" if p in failed_at_export else ""

        # Determine per-record key_status from the signer_is_folder_key check.
        key_status = "pinned"
        for c in checks:
            if c["check"] == "signer_is_folder_key":
                if not c["ok"]:
                    key_status = "unverifiable"
                elif c.get("detail", "").startswith("legacy"):
                    key_status = "legacy"
                    legacy_count += 1
        decisions_detail.append({
            "request_id": stem,
            "key_status": key_status,
            "ok": all(c["ok"] for c in checks),
        })

        for c in checks:
            if not c["ok"]:
                failures.append(f"{p}: {c['check']} failed: {c['detail'] or 'check failed'}{tag}")

    # Report broken audit chains (already verified above).
    for p, r in sorted(chain_results.items()):
        if not r["ok"]:
            tag = " (already broken at export)" if p in broken_at_export else ""
            failures.append(f"{p}: audit chain failed: {r['message']}{tag}")

    result["ok"] = not failures
    result["created_at"] = manifest.get("created_at")
    result["source_root"] = manifest.get("source_root")
    result["legacy_count"] = legacy_count
    result["decisions_detail"] = decisions_detail
    return result
