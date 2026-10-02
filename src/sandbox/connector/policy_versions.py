"""Policy versioning, change control and drift detection.

Two policies decide what an agent may do in a folder: the folder policy
(``.sandbox/policy.json``) and, optionally, the governance policy that
``semantic.governance_policy`` points at. This module gives both a history:

* **Content-addressed store.** Every version that was ever proposed or
  accepted is kept as ``.sandbox/policy_history/<sha256>.json``. The file holds
  the canonical JSON (sorted keys, no whitespace), so ``sha256(file) == name``.
  A version id is the first 12 hex characters of that hash.
* **Log.** ``policy_history/log.jsonl`` lists accepted versions in order, each
  with who accepted it, when, why, the previous version, and an Ed25519
  approval signed with that reviewer's key (``signing.sign_approval``).
  ``policy_history/head.json`` names the current approved version of each.
* **Change requests.** ``policy_history/changes/<id>.json``: a proposed version,
  signed by its proposer, that only a *different* reviewer (different id and
  different key) can approve. Approval writes the file and advances the head.
* **Drift.** When the policy on disk (or the governance file) is not the
  approved version, the gateway enforces the *meet*: the approved version,
  tightened by anything stricter in the file on disk. An out-of-band edit can
  add scrutiny but cannot remove it. Each new drift is written to the audit
  chain as a ``policy_drift`` event, and every decision records which version
  made it (``policy_version``).

A folder with no history yet ("unversioned") behaves as before: the file on
disk is enforced as-is. ``sandbox init`` records the first version; older
folders adopt one with ``sandbox policy baseline``.

Limits, stated plainly: reviewer identity is a reviewer id plus a key stored
under ``.sandbox/state/keys`` (docs/TCB.md). "Proposer is not the approver"
means two different ids with two different keys, not proven different people.
Anyone who can write ``.sandbox/`` can also rewrite this history; the audit
chain records each acceptance, which makes a rewrite detectable, not
impossible.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import VERDICTS, FolderPolicy, load_policy, save_policy

FOLDER = "folder"
GOVERNANCE = "governance"
KINDS = (FOLDER, GOVERNANCE)
SHORT = 12


# ---------------------------------------------------------------------------
# hashing and the content-addressed store
# ---------------------------------------------------------------------------

def canonical(content: dict[str, Any]) -> bytes:
    return json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_of(content: dict[str, Any] | None) -> str | None:
    if content is None:
        return None
    return hashlib.sha256(canonical(content)).hexdigest()


def short(sha: str | None) -> str | None:
    return sha[:SHORT] if sha else None


def history_dir(layout: FolderLayout) -> Path:
    return layout.base / "policy_history"


def _changes_dir(layout: FolderLayout) -> Path:
    return history_dir(layout) / "changes"


def _head_file(layout: FolderLayout) -> Path:
    return history_dir(layout) / "head.json"


def _log_file(layout: FolderLayout) -> Path:
    return history_dir(layout) / "log.jsonl"


def object_path(layout: FolderLayout, sha: str) -> Path:
    return history_dir(layout) / f"{sha}.json"


def _atomic_write(layout: FolderLayout, dest: Path, data: bytes) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    layout.tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp = layout.tmp_dir / f"{uuid.uuid4().hex}.tmp"
    tmp.write_bytes(data)
    os.replace(tmp, dest)


def store(layout: FolderLayout, content: dict[str, Any]) -> str:
    """Write *content* to the store (once); return its full sha256."""
    sha = sha256_of(content)
    path = object_path(layout, sha)
    if not path.exists():
        _atomic_write(layout, path, canonical(content))
    return sha


def load_object(layout: FolderLayout, sha: str) -> dict[str, Any] | None:
    try:
        return json.loads(object_path(layout, sha).read_bytes().decode("utf-8"))
    except (OSError, ValueError):
        return None


def resolve(layout: FolderLayout, ref: str) -> str | None:
    """Full sha256 for a version id or prefix (at least 4 hex chars), if unique."""
    ref = ref.strip().lower()
    if len(ref) < 4 or any(c not in "0123456789abcdef" for c in ref):
        return None
    d = history_dir(layout)
    if not d.is_dir():
        return None
    hits = [p.stem for p in d.glob(f"{ref}*.json") if len(p.stem) == 64]
    return hits[0] if len(hits) == 1 else None


# ---------------------------------------------------------------------------
# reading the policies on disk
# ---------------------------------------------------------------------------

def folder_content(layout: FolderLayout) -> dict[str, Any]:
    """The folder policy as the gateway loads it (protections re-injected)."""
    return load_policy(layout.policy_file).model_dump()


def normalize_folder(data: dict[str, Any]) -> dict[str, Any]:
    p = FolderPolicy.model_validate(data)
    p._inject_protections()
    return p.model_dump()


def normalize_governance(data: dict[str, Any]) -> dict[str, Any]:
    from sandbox.governance.policy import GovernancePolicy

    return GovernancePolicy.model_validate(data).model_dump()


def governance_path(layout: FolderLayout, ref: str) -> Path | None:
    """Where a governance pointer leads. Relative paths are tried against the
    folder root first, then the process working directory (as the hook does)."""
    if not ref:
        return None
    p = Path(ref)
    if p.is_absolute():
        return p
    under_root = layout.root / p
    return under_root if under_root.exists() else p


def read_governance(layout: FolderLayout, ref: str) -> dict[str, Any] | None:
    path = governance_path(layout, ref)
    if path is None:
        return None
    try:
        return normalize_governance(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return None


def read_head(layout: FolderLayout) -> dict[str, Any]:
    try:
        return json.loads(_head_file(layout).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def is_versioned(layout: FolderLayout) -> bool:
    return bool(read_head(layout).get(FOLDER))


def read_log(layout: FolderLayout) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        with open(_log_file(layout), encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass
    except OSError:
        pass
    return out


# ---------------------------------------------------------------------------
# the meet: approved policy, tightened by anything stricter on disk
# ---------------------------------------------------------------------------

_RANK = {v: i for i, v in enumerate(VERDICTS)}  # allow < observe < escalate < deny

_VERDICT_FIELDS = (
    ("triggers", "shell"), ("triggers", "write_outside"), ("triggers", "network"),
    ("triggers", "read_outside"), ("unknown_tool_action",), ("shell", "blocklist_action"),
)
# More entries = more scrutiny: keep everything from both.
_UNION_FIELDS = (
    ("deny_tools",), ("shell", "deny_patterns"), ("read", "deny_globs"), ("write", "deny_globs"),
    ("semantic", "taint_escalates"), ("semantic", "scan_tools"),
)
# More entries = less scrutiny: keep only what both contain.
_INTERSECT_FIELDS = (
    ("shell", "allow_patterns"), ("read", "allow_prefixes"), ("write", "allow_prefixes"),
    ("network", "allow_hosts"), ("network", "allow_mcp_servers"),
)
_AND_FIELDS = (("auto_allow",), ("network", "allow_search"))           # True only if both say so
_OR_FIELDS = (("semantic", "enabled"), ("semantic", "student"),        # True if either says so
              ("output", "scrub_secrets"), ("scan", "preserve_originals"),
              ("audit", "log_allowed"), ("alerts", "enabled"), ("limits", "enabled"))
_MIN_FIELDS = (("semantic", "threshold"), ("semantic", "screen_threshold"),
               ("limits", "shell"), ("limits", "write"), ("limits", "network"), ("limits", "total"))
_MAX_FIELDS = (("semantic", "taint_ttl_seconds"), ("semantic", "max_scan_chars"),
               ("audit", "retention_days"), ("audit", "retention_days_reviewed"),
               ("audit", "retention_days_incident"), ("limits", "window_seconds"))
# Every other field (URLs, timeouts, the governance pointer, ...) has no
# "stricter" direction, so the approved value is kept.


def _get(d: dict[str, Any], path: tuple[str, ...]) -> Any:
    for k in path:
        if not isinstance(d, dict) or k not in d:
            return None
        d = d[k]
    return d


def _set(d: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    for k in path[:-1]:
        d = d.setdefault(k, {})
    d[path[-1]] = value


def _stricter(a: Any, b: Any) -> Any:
    if b not in _RANK:
        return a
    if a not in _RANK:
        return b
    return a if _RANK[a] >= _RANK[b] else b


def meet(approved: dict[str, Any], other: dict[str, Any]) -> dict[str, Any]:
    """The approved folder policy, tightened by anything stricter in *other*.

    Never looser than *approved*. Equal to *other* exactly when *other* only
    tightens *approved* (see :func:`only_tightens`).
    """
    out = json.loads(json.dumps(approved))

    def both(path: tuple[str, ...]) -> tuple[Any, Any, bool]:
        a, b = _get(approved, path), _get(other, path)
        return a, b, a is not None and b is not None

    for path in _VERDICT_FIELDS:
        a, b, ok = both(path)
        if ok:
            _set(out, path, _stricter(a, b))
    for path in _UNION_FIELDS:
        a, b, ok = both(path)
        if ok:
            _set(out, path, list(b) + [x for x in a if x not in b])
    for path in _INTERSECT_FIELDS:
        a, b, ok = both(path)
        if ok:
            _set(out, path, [x for x in b if x in a])
    for path in _AND_FIELDS:
        a, b, ok = both(path)
        if ok:
            _set(out, path, bool(a) and bool(b))
    for path in _OR_FIELDS:
        a, b, ok = both(path)
        if ok:
            _set(out, path, bool(a) or bool(b))
    for path in _MIN_FIELDS:
        a, b, ok = both(path)
        if ok:
            _set(out, path, min(a, b))
    for path in _MAX_FIELDS:
        a, b, ok = both(path)
        if ok:
            _set(out, path, max(a, b))
    # A reviewed file stays trusted (unscanned) only if both versions trust it
    # at the same content hash.
    a, b, ok = both(("semantic", "trusted_files"))
    if ok:
        keys = {(t.get("path"), t.get("sha256")) for t in a}
        _set(out, ("semantic", "trusted_files"), [t for t in b if (t.get("path"), t.get("sha256")) in keys])
    return normalize_folder(out)


def only_tightens(old: dict[str, Any], new: dict[str, Any]) -> bool:
    """True if *new* is *old* with only stricter settings (or no change)."""
    return canonical(meet(old, new)) == canonical(normalize_folder(new))


def loosened_fields(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """Dotted paths where *new* is looser than *old*, or changed with no stricter direction."""
    m, n = meet(old, new), normalize_folder(new)
    out: list[str] = []

    def walk(a: Any, b: Any, prefix: str) -> None:
        if isinstance(a, dict) and isinstance(b, dict):
            for k in sorted(set(a) | set(b)):
                walk(a.get(k), b.get(k), f"{prefix}.{k}" if prefix else k)
        elif a != b:
            out.append(prefix)

    walk(m, n, "")
    return out


def union_governance(sources: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Every clause from every source (clauses only add scrutiny). A clause id
    used with different content in two sources is kept twice, renamed."""
    sources = [s for s in sources if s]
    if not sources:
        return None
    clauses: list[dict[str, Any]] = []
    seen: set[bytes] = set()
    ids: set[str] = set()
    for src in sources:
        for c in src.get("clauses", []):
            key = canonical(c)
            if key in seen:
                continue
            seen.add(key)
            c = dict(c)
            if c.get("id") in ids:
                c["id"] = f"{c.get('id')}~{hashlib.sha256(key).hexdigest()[:6]}"
            ids.add(c["id"])
            clauses.append(c)
    return normalize_governance({"name": sources[0].get("name", "governance policy"), "clauses": clauses})


# ---------------------------------------------------------------------------
# what the gateway enforces, and which version that is
# ---------------------------------------------------------------------------

def _evaluate(layout: FolderLayout) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None, bool]:
    """(effective folder content, version info, governance union to materialize or None, drifted)."""
    disk = folder_content(layout)
    disk_ref = disk.get("semantic", {}).get("governance_policy", "")
    disk_gov = read_governance(layout, disk_ref)
    disk_ids = {FOLDER: short(sha256_of(disk)), GOVERNANCE: short(sha256_of(disk_gov))}

    head = read_head(layout)
    if not head.get(FOLDER):
        return disk, {**disk_ids, "state": "unversioned"}, None, False

    approved = load_object(layout, head[FOLDER])
    if approved is None:
        # The approved version is missing from the store: fall back to the
        # shipped defaults as the baseline, and report drift.
        from sandbox.connector.policy import default_policy

        approved = default_policy().model_dump()
    # The approved governance version counts only while the approved folder
    # policy still points at a governance file (an approved change can remove it).
    approved_gov_sha = head.get(GOVERNANCE) if approved.get("semantic", {}).get("governance_policy") else None
    approved_gov = load_object(layout, approved_gov_sha) if approved_gov_sha else None
    approved_ids = {FOLDER: short(head[FOLDER]), GOVERNANCE: short(approved_gov_sha)}

    folder_drift = sha256_of(disk) != head[FOLDER]
    gov_drift = sha256_of(disk_gov) != approved_gov_sha
    if not folder_drift and not gov_drift:
        return disk, {**disk_ids, "state": "approved"}, None, False

    effective = meet(approved, disk) if folder_drift else disk
    eff_ref = effective.get("semantic", {}).get("governance_policy", "")
    eff_gov_at_ref = read_governance(layout, eff_ref)
    gov_union = union_governance([approved_gov, eff_gov_at_ref, disk_gov])
    materialize = None
    if gov_union is not None and canonical(gov_union) != canonical(eff_gov_at_ref or {}):
        # Point the enforced policy at the union, stored in the history.
        materialize = gov_union
        effective = json.loads(json.dumps(effective))
        effective["semantic"]["governance_policy"] = str(object_path(layout, sha256_of(gov_union)))
    info = {
        FOLDER: short(sha256_of(effective)),
        GOVERNANCE: short(sha256_of(gov_union)),
        "state": "drift",
        "approved": approved_ids,
        "on_disk": disk_ids,
        "drift": [k for k, d in ((FOLDER, folder_drift), (GOVERNANCE, gov_drift)) if d],
    }
    return effective, info, materialize, True


def version_info(layout: FolderLayout) -> dict[str, Any]:
    """Which policy versions are in force now (no side effects)."""
    try:
        return _evaluate(layout)[1]
    except Exception as exc:  # noqa: BLE001 — never break a caller over bookkeeping
        return {"state": "unknown", "error": type(exc).__name__}


def current_version(layout: FolderLayout) -> dict[str, Any]:
    """The version stamped on a record being written now (audit, escalation).

    Recomputed from disk each time (a few small file reads) rather than cached,
    so a long-running process (the MCP server) never stamps a stale version.
    """
    return version_info(layout)


def enforced_policy(layout: FolderLayout) -> tuple[FolderPolicy, dict[str, Any]]:
    """The policy the gateway must enforce now, and its version info.

    Approved, or unversioned: the file on disk. Drifted: the meet of the
    approved version and the file (see module docstring), with the governance
    pointer moved to the union of approved and on-disk clauses. The first time
    a given drift is seen it is written to the audit chain.
    """
    effective, info, materialize, drifted = _evaluate(layout)
    if drifted:
        store(layout, effective)
        if materialize is not None:
            store(layout, materialize)
        _report_drift(layout, info)
    policy = FolderPolicy.model_validate(effective)
    policy._inject_protections()
    return policy, info


def _report_drift(layout: FolderLayout, info: dict[str, Any]) -> None:
    marker = layout.state_dir / "policy_drift_seen.json"
    key = json.dumps(info.get("on_disk"), sort_keys=True)
    try:
        if json.loads(marker.read_text(encoding="utf-8")).get("key") == key:
            return
    except (OSError, ValueError):
        pass
    audit(layout, {
        "event": "policy_drift",
        "policy_version": info,
        "handling": "enforcing the approved version, tightened by stricter settings on disk",
    })
    _activity(layout, f"POLICY DRIFT  on disk {info.get('on_disk')} != approved {info.get('approved')}; "
                      "enforcing the stricter of the two. Review with `sandbox policy diff approved current`.")
    try:
        _atomic_write(layout, marker, json.dumps({"key": key, "at": time.time()}).encode("utf-8"))
    except OSError:
        pass


# ---------------------------------------------------------------------------
# audit helpers
# ---------------------------------------------------------------------------

def audit(layout: FolderLayout, record: dict[str, Any]) -> None:
    """Best-effort append to the folder's audit chain."""
    try:
        from sandbox.connector.audit import FolderAudit

        try:
            session_id = json.loads(layout.session_file.read_text(encoding="utf-8")).get("session_id", "")
        except (OSError, ValueError):
            session_id = ""
        FolderAudit(layout.audit_dir, session_id).append(record)
    except Exception:  # noqa: BLE001
        pass


def _activity(layout: FolderLayout, line: str) -> None:
    try:
        layout.logs_dir.mkdir(parents=True, exist_ok=True)
        with open(layout.logs_dir / "activity.log", "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {line}\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# signatures
# ---------------------------------------------------------------------------

_PROPOSAL_FIELDS = ("change_id", "kind", "base", "new_sha256", "governance_sha256",
                    "proposer", "reason", "proposed_at")


def _approval_subject(change_id: str, kind: str, base: str | None, new: str, gov: str | None = None) -> dict[str, Any]:
    """What an acceptance signature binds: the change id, the exact content hash(es) and the base."""
    fingerprint = new if not gov else f"{new}+{gov}"
    return {"request_id": change_id, "command": f"policy {kind} {short(base) or 'none'} -> {short(new)}",
            "fingerprint": fingerprint}


def _sign_proposal(layout: FolderLayout, change: dict[str, Any]) -> None:
    from sandbox.connector.signing import _canonical, _load_or_create_key
    from sandbox.crypto.signing import sign_message

    key = _load_or_create_key(layout, change["proposer"])
    change["proposer_public_key"] = bytes(key.verify_key).hex()
    change["proposal_signature"] = sign_message(_canonical(change, _PROPOSAL_FIELDS), key)


def verify_proposal(change: dict[str, Any]) -> bool:
    from nacl.signing import VerifyKey

    from sandbox.connector.signing import _canonical
    from sandbox.crypto.signing import verify_signature

    try:
        vk = VerifyKey(bytes.fromhex(change.get("proposer_public_key", "")))
    except (ValueError, TypeError):
        return False
    return verify_signature(_canonical(change, _PROPOSAL_FIELDS), change.get("proposal_signature", ""), vk)


def verify_entry(entry: dict[str, Any]) -> bool:
    """A log entry's approval verifies and binds exactly this version."""
    from sandbox.connector.signing import verify_approval

    approval = entry.get("approval") or {}
    subject = _approval_subject(entry.get("change_id", ""), entry.get("kind", ""), entry.get("previous"),
                                entry.get("sha256", ""), entry.get("governance_sha256"))
    return (verify_approval(approval) and approval.get("reviewer_id") == entry.get("by")
            and all(approval.get(k) == v for k, v in subject.items()))


def verify_change(change: dict[str, Any]) -> bool:
    """An approved change: valid proposal, valid approval of exactly it, two different reviewers."""
    from sandbox.connector.signing import verify_approval

    approval = change.get("approval") or {}
    subject = _approval_subject(change["change_id"], change["kind"], change.get("base"),
                                change["new_sha256"], change.get("governance_sha256"))
    return (verify_proposal(change) and verify_approval(approval)
            and all(approval.get(k) == v for k, v in subject.items())
            and approval.get("reviewer_id") != change.get("proposer")
            and approval.get("signer_public_key") != change.get("proposer_public_key"))


# ---------------------------------------------------------------------------
# accepting versions
# ---------------------------------------------------------------------------

def _accept(layout: FolderLayout, kind: str, content: dict[str, Any], *, by: str, reason: str, how: str,
            change_id: str = "", approval: dict[str, Any] | None = None,
            governance_sha: str | None = None) -> dict[str, Any]:
    """Store *content* as the approved version of *kind* and log it."""
    from sandbox.connector.signing import sign_approval

    head = read_head(layout)
    previous = head.get(kind)
    sha = store(layout, content)
    change_id = change_id or f"{how}-{uuid.uuid4().hex[:8]}"
    now = time.time()
    if approval is None:
        approval = sign_approval(layout, by, _approval_subject(change_id, kind, previous, sha, governance_sha), now)
    entry = {"kind": kind, "sha256": sha, "version": short(sha), "previous": previous, "by": by,
             "at": now, "reason": reason, "how": how, "change_id": change_id, "approval": approval}
    if governance_sha:
        entry["governance_sha256"] = governance_sha
    with open(_log_file(layout), "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    head[kind] = sha
    head["updated_at"] = now
    _atomic_write(layout, _head_file(layout), json.dumps(head, indent=2).encode("utf-8"))
    audit(layout, {"event": "policy_version_accepted", "kind": kind, "version": short(sha), "sha256": sha,
                   "previous": short(previous), "by": by, "how": how, "change_id": change_id, "reason": reason})
    _activity(layout, f"POLICY {kind} {short(previous) or 'none'} -> {short(sha)}  by {by} ({how})  {reason}")
    return entry


def baseline(layout: FolderLayout, reviewer: str, reason: str) -> list[dict[str, Any]]:
    """Adopt the policies on disk as the first approved versions (unversioned folders only)."""
    if is_versioned(layout):
        raise ValueError("this folder already has an approved policy version; use `sandbox policy propose`")
    history_dir(layout).mkdir(parents=True, exist_ok=True)
    disk = folder_content(layout)
    entries = [_accept(layout, FOLDER, disk, by=reviewer, reason=reason, how="baseline")]
    gov = read_governance(layout, disk.get("semantic", {}).get("governance_policy", ""))
    if gov is not None:
        entries.append(_accept(layout, GOVERNANCE, gov, by=reviewer, reason=reason, how="baseline"))
    return entries


def apply_edit(layout: FolderLayout, new_policy: FolderPolicy, actor: str, reason: str) -> dict[str, Any]:
    """How the CLI's direct-edit commands change the folder policy.

    Unversioned folder: written directly (as before), and audited.
    Versioned folder: an edit that only tightens the approved version is
    written at once and logged as a self-approved version (safety only ratchets
    up). Any other edit becomes a change request that a different reviewer must
    approve; the file is not touched.
    """
    new_policy._inject_protections()
    new = new_policy.model_dump()
    if not is_versioned(layout):
        old_sha = sha256_of(folder_content(layout))
        save_policy(new_policy, layout.policy_file)
        audit(layout, {"event": "policy_changed_unversioned", "from": short(old_sha),
                       "to": short(sha256_of(new)), "by": actor, "reason": reason})
        return {"status": "applied_unversioned", "version": short(sha256_of(new))}
    head = read_head(layout)
    approved = load_object(layout, head[FOLDER]) or {}
    if canonical(new) == canonical(approved):
        save_policy(new_policy, layout.policy_file)
        return {"status": "unchanged", "version": short(head[FOLDER])}
    if approved and only_tightens(approved, new):
        save_policy(new_policy, layout.policy_file)
        entry = _accept(layout, FOLDER, new, by=actor, reason=reason, how="tightening")
        return {"status": "applied", "version": entry["version"]}
    change = propose(layout, FOLDER, new, actor, reason)
    return {"status": "proposed", "change_id": change["change_id"], "loosens": change.get("loosens", [])}


# ---------------------------------------------------------------------------
# change requests
# ---------------------------------------------------------------------------

def _change_path(layout: FolderLayout, change_id: str) -> Path:
    safe = "".join(c for c in change_id if c.isalnum() or c in "-_")
    return _changes_dir(layout) / f"{safe}.json"


def load_change(layout: FolderLayout, change_id: str) -> dict[str, Any] | None:
    try:
        return json.loads(_change_path(layout, change_id).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def list_changes(layout: FolderLayout, status: str | None = None) -> list[dict[str, Any]]:
    d = _changes_dir(layout)
    out = []
    for p in sorted(d.glob("*.json")) if d.is_dir() else []:
        try:
            c = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if status is None or c.get("status") == status:
            out.append(c)
    out.sort(key=lambda c: c.get("proposed_at", 0))
    return out


def _approved_content(layout: FolderLayout, kind: str) -> dict[str, Any] | None:
    sha = read_head(layout).get(kind)
    return load_object(layout, sha) if sha else None


def _approved_governance_ref(layout: FolderLayout) -> str:
    approved = _approved_content(layout, FOLDER) or folder_content(layout)
    return approved.get("semantic", {}).get("governance_policy", "")


def propose(layout: FolderLayout, kind: str, content: dict[str, Any], proposer: str, reason: str) -> dict[str, Any]:
    """Create a signed change request for a new version of *kind*."""
    if kind not in KINDS:
        raise ValueError(f"unknown policy kind {kind!r}")
    if not reason.strip():
        raise ValueError("a reason is required")
    content = normalize_folder(content) if kind == FOLDER else normalize_governance(content)
    head = read_head(layout)
    base = head.get(kind)
    old = load_object(layout, base) if base else (
        folder_content(layout) if kind == FOLDER else read_governance(layout, _approved_governance_ref(layout)))
    if old is not None and canonical(old) == canonical(content):
        raise ValueError("the proposed version is identical to the approved one")
    gov_ref = ""
    if kind == GOVERNANCE:
        gov_ref = _approved_governance_ref(layout)
        if not gov_ref:
            raise ValueError("no governance policy is set for this folder (`sandbox governance use FILE`)")
    new_sha = store(layout, content)
    change: dict[str, Any] = {
        "change_id": f"chg-{uuid.uuid4().hex[:10]}",
        "kind": kind,
        "status": "open",
        "base": base,
        "new_sha256": new_sha,
        "governance_sha256": None,
        "proposer": proposer,
        "reason": reason,
        "proposed_at": time.time(),
        "diff": render_diff(old, content, short(base) or "current", short(new_sha)),
    }
    if kind == FOLDER:
        change["loosens"] = loosened_fields(old, content) if old is not None else []
        new_ref = content.get("semantic", {}).get("governance_policy", "")
        old_ref = (old or {}).get("semantic", {}).get("governance_policy", "")
        if new_ref and (new_ref != old_ref or not head.get(GOVERNANCE)):
            # A new governance pointer (or none approved yet): bind the
            # governance content it points at now, so it is approved with it.
            gov = read_governance(layout, new_ref)
            if gov is None:
                raise ValueError(f"governance policy {new_ref} could not be read")
            change["governance_sha256"] = store(layout, gov)
    else:
        change["governance_path"] = gov_ref
    _sign_proposal(layout, change)
    _atomic_write(layout, _change_path(layout, change["change_id"]),
                  json.dumps(change, indent=2).encode("utf-8"))
    audit(layout, {"event": "policy_change_proposed", "change_id": change["change_id"], "kind": kind,
                   "base": short(base), "new": short(new_sha), "proposer": proposer, "reason": reason,
                   "loosens": change.get("loosens", [])})
    _activity(layout, f"POLICY CHANGE PROPOSED  {change['change_id']}  {kind} {short(base) or 'none'} -> "
                      f"{short(new_sha)}  by {proposer}  {reason}")
    return change


def approve_change(layout: FolderLayout, change_id: str, reviewer: str, reason: str = "") -> dict[str, Any]:
    """Apply a change request with a reviewer's signed approval.

    Returns {"status": ...}: applied | not_open | same_reviewer | stale | changed.
    """
    from sandbox.connector.signing import reviewer_public_key, sign_approval

    path = _change_path(layout, change_id)
    change = load_change(layout, change_id)
    if change is None or change.get("status") != "open" or not verify_proposal(change):
        return {"status": "not_open"}
    if reviewer == change["proposer"] or reviewer_public_key(layout, reviewer) == change["proposer_public_key"]:
        return {"status": "same_reviewer"}
    kind = change["kind"]
    if read_head(layout).get(kind) != change.get("base"):
        return {"status": "stale"}  # the approved version moved since this was proposed
    content = load_object(layout, change["new_sha256"])
    if content is None or sha256_of(content) != change["new_sha256"]:
        return {"status": "changed"}
    gov_sha = change.get("governance_sha256")
    gov_content = None
    if gov_sha:
        ref = content.get("semantic", {}).get("governance_policy", "")
        gov_content = read_governance(layout, ref)
        if sha256_of(gov_content) != gov_sha:
            return {"status": "changed"}  # the governance file changed after the proposal

    # Claim it (one approver wins a race), then sign, apply, record.
    claimed = path.with_suffix(".claimed")
    try:
        os.rename(path, claimed)
    except OSError:
        return {"status": "not_open"}
    now = time.time()
    approval = sign_approval(layout, reviewer,
                             _approval_subject(change_id, kind, change.get("base"), change["new_sha256"], gov_sha), now)
    if kind == FOLDER:
        save_policy(FolderPolicy.model_validate(content), layout.policy_file)
    else:
        target = governance_path(layout, change.get("governance_path") or _approved_governance_ref(layout))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(content, indent=2, ensure_ascii=False), encoding="utf-8")
    why = reason or change["reason"]
    entry = _accept(layout, kind, content, by=reviewer, reason=why, how="change", change_id=change_id,
                    approval=approval, governance_sha=gov_sha)
    if gov_content is not None:
        _accept(layout, GOVERNANCE, gov_content, by=reviewer, reason=why, how="change",
                change_id=f"{change_id}-governance")
    change.update({"status": "approved", "approval": approval, "approved_by": reviewer,
                   "approved_at": now, "approval_reason": reason})
    _atomic_write(layout, path, json.dumps(change, indent=2).encode("utf-8"))
    try:
        claimed.unlink()
    except OSError:
        pass
    audit(layout, {"event": "policy_change_approved", "change_id": change_id, "kind": kind,
                   "version": entry["version"], "proposer": change["proposer"], "reviewer": reviewer})
    return {"status": "applied", "version": entry["version"], "change": change}


def reject_change(layout: FolderLayout, change_id: str, reviewer: str, reason: str) -> bool:
    """Close a change request without applying it (anyone may; it is the safe direction)."""
    change = load_change(layout, change_id)
    if change is None or change.get("status") != "open":
        return False
    change.update({"status": "rejected", "rejected_by": reviewer, "rejected_at": time.time(),
                   "rejection_reason": reason})
    _atomic_write(layout, _change_path(layout, change_id), json.dumps(change, indent=2).encode("utf-8"))
    audit(layout, {"event": "policy_change_rejected", "change_id": change_id, "reviewer": reviewer,
                   "reason": reason})
    return True


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------

def _pretty(content: dict[str, Any] | None) -> list[str]:
    if content is None:
        return []
    return json.dumps(content, indent=2, sort_keys=True, ensure_ascii=False).splitlines()


def render_diff(a: dict[str, Any] | None, b: dict[str, Any] | None, a_name: str, b_name: str) -> str:
    return "\n".join(difflib.unified_diff(_pretty(a), _pretty(b), fromfile=a_name, tofile=b_name, lineterm=""))


def summarize(a: dict[str, Any] | None, b: dict[str, Any] | None) -> list[str]:
    """One-line verdicts about going from *a* to *b*."""
    if a is None or b is None:
        return []
    if "clauses" in a or "clauses" in b:
        ca = {c["id"]: c for c in a.get("clauses", [])}
        cb = {c["id"]: c for c in b.get("clauses", [])}
        lines = []
        for cid in sorted(set(ca) - set(cb)):
            lines.append(f"clause removed (less scrutiny): {cid}")
        for cid in sorted(set(cb) - set(ca)):
            lines.append(f"clause added: {cid}")
        for cid in sorted(set(ca) & set(cb)):
            if ca[cid] != cb[cid]:
                lines.append(f"clause changed: {cid}")
        return lines
    loose = loosened_fields(a, b)
    if not loose:
        return ["only tightens (or no change)"]
    return [f"looser or changed without a stricter direction: {', '.join(loose)}"]
