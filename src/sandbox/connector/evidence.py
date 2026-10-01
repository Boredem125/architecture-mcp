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
  exporter key kept at ``.sandbox/state/keys/evidence-exporter.seed``.

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


# --- small helpers -------------------------------------------------------

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


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


def check_decision(rec: Any, stem: str, reviewer_keys: dict[str, str | None]) -> list[dict[str, Any]]:
    """The checks for one done-record. ``reviewer_keys`` maps reviewer id → the
    folder's public key for it (None if the folder has none)."""
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
    if expected is None:
        checks.append(_check("signer_is_folder_key", False, f"the folder has no key for reviewer {reviewer!r}"))
    elif rec.get("signer_public_key") != expected:
        checks.append(_check("signer_is_folder_key", False,
                             f"signed by key {str(rec.get('signer_public_key'))[:16]}..., "
                             f"not the folder's key for reviewer {reviewer!r}"))
    else:
        checks.append(_check("signer_is_folder_key", True))

    if rec.get("requires_dual") and rec.get("decision") == "approved":
        problems, good = [], []
        for n, a in enumerate(_approvals(rec), start=1):
            if not isinstance(a, dict):
                problems.append(f"approval {n}: not an object")
                continue
            who = _rid(a.get("reviewer_id"))
            if not verify_approval(a):
                problems.append(f"approval {n} ({who}): signature does not verify")
            elif any(a.get(k) != rec.get(k) for k in ("request_id", "command", "fingerprint")):
                problems.append(f"approval {n} ({who}): approves a different request or command")
            elif a.get("signer_public_key") != reviewer_keys.get(who):
                problems.append(f"approval {n} ({who}): not signed by the folder's key for {who!r}")
            else:
                good.append(a)
        if not distinct_approvals(good):
            problems.append(f"{len(good)} valid approval(s) by distinct reviewers and keys; 2 required")
        checks.append(_check("dual_control", not problems, "; ".join(problems)))
    return checks


def _checks_for(rec: Any, stem: str, reviewer_keys: dict[str, str | None]) -> list[dict[str, Any]]:
    if rec is None:
        return [_check("parse", False, "not valid JSON")]
    return check_decision(rec, stem, reviewer_keys)


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


def build_pack(layout: FolderLayout, since: float | None = None, until: float | None = None) -> dict[str, bytes]:
    """All pack files except the manifest, as {pack path: bytes}."""
    from sandbox.connector.policy import load_policy
    from sandbox.connector.signing import reviewer_public_key

    files: dict[str, bytes] = {}
    notes: list[str] = []

    # Audit chains, whole.
    chains: dict[str, Any] = {}
    audit_records: list[dict[str, Any]] = []
    if layout.audit_dir.is_dir():
        for d in sorted(p for p in layout.audit_dir.iterdir() if p.is_dir()):
            f = d / "records.jsonl"
            if not f.is_file():
                continue
            data = f.read_bytes()
            path = f"audit/{d.name}/records.jsonl"
            files[path] = data
            chains[d.name] = {"file": path, **verify_chain_bytes(data)}
            for line in data.split(b"\n"):
                rec = _read_json(line) if line.strip() else None
                if isinstance(rec, dict):
                    audit_records.append(rec)
    files[CHAINS_FILE] = _pretty(chains)

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

    index, failed = [], []
    for stem, data, rec in raw:
        path = f"decisions/{stem}.json"
        files[path] = data
        checks = _checks_for(rec, stem, reviewer_keys)
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
        "policies": policies,
        "failed_checks": failed + [{"file": c["file"], "check": "audit_chain", "detail": c["message"]}
                                   for c in chains.values() if not c["ok"]],
        "notes": notes,
        "limits": LIMITS,
    }
    files[SUMMARY] = _pretty(summary)
    return files


def sign_manifest(layout: FolderLayout, files: dict[str, bytes], meta: dict[str, Any]) -> bytes:
    from sandbox.connector.signing import _load_or_create_key
    from sandbox.crypto.signing import sign_message

    key = _load_or_create_key(layout, EXPORTER_KEY)
    body = {**meta, "format": FORMAT, "files": {p: _sha256(b) for p, b in sorted(files.items())},
            "exporter_public_key": bytes(key.verify_key).hex()}
    body["signature"] = sign_message(_canon({k: v for k, v in body.items() if k != "signature"}), key)
    return _pretty(body)


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


def verify_evidence(path: str | Path, exporter_key: str | None = None) -> dict[str, Any]:
    """Re-verify a pack offline. ``ok`` is False if anything fails; each entry
    of ``failures`` says what and where."""
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
        if not verify_signature(_canon(body), str(manifest.get("signature", "")), vk):
            failures.append(f"{MANIFEST}: signature does not verify (the manifest was changed after export)")
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

    for p in sorted(files):
        if not (p.startswith("decisions/") and p.endswith(".json")) or p == DECISIONS_INDEX:
            continue
        result["decisions"] += 1
        rec = _read_json(files[p])
        stem = PurePosixPath(p).stem
        checks = _checks_for(rec, stem, reviewer_keys)
        tag = " (already failing at export)" if p in failed_at_export else ""
        for c in checks:
            if not c["ok"]:
                failures.append(f"{p}: {c['check']} failed: {c['detail'] or 'check failed'}{tag}")

    for p in sorted(files):
        if p.startswith("audit/") and p.endswith("/records.jsonl"):
            result["sessions"] += 1
            r = verify_chain_bytes(files[p])
            if not r["ok"]:
                tag = " (already broken at export)" if p in broken_at_export else ""
                failures.append(f"{p}: audit chain failed: {r['message']}{tag}")

    result["ok"] = not failures
    result["created_at"] = manifest.get("created_at")
    result["source_root"] = manifest.get("source_root")
    return result
