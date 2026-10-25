"""CLI entry points for sync subcommands (T12b, ADR 0010 s3).

Thin click wrappers over the existing library code.  These commands are
on the hook's approver-command deny list for agents (C9 item 6):
``enroll``, ``sync``, ``unenroll``, ``signer`` are in
``classify._APPROVER_SUBCOMMANDS``.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import time
import urllib.error
import urllib.request

import click

# S2: character sets that must not appear in displayed server strings.
# C0 (U+0000-U+001F), C1 (U+0080-U+009F), DEL (U+007F),
# Unicode bidi controls (U+202A-202E, U+2066-2069, U+200E/200F, U+061C).
_CONTROL_CODEPOINTS: frozenset[int] = frozenset(
    set(range(0x00, 0x20))          # C0
    | set(range(0x80, 0xA0))        # C1
    | {0x7F}                        # DEL
    | {0x202A, 0x202B, 0x202C, 0x202D, 0x202E}     # bidi
    | {0x2066, 0x2067, 0x2068, 0x2069}              # bidi isolates
    | {0x200E, 0x200F}              # LRM / RLM
    | {0x061C}                      # ALM
)


def _has_control_chars(s: str) -> bool:
    """Return True if *s* contains any dangerous control character."""
    return any(ord(c) in _CONTROL_CODEPOINTS for c in s)


def _check_display_safety(fields: dict[str, str]) -> None:
    """Raise ``click.ClickException`` if any field contains control chars.

    Prints the offending field repr-escaped so the human sees why.
    """
    for label, val in fields.items():
        if isinstance(val, str) and _has_control_chars(val):
            click.echo(
                f"REFUSED: {label} contains control characters: {repr(val)}"
            )
            raise click.ClickException(
                f"refusing to sign: {label} contains control characters"
            )


def _warn_display_safety(fields: dict[str, str]) -> bool:
    """Print a warning if any field contains control chars.

    Unlike ``_check_display_safety`` this does NOT raise: deny is always
    allowed because it can only stop an action (ADR 0010 s7).
    Returns True if control characters were found.
    """
    found = False
    for label, val in fields.items():
        if isinstance(val, str) and _has_control_chars(val):
            click.echo(
                f"WARNING: {label} contains control characters: {repr(val)}"
            )
            found = True
    return found


@click.command("enroll")
@click.option("--server", required=True, help="Control plane URL")
@click.option("--code", required=True, help="Enrollment code")
@click.option("--expect-fingerprint", required=True, help="Expected registry fingerprint")
@click.option("--ca", default=None, help="CA bundle path")
@click.option("--operator", default=None, help="Expected operator user_id (must match server)")
def enroll(server: str, code: str, expect_fingerprint: str, ca: str | None, operator: str | None) -> None:
    """Enroll this connector with the control plane."""
    from sandbox.connector.sync.enroll import enroll as _enroll

    result = _enroll(server, code, expect_fingerprint, ca=ca, operator=operator)
    click.echo(f"Enrolled: device_id={result.get('device_id', '?')}")
    op = result.get("operator_user_id", "")
    if op:
        click.echo(f"Operator: {op}")


@click.command("sync")
@click.option("--once", is_flag=True, help="Run one sync cycle then exit")
@click.option("--server", default=None, help="Control plane URL (read from enrollment if omitted)")
def sync(once: bool, server: str | None) -> None:
    """Sync with the control plane: upload escalations, poll decisions, apply."""
    from sandbox.connector.layout import FolderLayout

    lay = FolderLayout(".")
    if not lay.exists():
        raise click.ClickException("no .sandbox/ in current directory; run 'sandbox init' first")

    from sandbox.connector.sync.state import is_managed
    if not is_managed(lay):
        raise click.ClickException("workspace is not managed; enroll first")

    run_once(lay, server)
    if not once:
        click.echo("sync: continuous mode not yet implemented; use --once")


def _read_enrollment(lay):
    """Read enrollment.json and return (server_url, device_id, token)."""
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    enroll_file = sync_dir / "enrollment.json"
    if not enroll_file.exists():
        return None
    try:
        data = json.loads(enroll_file.read_text(encoding="utf-8"))
        return data
    except (OSError, ValueError):
        return None


def _get_token(lay, server: str) -> str | None:
    """Get a device bearer token for the sync API (upload/decisions)."""
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    device_id = ""
    did_file = sync_dir / "device_id"
    if did_file.exists():
        device_id = did_file.read_text(encoding="utf-8").strip()
    if not device_id:
        return None
    try:
        from sandbox.connector.sync.enroll import request_token
        from sandbox.connector.keyhome import key_home_root, workspace_id
        from nacl.signing import SigningKey

        kh = key_home_root()
        if kh is None:
            return None
        ws_id = workspace_id(lay, create=False)
        dk_path = kh / ws_id / "device" / "device.key"
        if not dk_path.exists():
            return None
        dk = SigningKey(dk_path.read_bytes())
        return request_token(server, dk, device_id)
    except Exception:
        return None


def _get_signer_token(server: str, sk, kid: str) -> str | None:
    """Get a signer token via the agg/signer-assert/v1 flow (T7).

    The signer token is used for approval routes (GET detail, POST approval)
    instead of a device token. This is the T12b-2 fix: the signer client
    authenticates as a signer, not as the device.
    """
    nonce = secrets.token_hex(16)
    aud = server.rstrip("/")
    payload = {"key_id": kid, "nonce": nonce, "aud": aud, "iat": time.time()}
    tag = b"agg/signer-assert/v1"
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    msg = tag + b"\x00" + canonical
    sig = sk.sign(msg).signature.hex()
    assertion = {
        "kind": "agg/signer-assert/v1",
        "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": kid, "alg": "ed25519", "sig": sig}],
    }
    url = server.rstrip("/") + "/api/v1/sync/signer/token"
    body = json.dumps(assertion).encode()
    headers: dict[str, str] = {"Content-Type": "application/json"}
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        data = json.loads(resp.read())
        return data.get("token")
    except Exception:
        return None


def run_once(lay, server: str | None = None) -> dict:
    """One sync cycle: upload pending escalations, poll decisions, apply.

    Returns a summary dict for testing.
    """
    from sandbox.connector.queue import EscalationQueue, valid_request_id
    from sandbox.connector.sync.verified_state import load_verified_state
    from sandbox.connector.approval import apply_external, _binding_fingerprint
    from sandbox.connector import scrub

    queue = EscalationQueue(lay)
    results: dict = {"uploaded": 0, "polled": 0, "applied": {}}

    # Resolve server URL from enrollment if not given
    enroll_data = _read_enrollment(lay)
    effective_server = server
    if effective_server is None and enroll_data:
        effective_server = enroll_data.get("server_url", "")

    # 1. Upload pending escalations (POST /api/v1/sync/escalations, scrubbed,
    # idempotent: the server deduplicates by request_id)
    from sandbox.connector.sync.process import escalation_upload_body
    token = _get_token(lay, effective_server) if effective_server else None
    enroll_device_id = enroll_data.get("device_id", "") if enroll_data else ""
    pending = queue.list_pending()
    for rec in pending:
        rid = rec.get("request_id", "")
        try:
            upload_rec = dict(rec)
            if scrub.enabled(lay):
                if not scrub.scrub_fields(upload_rec, scrub.OUTPUT_FIELDS):
                    pass  # scrub_fields returns whether it redacted; ok either way
            # Build the structured body the server expects
            # (shared helper validates bundle_sequence, refuses non-int)
            body = escalation_upload_body(upload_rec, enroll_device_id,
                                          layout=lay)
            if body is None:
                continue
            if effective_server:
                _upload_escalation(effective_server, body, token)
            results["uploaded"] += 1
        except Exception:  # noqa: BLE001 -- L1: scrub failure blocks this record
            continue

    # 2. Poll decisions from GET /api/v1/sync/decisions
    decisions_by_request: dict[str, list[dict]] = {}
    if effective_server:
        if token is None:
            token = _get_token(lay, effective_server)
        raw_decisions = _fetch_decisions(effective_server, token)
        for row in raw_decisions:
            rid = row.get("request_id", "")
            if not valid_request_id(rid):
                continue
            # Check that we have a local pending record
            if queue.status(rid) != "pending":
                continue
            # Rebuild envelope with kind fixed in code (never trust server's kind)
            envelope = _rebuild_envelope(row)
            if envelope is not None:
                decisions_by_request.setdefault(rid, []).append(envelope)
        results["polled"] = len(raw_decisions)

    # 3. Apply decisions
    for rid, envelopes in decisions_by_request.items():
        try:
            result = asyncio.run(apply_external(lay, rid, envelopes,
                                                 clock=lambda: time.time()))
            results["applied"][rid] = result.get("status", "unknown")
            # Audit the outcome
            try:
                from sandbox.connector.audit import FolderAudit
                audit = FolderAudit(lay.audit_dir, session_id="sync")
                audit.append({
                    "event": "sync_decision_applied",
                    "request_id": rid,
                    "status": result.get("status", "unknown"),
                    "ts": time.time(),
                })
            except Exception:  # noqa: BLE001
                pass
        except Exception:  # noqa: BLE001
            results["applied"][rid] = "error"

    return results


def _fetch_escalation(server: str, request_id: str, token: str | None) -> dict | None:
    """GET /api/v1/sync/escalations/{request_id} and return the record."""
    url = server.rstrip("/") + f"/api/v1/sync/escalations/{request_id}"
    headers: dict[str, str] = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        data = json.loads(resp.read())
        if isinstance(data, dict):
            return data
    except Exception:  # noqa: BLE001
        pass
    return None


def _upload_escalation(server: str, rec: dict, token: str | None) -> None:
    """POST /api/v1/sync/escalations (idempotent by request_id)."""
    url = server.rstrip("/") + "/api/v1/sync/escalations"
    body = json.dumps(rec).encode()
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        urllib.request.urlopen(req, timeout=30)
    except Exception:  # noqa: BLE001 -- upload is best-effort
        pass


def _fetch_decisions(server: str, token: str | None) -> list[dict]:
    """GET /api/v1/sync/decisions and return the rows."""
    url = server.rstrip("/") + "/api/v1/sync/decisions"
    headers: dict[str, str] = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        data = json.loads(resp.read())
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("decisions", [])
    except Exception:  # noqa: BLE001
        pass
    return []


def _rebuild_envelope(row: dict) -> dict | None:
    """Rebuild an agg/remote-approval/v1 envelope from a server decision row.

    The kind is fixed in code (never trust the server's kind column).
    The server's user_id column is ignored (comes from the registry).
    """
    payload = row.get("signed_payload") or row.get("payload")
    # The signed_payload column is TEXT; the server may return a JSON string.
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            return None
    if not isinstance(payload, dict):
        return None
    # The server returns the field as "signature" (DB column name),
    # not "sig" (the envelope convention). Accept both.
    sig = row.get("sig") or row.get("signature") or ""
    key_id = row.get("key_id") or payload.get("key_id", "")
    if not sig or not key_id:
        sigs = row.get("signatures", [])
        if isinstance(sigs, list) and sigs:
            sig = sigs[0].get("sig", "")
            key_id = sigs[0].get("key_id", key_id)
    if not sig:
        return None
    return {
        "kind": "agg/remote-approval/v1",  # fixed in code
        "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": key_id, "alg": "ed25519", "sig": sig}],
    }


@click.command("unenroll")
@click.option("--decision", "decision_file", required=True, type=click.Path(exists=True),
              help="Path to the quorum-signed unenroll decision file")
def unenroll(decision_file: str) -> None:
    """Unenroll this connector from the control plane."""
    from sandbox.connector.layout import FolderLayout
    from sandbox.connector.sync.enroll import unenroll as _unenroll

    lay = FolderLayout(".")
    _unenroll(lay, decision_file)
    click.echo("Unenrolled.")


def _build_and_sign_envelope(
    request_id: str, rec: dict, vs, kid: str, sk, decision: str,
) -> dict:
    """Build and sign an agg/remote-approval/v1 envelope.

    Fix 3 (T12b-2): sign the server's canonical fields exactly as
    returned by GET /api/v1/sync/escalations/{id}.  Never recompute the
    fingerprint locally or substitute local vs.* values.
    """
    # Use server-supplied fields from the GET detail response
    user_id = vs.registry._keys[kid]["user_id"] if (vs and vs.registry) else ""
    payload = {
        "request_id": rec.get("request_id", request_id),
        "command": rec.get("command", ""),
        "fingerprint": rec.get("fingerprint", ""),
        "reviewer_id": user_id,
        "decision": decision,
        "approved_at": time.time(),
        "org_id": rec.get("org_id", getattr(vs, "org_id", "")),
        "project_id": rec.get("project_id", getattr(vs, "project_id", "")),
        "device_id": rec.get("device_id", getattr(vs, "device_id", "")),
        "registry_version": getattr(vs, "registry_version", 1),
        "policy_sequence": rec.get("policy_sequence", getattr(vs, "policy_sequence", 1)),
        "user_id": user_id,
        "key_id": kid,
        "nonce": secrets.token_hex(16),
        "not_after": time.time() + 900,
    }
    tag = "agg/remote-approval/v1"
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    msg = tag.encode("utf-8") + b"\x00" + canonical
    sig = sk.sign(msg).signature.hex()
    return {
        "kind": tag, "sig_v": 1, "payload": payload,
        "signatures": [{"key_id": kid, "alg": "ed25519", "sig": sig}],
    }


def _load_signer_key(lay, vs):
    """Load the first CLI signer key from the key home. Returns (sk, kid, user_id)."""
    from nacl.signing import SigningKey
    from sandbox.connector.keyhome import key_home_root, workspace_id as _wsid

    kh = key_home_root()
    if kh is None:
        raise click.ClickException("key home not available")
    ws_id = _wsid(lay, create=False)
    ws_dir = kh / ws_id
    seed_files = list(ws_dir.glob("*.seed"))
    cli_seeds = [s for s in seed_files if not s.stem.startswith("connector_")]
    if not cli_seeds:
        raise click.ClickException("no CLI signer key found in key home")
    sk = SigningKey(cli_seeds[0].read_bytes())
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    entry = vs.registry._keys.get(kid) if vs.registry else None
    if entry is None:
        raise click.ClickException(f"key {kid[:16]}... not found in registry")
    return sk, kid, entry.get("user_id", "")


def _post_approval(server: str, request_id: str, envelope: dict, token: str | None) -> None:
    """POST the signed envelope to /api/v1/sync/escalations/{id}/approvals."""
    url = server.rstrip("/") + f"/api/v1/sync/escalations/{request_id}/approvals"
    body = json.dumps(envelope).encode()
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        urllib.request.urlopen(req, timeout=30)
    except urllib.error.HTTPError as exc:
        raise click.ClickException(
            f"server returned {exc.code}: {exc.read().decode('utf-8', 'replace')[:200]}"
        )


@click.command("approve")
@click.argument("escalation_id")
@click.option("--server", default=None, help="Control plane URL")
@click.option("--yes", is_flag=True, help="Skip confirmation")
def signer_approve(escalation_id: str, server: str | None, yes: bool) -> None:
    """Approve a pending escalation as a CLI signer.

    Fetches the escalation detail from the server (by escalation_id),
    shows the canonical fields, signs them with the approver's CLI key,
    and POSTs the signed envelope back.  Uses a signer token (T12b-2).
    Never calls apply_external or the broker locally (S7).
    """
    from sandbox.connector.layout import FolderLayout
    from sandbox.connector.sync.verified_state import load_verified_state

    lay = FolderLayout(".")
    vs = load_verified_state(lay)
    if vs is None:
        raise click.ClickException("verified state unavailable; cannot sign")

    sk, kid, user_id = _load_signer_key(lay, vs)

    enroll_data = _read_enrollment(lay)
    effective_server = server or (enroll_data.get("server_url", "") if enroll_data else "")
    if not effective_server:
        raise click.ClickException("no server URL; pass --server or enroll first")

    # T12b-2: use a signer token, not a device token
    signer_token = _get_signer_token(effective_server, sk, kid)
    if signer_token is None:
        raise click.ClickException("failed to obtain signer token")

    # Fetch the escalation detail from the server (T12b-2 GET route)
    rec = _fetch_escalation(effective_server, escalation_id, signer_token)
    if rec is None:
        raise click.ClickException(f"escalation {escalation_id} not found on server")

    # F1 fix: validate policy_sequence as int and requires_dual as bool
    # so the signer prints only values it computed itself, never raw server
    # strings for these two fields.  Every other displayed field is already
    # checked for control characters below.
    raw_ps = rec.get("policy_sequence", 0)
    if not isinstance(raw_ps, int) or isinstance(raw_ps, bool):
        raise click.ClickException(
            f"server returned non-integer policy_sequence: {repr(raw_ps)}"
        )
    safe_requires_dual = bool(rec.get("requires_dual", True))

    # F8: validate bundle_sequence as int if present
    raw_bs = rec.get("bundle_sequence")
    if raw_bs is not None:
        if isinstance(raw_bs, bool) or not isinstance(raw_bs, int):
            raise click.ClickException(
                f"server returned non-integer bundle_sequence: {repr(raw_bs)}"
            )

    # S2: refuse to sign if any displayed field contains control chars
    _check_display_safety({
        "Request ID": str(rec.get("request_id", "")),
        "Command": str(rec.get("command", "")),
        "Device ID": str(rec.get("device_id", "")),
        "Project ID": str(rec.get("project_id", "")),
        "Org ID": str(rec.get("org_id", "")),
        "Fingerprint": str(rec.get("fingerprint", "")),
        "Root": str(rec.get("root", "")),
        "CWD": str(rec.get("exec_cwd", "")),
        "Kind": str(rec.get("kind", "")),
        "Tool name": str(rec.get("tool_name", "")),
        "Status": str(rec.get("status", "")),
    })

    # F8: recompute binding fingerprint and refuse if it doesn't match
    # the server's fingerprint.  Import only -- do not change approval.py.
    from sandbox.connector.approval import _binding_fingerprint  # noqa: PLC0415
    computed_fp = _binding_fingerprint(rec)
    server_fp = rec.get("fingerprint", "")
    if computed_fp != server_fp:
        raise click.ClickException(
            f"binding fingerprint mismatch: computed {computed_fp[:16]}... "
            f"vs server {server_fp[:16]}..."
        )

    # Show the server's canonical fields before signing
    click.echo(f"Escalation:      {escalation_id}")
    click.echo(f"Request ID:      {rec.get('request_id', '')}")
    click.echo(f"Command:         {rec.get('command', '')}")
    click.echo(f"Kind:            {rec.get('kind', '')}")
    click.echo(f"Tool name:       {rec.get('tool_name', '')}")
    click.echo(f"Root:            {rec.get('root', '')}")
    click.echo(f"CWD:             {rec.get('exec_cwd', '')}")
    click.echo(f"Device ID:       {rec.get('device_id', '')}")
    click.echo(f"Project ID:      {rec.get('project_id', '')}")
    click.echo(f"Org ID:          {rec.get('org_id', '')}")
    click.echo(f"Policy sequence: {raw_ps}")
    click.echo(f"Bundle sequence: {raw_bs if raw_bs is not None else ''}")
    click.echo(f"Fingerprint:     {rec.get('fingerprint', '')}")
    click.echo(f"Requires dual:   {safe_requires_dual}")

    if not yes:
        click.confirm("Approve this request?", abort=True)

    request_id = rec.get("request_id", escalation_id)
    envelope = _build_and_sign_envelope(request_id, rec, vs, kid, sk, "approve")
    _post_approval(effective_server, escalation_id, envelope, signer_token)
    click.echo(f"Approval posted for {escalation_id}")


@click.command("deny")
@click.argument("escalation_id")
@click.option("--server", default=None, help="Control plane URL")
@click.option("--yes", is_flag=True, help="Skip confirmation")
def signer_deny(escalation_id: str, server: str | None, yes: bool) -> None:
    """Deny a pending escalation as a CLI signer.

    Fetches the escalation detail, signs a deny, and POSTs it.
    Uses a signer token (T12b-2).
    Never calls apply_external or the broker locally (S7).
    """
    from sandbox.connector.layout import FolderLayout
    from sandbox.connector.sync.verified_state import load_verified_state

    lay = FolderLayout(".")
    vs = load_verified_state(lay)
    if vs is None:
        raise click.ClickException("verified state unavailable; cannot sign")

    sk, kid, user_id = _load_signer_key(lay, vs)

    enroll_data = _read_enrollment(lay)
    effective_server = server or (enroll_data.get("server_url", "") if enroll_data else "")
    if not effective_server:
        raise click.ClickException("no server URL; pass --server or enroll first")

    # T12b-2: use a signer token, not a device token
    signer_token = _get_signer_token(effective_server, sk, kid)
    if signer_token is None:
        raise click.ClickException("failed to obtain signer token")

    rec = _fetch_escalation(effective_server, escalation_id, signer_token)
    if rec is None:
        raise click.ClickException(f"escalation {escalation_id} not found on server")

    # ADR 0010 s7: deny is always allowed even with control characters.
    # Show escaped values so the human sees what they are denying.
    deny_fields = {
        "Request ID": str(rec.get("request_id", "")),
        "Command": str(rec.get("command", "")),
        "Device ID": str(rec.get("device_id", "")),
        "Fingerprint": str(rec.get("fingerprint", "")),
        "Root": str(rec.get("root", "")),
        "CWD": str(rec.get("exec_cwd", "")),
        "Kind": str(rec.get("kind", "")),
        "Tool name": str(rec.get("tool_name", "")),
    }
    has_ctrl = _warn_display_safety(deny_fields)

    click.echo(f"Escalation:      {escalation_id}")
    # If control chars were found, show repr-escaped values
    if has_ctrl:
        click.echo(f"Request ID:      {repr(rec.get('request_id', ''))}")
        click.echo(f"Command:         {repr(rec.get('command', ''))}")
        click.echo(f"Kind:            {repr(rec.get('kind', ''))}")
        click.echo(f"Tool name:       {repr(rec.get('tool_name', ''))}")
        click.echo(f"Root:            {repr(rec.get('root', ''))}")
        click.echo(f"CWD:             {repr(rec.get('exec_cwd', ''))}")
        click.echo(f"Device ID:       {repr(rec.get('device_id', ''))}")
        click.echo(f"Fingerprint:     {repr(rec.get('fingerprint', ''))}")
    else:
        click.echo(f"Request ID:      {rec.get('request_id', '')}")
        click.echo(f"Command:         {rec.get('command', '')}")
        click.echo(f"Kind:            {rec.get('kind', '')}")
        click.echo(f"Tool name:       {rec.get('tool_name', '')}")
        click.echo(f"Root:            {rec.get('root', '')}")
        click.echo(f"CWD:             {rec.get('exec_cwd', '')}")
        click.echo(f"Device ID:       {rec.get('device_id', '')}")
        click.echo(f"Fingerprint:     {rec.get('fingerprint', '')}")
    # F8: validate and print bundle_sequence as int
    raw_bs_deny = rec.get("bundle_sequence")
    if raw_bs_deny is not None and (isinstance(raw_bs_deny, bool) or not isinstance(raw_bs_deny, int)):
        raw_bs_deny = None
    click.echo(f"Bundle sequence: {raw_bs_deny if raw_bs_deny is not None else ''}")
    # F1: render requires_dual as a validated bool (deny path)
    click.echo(f"Requires dual:   {bool(rec.get('requires_dual', True))}")

    if not yes:
        click.confirm("Deny this request?", abort=True)

    request_id = rec.get("request_id", escalation_id)
    envelope = _build_and_sign_envelope(request_id, rec, vs, kid, sk, "deny")
    _post_approval(effective_server, escalation_id, envelope, signer_token)
    click.echo(f"Deny posted for {escalation_id}")


def register(cli: click.Group) -> None:
    """Attach the sync commands to the main CLI group."""
    cli.add_command(enroll)
    cli.add_command(sync)
    cli.add_command(unenroll)

    @cli.group("signer")
    def signer_group() -> None:
        """Signer key management and approval commands."""

    signer_group.add_command(signer_approve)
    signer_group.add_command(signer_deny)
