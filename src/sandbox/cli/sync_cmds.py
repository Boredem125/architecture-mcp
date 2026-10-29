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


# Body-specific set: LF (0x0A), CR (0x0D) and TAB (0x09) are allowed in
# script body text (they are layout characters).  Everything else in
# _CONTROL_CODEPOINTS still refuses.
_BODY_CONTROL_CODEPOINTS: frozenset[int] = _CONTROL_CODEPOINTS - {0x09, 0x0A, 0x0D}


def _has_body_control_chars(s: str) -> bool:
    """Return True if *s* contains a dangerous control character for body text.

    Unlike ``_has_control_chars``, this allows TAB, LF and CR (layout).
    """
    return any(ord(c) in _BODY_CONTROL_CODEPOINTS for c in s)


def _check_body_display_safety(body: str) -> None:
    """Raise ``click.ClickException`` if the body contains dangerous controls.

    Allows TAB, LF, CR; refuses everything else in the control set.
    """
    if _has_body_control_chars(body):
        click.echo("REFUSED: Script body contains control characters")
        raise click.ClickException(
            "refusing to sign: script body contains control characters"
        )


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

    T12c c3 (ADR 0010 s9 9.5): the payload includes script_rel,
    script_sha256 and preview_sha256, built from the same parsed values
    that were rendered (display rule: what you see is what you sign).
    """
    # Use server-supplied fields from the GET detail response
    user_id = vs.registry._keys[kid]["user_id"] if (vs and vs.registry) else ""

    # T12c c3: extract script fields from the record for the signed payload
    _script = rec.get("script")
    _script_rel = ""
    _script_sha256 = ""
    if isinstance(_script, dict):
        _script_rel = _script.get("rel", "")
        _script_sha256 = _script.get("sha256", "")
    _preview = rec.get("script_preview")
    _preview_sha256 = ""
    if isinstance(_preview, dict):
        _preview_sha256 = _preview.get("sha256", "")

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
        # T12c c3: script content binding fields (ADR 0010 s9 9.5)
        "script_rel": _script_rel,
        "script_sha256": _script_sha256,
        "preview_sha256": _preview_sha256,
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


def _display_script_panel(rec: dict) -> None:
    """Display the script content panel (ADR 0010 s9 9.5).

    Shows script.rel, sha256, size and the preview body with line numbers.
    For unbound records, shows "content NOT bound: <reason>".
    Scope line: "Only <rel> is bound. Files it loads are not." (S-L1).
    """
    _script = rec.get("script")
    _preview = rec.get("script_preview")
    _unbound = rec.get("script_unbound", "")

    # Unbound warning
    if _unbound:
        click.echo(f"  content NOT bound: {_unbound}")
        return

    # No script (binding "none"): nothing to show
    if _script is None:
        return

    # Script metadata
    rel = _script.get("rel", "")
    sha = _script.get("sha256", "")
    size = _script.get("size", 0)
    click.echo(f"Script file:     {rel}")
    click.echo(f"Script sha256:   {sha}")
    click.echo(f"Script size:     {size}")
    click.echo(f"  Only {rel} is bound. Files it loads are not.")

    # Preview body with line numbers
    if _preview is not None and _preview.get("shown", False):
        body_text = _preview.get("text", "")
        if body_text:
            click.echo("--- script body ---")
            for i, line in enumerate(body_text.splitlines(), 1):
                click.echo(f"  {i:4d} | {line}")
            click.echo("--- end ---")


def _check_body_hash(rec: dict) -> None:
    """Recompute sha256 of the displayed preview body and refuse on mismatch.

    ADR 0010 s9 9.5: the CLI signer recomputes the sha256 of the displayed
    body and refuses to sign when it differs from the record's
    script_preview.sha256 (exit non-zero, sign and send nothing).
    """
    _preview = rec.get("script_preview")
    if _preview is None:
        return  # no preview: nothing to check
    if not _preview.get("shown", False):
        return  # preview not shown: check not applicable

    body_text = _preview.get("text", "")
    expected_sha = _preview.get("sha256", "")
    if not expected_sha:
        return  # no expected hash: nothing to verify

    computed_sha = hashlib.sha256(body_text.encode("utf-8")).hexdigest()
    if computed_sha != expected_sha:
        raise click.ClickException(
            f"body hash mismatch: computed {computed_sha[:16]}... "
            f"vs record {expected_sha[:16]}...; refusing to sign "
            "(the server may have altered the preview body)"
        )


@click.command("approve")
@click.argument("escalation_id")
@click.option("--server", default=None, help="Control plane URL")
@click.option("--yes", is_flag=True, help="Skip confirmation")
def signer_approve(escalation_id: str, server: str | None, yes: bool) -> None:
    """Approve a pending escalation as a CLI signer.

    Fetches the escalation detail from the server (by escalation_id),
    shows the canonical fields and the script panel (rel, sha256, size,
    body with line numbers), signs them with the approver's CLI key,
    and POSTs the signed envelope back.  Uses a signer token (T12b-2).
    Never calls apply_external or the broker locally (S7).

    T12c c3 (ADR 0010 s9 9.5): shows every field covered by fingerprint v2,
    the "content NOT bound: <reason>" line for unbound records, recomputes
    sha256 over the displayed body and refuses to sign when it differs
    from the record's script_preview.sha256.  The signed payload includes
    script_rel, script_sha256 and preview_sha256.
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

    # T12c c3: refuse if fp_v is missing (a pre-c2 record that cannot be
    # fingerprint-verified with v2 fields)
    if rec.get("fp_v") is None:
        raise click.ClickException(
            "server record has no fp_v; it predates script content binding "
            "and cannot be approved with a v2 signer"
        )

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
    # R1 fix (c3 security review): script.rel and preview body text are
    # displayed and must be checked (ADR 0010 s7).
    _script_obj = rec.get("script")
    _preview_obj = rec.get("script_preview")
    _display_fields: dict[str, str] = {
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
    }
    if isinstance(_script_obj, dict) and _script_obj.get("rel"):
        _display_fields["Script file"] = str(_script_obj["rel"])
    _check_display_safety(_display_fields)
    # Body uses a separate check that allows TAB, LF and CR (layout chars)
    if isinstance(_preview_obj, dict) and _preview_obj.get("text"):
        _check_body_display_safety(str(_preview_obj["text"]))

    # T12c c3: body-hash check (ADR 0010 s9 9.5) -- refuse to sign if
    # the server altered the preview body
    _check_body_hash(rec)

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

    # T12c c3: script panel (ADR 0010 s9 9.5)
    _display_script_panel(rec)

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


# ---------------------------------------------------------------------------
# F7: shared HTTP helper -- HTTPS only (except loopback), no redirects
# ---------------------------------------------------------------------------

import os as _os
from urllib.parse import urlparse as _urlparse


def _check_transport_safety(url: str) -> None:
    """F7: refuse http:// to non-loopback hosts.  Raises ClickException."""
    parsed = _urlparse(url)
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http":
        host = (parsed.hostname or "").lower()
        if host in ("localhost", "127.0.0.1", "::1", "[::1]"):
            return
        raise click.ClickException(
            f"refusing http:// to non-loopback host {host}; use https"
        )
    raise click.ClickException(f"unsupported scheme: {parsed.scheme}")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses every 3xx (R2-3 / F7).

    Installed as the global default opener so that urllib.request.urlopen
    never silently follows a redirect and forwards credentials to
    another host.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        raise urllib.error.HTTPError(
            req.full_url, code, f"redirect to {newurl} refused",
            headers, fp,
        )

    # The base class routes 301, 302, 303, 307 and 308 through
    # http_error_302, which computes newurl and calls redirect_request
    # above; do not alias http_error_30x to redirect_request (different
    # signature: urllib calls them with 5 arguments, not 6).


# Install the no-redirect opener globally so that every call through
# urllib.request.urlopen (including _safe_urlopen and test mocks that
# patch urlopen) refuses 3xx redirects.
urllib.request.install_opener(
    urllib.request.build_opener(_NoRedirectHandler)
)


def _safe_urlopen(req, *, timeout: int = 30):
    """urlopen that refuses redirects (F7 / R2-3).

    The module installs a global opener whose redirect handler raises
    on every 3xx, so credentials never leave the original host.
    """
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        # Belt-and-suspenders: check nothing slipped through.
        code = getattr(resp, "status", None) or getattr(resp, "code", 200)
        if 300 <= code < 400:
            raise click.ClickException(
                f"redirect ({code}) refused; Bearer must not leave the host"
            )
        # A followed redirect (e.g. another module replaced the global
        # opener) shows as a changed final URL: refuse it too.
        geturl = getattr(resp, "geturl", None)
        final_url = geturl() if callable(geturl) else None
        if isinstance(final_url, str) and final_url != req.full_url:
            raise click.ClickException(
                "redirect refused; Bearer must not leave the host"
            )
        return resp
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise click.ClickException(
                f"redirect ({exc.code}) refused; Bearer must not leave the host"
            ) from exc
        raise


def _signer_safe_get(url: str, token: str | None):
    """GET JSON with transport safety.  Returns parsed JSON or raises."""
    _check_transport_safety(url)
    headers: dict[str, str] = {"Accept": "application/json"}
    req = urllib.request.Request(url, headers=headers, method="GET")
    if token:
        req.add_unredirected_header("Authorization", f"Bearer {token}")
    try:
        resp = _safe_urlopen(req)
        return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise click.ClickException(
                f"redirect ({exc.code}) refused; Bearer must not leave the host"
            ) from exc
        raise click.ClickException(
            f"server returned {exc.code}: "
            f"{exc.read().decode('utf-8', 'replace')[:200]}"
        ) from exc
    except urllib.error.URLError as exc:
        raise click.ClickException(
            f"cannot reach server: {exc.reason}"
        ) from exc


def _signer_safe_post(url: str, body: dict, token: str | None) -> dict:
    """POST JSON with transport safety.  Returns parsed response."""
    _check_transport_safety(url)
    data = json.dumps(body).encode()
    headers: dict[str, str] = {"Content-Type": "application/json"}
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    if token:
        req.add_unredirected_header("Authorization", f"Bearer {token}")
    try:
        resp = _safe_urlopen(req)
        return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise click.ClickException(
                f"redirect ({exc.code}) refused; Bearer must not leave the host"
            ) from exc
        raise click.ClickException(
            f"server returned {exc.code}: "
            f"{exc.read().decode('utf-8', 'replace')[:200]}"
        ) from exc
    except urllib.error.URLError as exc:
        raise click.ClickException(
            f"cannot reach server: {exc.reason}"
        ) from exc


# ---------------------------------------------------------------------------
# F4: secure seed file creation and loading
# ---------------------------------------------------------------------------

def _ensure_signer_dir(kh_root):
    """Create <key_home>/signer with 0o700 and Windows ACL hardening (F4)."""
    from sandbox.connector.keyhome import root_exposure, _secure_new_root

    link_dir = kh_root / "signer"
    fresh = not link_dir.exists()
    if not _is_windows_platform():
        saved = _os.umask(0o077)
        try:
            link_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        finally:
            _os.umask(saved)
    else:
        link_dir.mkdir(parents=True, exist_ok=True)
    if fresh:
        _secure_new_root(link_dir)
    return link_dir


def _is_windows_platform() -> bool:
    import platform as _plat
    return _plat.system() == "Windows"


def _write_seed_excl(path, seed_bytes: bytes) -> None:
    """Write a seed file with O_EXCL and mode 0o600 (F4 / R2-1).

    Uses O_BINARY where available (Windows) so 0x0A bytes are not
    converted to CRLF.  A 32-byte seed must round-trip at exactly
    32 bytes.
    """
    flags = _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL
    # R2-1: prevent text-mode CRLF conversion on Windows.
    flags |= getattr(_os, "O_BINARY", 0)
    if not _is_windows_platform():
        fd = _os.open(str(path), flags, 0o600)
    else:
        fd = _os.open(str(path), flags)
    try:
        _os.write(fd, seed_bytes)
    finally:
        _os.close(fd)


def _load_seed_checked(seed_path, signer_dir):
    """Load a seed file with exposure and length checks (F4).

    Returns a SigningKey.  Raises ClickException on any problem.
    """
    from nacl.signing import SigningKey
    from sandbox.connector.keyhome import root_exposure

    exposure = root_exposure(signer_dir)
    if exposure:
        raise click.ClickException(
            f"key home exposure: {exposure}; refusing to load seed"
        )
    raw = seed_path.read_bytes()
    if len(raw) != 32:
        raise click.ClickException(
            f"seed length {len(raw)}, expected 32 bytes; "
            "the seed file may be corrupted"
        )
    return SigningKey(raw)


# ---------------------------------------------------------------------------
# signer link (F4 hardened)
# ---------------------------------------------------------------------------

@click.command("link")
@click.option("--code", required=True, help="Signer link code from the web UI")
@click.option("--server", required=True, help="Control plane URL")
def signer_link(code: str, server: str) -> None:
    """Link this CLI key to the control plane.

    Consumes a link code created in the web UI and binds the local CLI
    signing key to the server.  The key home must be available.
    F4: seed written with O_EXCL 0o600 in a 0o700 directory.
    R2-1: root_exposure check before writing a new seed.
    R2-3: routed through _signer_safe_post (https-except-loopback, no
    redirects).
    """
    from nacl.signing import SigningKey
    from sandbox.connector.keyhome import key_home_root, root_exposure

    kh = key_home_root()
    if kh is None:
        raise click.ClickException("key home not available; set SANDBOX_KEY_HOME")

    link_dir = _ensure_signer_dir(kh)
    seed_path = link_dir / "signer.seed"
    if seed_path.exists():
        sk = _load_seed_checked(seed_path, link_dir)
    else:
        # R2-1: check exposure before writing -- a pre-existing signer/
        # directory with a broad ACL must not receive a new seed.
        exposure = root_exposure(link_dir)
        if exposure:
            raise click.ClickException(
                f"key home exposure: {exposure}; refusing to write seed"
            )
        sk = SigningKey.generate()
        _write_seed_excl(seed_path, bytes(sk))

    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()

    # R2-3: route through _signer_safe_post for transport safety
    # (https-except-loopback and no-redirect).  No Bearer token for
    # link -- only the one-time code is sent.
    url = server.rstrip("/") + "/api/v1/sync/signer/link"
    try:
        resp_data = _signer_safe_post(url, {
            "code": code,
            "key_id": kid,
            "public_key": pub.hex(),
        }, token=None)
    except click.ClickException as exc:
        raise click.ClickException(f"link failed: {exc.message}") from exc

    click.echo(f"Linked: key_id={kid[:16]}...")
    click.echo(f"Org: {resp_data.get('org_id', '?')}")
    click.echo(f"User: {resp_data.get('user_id', '?')}")
    # Save link metadata -- include iss/sub from the server response
    meta_path = link_dir / "link.json"
    meta_path.write_text(json.dumps({
        "server": server,
        "key_id": kid,
        "org_id": resp_data.get("org_id", ""),
        "user_id": resp_data.get("user_id", ""),
        "iss": resp_data.get("iss", ""),
        "sub": resp_data.get("sub", ""),
    }, indent=2), encoding="utf-8")


def _load_signer_link_key():
    """Load the signer key and link metadata from the key home (F4 checked).

    Returns (sk, kid, link_meta) where link_meta has server, org_id, user_id.
    """
    from sandbox.connector.keyhome import key_home_root

    kh = key_home_root()
    if kh is None:
        raise click.ClickException("key home not available; set SANDBOX_KEY_HOME")

    link_dir = kh / "signer"
    seed_path = link_dir / "signer.seed"
    if not seed_path.exists():
        raise click.ClickException("no signer key found; run 'signer link' first")

    sk = _load_seed_checked(seed_path, link_dir)
    kid = hashlib.sha256(bytes(sk.verify_key)).hexdigest()

    meta_path = link_dir / "link.json"
    if not meta_path.exists():
        raise click.ClickException("no link metadata; run 'signer link' first")

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    return sk, kid, meta


# Keep the old non-safe helpers for the approve/deny paths (pre-d3 code)
def _signer_http_get(url: str, token: str | None) -> dict | list | None:
    """GET a JSON resource with optional Bearer auth (legacy, pre-F7)."""
    headers: dict[str, str] = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        return json.loads(resp.read())
    except Exception:
        return None


def _signer_http_post(url: str, body: dict, token: str | None) -> dict:
    """POST JSON with optional Bearer auth (legacy, pre-F7)."""
    data = json.dumps(body).encode()
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raise click.ClickException(
            f"server returned {exc.code}: "
            f"{exc.read().decode('utf-8', 'replace')[:200]}"
        )


def _get_link_signer_token(server: str, sk, kid: str) -> str | None:
    """Obtain a signer token using the linked key (F7 safe)."""
    _check_transport_safety(server)
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
    try:
        data = _signer_safe_post(url, assertion, None)
        return data.get("token")
    except Exception:
        return None


@click.command("genesis")
@click.option("--genesis-code", required=True, help="Genesis code from the migrations output")
@click.option("--server", default=None, help="Control plane URL (from link metadata if omitted)")
@click.option("--approver", is_flag=True, help="Add the approver role (default: admin only)")
@click.option("--confirm-identity", nargs=2, default=None, type=str,
              help="Confirm identity: <iss> <sub> (must match server-reported)")
@click.option("--bundle-signer-key", default=None, type=str,
              help="Bundle signer public key (64 hex chars, required)")
@click.option("--yes", is_flag=True, help="Skip interactive confirmation")
def signer_genesis(genesis_code: str, server: str | None, approver: bool,
                   confirm_identity: tuple[str, str] | None,
                   bundle_signer_key: str | None, yes: bool) -> None:
    """Build and publish registry v1 (genesis).

    Builds the genesis envelope using the linked CLI key, signs it,
    and posts it to POST /api/v1/sync/signer/genesis.  Prints the
    registry fingerprint.

    The user_id is the server's user id (ADR 0011 s4), never the IdP
    subject.  Default roles: [admin].  --approver adds the approver role.
    --confirm-identity <iss> <sub> must match the server-reported identity;
    exits non-zero on mismatch.

    Stub ruling 1: --bundle-signer-key <64 hex> is required; no /config
    call is ever made.  F9/stub ruling 3: iss/sub must come from link.json;
    refuse if missing.  F12: refuse empty org_id or user_id.
    """
    from sandbox.connector.sync.signer import build_genesis

    sk, kid, meta = _load_signer_link_key()
    effective_server = server or meta.get("server", "")
    if not effective_server:
        raise click.ClickException("no server URL; pass --server or link first")

    # F7: transport safety on the effective server URL
    _check_transport_safety(effective_server)

    # F3/stub ruling 1: --bundle-signer-key is required; never call /config
    if not bundle_signer_key:
        raise click.ClickException(
            "missing --bundle-signer-key; genesis requires the bundle "
            "signer public key (64 hex chars)"
        )
    try:
        bundle_pub = bytes.fromhex(bundle_signer_key)
    except ValueError as exc:
        raise click.ClickException(
            f"invalid --bundle-signer-key: {exc}"
        ) from exc
    if len(bundle_pub) != 32:
        raise click.ClickException(
            f"--bundle-signer-key must be 32 bytes (64 hex chars), "
            f"got {len(bundle_pub)}"
        )

    # Get a signer token (F7 safe)
    token = _get_link_signer_token(effective_server, sk, kid)
    if token is None:
        raise click.ClickException("failed to obtain signer token")

    user_id = meta.get("user_id", "")
    org_id = meta.get("org_id", "")

    # F12: refuse empty org_id or user_id
    if not org_id:
        raise click.ClickException(
            "org_id is empty in link metadata; cannot create genesis"
        )
    if not user_id:
        raise click.ClickException(
            "user_id is empty in link metadata; cannot create genesis"
        )

    # F9/stub ruling 3: iss/sub must come from link.json, not from
    # --confirm-identity.  If link.json lacks them, refuse.
    iss = meta.get("iss", "")
    sub_val = meta.get("sub", "")
    if not iss or not sub_val:
        raise click.ClickException(
            "link.json lacks iss/sub identity fields; "
            "re-link with a server that returns them"
        )

    # F9: --confirm-identity must match stored values
    if confirm_identity is not None:
        ci_iss, ci_sub = confirm_identity
        if ci_iss != iss or ci_sub != sub_val:
            raise click.ClickException(
                f"identity mismatch: --confirm-identity gave "
                f"({ci_iss}, {ci_sub}) but link.json has ({iss}, {sub_val})"
            )

    bundle_kid = hashlib.sha256(bundle_pub).hexdigest()

    if not yes:
        click.echo(f"Org ID:    {org_id}")
        click.echo(f"User ID:   {user_id}")
        click.echo(f"ISS:       {iss}")
        click.echo(f"SUB:       {sub_val}")
        click.echo(f"Key ID:    {kid[:16]}...")
        click.echo(f"Bundle signer key_id: {bundle_kid[:16]}...")
        click.echo(f"Roles:     {['admin', 'approver'] if approver else ['admin']}")
        click.confirm("Create genesis registry?", abort=True)

    env, fp = build_genesis(
        sk, org_id, iss, sub_val, bundle_pub,
        user_id=user_id, approver=approver,
    )

    # Post to genesis route (F7 safe)
    result = _signer_safe_post(
        effective_server.rstrip("/") + "/api/v1/sync/signer/genesis",
        {"genesis_code": genesis_code, "envelope": env},
        token,
    )

    click.echo(f"Genesis published: version={result.get('version', '?')}")
    click.echo(f"Fingerprint: {fp}")


@click.command("sign-registry")
@click.option("--in", "in_file", default=None, type=click.Path(exists=True),
              help="Read a partial envelope from FILE")
@click.option("--out", "out_file", default=None, type=click.Path(),
              help="Write the (possibly partial) envelope to FILE")
@click.option("--publish", is_flag=True, help="Post the complete envelope to /signatures")
@click.option("--add", "add_key_ids", multiple=True, help="Key IDs to add (repeatable)")
@click.option("--admin", is_flag=True, help="Grant admin role to added keys")
@click.option("--confirm-key-id", "confirm_key_ids_opt", multiple=True,
              help="Typed key_id confirmation (repeatable)")
@click.option("--confirm-identity", nargs=2, default=None, type=str,
              help="Confirm identity: <iss> <sub>")
@click.option("--expect-fingerprint", default=None, type=str,
              help="Expected registry fingerprint for chain verification")
@click.option("--threshold", "threshold_opt", default=None, type=int,
              help="Set the threshold in build mode (F10)")
@click.option("--server", default=None, help="Control plane URL")
@click.option("--yes", is_flag=True, help="Skip interactive confirmation")
def signer_sign_registry(in_file: str | None, out_file: str | None,
                         publish: bool, add_key_ids: tuple[str, ...],
                         admin: bool, confirm_key_ids_opt: tuple[str, ...],
                         confirm_identity: tuple[str, str] | None,
                         expect_fingerprint: str | None,
                         threshold_opt: int | None,
                         server: str | None, yes: bool) -> None:
    """Build or co-sign a registry version.

    Without --in, builds the next version from the latest server version
    plus the chosen candidates.  With --in FILE, co-signs an existing
    partial envelope.

    Stub ruling 2: fetches GET /api/v1/sync/signer/registry (full chain,
    org-scoped) and runs verify_chain against --expect-fingerprint or
    stored root fingerprint.

    F1: --confirm-key-id must exactly equal the added key set.
    F2: verify the chain, check prev_hash/version/org/signatures/kind.
    F8: prev_hash = sha256(org_id + ':' + canonical(prev)).
    F10: --threshold N in build mode.
    """
    from pathlib import Path
    from sandbox.connector.sync.signer import (
        compute_diff,
        confirm_key_ids as _confirm_key_ids,
    )
    from sandbox.protocol.envelope import (
        canonical_bytes,
        key_id as compute_key_id,
    )
    from sandbox.protocol.domains import REGISTRY
    from sandbox.protocol.registry import verify_chain, RegistryError, _payload_hash

    sk, kid, meta = _load_signer_link_key()
    effective_server = server or meta.get("server", "")
    if not effective_server:
        raise click.ClickException("no server URL; pass --server or link first")

    # F7: transport safety
    _check_transport_safety(effective_server)

    token = _get_link_signer_token(effective_server, sk, kid)
    if token is None:
        raise click.ClickException("failed to obtain signer token")

    confirmed_set = set(confirm_key_ids_opt)

    # Stub ruling 2: fetch the full chain from /api/v1/sync/signer/registry
    registry_url = (
        effective_server.rstrip("/")
        + "/api/v1/sync/signer/registry"
    )
    try:
        chain_data = _signer_safe_get(registry_url, token)
    except click.ClickException:
        raise click.ClickException(
            "failed to fetch registry chain from server"
        )
    if not isinstance(chain_data, list) or not chain_data:
        raise click.ClickException(
            "registry chain is empty or malformed"
        )

    # Determine the fingerprint to verify against
    fp = expect_fingerprint
    if not fp:
        # Try stored fingerprint from signer dir
        from sandbox.connector.keyhome import key_home_root
        kh = key_home_root()
        if kh:
            fp_path = kh / "signer" / "root_fingerprint"
            if fp_path.exists():
                fp = fp_path.read_text(encoding="utf-8").strip()
    if not fp:
        raise click.ClickException(
            "no --expect-fingerprint and no stored root fingerprint; "
            "cannot verify registry chain"
        )

    # Verify the chain
    try:
        verified_registry = verify_chain(chain_data, fp)
    except RegistryError as exc:
        raise click.ClickException(
            f"registry chain verification failed: {exc.reason}"
        )

    # The verified latest is the last envelope in the chain
    latest_env = chain_data[-1]
    latest_payload = latest_env.get("payload", {})
    latest_version = latest_payload.get("version", 0)
    latest_org = latest_payload.get("org_id", "")

    # Canonical JSON helper
    _cj = lambda p: json.dumps(p, sort_keys=True, separators=(",", ":")).encode()

    if in_file is not None:
        # ---------------------------------------------------------------
        # Co-sign mode
        # ---------------------------------------------------------------
        partial = json.loads(Path(in_file).read_text(encoding="utf-8"))
        payload = partial.get("payload", {})
        existing_sigs = partial.get("signatures", [])

        # F2: check kind
        if partial.get("kind") != REGISTRY:
            raise click.ClickException(
                f"envelope kind {partial.get('kind')!r} is not {REGISTRY!r}"
            )
        # F2: check sig_v
        if partial.get("sig_v") != 1:
            raise click.ClickException(
                f"envelope sig_v {partial.get('sig_v')!r} is not 1"
            )

        # F2: check version == latest + 1
        new_ver = payload.get("version")
        if new_ver != latest_version + 1:
            raise click.ClickException(
                f"version mismatch: partial has {new_ver}, "
                f"expected {latest_version + 1}"
            )

        # F2: check org_id
        if payload.get("org_id") != latest_org:
            raise click.ClickException(
                f"org_id mismatch: partial has {payload.get('org_id')!r}, "
                f"expected {latest_org!r}"
            )

        # F2: check prev_hash
        expected_prev = _payload_hash(latest_payload)
        if payload.get("prev_hash") != expected_prev:
            raise click.ClickException(
                f"prev_hash mismatch: partial has {payload.get('prev_hash')!r}, "
                f"expected {expected_prev[:16]}..."
            )

        # F2: verify every existing signature
        msg = canonical_bytes(REGISTRY, payload)
        # Build a trusted key map from the latest version's keys
        trusted_keys: dict[str, bytes] = {}
        for k in latest_payload.get("keys", []):
            try:
                trusted_keys[k["key_id"]] = bytes.fromhex(k["public_key"])
            except (ValueError, KeyError):
                pass
        # Also include keys from the new payload (for new signers)
        for k in payload.get("keys", []):
            try:
                trusted_keys[k["key_id"]] = bytes.fromhex(k["public_key"])
            except (ValueError, KeyError):
                pass

        for sig_entry in existing_sigs:
            sig_kid = sig_entry.get("key_id", "")
            sig_hex = sig_entry.get("sig", "")
            pub_bytes = trusted_keys.get(sig_kid)
            if pub_bytes is None:
                raise click.ClickException(
                    f"existing signature by unknown key {sig_kid[:16]}..."
                )
            try:
                from nacl.signing import VerifyKey
                vk = VerifyKey(pub_bytes)
                vk.verify(msg, bytes.fromhex(sig_hex))
            except Exception as exc:
                raise click.ClickException(
                    f"existing signature by {sig_kid[:16]}... is invalid: {exc}"
                )

        # F2: refuse if own key_id is already in signatures (duplicate)
        own_sigs = [s for s in existing_sigs if s.get("key_id") == kid]
        if own_sigs:
            raise click.ClickException(
                f"own key_id already in signatures (duplicate); "
                f"refusing to co-sign twice"
            )

        # Compute diff for display
        prev_bytes = _cj(latest_payload)
        new_bytes = _cj(payload)
        diff_text = compute_diff(prev_bytes, new_bytes)
        click.echo("Registry version diff:")
        click.echo(diff_text)

        # F1: determine added keys (in new but not in latest)
        latest_kids = {k["key_id"] for k in latest_payload.get("keys", [])}
        added_kids = [
            k["key_id"] for k in payload.get("keys", [])
            if k["key_id"] not in latest_kids
        ]
        # F1: check confirm-key-id matches added set exactly
        if added_kids:
            if confirmed_set != set(added_kids):
                raise click.ClickException(
                    f"--confirm-key-id set {confirmed_set} does not match "
                    f"added key set {set(added_kids)}; refusing to sign"
                )
            # F1: verify sha256(public_key) == key_id for each added key
            new_key_map = {k["key_id"]: k for k in payload.get("keys", [])}
            for akid in added_kids:
                entry = new_key_map.get(akid, {})
                try:
                    pub_hex = entry.get("public_key", "")
                    computed = hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()
                    if computed != akid:
                        raise click.ClickException(
                            f"key_id {akid[:16]}... != sha256(public_key)"
                        )
                except (ValueError, TypeError) as exc:
                    raise click.ClickException(
                        f"cannot verify key_id {akid[:16]}...: {exc}"
                    )

        if not yes:
            click.confirm("Co-sign this registry version?", abort=True)

        # Sign
        sig = sk.sign(msg).signature.hex()
        new_sig_entry = {"key_id": kid, "alg": "ed25519", "sig": sig}
        envelope = {
            "kind": REGISTRY,
            "sig_v": 1,
            "payload": payload,
            "signatures": existing_sigs + [new_sig_entry],
        }
    else:
        # ---------------------------------------------------------------
        # Build mode
        # ---------------------------------------------------------------
        candidates_url = (
            effective_server.rstrip("/")
            + "/api/v1/sync/signer/candidates"
        )
        try:
            candidates = _signer_safe_get(candidates_url, token)
        except click.ClickException:
            candidates = []
        if not isinstance(candidates, list):
            candidates = []

        prev_payload = latest_payload
        prev_version = latest_version

        # F8: prev_hash uses org prefix (payload_hash)
        prev_hash_val = _payload_hash(prev_payload)

        new_version = prev_version + 1
        org_id = prev_payload.get("org_id", meta.get("org_id", ""))

        # Start with existing keys
        new_keys = list(prev_payload.get("keys", []))
        new_admins = list(prev_payload.get("admins", []))

        # Add requested candidates
        for add_kid in add_key_ids:
            cand = next(
                (c for c in candidates if c.get("key_id") == add_kid), None
            )
            if cand is None:
                raise click.ClickException(
                    f"candidate key {add_kid[:16]}... not found on server"
                )
            roles = ["approver"]
            if admin:
                roles = ["admin", "approver"]
            new_keys.append({
                "key_id": cand["key_id"],
                "public_key": cand["public_key"],
                "user_id": cand["user_id"],
                "iss": cand["iss"],
                "sub": cand["sub"],
                "alg": "ed25519",
                "kind": cand.get("kind", "cli"),
                "roles": roles,
                "added_in": new_version,
            })
            if admin:
                new_admins.append(cand["key_id"])

        # F10: --threshold N in build mode
        new_threshold = prev_payload.get("threshold", 1)
        if threshold_opt is not None:
            new_threshold = threshold_opt

        payload = {
            "org_id": org_id,
            "version": new_version,
            "prev_hash": prev_hash_val,
            "threshold": new_threshold,
            "admins": new_admins,
            "keys": new_keys,
            "bundle_signer": prev_payload.get("bundle_signer", {}),
            "expires_at": prev_payload.get("expires_at", time.time() + 7 * 24 * 3600),
        }

        # Compute and show diff
        prev_bytes = _cj(prev_payload)
        new_bytes = _cj(payload)
        diff_text = compute_diff(prev_bytes, new_bytes)
        click.echo("Registry version diff:")
        click.echo(diff_text)

        # F1: determine added keys
        latest_kids = {k["key_id"] for k in prev_payload.get("keys", [])}
        added_kids_list = [akid for akid in add_key_ids if akid not in latest_kids]

        # F1: check confirm-key-id matches added set exactly
        if added_kids_list:
            if confirmed_set != set(added_kids_list):
                raise click.ClickException(
                    f"--confirm-key-id set {confirmed_set} does not match "
                    f"added key set {set(added_kids_list)}; refusing to sign"
                )
            # F1: verify sha256(public_key) == key_id for each added key
            new_key_map = {k["key_id"]: k for k in new_keys}
            for akid in added_kids_list:
                entry = new_key_map.get(akid, {})
                try:
                    pub_hex = entry.get("public_key", "")
                    computed = hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()
                    if computed != akid:
                        raise click.ClickException(
                            f"key_id {akid[:16]}... != sha256(public_key)"
                        )
                except (ValueError, TypeError) as exc:
                    raise click.ClickException(
                        f"cannot verify key_id {akid[:16]}...: {exc}"
                    )

        if not yes:
            click.confirm("Sign this registry version?", abort=True)

        # Sign
        tag = REGISTRY
        msg = canonical_bytes(tag, payload)
        sig = sk.sign(msg).signature.hex()
        envelope = {
            "kind": tag,
            "sig_v": 1,
            "payload": payload,
            "signatures": [
                {"key_id": kid, "alg": "ed25519", "sig": sig}
            ],
        }

    # Output
    if out_file:
        Path(out_file).write_text(
            json.dumps(envelope, indent=2), encoding="utf-8"
        )
        click.echo(f"Envelope written to {out_file}")

    if publish:
        pub_url = (
            effective_server.rstrip("/")
            + "/api/v1/sync/signer/signatures"
        )
        result = _signer_safe_post(
            pub_url,
            {"type": "registry", "envelope": envelope, "org_id": meta.get("org_id", "")},
            token,
        )
        click.echo(f"Published: version={result.get('version', '?')}")


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
    signer_group.add_command(signer_link)
    signer_group.add_command(signer_genesis)
    signer_group.add_command(signer_sign_registry)
