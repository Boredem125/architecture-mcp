"""CLI commands for T3 policy-change workflow.

issue-code, propose-bundle, approve-change, publish -- attached to ``signer``.
Connector TCB files are imported by name, never edited.

Keys: --key-file (N2: warns on exposure, never refuses) or linked key
(_load_signer_link_key).
Tokens: minted at /api/v1/sync/signer/token with the bare envelope.
No new loader, no token cache, no AGG_KEY_HOME (MUST 10, D2).
"""
from __future__ import annotations

import hashlib
import json
import pathlib

import click
import httpx

from sandbox.cli.sync_cmds import (
    _check_display_safety,
    _check_transport_safety,
)
from sandbox.connector.sync.bundles import (
    BUNDLE_FIELDS,
    BundleError,
    _bundle_hash,
    _verify_bundle_signer_in_registry,
    _verify_envelope_structure,
    _verify_signature,
    loosened,
)
from sandbox.protocol.envelope import canonical_bytes
from sandbox.protocol.registry import verify_chain

# Deny-all base (connector step 10 literal, A9 item 3)
DENY_ALL_BASE: dict = {
    "folder_policy": {"shell": {"blocklist_action": "deny"}},
    "governance_policy": {"clauses": []},
    "mcp_policy": {"servers": []},
    "approval": {"local_fallback": False, "allow_requester": False},
}

_SERVER_OWNED_KEYS = frozenset({
    "org_id", "project_id", "sequence", "base_sequence",
    "registry_version", "environment",
    "issued_at", "not_before", "expires_at",
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_str(val):
    """Ensure server strings are display-safe (M-11)."""
    return json.dumps(val, ensure_ascii=True) if isinstance(val, str) else str(val)


def _require_str(bundle: dict, key: str) -> str:
    """Extract a non-empty str from the hashed bundle, or raise ClickException."""
    v = bundle.get(key)
    if not isinstance(v, str) or not v:
        raise click.ClickException(
            f"bundle field {_safe_str(key)}: expected non-empty str, "
            f"got {_safe_str(type(v).__name__)}")
    return v


def _require_int(bundle: dict, key: str) -> int:
    """Extract an int (not bool) from the hashed bundle, or raise ClickException."""
    v = bundle.get(key)
    if isinstance(v, bool) or not isinstance(v, int):
        raise click.ClickException(
            f"bundle field {_safe_str(key)}: expected int, "
            f"got {_safe_str(type(v).__name__)}")
    return v


def _strict_json_parse(raw: str) -> dict:
    """Parse JSON with duplicate-key detection at every depth and NaN refusal."""
    def _pairs(pairs):
        keys = set()
        result = {}
        for k, v in pairs:
            if k in keys:
                raise ValueError(f"duplicate key: {k!r}")
            keys.add(k)
            result[k] = v
        return result

    def _refuse(s):
        raise ValueError(f"NaN/Infinity: {s!r}")

    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_refuse)


def _load_key(key_file: str | None):
    """Load signing key from --key-file or the linked key (MUST 10).

    --key-file: N2 conditions: hex exactly 64 hex chars with at most one
    trailing newline removed; raw exactly 32 bytes, never stripped;
    anything else refused.
    No --key-file: _load_signer_link_key (signer.seed, D4-2).
    Returns (sk, meta) or (None, None) when no key is configured.
    """
    if key_file:
        from nacl.signing import SigningKey
        p = pathlib.Path(key_file)
        raw = p.read_bytes()

        # N2: print root_exposure warning to stderr without refusing
        try:
            from sandbox.connector.keyhome import root_exposure
            warning = root_exposure(p.parent)
            if warning:
                import sys
                print(f"warning: {warning}", file=sys.stderr)
        except Exception:
            pass

        # N2 condition 1: hex exactly 64 chars with at most one trailing newline
        # Try to strip at most one trailing \r\n or \n
        text_raw = raw
        if text_raw.endswith(b"\r\n"):
            text_raw = text_raw[:-2]
        elif text_raw.endswith(b"\n"):
            text_raw = text_raw[:-1]

        if len(text_raw) == 64:
            try:
                hex_str = text_raw.decode("ascii")
                # Verify all chars are hex
                seed = bytes.fromhex(hex_str)
                return SigningKey(seed), None
            except (ValueError, UnicodeDecodeError):
                pass

        # N2 condition 2: raw exactly 32 bytes, never stripped
        if len(raw) == 32:
            return SigningKey(raw), None

        # N2 condition 3: anything else refused
        raise click.ClickException(
            f"seed file {len(raw)} bytes: expected exactly 32 raw bytes "
            f"or 64 hex chars (with at most one trailing newline)")
    # Linked key -- may not exist (R3-2: no fallback)
    from sandbox.connector.keyhome import key_home_root
    kh = key_home_root()
    if kh is None:
        return None, None
    seed_path = kh / "signer" / "signer.seed"
    if not seed_path.exists():
        return None, None
    # signer.seed exists: use _load_signer_link_key and let its
    # ClickException propagate (exit 1).  This preserves D4-2 tamper
    # detection, F4 exposure refusal, and the link binding.
    from sandbox.cli.sync_cmds import _load_signer_link_key
    sk, kid, meta = _load_signer_link_key()
    return sk, meta


def _mint_token(client: httpx.Client, server: str, sk) -> str:
    """Mint a signer token at /api/v1/sync/signer/token (bare envelope)."""
    import secrets
    import time

    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    nonce = secrets.token_hex(16)
    payload = {"key_id": kid, "nonce": nonce, "aud": server.rstrip("/"),
               "iat": time.time()}
    msg = canonical_bytes("agg/signer-assert/v1", payload)
    sig = sk.sign(msg).signature.hex()
    env = {
        "kind": "agg/signer-assert/v1", "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": kid, "alg": "ed25519", "sig": sig}],
    }
    r = client.post(f"{server.rstrip('/')}/api/v1/sync/signer/token", json=env)
    if r.status_code not in (200, 201):
        raise click.ClickException(f"token mint failed: {r.status_code}")
    tok = r.json().get("token")
    if not tok:
        raise click.ClickException("token mint returned no token")
    return tok


def _bearer(token: str | None) -> dict:
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


# ---------------------------------------------------------------------------
# issue-code
# ---------------------------------------------------------------------------

@click.command("issue-code")
@click.option("--server", required=True, help="Control plane URL")
@click.option("--project", required=True, help="Project ID")
@click.option("--operator", required=True, help="Operator user ID")
@click.option("--key-file", default=None, help="Signing key file")
def issue_code(server, project, operator, key_file):
    """Issue an enrollment code through the CLI."""
    _check_transport_safety(server)
    sk, _ = _load_key(key_file)

    with httpx.Client(follow_redirects=False, timeout=30) as c:
        token = None
        if sk is not None:
            # MUST 8 (C-e): failed mint exits 1 when key is configured
            token = _mint_token(c, server, sk)
        r = c.post(f"{server.rstrip('/')}/api/v1/admin/enrollment-codes",
                    json={"project_id": project, "operator_user_id": operator},
                    headers=_bearer(token))

    if r.status_code not in (200, 201):
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        raise click.ClickException(
            f"issue-code failed: {_safe_str(body.get('error', r.status_code))} "
            f"{_safe_str(body.get('detail', ''))}")

    resp = r.json()
    _check_display_safety({"code_id": resp.get("code_id", ""),
                           "expires_at": str(resp.get("expires_at", ""))})
    click.echo(f"code_id: {_safe_str(resp.get('code_id', ''))}")
    click.echo(f"expires_at: {_safe_str(resp.get('expires_at', ''))}")
    click.echo("the operator reads the code once at /enroll/<code_id>")


# ---------------------------------------------------------------------------
# propose-bundle
# ---------------------------------------------------------------------------

@click.command("propose-bundle")
@click.option("--server", required=True)
@click.option("--project", required=True)
@click.option("--bundle-file", required=True, type=click.Path(exists=True))
@click.option("--key-file", default=None)
def propose_bundle(server, project, bundle_file, key_file):
    """Propose a bundle from a JSON file."""
    _check_transport_safety(server)
    sk, _ = _load_key(key_file)

    # Strict local parse (MUST 12)
    raw = open(bundle_file, "r").read()
    try:
        bundle = _strict_json_parse(raw)
    except (ValueError, RecursionError) as exc:
        raise click.ClickException(f"invalid JSON: {exc}") from exc
    if not isinstance(bundle, dict):
        raise click.ClickException("bundle must be a JSON object")

    with httpx.Client(follow_redirects=False, timeout=30) as c:
        token = None
        if sk is not None:
            # MUST 8 (C-e): failed mint exits 1 when key is configured
            token = _mint_token(c, server, sk)
        r = c.post(f"{server.rstrip('/')}/api/v1/admin/bundle-proposals",
                    json={"project_id": project, "bundle": bundle},
                    headers=_bearer(token))

    if r.status_code not in (200, 201):
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        raise click.ClickException(
            f"propose-bundle failed: {_safe_str(body.get('error', r.status_code))} "
            f"{_safe_str(body.get('detail', ''))}")

    resp = r.json()
    server_bundle = resp.get("bundle")
    server_hash = resp.get("bundle_hash", resp.get("hash", ""))

    # MUST 7 / N3: bundle is required in the response
    if server_bundle is None:
        raise click.ClickException(
            f"server response has no bundle; unverified server hash "
            f"{_safe_str(server_hash)}; refusing")

    # Verify hash from returned bundle
    local_hash = _bundle_hash(server_bundle)
    if local_hash != server_hash:
        raise click.ClickException(
            f"hash mismatch: local {local_hash} != server {_safe_str(server_hash)}")

    # MUST 7 (C-b1): added keys must be server-owned (MUST 3: sanitize)
    for k in server_bundle:
        if k not in BUNDLE_FIELDS:
            raise click.ClickException(
                f"server added unknown key: {_safe_str(k)}")
        if k not in bundle and k not in _SERVER_OWNED_KEYS:
            raise click.ClickException(
                f"server added non-server-owned key: {_safe_str(k)}")

    # MUST 7 (C-b2): every section sent must be present and equal
    for k in bundle:
        if k not in server_bundle:
            raise click.ClickException(f"server dropped section: {k}")
        if server_bundle[k] != bundle[k]:
            raise click.ClickException(f"server altered {k}")

    pid = resp.get("id", resp.get("proposal_id", ""))
    click.echo(f"proposal {_safe_str(pid)} bundle_hash {local_hash}")


# ---------------------------------------------------------------------------
# approve-change
# ---------------------------------------------------------------------------

@click.command("approve-change")
@click.argument("proposal_id")
@click.option("--server", required=True)
@click.option("--key-file", default=None)
@click.option("--expect-fingerprint", default=None)
@click.option("--yes", is_flag=True)
def approve_change(proposal_id, server, key_file, expect_fingerprint, yes):
    """Fetch a proposal, verify locally, sign and submit an approval."""
    _check_transport_safety(server)
    sk, _ = _load_key(key_file)

    # MUST 6 (C-d): no key -> exit 1 via ClickException, no traceback
    if sk is None:
        raise click.ClickException(
            "no signing key: pass --key-file or link a signer key")

    pub = bytes(sk.verify_key)
    own_kid = hashlib.sha256(pub).hexdigest()

    # S-2: anchor resolution, before any network call.
    # (a) enrolled workspace, (b) --expect-fingerprint, (c) stored root_fingerprint.
    anchor_fp = None

    from sandbox.connector.keyhome import key_home_root
    kh = key_home_root()

    if expect_fingerprint is not None:
        anchor_fp = expect_fingerprint

    if anchor_fp is None and kh is not None:
        fp_path = kh / "signer" / "root_fingerprint"
        if fp_path.is_file():
            anchor_fp = fp_path.read_text().strip()

    # D2: no anchor -> exit 1, unconditionally, before any network call.
    if anchor_fp is None:
        raise click.ClickException(
            "no trust anchor: enroll a workspace, pass "
            "--expect-fingerprint, or store signer/root_fingerprint")

    # approve-change never writes the fingerprint file.

    with httpx.Client(follow_redirects=False, timeout=30) as c:
        # Mint a token (D3: approve-change mints a token)
        token = _mint_token(c, server, sk)
        hdrs = _bearer(token)

        # Fetch and verify registry (MUST 11)
        try:
            r_reg = c.get(
                f"{server.rstrip('/')}/api/v1/sync/signer/registry",
                headers=hdrs)
            if r_reg.status_code != 200:
                raise click.ClickException(
                    f"registry fetch failed: {r_reg.status_code}")
            reg_data = r_reg.json()
            # Bare list (as the real route returns)
            if isinstance(reg_data, list):
                chain = reg_data
            elif isinstance(reg_data, dict) and "chain" in reg_data:
                chain = reg_data["chain"]
            else:
                raise click.ClickException("registry: unexpected shape")
            if not chain:
                raise click.ClickException("registry: empty chain")
            reg = verify_chain(chain, anchor_fp)
        except click.ClickException:
            raise
        except Exception as exc:
            raise click.ClickException(
                f"registry verification failed: {_safe_str(str(exc))}") from exc

        # GET detail
        r_detail = c.get(
            f"{server.rstrip('/')}/api/v1/admin/bundle-proposals/{proposal_id}",
            headers=hdrs)
        if r_detail.status_code != 200:
            raise click.ClickException(
                f"proposal fetch failed: {r_detail.status_code}")

        detail = r_detail.json()
        proposal_bundle = detail.get("bundle", {})
        proposal_hash = detail.get("bundle_hash", detail.get("hash", ""))

        # Verify hash
        local_hash = _bundle_hash(proposal_bundle)
        if local_hash != proposal_hash:
            raise click.ClickException(
                f"hash mismatch: local={local_hash} server={_safe_str(proposal_hash)}")

        # Field checks (MUST 3: sanitize server-derived keys)
        for k in proposal_bundle:
            if k not in BUNDLE_FIELDS:
                raise click.ClickException(
                    f"unknown field: {_safe_str(k)}")
        if "change_approvals" in proposal_bundle:
            raise click.ClickException("bundle contains change_approvals")

        # MUST 2: read fields only from hashed bundle, with type checks
        prop_org = _require_str(proposal_bundle, "org_id")
        prop_project = _require_str(proposal_bundle, "project_id")
        seq = _require_int(proposal_bundle, "sequence")
        base_seq = _require_int(proposal_bundle, "base_sequence")
        prop_rv = _require_int(proposal_bundle, "registry_version")

        if seq != base_seq + 1:
            raise click.ClickException(
                f"sequence {_safe_str(str(seq))} != base "
                f"{_safe_str(str(base_seq))} + 1")

        # Base verification
        if base_seq == 0:
            base_payload = DENY_ALL_BASE
        else:
            base_detail = detail.get("base", {})
            base_env = base_detail.get("envelope")
            if base_env is None:
                raise click.ClickException("base >= 1 but no base envelope")
            try:
                _verify_envelope_structure(base_env)
            except BundleError as exc:
                raise click.ClickException(
                    f"base structure invalid: {_safe_str(str(exc))}") from exc

            from sandbox.connector.sync.process import _bundle_signer_pub
            try:
                bs_pub = _bundle_signer_pub(reg)
                _verify_signature(base_env, bs_pub)
                _verify_bundle_signer_in_registry(reg, bs_pub)
            except BundleError as exc:
                raise click.ClickException(
                    f"base signature invalid: {_safe_str(str(exc))}") from exc

            bp = base_env.get("payload", {})
            if bp.get("sequence") != base_seq:
                raise click.ClickException("base sequence mismatch")
            if bp.get("org_id") != prop_org:
                raise click.ClickException("base org mismatch")
            if bp.get("project_id") != prop_project:
                raise click.ClickException("base project mismatch")
            base_payload = bp

        # Diff from local bytes
        diff = {}
        for sec in ("folder_policy", "governance_policy", "mcp_policy",
                     "approval", "environment"):
            old = base_payload.get(sec, {})
            new = proposal_bundle.get(sec, {})
            if old != new:
                diff[sec] = {"old": old, "new": new}

        # Loosened (M-4: error -> refuse; MUST 3: sanitize exc text)
        try:
            sections_loosened = loosened(base_payload, proposal_bundle)
        except Exception as exc:
            raise click.ClickException(
                f"loosened error: {_safe_str(str(exc))}") from exc

        is_loosening = bool(sections_loosened)
        is_first = base_seq == 0
        needed = 2 if (is_loosening or is_first) else 1

        # Org check (MUST 2 / C-a): unconditional comparison
        chain_org = chain[0].get("payload", {}).get("org_id") if chain else None
        if str(prop_org) != str(chain_org):
            raise click.ClickException("proposal org != registry org")

        if prop_rv < reg.version:
            raise click.ClickException(
                f"proposal registry_version {prop_rv} < chain version {reg.version}")

        # Own key must be a cli entry with a counting role
        own_entry = reg._keys.get(own_kid)
        if own_entry is None:
            raise click.ClickException("own key not in registry")
        if own_entry.get("kind") != "cli":
            raise click.ClickException("own key is not cli")
        own_roles = set(own_entry.get("roles", []))
        if not own_roles.intersection({"policy_author", "approver", "admin"}):
            raise click.ClickException("own key has no counting role")

        # Confirm screen (M-11)
        click.echo(f"org_id: {_safe_str(prop_org)}")
        click.echo(f"project_id: {_safe_str(prop_project)}")
        click.echo(f"environment: {_safe_str(proposal_bundle.get('environment', ''))}")
        click.echo(f"sequence: {_safe_str(str(seq))}")
        click.echo(f"base_sequence: {_safe_str(str(base_seq))}")
        click.echo(f"registry_version: {_safe_str(str(prop_rv))}")
        click.echo(f"bundle_hash: {proposal_hash}")
        for sec, d in diff.items():
            click.echo(f"  {sec}:")
            click.echo(f"    old: {_safe_str(d['old'])}")
            click.echo(f"    new: {_safe_str(d['new'])}")
        if not diff:
            click.echo("  no section changes")
        if is_loosening:
            click.echo(f"loosened: {_safe_str(json.dumps(sections_loosened))}")
        click.echo(f"approvals needed: {needed}")

        if not yes:
            if not click.confirm("Approve this change?"):
                raise click.ClickException("aborted by user")

        # Sign
        sign_payload = {"bundle_hash": proposal_hash}
        msg = canonical_bytes("agg/policy-change/v1", sign_payload)
        sig = sk.sign(msg).signature.hex()
        approval_env = {
            "kind": "agg/policy-change/v1", "sig_v": 1,
            "payload": sign_payload,
            "signatures": [{"key_id": own_kid, "alg": "ed25519", "sig": sig}],
        }

        # POST approval (M-10: no POST before every local check)
        r_approve = c.post(
            f"{server.rstrip('/')}/api/v1/admin/bundle-proposals/"
            f"{proposal_id}/approvals",
            json={"approval": approval_env},
            headers=hdrs)

    if r_approve.status_code not in (200, 201):
        body = r_approve.json() if r_approve.headers.get(
            "content-type", "").startswith("application/json") else {}
        raise click.ClickException(
            f"approval failed: {r_approve.status_code} "
            f"{_safe_str(body.get('error', ''))} "
            f"{_safe_str(body.get('detail', ''))}")

    click.echo(f"approved proposal {_safe_str(proposal_id)}")


# ---------------------------------------------------------------------------
# publish
# ---------------------------------------------------------------------------

@click.command("publish")
@click.argument("proposal_id")
@click.option("--server", required=True)
@click.option("--key-file", default=None)
def publish(proposal_id, server, key_file):
    """Publish a proposal."""
    _check_transport_safety(server)
    sk, _ = _load_key(key_file)

    with httpx.Client(follow_redirects=False, timeout=30) as c:
        token = None
        if sk is not None:
            # MUST 8 (C-e): failed mint exits 1 when key is configured
            token = _mint_token(c, server, sk)
        r = c.post(
            f"{server.rstrip('/')}/api/v1/admin/bundle-proposals/"
            f"{proposal_id}/publish",
            json={}, headers=_bearer(token))

    if r.status_code in (200, 201):
        resp = r.json()
        click.echo(f"published: sequence={_safe_str(resp.get('sequence', '?'))} "
                   f"hash={_safe_str(resp.get('bundle_hash', '?'))}")
    else:
        body = r.json() if r.headers.get(
            "content-type", "").startswith("application/json") else {}
        click.echo(f"publish refused: {_safe_str(body.get('error', r.status_code))} "
                   f"{_safe_str(body.get('detail', ''))}")
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register(cli) -> None:
    """Attach issue-code, propose-bundle, approve-change, publish to signer."""
    signer = cli.commands.get("signer")
    if signer is None:
        return
    signer.add_command(issue_code, "issue-code")
    signer.add_command(propose_bundle, "propose-bundle")
    signer.add_command(approve_change, "approve-change")
    signer.add_command(publish, "publish")
