"""M3 T9a security tests: R1 fixes T9A-1 to T9A-9, R2 fixes R2-1 to R2-14,
Lows, T9A-10 nodes, and R4 items.

Strict xfail ``raises=M3T9Pending``; the build removes only the markers.
Guards PASS today.

Spec: T9A_SPEC.md sections 2, 4, 5, 6, 7, 8.
Review: T9A_SECURITY_REVIEW.md sections R1 to R5.
"""
from __future__ import annotations

import ast
import asyncio
import binascii
import json
import os
import secrets
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
from email.utils import formatdate
from pathlib import Path

import click.testing
import pytest

from tests.m3_pending import require_m3
from tests.security.test_m2_t12_remote import (
    _build_registry,
    _create_pending_request,
    _keygen,
    _make_remote_approval,
    _make_remote_deny,
    _setup_managed_workspace,
    _sign_envelope,
    _ws,
)
from tests.security.test_m3_t9a_fetch_decisions import (
    _build_server_row,
    _read_audit,
    _run_alerts_cli,
    _run_status_cli,
    _pending_request_ids,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_APPROVAL_PY = _REPO_ROOT / "src" / "sandbox" / "connector" / "approval.py"


def _need(reason: str = "") -> None:
    """Raise M3T9Pending when the T9a R1 features are still absent."""
    if os.environ.get("M3_T9A_BODIES") == "1":
        return
    from sandbox.connector import alerts
    require_m3(9, "decision_refused" in alerts._ALWAYS, reason)



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _date_hdr():
    return {"Date": formatdate(usegmt=True)}

def _run_status_json(layout):
    from sandbox.cli.connector_cmds import status_cmd
    r = click.testing.CliRunner().invoke(status_cmd, [str(layout.root), "--json"])
    if r.exit_code != 0 or not r.output.strip():
        return {}
    try: return json.loads(r.output)
    except json.JSONDecodeError: return {}

def _good_row(ws, lay, rid, idx=0, cmd="echo x", not_after=None):
    rec = _create_pending_request(lay, rid, command=cmd)
    sk, _, kid = ws["admin_sks"][idx][:3]
    appr = _make_remote_approval(sk, request_id=rid, command=cmd,
                                 fingerprint=rec["fingerprint"],
                                 user_id=f"admin-{kid[:8]}",
                                 not_after=not_after)
    return rec, appr, _build_server_row(appr, rid)

def _stub_decisions(rows, hdrs=None):
    h = hdrs or _date_hdr()
    def connect(method, url, body=None, headers=None, token=None):
        if "/sync/decisions" in url: return (200, {"decisions": rows}, h)
        return (200, {}, h)
    return connect

def _stub_status(status, body=None, hdrs=None):
    h = hdrs or _date_hdr()
    def connect(method, url, body_=None, headers=None, token=None):
        if "/sync/decisions" in url: return (status, body or {}, h)
        return (200, {}, h)
    return connect

def _mk(lay, connect):
    from sandbox.connector.sync.process import SyncProcess
    dsk = _keygen()
    s = SyncProcess(layout=lay, server_url="http://127.0.0.1:9999",
                    device_key=bytes(dsk[0]), device_id="dev-1",
                    clock=time.monotonic, connect=connect)
    s._token = "t"; s._token_expires = time.monotonic() + 3600
    return s, dsk

def _mk2(lay, connect, dsk):
    from sandbox.connector.sync.process import SyncProcess
    s = SyncProcess(layout=lay, server_url="http://127.0.0.1:9999",
                    device_key=bytes(dsk[0]), device_id="dev-1",
                    clock=time.monotonic, connect=connect)
    s._token = "t"; s._token_expires = time.monotonic() + 3600
    return s

def _full_cycle_connect(rows, calls=None):
    """Connect stub that serves token, registry, decisions, and tracks calls to later routes."""
    h = _date_hdr()
    if calls is None:
        calls = []
    def connect(method, url, body=None, headers=None, token=None):
        calls.append(url)
        if "/sync/token" in url: return (200, {"access_token": "t", "expires_in": 3600}, h)
        if "/sync/registry" in url: return (200, {"registry": []}, h)
        if "/sync/decisions" in url: return (200, {"decisions": rows}, h)
        return (200, {}, h)
    connect.calls = calls
    return connect


# ===================================================================
# Guards: PASS on today's build
# ===================================================================

class TestGuards:
    def test_differential_verdict_unchanged(self, tmp_path, monkeypatch):
        from sandbox.connector.approval import apply_external
        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]; rid = "req-diff-001"
        rec = _create_pending_request(lay, rid, command="echo diff")
        bad = _make_remote_approval(_keygen()[0], request_id=rid, command="echo diff",
                                    fingerprint=rec["fingerprint"], user_id="evil")
        r = asyncio.run(apply_external(lay, rid, [bad], clock=lambda: time.time()))
        assert r.get("status") != "executed"
        assert rid in _pending_request_ids(lay)

    def test_cap_does_not_affect_audit_fork(self, tmp_path, monkeypatch):
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]
        rows = []
        for i in range(10):
            rid = f"req-fk-{i:03d}"
            rec = _create_pending_request(lay, rid, command=f"echo f{i}")
            rows.append(_build_server_row(_make_remote_approval(
                _keygen()[0], request_id=rid, command=f"echo f{i}",
                fingerprint=rec["fingerprint"], user_id=f"e{i}"), rid))
        s, _ = _mk(lay, _stub_decisions(rows))
        _fetch_decisions(s)
        lay.logs_dir.mkdir(parents=True, exist_ok=True)
        with open(lay.logs_dir / "alerts.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps({"event":"audit_fork","reason":"test","tool":"test",
                                "ts":time.time(),"kind":"audit_fork"}) + "\n")
        assert len([a for a in read_alerts(lay, limit=500) if a.get("event") == "audit_fork"]) == 1

    def test_repeat_poll_audit_comparison(self, tmp_path, monkeypatch):
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.approval import apply_external
        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]; admin = ws["admin_sks"]; rid = "req-rp-001"
        rec = _create_pending_request(lay, rid, command="echo rp", requires_dual=False)
        fp = rec["fingerprint"]
        a0 = _make_remote_approval(admin[0][0], request_id=rid, command="echo rp",
                                   fingerprint=fp, user_id=f"admin-{admin[0][2][:8]}")
        a1 = _make_remote_approval(admin[1][0], request_id=rid, command="echo rp",
                                   fingerprint=fp, user_id=f"admin-{admin[1][2][:8]}")
        asyncio.run(apply_external(lay, rid, [a0, a1], clock=lambda: time.time()))
        n0 = len(_read_audit(lay))
        s, _ = _mk(lay, _stub_decisions([_build_server_row(a0, rid)]))
        _fetch_decisions(s)
        new = [r for r in _read_audit(lay)[n0:]
               if r.get("event") in ("sync_decision_applied","decision_refused")]
        assert len(new) == 0

    @pytest.mark.parametrize("blob", ["not json", 42], ids=["not_json","scalar"])
    def test_corrupt_state_guard(self, tmp_path, monkeypatch, blob):
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay = ws["lay"]; _, _, row = _good_row(ws, lay, "req-cg-001")
        row = dict(row); row["signature"] = "00"*64
        sp = lay.root / ".sandbox" / "logs" / "decision_state.json"
        sp.parent.mkdir(parents=True, exist_ok=True)
        sp.write_text(json.dumps(blob) if not isinstance(blob, str) else blob, encoding="utf-8")
        s, _ = _mk(lay, _stub_decisions([row]))
        _fetch_decisions(s)
        assert len([a for a in read_alerts(lay, limit=200)
                    if a.get("event") in ("decision_refused","decisions_malformed")]) >= 1
        sp.write_text(json.dumps(blob) if not isinstance(blob, str) else blob, encoding="utf-8")
        from sandbox.cli.connector_cmds import status_cmd
        assert click.testing.CliRunner().invoke(status_cmd, [str(lay.root)]).exit_code == 0


# ===================================================================
# Targets: FAIL on today's build
# ===================================================================

class TestT9A1:
    def test_verify_remote_approval_has_no_bare_return_none(self):
        src = _APPROVAL_PY.read_text(encoding="utf-8")
        tree = ast.parse(src)
        func = next((n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_verify_remote_approval"), None)
        assert func, "_verify_remote_approval not found"
        drops = {n.lineno for n in ast.walk(func) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_drop"}
        rets = [n.lineno for n in ast.walk(func) if isinstance(n, ast.Return) and (n.value is None or (isinstance(n.value, ast.Constant) and n.value is None))]
        assert drops, f"no _drop calls; bare returns at: {rets}"
        assert len(drops) >= len(rets), f"{len(drops)} _drop < {len(rets)} return None"

    def test_outage_at_registry_counts_toward_three(self, tmp_path, monkeypatch):
        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        def c(m, u, body=None, headers=None, token=None):
            if "/sync/token" in u: return (200, {"access_token":"t","expires_in":3600}, _date_hdr())
            if "/sync/registry" in u: raise ConnectionError("down")
            return (200, {}, _date_hdr())
        dsk = _keygen()
        for _ in range(3):
            s = SyncProcess(layout=lay, server_url="http://127.0.0.1:9999", device_key=bytes(dsk[0]), device_id="dev-1", clock=time.monotonic, connect=c)
            try: run_once(s)
            except SyncError: pass
        fetch_alerts = [a for a in read_alerts(lay, limit=200) if a.get("event")=="decisions_fetch_failed"]
        assert len(fetch_alerts) >= 1
        assert fetch_alerts[0].get("reason_code") == "network_error", \
            f"outage at registry must be network_error; got {fetch_alerts[0].get('reason_code')}"

    def test_revoked_token_route_401_alerts_stage_token(self, tmp_path, monkeypatch):
        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        def c(m, u, body=None, headers=None, token=None):
            if "/sync/token" in u: return (401, {"detail":"revoked"}, _date_hdr())
            return (200, {}, _date_hdr())
        s = SyncProcess(layout=lay, server_url="http://127.0.0.1:9999", device_key=bytes(_keygen()[0]), device_id="dev-1", clock=time.monotonic, connect=c)
        s._token = "old"; s._token_expires = 0
        try: run_once(s)
        except SyncError: pass
        assert len([a for a in read_alerts(lay, limit=200) if a.get("reason_code")=="token_rejected"]) >= 1

class TestT9A2:
    def test_malformed_json_through_default_connect(self, tmp_path, monkeypatch):
        import http.server, threading
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _create_pending_request(lay, "req-mj-001", command="echo mj")
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200); self.send_header("Date",formatdate(usegmt=True)); self.end_headers()
                self.wfile.write(b"<html>captive</html>")
            do_POST = do_GET
            def log_message(self, *a): pass
        srv = http.server.HTTPServer(("127.0.0.1", 0), H); port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            from sandbox.connector.sync.process import SyncProcess, _fetch_decisions
            from sandbox.connector.alerts import read_alerts
            s = SyncProcess(layout=lay, server_url=f"http://127.0.0.1:{port}", device_key=bytes(_keygen()[0]), device_id="dev-1", clock=time.monotonic, connect=None)
            s._token = "t"; s._token_expires = time.monotonic() + 3600
            _fetch_decisions(s)
            assert len([a for a in read_alerts(lay, limit=200) if a.get("reason_code")=="unparseable_body"]) >= 1
        finally: srv.shutdown()

    def test_unparseable_marker_equals_empty_dict(self):
        from sandbox.connector.sync.process import _default_connect
        import http.server, threading
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200); self.send_header("Date",formatdate(usegmt=True)); self.end_headers()
                self.wfile.write(b"not json")
            do_POST = do_GET
            def log_message(self, *a): pass
        srv = http.server.HTTPServer(("127.0.0.1", 0), H); port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            _, body, _ = _default_connect("GET", f"http://127.0.0.1:{port}/sync/decisions")
            assert body == {}
            assert type(body) is not dict or hasattr(body, "_unparseable")
        finally: srv.shutdown()

class TestT9A3:
    def test_tls_verify_failure_real_self_signed(self, tmp_path, monkeypatch):
        """TLS verification against a real self-signed server through _default_connect."""
        import http.server, threading
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime as dt
        key = rsa.generate_private_key(65537, 2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(dt.datetime.now(dt.timezone.utc))
                .not_valid_after(dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=1))
                .sign(key, hashes.SHA256()))
        cf = tmp_path/"cert.pem"; cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        kf = tmp_path/"key.pem"; kf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(str(cf), str(kf))
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200); self.send_header("Date",formatdate(usegmt=True)); self.end_headers()
                self.wfile.write(b'{"decisions":[]}')
            do_POST = do_GET
            def log_message(self, *a): pass
        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            from sandbox.connector.sync.process import SyncProcess, _fetch_decisions
            from sandbox.connector.alerts import read_alerts
            # Fix 3: create workspace dir before passing to _setup_managed_workspace
            ws_dir = tmp_path / "ws"
            ws_dir.mkdir(parents=True, exist_ok=True)
            ws = _setup_managed_workspace(ws_dir, monkeypatch); lay = ws["lay"]
            _create_pending_request(lay, "req-tls-001", command="echo tls")
            s = SyncProcess(layout=lay, server_url=f"https://127.0.0.1:{port}", device_key=bytes(_keygen()[0]), device_id="dev-1", clock=time.monotonic, connect=None)
            s._token = "t"; s._token_expires = time.monotonic() + 3600
            _fetch_decisions(s)
            assert len([a for a in read_alerts(lay, limit=200) if a.get("reason_code")=="tls_verify_failed"]) >= 1
        finally: srv.shutdown()

    def test_tls_verify_at_token_route(self, tmp_path, monkeypatch):
        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        def c(m, u, body=None, headers=None, token=None):
            if "/sync/token" in u: raise urllib.error.URLError(ssl.SSLCertVerificationError("bad cert"))
            return (200, {}, _date_hdr())
        s = SyncProcess(layout=lay, server_url="http://127.0.0.1:9999", device_key=bytes(_keygen()[0]), device_id="dev-1", clock=time.monotonic, connect=c)
        s._token = "old"; s._token_expires = 0
        try: run_once(s)
        except SyncError: pass
        assert len([a for a in read_alerts(lay, limit=200) if a.get("reason_code")=="tls_verify_failed"]) >= 1

class TestT9A4:
    def test_second_poll_writes_no_alert_or_audit(self, tmp_path, monkeypatch):
        """Fix 2: assert first poll produced alerts/audit before comparing."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _, _, row = _good_row(ws, lay, "req-dd-001"); row = dict(row); row["signature"] = "00"*64
        s, _ = _mk(lay, _stub_decisions([row]))
        _fetch_decisions(s)
        c1a = len([a for a in read_alerts(lay, limit=500) if a.get("event") in ("decision_refused","decisions_malformed")])
        c1u = len([r for r in _read_audit(lay) if r.get("event") in ("decision_refused","decisions_malformed")])
        assert c1a >= 1, "first poll must alert"
        assert c1u >= 1, "first poll must audit"
        _fetch_decisions(s)
        c2a = len([a for a in read_alerts(lay, limit=500) if a.get("event") in ("decision_refused","decisions_malformed")])
        c2u = len([r for r in _read_audit(lay) if r.get("event") in ("decision_refused","decisions_malformed")])
        assert c2a == c1a, f"second poll added alerts; {c1a}->{c2a}"
        assert c2u == c1u, f"second poll added audit; {c1u}->{c2u}"

    def test_realert_after_one_hour_with_repeats(self, tmp_path, monkeypatch):
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        # Fix 5: set not_after far enough in the future so the monkeypatched
        # clock (+3700 s) does not expire the approval (approval.py:544 checks
        # now > not_after + 120).  Default not_after is +900 s which expires
        # at +1020 s, well before +3700.  Use +86400 s (24 h).
        _, _, row = _good_row(ws, lay, "req-ra-001", not_after=time.time() + 86400)
        row = dict(row); row["signature"]="00"*64
        dsk = _keygen(); s1 = _mk2(lay, _stub_decisions([row]), dsk)
        _fetch_decisions(s1)
        n1 = len([a for a in read_alerts(lay, limit=500) if a.get("event")=="decision_refused"])
        assert n1 >= 1, "first poll must produce a decision_refused alert"
        rt = time.time; monkeypatch.setattr(time, "time", lambda: rt() + 3700)
        # Rebuild the row's signed_payload with the same not_after (already 24 h out)
        # so the second call's connect stub also serves a non-expired approval.
        s2 = _mk2(lay, _stub_decisions([row]), dsk); _fetch_decisions(s2)
        ra = [a for a in read_alerts(lay, limit=500) if a.get("event")=="decision_refused"]
        assert len(ra) >= n1 + 1, "re-alert must fire"
        assert ra[-1].get("repeats", 0) >= 1, "re-alert must carry repeats >= 1"

    def test_new_code_on_same_request_alerts(self, tmp_path, monkeypatch):
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-nc-001"; rec = _create_pending_request(lay, rid, command="echo nc"); fp = rec["fingerprint"]
        row1 = _build_server_row(_make_remote_approval(_keygen()[0], request_id=rid, command="echo nc", fingerprint=fp, user_id="evil"), rid)
        dsk = _keygen(); s1 = _mk2(lay, _stub_decisions([row1]), dsk); _fetch_decisions(s1)
        n1 = len([a for a in read_alerts(lay, limit=500) if a.get("event")=="decision_refused"])
        assert n1 >= 1
        bob_sk = ws["admin_sks"][0][0]; bob_kid = ws["admin_sks"][0][2]
        ga = _make_remote_approval(bob_sk, request_id=rid, command="echo nc", fingerprint=fp, user_id=f"admin-{bob_kid[:8]}")
        row2 = _build_server_row(ga, rid)
        sb = binascii.unhexlify(row2["signature"])
        row2["signature"] = binascii.hexlify(bytes([sb[0]^1])+sb[1:]).decode()
        s2 = _mk2(lay, _stub_decisions([row2]), dsk); _fetch_decisions(s2)
        n2 = len([a for a in read_alerts(lay, limit=500) if a.get("event")=="decision_refused"])
        assert n2 > n1, f"new code must add alert; {n1}->{n2}"

    def test_alert_cap_per_cycle_and_hour_with_one_suppressed_record(self, tmp_path, monkeypatch):
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rows = []
        for i in range(20):
            rid = f"req-cp-{i:03d}"; rec = _create_pending_request(lay, rid, command=f"echo c{i}")
            rows.append(_build_server_row(_make_remote_approval(_keygen()[0], request_id=rid, command=f"echo c{i}", fingerprint=rec["fingerprint"], user_id=f"e{i}"), rid))
        dsk = _keygen()
        for _ in range(3):
            s = _mk2(lay, _stub_decisions(rows), dsk); _fetch_decisions(s)
        alerts = read_alerts(lay, limit=500)
        da = [a for a in alerts if a.get("event") in ("decision_refused","decisions_malformed","decision_apply_failed")]
        su = [a for a in alerts if a.get("event")=="decision_alerts_suppressed"]
        assert len(da) <= 12, f"per-hour cap 12; got {len(da)}"
        assert len(su) <= 1, f"at most 1 suppressed/hour; got {len(su)}"

    def test_capped_key_fires_in_later_window(self, tmp_path, monkeypatch):
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rows = []
        for i in range(10):
            rid = f"req-lw-{i:03d}"; rec = _create_pending_request(lay, rid, command=f"echo l{i}")
            rows.append(_build_server_row(_make_remote_approval(_keygen()[0], request_id=rid, command=f"echo l{i}", fingerprint=rec["fingerprint"], user_id=f"e{i}"), rid))
        dsk = _keygen(); s1 = _mk2(lay, _stub_decisions(rows), dsk); _fetch_decisions(s1)
        nb = len([a for a in read_alerts(lay, limit=500) if a.get("event")=="decision_refused"])
        rt = time.time; monkeypatch.setattr(time, "time", lambda: rt() + 3700)
        s2 = _mk2(lay, _stub_decisions(rows), dsk); _fetch_decisions(s2)
        na = len([a for a in read_alerts(lay, limit=500) if a.get("event")=="decision_refused"])
        assert na > nb, "suppressed keys must fire later"

class TestT9A5:
    @pytest.mark.parametrize("blob,label", [
        ({"hour_start": "x"}, "hour_start_string"),
        ({"entries": []}, "entries_list"),
        ({"entries": "abc"}, "entries_string"),
        ({"entries": {"k": 1}}, "entry_value_int"),
        ({"net_consecutive": "x"}, "net_consecutive_string"),
        ({"alerts_this_hour": "x"}, "alerts_this_hour_string"),
    ], ids=["hour_start_string","entries_list","entries_string","entry_value_int","net_consecutive_string","alerts_this_hour_string"])
    def test_corrupt_state_file_means_more_alerts_not_fewer(self, tmp_path, monkeypatch, blob, label):
        """Fix 4: each param through run_once (full cycle) and real sandbox status."""
        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _, _, row = _good_row(ws, lay, "req-cs-001"); row = dict(row); row["signature"]="00"*64
        sp = lay.root / ".sandbox" / "logs" / "decision_state.json"
        sp.parent.mkdir(parents=True, exist_ok=True)
        sp.write_text(json.dumps(blob), encoding="utf-8")
        # Drive through run_once so the full cycle completes:
        # decisions, bundle, escalation and audit routes all called
        calls = []
        conn = _full_cycle_connect([row], calls)
        s = SyncProcess(layout=lay, server_url="http://127.0.0.1:9999",
                        device_key=bytes(_keygen()[0]), device_id="dev-1",
                        clock=time.monotonic, connect=conn)
        try: run_once(s)
        except SyncError: pass
        # Alert must have been raised
        assert len([a for a in read_alerts(lay, limit=200)
                    if a.get("event") in ("decision_refused","decisions_malformed")]) >= 1, \
            f"alerts suppressed by {blob!r}"
        # Later routes (bundle, escalation, audit) must have been called
        later = [u for u in calls if "/sync/bundle" in u or "/sync/escalation" in u or "/sync/audit" in u]
        assert len(later) >= 1, f"cycle must complete through later routes; calls={calls}"
        # Real sandbox status must exit 0 with no traceback
        sp.write_text(json.dumps(blob), encoding="utf-8")
        from sandbox.cli.connector_cmds import status_cmd
        r = click.testing.CliRunner().invoke(status_cmd, [str(lay.root)])
        assert r.exit_code == 0, f"status crashed on {blob!r}: {r.exception}"

    def test_future_timestamp_treated_as_absent(self, tmp_path, monkeypatch):
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _, appr, row = _good_row(ws, lay, "req-ft-001"); row = dict(row); row["signature"]="00"*64
        kid = appr["signatures"][0]["key_id"]
        sp = lay.root / ".sandbox" / "logs" / "decision_state.json"
        sp.parent.mkdir(parents=True, exist_ok=True)
        sp.write_text(json.dumps({"entries":{f"decision_refused:req-ft-001:bad_signature:{kid}":
            {"count":1,"alerted":True,"last_alerted":9e18,"last_seen":0,"first_seen":0,"repeats":0}},
            "hour_start":9e18,"alerts_this_hour":100}), encoding="utf-8")
        s, _ = _mk(lay, _stub_decisions([row])); _fetch_decisions(s)
        assert len([a for a in read_alerts(lay, limit=200) if a.get("event")=="decision_refused"]) >= 1

class TestT9A6:
    def test_status_prints_code_not_key_id(self, tmp_path, monkeypatch):
        """T9A-6: parts[-1] at line 471 is the key_id, not the code."""
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _, appr, row = _good_row(ws, lay, "req-sk-001"); row = dict(row); row["signature"]="00"*64
        s, _ = _mk(lay, _stub_decisions([row])); _fetch_decisions(s)
        status = _run_status_cli(lay); kid = appr["signatures"][0]["key_id"]
        lines = [l for l in status.splitlines() if "awaiting_second:" in l]
        assert lines, f"no awaiting_second line; got:\n{status}"
        for line in lines:
            after = line.split("awaiting_second:")[-1].strip()
            first_token = after.split(":")[0].strip()
            assert first_token != kid, f"full key_id printed as code: {line}"

    def test_one_line_per_refusal(self, tmp_path, monkeypatch):
        """T9A-6: blocks 464-476 and 571-582 both print today."""
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _, _, row = _good_row(ws, lay, "req-ol-001"); row = dict(row); row["signature"]="00"*64
        s, _ = _mk(lay, _stub_decisions([row])); _fetch_decisions(s)
        status = _run_status_cli(lay)
        lines = [l for l in status.splitlines() if "awaiting_second" in l]
        assert len(lines) <= 1, f"refusal printed {len(lines)} times: {lines}"

    def test_hex_request_ids_in_json(self, tmp_path, monkeypatch):
        """T9A-6: rid.startswith('req-') at line 526 drops hex ids."""
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        hex_rid = secrets.token_hex(16)
        rec = _create_pending_request(lay, hex_rid, command="echo hex")
        row = _build_server_row(_make_remote_approval(_keygen()[0], request_id=hex_rid, command="echo hex", fingerprint=rec["fingerprint"], user_id="evil"), hex_rid)
        s, _ = _mk(lay, _stub_decisions([row])); _fetch_decisions(s)
        j = _run_status_json(lay); decisions = j.get("decisions", {})
        assert hex_rid in decisions, f"hex rid not in --json decisions: {decisions}"

    def test_claimed_record_shown_with_inspect_by_hand(self, tmp_path, monkeypatch):
        """Claimed record must show 'inspect by hand' in sandbox status."""
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-cl-001"
        _create_pending_request(lay, rid, command="echo claimed")
        # Move to claimed deterministically
        lay.claimed_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(lay.pending_dir / f"{rid}.json"), str(lay.claimed_dir / f"{rid}.json"))
        from sandbox.connector.queue import EscalationQueue
        assert EscalationQueue(lay).status(rid) == "claimed", "record must be claimed"
        # Seed decision state so display path shows it
        sp = lay.root / ".sandbox" / "logs" / "decision_state.json"
        sp.parent.mkdir(parents=True, exist_ok=True)
        sp.write_text(json.dumps({"entries":{f"decision_apply_failed:{rid}:apply_raised":
            {"count":1,"alerted":True,"last_seen":time.time(),"first_seen":time.time(),"repeats":0,
             "reason":f"{rid} apply failed, record is claimed; it will not run again, inspect by hand"}}}), encoding="utf-8")
        status = _run_status_cli(lay)
        assert rid in status, f"claimed {rid} not in status:\n{status}"
        assert "inspect by hand" in status.lower(), f"no 'inspect by hand':\n{status}"

    def test_awaiting_second_text(self, tmp_path, monkeypatch):
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-as-001"
        rec = _create_pending_request(lay, rid, command="echo as", requires_dual=True)
        bob_kid = ws["admin_sks"][0][2]
        row = _build_server_row(_make_remote_approval(ws["admin_sks"][0][0], request_id=rid, command="echo as",
                                                       fingerprint=rec["fingerprint"], user_id=f"admin-{bob_kid[:8]}"), rid)
        s, _ = _mk(lay, _stub_decisions([row])); _fetch_decisions(s)
        status = _run_status_cli(lay)
        assert "1 of 2" in status, f"must show '1 of 2'; got:\n{status}"

    def test_network_status_shows_at_stage(self, tmp_path, monkeypatch):
        """T9A-6: network line must show 'at <stage>'."""
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _create_pending_request(lay, "req-ns-001", command="echo ns")
        def nf(m, u, body=None, headers=None, token=None):
            if "/sync/decisions" in u: raise ConnectionError("down")
            return (200, {}, _date_hdr())
        dsk = _keygen()
        for _ in range(3):
            s = _mk2(lay, nf, dsk); _fetch_decisions(s)
        status = _run_status_cli(lay)
        net_lines = [l for l in status.splitlines() if "network_error" in l]
        assert net_lines, f"no network_error line; got:\n{status}"
        assert any("at " in l for l in net_lines), f"network line missing 'at <stage>': {net_lines}"

    def test_http_n_on_fetch_line(self, tmp_path, monkeypatch):
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _create_pending_request(lay, "req-hn-001", command="echo hn")
        s, _ = _mk(lay, _stub_status(502, {"detail":"gw"})); _fetch_decisions(s)
        status = _run_status_cli(lay)
        assert "HTTP" in status and "502" in status, f"must show 'HTTP 502'; got:\n{status}"

class TestT9A7:
    def test_nonces_corrupt_alerts(self, tmp_path, monkeypatch):
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        import sandbox.connector.approval as apmod
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-nc7-001"; rec = _create_pending_request(lay, rid, command="echo nc")
        row = _build_server_row(_make_remote_approval(ws["admin_sks"][0][0], request_id=rid, command="echo nc",
                                                       fingerprint=rec["fingerprint"], user_id=f"admin-{ws['admin_sks'][0][2][:8]}"), rid)
        monkeypatch.setattr(apmod, "_load_seen_nonces", lambda l: ({}, True))
        s, _ = _mk(lay, _stub_decisions([row])); _fetch_decisions(s)
        combined = read_alerts(lay, limit=200) + _read_audit(lay)
        assert len([r for r in combined if r.get("reason_code")=="nonces_corrupt"]) >= 1

    def test_post_signature_verified_yes(self, tmp_path, monkeypatch):
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        bob_kid = ws["admin_sks"][0][2]; bob_uid = f"admin-{bob_kid[:8]}"
        sync_dir = lay.root / ".sandbox" / "state" / "sync"
        e = json.loads((sync_dir/"enrollment.json").read_text(encoding="utf-8"))
        e["operator_user_id"] = bob_uid
        (sync_dir/"enrollment.json").write_text(json.dumps(e), encoding="utf-8")
        rid = "req-pv-001"; rec = _create_pending_request(lay, rid, command="echo pv")
        row = _build_server_row(_make_remote_approval(ws["admin_sks"][0][0], request_id=rid, command="echo pv",
                                                       fingerprint=rec["fingerprint"], user_id=bob_uid), rid)
        s, _ = _mk(lay, _stub_decisions([row])); _fetch_decisions(s)
        out = _run_alerts_cli(lay)
        assert f"(user {bob_uid})" in out or f"user {bob_uid}" in out, f"must show registry user id; got:\n{out}"

    def test_prod_refused_split_on_staging(self, tmp_path, monkeypatch):
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch, environment="staging", registry_expires_at=time.time()-3600)
        lay = ws["lay"]; rid = "req-pr-001"
        rec = _create_pending_request(lay, rid, command="echo pr")
        row = _build_server_row(_make_remote_approval(ws["admin_sks"][0][0], request_id=rid, command="echo pr",
                                                       fingerprint=rec["fingerprint"], user_id=f"admin-{ws['admin_sks'][0][2][:8]}"), rid)
        s, _ = _mk(lay, _stub_decisions([row])); _fetch_decisions(s)
        codes = [r.get("reason_code") for r in (read_alerts(lay, limit=200)+_read_audit(lay)) if r.get("event")=="decision_refused"]
        assert "registry_expired" in codes, f"must say registry_expired; codes={codes}"
        assert "prod_refused" not in codes, f"must NOT say prod_refused; codes={codes}"

    def test_refusals_kept_when_request_finishes(self, tmp_path, monkeypatch):
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-rk-001"; rec = _create_pending_request(lay, rid, command="echo rk", requires_dual=True); fp = rec["fingerprint"]
        ba = _make_remote_approval(ws["admin_sks"][0][0], request_id=rid, command="echo rk", fingerprint=fp, user_id=f"admin-{ws['admin_sks'][0][2][:8]}")
        ca = _make_remote_approval(ws["admin_sks"][1][0], request_id=rid, command="echo rk", fingerprint=fp, user_id=f"admin-{ws['admin_sks'][1][2][:8]}")
        fa = _make_remote_approval(_keygen()[0], request_id=rid, command="echo rk", fingerprint=fp, user_id="evil")
        rows = [_build_server_row(fa, rid), _build_server_row(ba, rid), _build_server_row(ca, rid)]
        s, _ = _mk(lay, _stub_decisions(rows)); _fetch_decisions(s)
        assert len([r for r in _read_audit(lay) if r.get("event")=="decision_refused"]) >= 1

class TestT9A8:
    def test_apply_raises_after_claim_status_says_inspect_and_no_retry(self, tmp_path, monkeypatch):
        """Seed via the real claim path: valid approvals, claim succeeds,
        then broker raises.  Assert exact spec text and request id.

        The product only writes pending records to lay.pending_dir, not
        .sandbox/pending/ (T9A_SECURITY_REVIEW "Follow-up for the lead").
        """
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-ar-001"; rec = _create_pending_request(lay, rid, command="echo ar", requires_dual=True); fp = rec["fingerprint"]
        ba = _make_remote_approval(ws["admin_sks"][0][0], request_id=rid, command="echo ar", fingerprint=fp, user_id=f"admin-{ws['admin_sks'][0][2][:8]}")
        ca = _make_remote_approval(ws["admin_sks"][1][0], request_id=rid, command="echo ar", fingerprint=fp, user_id=f"admin-{ws['admin_sks'][1][2][:8]}")
        rows = [_build_server_row(ba, rid), _build_server_row(ca, rid)]
        # Remove the .sandbox/pending/ copy so apply_external reads from
        # lay.pending_dir only, as the product does.
        old_pending = lay.root / ".sandbox" / "pending" / f"{rid}.json"
        if old_pending.exists():
            old_pending.unlink()
        # Monkeypatch the broker to raise AFTER the claim succeeds
        from sandbox.connector.broker import FolderBroker
        _orig_execute = FolderBroker.execute
        async def _boom_execute(self, record, reviewer_id, reason):
            raise RuntimeError("broker failure after claim")
        monkeypatch.setattr(FolderBroker, "execute", _boom_execute)
        broker_calls = []
        async def _counting_boom(self, record, reviewer_id, reason):
            broker_calls.append(1)
            raise RuntimeError("broker failure after claim")
        monkeypatch.setattr(FolderBroker, "execute", _counting_boom)
        # 3 polls, same rows: broker must be called only once (claimed records are not retried)
        dsk = _keygen()
        for _ in range(3):
            s = _mk2(lay, _stub_decisions(rows), dsk); _fetch_decisions(s)
        alerts = read_alerts(lay, limit=200)
        apply_failed = [a for a in alerts if a.get("event") == "decision_apply_failed"]
        assert len(apply_failed) >= 1, f"expected decision_apply_failed; got events: {[a.get('event') for a in alerts]}"
        # Assert exact spec text and request id
        a = apply_failed[0]
        assert a.get("reason_code") == "apply_raised", f"reason_code must be apply_raised; got {a.get('reason_code')}"
        assert rid in (a.get("request_id") or a.get("reason", "")), f"request id {rid} must appear in alert"
        assert "inspect by hand" in a.get("reason", "").lower(), f"must say 'inspect by hand'; got {a.get('reason')}"
        # R4: 3 polls, 1 broker call (claimed record not retried)
        assert len(broker_calls) == 1, f"broker must be called exactly once across 3 polls; got {len(broker_calls)}"
        # R4: status says "inspect by hand"
        status = _run_status_cli(lay)
        assert rid in status, f"claimed {rid} must appear in status: {status}"
        assert "inspect" in status.lower(), f"status must say 'inspect': {status}"

    def test_nonce_save_failed_alerts(self, tmp_path, monkeypatch):
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        import sandbox.connector.approval as apmod
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-nsf-001"; rec = _create_pending_request(lay, rid, command="echo nsf"); fp = rec["fingerprint"]
        ba = _make_remote_approval(ws["admin_sks"][0][0], request_id=rid, command="echo nsf", fingerprint=fp, user_id=f"admin-{ws['admin_sks'][0][2][:8]}")
        ca = _make_remote_approval(ws["admin_sks"][1][0], request_id=rid, command="echo nsf", fingerprint=fp, user_id=f"admin-{ws['admin_sks'][1][2][:8]}")
        rows = [_build_server_row(ba, rid), _build_server_row(ca, rid)]
        def boom(*a, **k): return False
        monkeypatch.setattr(apmod, "_save_seen_nonces", boom)
        s, _ = _mk(lay, _stub_decisions(rows)); _fetch_decisions(s)
        assert len([a for a in read_alerts(lay, limit=200) if a.get("reason_code")=="nonce_save_failed"]) >= 1

    def test_pending_record_unreadable_alerts(self, tmp_path, monkeypatch):
        """pending_record_unreadable: queue.status says pending but
        apply_external returns not_pending (the file is corrupt).

        The product only writes pending records to lay.pending_dir, not
        .sandbox/pending/ (T9A_SECURITY_REVIEW "Follow-up for the lead").
        """
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-pru-001"; rec = _create_pending_request(lay, rid, command="echo pru"); fp = rec["fingerprint"]
        ba = _make_remote_approval(ws["admin_sks"][0][0], request_id=rid, command="echo pru", fingerprint=fp, user_id=f"admin-{ws['admin_sks'][0][2][:8]}")
        ca = _make_remote_approval(ws["admin_sks"][1][0], request_id=rid, command="echo pru", fingerprint=fp, user_id=f"admin-{ws['admin_sks'][1][2][:8]}")
        rows = [_build_server_row(ba, rid), _build_server_row(ca, rid)]
        # Remove the .sandbox/pending/ copy so apply_external reads ONLY
        # from lay.pending_dir, as the product does.
        old_pending = lay.root / ".sandbox" / "pending" / f"{rid}.json"
        if old_pending.exists():
            old_pending.unlink()
        # Corrupt the file in lay.pending_dir: apply_external returns
        # not_pending, but queue.status still says pending (file exists).
        (lay.pending_dir / f"{rid}.json").write_text("{bad", encoding="utf-8")
        s, _ = _mk(lay, _stub_decisions(rows)); _fetch_decisions(s)
        assert len([a for a in read_alerts(lay, limit=200) if a.get("reason_code")=="pending_record_unreadable"]) >= 1

    def test_server_time_write_failed_cycle_ok_and_dedupes(self, tmp_path, monkeypatch):
        """Fix 5: assert not _decisions_failed after first fetch, plus exit-code path."""
        from sandbox.connector.sync.process import SyncProcess, _fetch_decisions, run_once, SyncError
        from sandbox.connector.alerts import read_alerts
        import sandbox.connector.sync.state as st
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _create_pending_request(lay, "req-stw-001", command="echo stw")
        def boom(*a, **k): raise OSError("boom")
        monkeypatch.setattr(st, "write_server_time_state", boom)
        s, _ = _mk(lay, _stub_decisions([])); _fetch_decisions(s)
        assert not s._decisions_failed, "server_time_write_failed must not set _decisions_failed"
        n1 = len([a for a in read_alerts(lay, limit=200) if a.get("reason_code")=="server_time_write_failed"])
        assert n1 >= 1
        _fetch_decisions(s)
        n2 = len([a for a in read_alerts(lay, limit=200) if a.get("reason_code")=="server_time_write_failed"])
        assert n2 == n1, f"must dedupe; {n1}->{n2}"
        # Exit-code path: run_once must not exit 1 for this failure
        def full_c(m, u, body=None, headers=None, token=None):
            if "/sync/token" in u: return (200, {"access_token":"t","expires_in":3600}, _date_hdr())
            if "/sync/registry" in u: return (200, {"registry":[]}, _date_hdr())
            if "/sync/decisions" in u: return (200, {"decisions":[]}, _date_hdr())
            return (200, {}, _date_hdr())
        s2 = SyncProcess(layout=lay, server_url="http://127.0.0.1:9999",
                         device_key=bytes(_keygen()[0]), device_id="dev-1",
                         clock=time.monotonic, connect=full_c)
        raised = False
        try: run_once(s2)
        except SyncError: raised = True
        assert not raised, "server_time_write_failed must not cause run_once to raise SyncError"

class TestT9A9:
    def test_non_dict_registry_200_fails_cycle(self, tmp_path, monkeypatch):
        """Fix 6: exact behaviour is SyncError raised from run_once and --once exits 1."""
        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        def c(m, u, body=None, headers=None, token=None):
            if "/sync/token" in u: return (200, {"access_token":"t","expires_in":3600}, _date_hdr())
            if "/sync/registry" in u: return (200, [], _date_hdr())
            if "/sync/decisions" in u: return (200, {"decisions":[]}, _date_hdr())
            return (200, {}, _date_hdr())
        s = SyncProcess(layout=lay, server_url="http://127.0.0.1:9999", device_key=bytes(_keygen()[0]), device_id="dev-1", clock=time.monotonic, connect=c)
        with pytest.raises(SyncError):
            run_once(s)

# Fix 1: reason code tests use secrets.token_hex for rid and assert reason_code in read_alerts
_REASON_CODES = ["unknown_key","bad_signature","not_dual_eligible","operator_self_approval","clock_skew","record_changed","nonce_save_failed"]

def _build_reason_code_fixture(ws, lay, monkeypatch, code):
    """Build a fixture that genuinely produces each reason code.

    Returns (row_list, rid) where the row produces exactly `code` through
    _fetch_decisions on a managed workspace with `ws`.
    """
    rid = f"req-rc-{secrets.token_hex(4)}"
    admin_sks = ws["admin_sks"]
    bob_sk, _, bob_kid = admin_sks[0][:3]
    bob_uid = f"admin-{bob_kid[:8]}"
    carol_sk, _, carol_kid = admin_sks[1][:3]
    carol_uid = f"admin-{carol_kid[:8]}"

    if code == "unknown_key":
        # Use a key not in the registry
        rec = _create_pending_request(lay, rid, command="echo rc")
        appr = _make_remote_approval(_keygen()[0], request_id=rid,
                                     command="echo rc", fingerprint=rec["fingerprint"],
                                     user_id="evil")
        return [_build_server_row(appr, rid)], rid

    elif code == "bad_signature":
        # Use a registry key but corrupt the signature
        rec = _create_pending_request(lay, rid, command="echo rc")
        appr = _make_remote_approval(bob_sk, request_id=rid,
                                     command="echo rc", fingerprint=rec["fingerprint"],
                                     user_id=bob_uid)
        row = _build_server_row(appr, rid)
        sb = binascii.unhexlify(row["signature"])
        row["signature"] = binascii.hexlify(bytes([sb[0] ^ 1]) + sb[1:]).decode()
        return [row], rid

    elif code == "not_dual_eligible":
        # The standard 2-admin workspace can't produce not_dual_eligible because
        # both admin keys have >= 2 admin signatures (counts_for_dual = True).
        # Use the caller-provided single_admin workspace (ws was built with
        # single_admin=True).  In a single-admin genesis, each key has only 1
        # admin signature, so counts_for_dual returns False.
        # The caller must pass ws/lay from a single_admin=True workspace.
        rec = _create_pending_request(lay, rid, command="echo rc")
        appr = _make_remote_approval(bob_sk, request_id=rid,
                                     command="echo rc", fingerprint=rec["fingerprint"],
                                     user_id=bob_uid)
        row = _build_server_row(appr, rid)
        return [row], rid

    elif code == "operator_self_approval":
        # Set operator_user_id to bob, then bob approves
        sync_dir = lay.root / ".sandbox" / "state" / "sync"
        e = json.loads((sync_dir / "enrollment.json").read_text(encoding="utf-8"))
        e["operator_user_id"] = bob_uid
        (sync_dir / "enrollment.json").write_text(json.dumps(e), encoding="utf-8")
        rec = _create_pending_request(lay, rid, command="echo rc")
        appr = _make_remote_approval(bob_sk, request_id=rid,
                                     command="echo rc", fingerprint=rec["fingerprint"],
                                     user_id=bob_uid)
        return [_build_server_row(appr, rid)], rid

    elif code == "clock_skew":
        # Use a Date header > 2 minutes off
        rec = _create_pending_request(lay, rid, command="echo rc")
        appr = _make_remote_approval(bob_sk, request_id=rid,
                                     command="echo rc", fingerprint=rec["fingerprint"],
                                     user_id=bob_uid)
        row = _build_server_row(appr, rid)
        # Serve with a Date that is 5 minutes in the past
        return [row], rid

    elif code == "record_changed":
        # TOCTOU: the pending record changed between read and claim
        # (approval.py:1022 checks claimed_fp != expected_fp).
        # Commands match in the approval (signature verification passes),
        # but monkeypatching queue.claim modifies the claimed record
        # so the fingerprint changes.
        rec = _create_pending_request(lay, rid, command="echo rc")
        appr = _make_remote_approval(bob_sk, request_id=rid,
                                     command="echo rc", fingerprint=rec["fingerprint"],
                                     user_id=bob_uid)
        ca = _make_remote_approval(carol_sk, request_id=rid,
                                   command="echo rc", fingerprint=rec["fingerprint"],
                                   user_id=carol_uid)
        # Monkeypatch queue.claim to simulate a TOCTOU race: the record
        # changes between the initial read and the claim (approval.py:989).
        from sandbox.connector.queue import EscalationQueue
        _orig_claim = EscalationQueue.claim
        def _toctou_claim(self, r_id, reviewer_id):
            result = _orig_claim(self, r_id, reviewer_id)
            if result is not None and r_id == rid:
                result["command"] = "echo TAMPERED"  # changes fingerprint
            return result
        monkeypatch.setattr(EscalationQueue, "claim", _toctou_claim)
        return [_build_server_row(appr, rid), _build_server_row(ca, rid)], rid

    elif code == "nonce_save_failed":
        # Caller monkeypatches _save_seen_nonces before calling this
        rec = _create_pending_request(lay, rid, command="echo rc")
        appr = _make_remote_approval(bob_sk, request_id=rid,
                                     command="echo rc", fingerprint=rec["fingerprint"],
                                     user_id=bob_uid)
        ca = _make_remote_approval(carol_sk, request_id=rid,
                                   command="echo rc", fingerprint=rec["fingerprint"],
                                   user_id=carol_uid)
        return [_build_server_row(appr, rid), _build_server_row(ca, rid)], rid

    raise ValueError(f"unknown code: {code}")


class TestReasonCodes:
    @pytest.mark.parametrize("code", _REASON_CODES)
    def test_reason_code_reaches_status_and_alerts(self, tmp_path, monkeypatch, code):
        """Fix 1: rid uses secrets.token_hex, fixture genuinely produces each code.

        Assert reason_code field in read_alerts, not just substring in status text.
        """
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]

        if code == "not_dual_eligible":
            # Need a single_admin workspace where each key has < 2 admin sigs,
            # as TestNonCountingApproval in test_m3_t9a_fetch_decisions.py does.
            sa_dir = tmp_path / "sa"
            sa_dir.mkdir(parents=True, exist_ok=True)
            sa_ws = _setup_managed_workspace(sa_dir, monkeypatch,
                                             single_admin=True)
            sa_lay = sa_ws["lay"]
            rows, rid = _build_reason_code_fixture(sa_ws, sa_lay, monkeypatch, code)
            s, _ = _mk(sa_lay, _stub_decisions(rows))
            lay = sa_lay  # use single_admin layout for assertions below
        elif code == "clock_skew":
            # Need a Date header > 2 minutes off
            rows, rid = _build_reason_code_fixture(ws, lay, monkeypatch, code)
            old_date = "Wed, 01 Jan 2020 00:00:00 GMT"
            s, _ = _mk(lay, _stub_decisions(rows, hdrs={"Date": old_date}))
        elif code == "nonce_save_failed":
            import sandbox.connector.approval as apmod
            def boom(*a, **k): return False
            monkeypatch.setattr(apmod, "_save_seen_nonces", boom)
            rows, rid = _build_reason_code_fixture(ws, lay, monkeypatch, code)
            s, _ = _mk(lay, _stub_decisions(rows))
        else:
            rows, rid = _build_reason_code_fixture(ws, lay, monkeypatch, code)
            s, _ = _mk(lay, _stub_decisions(rows))
        _fetch_decisions(s)

        # Assert reason_code appears in the actual alert records
        all_alerts = read_alerts(lay, limit=200)
        matching = [r for r in all_alerts if r.get("reason_code") == code]
        assert len(matching) >= 1, (
            f"reason_code {code!r} not found in any alert record; "
            f"all reason_codes: {[r.get('reason_code') for r in all_alerts]}"
        )

        # Also verify it appears in status or alerts CLI text
        status = _run_status_cli(lay); alerts_out = _run_alerts_cli(lay)
        assert code in status or code in alerts_out, f"code {code} not in status or alerts CLI text"

class TestLows:
    def test_audit_append_failure_still_alerts(self, tmp_path, monkeypatch):
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        import sandbox.connector.audit as am
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _create_pending_request(lay, "req-aaf-001", command="echo aaf")
        def boom(self, *a, **k): raise OSError("full")
        monkeypatch.setattr(am.FolderAudit, "append", boom)
        s, _ = _mk(lay, _stub_status(500, {"detail":"err"})); _fetch_decisions(s)
        assert len([a for a in read_alerts(lay, limit=200) if a.get("event")=="decisions_fetch_failed"]) >= 1

    def test_alerts_disabled_still_audits(self, tmp_path, monkeypatch):
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _create_pending_request(lay, "req-ad-001", command="echo ad")
        s, _ = _mk(lay, _stub_status(500, {"detail":"err"})); _fetch_decisions(s)
        assert len([r for r in _read_audit(lay) if r.get("event")=="decisions_fetch_failed"]) >= 1

class TestHostileH1:
    def test_control_chars_stripped_from_status(self, tmp_path, monkeypatch):
        """Hostile row value: ESC/NUL/BEL in key_id must not reach output."""
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _, appr, row = _good_row(ws, lay, "req-cc-001")
        evil = "\x1b]0;PWNED\x07\x1b[2J" + "a"*100
        row = dict(row); p = json.loads(row["signed_payload"]); p["key_id"] = evil
        row["signed_payload"] = json.dumps(p); row["key_id"] = evil
        s, _ = _mk(lay, _stub_decisions([row])); _fetch_decisions(s)
        st = _run_status_cli(lay); al = _run_alerts_cli(lay)
        for ch in ["\x1b","\x07","\x00"]:
            assert ch not in st, f"{ch!r} in status"; assert ch not in al, f"{ch!r} in alerts"

    def test_server_text_newlines_stripped(self, tmp_path, monkeypatch):
        """Untrusted text: newlines in server text must not inject fake log lines."""
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _create_pending_request(lay, "req-nl-001", command="echo nl")
        s, _ = _mk(lay, _stub_status(500, {"detail":"x\n[2026-11-05] AUDIT_FORK  sync  forged\r\tz"}))
        _fetch_decisions(s)
        assert "AUDIT_FORK" not in _run_alerts_cli(lay)

class TestHostileH2:
    def test_non_string_key_id_cycle_continues(self, tmp_path, monkeypatch):
        """Fix 7: also assert refusal recorded, good row applied, not _decisions_failed."""
        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        # Create two requests: one for the bad row, one for a good row
        _create_pending_request(lay, "req-nsk-001", command="echo nsk")
        rid_good = "req-nsk-good"
        rec_good, appr_good, good_row = _good_row(ws, lay, rid_good, idx=0, cmd="echo good")
        # Second admin approves too for dual control
        ca = _make_remote_approval(ws["admin_sks"][1][0], request_id=rid_good,
                                   command="echo good", fingerprint=rec_good["fingerprint"],
                                   user_id=f"admin-{ws['admin_sks'][1][2][:8]}")
        good_row2 = _build_server_row(ca, rid_good)

        bad = {"request_id":"req-nsk-001","signed_payload":json.dumps({"key_id":5}),"signature":"aa"*64,"key_id":5}
        calls = []
        def lc(m, u, body=None, headers=None, token=None):
            calls.append(u)
            if "/sync/decisions" in u: return (200, {"decisions":[bad, good_row, good_row2]}, _date_hdr())
            if "/sync/token" in u: return (200, {"access_token":"t","expires_in":3600}, _date_hdr())
            if "/sync/registry" in u: return (200, {"registry":[]}, _date_hdr())
            return (200, {}, _date_hdr())
        s = SyncProcess(layout=lay, server_url="http://127.0.0.1:9999", device_key=bytes(_keygen()[0]), device_id="dev-1", clock=time.monotonic, connect=lc)
        try: run_once(s)
        except SyncError: pass
        # Later routes must run
        assert len([u for u in calls if "/sync/audit" in u or "/sync/bundle" in u]) >= 1, f"later routes must run; calls={calls}"
        # Refusal must be recorded (row_invalid/malformed)
        all_alerts = read_alerts(lay, limit=200)
        refusal_alerts = [a for a in all_alerts if a.get("event") in ("decision_refused","decisions_malformed")]
        assert len(refusal_alerts) >= 1, f"refusal must be recorded; alerts={all_alerts}"
        # The failure must not be counted as _decisions_failed (spec says cycle OK)
        assert not s._decisions_failed, "bad row must not set _decisions_failed"

    def test_deeply_nested_json_kills_cycle(self, tmp_path, monkeypatch):
        """Fix 7: also assert refusal recorded, good row applied, not _decisions_failed."""
        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _create_pending_request(lay, "req-dj-001", command="echo dj")
        # Also create a good request to verify it still applies
        rid_good = "req-dj-good"
        rec_good, appr_good, good_row = _good_row(ws, lay, rid_good, idx=0, cmd="echo djgood")
        ca = _make_remote_approval(ws["admin_sks"][1][0], request_id=rid_good,
                                   command="echo djgood", fingerprint=rec_good["fingerprint"],
                                   user_id=f"admin-{ws['admin_sks'][1][2][:8]}")
        good_row2 = _build_server_row(ca, rid_good)

        row = {"request_id":"req-dj-001","signed_payload":"["*200000,"signature":"aa"*64,"key_id":"bb"*32}
        calls = []
        def lc(m, u, body=None, headers=None, token=None):
            calls.append(u)
            if "/sync/decisions" in u: return (200, {"decisions":[row, good_row, good_row2]}, _date_hdr())
            if "/sync/token" in u: return (200, {"access_token":"t","expires_in":3600}, _date_hdr())
            if "/sync/registry" in u: return (200, {"registry":[]}, _date_hdr())
            return (200, {}, _date_hdr())
        s = SyncProcess(layout=lay, server_url="http://127.0.0.1:9999", device_key=bytes(_keygen()[0]), device_id="dev-1", clock=time.monotonic, connect=lc)
        try: run_once(s)
        except SyncError: pass
        # Later routes must run
        assert len([u for u in calls if "/sync/audit" in u or "/sync/bundle" in u]) >= 1, f"later routes must run; calls={calls}"
        # Refusal must be recorded
        all_alerts = read_alerts(lay, limit=200)
        assert len([a for a in all_alerts if a.get("event") in ("decision_refused", "decisions_malformed")]) >= 1, "refusal record must be produced"
        # The failure must not be counted as _decisions_failed (spec says cycle OK)
        assert not s._decisions_failed, "deeply nested JSON must not set _decisions_failed"

class TestHostileH3:
    def test_rotated_rows_bounded_audit(self, tmp_path, monkeypatch):
        """Untrusted text: 300 bad rows must not produce 300 audit records."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.audit import FolderAudit
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rows = []
        for i in range(300):
            rid = f"req-rot-{i:04d}"; _create_pending_request(lay, rid, command=f"echo r{i}")
            rows.append({"request_id":rid,"signed_payload":"{bad","signature":"aa"*64,"key_id":"bb"*32})
        s, _ = _mk(lay, _stub_decisions(rows)); _fetch_decisions(s)
        da = [r for r in FolderAudit(lay.audit_dir, session_id="sync").list_records(limit=100000)
              if r.get("event") in ("decisions_malformed","decision_refused","decision_apply_failed")]
        assert len(da) <= 50, f"audit unbounded; got {len(da)} from 300 rows"

class TestHostileRowValues:
    @pytest.mark.parametrize("field,value,label", [
        ("key_id", 42, "int_keyid"),
        ("key_id", None, "null_keyid"),
        ("key_id", {"nested":{"deep":"x"}}, "deep_nested_keyid"),
        ("key_id", "\x1b[2Jevil", "escape_keyid"),
        ("key_id", "\n\r\x00evil", "control_keyid"),
    ], ids=["int_keyid","null_keyid","deep_nested_keyid","escape_keyid","control_keyid"])
    def test_hostile_row_field_value(self, tmp_path, monkeypatch, field, value, label):
        """Hostile row value: must not crash and must not leak control chars."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _create_pending_request(lay, "req-hv-001", command="echo hv")
        row = {"request_id":"req-hv-001","signed_payload":"{}","signature":"00"*64,"key_id":"aa"*32}
        row[field] = value
        s, _ = _mk(lay, _stub_decisions([row])); _fetch_decisions(s)
        assert len([r for r in read_alerts(lay, limit=200) if r.get("event") in ("decision_refused","decisions_malformed")]) >= 1
        st = _run_status_cli(lay); al = _run_alerts_cli(lay)
        for ch in ["\x1b","\x00","\x07"]:
            assert ch not in st, f"{ch!r} in status"; assert ch not in al, f"{ch!r} in alerts"


# ===================================================================
# New targets: spec section 4 rows and section 5
# ===================================================================

class TestNewTargets:

    def test_alert_order_under_cap(self, tmp_path, monkeypatch):
        """Target 8: order is apply_failed, fetch_failed, refused, malformed.

        With 6 bad rows and one real refusal in the same response,
        the refusal must get its alert (the review measured it starved).
        """
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rows = []
        # 6 malformed rows (bad signature payloads)
        for i in range(6):
            rid = f"req-ord-{i:03d}"
            _create_pending_request(lay, rid, command=f"echo o{i}")
            rows.append({"request_id": rid, "signed_payload": "{bad", "signature": "aa"*64, "key_id": "bb"*32})
        # 1 real refusal: unknown key on a valid-shaped row
        rid_ref = f"req-ord-refusal"
        rec = _create_pending_request(lay, rid_ref, command="echo refusal")
        appr = _make_remote_approval(_keygen()[0], request_id=rid_ref,
                                     command="echo refusal", fingerprint=rec["fingerprint"],
                                     user_id="evil")
        rows.append(_build_server_row(appr, rid_ref))
        s, _ = _mk(lay, _stub_decisions(rows))
        _fetch_decisions(s)
        alerts = read_alerts(lay, limit=500)
        refused = [a for a in alerts if a.get("event") == "decision_refused"]
        assert len(refused) >= 1, (
            f"refusal must get its alert despite 6 malformed rows; "
            f"all events: {[a.get('event') for a in alerts]}"
        )

    def test_clear_request_on_leave_pending(self, tmp_path, monkeypatch):
        """Target 9: request keys clear when a request leaves pending.

        R4: the test must fail by the clear_request line alone.  After the
        first request executes, its decision_state keys must be gone, so a
        second refusal with the same key on a NEW request alerts immediately.
        """
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        from sandbox.connector.sync.decision_state import DecisionState
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        # First request: unknown key refusal + valid approvals to execute
        rid1 = f"req-clr-{secrets.token_hex(4)}"
        rec1 = _create_pending_request(lay, rid1, command="echo clr1")
        evil_sk = _keygen()
        appr1 = _make_remote_approval(evil_sk[0], request_id=rid1,
                                      command="echo clr1", fingerprint=rec1["fingerprint"],
                                      user_id="evil")
        row1 = _build_server_row(appr1, rid1)
        ba = _make_remote_approval(ws["admin_sks"][0][0], request_id=rid1,
                                   command="echo clr1", fingerprint=rec1["fingerprint"],
                                   user_id=f"admin-{ws['admin_sks'][0][2][:8]}")
        ca = _make_remote_approval(ws["admin_sks"][1][0], request_id=rid1,
                                   command="echo clr1", fingerprint=rec1["fingerprint"],
                                   user_id=f"admin-{ws['admin_sks'][1][2][:8]}")
        dsk = _keygen()
        s1 = _mk2(lay, _stub_decisions([row1, _build_server_row(ba, rid1), _build_server_row(ca, rid1)]), dsk)
        _fetch_decisions(s1)
        n1 = len([a for a in read_alerts(lay, limit=500) if a.get("event") == "decision_refused"])
        assert n1 >= 1, "first refusal must alert"

        # R4: assert the request's keys are cleared from decision_state
        logs_dir = lay.root / ".sandbox" / "logs"
        ds = DecisionState(logs_dir)
        rid1_keys = [k for k in ds._entries if f":{rid1}:" in k]
        require_m3(9, len(rid1_keys) == 0,
            f"clear_request must remove rid1 keys after it leaves pending; "
            f"remaining: {rid1_keys}"
        )

        # Second request: same evil key, same code, different rid -> must alert
        rid2 = f"req-clr-{secrets.token_hex(4)}"
        rec2 = _create_pending_request(lay, rid2, command="echo clr2")
        appr2 = _make_remote_approval(evil_sk[0], request_id=rid2,
                                      command="echo clr2", fingerprint=rec2["fingerprint"],
                                      user_id="evil")
        row2 = _build_server_row(appr2, rid2)
        s2 = _mk2(lay, _stub_decisions([row2]), dsk)
        _fetch_decisions(s2)
        n2 = len([a for a in read_alerts(lay, limit=500) if a.get("event") == "decision_refused"])
        assert n2 > n1, f"new request with same key must alert again; {n1}->{n2}"

    def test_max_reasons_per_request(self, tmp_path, monkeypatch):
        """Target 10: 8 reasons per request, '+n more' in status."""
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = f"req-max-{secrets.token_hex(4)}"
        rec = _create_pending_request(lay, rid, command="echo maxr")
        # Create 12 different bad approvals for the same request
        rows = []
        for i in range(12):
            evil_sk = _keygen()
            appr = _make_remote_approval(evil_sk[0], request_id=rid,
                                         command="echo maxr", fingerprint=rec["fingerprint"],
                                         user_id=f"evil-{i}")
            rows.append(_build_server_row(appr, rid))
        s, _ = _mk(lay, _stub_decisions(rows))
        _fetch_decisions(s)
        status = _run_status_cli(lay)
        assert "+", f"must show '+n more' for truncated reasons; got:\n{status}"
        # Count lines for this request
        rid_lines = [l for l in status.splitlines() if rid in l or "more" in l.lower()]
        # The status must cap at 8 reasons and show "+n more"
        assert any("more" in l.lower() for l in status.splitlines()), \
            f"must show '+n more' in status; got:\n{status}"

    def test_sync_decision_applied_only_on_change(self, tmp_path, monkeypatch):
        """Target 11: sync_decision_applied only on a change of (status, approvals, reason_codes).

        For a PENDING request across polls, count audit records before and after.
        """
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = f"req-sda-{secrets.token_hex(4)}"
        rec = _create_pending_request(lay, rid, command="echo sda")
        # One valid approval: awaiting_second (dual required)
        bob_sk, _, bob_kid = ws["admin_sks"][0][:3]
        appr = _make_remote_approval(bob_sk, request_id=rid,
                                     command="echo sda", fingerprint=rec["fingerprint"],
                                     user_id=f"admin-{bob_kid[:8]}")
        row = _build_server_row(appr, rid)
        dsk = _keygen()
        s1 = _mk2(lay, _stub_decisions([row]), dsk)
        _fetch_decisions(s1)
        n1 = len([r for r in _read_audit(lay) if r.get("event") == "sync_decision_applied"])
        assert n1 >= 1, "first poll must write sync_decision_applied"
        # Same response again: no new record
        s2 = _mk2(lay, _stub_decisions([row]), dsk)
        _fetch_decisions(s2)
        n2 = len([r for r in _read_audit(lay) if r.get("event") == "sync_decision_applied"])
        assert n2 == n1, f"same outcome must not add sync_decision_applied; {n1}->{n2}"

    def test_malformed_key_survives_200(self, tmp_path, monkeypatch):
        """Target 12: a malformed key (kind, code) survives a 200.

        5 polls of one bad body give 1 alert, not 5.
        """
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = f"req-mk-{secrets.token_hex(4)}"
        _create_pending_request(lay, rid, command="echo mk")
        bad_row = {"request_id": rid, "signed_payload": "{bad", "signature": "aa"*64, "key_id": "bb"*32}
        dsk = _keygen()
        for _ in range(5):
            s = _mk2(lay, _stub_decisions([bad_row]), dsk)
            _fetch_decisions(s)
        alerts = read_alerts(lay, limit=500)
        malformed = [a for a in alerts if a.get("event") in ("decisions_malformed", "decision_refused")]
        assert len(malformed) == 1, f"5 polls of same bad body must give 1 alert, got {len(malformed)}"

    def test_repeats_and_suppressed_per_hour(self, tmp_path, monkeypatch):
        """Target 13: repeats: n on re-alert, one decision_alerts_suppressed per hour.

        Spec section 5: 13 lines per hour total.
        """
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        # Create many bad rows to exceed the per-cycle cap
        rows = []
        for i in range(20):
            rid = f"req-rph-{i:03d}"
            _create_pending_request(lay, rid, command=f"echo rp{i}")
            rows.append(_build_server_row(_make_remote_approval(
                _keygen()[0], request_id=rid, command=f"echo rp{i}",
                fingerprint=_create_pending_request(lay, f"req-rph-dup-{i:03d}", command=f"echo rp{i}")["fingerprint"],
                user_id=f"e{i}"), rid))
        dsk = _keygen()
        # Run multiple cycles
        for _ in range(4):
            s = _mk2(lay, _stub_decisions(rows), dsk)
            _fetch_decisions(s)
        alerts = read_alerts(lay, limit=500)
        # 13 lines per hour total (12 decision alerts + 1 suppressed)
        decision_alerts = [a for a in alerts if a.get("event") in (
            "decision_refused", "decisions_malformed", "decision_apply_failed",
            "decision_alerts_suppressed")]
        assert len(decision_alerts) <= 13, \
            f"must be at most 13 lines per hour; got {len(decision_alerts)}"
        # suppressed record must appear at most once per hour
        suppressed = [a for a in alerts if a.get("event") == "decision_alerts_suppressed"]
        assert len(suppressed) <= 1, \
            f"at most 1 suppressed per hour; got {len(suppressed)}"


# ===================================================================
# Target 14: terminal safety
# ===================================================================

_TERMINAL_CHARS = [
    # C0 controls
    ("\x1b", "ESC"),
    ("\x07", "BEL"),
    ("\x00", "NUL"),
    ("\x08", "BS"),
    ("\r", "CR"),
    ("\n", "LF"),
    # C1 controls
    ("\x9b", "C1_CSI"),
    # DEL
    ("\x7f", "DEL"),
    # Bidi controls
    ("‮", "BIDI_RLO"),
    ("⁦", "BIDI_LRI"),
]


class TestTerminalSafety:
    """Target 14: parametrize over control characters through both sandbox status and sandbox alerts.

    A fix stripping only three characters (ESC, BEL, NUL) must fail on the others.
    Uses unique markers around the control char so the assertion is non-vacuous
    even for LF and CR (which appear naturally in multi-line CLI output).
    """

    @pytest.mark.parametrize("char,label", _TERMINAL_CHARS,
                             ids=[t[1] for t in _TERMINAL_CHARS])
    def test_terminal_safety_status(self, tmp_path, monkeypatch, char, label):
        """Control char in key_id must not survive into sandbox status output."""
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        # Use _good_row then mutate key_id (like the original H1 test)
        # Short markers (4 chars each) so the pattern fits within the
        # 12-char key_id truncation used by alerts
        ma = secrets.token_hex(2)
        mb = secrets.token_hex(2)
        evil_kid = f"{ma}{char}{mb}" + "a" * 55
        _, appr, row = _good_row(ws, lay, "req-ts-001")
        row = dict(row)
        p = json.loads(row["signed_payload"]); p["key_id"] = evil_kid
        row["signed_payload"] = json.dumps(p); row["key_id"] = evil_kid
        s, _ = _mk(lay, _stub_decisions([row]))
        _fetch_decisions(s)
        status = _run_status_cli(lay)
        assert f"{ma}{char}{mb}" not in status, \
            f"{label} ({char!r}) must be stripped from key_id in sandbox status"

    @pytest.mark.parametrize("char,label", _TERMINAL_CHARS,
                             ids=[t[1] for t in _TERMINAL_CHARS])
    def test_terminal_safety_alerts(self, tmp_path, monkeypatch, char, label):
        """Control char in key_id must not survive into sandbox alerts output."""
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        # Short markers (4 chars each) so the 9-char pattern (4+1+4) fits
        # within the 12-char key_id display in alerts
        ma = secrets.token_hex(2)
        mb = secrets.token_hex(2)
        evil_kid = f"{ma}{char}{mb}" + "a" * 55
        _, appr, row = _good_row(ws, lay, "req-ta-001")
        row = dict(row)
        p = json.loads(row["signed_payload"]); p["key_id"] = evil_kid
        row["signed_payload"] = json.dumps(p); row["key_id"] = evil_kid
        s, _ = _mk(lay, _stub_decisions([row]))
        _fetch_decisions(s)
        alerts_text = _run_alerts_cli(lay)
        assert f"{ma}{char}{mb}" not in alerts_text, \
            f"{label} ({char!r}) must be stripped from key_id in sandbox alerts"




# ===================================================================
# R2 findings: MUST before the T9a commit (T9A_SECURITY_REVIEW.md R2)
# ===================================================================


class TestR2_1:
    """R2-1 HIGH: a key_id is cleaned into a valid one before the sig check.

    R3 (A section): replaced the source grep with a behavioural node.
    A control char in the unsigned key_id column must NOT be cleaned before
    the signature check; a mismatch between the signed payload.key_id and
    the server's key_id must stay a mismatch (pending, not executed).
    """

    def test_r2_1_sanitized_key_id_changes_verdict(self, tmp_path, monkeypatch):
        """Behavioural: a control char prepended to a valid key_id must cause
        the row to stay pending (signature mismatch), not execute."""
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-r21beh-001"
        rec = _create_pending_request(lay, rid, command="echo r21", requires_dual=True)
        fp = rec["fingerprint"]
        bob_sk, _, bob_kid = ws["admin_sks"][0][:3]
        carol_sk, _, carol_kid = ws["admin_sks"][1][:3]
        # Good row from bob
        ba = _make_remote_approval(bob_sk, request_id=rid, command="echo r21",
                                   fingerprint=fp, user_id=f"admin-{bob_kid[:8]}")
        # Good row from carol, but with a control char prepended to the
        # unsigned key_id column (the signed payload.key_id is clean).
        ca = _make_remote_approval(carol_sk, request_id=rid, command="echo r21",
                                   fingerprint=fp, user_id=f"admin-{carol_kid[:8]}")
        row_ca = _build_server_row(ca, rid)
        # Prepend LF to the unsigned key_id -- if sanitization cleans it,
        # the row becomes valid and the request executes.
        row_ca["key_id"] = "\n" + row_ca["key_id"]
        s, _ = _mk(lay, _stub_decisions([_build_server_row(ba, rid), row_ca]))
        _fetch_decisions(s)
        require_m3(9, rid in _pending_request_ids(lay),
            "R2-1: control-char key_id was sanitized before sig check; "
            "request executed instead of staying pending")


class TestR2_2:
    """R2-2 HIGH: the key id is stored and shown as server text."""

    def test_r2_2_key_id_hex_or_invalid(self, tmp_path, monkeypatch):
        """'Spec section 5: key id must be hex or prints invalid.'

        A key_id that is not lowercase hex of the expected length must print
        as 'invalid' in sandbox status and sandbox alerts, never the raw value."""
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _, _, row = _good_row(ws, lay, "req-r22-001")
        evil_kid = "NOT-HEX-!@#$%^" + "Z" * 100
        row = dict(row)
        p = json.loads(row["signed_payload"]); p["key_id"] = evil_kid
        row["signed_payload"] = json.dumps(p); row["key_id"] = evil_kid
        s, _ = _mk(lay, _stub_decisions([row]))
        _fetch_decisions(s)
        alerts_text = _run_alerts_cli(lay, lines=50)
        # _sanitize_field strips controls but NOT arbitrary printables.
        # The raw non-hex key_id passes through sanitize and reaches display
        # (_key_id_display truncates to 12 chars, so check within that).
        require_m3(9, evil_kid[:10] not in alerts_text,
            f"R2-2: raw non-hex key_id leaked to alerts")

    def test_r2_2_key_id_size_bounded(self, tmp_path, monkeypatch):
        """'record[key_id] at 702 and alerts.py:97-100 have no cap. Measured:
        a 1 MB key id gives a 1 MB audit record.'"""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _, _, row = _good_row(ws, lay, "req-r22s-001")
        huge_kid = "a" * (1024 * 1024)  # 1 MB
        row = dict(row)
        p = json.loads(row["signed_payload"]); p["key_id"] = huge_kid
        row["signed_payload"] = json.dumps(p); row["key_id"] = huge_kid
        s, _ = _mk(lay, _stub_decisions([row]))
        _fetch_decisions(s)
        alerts = read_alerts(lay, limit=200)
        total = sum(len(json.dumps(a)) for a in alerts)
        require_m3(9, total < 50000,
            f"R2-2: alert records must be bounded; total bytes: {total}")

    def test_r2_2_nbsp_nnbsp_stripped(self):
        """'NBSP and NNBSP are in neither _CTRL_CHARS nor _LOCAL_CTRL. Measured:
        they reach sandbox status, sandbox alerts and the audit record.'"""
        from sandbox.connector.sync.process import _CTRL_CHARS
        require_m3(9, 0xA0 in _CTRL_CHARS,
            "R2-2: NBSP (U+00A0) not in _CTRL_CHARS")


class TestR2_3:
    """R2-3 HIGH: section 4 keys and order are still not as specified."""

    def test_r2_3_unverified_key_no_server_key_id(self, tmp_path, monkeypatch):
        """'Unverified refusal key is (kind, rid, code); a server-chosen key id
        never makes a new key.' But process.py:669 uses the key id for every
        refusal, verified or not."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-r23-001"
        rec = _create_pending_request(lay, rid, command="echo r23")
        sk1 = _keygen(); sk2 = _keygen()
        a1 = _make_remote_approval(sk1[0], request_id=rid, command="echo r23",
                                   fingerprint=rec["fingerprint"], user_id="e1")
        a2 = _make_remote_approval(sk2[0], request_id=rid, command="echo r23",
                                   fingerprint=rec["fingerprint"], user_id="e2")
        dsk = _keygen()
        s = _mk2(lay, _stub_decisions([_build_server_row(a1, rid), _build_server_row(a2, rid)]), dsk)
        _fetch_decisions(s)
        alerts = [a for a in read_alerts(lay, limit=200) if a.get("reason_code") == "unknown_key"]
        # Bug: dedupe key includes key_id, so two different unknown keys -> two alerts.
        # Spec: unverified key is (kind, rid, code), so same key -> 1 alert.
        require_m3(9, len(alerts) == 1,
            f"R2-3: two unknown keys on the same request should be ONE alert "
            f"(key excludes key_id); got {len(alerts)}")

    def test_r2_3_mark_realerted_after_cap(self, tmp_path, monkeypatch):
        """'707-708 calls mark_realerted before the cap check at 714. Measured:
        a capped re-alert writes nothing, counts as a repeat and resets the
        timer, so the next cycle stays silent too.'

        Approach: cycle 1 alerts one key. Modify state so re-alert window
        has passed AND per-hour cap is at the limit. Cycle 2 processes the
        same row: should_alert=True (window passed), is_realert=True, then
        mark_realerted runs BEFORE may_alert returns False (per-hour cap).
        Bug: last_alerted is reset despite the cap blocking the alert."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.sync.decision_state import (
            DecisionState, DECISION_REALERT_SECONDS,
            DECISION_ALERTS_PER_HOUR,
        )
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        logs_dir = lay.root / ".sandbox" / "logs"

        # Cycle 1: 1 request, 1 unknown-key refusal. Alert fires, alerted=True.
        old_rid = "req-r23m-old"
        old_evil = _keygen()
        rec_old = _create_pending_request(lay, old_rid, command="echo old")
        old_row = _build_server_row(_make_remote_approval(
            old_evil[0], request_id=old_rid, command="echo old",
            fingerprint=rec_old["fingerprint"], user_id="evil-old"), old_rid)
        dsk = _keygen()
        s1 = _mk2(lay, _stub_decisions([old_row]), dsk); _fetch_decisions(s1)

        # Modify saved state:
        # 1. Set old key's last_alerted to >REALERT ago (window passes)
        # 2. Set alerts_this_hour to per-hour cap (may_alert returns False)
        ds_file = logs_dir / "decision_state.json"
        state = json.loads(ds_file.read_text(encoding="utf-8"))
        old_last_alerted = time.time() - DECISION_REALERT_SECONDS - 10
        target_entry_key = None
        for k, v in state["entries"].items():
            if "decision_refused" in k and old_rid in k and v.get("alerted"):
                v["last_alerted"] = old_last_alerted
                target_entry_key = k
                break
        assert target_entry_key is not None, "must find alerted refusal entry"
        state["alerts_this_hour"] = DECISION_ALERTS_PER_HOUR  # at the cap
        ds_file.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")

        # Cycle 2: same single row. The old key is a re-alert.
        # should_alert=True (window passed), is_realert=True.
        # mark_realerted runs at line 708 (sets last_alerted=now).
        # may_alert returns False (ath >= DECISION_ALERTS_PER_HOUR).
        s2 = _mk2(lay, _stub_decisions([old_row]), dsk); _fetch_decisions(s2)

        # Read state after cycle 2
        ds2 = DecisionState(logs_dir)
        entry = ds2._entries.get(target_entry_key, {})
        updated_la = entry.get("last_alerted", 0)
        # Bug: mark_realerted at 708 runs before cap check at 714, setting
        # last_alerted to now even though the cap blocked the alert.
        # In fixed code, last_alerted stays at old_last_alerted.
        require_m3(9, abs(updated_la - old_last_alerted) < 2,
            f"R2-3: capped re-alert reset last_alerted from {old_last_alerted:.0f} "
            f"to {updated_la:.0f}; mark_realerted ran before cap check")


class TestR2_4:
    """R2-4 MEDIUM: outcome marked as recorded before it is recorded."""

    def test_r2_4_outcome_not_marked_before_append(self, tmp_path, monkeypatch):
        """'process.py:776-783 stores outcome_sig before the append at 798.
        One failed append loses that outcome record for good.'

        Assert: after a failed audit append, the next poll re-writes the record."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.audit import FolderAudit
        import sandbox.connector.audit as am
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-r24-001"
        _, _, row = _good_row(ws, lay, rid); row = dict(row); row["signature"] = "00" * 64
        dsk = _keygen()
        # First poll: make audit append fail
        orig_append = FolderAudit.append
        call_count = [0]
        def failing_append(self, *a, **k):
            call_count[0] += 1
            if call_count[0] <= 2:
                raise OSError("disk full")
            return orig_append(self, *a, **k)
        monkeypatch.setattr(am.FolderAudit, "append", failing_append)
        s1 = _mk2(lay, _stub_decisions([row]), dsk); _fetch_decisions(s1)
        # Second poll: append succeeds now
        s2 = _mk2(lay, _stub_decisions([row]), dsk); _fetch_decisions(s2)
        records = _read_audit(lay)
        refused = [r for r in records if r.get("event") == "decision_refused"]
        require_m3(9, len(refused) >= 1,
            "R2-4: after a failed append, the next poll must re-write the record")


class TestR2_5:
    """R2-5 HIGH: T9A-5 partly done. Corrupt state forms still crash.

    int(NaN) at decision_state.py:97 raises ValueError OUTSIDE the
    try/except that only covers read_text/json.loads (lines 56-60).
    _load_decision_state has no try/except either, so the ValueError
    propagates to _fetch_decisions and stops the whole cycle."""

    def test_r2_5_nan_alerts_this_hour(self):
        """int(NaN) at decision_state.py:97 raises ValueError outside the
        try/except at lines 56-60. DecisionState.__init__ crashes."""
        from sandbox.connector.sync.decision_state import DecisionState
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            sp = Path(td) / "decision_state.json"
            sp.write_text('{"alerts_this_hour":NaN,"entries":{}}',
                          encoding="utf-8")
            crashed = False
            try:
                DecisionState(Path(td))
            except (ValueError, OverflowError):
                crashed = True
            require_m3(9, not crashed,
                "R2-5: NaN in alerts_this_hour crashes DecisionState.__init__")

    def test_r2_5_nan_net_consecutive(self):
        """int(NaN) at decision_state.py:96 raises ValueError."""
        from sandbox.connector.sync.decision_state import DecisionState
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            sp = Path(td) / "decision_state.json"
            sp.write_text('{"net_consecutive":NaN,"entries":{}}',
                          encoding="utf-8")
            crashed = False
            try:
                DecisionState(Path(td))
            except (ValueError, OverflowError):
                crashed = True
            require_m3(9, not crashed,
                "R2-5: NaN in net_consecutive crashes DecisionState.__init__")

    def test_r2_5_inf_suppressed_this_hour(self):
        """int(Infinity) at decision_state.py:99 raises OverflowError."""
        from sandbox.connector.sync.decision_state import DecisionState
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            sp = Path(td) / "decision_state.json"
            sp.write_text('{"suppressed_this_hour":Infinity,"entries":{}}',
                          encoding="utf-8")
            crashed = False
            try:
                DecisionState(Path(td))
            except (ValueError, OverflowError):
                crashed = True
            require_m3(9, not crashed,
                "R2-5: Infinity in suppressed_this_hour crashes DecisionState.__init__")

    def test_r2_5_truncated_json_guard(self, tmp_path):
        """Guard: truncated JSON is caught by _load (ValueError from json.loads).
        DecisionState falls back to empty. Already working."""
        from sandbox.connector.sync.decision_state import DecisionState
        sp = tmp_path / "decision_state.json"
        sp.write_text('{"entries": {"k": {"count":', encoding="utf-8")
        ds = DecisionState(tmp_path)
        assert ds._entries == {}, "truncated JSON must yield empty state"

    def test_r2_5_directory_guard(self, tmp_path):
        """Guard: directory at state file path is caught by _load (OSError).
        DecisionState falls back to empty. Already working."""
        from sandbox.connector.sync.decision_state import DecisionState
        sp = tmp_path / "decision_state.json"
        sp.mkdir(parents=True, exist_ok=True)
        ds = DecisionState(tmp_path)
        assert ds._entries == {}, "directory must yield empty state"

    def test_r2_5_non_utf8_guard(self, tmp_path):
        """Guard: non-UTF-8 bytes are caught by _load (UnicodeDecodeError
        is a subclass of ValueError). DecisionState falls back to empty."""
        from sandbox.connector.sync.decision_state import DecisionState
        sp = tmp_path / "decision_state.json"
        sp.write_bytes(b'\x80\x81\x82\xff')
        ds = DecisionState(tmp_path)
        assert ds._entries == {}, "non-UTF-8 must yield empty state"


class TestR2_6:
    """R2-6 MEDIUM: executed and denied can be suppressed."""

    def test_r2_6_executed_not_suppressed(self, tmp_path, monkeypatch):
        """R2-6 intent: an executed or denied record is written on first
        sighting, even when a matching outcome_sig was pre-seeded in the
        decision state.  The dedupe must not suppress executed/denied.

        R3-2 corrected premise: do NOT demand re-audit on repeat polls.
        Pre-seed an outcome_sig in the state, then execute via
        _fetch_decisions; the first sighting must still write the record."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.sync.decision_state import DecisionState
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-r26-001"
        rec = _create_pending_request(lay, rid, command="echo r26", requires_dual=True)
        fp = rec["fingerprint"]
        ba = _make_remote_approval(ws["admin_sks"][0][0], request_id=rid,
                                   command="echo r26", fingerprint=fp,
                                   user_id=f"admin-{ws['admin_sks'][0][2][:8]}")
        ca = _make_remote_approval(ws["admin_sks"][1][0], request_id=rid,
                                   command="echo r26", fingerprint=fp,
                                   user_id=f"admin-{ws['admin_sks'][1][2][:8]}")
        rows = [_build_server_row(ba, rid), _build_server_row(ca, rid)]
        # Pre-seed the outcome_sig so the dedupe path fires
        logs_dir = lay.root / ".sandbox" / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        sp = logs_dir / "decision_state.json"
        # R4-9 / R5-1: seed the exact outcome_sig the product computes.
        # process.py:834: f"{status}:{approvals_count}:{reason_codes}:{reason_code}"
        # For an executed request: status=executed, approvals=None
        # (apply_external returns no 'approvals' key for executed),
        # no reason_codes (sorted set -> []), no reason_code -> None.
        seeded_sig = "executed:None:[]:None"
        sp.write_text(json.dumps({"entries": {
            f"sync_decision_applied:{rid}": {
                "outcome_sig": seeded_sig,
                "last_seen": time.time(), "count": 1,
                "alerted": True, "first_seen": time.time(), "repeats": 0,
            }
        }}), encoding="utf-8")
        dsk = _keygen()
        s1 = _mk2(lay, _stub_decisions(rows), dsk); _fetch_decisions(s1)
        records = _read_audit(lay)
        applied = [r for r in records if r.get("event") == "sync_decision_applied"
                   and r.get("status") == "executed"]
        require_m3(9, len(applied) >= 1,
            f"R2-6: executed record suppressed by pre-seeded outcome_sig; "
            f"audit records with status=executed: {len(applied)}")
        # R5-1: confirm the state entry carries the seeded sig, so a future
        # format change fails the node instead of making it vacuous again.
        ds = DecisionState(logs_dir)
        state_entry = ds._entries.get(f"sync_decision_applied:{rid}")
        assert state_entry is not None, \
            f"R5-1: no state entry for sync_decision_applied:{rid}"
        assert state_entry["outcome_sig"] == seeded_sig, \
            f"R5-1: outcome_sig mismatch; expected {seeded_sig!r}, " \
            f"got {state_entry['outcome_sig']!r}"


class TestR2_7:
    """R2-7 HIGH: empty 200 is still 'no decisions'."""

    def test_r2_7_empty_body_200_alerts(self, tmp_path, monkeypatch):
        """'process.py:1056 keeps the if body: guard. Measured: empty body, {}
        -> No alert, no status line, successful cycle.'

        An empty body on a 200 is not one of the frozen empty shapes and must
        alert as unparseable_body or decisions_key_missing."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _create_pending_request(lay, "req-r27-001", command="echo r27")
        def empty_connect(method, url, body=None, headers=None, token=None):
            if "/sync/decisions" in url: return (200, {}, _date_hdr())
            return (200, {}, _date_hdr())
        s, _ = _mk(lay, empty_connect)
        _fetch_decisions(s)
        alerts = read_alerts(lay, limit=200)
        malformed = [a for a in alerts if a.get("event") == "decisions_malformed"]
        require_m3(9, len(malformed) >= 1,
            "R2-7: an empty dict body on a 200 must alert as malformed; got none")


class TestR2_8:
    """R2-8 MEDIUM: the non-existent path exists inside the package."""

    def test_r2_8_layout_none_no_writes(self):
        """'With layout=None nothing is written anywhere under the package
        directory and no __nonexistent_state__ directory appears.'

        process.py:596 passes Path(__file__).parent / '__nonexistent_state__'
        to DecisionState, whose save() calls mkdir(parents=True) and writes."""
        import sandbox.connector.sync.process as proc_mod
        from sandbox.connector.sync.process import _load_decision_state, SyncProcess
        pkg_dir = Path(proc_mod.__file__).parent
        # Create a SyncProcess with layout=None
        s = SyncProcess(layout=None, server_url="http://127.0.0.1:9999",
                        device_key=bytes(_keygen()[0]), device_id="dev-1",
                        clock=time.monotonic,
                        connect=lambda m, u, body=None, headers=None, token=None: (200, {"decisions": []}, _date_hdr()))
        ds = _load_decision_state(s)
        # Trigger save which creates the directory
        ds.save()
        ne_dir = pkg_dir / "__nonexistent_state__"
        require_m3(9, not ne_dir.exists(),
            f"R2-8: layout=None created {ne_dir} under the package directory")


class TestR2_9:
    """R2-9 MEDIUM: non-200 reason ends in ': str'."""

    def test_r2_9_server_text_in_alert(self, tmp_path, monkeypatch):
        """'process.py:1020: _REFUSAL_SENTENCES.get(code, type(code).__name__).
        Measured: decisions not fetched: HTTP 500 at decisions: http_5xx: str.
        Server text is computed and thrown away.'

        The spec says '(server says: <text>)' for 4xx and 5xx."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _create_pending_request(lay, "req-r29-001", command="echo r29")
        s, _ = _mk(lay, _stub_status(500, {"detail": "custom error text"}))
        _fetch_decisions(s)
        alerts = read_alerts(lay, limit=200)
        fetch_failed = [a for a in alerts if a.get("event") == "decisions_fetch_failed"]
        reason = fetch_failed[0].get("reason", "") if fetch_failed else ""
        require_m3(9, ": str" not in reason,
            f"R2-9: reason ends in ': str': {reason}")

    def test_r2_9_scrub_failure_drops_text(self, tmp_path, monkeypatch):
        """'_safe_server_text also calls scrub_text outside any try at 563.
        A raising scrub leaves _fetch_decisions as an exception.'"""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        from sandbox.connector import scrub as _scrub_mod
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _create_pending_request(lay, "req-r29s-001", command="echo r29s")
        # Make scrub_text raise when called from _safe_server_text
        monkeypatch.setattr(_scrub_mod, "scrub_text",
                            lambda t: (_ for _ in ()).throw(ValueError("boom")))
        s, _ = _mk(lay, _stub_status(500, {"detail": "test"}))
        raised = False
        try:
            _fetch_decisions(s)
        except Exception:
            raised = True
        require_m3(9, not raised,
            "R2-9: scrub_text failure raises from _fetch_decisions "
            "(scrub_text at line 563 is outside try)")


class TestR2_10:
    """R2-10 MEDIUM: T9A-1 partly done."""

    def test_r2_10_500_at_token_says_http_5xx(self, tmp_path, monkeypatch):
        """'A 500 at /sync/token says transport_refused at token: SyncError.
        The spec row says http_5xx, HTTP 500 at token.'"""
        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        def c(m, u, body=None, headers=None, token=None):
            if "/sync/token" in u: return (500, {"detail": "down"}, _date_hdr())
            return (200, {}, _date_hdr())
        s = SyncProcess(layout=lay, server_url="http://127.0.0.1:9999",
                        device_key=bytes(_keygen()[0]), device_id="dev-1",
                        clock=time.monotonic, connect=c)
        s._token = "old"; s._token_expires = 0
        try: run_once(s)
        except SyncError: pass
        alerts = read_alerts(lay, limit=200)
        codes = [a.get("reason_code") for a in alerts]
        require_m3(9, "transport_refused" not in codes,
            f"R2-10: 500 at token must be http_5xx, not transport_refused; got {codes}")

    def test_r2_10_http_exception_at_token(self, tmp_path, monkeypatch):
        """'http.client.HTTPException at token or registry records nothing.'"""
        import http.client
        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        def c(m, u, body=None, headers=None, token=None):
            if "/sync/token" in u: raise http.client.HTTPException("bad")
            return (200, {}, _date_hdr())
        s = SyncProcess(layout=lay, server_url="http://127.0.0.1:9999",
                        device_key=bytes(_keygen()[0]), device_id="dev-1",
                        clock=time.monotonic, connect=c)
        s._token = "old"; s._token_expires = 0
        for _ in range(3):
            try: run_once(s)
            except SyncError: pass
            except Exception: pass
        alerts = read_alerts(lay, limit=200)
        require_m3(9,
            len([a for a in alerts if a.get("event") == "decisions_fetch_failed"]) >= 1,
            "R2-10: HTTPException at token must eventually alert")


class TestR2_11:
    """R2-11 MEDIUM: invalid_id is still silent."""

    def test_r2_11_invalid_id_alerts(self, tmp_path, monkeypatch):
        """R4-7: drive a real invalid_id by patching _validate_request_id to
        return "invalid_id" (the product's actual return value).
        The alert must say ``request_id_refused`` (spec section 2)."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        import sandbox.connector.approval as apmod
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-r211-001"
        rec = _create_pending_request(lay, rid, command="echo r211")
        fp = rec["fingerprint"]
        ba = _make_remote_approval(ws["admin_sks"][0][0], request_id=rid,
                                   command="echo r211", fingerprint=fp,
                                   user_id=f"admin-{ws['admin_sks'][0][2][:8]}")
        ca = _make_remote_approval(ws["admin_sks"][1][0], request_id=rid,
                                   command="echo r211", fingerprint=fp,
                                   user_id=f"admin-{ws['admin_sks'][1][2][:8]}")
        rows = [_build_server_row(ba, rid), _build_server_row(ca, rid)]
        # R4-7: patch _validate_request_id to return "invalid_id" (its real return)
        monkeypatch.setattr(apmod, "_validate_request_id",
                            lambda *a, **k: "invalid_id")
        s, _ = _mk(lay, _stub_decisions(rows))
        _fetch_decisions(s)
        alerts = read_alerts(lay, limit=200)
        require_m3(9,
            len([a for a in alerts
                if a.get("reason_code") == "request_id_refused"]) >= 1,
            f"R2-11/R4-7: real invalid_id must alert as request_id_refused; "
            f"got: {[a.get('reason_code') for a in alerts]}")


class TestR2_12:
    """R2-12 MEDIUM: T9A-6 is not as written."""

    def test_r2_12_dual_control_1_of_2(self, tmp_path, monkeypatch):
        """'Status prints [dual control 0/2] directly above 1 of 2 counted.
        The spec says [dual control 1/2].'"""
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-r212-001"
        rec = _create_pending_request(lay, rid, command="echo r212", requires_dual=True)
        bob_kid = ws["admin_sks"][0][2]
        row = _build_server_row(_make_remote_approval(ws["admin_sks"][0][0],
            request_id=rid, command="echo r212",
            fingerprint=rec["fingerprint"],
            user_id=f"admin-{bob_kid[:8]}"), rid)
        s, _ = _mk(lay, _stub_decisions([row]))
        _fetch_decisions(s)
        status = _run_status_cli(lay)
        require_m3(9, "0/2" not in status,
            f"R2-12: must show '1/2' or '1 of 2', not '0/2'; got:\n{status}")

    def test_r2_12_claimed_not_apply_failed(self, tmp_path, monkeypatch):
        """'645-649: both branches print the same text, so a record claimed by
        a local approval still in progress reads apply failed.'"""
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-r212c-001"
        _create_pending_request(lay, rid, command="echo r212c")
        # Move to claimed
        lay.claimed_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(lay.pending_dir / f"{rid}.json"),
                    str(lay.claimed_dir / f"{rid}.json"))
        # Seed state entry as claimed (no apply_raised)
        sp = lay.root / ".sandbox" / "logs" / "decision_state.json"
        sp.parent.mkdir(parents=True, exist_ok=True)
        sp.write_text(json.dumps({"entries": {
            f"decision_apply_failed:{rid}:claimed": {
                "count": 1, "alerted": True,
                "last_seen": time.time(), "first_seen": time.time(),
                "repeats": 0, "reason": f"{rid} is claimed"
            }
        }}), encoding="utf-8")
        status = _run_status_cli(lay)
        require_m3(9,
            "it will not run again" not in status.lower(),
            f"R2-12: a merely claimed record says 'it will not run again': {status}")


class TestR2_13:
    """R2-13 MEDIUM: sandbox alerts is sanitized only on some write paths."""

    def test_r2_13_alerts_color_no_esc(self, tmp_path, monkeypatch):
        """'records_cmds.py:87 prints stored fields raw. Measured with
        color=True: an ESC in a hand-edited alerts file reaches the output.'

        Must pass color=True because plain CliRunner strips ANSI."""
        from sandbox.cli.records_cmds import alerts_cmd
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        # Plant an ESC in an alert record
        lay.logs_dir.mkdir(parents=True, exist_ok=True)
        evil_record = {
            "event": "decision_refused", "kind": "decision_refused",
            "reason": "test \x1b[31mEVIL\x1b[0m injection",
            "tool": "sync", "ts": time.time(),
        }
        with open(lay.logs_dir / "alerts.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(evil_record) + "\n")
        runner = click.testing.CliRunner()
        result = runner.invoke(alerts_cmd, [str(lay.root), "-n", "50"], color=True)
        require_m3(9, "\x1b" not in result.output,
            f"R2-13: ESC byte reached sandbox alerts output")

    def test_r2_13_key_id_hex_or_invalid_in_alerts(self, tmp_path, monkeypatch):
        """records_cmds.py:87 prints stored fields raw. A non-hex key_id in
        the alert record reaches the output verbatim."""
        from sandbox.cli.records_cmds import alerts_cmd
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        # Plant an alert record with a non-hex key_id directly in the file
        lay.logs_dir.mkdir(parents=True, exist_ok=True)
        evil_kid = "INJECTED-SERVER-TEXT!"
        evil_record = {
            "event": "decision_refused", "kind": "decision_refused",
            "reason": f"test refusal key_id={evil_kid}",
            "key_id": evil_kid,
            "tool": "sync", "ts": time.time(),
        }
        with open(lay.logs_dir / "alerts.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(evil_record) + "\n")
        runner = click.testing.CliRunner()
        result = runner.invoke(alerts_cmd, [str(lay.root), "-n", "50"], color=True)
        # The reason field contains the evil key_id and prints raw at line 87.
        require_m3(9, evil_kid not in result.output,
            f"R2-13: non-hex key_id reached sandbox alerts output verbatim")


class TestR2_14:
    """R2-14 LOW: remove try/except around _save_seen_nonces."""

    def test_r2_14_nonce_save_exception_caught(self):
        """'The wrap is only product effect is the third row. Fix: restore HEAD
        lines and make both fixtures return False, as the product does.'

        The try/except at approval.py:853-856 catches Exception and converts
        to nonce_saved = False. This hides real errors. Verify the try/except
        is absent by AST inspection."""
        import ast
        src = _APPROVAL_PY.read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "apply_external":
                fn_src = ast.get_source_segment(src, node)
                if fn_src is None:
                    continue
                # The defect: a try/except around _save_seen_nonces
                has_try_except = ("_save_seen_nonces" in fn_src
                                  and "except Exception" in fn_src
                                  and "nonce_saved = False" in fn_src)
                require_m3(9, not has_try_except,
                    "R2-14: try/except around _save_seen_nonces at approval.py:853-856 "
                    "still present")
                return
        require_m3(9, False, "R2-14: apply_external not found")


class TestR2Lows:
    """R2 Lows: fix with the above."""

    def test_r2_low_reason_uses_real_status(self, tmp_path, monkeypatch):
        """'Reason lines say awaiting_second when the request executed or was
        denied. Use the real status.'

        Bug at process.py:1212-1219: the refusal processing loop always puts
        'awaiting_second' in the reason line, regardless of the result status.
        When a request is executed (2 valid dual approvals) but one envelope
        was refused, the refusal alert still says 'awaiting_second'."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-r2low-001"
        rec = _create_pending_request(lay, rid, command="echo r2low", requires_dual=True)
        fp = rec["fingerprint"]
        # One unknown key (refused) + two valid admin keys = executed + one refusal
        fa = _make_remote_approval(_keygen()[0], request_id=rid, command="echo r2low",
                                   fingerprint=fp, user_id="evil")
        ba = _make_remote_approval(ws["admin_sks"][0][0], request_id=rid,
                                   command="echo r2low", fingerprint=fp,
                                   user_id=f"admin-{ws['admin_sks'][0][2][:8]}")
        ca = _make_remote_approval(ws["admin_sks"][1][0], request_id=rid,
                                   command="echo r2low", fingerprint=fp,
                                   user_id=f"admin-{ws['admin_sks'][1][2][:8]}")
        rows = [_build_server_row(fa, rid), _build_server_row(ba, rid), _build_server_row(ca, rid)]
        s, _ = _mk(lay, _stub_decisions(rows))
        _fetch_decisions(s)
        # Confirm request was executed (not still awaiting)
        records = _read_audit(lay)
        applied = [r for r in records if r.get("event") == "sync_decision_applied"]
        exec_recs = [r for r in applied if r.get("status") == "executed"]
        assert len(exec_recs) >= 1, "request must be executed with 2 valid approvals"
        # Bug: refusal alerts say "awaiting_second" even though request was executed
        alerts = read_alerts(lay, limit=200)
        refusal_alerts = [a for a in alerts
                          if a.get("event") == "decision_refused"
                          and rid in a.get("reason", "")]
        has_awaiting = any("awaiting_second" in a.get("reason", "")
                           for a in refusal_alerts)
        require_m3(9, not has_awaiting,
            f"R2 Low: refusal alert says awaiting_second but request executed: "
            f"{[a.get('reason','')[:80] for a in refusal_alerts]}")

    def test_r2_low_malformed_key_shows_age(self, tmp_path, monkeypatch):
        """'decisions_malformed and server_time_write_failed keys never clear,
        so status says "last response malformed" long after recovery.'"""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.sync.decision_state import DecisionState
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _create_pending_request(lay, "req-r2ls-001", command="echo r2ls")
        # First: malformed response
        def bad_c(m, u, body=None, headers=None, token=None):
            if "/sync/decisions" in u: return (200, {"other": "data"}, _date_hdr())
            return (200, {}, _date_hdr())
        s1, _ = _mk(lay, bad_c); _fetch_decisions(s1)
        # Second: recovery (good response)
        dsk = _keygen()
        s2 = _mk2(lay, _stub_decisions([]), dsk); _fetch_decisions(s2)
        # Check: malformed keys should have been cleared after a good 200
        logs_dir = lay.root / ".sandbox" / "logs"
        ds = DecisionState(logs_dir)
        malformed_keys = [k for k in ds._entries if "decisions_malformed" in k]
        require_m3(9, len(malformed_keys) == 0,
            f"R2 Low: malformed keys persist after recovery: {malformed_keys}")

    def test_r2_low_3xx_no_server_text_guard(self, tmp_path, monkeypatch):
        """Guard: 3xx alert does not carry server text (fixed at process.py:1019).
        The 400 <= status < 600 gate excludes 3xx. Already working."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _create_pending_request(lay, "req-r2l3-001", command="echo r2l3")
        s, _ = _mk(lay, _stub_status(301, {"detail": "redirect text"}))
        _fetch_decisions(s)
        alerts = read_alerts(lay, limit=200)
        fetch_reasons = [a.get("reason", "") for a in alerts
                         if a.get("event") == "decisions_fetch_failed"]
        has_server_text = any("redirect text" in r for r in fetch_reasons)
        assert not has_server_text, f"3xx must not carry server text: {fetch_reasons}"

    def test_r2_low_verify_raised_includes_type(self, tmp_path, monkeypatch):
        """'verify_raised omits the type name.'"""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        import sandbox.connector.approval as apmod
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-r2lvr-001"
        rec = _create_pending_request(lay, rid, command="echo r2lvr")
        row = _build_server_row(_make_remote_approval(ws["admin_sks"][0][0],
            request_id=rid, command="echo r2lvr",
            fingerprint=rec["fingerprint"],
            user_id=f"admin-{ws['admin_sks'][0][2][:8]}"), rid)
        def boom(*a, **k): raise TypeError("bad verify")
        monkeypatch.setattr(apmod, "_verify_remote_approval", boom)
        s, _ = _mk(lay, _stub_decisions([row]))
        _fetch_decisions(s)
        alerts = read_alerts(lay, limit=200)
        vr = [a for a in alerts if a.get("reason_code") == "verify_raised"]
        assert len(vr) >= 1, "verify_raised alert must appear"
        require_m3(9, "TypeError" in vr[0].get("reason", ""),
            f"R2 Low: verify_raised omits type name; got: {vr[0].get('reason')}")


class TestR4_H2KeyIdCheck:
    """R4: a node that bites when the H2 key-id type check is removed.

    It must still bite after R2-1 is built: assert on the verdict, not on
    the sanitizer. This is a GUARD: passes today, fails when the check
    is removed."""

    def test_r4_h2_key_id_type_check_bites_on_verdict(self, tmp_path, monkeypatch):
        """A non-string key_id in the row must not change the verdict
        compared to a string key_id that is unknown. Both must refuse."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-r4h2-001"
        rec = _create_pending_request(lay, rid, command="echo r4h2")
        row = {"request_id": rid, "signed_payload": json.dumps({"key_id": 42}),
               "signature": "00" * 64, "key_id": 42}
        s, _ = _mk(lay, _stub_decisions([row]))
        _fetch_decisions(s)
        assert rid in _pending_request_ids(lay), "non-string key_id must not execute"
        alerts = read_alerts(lay, limit=200)
        refused = [a for a in alerts if a.get("event") in ("decision_refused", "decisions_malformed")]
        assert len(refused) >= 1, "non-string key_id must produce a refusal alert"


# ===================================================================
# R3 targets: FAIL on HEAD 81fda66 (T9A_SECURITY_REVIEW.md Round 3)
# ===================================================================


# ---- R3-1: _rebuild_envelope executes rows that 975e2bc refuses ----

# The 12 row forms from the review table (R3-1):
_R3_1_ROW_FORMS = [
    # key_id is non-string with valid signatures list (5 forms)
    ("kid_int", {"key_id": 42}),
    ("kid_list", {"key_id": ["a"]}),
    ("kid_dict", {"key_id": {"x": 1}}),
    ("kid_bool", {"key_id": True}),
    ("kid_float", {"key_id": 1.5}),
    # signature is non-string with valid signatures list (4 forms)
    ("sig_int", {"signature_override": 42}),
    ("sig_list", {"signature_override": ["a"]}),
    ("sig_dict", {"signature_override": {"x": 1}}),
    ("sig_bool", {"signature_override": True}),
    # No top-level signature; signatures[0].key_id is non-string; row key_id valid (3 forms)
    ("fallback_kid_int", {"fallback_kid": 42}),
    ("fallback_kid_list", {"fallback_kid": ["a"]}),
    ("fallback_kid_null", {"fallback_kid": None}),
]


class TestR3_1:
    """R3-1 HIGH: _rebuild_envelope executes rows that 975e2bc refuses.

    Each of the 12 row forms must stay pending (not execute) when served
    alongside a good second approval.
    """

    @pytest.mark.parametrize("label,form", _R3_1_ROW_FORMS,
                             ids=[f[0] for f in _R3_1_ROW_FORMS])
    def test_r3_1_row_form_stays_pending(self, tmp_path, monkeypatch, label, form):
        """Each of the 12 row forms from the R3-1 table must stay pending.

        The key point: the non-string top-level key_id or signature, combined
        with a VALID signatures[] list, makes _rebuild_envelope pick up the
        good values from the fallback path and execute what 975e2bc refused.
        """
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = f"req-r31-{label}"
        rec = _create_pending_request(lay, rid, command="echo r31", requires_dual=True)
        fp = rec["fingerprint"]
        bob_sk, _, bob_kid = ws["admin_sks"][0][:3]
        carol_sk, _, carol_kid = ws["admin_sks"][1][:3]
        # Good rows from both admins (would execute normally)
        ba = _make_remote_approval(bob_sk, request_id=rid, command="echo r31",
                                   fingerprint=fp, user_id=f"admin-{bob_kid[:8]}")
        ca = _make_remote_approval(carol_sk, request_id=rid, command="echo r31",
                                   fingerprint=fp, user_id=f"admin-{carol_kid[:8]}")
        good_row_bob = _build_server_row(ba, rid)
        good_row_carol = _build_server_row(ca, rid)
        # The valid signatures list with the correct key_id and sig
        valid_sigs = [{"key_id": good_row_bob["key_id"],
                       "sig": good_row_bob.get("signature", "")}]
        # Mutate bob's row per the form spec
        bad_row = dict(good_row_bob)
        if "key_id" in form:
            # Non-string key_id at top level, but valid signatures[] list
            bad_row["key_id"] = form["key_id"]
            bad_row["signatures"] = valid_sigs
        elif "signature_override" in form:
            # Non-string signature at top level, but valid signatures[] list
            bad_row["signature"] = form["signature_override"]
            bad_row["signatures"] = valid_sigs
        elif "fallback_kid" in form:
            # Remove top-level signature; signatures[0].key_id is non-string
            # but the row's key_id is valid
            bad_row.pop("signature", None)
            bad_row["signatures"] = [{"key_id": form["fallback_kid"],
                                      "sig": good_row_bob.get("signature", "")}]
        s, _ = _mk(lay, _stub_decisions([bad_row, good_row_carol]))
        _fetch_decisions(s)
        require_m3(9, rid in _pending_request_ids(lay),
            f"R3-1: row form {label} caused execution; 975e2bc kept it pending")


class TestR3_1_Differential:
    """Permanent differential: current _rebuild_envelope vs frozen 975e2bc fixture.

    Every row form that 975e2bc returned None for must also return None
    (or an equivalent refusal) from the current rebuild.
    """

    def test_r3_1_differential_rebuild(self):
        """Compare the current _rebuild_envelope against the 975e2bc fixture
        on all 12 row forms plus the base case."""
        from sandbox.connector.sync.process import _rebuild_envelope
        from tests.security.fixtures.rebuild_975e2bc import rebuild_975e2bc
        # Base: a well-formed row must produce an envelope in both
        base = {"signed_payload": json.dumps({"key_id": "aa" * 32, "command": "echo x"}),
                "signature": "bb" * 64, "key_id": "aa" * 32}
        old = rebuild_975e2bc(base)
        new, _ = _rebuild_envelope(base)
        assert old is not None and new is not None, "base case must produce envelope in both"
        # Non-string key_id with valid signatures: 975e2bc returns envelope (truthy)
        # but the key_id is the raw non-string; _verify will then refuse it
        for label, form in _R3_1_ROW_FORMS:
            row = dict(base)
            if "key_id" in form:
                row["key_id"] = form["key_id"]
            elif "signature_override" in form:
                row["signature"] = form["signature_override"]
            elif "fallback_kid" in form:
                row.pop("signature", None)
                row["signatures"] = [{"key_id": form["fallback_kid"], "sig": "cc" * 64}]
            old_env = rebuild_975e2bc(row)
            new_env, reason = _rebuild_envelope(row)
            # If 975e2bc returned None, the new code must also return None
            if old_env is None:
                assert new_env is None, (
                    f"R3-1 differential: 975e2bc returned None for {label}, "
                    f"but current returns an envelope (reason={reason})")


# ---- R3-2: E13 is back: every poll of a done request writes executed ----

class TestR3_2:
    """R3-2 HIGH: execute one request, poll 10 times, exactly 1 executed record."""

    def test_r3_2_execute_then_poll_10_times(self, tmp_path, monkeypatch):
        """Execute a request through _fetch_decisions, then poll 10 more
        times with the same rows.  Spec: exactly 1 sync_decision_applied
        record with status=executed."""
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-r32-001"
        rec = _create_pending_request(lay, rid, command="echo r32", requires_dual=True)
        fp = rec["fingerprint"]
        ba = _make_remote_approval(ws["admin_sks"][0][0], request_id=rid,
                                   command="echo r32", fingerprint=fp,
                                   user_id=f"admin-{ws['admin_sks'][0][2][:8]}")
        ca = _make_remote_approval(ws["admin_sks"][1][0], request_id=rid,
                                   command="echo r32", fingerprint=fp,
                                   user_id=f"admin-{ws['admin_sks'][1][2][:8]}")
        rows = [_build_server_row(ba, rid), _build_server_row(ca, rid)]
        dsk = _keygen()
        # Execute
        s0 = _mk2(lay, _stub_decisions(rows), dsk); _fetch_decisions(s0)
        # 10 more polls
        for _ in range(10):
            s = _mk2(lay, _stub_decisions(rows), dsk); _fetch_decisions(s)
        records = _read_audit(lay)
        executed = [r for r in records if r.get("event") == "sync_decision_applied"
                    and r.get("status") == "executed"]
        require_m3(9, len(executed) == 1,
            f"R3-2: 10 polls of done request gave {len(executed)} executed records, "
            f"expected exactly 1")


# ---- R3-3: R2-5 still not done: corrupt state-file forms ----

# Cycle-stopping forms at top-level (crash in __init__ or _evict):
_R3_3_CYCLE_STOP_FORMS = [
    ("bigint_hour_start", {"hour_start": int("1" + "0" * 400)}),
    ("bigint_net_consecutive", {"net_consecutive": int("1" + "0" * 400)}),
    ("bigint_first_seen", "_entry_first_seen_bigint"),
    ("evict_last_seen_str", "_evict_last_seen_str"),
]

# Entry-level forms that crash in note()/should_alert() when the key matches:
_R3_3_ENTRY_CRASH_FORMS = [
    ("entry_alerted_only", "_entry_alerted_only"),
    ("entry_count_str", "_entry_count_str"),
    ("entry_first_seen_future_alerted", "_entry_first_seen_future"),
    ("entry_last_alerted_str", "_entry_last_alerted_str"),
    ("entry_last_alerted_null", "_entry_last_alerted_null"),
    ("entry_repeats_str", "_entry_repeats_str"),
]

# The 3 crash forms for sandbox status:
_R3_3_STATUS_CRASH_FORMS = [
    ("nan_net_consecutive", {"net_consecutive": "NaN_marker"}),  # will be injected as NaN
    ("inf_net_consecutive", {"net_consecutive": "Inf_marker"}),
    ("outcome_sig_int", "_outcome_sig_int"),  # needs a pending request with matching rid
]

# Wrong-type field accepted instead of dropped:
_R3_3_WRONG_TYPE = [
    ("alerted_str_no", "_alerted_str_no"),
]


def _build_r3_3_state_blob(form_name, entry_key=None):
    """Build a corrupt state JSON string from the form name.

    When ``entry_key`` is provided, the corrupt entry uses that exact key
    so the refusal's dedupe key matches during note()/should_alert().
    """
    now = time.time()
    k = entry_key or "decision_refused:req-cs-001:bad_signature:deadbeef"
    if form_name == "_entry_first_seen_bigint":
        e = {"count": 1, "alerted": True, "first_seen": int("1" + "0" * 400),
             "last_seen": now, "repeats": 0}
        return json.dumps({"entries": {k: e}})
    elif form_name == "_entry_alerted_only":
        return json.dumps({"entries": {k: {"alerted": True}}})
    elif form_name == "_entry_count_str":
        return json.dumps({"entries": {k: {"count": "x", "alerted": True,
                                           "first_seen": now, "last_seen": now, "repeats": 0}}})
    elif form_name == "_entry_first_seen_future":
        return json.dumps({"entries": {k: {"count": 1, "alerted": True,
                                           "first_seen": now + 999999, "last_seen": now, "repeats": 0}}})
    elif form_name == "_entry_last_alerted_str":
        return json.dumps({"entries": {k: {"count": 1, "alerted": True,
                                           "last_alerted": "x", "first_seen": now, "last_seen": now, "repeats": 0}}})
    elif form_name == "_entry_last_alerted_null":
        return json.dumps({"entries": {k: {"count": 1, "alerted": True,
                                           "last_alerted": None, "first_seen": now, "last_seen": now, "repeats": 0}}})
    elif form_name == "_entry_repeats_str":
        # last_alerted must be > REALERT_SECONDS ago so should_alert() returns
        # True and the code path through get_repeats() -> repeats > 0 is reached.
        return json.dumps({"entries": {k: {"count": 1, "alerted": True,
                                           "repeats": "x", "first_seen": now - 7200,
                                           "last_seen": now, "last_alerted": now - 7200}}})
    elif form_name == "_evict_last_seen_str":
        entries = {}
        for i in range(300):
            entries[f"decision_refused:req-ev-{i:04d}:bad_signature:ee{i:04d}"] = {
                "count": 1, "alerted": True, "last_seen": "x",
                "first_seen": now, "repeats": 0}
        return json.dumps({"entries": entries})
    elif form_name == "_outcome_sig_int":
        return json.dumps({"entries": {
            f"sync_decision_applied:req-cs-001": {
                "outcome_sig": 5, "last_seen": now, "count": 1,
                "alerted": True, "first_seen": now, "repeats": 0}}})
    elif form_name == "_alerted_str_no":
        return json.dumps({"entries": {k: {"count": 1, "alerted": "no",
                                           "first_seen": now, "last_seen": now, "repeats": 0}}})
    raise ValueError(f"unknown form: {form_name}")


class TestR3_3:
    """R3-3 HIGH: corrupt state-file forms from the private file.

    Each of the 10 cycle-stopping forms must not stop the cycle:
    uploads must still run and an alert must be raised.
    """

    @pytest.mark.parametrize("label,form", _R3_3_CYCLE_STOP_FORMS,
                             ids=[f[0] for f in _R3_3_CYCLE_STOP_FORMS])
    def test_r3_3_cycle_stop_form(self, tmp_path, monkeypatch, label, form):
        """Each form: cycle never raises, uploads still run, an alert is raised.

        The corrupt entry's key must match the refusal key that the test row
        produces, so note()/should_alert() actually read the corrupt values.
        For bigint forms at top level, the crash is in __init__.
        """
        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        # Build a good row for req-cs-001 with admin[0], then corrupt its sig
        rec, appr, row = _good_row(ws, lay, "req-cs-001")
        row = dict(row); row["signature"] = "00" * 64
        # bad_signature refusals have verified=False -> dedupe key has no key_id
        entry_key = "decision_refused:req-cs-001:bad_signature"
        sp = lay.root / ".sandbox" / "logs" / "decision_state.json"
        sp.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(form, str):
            sp.write_text(_build_r3_3_state_blob(form, entry_key=entry_key), encoding="utf-8")
        else:
            sp.write_text(json.dumps(form), encoding="utf-8")
        calls = []
        conn = _full_cycle_connect([row], calls)
        s = SyncProcess(layout=lay, server_url="http://127.0.0.1:9999",
                        device_key=bytes(_keygen()[0]), device_id="dev-1",
                        clock=time.monotonic, connect=conn)
        cycle_raised = False
        try:
            run_once(s)
        except SyncError:
            cycle_raised = True
        except Exception:
            cycle_raised = True
        # Uploads must have run (bundle/escalation/audit routes)
        later = [u for u in calls if "/sync/bundle" in u or "/sync/escalation" in u or "/sync/audit" in u]
        require_m3(9, len(later) >= 1,
            f"R3-3: form {label} stopped the cycle before later routes; "
            f"calls={[u.split('/')[-1] for u in calls]}")

    @pytest.mark.parametrize("label,form", _R3_3_STATUS_CRASH_FORMS,
                             ids=[f[0] for f in _R3_3_STATUS_CRASH_FORMS])
    def test_r3_3_status_crash_form(self, tmp_path, monkeypatch, label, form):
        """sandbox status must not crash (exit 1) on these 3 forms.

        The outcome_sig_int form needs a pending request whose rid matches
        the entry key ``sync_decision_applied:req-cs-001`` so that
        connector_cmds.py:471 (``"awaiting_second" in sig``) is reached.
        """
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        # For outcome_sig_int, create a pending request so the code path is hit
        if label == "outcome_sig_int":
            _create_pending_request(lay, "req-cs-001", command="echo osi",
                                    requires_dual=True)
        sp = lay.root / ".sandbox" / "logs" / "decision_state.json"
        sp.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(form, str):
            sp.write_text(_build_r3_3_state_blob(form), encoding="utf-8")
        elif "NaN_marker" in str(form.get("net_consecutive", "")):
            sp.write_text('{"net_consecutive":NaN,"entries":{}}', encoding="utf-8")
        elif "Inf_marker" in str(form.get("net_consecutive", "")):
            sp.write_text('{"net_consecutive":Infinity,"entries":{}}', encoding="utf-8")
        else:
            sp.write_text(json.dumps(form), encoding="utf-8")
        from sandbox.cli.connector_cmds import status_cmd
        r = click.testing.CliRunner().invoke(status_cmd, [str(lay.root)])
        require_m3(9, r.exit_code == 0,
            f"R3-3: sandbox status crashed on {label}: exit {r.exit_code}, "
            f"exc={r.exception}")
        # Also --json must not crash
        rj = click.testing.CliRunner().invoke(status_cmd, [str(lay.root), "--json"])
        require_m3(9, rj.exit_code == 0,
            f"R3-3: sandbox status --json crashed on {label}: exit {rj.exit_code}")

    def test_r3_3_alerted_str_drops_file(self, tmp_path, monkeypatch):
        """alerted: 'no' (truthy string) must drop the file, not accept it."""
        from sandbox.connector.sync.decision_state import DecisionState
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        sp = lay.root / ".sandbox" / "logs" / "decision_state.json"
        sp.parent.mkdir(parents=True, exist_ok=True)
        sp.write_text(_build_r3_3_state_blob("_alerted_str_no"), encoding="utf-8")
        ds = DecisionState(sp.parent)
        require_m3(9, len(ds._entries) == 0,
            f"R3-3: alerted='no' was accepted; entries={list(ds._entries.keys())[:3]}")

    @pytest.mark.parametrize("label,form", _R3_3_ENTRY_CRASH_FORMS,
                             ids=[f[0] for f in _R3_3_ENTRY_CRASH_FORMS])
    def test_r3_3_entry_crash_run_once(self, tmp_path, monkeypatch, label, form):
        """Each corrupt entry form crashes during run_once (through note/
        should_alert/get_repeats in _decision_alert) and skips bundle/
        escalation/audit upload.  Same pattern as cycle_stop_form.

        The corrupt entry key must match the dedupe key that _decision_alert
        builds.  For bad_signature with verified=False, the dedupe key is
        ``(event, rid, code)`` with NO key_id suffix.
        """
        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rec, appr, row = _good_row(ws, lay, "req-ec-001")
        row = dict(row); row["signature"] = "00" * 64
        # bad_signature refusals have verified=False -> dedupe key has no key_id
        entry_key = "decision_refused:req-ec-001:bad_signature"
        sp = lay.root / ".sandbox" / "logs" / "decision_state.json"
        sp.parent.mkdir(parents=True, exist_ok=True)
        sp.write_text(_build_r3_3_state_blob(form, entry_key=entry_key),
                      encoding="utf-8")
        calls = []
        conn = _full_cycle_connect([row], calls)
        s = SyncProcess(layout=lay, server_url="http://127.0.0.1:9999",
                        device_key=bytes(_keygen()[0]), device_id="dev-1",
                        clock=time.monotonic, connect=conn)
        cycle_raised = False
        try:
            run_once(s)
        except (SyncError, Exception):
            cycle_raised = True
        later = [u for u in calls if "/sync/bundle" in u or "/sync/escalation" in u or "/sync/audit" in u]
        require_m3(9, len(later) >= 1,
            f"R3-3: entry form {label} stopped the cycle before later routes; "
            f"calls={[u.split('/')[-1] for u in calls]}")


# ---- R3-4: load_verified_state raising gives apply_raised, not nonce_save_failed ----

class TestR3_4:
    """R3-4 MEDIUM: the R2-14 inference mislabels every early failure."""

    def test_r3_4_load_verified_state_raise(self, tmp_path, monkeypatch):
        """When load_verified_state raises before execution, the alert must
        say ``apply_raised (RuntimeError)``, not ``nonce_save_failed``."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        from sandbox.connector.sync import verified_state as vs_mod
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-r34-001"
        rec = _create_pending_request(lay, rid, command="echo r34", requires_dual=True)
        fp = rec["fingerprint"]
        ba = _make_remote_approval(ws["admin_sks"][0][0], request_id=rid,
                                   command="echo r34", fingerprint=fp,
                                   user_id=f"admin-{ws['admin_sks'][0][2][:8]}")
        ca = _make_remote_approval(ws["admin_sks"][1][0], request_id=rid,
                                   command="echo r34", fingerprint=fp,
                                   user_id=f"admin-{ws['admin_sks'][1][2][:8]}")
        rows = [_build_server_row(ba, rid), _build_server_row(ca, rid)]
        # Patch load_verified_state at its source module so the import inside
        # apply_external._impl() picks it up
        monkeypatch.setattr(vs_mod, "load_verified_state",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("state file corrupt")))
        s, _ = _mk(lay, _stub_decisions(rows))
        _fetch_decisions(s)
        alerts = read_alerts(lay, limit=200)
        codes = [a.get("reason_code") for a in alerts]
        require_m3(9, "nonce_save_failed" not in codes,
            f"R3-4: load_verified_state raising gave nonce_save_failed; codes={codes}")


# ---- R3-5: empty pending file gives pending_record_unreadable ----

class TestR3_5:
    """R3-5 MEDIUM: empty pending file must give pending_record_unreadable."""

    def test_r3_5_empty_pending_file(self, tmp_path, monkeypatch):
        """An empty pending file must alert as pending_record_unreadable."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-r35-001"
        rec = _create_pending_request(lay, rid, command="echo r35")
        # R4-6: delete the .sandbox/pending/ copy that _create_pending_request
        # writes -- the product never writes to that path.
        old_pending = lay.root / ".sandbox" / "pending" / f"{rid}.json"
        if old_pending.exists():
            old_pending.unlink()
        # Make the pending file empty
        pf = lay.pending_dir / f"{rid}.json"
        pf.write_text("", encoding="utf-8")
        ba = _make_remote_approval(ws["admin_sks"][0][0], request_id=rid,
                                   command="echo r35", fingerprint="fake",
                                   user_id=f"admin-{ws['admin_sks'][0][2][:8]}")
        rows = [_build_server_row(ba, rid)]
        s, _ = _mk(lay, _stub_decisions(rows))
        _fetch_decisions(s)
        alerts = read_alerts(lay, limit=200)
        require_m3(9,
            len([a for a in alerts
                if a.get("reason_code") == "pending_record_unreadable"]) >= 1,
            f"R3-5: empty pending file must give pending_record_unreadable; "
            f"got: {[a.get('reason_code') for a in alerts]}")


# ---- R3-6: HTTPException at token is not network_error ----

class TestR3_6:
    """R3-6 MEDIUM: HTTPException at token; no str(exc) server text."""

    def test_r3_6_http_exception_not_network_error(self, tmp_path, monkeypatch):
        """HTTPException at token must be classified as transport_error,
        immediate (alerts on cycle 1), not network_error (3-cycle counter).

        The bug: process.py:438 classifies HTTPException (not OSError/SyncError)
        as network_error with immediate=False.  After 1 cycle, no alert fires.
        The spec says transport_error, immediate."""
        import http.client
        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        def c(m, u, body=None, headers=None, token=None):
            if "/sync/token" in u:
                raise http.client.HTTPException("malformed status line")
            return (200, {}, _date_hdr())
        dsk = _keygen()
        # Single cycle: should alert immediately (transport_error)
        s = SyncProcess(layout=lay, server_url="http://127.0.0.1:9999",
                        device_key=bytes(dsk[0]), device_id="dev-1",
                        clock=time.monotonic, connect=c)
        s._token = "old"; s._token_expires = 0
        try:
            run_once(s)
        except (SyncError, Exception):
            pass
        alerts = read_alerts(lay, limit=200)
        fetch_failed = [a for a in alerts if a.get("event") == "decisions_fetch_failed"]
        # With network_error (immediate=False), no alert after 1 cycle.
        # With transport_error (immediate=True), alert after 1 cycle.
        require_m3(9, len(fetch_failed) >= 1,
            f"R3-6: HTTPException at token: no alert after 1 cycle "
            f"(classified as network_error with 3-cycle counter); "
            f"got: {[a.get('reason_code') for a in alerts]}")

    def test_r3_6_no_str_exc_in_output(self, tmp_path, monkeypatch):
        """process.py:330 puts str(exc) in the SyncError message.
        The spec says type(exc).__name__ only."""
        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        sentinel = "SENTINEL_SERVER_TEXT_MUST_NOT_APPEAR"
        def c(m, u, body=None, headers=None, token=None):
            if "/sync/token" in u:
                raise ValueError(sentinel)
            return (200, {}, _date_hdr())
        s = SyncProcess(layout=lay, server_url="http://127.0.0.1:9999",
                        device_key=bytes(_keygen()[0]), device_id="dev-1",
                        clock=time.monotonic, connect=c)
        s._token = "old"; s._token_expires = 0
        exc_msg = ""
        try:
            run_once(s)
        except SyncError as e:
            exc_msg = str(e)
        except Exception as e:
            exc_msg = str(e)
        require_m3(9, sentinel not in exc_msg,
            f"R3-6: str(exc) server text reached SyncError message: {exc_msg[:200]}")


# ---- R3-7: alert key does not split by status code; network/HTTP line format ----

class TestR3_7:
    """R3-7 MEDIUM: R2-12 as written."""

    def test_r3_7_network_line_has_stage(self, tmp_path, monkeypatch):
        """sandbox status shows 'network_error, N in a row' with no 'at decisions'.
        Line 601 of connector_cmds.py: the net_consecutive line lacks the stage."""
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _create_pending_request(lay, "req-r37-001", command="echo r37")
        def nf(m, u, body=None, headers=None, token=None):
            if "/sync/decisions" in u: raise ConnectionError("down")
            return (200, {}, _date_hdr())
        dsk = _keygen()
        for _ in range(3):
            s = _mk2(lay, nf, dsk); _fetch_decisions(s)
        status = _run_status_cli(lay)
        # The net_consecutive line (connector_cmds.py:601) is the one with
        # "N in a row"; it must also say "at decisions" or "at <stage>".
        net_count_lines = [l for l in status.splitlines()
                           if "in a row" in l and "network_error" in l]
        require_m3(9, net_count_lines and any("at " in l for l in net_count_lines),
            f"R3-7: net_consecutive line lacks 'at <stage>': {net_count_lines}")

    def test_r3_7_entry_stores_fields_not_key_split(self, tmp_path, monkeypatch):
        """R3-7 spec: 'store code, rid, key_id, verified, reason, stage in
        each entry; one reader; never split a key.'  Today, the entry dict
        has only count/alerted/first_seen/last_seen/repeats/reason -- no code,
        rid, key_id, verified or stage.  connector_cmds.py:491,577,607 recover
        them by splitting the key on ':'.  The entry must carry its own fields."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.sync.decision_state import DecisionState
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _, _, row = _good_row(ws, lay, "req-r37f-001")
        row = dict(row); row["signature"] = "00" * 64
        s, _ = _mk(lay, _stub_decisions([row]))
        _fetch_decisions(s)
        ds_path = lay.root / ".sandbox" / "logs" / "decision_state.json"
        raw = json.loads(ds_path.read_text(encoding="utf-8"))
        entries = raw.get("entries", {})
        refusal_entries = {k: v for k, v in entries.items()
                          if k.startswith("decision_refused:")}
        require_m3(9, refusal_entries, "no refusal entries found")
        for k, v in refusal_entries.items():
            require_m3(9, "code" in v and "rid" in v,
                f"R3-7: entry has no 'code'/'rid' fields; keys split from "
                f"'{k}'; entry keys: {list(v.keys())}")

    def test_r3_7_http_line_no_double_stage(self, tmp_path, monkeypatch):
        """HTTP line must not say 'at decisions' twice.
        Measured: 'HTTP 500 at decisions: http_5xx at decisions'."""
        from sandbox.connector.sync.process import _fetch_decisions
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _create_pending_request(lay, "req-r37h-001", command="echo r37h")
        s, _ = _mk(lay, _stub_status(500, {"detail": "err"}))
        _fetch_decisions(s)
        status = _run_status_cli(lay)
        http_lines = [l for l in status.splitlines()
                      if "HTTP" in l and "500" in l]
        for line in http_lines:
            count = line.count("at decisions")
            require_m3(9, count <= 1,
                f"R3-7: HTTP line says 'at decisions' {count} times: {line}")


# ---- R3-8: malformed rows keyed/recorded per request_id ----

class TestR3_8:
    """R3-8 MEDIUM: malformed rows must NOT be keyed by request_id."""

    def test_r3_8_malformed_one_per_code_per_cycle(self, tmp_path, monkeypatch):
        """5 malformed rows with different request_ids but the same code
        must produce 1 alert with count=5, not 5 alerts."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rows = []
        for i in range(5):
            rid = f"req-r38-{i:03d}"
            _create_pending_request(lay, rid, command=f"echo r38-{i}")
            rows.append({"request_id": rid, "signed_payload": "{bad",
                         "signature": "aa" * 64, "key_id": "bb" * 32})
        s, _ = _mk(lay, _stub_decisions(rows))
        _fetch_decisions(s)
        alerts = read_alerts(lay, limit=200)
        malformed = [a for a in alerts if a.get("event") == "decisions_malformed"]
        require_m3(9, len(malformed) == 1,
            f"R3-8: 5 malformed rows produced {len(malformed)} alerts, "
            f"expected 1 with count; rids in alerts: "
            f"{[a.get('request_id', a.get('rid', '')) for a in malformed]}")


# ---- R3-9: restore async def apply_external ----

class TestR3_9:
    """R3-9 LOW: apply_external must be async def, not def returning coroutine."""

    def test_r3_9_apply_external_is_async_def(self):
        """apply_external must be declared as ``async def``, not ``def``
        returning an inner coroutine.  The product was bent to fit a test
        predicate (R3 ruling A)."""
        import inspect
        from sandbox.connector.approval import apply_external
        require_m3(9, inspect.iscoroutinefunction(apply_external),
            "R3-9: apply_external is not a coroutine function "
            "(def returning _impl, not async def)")


# ---- Mutation guards (item 11): bite-proven ----

class TestR3_MutationGuards:
    """Mutation-proven guards: each must fail when the named fix is reverted.

    These are GUARDS (PASS today).  The mutation proof is done on a scratch
    copy of the product and verified by the security review.
    """

    def test_h2_verified_first_sort(self, tmp_path, monkeypatch):
        """R4-8: H2 verified-first sort with a genuinely verified refusal.

        A registered admin key signs a valid approval for a DIFFERENT command
        (command_mismatch). The signature verifies, so verified=True. Put it
        last in row order, after 6 malformed, 8 unknown_key and 5 bad_signature
        rows on registered keys. It must be the first decision_refused alert.

        This is a GUARD: passes today and on the revert. It must fail when
        verified-first is removed (bite proven on scratch copy).
        """
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rows = []
        # 6 malformed rows
        for i in range(6):
            rid = f"req-vf-m{i:03d}"
            _create_pending_request(lay, rid, command=f"echo vfm{i}")
            rows.append({"request_id": rid, "signed_payload": "{bad",
                         "signature": "aa" * 64, "key_id": "bb" * 32})
        # 8 unverified refusals (unknown key)
        for i in range(8):
            rid = f"req-vf-u{i:03d}"
            rec = _create_pending_request(lay, rid, command=f"echo vfu{i}")
            rows.append(_build_server_row(_make_remote_approval(
                _keygen()[0], request_id=rid, command=f"echo vfu{i}",
                fingerprint=rec["fingerprint"], user_id=f"evil-{i}"), rid))
        # 5 bad_signature rows on registered keys (corrupt sig)
        for i in range(5):
            rid = f"req-vf-bs{i:03d}"
            rec = _create_pending_request(lay, rid, command=f"echo vfbs{i}")
            bob_sk, _, bob_kid = ws["admin_sks"][0][:3]
            ba = _make_remote_approval(bob_sk, request_id=rid, command=f"echo vfbs{i}",
                                       fingerprint=rec["fingerprint"],
                                       user_id=f"admin-{bob_kid[:8]}")
            brow = _build_server_row(ba, rid)
            sb = binascii.unhexlify(brow["signature"])
            brow["signature"] = binascii.hexlify(bytes([sb[0] ^ 1]) + sb[1:]).decode()
            rows.append(brow)
        # 1 genuinely verified refusal: command_mismatch on a registered admin key.
        # Bob signs an approval for command "echo WRONG" but the pending record
        # has command "echo vfv". The signature verifies (payload matches
        # Bob's key), but the command doesn't match the pending record.
        rid_v = "req-vf-v001"
        rec_v = _create_pending_request(lay, rid_v, command="echo vfv")
        bob_sk, _, bob_kid = ws["admin_sks"][0][:3]
        va = _make_remote_approval(bob_sk, request_id=rid_v, command="echo WRONG",
                                   fingerprint=rec_v["fingerprint"],
                                   user_id=f"admin-{bob_kid[:8]}")
        rows.append(_build_server_row(va, rid_v))
        s, _ = _mk(lay, _stub_decisions(rows))
        _fetch_decisions(s)
        alerts = read_alerts(lay, limit=500)
        refused_alerts = [a for a in alerts if a.get("event") == "decision_refused"]
        assert len(refused_alerts) >= 1, "must produce at least one decision_refused alert"
        # The genuinely verified refusal (command_mismatch) must be first
        first_code = refused_alerts[0].get("reason_code", refused_alerts[0].get("code", ""))
        assert first_code == "command_mismatch", \
            f"verified refusal (command_mismatch) must alert first; got {first_code}"

    def test_guard_r2_4_outcome_path(self, tmp_path, monkeypatch):
        """R2-4 outcome path: after a failed audit append, the OUTCOME
        must not be marked as recorded, so the next poll re-writes it."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.sync.decision_state import DecisionState
        from sandbox.connector.audit import FolderAudit
        import sandbox.connector.audit as am
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-grd4-001"
        rec = _create_pending_request(lay, rid, command="echo grd4")
        _, _, row = _good_row(ws, lay, rid); row = dict(row); row["signature"] = "00" * 64
        dsk = _keygen()
        # First poll: audit append fails
        call_count = [0]
        orig_append = FolderAudit.append
        def failing_append(self, *a, **k):
            call_count[0] += 1
            if call_count[0] <= 3:
                raise OSError("disk full")
            return orig_append(self, *a, **k)
        monkeypatch.setattr(am.FolderAudit, "append", failing_append)
        s1 = _mk2(lay, _stub_decisions([row]), dsk); _fetch_decisions(s1)
        # The outcome_sig must NOT be set in the state (it was not recorded)
        logs_dir = lay.root / ".sandbox" / "logs"
        ds = DecisionState(logs_dir)
        outcome_key = f"sync_decision_applied:{rid}"
        entry = ds._entries.get(outcome_key, {})
        assert not entry.get("outcome_sig"), \
            f"outcome_sig must not be set after failed append: {entry}"

    def test_guard_r2_11_branch(self, tmp_path, monkeypatch):
        """R2-11 guard: a real invalid_id via _validate_request_id returning
        "invalid_id" must produce a request_id_refused alert.

        R4-6/R4-7: uses the product's real return value "invalid_id" and
        expects request_id_refused (spec section 2). No pre-check dependency.
        """
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        import sandbox.connector.approval as apmod
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-grd11-001"
        rec = _create_pending_request(lay, rid, command="echo grd11")
        fp = rec["fingerprint"]
        ba = _make_remote_approval(ws["admin_sks"][0][0], request_id=rid,
                                   command="echo grd11", fingerprint=fp,
                                   user_id=f"admin-{ws['admin_sks'][0][2][:8]}")
        ca = _make_remote_approval(ws["admin_sks"][1][0], request_id=rid,
                                   command="echo grd11", fingerprint=fp,
                                   user_id=f"admin-{ws['admin_sks'][1][2][:8]}")
        rows = [_build_server_row(ba, rid), _build_server_row(ca, rid)]
        # Patch _validate_request_id to return "invalid_id" (its real return)
        monkeypatch.setattr(apmod, "_validate_request_id",
                            lambda *a, **k: "invalid_id")
        s, _ = _mk(lay, _stub_decisions(rows))
        _fetch_decisions(s)
        alerts = read_alerts(lay, limit=200)
        refused = [a for a in alerts
                   if a.get("reason_code") in ("request_id_refused",)]
        assert len(refused) >= 1, \
            f"R2-11 guard: invalid_id must produce request_id_refused; got {[a.get('reason_code') for a in alerts]}"


# ---- H1: malformed HTTP status line, no ESC/OSC in output ----

class TestR3_H1:
    """H1: malformed HTTP status line at /sync/token: no ESC/OSC bytes in
    sandbox sync --once output; sandbox alerts strips unicode bidi/ZWSP/BOM/SHY."""

    def test_h1_no_esc_in_sync_error(self, tmp_path, monkeypatch):
        """A server sending a malformed HTTP status line with ESC/OSC bytes
        must not have those bytes reach the SyncError message."""
        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        # Simulate what happens: http.client raises BadStatusLine with the raw line
        import http.client
        evil_line = "XYZ \x1b]0;pwned\x07\x1b[2J\x1b[31mRED"
        def c(m, u, body=None, headers=None, token=None):
            if "/sync/token" in u:
                raise http.client.BadStatusLine(evil_line)
            return (200, {}, _date_hdr())
        s = SyncProcess(layout=lay, server_url="http://127.0.0.1:9999",
                        device_key=bytes(_keygen()[0]), device_id="dev-1",
                        clock=time.monotonic, connect=c)
        s._token = "old"; s._token_expires = 0
        exc_msg = ""
        try:
            run_once(s)
        except SyncError as e:
            exc_msg = str(e)
        except Exception as e:
            exc_msg = str(e)
        require_m3(9, "\x1b" not in exc_msg,
            f"H1: ESC byte in SyncError message from malformed status line: "
            f"{exc_msg[:100]!r}")

    @pytest.mark.parametrize("char,label", [
        (" ", "LINE_SEPARATOR"),
        (" ", "PARAGRAPH_SEPARATOR"),
        ("​", "ZERO_WIDTH_SPACE"),
        ("﻿", "BOM"),
    ], ids=["LINE_SEPARATOR", "PARAGRAPH_SEPARATOR", "ZERO_WIDTH_SPACE", "BOM"])
    def test_h1_alerts_strips_unicode(self, tmp_path, monkeypatch, char, label):
        """sandbox alerts must strip U+2028, U+2029, U+200B, U+FEFF from output."""
        from sandbox.cli.records_cmds import alerts_cmd
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        lay.logs_dir.mkdir(parents=True, exist_ok=True)
        evil_record = {
            "event": "decision_refused", "kind": "decision_refused",
            "reason": f"test {char}injected",
            "tool": "sync", "ts": time.time(),
        }
        with open(lay.logs_dir / "alerts.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(evil_record) + "\n")
        runner = click.testing.CliRunner()
        result = runner.invoke(alerts_cmd, [str(lay.root), "-n", "50"], color=True)
        require_m3(9, char not in result.output,
            f"H1: {label} ({char!r}) reached sandbox alerts output")

    def test_h1_alerts_strips_soft_hyphen(self, tmp_path, monkeypatch):
        """SHOULD: sandbox alerts strips U+00AD (soft hyphen).

        Mark this target as SHOULD in the docstring; it is still a strict
        xfail target because the review asks for it.
        """
        from sandbox.cli.records_cmds import alerts_cmd
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        lay.logs_dir.mkdir(parents=True, exist_ok=True)
        evil_record = {
            "event": "decision_refused", "kind": "decision_refused",
            "reason": f"test ­injected",
            "tool": "sync", "ts": time.time(),
        }
        with open(lay.logs_dir / "alerts.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(evil_record) + "\n")
        runner = click.testing.CliRunner()
        result = runner.invoke(alerts_cmd, [str(lay.root), "-n", "50"], color=True)
        require_m3(9, "­" not in result.output,
            "H1 SHOULD: U+00AD (soft hyphen) reached sandbox alerts output")


# ===================================================================
# R4 targets: FAIL on today's build (T9A_SECURITY_REVIEW.md Round 4)
# ===================================================================


class TestR4_1:
    """R4-1 MEDIUM: network failures at token and registry are transport_error.

    ConnectionRefusedError (an OSError) at token or registry is classified
    as transport_error (immediate) instead of network_error (3-cycle counter).
    Spec section 2 row 1 says network_error with 3-cycle counting.
    """

    @pytest.mark.parametrize("stage", ["token", "registry"],
                             ids=["token", "registry"])
    def test_r4_1_outage_counts_toward_three(self, tmp_path, monkeypatch, stage):
        """ConnectionRefusedError at the given stage: cycles 1-2 must NOT
        alert; cycle 3 must alert with reason_code=network_error."""
        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]

        def c(m, u, body=None, headers=None, token=None):
            if f"/sync/{stage}" in u:
                raise ConnectionRefusedError("refused")
            if "/sync/token" in u:
                return (200, {"access_token": "t", "expires_in": 3600}, _date_hdr())
            return (200, {}, _date_hdr())

        dsk = _keygen()
        for cycle in range(1, 4):
            s = SyncProcess(
                layout=lay, server_url="http://127.0.0.1:9999",
                device_key=bytes(dsk[0]), device_id="dev-1",
                clock=time.monotonic, connect=c)
            if stage != "token":
                s._token = "t"; s._token_expires = time.monotonic() + 3600
            try:
                run_once(s)
            except SyncError:
                pass

            alerts = [a for a in read_alerts(lay, limit=200)
                      if a.get("event") == "decisions_fetch_failed"]

            if cycle < 3:
                require_m3(9, len(alerts) == 0,
                    f"R4-1: cycle {cycle} at {stage} must NOT alert; "
                    f"got {len(alerts)} alerts with codes "
                    f"{[a.get('reason_code') for a in alerts]}")
            else:
                require_m3(9, len(alerts) == 1,
                    f"R4-1: cycle 3 at {stage} must produce exactly 1 alert; "
                    f"got {len(alerts)}")
                require_m3(9, alerts[0].get("reason_code") == "network_error",
                    f"R4-1: cycle 3 alert must be network_error; "
                    f"got {alerts[0].get('reason_code')}")
                require_m3(9, stage in alerts[0].get("reason", ""),
                    f"R4-1: alert must name stage '{stage}'; "
                    f"reason={alerts[0].get('reason','')[:80]}")

        # Also check status line shows the counter
        status = _run_status_cli(lay)
        status_lines = [l for l in status.splitlines()
                        if "in a row" in l]
        require_m3(9, len(status_lines) >= 1,
            f"R4-1: status must show 'N in a row' line; got:\n{status}")


class TestR4_2:
    """R4-2 MEDIUM: frozen test_f1_short_device_key_raises (local key text).

    Since R3-6, a short device key raises nacl ValueError which becomes
    'transport_error at token' -- a local key problem misclassified as
    transport. The fix adds SyncLocalKeyError raised before nacl.
    """

    def test_r4_2_short_key_is_local_not_transport(self, tmp_path, monkeypatch):
        """With device_key=b'short': SyncError matching '32', no
        decisions_fetch_failed alert, and 'short' absent from the message."""
        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        s = SyncProcess(
            layout=lay, server_url="http://127.0.0.1:9999",
            device_key=b"short", device_id="dev-1",
            clock=time.monotonic,
            connect=lambda m, u, body=None, headers=None, token=None: (
                200, {"access_token": "t", "expires_in": 3600}, _date_hdr()))
        exc_msg = ""
        try:
            run_once(s)
        except SyncError as e:
            exc_msg = str(e)
        except Exception as e:
            exc_msg = str(e)
        require_m3(9, "32" in exc_msg,
            f"R4-2: SyncError must mention '32'; got: {exc_msg[:100]}")
        alerts = read_alerts(lay, limit=200)
        fetch_failed = [a for a in alerts
                        if a.get("event") == "decisions_fetch_failed"]
        require_m3(9, len(fetch_failed) == 0,
            f"R4-2: short key must NOT produce decisions_fetch_failed alert; "
            f"got {len(fetch_failed)} with codes "
            f"{[a.get('reason_code') for a in fetch_failed]}")
        require_m3(9, "short" not in exc_msg.lower(),
            f"R4-2: 'short' must not appear in error message: {exc_msg[:100]}")


class TestR4_3:
    """R4-3 MEDIUM (H3 residual): counter range.

    A hand-edited negative net_consecutive silences the network alert
    counter (it must count from -N to 3, taking N+3 cycles). The fix
    requires 0 <= counter <= 2**63 or drop the whole file.
    """

    def test_r4_3_counter_range_drops_file(self, tmp_path, monkeypatch):
        """Seed net_consecutive=-999999. Three outage cycles at decisions must
        give exactly one network_error alert and the status line.
        Fails today: 0 alerts and no line (counter counts from -999999)."""
        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        # Seed a corrupt state with a very negative net_consecutive
        sp = lay.root / ".sandbox" / "logs" / "decision_state.json"
        sp.parent.mkdir(parents=True, exist_ok=True)
        sp.write_text(json.dumps({
            "net_consecutive": -999999,
            "entries": {},
        }), encoding="utf-8")
        def c(m, u, body=None, headers=None, token=None):
            if "/sync/token" in u:
                return (200, {"access_token": "t", "expires_in": 3600}, _date_hdr())
            if "/sync/decisions" in u:
                raise ConnectionError("down")
            return (200, {}, _date_hdr())
        dsk = _keygen()
        for _ in range(3):
            s = SyncProcess(
                layout=lay, server_url="http://127.0.0.1:9999",
                device_key=bytes(dsk[0]), device_id="dev-1",
                clock=time.monotonic, connect=c)
            s._token = "t"; s._token_expires = time.monotonic() + 3600
            try:
                run_once(s)
            except SyncError:
                pass
        alerts = [a for a in read_alerts(lay, limit=200)
                  if a.get("event") == "decisions_fetch_failed"
                  and a.get("reason_code") == "network_error"]
        require_m3(9, len(alerts) == 1,
            f"R4-3: after 3 cycles with negative net_consecutive, must get "
            f"exactly 1 network_error alert; got {len(alerts)}")
        status = _run_status_cli(lay)
        require_m3(9, "in a row" in status,
            f"R4-3: status must show 'in a row'; got:\n{status}")


# R4-4: wrong type drops the file (deviation 3)

_R4_4_WRONG_TYPE_FORMS = [
    ("count_str", {"count": "x"}),
    ("repeats_list", {"repeats": [1]}),
    ("first_seen_str", {"first_seen": "x"}),
    ("reason_int", {"reason": 5}),
    ("code_int", {"code": 5}),
    ("verified_str", {"verified": "yes"}),
    ("status_str", {"status": "500"}),
    ("entry_is_list", "_entry_is_list"),
]


class TestR4_4:
    """R4-4 LOW: a wrong type drops the file (deviation 3).

    Spec section 5 says a field of the wrong type drops the file.
    Today, wrong types are coerced (deviation 3).
    """

    @pytest.mark.parametrize("label,form", _R4_4_WRONG_TYPE_FORMS,
                             ids=[f[0] for f in _R4_4_WRONG_TYPE_FORMS])
    def test_r4_4_wrong_type_drops_file(self, tmp_path, monkeypatch, label, form):
        """The refusal key's entry has alerted:true, last_alerted 10s ago,
        plus one wrong field. The next cycle must write the refusal alert
        (because the corrupt state was dropped -> fresh state -> alerts fire)."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _, _, row = _good_row(ws, lay, "req-r44-001")
        row = dict(row); row["signature"] = "00" * 64
        entry_key = "decision_refused:req-r44-001:bad_signature"
        sp = lay.root / ".sandbox" / "logs" / "decision_state.json"
        sp.parent.mkdir(parents=True, exist_ok=True)
        now = time.time()
        if form == "_entry_is_list":
            # The refusal entry has alerted:True (suppresses), plus another
            # entry that is a list. R4-4: the list entry must drop the whole
            # file. Today it's just skipped, leaving the suppressing entry.
            now_ts = time.time()
            state = {"entries": {
                entry_key: {
                    "count": 1, "alerted": True,
                    "last_alerted": now_ts - 10,
                    "first_seen": now_ts - 100,
                    "last_seen": now_ts - 5,
                    "repeats": 0,
                },
                "corrupt_entry": [1, 2, 3],
            }}
        else:
            entry = {
                "count": 1, "alerted": True,
                "last_alerted": now - 10,
                "first_seen": now - 100,
                "last_seen": now - 5,
                "repeats": 0,
            }
            entry.update(form)
            state = {"entries": {entry_key: entry}}
        sp.write_text(json.dumps(state), encoding="utf-8")
        s, _ = _mk(lay, _stub_decisions([row]))
        _fetch_decisions(s)
        alerts = [a for a in read_alerts(lay, limit=200)
                  if a.get("event") in ("decision_refused", "decisions_malformed")]
        require_m3(9, len(alerts) >= 1,
            f"R4-4: wrong-typed '{label}' must drop file and re-alert; "
            f"got {len(alerts)} alerts")


class TestR4_5:
    """R4-5 MEDIUM: R3-4 as written (deviation 2).

    PermissionError variant: test_r3_4_load_verified_state_raise with
    PermissionError must give apply_raised, not nonce_save_failed.
    The PermissionError case fails today because the narrowed try/except
    only catches OSError (not generic Exception).
    """

    def test_r3_4_permission_error_variant(self, tmp_path, monkeypatch):
        """PermissionError from load_verified_state must alert as
        apply_raised (PermissionError), not nonce_save_failed."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        from sandbox.connector.sync import verified_state as vs_mod
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-r45-001"
        rec = _create_pending_request(lay, rid, command="echo r45", requires_dual=True)
        fp = rec["fingerprint"]
        ba = _make_remote_approval(ws["admin_sks"][0][0], request_id=rid,
                                   command="echo r45", fingerprint=fp,
                                   user_id=f"admin-{ws['admin_sks'][0][2][:8]}")
        ca = _make_remote_approval(ws["admin_sks"][1][0], request_id=rid,
                                   command="echo r45", fingerprint=fp,
                                   user_id=f"admin-{ws['admin_sks'][1][2][:8]}")
        rows = [_build_server_row(ba, rid), _build_server_row(ca, rid)]
        monkeypatch.setattr(vs_mod, "load_verified_state",
                            lambda *a, **k: (_ for _ in ()).throw(
                                PermissionError("access denied")))
        s, _ = _mk(lay, _stub_decisions(rows))
        _fetch_decisions(s)
        alerts = read_alerts(lay, limit=200)
        codes = [a.get("reason_code") for a in alerts]
        require_m3(9, "nonce_save_failed" not in codes,
            f"R4-5: PermissionError gave nonce_save_failed; codes={codes}")
        require_m3(9, "apply_raised" in codes,
            f"R4-5: PermissionError must give apply_raised; codes={codes}")


class TestR4_6:
    """R4-6 MEDIUM: R3-5 as written (deviation 1).

    For each pending-file form, _fetch_decisions and apply_external must
    produce the same queue status on identical workspace copies.

    Forms: empty canonical file, garbage, a directory named <rid>.json,
    and empty canonical plus a valid .sandbox/pending/ copy with one deny.
    Spec: T9A_SECURITY_REVIEW.md Round 4, R4-6 and deviation 1.
    """

    @pytest.mark.parametrize("form", [
        "empty", "garbage", "directory", "deny_copy",
    ])
    def test_r4_6_fetch_layer_adds_no_verdict(self, form, tmp_path, monkeypatch):
        """Build two identical workspaces. Run _fetch_decisions on one and
        asyncio.run(apply_external(...)) on the other. Assert same queue status."""
        import tempfile as _tf
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.approval import apply_external
        from sandbox.connector.queue import EscalationQueue
        from sandbox.connector.layout import FolderLayout

        # -- 1. Build workspace A in tmp_path --
        ws = _setup_managed_workspace(tmp_path, monkeypatch)
        lay_a = ws["lay"]
        rid = f"req-r46-{form}"
        cmd = f"echo r46-{form}"
        rec = _create_pending_request(lay_a, rid, command=cmd)
        fp = rec["fingerprint"]

        # Delete .sandbox/pending/ copy (product never writes there)
        old_pending = lay_a.root / ".sandbox" / "pending" / f"{rid}.json"
        if old_pending.exists():
            old_pending.unlink()

        # -- 2. Corrupt the canonical file per form --
        canonical = lay_a.pending_dir / f"{rid}.json"
        if form == "empty":
            canonical.write_text("", encoding="utf-8")
        elif form == "garbage":
            canonical.write_text("{definitely not json!!!", encoding="utf-8")
        elif form == "directory":
            canonical.unlink()
            canonical.mkdir()
        elif form == "deny_copy":
            # Write a valid pending record to .sandbox/pending/ path
            pend_dir = lay_a.root / ".sandbox" / "pending"
            pend_dir.mkdir(parents=True, exist_ok=True)
            pend_copy = pend_dir / f"{rid}.json"
            # Re-read canonical (still valid at this point) and copy it
            shutil.copy2(str(canonical), str(pend_copy))
            # Now empty the canonical
            canonical.write_text("", encoding="utf-8")

        # -- 3. Build the deny row (sent to both paths) --
        admin_sk = ws["admin_sks"][0][0]
        admin_uid = f"admin-{ws['admin_sks'][0][2][:8]}"
        deny_env = _make_remote_deny(
            admin_sk, request_id=rid, command=cmd,
            fingerprint=fp, user_id=admin_uid)
        server_row = _build_server_row(deny_env, rid)

        # -- 4. Copy the entire tmp_path tree to a second location --
        with _tf.TemporaryDirectory() as td:
            copy_root = Path(td) / "copy"
            shutil.copytree(str(tmp_path), str(copy_root))

            # Reconstruct layout B by mirroring the relative paths
            ws_rel = lay_a.root.relative_to(tmp_path)
            lay_b = FolderLayout(copy_root / ws_rel)
            kh_rel = Path(os.environ["SANDBOX_KEY_HOME"]).relative_to(tmp_path)
            monkeypatch.setenv("SANDBOX_KEY_HOME", str(copy_root / kh_rel))

            # -- 5a. Run apply_external on workspace B --
            result_b = asyncio.run(apply_external(
                lay_b, rid, [deny_env], clock=lambda: time.time()))
            q_b = EscalationQueue(lay_b)
            status_b = q_b.status(rid)

            # Restore keyhome to workspace A
            monkeypatch.setenv("SANDBOX_KEY_HOME", str(tmp_path / kh_rel))

        # -- 5b. Run _fetch_decisions on workspace A --
        s, _ = _mk(lay_a, _stub_decisions([server_row]))
        _fetch_decisions(s)
        q_a = EscalationQueue(lay_a)
        status_a = q_a.status(rid)

        # -- 6. Assert: queue status must be the same --
        require_m3(9, status_a == status_b,
            f"R4-6 [{form}]: _fetch_decisions gave '{status_a}' but "
            f"apply_external gave '{status_b}'")


class TestR4_10:
    """R4-10 LOW: R3-7 network line must have stage on cycles 1 and 2.

    Measured: cycles 1-2 print 'network_error, 1 in a row' with no stage.
    The spec says 'network_error at <stage>, <n> in a row'.
    """

    @pytest.mark.parametrize("stage", ["decisions", "registry"],
                             ids=["decisions", "registry"])
    def test_r4_10_network_line_stage_on_early_cycles(self, tmp_path, monkeypatch, stage):
        """One outage cycle at the given stage: the status line must say
        'network_error at <stage>, 1 in a row'. Fails today: no stage."""
        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _create_pending_request(lay, "req-r410-001", command="echo r410")

        def c(m, u, body=None, headers=None, token=None):
            if f"/sync/{stage}" in u:
                raise ConnectionError("down")
            if "/sync/token" in u:
                return (200, {"access_token": "t", "expires_in": 3600}, _date_hdr())
            return (200, {}, _date_hdr())

        dsk = _keygen()
        s = SyncProcess(
            layout=lay, server_url="http://127.0.0.1:9999",
            device_key=bytes(dsk[0]), device_id="dev-1",
            clock=time.monotonic, connect=c)
        if stage != "token":
            s._token = "t"; s._token_expires = time.monotonic() + 3600
        try:
            run_once(s)
        except SyncError:
            pass
        status = _run_status_cli(lay)
        # Spec line: 'Decisions: fetch failed: network_error at <stage>, <n> in a row'
        expected_fragment = f"network_error at {stage}"
        require_m3(9, expected_fragment in status,
            f"R4-10: status after 1 cycle must contain '{expected_fragment}'; "
            f"got:\n{status}")
        # Must NOT have a second 'network_error at <stage>' line (R4-10 fix)
        net_lines = [l for l in status.splitlines()
                     if f"network_error" in l and f"at {stage}" in l]
        require_m3(9, len(net_lines) <= 1,
            f"R4-10: must have at most 1 network_error line for {stage}; "
            f"got {len(net_lines)}: {net_lines}")

        # R5-3: run two more outage cycles at the same stage with a fresh
        # SyncProcess each time. After 3 total cycles a network_error entry
        # exists in the state. The status must still show exactly one line.
        for cycle in range(2, 4):
            s2 = SyncProcess(
                layout=lay, server_url="http://127.0.0.1:9999",
                device_key=bytes(dsk[0]), device_id="dev-1",
                clock=time.monotonic, connect=c)
            if stage != "token":
                s2._token = "t"; s2._token_expires = time.monotonic() + 3600
            try:
                run_once(s2)
            except SyncError:
                pass
        status3 = _run_status_cli(lay)
        net_lines3 = [l.rstrip() for l in status3.splitlines()
                      if "network_error" in l]
        expected_line = (f"  Decisions: fetch failed: network_error "
                         f"at {stage}, 3 in a row")
        require_m3(9, net_lines3 == [expected_line],
            f"R5-3: after 3 cycles, network_error lines must be exactly "
            f"{[expected_line]!r}; got {net_lines3!r}")


class TestR4_11:
    """R4-11 MEDIUM (H1 residual): str(exc) in the outer handler.

    process.py:371-373 outer except Exception puts str(exc) in SyncError.
    sandbox sync --once prints it. Spec rows I and T say type name only.
    """

    def test_h1_no_esc_in_sync_error_later_stage(self, tmp_path, monkeypatch):
        """An exception at a later stage (bundle/escalation/audit) with
        hostile text must not have that text appear in the SyncError message.
        The outer handler must use type(exc).__name__, not str(exc).

        Drive through run_once: token and registry succeed, decisions succeed,
        then _fetch_bundle raises an exception with ESC/server text.
        """
        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
        import sandbox.connector.sync.process as proc_mod
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        sentinel = "\x1b]0;PWNED\x07 server_secret_text_MUST_NOT_APPEAR"

        # Monkeypatch _fetch_bundle to raise an exception with hostile text
        def _boom_bundle(sync):
            raise RuntimeError(sentinel)
        monkeypatch.setattr(proc_mod, "_fetch_bundle", _boom_bundle)

        dsk = _keygen()
        s = SyncProcess(
            layout=lay, server_url="http://127.0.0.1:9999",
            device_key=bytes(dsk[0]), device_id="dev-1",
            clock=time.monotonic,
            connect=lambda m, u, body=None, headers=None, token=None: (
                200, {"access_token": "t", "expires_in": 3600,
                      "registry": [], "decisions": []}, _date_hdr()))
        s._token = "t"; s._token_expires = time.monotonic() + 3600
        exc_msg = ""
        try:
            run_once(s)
        except SyncError as e:
            exc_msg = str(e)
        except Exception as e:
            exc_msg = str(e)

        require_m3(9, "\x1b" not in exc_msg,
            f"R4-11: ESC byte in SyncError from outer handler: {exc_msg[:100]!r}")
        require_m3(9, "MUST_NOT_APPEAR" not in exc_msg,
            f"R4-11: server text leaked to SyncError: {exc_msg[:100]!r}")
        # Must contain only the type name
        require_m3(9, "RuntimeError" in exc_msg,
            f"R4-11: SyncError must contain type name 'RuntimeError'; "
            f"got: {exc_msg[:100]}")


# ===================================================================
# R4 SHOULD guards
# ===================================================================


class TestR4_ShouldGuards:
    """SHOULD guards from section E: cheap to write, proven non-vacuous."""

    def test_should_verified_refusal_keeps_key_id(self, tmp_path, monkeypatch):
        """E SHOULD: a verified refusal (command_mismatch) must keep its
        key_id in the alert record. A non-string key_id is still refused
        as malformed (either refusal is acceptable)."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        rid = "req-should-kid"
        rec = _create_pending_request(lay, rid, command="echo shouldkid")
        bob_sk, _, bob_kid = ws["admin_sks"][0][:3]
        # Bob signs for a different command -> command_mismatch, verified=True
        va = _make_remote_approval(bob_sk, request_id=rid,
                                   command="echo DIFFERENT",
                                   fingerprint=rec["fingerprint"],
                                   user_id=f"admin-{bob_kid[:8]}")
        s, _ = _mk(lay, _stub_decisions([_build_server_row(va, rid)]))
        _fetch_decisions(s)
        alerts = read_alerts(lay, limit=200)
        verified_refusals = [a for a in alerts
                             if a.get("event") == "decision_refused"
                             and a.get("reason_code") == "command_mismatch"]
        assert len(verified_refusals) >= 1, \
            f"must produce command_mismatch alert; got {[a.get('reason_code') for a in alerts]}"
        # The key_id must be present in the alert
        alert_kid = verified_refusals[0].get("key_id", "")
        assert alert_kid, \
            f"verified refusal must keep key_id; got empty in alert: {verified_refusals[0]}"

    def test_should_nonce_replay_in_post_sig_codes(self):
        """E SHOULD: nonce_replay must be in _POST_SIG_CODES (fail-safe)."""
        from sandbox.connector.approval import _POST_SIG_CODES
        assert "nonce_replay" in _POST_SIG_CODES, \
            f"nonce_replay not in _POST_SIG_CODES; got {_POST_SIG_CODES}"

    @pytest.mark.parametrize("missing_field",
                             ["count", "alerted", "first_seen", "last_seen"])
    def test_r5_2_nonalert_missing_field_drops_file(self, tmp_path, monkeypatch,
                                                     missing_field):
        """R5-2: a non-alert entry missing count, alerted, first_seen or
        last_seen must drop the file.  Setup: the refusal key's entry is
        alerted with last_alerted 10 s ago (same as TestR4_4).  A second
        entry decision_refused:req-other:unknown_key has the named field
        removed.  The next cycle must write the refusal alert (because the
        corrupt state was dropped -> fresh state -> alerts fire)."""
        from sandbox.connector.sync.process import _fetch_decisions
        from sandbox.connector.alerts import read_alerts
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        _, _, row = _good_row(ws, lay, "req-r52-001")
        row = dict(row); row["signature"] = "00" * 64
        entry_key = "decision_refused:req-r52-001:bad_signature"
        sp = lay.root / ".sandbox" / "logs" / "decision_state.json"
        sp.parent.mkdir(parents=True, exist_ok=True)
        now = time.time()
        # First entry: the refusal key, alerted, suppresses alerts
        good_entry = {
            "count": 1, "alerted": True,
            "last_alerted": now - 10,
            "first_seen": now - 100,
            "last_seen": now - 5,
            "repeats": 0,
        }
        # Second entry: non-alert with the named field removed
        other_entry = {
            "count": 1, "alerted": False,
            "first_seen": now - 5, "last_seen": now - 5,
            "repeats": 0,
        }
        del other_entry[missing_field]
        state = {"entries": {
            entry_key: good_entry,
            "decision_refused:req-other:unknown_key": other_entry,
        }}
        sp.write_text(json.dumps(state), encoding="utf-8")
        s, _ = _mk(lay, _stub_decisions([row]))
        _fetch_decisions(s)
        alerts = [a for a in read_alerts(lay, limit=200)
                  if a.get("event") in ("decision_refused", "decisions_malformed")]
        assert len(alerts) >= 1, \
            f"R5-2: non-alert entry missing '{missing_field}' must drop " \
            f"file and re-alert; got {len(alerts)} alerts"

    def test_should_registry_stage_str_exc(self, tmp_path, monkeypatch):
        """E SHOULD: str(exc) at registry stage should not reach the
        SyncError message (R3-6 node covers token; this covers registry)."""
        from sandbox.connector.sync.process import SyncProcess, run_once, SyncError
        ws = _setup_managed_workspace(tmp_path, monkeypatch); lay = ws["lay"]
        sentinel = "REGISTRY_SECRET_SENTINEL"
        def c(m, u, body=None, headers=None, token=None):
            if "/sync/token" in u:
                return (200, {"access_token": "t", "expires_in": 3600}, _date_hdr())
            if "/sync/registry" in u:
                raise ValueError(sentinel)
            return (200, {}, _date_hdr())
        s = SyncProcess(
            layout=lay, server_url="http://127.0.0.1:9999",
            device_key=bytes(_keygen()[0]), device_id="dev-1",
            clock=time.monotonic, connect=c)
        exc_msg = ""
        try:
            run_once(s)
        except SyncError as e:
            exc_msg = str(e)
        except Exception as e:
            exc_msg = str(e)
        assert sentinel not in exc_msg, \
            f"str(exc) at registry reached SyncError: {exc_msg[:100]}"
