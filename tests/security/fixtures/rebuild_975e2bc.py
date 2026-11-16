"""Frozen copy of ``_rebuild_decision_envelope`` from commit 975e2bc.

This is the exact function body from process.py at 975e2bc (lines 519-549),
used as a differential fixture.  The current ``_rebuild_envelope`` (81fda66)
must produce identical verdicts for every row form that 975e2bc handled.

Any row form where the two disagree is a verdict regression (R3-1).
"""
from __future__ import annotations

import json


def rebuild_975e2bc(row: dict) -> dict | None:
    """975e2bc ``_rebuild_decision_envelope``, verbatim."""
    payload = row.get("signed_payload") or row.get("payload")
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            return None
    if not isinstance(payload, dict):
        return None
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
        "kind": "agg/remote-approval/v1",
        "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": key_id, "alg": "ed25519", "sig": sig}],
    }
