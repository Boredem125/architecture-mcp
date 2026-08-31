"""EscalationQueue — the cross-process bus, backed by the folder itself.

The connector is N processes (hook subprocess, MCP server, approver terminal,
maybe a dashboard). No in-memory dict can coordinate them, so the folder is
the source of truth. Atomicity comes from NTFS-atomic ``os.replace`` (write to
``tmp/`` then move into place) and ``os.rename`` for claiming (the OS lets
exactly one caller win the rename race — no locks needed).

Request lifecycle:  pending/  --claim-->  claimed/  --finish-->  done/ (+ out/)
"""
from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from sandbox.connector.layout import FolderLayout


class EscalationQueue:
    def __init__(self, layout: FolderLayout) -> None:
        self._layout = layout
        layout.ensure_dirs()

    # --- writing ---------------------------------------------------------
    def _atomic_write(self, dest: Path, obj: dict[str, Any]) -> None:
        tmp = self._layout.tmp_dir / f"{uuid.uuid4().hex}.tmp"
        tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, dest)  # atomic on the same volume

    def submit(self, record: dict[str, Any]) -> str:
        """Enqueue a request. Returns its request_id (minted if absent)."""
        request_id = record.get("request_id") or uuid.uuid4().hex[:16]
        record["request_id"] = request_id
        record.setdefault("created_at", time.time())
        self._atomic_write(self._layout.pending_dir / f"{request_id}.json", record)
        ident = record.get("identity", {}) or {}
        who = ident.get("agent_type", record.get("origin", "agent"))
        risk = (record.get("risk", {}) or {}).get("score", "?")
        self._activity(
            f"ESCALATED  {request_id}  [{who}]  risk={risk}  "
            f"{record.get('command') or record.get('path') or record.get('url') or ''}"
        )
        return request_id

    def _activity(self, line: str) -> None:
        """Append a human-readable line to .sandbox/logs/activity.log.

        This is the friendly, grep-able companion to the machine-readable audit
        chain — it lives in the obvious place (logs/) so nothing looks empty.
        Best-effort: never breaks the queue.
        """
        try:
            self._layout.logs_dir.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime("%Y-%m-%d %H:%M:%S")
            with open(self._layout.logs_dir / "activity.log", "a", encoding="utf-8") as f:
                f.write(f"[{stamp}] {line}\n")
        except OSError:
            pass

    # --- reading ---------------------------------------------------------
    @staticmethod
    def _read(path: Path) -> dict[str, Any] | None:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def list_pending(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for f in sorted(self._layout.pending_dir.glob("*.json")):
            rec = self._read(f)
            if rec is not None:
                out.append(rec)
        out.sort(key=lambda r: r.get("created_at", 0.0))
        return out

    def get(self, request_id: str) -> dict[str, Any] | None:
        """Return the merged view of a request across all stages."""
        for d in (self._layout.done_dir, self._layout.claimed_dir, self._layout.pending_dir):
            rec = self._read(d / f"{request_id}.json")
            if rec is not None:
                return rec
        return None

    def status(self, request_id: str) -> str:
        if (self._layout.done_dir / f"{request_id}.json").exists():
            return "done"
        if (self._layout.claimed_dir / f"{request_id}.json").exists():
            return "claimed"
        if (self._layout.pending_dir / f"{request_id}.json").exists():
            return "pending"
        return "unknown"

    # --- claiming / finishing -------------------------------------------
    def claim(self, request_id: str, reviewer_id: str) -> dict[str, Any] | None:
        """Atomically move pending -> claimed. None if we lost the race."""
        src = self._layout.pending_dir / f"{request_id}.json"
        dst = self._layout.claimed_dir / f"{request_id}.json"
        try:
            os.rename(src, dst)  # raises if another approver already took it
        except OSError:
            return None
        rec = self._read(dst) or {}
        rec["reviewer_id"] = reviewer_id
        rec["claimed_at"] = time.time()
        self._atomic_write(dst, rec)
        return rec

    def finish(self, request_id: str, result: dict[str, Any]) -> None:
        """Write the terminal done-record (+ human-readable out/ text).

        Every terminal record is cryptographically signed here — the single
        chokepoint all approver paths (CLI, watch, API) flow through — binding
        the approver's identity to the decision (non-repudiation). Best-effort:
        a signing failure must never break the approval loop.
        """
        result.setdefault("request_id", request_id)
        result.setdefault("decided_at", time.time())
        try:
            from sandbox.connector.signing import sign_record

            sign_record(self._layout, result.get("reviewer_id", "cli"), result)
        except Exception:  # noqa: BLE001 — signing is additive, never load-bearing
            pass
        self._atomic_write(self._layout.done_dir / f"{request_id}.json", result)

        decision = str(result.get("decision") or result.get("state") or "decided").upper()
        exit_code = result.get("exit_code")
        exit_str = f"  exit={exit_code}" if exit_code is not None else ""
        self._activity(
            f"{decision:<9}  {request_id}  by {result.get('reviewer_id', '?')}"
            f"{exit_str}  {result.get('command', '')}"
        )

        # broker_out-compatible text for humans / grep.
        out_path = self._layout.out_dir / f"{request_id}.txt"
        state = result.get("state", result.get("decision", "unknown"))
        if result.get("state") == "executed" or result.get("decision") == "approved":
            text = (
                f"EXIT_CODE: {result.get('exit_code')}\n"
                f"--- STDOUT ---\n{result.get('stdout', '')}\n"
                f"--- STDERR ---\n{result.get('stderr', '')}\n"
            )
        else:
            text = f"STATUS: {str(state).upper()}\nREASON: {result.get('reason', '')}\n"
        try:
            out_path.write_text(text, encoding="utf-8")
        except OSError:
            pass

        # Clean up the claimed marker if present.
        claimed = self._layout.claimed_dir / f"{request_id}.json"
        if claimed.exists():
            try:
                claimed.unlink()
            except OSError:
                pass

    # --- waiting ---------------------------------------------------------
    async def wait(
        self, request_id: str, timeout: float, poll_interval: float = 0.1
    ) -> dict[str, Any] | None:
        """Block until a done-record appears, or *timeout* elapses.

        Polling one known filename beats a filesystem watcher here: it is
        immune to missed-event/buffer-overflow edge cases under heavy churn.
        """
        deadline = time.monotonic() + timeout
        done_path = self._layout.done_dir / f"{request_id}.json"
        while time.monotonic() < deadline:
            rec = self._read(done_path)
            if rec is not None:
                return rec
            await asyncio.sleep(poll_interval)
        return None
