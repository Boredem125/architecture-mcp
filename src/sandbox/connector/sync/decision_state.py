"""Persisted dedupe and rate-limit state for decision alerts (T9a).

State file: ``.sandbox/logs/decision_state.json``, written atomically.
Outside ``state/sync/`` so it never enters the trust directory.  It is
**display and rate-limit state only**: no decision path reads it.  Corrupt
or missing means empty -- more alerts, never fewer.  No network imports.

Spec: T9A_SPEC.md section 4.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path


# -- Constants (spec section 4) --

DECISION_REALERT_SECONDS: int = 3600
DECISION_ALERTS_PER_CYCLE: int = 5
DECISION_ALERTS_PER_HOUR: int = 12
DECISIONS_NET_ALERT_AFTER: int = 3
MAX_KEYS: int = 256
MAX_REASONS_PER_REQUEST: int = 8


class DecisionState:
    """In-memory representation of the decision_state.json file.

    Keys: ``(kind, *key_parts)`` tuples mapped to entry dicts.  Each entry
    has ``count``, ``alerted`` (bool), ``last_seen`` (epoch float),
    ``first_seen`` (epoch float), ``repeats`` (int, re-alert count).
    """

    def __init__(self, logs_dir: Path) -> None:
        self._path = logs_dir / "decision_state.json"
        self._entries: dict[str, dict] = {}
        self._alerts_this_cycle: int = 0
        self._alerts_this_hour: int = 0
        self._hour_start: float = 0.0
        self._suppressed_this_hour: int = 0
        self._net_consecutive: int = 0
        self._load()

    # -- persistence --

    @staticmethod
    def _finite_int(val: object, default: int = 0) -> int:
        """Convert a numeric value to int, returning *default* for NaN/Inf/non-numeric."""
        import math
        if isinstance(val, bool):
            return default
        if isinstance(val, (int, float)):
            if math.isnan(val) or math.isinf(val):
                return default
            return int(val)
        return default

    @staticmethod
    def _finite_float(val: object, default: float = 0.0) -> float:
        """Convert a numeric value to float, returning *default* for NaN/Inf/non-numeric."""
        import math
        if isinstance(val, bool):
            return default
        if isinstance(val, (int, float)):
            if math.isnan(val) or math.isinf(val):
                return default
            return float(val)
        return default

    def _load(self) -> None:
        """Load from disk; corrupt or missing -> empty (more alerts, never fewer).

        Type-checks every field.  Any wrong type drops the whole file.
        Non-finite numbers (NaN, Inf) are treated as absent (R2-5).
        Future timestamps (later than now) are treated as absent so a
        hand-edited ``hour_start`` or ``last_alerted`` cannot silence alerts.
        Catches ``RecursionError`` for deeply nested JSON.
        """
        try:
            raw = self._path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, ValueError, KeyError, RecursionError):
            return
        if not isinstance(data, dict):
            return
        # -- type-check scalar fields; any wrong type -> drop file --
        entries = data.get("entries", {})
        if not isinstance(entries, dict):
            return
        net_raw = data.get("net_consecutive", 0)
        if not isinstance(net_raw, (int, float)) or isinstance(net_raw, bool):
            return
        ath_raw = data.get("alerts_this_hour", 0)
        if not isinstance(ath_raw, (int, float)) or isinstance(ath_raw, bool):
            return
        hs_raw = data.get("hour_start", 0.0)
        if not isinstance(hs_raw, (int, float)) or isinstance(hs_raw, bool):
            return
        sth_raw = data.get("suppressed_this_hour", 0)
        if not isinstance(sth_raw, (int, float)) or isinstance(sth_raw, bool):
            return
        # R2-5: reject non-finite numbers
        net = self._finite_int(net_raw)
        ath = self._finite_int(ath_raw)
        hs = self._finite_float(hs_raw)
        sth = self._finite_int(sth_raw)
        # -- type-check each entry value --
        now = time.time()
        validated: dict[str, dict] = {}
        for k, v in entries.items():
            if not isinstance(k, str) or not isinstance(v, dict):
                continue
            validated[k] = v
            # R2-5: future timestamps treated as absent (T9A-5)
            for ts_field in ("last_alerted", "first_seen", "last_seen"):
                ts_val = v.get(ts_field)
                if isinstance(ts_val, (int, float)):
                    import math
                    if math.isnan(ts_val) or math.isinf(ts_val) or ts_val > now:
                        v.pop(ts_field, None)
                        if ts_field == "last_alerted":
                            v["alerted"] = False
        # Future hour_start treated as absent
        if hs > now:
            hs = 0.0
            ath = 0
            sth = 0
        self._entries = validated
        self._net_consecutive = net
        self._alerts_this_hour = ath
        self._hour_start = hs
        self._suppressed_this_hour = sth

    def save(self) -> None:
        """Atomic write via temp + rename."""
        data = {
            "entries": self._entries,
            "net_consecutive": self._net_consecutive,
            "alerts_this_hour": self._alerts_this_hour,
            "hour_start": self._hour_start,
            "suppressed_this_hour": self._suppressed_this_hour,
        }
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, separators=(",", ":")),
                           encoding="utf-8")
            os.replace(str(tmp), str(self._path))
        except OSError:
            pass

    # -- network counter (spec section 4) --

    @property
    def net_consecutive(self) -> int:
        return self._net_consecutive

    def note_net_failure(self) -> int:
        """Increment and return the consecutive network failure count."""
        self._net_consecutive += 1
        return self._net_consecutive

    def reset_net_counter(self) -> None:
        self._net_consecutive = 0

    # -- dedupe --

    def _make_key(self, parts: tuple) -> str:
        return ":".join(str(p) for p in parts)

    def is_first_sighting(self, key_parts: tuple) -> bool:
        """True if this key has never been seen before."""
        return self._make_key(key_parts) not in self._entries

    def note(self, key_parts: tuple, *, reason: str = "") -> dict:
        """Record a sighting; return the entry.  First sighting -> alerted=False."""
        k = self._make_key(key_parts)
        now = time.time()
        if k not in self._entries:
            self._entries[k] = {
                "count": 1,
                "alerted": False,
                "last_seen": now,
                "first_seen": now,
                "repeats": 0,
            }
        else:
            self._entries[k]["count"] += 1
            self._entries[k]["last_seen"] = now
        if reason:
            self._entries[k]["reason"] = reason
        self._evict()
        return self._entries[k]

    def should_alert(self, key_parts: tuple) -> bool:
        """True if this key should fire an alert now.

        First sighting: yes.  Same key later: no.  After REALERT_SECONDS: yes.
        """
        k = self._make_key(key_parts)
        entry = self._entries.get(k)
        if entry is None:
            return True
        if not entry["alerted"]:
            return True
        elapsed = time.time() - entry.get("last_alerted", entry["first_seen"])
        if elapsed >= DECISION_REALERT_SECONDS:
            return True
        return False

    def mark_alerted(self, key_parts: tuple) -> None:
        k = self._make_key(key_parts)
        entry = self._entries.get(k)
        if entry:
            entry["alerted"] = True
            entry["last_alerted"] = time.time()

    def mark_realerted(self, key_parts: tuple) -> None:
        k = self._make_key(key_parts)
        entry = self._entries.get(k)
        if entry:
            entry["repeats"] = entry.get("repeats", 0) + 1
            entry["last_alerted"] = time.time()

    def get_repeats(self, key_parts: tuple) -> int:
        k = self._make_key(key_parts)
        entry = self._entries.get(k)
        return entry.get("repeats", 0) if entry else 0

    def get_count(self, key_parts: tuple) -> int:
        k = self._make_key(key_parts)
        entry = self._entries.get(k)
        return entry.get("count", 0) if entry else 0

    # -- caps --

    def begin_cycle(self) -> None:
        """Reset per-cycle counters."""
        self._alerts_this_cycle = 0
        now = time.time()
        if now - self._hour_start >= 3600:
            self._alerts_this_hour = 0
            self._hour_start = now
            self._suppressed_this_hour = 0

    def may_alert(self) -> bool:
        """True if the per-cycle and per-hour caps have not been hit."""
        return (self._alerts_this_cycle < DECISION_ALERTS_PER_CYCLE
                and self._alerts_this_hour < DECISION_ALERTS_PER_HOUR)

    def record_alert(self) -> None:
        self._alerts_this_cycle += 1
        self._alerts_this_hour += 1

    def record_suppressed(self) -> None:
        self._suppressed_this_hour += 1

    @property
    def suppressed_this_hour(self) -> int:
        return self._suppressed_this_hour

    # -- clear --

    def clear_fetch_keys(self) -> None:
        """Clear fetch-related keys on a 200.

        Clears ``decisions_fetch_failed`` entries only (not
        ``server_time_write_failed`` or ``decisions_malformed``).
        Malformed keys are cleared separately after processing confirms
        no new malformed rows appeared.
        """
        to_remove = [k for k in self._entries
                     if k.startswith("decisions_fetch_failed:")
                     and "server_time_write_failed" not in k]
        for k in to_remove:
            del self._entries[k]

    def clear_malformed_keys(self) -> None:
        """Clear ``decisions_malformed`` entries after a clean 200.

        Called only when processing found no malformed rows in this cycle.
        """
        to_remove = [k for k in self._entries
                     if k.startswith("decisions_malformed:")]
        for k in to_remove:
            del self._entries[k]

    def clear_request(self, rid: str) -> None:
        """Clear keys for a specific request when it leaves pending."""
        to_remove = [k for k in self._entries if f":{rid}:" in k]
        for k in to_remove:
            del self._entries[k]

    # -- eviction --

    def _evict(self) -> None:
        """Keep at most MAX_KEYS entries, oldest last_seen evicted."""
        if len(self._entries) <= MAX_KEYS:
            return
        sorted_keys = sorted(
            self._entries, key=lambda k: self._entries[k].get("last_seen", 0),
        )
        while len(self._entries) > MAX_KEYS:
            del self._entries[sorted_keys.pop(0)]


class NullDecisionState(DecisionState):
    """No-op stub for layout=None: writes nothing anywhere (R2-8)."""

    def __init__(self) -> None:
        # Do not call super().__init__: no path, no file read.
        self._path = None
        self._entries: dict[str, dict] = {}
        self._alerts_this_cycle: int = 0
        self._alerts_this_hour: int = 0
        self._hour_start: float = 0.0
        self._suppressed_this_hour: int = 0
        self._net_consecutive: int = 0

    def _load(self) -> None:
        pass

    def save(self) -> None:
        pass  # no-op: never writes
