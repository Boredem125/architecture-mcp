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
        self._net_stage: str = ""
        self._load()

    # -- persistence --

    # R3-3: ints above this magnitude cannot safely convert to float
    # (OverflowError in math.isnan/isinf). Guard before math calls.
    _INT_GUARD = 2**63

    @staticmethod
    def _finite_int(val: object, default: int = 0) -> int:
        """Convert a numeric value to int, returning *default* for NaN/Inf/non-numeric.

        R3-3: huge ints (> 2**63) return default -- they would OverflowError
        in math.isnan/isinf, and no valid state field needs values that large.
        """
        import math
        if isinstance(val, bool):
            return default
        if isinstance(val, int):
            if abs(val) > DecisionState._INT_GUARD:
                return default
            return val
        if isinstance(val, float):
            if math.isnan(val) or math.isinf(val):
                return default
            return int(val)
        return default

    @staticmethod
    def _finite_float(val: object, default: float = 0.0) -> float:
        """Convert a numeric value to float, returning *default* for NaN/Inf/non-numeric.

        R3-3: huge ints (> 2**63) return default.
        """
        import math
        if isinstance(val, bool):
            return default
        if isinstance(val, int):
            if abs(val) > DecisionState._INT_GUARD:
                return default
            return float(val)
        if isinstance(val, float):
            if math.isnan(val) or math.isinf(val):
                return default
            return val
        return default

    def _load(self) -> None:
        """Load from disk; corrupt or missing -> empty (more alerts, never fewer).

        Any present field of the wrong type drops the whole file (R4-4).
        Counters must be ``int`` (not ``bool``), ``0 <= v <= 2**63`` (R4-3).
        Non-finite numbers (NaN, Inf) are treated as absent (R2-5).
        Future timestamps (later than now) are treated as absent so a
        hand-edited ``hour_start`` or ``last_alerted`` cannot silence alerts.
        Catches ``RecursionError`` for deeply nested JSON.
        """
        try:
            raw = self._path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except Exception:  # noqa: BLE001 -- corrupt state -> empty (T9A-5, R3-3)
            return
        if not isinstance(data, dict):
            return
        # R4-4: wrap all validation in try/except so any wrong type
        # drops the file (caller catches -> empty state).
        try:
            self._validate(data)
        except Exception:  # noqa: BLE001 -- corrupt -> empty
            self._entries = {}

    def _validate(self, data: dict) -> None:
        """Validate and apply loaded state (R3-3, R4-3, R4-4).

        Any present field of the wrong type raises, and ``_load`` catches
        it, giving empty state.  No coercion defaults: wrong types drop
        the whole file.
        """
        import math

        def _require_counter(val: object) -> int:
            """int (not bool), 0 <= v <= 2**63, or raise."""
            if isinstance(val, bool) or not isinstance(val, int):
                raise ValueError("counter is not int")
            if val < 0 or val > self._INT_GUARD:
                raise ValueError("counter out of range")
            return val

        def _require_ts(val: object) -> float:
            """int or float (not bool), finite, or raise."""
            if isinstance(val, bool):
                raise ValueError("timestamp is bool")
            if isinstance(val, int):
                if abs(val) > self._INT_GUARD:
                    raise ValueError("timestamp too large")
                return float(val)
            if isinstance(val, float):
                if math.isnan(val) or math.isinf(val):
                    raise ValueError("timestamp non-finite")
                return val
            raise ValueError("timestamp wrong type")

        # -- type-check top-level counters; any wrong type -> raise --
        entries = data.get("entries", {})
        if not isinstance(entries, dict):
            raise ValueError("entries is not a dict")

        net = _require_counter(data.get("net_consecutive", 0))
        ath = _require_counter(data.get("alerts_this_hour", 0))
        sth = _require_counter(data.get("suppressed_this_hour", 0))
        hs = _require_ts(data.get("hour_start", 0.0))

        # -- R4-4: full type-check of each entry value --
        now = time.time()
        validated: dict[str, dict] = {}
        for k, v in entries.items():
            if not isinstance(k, str):
                raise ValueError("entry key is not a string")
            if not isinstance(v, dict):
                # R4-4: an entry that is a list (or other non-dict) drops file
                raise ValueError("entry value is not a dict")

            # --- alerted, verified: must be bool if present ---
            alerted_raw = v.get("alerted")
            if alerted_raw is not None and not isinstance(alerted_raw, bool):
                raise ValueError("alerted is not bool")
            verified_raw = v.get("verified")
            if verified_raw is not None and not isinstance(verified_raw, bool):
                raise ValueError("verified is not bool")
            is_alerted = v.get("alerted", False) is True

            # --- counters: int (not bool), 0 <= v <= 2**63 ---
            count_raw = v.get("count")
            if count_raw is not None:
                v["count"] = _require_counter(count_raw)
            elif not is_alerted:
                raise ValueError("non-alert entry missing count")
            else:
                v["count"] = 1  # safe default for alerted entries
            repeats_raw = v.get("repeats")
            if repeats_raw is not None:
                v["repeats"] = _require_counter(repeats_raw)
            else:
                v["repeats"] = 0  # safe default

            # --- timestamps: int or float (not bool), finite ---
            for ts_field in ("first_seen", "last_seen", "last_alerted", "hour_start"):
                ts_val = v.get(ts_field)
                if ts_val is None:
                    if ts_field in v:
                        v.pop(ts_field)
                    continue
                ts_f = _require_ts(ts_val)
                if ts_f > now:
                    # Future timestamp: treat as absent
                    if ts_field == "last_alerted":
                        v.pop(ts_field, None)
                        v["alerted"] = False
                    else:
                        v[ts_field] = 0.0
                else:
                    v[ts_field] = ts_f

            # R4-4: a non-alert entry missing alerted, first_seen or
            # last_seen drops the file.
            if not is_alerted:
                if alerted_raw is None:
                    raise ValueError("non-alert entry missing alerted")
                if "first_seen" not in v or "last_seen" not in v:
                    raise ValueError("non-alert entry missing first_seen or last_seen")

            # --- string fields: must be str if present ---
            for str_field in ("reason", "outcome_sig", "code", "rid", "key_id", "stage"):
                sf_val = v.get(str_field)
                if sf_val is not None and not isinstance(sf_val, str):
                    raise ValueError(f"{str_field} is not a string")

            # --- status: int or absent ---
            status_val = v.get("status")
            if status_val is not None:
                if isinstance(status_val, bool) or not isinstance(status_val, int):
                    raise ValueError("status is not int")

            # Ensure first_seen always exists (should_alert needs it)
            if "first_seen" not in v:
                v["first_seen"] = 0.0

            validated[k] = v

        # Future hour_start treated as absent
        if hs > now:
            hs = 0.0
            ath = 0
            sth = 0

        # R4-10: net_stage must be a string; ignore if not
        net_stage_raw = data.get("net_stage", "")
        if not isinstance(net_stage_raw, str):
            net_stage_raw = ""

        self._entries = validated
        self._net_consecutive = net
        self._net_stage = net_stage_raw
        self._alerts_this_hour = ath
        self._hour_start = hs
        self._suppressed_this_hour = sth

    def save(self) -> None:
        """Atomic write via temp + rename."""
        data = {
            "entries": self._entries,
            "net_consecutive": self._net_consecutive,
            "net_stage": self._net_stage,
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

    def note_net_failure(self, stage: str = "") -> int:
        """Increment and return the consecutive network failure count.

        *stage* is persisted so the status line can show ``at <stage>``
        on every cycle, not only after the alert threshold (R4-10).
        """
        self._net_consecutive += 1
        if stage:
            self._net_stage = stage
        return self._net_consecutive

    def reset_net_counter(self) -> None:
        self._net_consecutive = 0
        self._net_stage = ""

    # -- dedupe --

    def _make_key(self, parts: tuple) -> str:
        return ":".join(str(p) for p in parts)

    def note(self, key_parts: tuple, *, reason: str = "",
             code: str = "", rid: str = "", key_id: str = "",
             verified: bool = False, stage: str = "",
             status: object = None) -> dict:
        """Record a sighting; return the entry.  First sighting -> alerted=False.

        R3-7: store code, rid, key_id, verified, reason, stage, status
        in each entry so the reader never needs to split the key.
        """
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
        # R3-7: always store structured fields so the reader never parses keys
        if code:
            self._entries[k]["code"] = code
        if rid:
            self._entries[k]["rid"] = rid
        if key_id:
            self._entries[k]["key_id"] = key_id
        if verified:
            self._entries[k]["verified"] = verified
        if stage:
            self._entries[k]["stage"] = stage
        if status is not None:
            self._entries[k]["status"] = status
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
        self._net_stage: str = ""

    def _load(self) -> None:
        pass

    def save(self) -> None:
        pass  # no-op: never writes
