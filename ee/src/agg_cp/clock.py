"""Injected clock for the control plane.

The only place the system clock is read.  All other ``agg_cp`` code
receives a :class:`Clock` instance, which tests can replace with a
settable/advanceable fake.
"""
from __future__ import annotations

import datetime as dt
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    """Protocol for a clock that returns tz-aware UTC datetimes."""

    def now(self) -> dt.datetime: ...


class SystemClock:
    """Real system clock.  Always returns UTC-aware datetimes."""

    def now(self) -> dt.datetime:
        return dt.datetime.now(dt.timezone.utc)
