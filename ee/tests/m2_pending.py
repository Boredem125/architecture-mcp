"""M2 sentinel exceptions for ee/ tests-first strict xfail.

Mirrors tests/m2_pending.py for the ee/ tree.  Kept separate so
each tree can be collected independently.
"""


class M2T2Pending(Exception):
    """T2: ee/ portable process group helper."""


class M2T3Pending(Exception):
    """T3: Lows and DB pool."""


class M2T4Pending(Exception):
    """T4: Slim api base image."""


class M2T5Pending(Exception):
    """T5: M2 tables, RLS, triggers, SECURITY DEFINER functions."""


class M2T6Pending(Exception):
    """T6: Envelope, tags, kind matrix, registry."""


class M2T7Pending(Exception):
    """T7: sandbox signer and server signer routes."""


class M2T8Pending(Exception):
    """T8: Enrollment, tokens, revocation, sticky mode, un-enroll."""


class M2T9Pending(Exception):
    """T9: Bundles: per-section loosening, environment, overlay."""


class M2T10Pending(Exception):
    """T10: sandbox sync process, backoff, state denies, socket guard."""


class M2T11Pending(Exception):
    """T11: Audit upload, checkpoints, quarantine, retention guard."""


class M2T12Pending(Exception):
    """T12: Escalations, decisions, apply_external, skew rule."""


class M2T13Pending(Exception):
    """T13: Web pages: browser key enroll, pending list, approve/deny."""


class M2T14Pending(Exception):
    """T14: Compose: bundle-signer secret, carol, payments-staging."""


class M2T15Pending(Exception):
    """T15: Hostile review (no code; sentinel reserved)."""


class M2T16Pending(Exception):
    """T16: Gate run and demo."""


class M2T17Pending(Exception):
    """T17: Docs (no code; sentinel reserved)."""


def require_m2(task_num: int, condition: bool, msg: str = "") -> None:
    """Raise ``M2T<n>Pending`` when *condition* is False."""
    if condition:
        return
    _MAP = {
        2: M2T2Pending,
        3: M2T3Pending,
        4: M2T4Pending,
        5: M2T5Pending,
        6: M2T6Pending,
        7: M2T7Pending,
        8: M2T8Pending,
        9: M2T9Pending,
        10: M2T10Pending,
        11: M2T11Pending,
        12: M2T12Pending,
        13: M2T13Pending,
        14: M2T14Pending,
        15: M2T15Pending,
        16: M2T16Pending,
        17: M2T17Pending,
    }
    exc_cls = _MAP.get(task_num)
    if exc_cls is None:
        raise ValueError(f"Unknown task number: {task_num}")
    raise exc_cls(msg or f"T{task_num} feature not implemented yet")
