"""M3 sentinel exceptions for tests-first strict xfail.

Mirror of ``tests/m2_pending.py`` for M3 (``docs/control-plane/M3_PLAN.md``,
task table).  QA commits each task's failing tests as
``xfail(strict=True, raises=M3T<n>Pending)``; the build removes only the
marker.  A helper ``require_m3`` raises the task's sentinel when the feature
is still absent (failed import, missing attribute, missing route).  The
sentinel is raised only by one feature-absence check at the top of a test;
the final assertions stay plain ``assert`` (rule from M2 T6 on).

T9a and T9b share ``M3T9Pending``.
"""


class M3T1Pending(Exception):
    """T1: admin reads (devices, codes status, bundles, alerts, verify, JSONL export); record_hash at ingest."""


class M3T2Pending(Exception):
    """T2: web app router, Approve page with context, Devices and enrollment, Policy proposals."""


class M3T3Pending(Exception):
    """T3: enrollment-code flow, proposals, approvals and publish routes, CSRF on the two admin POSTs."""


class M3T4Pending(Exception):
    """T4: server verification at publish, migration labels, AGG_ALLOW_DIRECT_PUBLISH demo-only flag."""


class M3T5Pending(Exception):
    """T5: pilot.sh up/doctor/backup/restore/upgrade, ACME, Keycloak pilot realm, docs/PILOT.md."""


class M3T6Pending(Exception):
    """T6: ee/deploy/m3_pilot.py (Playwright), scenario static checks, ee-web-e2e CI job."""


class M3T7Pending(Exception):
    """T7: evidence pack signed by a dedicated evidence_signer_key; --expect-root; verifier extension."""


class M3T8Pending(Exception):
    """T8: web app Alerts, device detail with badge, Evidence download and JSONL export, history, Settings."""


class M3T9Pending(Exception):
    """T9a/T9b: D5 security follow-ups (_fetch_decisions never swallows; remaining MUSTs and SHOULDs)."""


class M3T10Pending(Exception):
    """T10: pilot hardening: backup and restore drill, upgrade from an M2 stack, Trivy and ZAP."""


class M3T11Pending(Exception):
    """T11 (option): device quarantine and signed stop (agg/stop/v1)."""


class M3T12Pending(Exception):
    """T12: hostile review (no code; sentinel reserved)."""


class M3T13Pending(Exception):
    """T13: gate run and M3_DEMO.md (no code; sentinel reserved)."""


class M3T14Pending(Exception):
    """T14: docs (no code; sentinel reserved)."""


_MAP = {
    1: M3T1Pending,
    2: M3T2Pending,
    3: M3T3Pending,
    4: M3T4Pending,
    5: M3T5Pending,
    6: M3T6Pending,
    7: M3T7Pending,
    8: M3T8Pending,
    9: M3T9Pending,
    10: M3T10Pending,
    11: M3T11Pending,
    12: M3T12Pending,
    13: M3T13Pending,
    14: M3T14Pending,
}


def require_m3(task_num: int, condition: bool, msg: str = "") -> None:
    """Raise ``M3T<n>Pending`` when *condition* is False."""
    if condition:
        return
    exc_cls = _MAP.get(task_num)
    if exc_cls is None:
        raise ValueError(f"Unknown task number: {task_num}")
    raise exc_cls(msg or f"T{task_num} feature not implemented yet")
