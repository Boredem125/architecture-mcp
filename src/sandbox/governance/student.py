"""Distilled per-clause classifiers for governance clauses (optional).

A clause may name a model file (``student_model``, relative to the policy
file or absolute) produced by ``benchmarks/governance/train.py``. It reuses
the injection student's runtime (sandbox/semantic/student.py): TF-IDF word
and character n-grams into a linear layer, pure Python, about a millisecond.

The student adds a second detector to the clause; it never replaces the
deterministic ``requires_actions`` gate, and a clause still only raises
scrutiny.
"""
from __future__ import annotations

from pathlib import Path

from sandbox.governance.policy import GovernancePolicy
from sandbox.semantic.student import Student

_CACHE: dict[str, Student] = {}


def load_students(policy: GovernancePolicy, policy_path: str | Path | None = None) -> dict[str, Student]:
    """{clause_id: Student} for clauses whose model file exists."""
    from sandbox.governance.policy import example_policy_path

    base = Path(policy_path).parent if policy_path else example_policy_path().parent
    out = {}
    for c in policy.clauses:
        if not c.student_model:
            continue
        path = Path(c.student_model)
        if not path.is_absolute():
            path = base / path
        key = str(path.resolve())
        try:
            if key not in _CACHE:
                _CACHE[key] = Student.load(path)
            out[c.id] = _CACHE[key]
        except OSError:
            continue  # model missing: the clause falls back to its check alone
    return out
