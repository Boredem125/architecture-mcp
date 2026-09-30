"""Plain-language governance clauses, evaluated at runtime (governance-as-code).

A clause is written in English for humans and audit, and compiled to a jev-os
check plus optional deterministic gates. Clauses only raise scrutiny (escalate
or deny), never permit. Each clause ships example cases so its reliability is
measured, not assumed — zero-shot checks vary a lot by wording.
"""
