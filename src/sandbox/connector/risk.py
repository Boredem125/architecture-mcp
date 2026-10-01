"""Transparent, explainable risk scoring.

The score is deliberately **not a magic number**: it is a sum of named,
weighted factors, and every result carries the itemized breakdown so a human
(or an interviewer) can see exactly why. The exact weights matter less than the
principle the score demonstrates — **authorization is contextual**: the same
command is low-risk in one context and critical in another.

The score *refines* a classifier verdict; it never overrides a hard security
decision. A blocklist/self-protection ``deny`` stays denied and an allowlisted
``allow`` stays allowed regardless of score. Where the classifier says a trigger
fired, the score decides the *tier* of response:

    score  < 25  → allow      (auto)
    25 – 49      → observe    (audit, allow)
    50 – 79      → escalate   (one human approver)
    >= 80        → critical   (dual control: two distinct approvers, connector/approval.py)

Bands are policy-tunable; the defaults live here.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

# Default band thresholds (inclusive lower bound).
BAND_OBSERVE = 25
BAND_ESCALATE = 50
BAND_CRITICAL = 80

# Paths whose mere involvement raises risk sharply — secrets, keys, prod config.
_SENSITIVE_PATTERNS = (
    (re.compile(r"\.env\b", re.I), "env/secret file", 30),
    (re.compile(r"(^|[\\/])\.ssh([\\/]|$)", re.I), "SSH keys", 40),
    (re.compile(r"(secret|credential|password|token|apikey|api_key)", re.I), "credential-like path", 35),
    (re.compile(r"(^|[\\/])\.aws([\\/]|$)", re.I), "AWS credentials", 40),
    (re.compile(r"(id_rsa|id_ed25519|\.pem|\.pfx|\.key)$", re.I), "private key material", 40),
    (re.compile(r"(prod|production)", re.I), "production resource", 25),
)

# Trust level → risk delta (higher trust lowers risk).
_TRUST_DELTA = {
    "untrusted": +15,
    "low": +8,
    "standard": 0,
    "high": -10,
}

# Environment → risk delta (prod is riskier than dev).
_ENV_DELTA = {
    "dev": -5,
    "development": -5,
    "staging": +5,
    "stage": +5,
    "prod": +20,
    "production": +20,
}


@dataclass
class RiskFactor:
    """One named contribution to the total score."""

    name: str
    points: int
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "points": self.points, "detail": self.detail}


@dataclass
class RiskAssessment:
    """The total score plus the itemized factors that produced it."""

    score: int
    factors: list[RiskFactor] = field(default_factory=list)

    @property
    def band(self) -> str:
        if self.score >= BAND_CRITICAL:
            return "critical"
        if self.score >= BAND_ESCALATE:
            return "escalate"
        if self.score >= BAND_OBSERVE:
            return "observe"
        return "allow"

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "band": self.band,
            "factors": [f.to_dict() for f in self.factors],
        }

    def raise_by(self, factor: RiskFactor) -> None:
        """Add a factor that can only raise the score (the semantic ratchet).

        Model-derived factors go through here so a fooled or misbehaving model
        can never lower risk: negative points are rejected outright.
        """
        if factor.points < 0:
            raise ValueError(f"{factor.name}: risk factors from this path must be >= 0")
        self.factors.append(factor)
        self.score = max(0, min(100, self.score + factor.points))

    def explain(self) -> str:
        lines = [f"Risk {self.score}/100 -> {self.band.upper()}"]
        for f in sorted(self.factors, key=lambda x: -abs(x.points)):
            sign = "+" if f.points >= 0 else ""
            lines.append(f"  {sign}{f.points:>3}  {f.name}"
                         + (f" - {f.detail}" if f.detail else ""))
        return "\n".join(lines)


# Base privilege weight by trigger — the intrinsic risk of the operation class.
_TRIGGER_BASE = {
    "shell": 45,
    "network": 40,
    "write_outside": 55,
    "read_outside": 20,
    "": 5,  # in-folder/allowed
}


def assess(
    *,
    trigger: str,
    command: str = "",
    target_path: str = "",
    host: str = "",
    identity: Any = None,
    environment: str | None = None,
    reversible: bool | None = None,
    host_allowlisted: bool = False,
) -> RiskAssessment:
    """Compute an explainable risk score for one classified action."""
    factors: list[RiskFactor] = []

    base = _TRIGGER_BASE.get(trigger, 25)
    factors.append(RiskFactor("privilege", base, f"{trigger or 'in-folder'} operation"))

    # Sensitive resource involvement (path or command text).
    haystack = f"{target_path} {command}"
    for pattern, label, pts in _SENSITIVE_PATTERNS:
        if pattern.search(haystack):
            factors.append(RiskFactor("sensitive-resource", pts, label))
            break  # one (the first/most severe) is enough

    # Network destination.
    if trigger == "network":
        if host_allowlisted:
            factors.append(RiskFactor("destination", -25, f"{host} is allowlisted"))
        elif host:
            factors.append(RiskFactor("destination", +15, f"unrecognized host {host}"))
        else:
            factors.append(RiskFactor("destination", +20, "unknown destination"))

    # Reversibility.
    if reversible is None:
        reversible = trigger in ("read_outside", "")
    if not reversible:
        factors.append(RiskFactor("reversibility", +10, "hard to undo"))

    # Environment.
    env = (environment or os.environ.get("SANDBOX_ENV") or "").lower()
    if env in _ENV_DELTA:
        factors.append(RiskFactor("environment", _ENV_DELTA[env], env))

    # Identity trust.
    trust = getattr(identity, "trust_level", "standard") if identity else "standard"
    delta = _TRUST_DELTA.get(trust, 0)
    if delta:
        factors.append(RiskFactor("identity-trust", delta, f"trust={trust}"))

    score = sum(f.points for f in factors)
    score = max(0, min(100, score))
    return RiskAssessment(score=score, factors=factors)
