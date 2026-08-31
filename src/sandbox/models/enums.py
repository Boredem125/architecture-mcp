from __future__ import annotations

from enum import StrEnum


class ActionType(StrEnum):
    READ = "READ"
    WRITE = "WRITE"
    EXECUTE = "EXECUTE"
    NETWORK = "NETWORK"
    SECRET_ACCESS = "SECRET_ACCESS"


class RiskTier(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, RiskTier):
            return NotImplemented
        order = list(RiskTier)
        return order.index(self) > order.index(other)

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, RiskTier):
            return NotImplemented
        order = list(RiskTier)
        return order.index(self) >= order.index(other)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, RiskTier):
            return NotImplemented
        order = list(RiskTier)
        return order.index(self) < order.index(other)

    def __le__(self, other: object) -> bool:
        if not isinstance(other, RiskTier):
            return NotImplemented
        order = list(RiskTier)
        return order.index(self) <= order.index(other)

    def upgrade(self) -> RiskTier:
        order = list(RiskTier)
        idx = order.index(self)
        return order[min(idx + 1, len(order) - 1)]


class PolicyDecision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


class ContentDecision(StrEnum):
    CLEAR = "CLEAR"
    BLOCK = "BLOCK"


class HITLDecision(StrEnum):
    APPROVE = "APPROVE"
    DENY = "DENY"
    TIMEOUT = "TIMEOUT"
    PENDING = "PENDING"


class ExecutionResult(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    TIMEOUT = "TIMEOUT"
    SKIPPED = "SKIPPED"


class ZoneSource(StrEnum):
    AGENT = "AGENT"
    SANDBOX = "SANDBOX"
    LOCAL = "LOCAL"


class SessionEndReason(StrEnum):
    DONE = "done"
    TTL_EXPIRED = "ttl_expired"
    BUDGET_EXHAUSTED = "budget_exhausted"
    KILL_SWITCH = "kill_switch"
    AUDIT_FAILURE = "audit_failure"
    ERROR = "error"


class AnomalyType(StrEnum):
    RATE_SPIKE = "rate_spike"
    ACTION_DRIFT = "action_drift"
    RESOURCE_DRIFT = "resource_drift"
    CONTEXT_POISONING = "context_poisoning"
    POLICY_PROBE = "policy_probe"
    PATH_TRAVERSAL = "path_traversal"
    UNAUTHORIZED_SECRET = "unauthorized_secret"
