"""Risk scoring — transparent, explainable, contextual."""
from __future__ import annotations

from sandbox.connector.identity import AgentIdentity
from sandbox.connector.risk import assess


def test_safe_readlike_is_low():
    a = assess(trigger="", command="ls")
    assert a.band == "allow"
    assert a.score < 25


def test_shell_escalates():
    a = assess(trigger="shell", command="npm install -g typescript")
    assert a.band in ("escalate", "critical")
    assert any(f.name == "privilege" for f in a.factors)


def test_same_command_riskier_touching_secrets():
    plain = assess(trigger="write_outside", target_path="/tmp/notes.txt")
    secret = assess(trigger="write_outside", target_path="/app/.env")
    assert secret.score > plain.score
    assert any("sensitive" in f.name for f in secret.factors)


def test_allowlisted_host_lowers_network_risk():
    known = assess(trigger="network", host="pypi.org", host_allowlisted=True)
    unknown = assess(trigger="network", host="evil.example.com", host_allowlisted=False)
    assert unknown.score > known.score


def test_production_environment_raises_risk():
    dev = assess(trigger="shell", command="deploy", environment="dev")
    prod = assess(trigger="shell", command="deploy", environment="production")
    assert prod.score > dev.score


def test_high_trust_lowers_risk():
    low = assess(trigger="shell", command="x",
                 identity=AgentIdentity(trust_level="untrusted"))
    high = assess(trigger="shell", command="x",
                  identity=AgentIdentity(trust_level="high"))
    assert low.score > high.score


def test_credential_access_reaches_critical():
    a = assess(trigger="shell", command="cat ~/.ssh/id_rsa",
               target_path="~/.ssh/id_rsa", environment="production")
    assert a.band == "critical"
    assert a.score >= 80


def test_explanation_itemizes_factors():
    a = assess(trigger="network", host="evil.com")
    text = a.explain()
    assert "Risk" in text and "privilege" in text
    # every factor is a named contribution, not a magic number
    assert len(a.factors) >= 2


def test_score_is_bounded():
    a = assess(trigger="write_outside", command="rm .env .ssh/id_rsa prod secret",
               target_path="/prod/.env", environment="production",
               identity=AgentIdentity(trust_level="untrusted"))
    assert 0 <= a.score <= 100
