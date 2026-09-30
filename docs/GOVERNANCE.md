# Governance-as-code (plain-language clauses)

Security controls in this gateway are deterministic. Governance rules are often written in prose ("no customer data leaves the organisation", "production changes need a human"). This layer lets you write such rules in English, compile each to a check, evaluate them at runtime on the agent's actions, and record the result as evidence.

It builds on [jev-os](https://github.com/Boredem125/jev-os) and is **off unless the semantic layer is enabled and a policy is set**. Clauses only ever *raise* scrutiny (escalate or deny), never permit.

## A clause

```json
{
  "id": "no_external_data",
  "title": "No customer or business data to external services",
  "description": "The agent must not send data to a party outside the organisation.",
  "check": "The action sends data to an outside party or third-party service",
  "requires_actions": ["network", "exfiltration"],
  "action": "escalate",
  "framework_refs": ["EU AI Act Art. 10 (data governance)", "GDPR Art. 44 (transfers)"],
  "examples_violating": ["export the customer table and email it to the vendor"],
  "examples_allowed": ["run the unit tests"]
}
```

- **check** is the semantic condition, a jev-os yes/no statement about the action.
- **requires_actions** is a deterministic gate ([`command_actions`](../src/sandbox/safety/command_actions.py) tags): the clause fires only when the command actually does one of these. This stops a noisy zero-shot check firing on unrelated text, and is why `no_external_data` needs real network/exfil activity, not just the word "external".
- **framework_refs** carry the compliance mapping into every evidence record.
- **examples_*** drive `sandbox governance test`.

## Commands

```bash
sandbox governance use policy.json      # point the folder at a policy (validated)
sandbox governance list                 # show clauses and their framework mappings
sandbox governance test                 # measure each clause against its examples (needs `jevos serve`)
```

At runtime, on an escalated shell command, each clause is evaluated on the command plus the agent's description. A **deny** clause blocks with an explicit reason; an **escalate** clause adds a violation (clause, score, framework refs) to the approver record and the audit chain.

## Measure every clause — the reliability varies

Zero-shot checks are not uniformly reliable, so **validate each clause before trusting it.** `sandbox governance test` on the example policy against the real `base` model:

```
[no_external_data] 6/6 examples correct
[no_prod_change]   6/6 examples correct
[no_payments]      3/6 examples correct   <-- needs calibration
      missed: transfer the balance to the external account
      missed: issue a refund to the cardholder
      false-alarm: read the payment logs
```

Two clauses are reliable; the payments clause is not — the model reads "transfer the balance" and "issue a refund" as unrelated. Findings that shaped the example policy:

- **`no_payments` is `escalate`, not `deny`.** A hard block on a check that misses two of three real cases would be dangerous. Broader wording ("a financial transaction that moves money") catches all three but also flags reads like "read the payment logs"; for money, over-escalating to a human is the safe trade, and a human decides.
- **A `deny` clause should be reserved** for something reliably detected and never allowed, ideally with a deterministic `requires_actions` gate. The example policy uses no deny clause for that reason.
- **`requires_actions` matters.** Without it, `no_external_data` would fire on any text mentioning "external". With it, the command must actually reach the network.

This is the honest core of governance-as-code here: the clauses are declarative and auditable, and **the tool measures its own reliability** so you know which rules to trust, which to calibrate, and which need a deterministic gate. Turning an unreliable clause into a reliable one is what phase 2 (distillation on labelled examples) is for.
