# Governance on non-shell tool calls: benchmark

Governance clauses (`src/sandbox/governance/`) were only evaluated on shell
commands that were already escalating. MCP tools on allowlisted servers and
WebFetch to allowlisted hosts were allowed without any clause seeing them, so
"no moving money without human review" never saw `mcp__stripe__create_refund`.

## The set (frozen before any detection code)

`calls.jsonl`: 93 tool calls (sha256 `4c958fb0e92280489ee63b45241ad7a36edb887600cd9dd1c8c087eea8c944b8`), made by `generate.py`:
written by `qwen/qwen3.8-27b`, labelled by `openai/gpt-oss-120b` against the
three clauses of the example policy (`no_external_data`, `no_prod_change`,
`no_payments`). 43 violate at least one clause (13 payments, 11 external
data, 19 production changes); 50 don't (35 lookalikes such as staging
deploys, internal Slack messages and read-only payment queries, plus 15
ordinary calls). Fixtures only: example.com/.invalid hosts, invented IDs.

Labels are the labeller's, not human-reviewed. It usually tags a payment as
also sending customer data to an outside party, which is defensible.

## Split and bar (fixed before building anything)

Rows split by `sha256(id) % 2`: **dev** (even) may be inspected while
building the deterministic part; **test** (odd) is scored once.

Systems compared on test: the current gateway (no clause sees these calls);
jev-os clause checks on the call rendered as text; a deterministic
description of what the call does; and description gate AND check, as for
shell commands.

**Bar:** governance on non-shell calls is wired in (escalate on a hit) if the
chosen system reaches, on test, recall >= 0.7 over (call, clause) pairs and
false alarms on at most 10% of the benign test calls. Clauses that miss it
individually are reported as such.

## Result

The system was chosen on dev before the test run: **gate+check** (34/40
pairs caught, 1/26 benign calls flagged on dev; tags alone flagged 4/26,
over the bar). One test run (`run.py --split test`, jev-os `base`):

| system | caught (call, clause) pairs | benign calls flagged |
|---|---|---|
| current gateway | 0/20 | 0/24 |
| check (jev-os) | 18/20 | 17/24 |
| describe (tags) | 16/20 | 2/24 |
| **gate+check** | **16/20 (0.80)** | **0/24** |

Per clause: external data 7/8, production changes 7/10, payments 2/2. The
bar (recall >= 0.7, <= 10% benign flagged) is met, so tool-call governance
is wired in (`connector/hook_eval.py`, approve-then-retry grants in
`connector/tool_grants.py`).

Limits: 41 test calls is small (payments has only 2 positives on test); the
labels are one LLM's; and the tags were written by the same person who chose
the categories (looking only at the dev half). The three missed production
changes were calls whose names don't look like infrastructure operations.

