# Governance clauses on shell commands: benchmark

Governance clauses are checked on escalated shell commands, on the command
plus the agent's one-line description (`src/sandbox/governance/evaluate.py`).
Until now their only measurement was each clause's own six examples
(`sandbox governance test`), where the zero-shot payments clause caught 3 of 6.

## The set (frozen before any training)

`commands.jsonl`: 105 commands with descriptions (sha256 `5bbd7bc6ab95365e6a33c4410079ebb929c7e3a8ccee6a4c0b9376d0d96c2ef5`), from
`generate.py test`: written by `qwen/qwen3.8-27b`, labelled by
`openai/gpt-oss-120b` against the example policy's three clauses. 41 violate
at least one clause (9 payments, 19 external data, 13 production changes); 64
don't (46 lookalikes such as reading invoices, deploying to staging, pushing
build artifacts, plus 18 ordinary commands). Fixtures only: example.com or
.invalid hosts, invented IDs. Labels are one LLM's; the labeller usually tags
a payment as also sending customer data out, which is defensible.

## Split and bar (fixed before training)

Rows split by `sha256(id) % 2`: **dev** (even) for building and choosing;
**test** (odd) scored once.

Baseline: today's evaluation (clause check AND `requires_actions` gate) on
"description + command". Candidate: a small per-clause classifier trained on
commands written by a different model (`generate.py train`), combined with
the baseline as chosen on dev.

**Bar:** the candidate ships if, on test, recall over (command, clause)
pairs rises by at least 0.10 over the baseline, and benign commands flagged
stay at or below the larger of the baseline's count and 10% of the benign
test commands.

### Amendment (recorded after the dev baseline, before any test run)

The dev baseline (today's check AND gate) caught 23/27 violating pairs
(recall 0.85) but flagged 9 of 35 benign commands, 10 false alarms coming
from `no_prod_change` on staging and read-only production commands. The bar
above targets recall and only allows an OR combination, which can't reduce
false alarms, so it measures the wrong weakness. Added, and judged on the
same single test run:

- **Candidate B:** the clause's student replaces the check, behind the same
  gate (`student` in `run.py`).
- **B ships if**, on test, F1 over (command, clause) pairs rises by at least
  0.05 over the baseline, and recall drops by no more than 0.05.

The original bar still applies to the OR candidate. Both results are
reported whichever way they go.

## Result: not adopted

Chosen on dev? Neither candidate looked good on dev (baseline recall 0.85 with
9/35 benign flagged; replace 0.63, 5/35; either 0.89, 12/35). The single test
run (`run.py --split test`, jev-os `base`), pairs over the three clauses:

| system | recall | benign flagged | pair F1 |
|---|---|---|---|
| baseline (check AND gate) | 19/24 (0.79) | 7/29 | 0.68 |
| student replaces the check | 17/24 (0.71) | 1/29 | 0.81 |
| either | 19/24 (0.79) | 8/29 | 0.67 |

- **Either** (original bar: recall +0.10): recall +0.00. **Not adopted.**
- **Replace** (amended bar: F1 +0.05, recall -0.05 at most): F1 +0.13 but
  recall -0.08. **Not adopted.**

So the example policy keeps its zero-shot checks, and the student wiring
(`student_model`, `student_mode`) ships unused, for clauses someone trains
with this method.

**Lead for a next round, not adopted now:** on test, the `no_prod_change`
student removed all 11 production false alarms at the same recall (7/8).
Turning on only that student after seeing this would be choosing on the test
set, and dev didn't support it (its recall there was 4/9 against 7/9). It
needs a fresh test set. Also, the two labellers disagree on whether a payment
"sends customer data out" (gpt-oss-120b, which labelled the test set, usually
says yes; qwen, which labelled training, says no), which costs the
external-data student recall on payment commands.

Per clause on test (caught/positives, false alarms): baseline external
8/12, 2; production 7/8, 11; payments 4/4, 0. Students: 7/12, 1; 7/8, 0;
3/4, 0. Training: 267 commands (gpt-oss-120b, labelled by qwen), threshold
by F1 on a held-back 30% of training data.
