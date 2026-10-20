# Trusted Computing Base (TCB)

Every security system rests on a set of components it *must* trust; naming them honestly is
the difference between a real control and security theatre. This is the connector's TCB and
the trust assumption behind it.

## The core assumption

> **The `.sandbox/` folder is trusted infrastructure.**

The control plane — policy, queue, audit — lives in `.sandbox/`. The reviewers' signing keys
and pins do not: they live in a per-user key home outside every workspace
([keyhome.py](../src/sandbox/connector/keyhome.py), [ADR 0007](adr/0007-reviewer-key-custody-pins-domain-tags.md)).
The design protects both *from the mediated agent*: `.sandbox/**` is a non-removable
write-deny, `\.sandbox` is a shell deny-pattern, the key home is a non-removable
read/write/delete/rename deny, and every hook path fails **closed**. So an agent acting
*through* its normal tools cannot touch the control plane or the keys.

What the model does **not** defend against is an actor with **unrestricted, unmediated
filesystem access** to `.sandbox/` or the key home (e.g. a second process running as the same
OS user, including a `python` command a human approved, or an attacker who already has the
developer's shell). That is out of scope by construction — if
the attacker is already the user outside the sandbox, there is no sandbox left to enforce.

## The components (and what each must be trusted to do)

| # | Component | File(s) | Must be trusted to… | If compromised… |
|---|-----------|---------|---------------------|-----------------|
| 1 | **Hook stub** | `.sandbox/hooks/*.py` (from [hook_templates.py](../src/sandbox/connector/hook_templates.py)) | read stdin, locate `.sandbox/`, delegate; fail closed on error | the agent's calls go ungoverned → the stub is minimal, stdlib-only, and exits non-zero on any error |
| 2 | **Hook logic** | [hook_eval.py](../src/sandbox/connector/hook_eval.py), [classify.py](../src/sandbox/connector/classify.py), [risk.py](../src/sandbox/connector/risk.py) | classify correctly, escalate the right things | wrong verdicts → covered by the largest test surface in the repo |
| 3 | **Broker** | [broker.py](../src/sandbox/connector/broker.py), [privilege_broker.py](../src/sandbox/broker/privilege_broker.py) | run only *approved* actions, outside the agent | arbitrary execution → only ever invoked by the approver on a claimed record |
| 4 | **Approver** | `sandbox watch` / CLI / API ([connector_cmds.py](../src/sandbox/cli/connector_cmds.py)) | present the decision truthfully; be a real human/role | rubber-stamping → risk band + factors surfaced; dual control for critical: two distinct signed approvals (distinct ids and keys, not proof of two humans) |
| 5 | **Policy loader** | [policy.py](../src/sandbox/connector/policy.py) | re-inject self-protection every load | agent frees itself → protections are non-removable by construction |
| 6 | **Audit writer + signer** | [audit.py](../src/sandbox/connector/audit.py), [signing.py](../src/sandbox/connector/signing.py), [keyhome.py](../src/sandbox/connector/keyhome.py) | append-only, chained, signed; keep seeds only in the key home | forged history → hash chain + Ed25519 signatures (domain-tagged, checked against pinned reviewer keys); rehydrates on restart; no key home → no signature |
| 7 | **`.sandbox/` storage** | the folder | integrity of the above | total compromise → the core assumption above; hardened in prod (below) |

## How production would shrink the TCB

This is a local proof-of-work. In a bank, the trust boundary tightens:

- **Signing keys → HSM / smartcard.** Today the approver's Ed25519 seed sits at
  `<key home>/<workspace id>/<reviewer>.seed`, outside the workspace but readable by the
  same OS user. In production the approver's key is a per-human
  credential in an HSM or smartcard; the *signing interface* here is what transfers, not the
  on-disk custody. The evidence exporter's key (`evidence-exporter.seed`, which signs
  `sandbox export-evidence` manifests) sits in the same folder and has the same limit.
- **Control plane → out of the workspace.** The keys have moved out of `.sandbox/`; the
  queue and audit have not. Move that state to a service or a directory the developer's own
  account cannot write, so component 7 no longer depends on workspace filesystem permissions.
- **Approver identity → SSO/RBAC.** `reviewer_id` becomes an authenticated principal; dual
  control requires two *distinct* authenticated humans.
- **Audit → append-only sink.** Ship the chain to a WORM store; the local chain becomes a
  spool, not the system of record.

Naming these keeps the demo honest and shows the path from proof-of-work to production.
