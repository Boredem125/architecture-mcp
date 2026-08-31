# Threat model — organized by attacker goal

A useful threat model asks *what can an attacker achieve*, not just *which commands look
scary*. The adversary here is a **compromised or prompt-injected agent** operating with
the developer's ambient access — the exact scenario regulated enterprises are concerned
with. The model *may* run a
private, in-tenant LLM; that changes nothing below, because these are authorization and
action threats, not data-residency threats.

For each goal: the attack, and the control that stops it.

## Goal 1 — Escape the workspace

**Attack.** `../../secret`, absolute paths, symlink/junction into the tree, UNC
(`\\host\share`), device paths (`\\?\`), NTFS alternate data streams (`file.txt:evil`),
drive-relative (`C:foo`).
**Control.** One containment primitive ([fs/containment.py](../src/sandbox/fs/containment.py)):
`resolve_under` does case-normalized, component-aware comparison, walks the ancestor chain
rejecting reparse points, and refuses UNC/device/ADS/drive-relative paths. Reads/writes
outside the root are classified `read_outside` / `write_outside` and escalated or denied.

## Goal 2 — Privilege escalation

**Attack.** Spawn PowerShell, edit services/registry, `sudo`, install global tooling.
**Control.** Shell tools are gated: blocklist → deny; otherwise the configured trigger
(default **escalate**). The approved command runs in the **broker outside the agent**, at
the approver's discretion — the agent never receives elevated capability itself.

## Goal 3 — Data theft / exfiltration

**Attack.** Read a secret, then `curl`/DNS/MCP it to an external host — a destination a
private model gateway never inspects.
**Control.** Network tools are gated by host allowlist; unknown destinations escalate. The
risk score spikes when the command also touches `.env`/`.ssh`/credential paths. Outbound
approved-command output is run through the secret/PII scrubber before it re-enters context.
This is the **kill-chain demo**: reasoning layer compromised, authorization layer holds.

## Goal 4 — Policy manipulation

**Attack.** Edit `policy.json` to allow itself; disable hooks; weaken triggers.
**Control.** `.sandbox/**` and `.git/hooks/**` are **re-injected into the deny list on
every policy load** — non-removable. `\.sandbox` is a shell deny-pattern. An agent that is
denied cannot free itself by editing its own constraints.

## Goal 5 — Audit evasion

**Attack.** Delete or rewrite audit records; fork the chain via a process restart; race
the queue.
**Control.** Tamper-evident SHA-256 hash chain that **rehydrates from disk** (a restart
cannot silently fork it); every terminal record is Ed25519-signed (non-repudiation);
`.sandbox/` writes are denied so the log is not agent-writable; the queue uses atomic
`os.rename` claiming (single winner, no race).

## Goal 6 — Human manipulation (social engineering the approver)

**Attack.** A plausible-looking command with a misleading `description`; **approval
fatigue** — burying one bad request in a flood of benign ones.
**Control.** The approver panel shows *identity + risk band + reason code + the itemized
risk factors*, not just the command string, so the human sees why it matters. Critical-risk
actions require **two** approvers (dual control). *Roadmap:* approval-fatigue detection
raises scrutiny when approval rate spikes (see [ROADMAP.md](ROADMAP.md)).

---

**Residual risk / honest limits.** The `.sandbox/` folder is trusted infrastructure — an
attacker with unrestricted filesystem access to it outside the agent's mediated path is
outside this model's boundary. See [TCB.md](TCB.md) for the trust boundary and how a
production deployment would harden it.
