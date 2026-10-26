# OpenShell evaluation (lead-architect + product-manager, 25 Oct 2026)

**Status: the M3 spike was dropped by the founder on 25 Oct.** No fork, no adapter, no NVIDIA code. We rebuild selected ideas in our own code instead; see `SENTRY_IDEAS.md`.

**Recommendation that stands:** stay independent (option A). Forking or basing on OpenShell (C) is a no. The adapter (B) is off the roadmap.
OpenShell boxes the agent in a Linux sandbox. We authorize and sign the actions that cross it. We are complementary to it, not built on it.

## Evidence (verified 25 Oct)
| Fact | Source |
|---|---|
| Apache-2.0 with a DCO; about 87% Rust. Ours is Python (about 14.7k lines connector, 8.7k ee) | [repo](https://github.com/NVIDIA/OpenShell), GitHub API |
| v0.1.5 shipped 20 Oct; 577 open issues; 19.7k stars | GitHub releases API |
| Linux sandbox (Landlock, seccomp, kernel 6.2+). Windows only through WSL 2, "experimental" | [support matrix](https://docs.nvidia.com/openshell/latest/about/support-matrix) |
| Policy advisor approvals happen in a TUI; the sample governance interceptor signs policy with an in-memory key regenerated at each start, not bound to a person. No per-person keys or dual control found | `examples/policy-advisor`, `examples/governance-interceptor` |
| OCSF events export as JSONL or OTLP; no signing, chaining or approver identity stated | [observability](https://docs.nvidia.com/openshell/latest/observability) |
| Part of NVIDIA's Open Agent Safety Platform with Sentry (BlueField-4 DPUs) | [nvidia.com](https://nvidia.com/en-us/solutions/ai/agent-safety) |

## What still holds
- **Defensible ground:** per-person keys, dual control, offline verification against a root the buyer holds, and runtimes OpenShell doesn't reach (Windows hosts, Claude Code hooks, MCP). "Signing" alone isn't defensible: NVIDIA's own example already signs policy.
- **Platform risk:** NVIDIA is one step from per-person approval keys. Mitigation: vendor-independent offline verification and coverage of runtimes NVIDIA doesn't reach.
- **Clean room:** anything we adopt is built from public docs and our own design. We copy no code.

## Superseded
The 3-day spike, its exit metric and founder questions 1-3 of the earlier draft are withdrawn. Discovery question 3 (Linux sandboxes or developer laptops, Windows included) moves to `SENTRY_IDEAS.md`.
