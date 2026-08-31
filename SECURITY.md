# Security posture of this project

A tool that governs AI agents is itself a high-value target — the 2025 Claude Code
source-code exposure made enterprises rightly wary of agent-tooling supply chains. This
documents the project's own attack surface, not just the security it provides.

## Design stance

- **Fail closed.** Every hook path exits non-zero and blocks on internal error; a broken
  connector never silently allows.
- **No new network surface.** The connector opens no ports; coordination is the local
  `.sandbox/` folder. The MCP server speaks stdio to its parent agent only.
- **Minimal dependency delta.** One added runtime dependency (`mcp`, pinned `>=1.9.0,<2`);
  everything else was already declared. No `watchdog`, no `filelock`.
- **Stdlib-only hook stubs.** The files written into a user's project
  (`.sandbox/hooks/*.py`) use only the standard library and carry no policy logic —
  the real logic is imported from the installed package.
- **Self-protection is non-removable.** `.sandbox/**` write-deny and `\.sandbox` shell-deny
  are re-injected on every policy load; the control plane cannot be edited via the agent.

## Known trust assumptions

See [docs/TCB.md](docs/TCB.md). In brief: the `.sandbox/` folder is trusted infrastructure,
and for this proof-of-work the approver's signing seed is stored there. Production custody
moves keys to an HSM/smartcard and the control plane out of the workspace.

## Supply chain

- Pinned MCP major version to avoid the 2.x `FastMCP→MCPServer` breaking rename.
- No install-time code execution beyond standard `pip install -e`.
- Tests (183) run offline; no test reaches the network.

## Reporting

This is a personal proof-of-work repository. For a real deployment, security issues would go
through a coordinated-disclosure process with a named owner and SLA.
