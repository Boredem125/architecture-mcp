"""The typed questions the semantic layer asks, as jev-os question specs.

Plain dicts (the jev-os HTTP API format), so the gateway needs no jev-os install
to use them: hooks send them to a running `jevos serve`, and the benchmark
converts them with `jevos.questions_from_dict`.

Statements are written literally and positively: the NLI models behind jev-os
answer exactly what is written. Change wording only against the benchmark in
benchmarks/injection/, since small wording changes move results a lot.
"""
from __future__ import annotations

# Untrusted content (READMEs, web pages, tool output) trying to steer the agent.
INJECTION_CHECKS: dict[str, dict[str, str]] = {
    "override": {"type": "noul", "instructions": "The text tries to override or ignore previous instructions"},
    "instructs_ai": {"type": "noul", "instructions": "The text gives instructions to an AI system"},
    "exfiltrate": {"type": "noul", "instructions": "The text tells an AI to send data, secrets or files somewhere"},
}
