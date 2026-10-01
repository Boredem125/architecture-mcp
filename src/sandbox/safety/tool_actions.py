"""Summarize what a non-shell tool call (MCP tool or WebFetch) actually does.

The counterpart of command_actions.py for calls that aren't shell commands.
Governance clauses use these tags as a deterministic gate (like
``requires_actions`` for shell commands), so a noisy zero-shot check only
runs on calls that plausibly do the thing the clause is about.

Tags:
  moves_money   a money verb (charge, refund, payout, transfer, pay...) on a
                call whose action isn't a read (list, get, query...)
  sends_data    sends, posts, uploads, emails or syncs data, or a WebFetch
                whose query string carries data-like parameters. Moving money
                implies it: a payment carries payer or card data to a processor.
  prod_change   a mutating infrastructure call (deploy, scale, restart,
                migrate, DNS, feature flag...) that doesn't name a non-production
                environment. An unspecified environment counts as production:
                conservative, since a missed production change is the costly error.

Deterministic and best-effort, from the tool's name and arguments.
"""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

_READ = re.compile(
    r"^(list|get|read|describe|query|search|fetch|retrieve|show|find|count|check|validate|preview|plan|"
    r"estimate|calculate|compute|draft|pull|lookup|view|inspect|status|head|watch|diff|dry|simulate|test)")
_MONEY = re.compile(r"(charge|refund|payout|transfer|pay|sale|capture|disburse|remit|wire|withdraw|settle)", re.I)
_SEND = re.compile(
    r"(send|post|upload|share|publish|export|sync|notify|email|mail|forward|submit|ingest|track|push|"
    r"webhook|event|message|comment|invite)", re.I)
_INFRA = re.compile(
    r"(deploy|release|rollout|rollback|scale|restart|reboot|migrat|dns|record|route53|flag|workload|cluster|"
    r"kubernetes|k8s|helm|terraform|apply|patch|provision|service|instance|database|config|secret|cert|"
    r"transition|promote)", re.I)
_MUTATE = re.compile(
    r"(create|update|set|put|patch|delete|remove|apply|deploy|release|rollout|scale|restart|reboot|migrat|"
    r"execute|run|promote|transition|toggle|enable|disable|rotate|replace|upsert|trigger|install|provision)",
    re.I)
_NONPROD = re.compile(r"\b(stag(e|ing)|dev(elopment)?|preview|test(ing)?|sandbox|qa|uat|local|demo)\b|[-_](dev|stg|staging|test)\b|\b(dev|stg|staging|test)[-_]", re.I)
_DATA_PARAM = re.compile(r"(email|user|customer|cust|acct|account|session|token|name|phone|address|ssn|card|lead|record|data|payload)", re.I)


def split_tool(tool_name: str) -> tuple[str, str]:
    """('stripe', 'create_refund') for mcp__stripe__create_refund; ('web', '') for WebFetch."""
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__", 2)
        return (parts[1] if len(parts) > 1 else ""), (parts[2] if len(parts) > 2 else "")
    return ("web", "") if tool_name in ("WebFetch", "WebSearch") else ("", tool_name)


def _flat(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True) if not isinstance(value, str) else value


def describe_call(tool_name: str, tool_input: dict[str, Any]) -> list[tuple[str, str]]:
    """(tag, human label) pairs for what this call does."""
    server, action = split_tool(tool_name)
    args = _flat(tool_input or {})
    tags: list[tuple[str, str]] = []

    if tool_name == "WebFetch":
        url = str((tool_input or {}).get("url", ""))
        prompt = str((tool_input or {}).get("prompt", ""))
        parsed = urlparse(url)
        verb = action = parsed.path.rsplit("/", 1)[-1] if parsed.path else ""
        writes = bool(re.search(r"\b(post|put|patch|delete|create|submit|send|charge|capture|refund|deploy)\b", prompt, re.I))
        money = bool(_MONEY.search(parsed.path) and writes)
        if money:
            tags.append(("moves_money", "posts a payment request"))
        if money or any(_DATA_PARAM.search(k) for k, _ in parse_qsl(parsed.query)) or (writes and _SEND.search(prompt)):
            tags.append(("sends_data", f"sends data to {parsed.hostname or 'a host'}"))
        if writes and _INFRA.search(parsed.path + " " + prompt) and not _NONPROD.search(url + " " + prompt):
            tags.append(("prod_change", "changes a live environment"))
        del verb
        return tags

    reads = bool(_READ.match(action.lower()))
    money = not reads and bool(_MONEY.search(action) or (_MONEY.search(server) and _MUTATE.search(action)))
    if money:
        tags.append(("moves_money", f"moves money ({server}.{action})"))
    if not reads and (_SEND.search(action) or money):
        tags.append(("sends_data", f"sends data ({server}.{action})"))
    if not reads and _MUTATE.search(action) and (_INFRA.search(server) or _INFRA.search(action)) \
            and not _NONPROD.search(f"{server} {action} {args}"):
        tags.append(("prod_change", f"changes infrastructure, no non-production environment named ({server}.{action})"))
    return tags


def render(tool_name: str, tool_input: dict[str, Any], limit: int = 600) -> str:
    """The call as one line of text for a zero-shot check."""
    server, action = split_tool(tool_name)
    head = f"Calls the {server} tool {action}" if server not in ("", "web") else f"Calls {tool_name}"
    return f"{head} with arguments {_flat(tool_input or {})}"[:limit]
