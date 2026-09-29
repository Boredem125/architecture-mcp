"""Scan untrusted tool output for instructions aimed at the AI.

Text is judged sentence by sentence, not as one document. Scored whole, a
README with one planted instruction came out at 0.04 (the benign text drowns it
out); scored per segment, the planted sentence came out at 0.99 and the benign
ones at <= 0.04.
"""
from __future__ import annotations

import fnmatch
import hashlib
import re
from dataclasses import dataclass
from typing import Any

from sandbox.semantic.checks import INJECTION_CHECKS
from sandbox.semantic.client import SemanticClient


@dataclass
class InjectionFinding:
    tool: str
    scores: dict[str, float]
    top_check: str
    top_score: float
    model: str
    latency_ms: float
    text_sha256: str
    text_chars: int
    segment_index: int = 0
    segment_count: int = 1
    segment_sha256: str = ""

    def evidence(self) -> dict[str, Any]:
        # The scanned text itself is not recorded: tool output can contain
        # secrets. The hashes let an examiner match it to the source later.
        return {
            "tool": self.tool,
            "scores": {k: round(v, 4) for k, v in self.scores.items()},
            "top_check": self.top_check,
            "top_score": round(self.top_score, 4),
            "model": self.model,
            "latency_ms": round(self.latency_ms, 1),
            "text_sha256": self.text_sha256,
            "text_chars": self.text_chars,
            "segment_index": self.segment_index,
            "segment_count": self.segment_count,
            "segment_sha256": self.segment_sha256,
        }


_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")
MIN_SEGMENT_CHARS = 25


def segments(text: str) -> list[str]:
    """Sentences and lines, with tiny fragments ("-->", "# Title") merged into a neighbour."""
    out: list[str] = []
    for piece in (p.strip() for p in _SPLIT.split(text)):
        if not piece:
            continue
        if out and (len(piece) < MIN_SEGMENT_CHARS or len(out[-1]) < MIN_SEGMENT_CHARS):
            out[-1] = f"{out[-1]} {piece}"
        else:
            out.append(piece)
    return out


def should_scan(tool_name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(tool_name, p) for p in patterns)


def response_text(tool_response: Any, limit: int) -> str:
    """Collect the human-readable strings from a tool response, depth-first."""
    parts: list[str] = []
    size = 0

    def walk(value: Any) -> None:
        nonlocal size
        if size >= limit:
            return
        if isinstance(value, str):
            s = value.strip()
            if s:
                parts.append(s)
                size += len(s)
        elif isinstance(value, dict):
            for v in value.values():
                walk(v)
        elif isinstance(value, (list, tuple)):
            for v in value:
                walk(v)

    walk(tool_response)
    return "\n".join(parts)[:limit]


def scan(tool_name: str, text: str, client: SemanticClient, threshold: float) -> InjectionFinding | None:
    """A finding if any injection check reaches the threshold, else None.

    None also covers "service unavailable": no extra scrutiny, never less.
    """
    segs = segments(text)
    if not segs:
        return None
    results = client.ask_many(segs, INJECTION_CHECKS)
    if not results:
        return None
    worst = max(range(len(results)), key=lambda i: results[i].top()[1])
    top_check, top_score = results[worst].top()
    if top_score < threshold:
        return None
    return InjectionFinding(
        tool=tool_name,
        scores=results[worst].scores,
        top_check=top_check,
        top_score=top_score,
        model=results[worst].model,
        latency_ms=sum(r.latency_ms for r in results),
        text_sha256=_sha(text),
        text_chars=len(text),
        segment_index=worst,
        segment_count=len(segs),
        segment_sha256=_sha(segs[worst]),
    )


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()
