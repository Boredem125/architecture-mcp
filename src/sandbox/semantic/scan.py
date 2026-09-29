"""Scan untrusted tool output for instructions aimed at the AI.

Text is judged sentence by sentence, not as one document. Scored whole, a
README with one planted instruction came out at 0.04 (the benign text drowns it
out); scored per segment, the planted sentence came out at 0.99 and the benign
ones at <= 0.04.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
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


# Block and HTML comment markers, which hide text from a human reader. Line
# comment markers (#, //) are kept: they tell the model the text is a code
# comment, and without them "# Forget the cached token if..." read as an
# instruction to forget (0.69 vs below threshold with the marker).
_COMMENT = re.compile(r"<!--|-->|/\*+|\*+/")
# Tool/log chatter that carries no instruction and dilutes the sentence after it:
# "npm WARN deprecated", "HTTP 200 OK", "[INFO] 12:01:03", "Build succeeded."
_NOISE_LINE = re.compile(
    r"^\s*(?:(?:npm|yarn|pnpm|pip)\s+(?:WARN|ERR!|notice|warn)\b.*"
    r"|HTTP/?[\d.]*\s+\d{3}\b.*"
    r"|\[?(?:INFO|WARN|WARNING|DEBUG|ERROR|TRACE)\]?:?\s*$"
    r"|(?:Build|Tests?|Deploy)\s+(?:succeeded|passed|failed)\.?"
    r"|Test results:.*)\s*$",
    re.I | re.M,
)


def unwrap(text: str) -> str:
    """Pull the prose out of machine formatting before judging it.

    JSON anywhere in the text is replaced by its string values; comment markers
    and tool/log chatter lines are removed. An instruction wrapped as
    {"message": "To the model reading this: ..."} or /* NOTE FOR LLM: ... */ is
    then judged as the sentence it is.
    """
    out, i = [], 0
    decoder = json.JSONDecoder()
    while i < len(text):
        j = min((k for k in (text.find("{", i), text.find("[", i)) if k != -1), default=-1)
        if j == -1:
            out.append(text[i:])
            break
        out.append(text[i:j])
        try:
            value, end = decoder.raw_decode(text, j)
        except ValueError:
            out.append(text[j])
            i = j + 1
            continue
        strings = _strings(value)
        out.append("\n" + "\n".join(strings) + "\n" if strings else " ")
        i = end
    prose = "".join(out)
    prose = _NOISE_LINE.sub("", prose)
    return _COMMENT.sub(" ", prose)


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def prepare(text: str) -> list[str]:
    """Text → the segments the model judges. Shared by the gateway and the benchmark."""
    return segments(unwrap(text))


def verdict(scores: dict[str, float], threshold: float) -> str:
    """One segment's scores → "high" (taint) or "none".

    High if any direct signal fires, or if the sentence both addresses an AI
    and asks for an action. The combination was chosen on the hand-written dev
    sets (+3 caught, 0 new false alarms) and checked on held-out data (no
    change either way); see benchmarks/injection/README.md.
    """
    direct = max(scores["override"], scores["instructs_ai"], scores["exfiltrate"]) >= threshold
    aimed_action = scores["addresses_ai"] >= threshold and scores["requests_action"] >= threshold
    return "high" if direct or aimed_action else "none"


def reason(scores: dict[str, float], threshold: float) -> tuple[str, float]:
    """The check (or check pair) that decided, and its score, for the evidence record."""
    direct = {k: scores[k] for k in ("override", "instructs_ai", "exfiltrate")}
    top = max(direct, key=direct.get)
    if direct[top] >= threshold:
        return top, direct[top]
    return "addresses_ai+requests_action", min(scores["addresses_ai"], scores["requests_action"])


def scan(tool_name: str, text: str, client: SemanticClient, threshold: float) -> InjectionFinding | None:
    """A finding if any segment's verdict is "high", else None.

    None also covers "service unavailable": no extra scrutiny, never less.
    """
    segs = prepare(text)
    if not segs:
        return None
    results = client.ask_many(segs, INJECTION_CHECKS)
    if not results:
        return None
    flagged = [i for i, r in enumerate(results) if verdict(r.scores, threshold) == "high"]
    if not flagged:
        return None
    worst = max(flagged, key=lambda i: reason(results[i].scores, threshold)[1])
    top_check, top_score = reason(results[worst].scores, threshold)
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
