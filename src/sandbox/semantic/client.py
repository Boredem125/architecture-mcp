"""Talk to a local jev-os service (`jevos serve`) with a short timeout.

Hooks are short-lived subprocesses, so the model can't be loaded per call; it
lives in a long-running local service instead. Every failure (service down,
timeout, bad response) returns ``None``, and callers treat ``None`` as "no
extra scrutiny", which is today's behavior. The semantic layer can never make
a decision more permissive, so failing open here is safe.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass
class SemanticResult:
    scores: dict[str, float]
    model: str
    latency_ms: float

    def top(self) -> tuple[str, float]:
        name = max(self.scores, key=self.scores.get)
        return name, self.scores[name]


class SemanticClient:
    def __init__(self, url: str, api_key_env: str = "JEVOS_API_KEY", timeout_seconds: float = 3.0) -> None:
        self.url = url.rstrip("/")
        self.api_key = os.environ.get(api_key_env, "")
        self.timeout = timeout_seconds

    @classmethod
    def from_policy(cls, semantic_policy: Any) -> "SemanticClient":
        return cls(semantic_policy.url, semantic_policy.api_key_env, semantic_policy.timeout_seconds)

    @classmethod
    def screen_from_policy(cls, semantic_policy: Any) -> "SemanticClient | None":
        """The fast stage-1 screen (a second service, e.g. the xsmall model), or
        None when no screen is configured. Same key and timeout as the main one."""
        url = getattr(semantic_policy, "screen_url", "")
        if not url:
            return None
        return cls(url, semantic_policy.api_key_env, semantic_policy.timeout_seconds)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}

    def ask(self, text: str, checks: dict[str, dict[str, Any]]) -> SemanticResult | None:
        """Yes/no probabilities for each check, or None if the service can't answer."""
        try:
            resp = httpx.post(
                f"{self.url}/v1/system_one",
                json={"state": text, "questions": checks},
                headers=self._headers(),
                timeout=_timeout(self.timeout),
            )
            if resp.status_code != 200:
                return None
            return _parse(resp.json(), checks)
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            return None

    def ask_many(self, texts: list[str], checks: dict[str, dict[str, Any]]) -> list[SemanticResult] | None:
        """One result per text via /v1/batch, or None if any part fails.

        Falls back to one /v1/system_one call per text on services without the
        batch endpoint. The timeout covers the whole call, not each text.
        """
        if not texts:
            return []
        deadline = time.monotonic() + self.timeout
        results: list[SemanticResult] = []
        try:
            for start in range(0, len(texts), BATCH_SIZE):
                chunk = texts[start:start + BATCH_SIZE]
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                resp = httpx.post(
                    f"{self.url}/v1/batch",
                    json={"states": chunk, "questions": checks},
                    headers=self._headers(),
                    timeout=_timeout(remaining),
                )
                if resp.status_code == 404:
                    return self._ask_each(texts, checks, deadline)
                if resp.status_code != 200:
                    return None
                parsed = [_parse(r, checks) for r in resp.json().get("results", [])]
                if len(parsed) != len(chunk) or any(p is None for p in parsed):
                    return None
                results.extend(parsed)  # type: ignore[arg-type]
            return results
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            return None

    def _ask_each(self, texts: list[str], checks: dict[str, dict[str, Any]], deadline: float) -> list[SemanticResult] | None:
        out = []
        for text in texts:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self.timeout, saved = remaining, self.timeout
            try:
                r = self.ask(text, checks)
            finally:
                self.timeout = saved
            if r is None:
                return None
            out.append(r)
        return out


BATCH_SIZE = 64  # jev-os /v1/batch limit
# The service is local, so connecting takes well under a millisecond when it
# is up. When it is down, Windows takes about 2 s to report a refused
# localhost connection, and every scan paid that. A short connect timeout
# makes "service down" fast; the read timeout stays the full budget.
CONNECT_TIMEOUT = 0.5


def _timeout(total: float) -> httpx.Timeout:
    return httpx.Timeout(total, connect=min(CONNECT_TIMEOUT, total))


def _parse(data: dict[str, Any], checks: dict[str, dict[str, Any]]) -> SemanticResult | None:
    scores = {
        name: float(ans["noul"])
        for name, ans in data.get("answers", {}).items()
        if ans.get("type", "noul") == "noul" and "noul" in ans
    }
    if set(scores) != set(checks):
        return None
    return SemanticResult(scores, str(data.get("model", "")), float(data.get("latency_ms", 0.0)))
