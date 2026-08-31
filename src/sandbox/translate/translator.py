"""Plain-language translation of agent actions.

Pluggable provider interface. M1 ships a template/raw summarizer.
M2 adds Grok (XAI_API_KEY) and other LLM providers.

The translator takes structured action events and produces human-readable
explanations for the side panel in the LiveSession UI.
"""
from __future__ import annotations

import re
from typing import Any, Protocol

import structlog

from sandbox.config import TranslateSettings

logger = structlog.get_logger(__name__)


class TranslationProvider(Protocol):
    """Interface for translation providers."""

    async def translate(self, event: dict[str, Any]) -> str:
        """Translate a structured event into plain language."""
        ...


class TemplateTranslator:
    """Template-based translator — M1 fallback, no API calls needed."""

    _TEMPLATES: dict[str, str] = {
        "launch_started": "Started {app_type} (PID {pid}) in {jail_mode} jail mode.",
        "launch_exited": "{app_type} exited with code {exit_code}.",
        "launch_output": "[{stream}] {line}",
        "broker_request": "Requesting privileged access: {command}",
        "broker_decision": "Privilege request {decision} by {reviewer_id}.",
        "hitl_pending": "Action escalated for human review: {action_type} (risk: {risk_tier})",
        "hitl_decided": "Review decision: {decision} by {reviewer_id}.",
        "file_created": "Created file: {path}",
        "file_modified": "Modified file: {path}",
        "file_deleted": "Deleted file: {path}",
    }

    async def translate(self, event: dict[str, Any]) -> str:
        event_type = event.get("event", "unknown")
        template = self._TEMPLATES.get(event_type)
        if template:
            try:
                return template.format_map(_SafeDict(event))
            except (KeyError, ValueError):
                pass
        return self._raw_summary(event)

    def _raw_summary(self, event: dict[str, Any]) -> str:
        event_type = event.get("event", "action")
        parts = [f"[{event_type}]"]
        for k, v in event.items():
            if k in ("event", "timestamp"):
                continue
            parts.append(f"{k}={v}")
        return " ".join(parts)


class _SafeDict(dict):
    """Dict that returns {key} for missing keys instead of raising."""
    def __missing__(self, key: str) -> str:
        return f"{{{key}}}"


class ActionTranslator:
    """Main translator — selects provider based on config."""

    def __init__(self, settings: TranslateSettings | None = None) -> None:
        self._settings = settings or TranslateSettings()
        self._provider = self._create_provider()

    def _create_provider(self) -> TranslationProvider:
        provider_name = self._settings.provider
        if provider_name == "grok" and self._settings.xai_api_key:
            logger.info("translator.using_grok")
            return _GrokStub(self._settings)
        return TemplateTranslator()

    async def translate(self, event: dict[str, Any]) -> str:
        return await self._provider.translate(event)


class _GrokStub:
    """Placeholder for M2 Grok provider."""

    def __init__(self, settings: TranslateSettings) -> None:
        self._settings = settings

    async def translate(self, event: dict[str, Any]) -> str:
        # M2: call XAI API with event context
        fallback = TemplateTranslator()
        return await fallback.translate(event)
