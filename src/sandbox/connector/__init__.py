"""Folder connector — plug the sandbox into an agent you already run.

Drop `.sandbox/` into a project folder; an external agent (Claude Code,
Codex, …) works there; privileged actions are escalated to a human and the
approved output is fed back into the agent's context. See the connector
plan for the full design.
"""
