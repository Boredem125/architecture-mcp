"""Agent Runtime — spawns and manages AI agents with sandboxed tool execution.

Every tool call from a real agent (Claude, Codex, etc.) is routed through
the 8-step mediation pipeline before execution. The agent never touches
the host system directly.
"""
from __future__ import annotations

import asyncio
import os
import time
import uuid
from enum import StrEnum
from typing import Any

import structlog

from sandbox.agents.tools import SandboxedToolkit
from sandbox.config import ContainmentSettings, ExecutorSettings
from sandbox.containment.docker_sandbox import DockerSandbox, _check_docker_available
from sandbox.containment.process_sandbox import ProcessSandbox
from sandbox.models.enums import ActionType
from sandbox.models.messages import ActionRequest, PipelineStatus
from sandbox.models.session import SessionStartRequest, SessionState
from sandbox.pipeline.orchestrator import PipelineOrchestrator
from sandbox.pipeline.session_manager import SessionManager

logger = structlog.get_logger()


class AgentStatus(StrEnum):
    INITIALIZING = "initializing"
    RUNNING = "running"
    WAITING_HITL = "waiting_hitl"
    COMPLETED = "completed"
    FAILED = "failed"
    KILLED = "killed"


class AgentRun:
    """Tracks a single agent execution lifecycle."""

    def __init__(
        self,
        run_id: str,
        agent_type: str,
        agent_id: str,
        session: SessionState,
        task: str,
    ) -> None:
        self.run_id = run_id
        self.agent_type = agent_type
        self.agent_id = agent_id
        self.session = session
        self.task = task
        self.status = AgentStatus.INITIALIZING
        self.started_at = time.time()
        self.ended_at: float | None = None
        self.messages: list[dict[str, Any]] = []
        self.tool_calls: list[dict[str, Any]] = []
        self.error: str | None = None
        self.containment: str = "none"
        self.container_id: str | None = None
        self._cancel_event = asyncio.Event()
        self._task: asyncio.Task[Any] | None = None
        self._sandbox: DockerSandbox | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "agent_type": self.agent_type,
            "agent_id": self.agent_id,
            "session_id": self.session.session_id,
            "task": self.task,
            "status": self.status.value,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "message_count": len(self.messages),
            "tool_call_count": len(self.tool_calls),
            "error": self.error,
            "containment": self.containment,
            "container_id": self.container_id,
        }


class AgentRuntime:
    """Manages agent lifecycle — spawn, run, kill.

    The runtime creates a sandbox session for each agent, wraps tools
    so every action goes through the pipeline, and streams events via
    the WebSocket broadcaster.

    When Docker is available and enabled, each agent gets its own
    container for real OS-level isolation. Otherwise falls back to
    host execution with a visible WARNING.
    """

    def __init__(
        self,
        session_manager: SessionManager,
        event_broadcaster: Any = None,
        containment_settings: ContainmentSettings | None = None,
        executor_settings: ExecutorSettings | None = None,
    ) -> None:
        self._session_manager = session_manager
        self._broadcaster = event_broadcaster
        self._runs: dict[str, AgentRun] = {}
        self._containment = containment_settings or ContainmentSettings()
        self._executor = executor_settings or ExecutorSettings()
        self._docker_available: bool | None = None

    @property
    def active_runs(self) -> list[AgentRun]:
        return [r for r in self._runs.values() if r.status == AgentStatus.RUNNING]

    def get_run(self, run_id: str) -> AgentRun | None:
        return self._runs.get(run_id)

    def list_runs(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._runs.values()]

    async def spawn_agent(
        self,
        agent_type: str,
        task: str,
        capabilities: list[str],
        workspace_root: str = "/tmp/workspace",
        max_writes: int = 50,
        ttl_seconds: int = 1800,
        api_key: str | None = None,
        model: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AgentRun:
        """Spawn a new agent with sandboxed tools.

        1. Creates a sandbox session with scoped capabilities
        2. Builds sandboxed tool definitions
        3. Launches the agent via its SDK
        4. Returns the AgentRun handle
        """
        run_id = str(uuid.uuid4())
        agent_id = f"{agent_type}-{run_id[:8]}"

        allowed_actions = [ActionType(c) for c in capabilities]
        session = self._session_manager.create_session(
            SessionStartRequest(
                agent_id=agent_id,
                declared_task=task,
                allowed_actions=allowed_actions,
                workspace_root=workspace_root,
                max_writes=max_writes,
                ttl_seconds=ttl_seconds,
            )
        )

        run = AgentRun(
            run_id=run_id,
            agent_type=agent_type,
            agent_id=agent_id,
            session=session,
            task=task,
        )
        self._runs[run_id] = run

        # Containment: Docker > ProcessSandbox (Job Objects / rlimits)
        sandbox: DockerSandbox | ProcessSandbox | None = None
        if self._containment.enable_docker:
            if self._docker_available is None:
                self._docker_available = _check_docker_available()

            if self._docker_available:
                try:
                    sandbox = DockerSandbox(
                        session_id=session.session_id,
                        containment_settings=self._containment,
                        executor_settings=self._executor,
                        workspace_host_path=workspace_root,
                        capabilities=capabilities,
                    )
                    container_id = await sandbox.create()
                    run.containment = "docker"
                    run.container_id = container_id
                    run._sandbox = sandbox
                    logger.info(
                        "agent_containerized",
                        run_id=run_id,
                        container_id=container_id[:12],
                    )
                except Exception as e:
                    logger.warning(
                        "docker_failed_using_process_sandbox",
                        error=str(e),
                        run_id=run_id,
                    )
                    sandbox = None

        # Fallback: ProcessSandbox with Job Objects / rlimits
        if sandbox is None:
            try:
                sandbox = ProcessSandbox(
                    session_id=session.session_id,
                    containment_settings=self._containment,
                    executor_settings=self._executor,
                    workspace_host_path=workspace_root,
                    capabilities=capabilities,
                )
                container_id = await sandbox.create()
                run.containment = "process"
                run.container_id = container_id
                run._sandbox = sandbox
                logger.info(
                    "agent_process_sandboxed",
                    run_id=run_id,
                    container_id=container_id,
                )
            except Exception as e:
                logger.error(
                    "process_sandbox_failed",
                    error=str(e),
                    run_id=run_id,
                )
                run.containment = "none"

        await self._emit_event("agent_spawned", run, {
            "capabilities": capabilities,
            "workspace_root": workspace_root,
            "ttl_seconds": ttl_seconds,
            "containment": run.containment,
            "container_id": run.container_id,
        })

        orchestrator = PipelineOrchestrator(
            session_manager=self._session_manager,
            event_broadcaster=self._broadcaster,
        )

        toolkit = SandboxedToolkit(
            session=session,
            orchestrator=orchestrator,
            workspace_root=workspace_root,
            event_broadcaster=self._broadcaster,
            sandbox=docker_sandbox,
        )

        if agent_type == "claude-code":
            run._task = asyncio.create_task(
                self._run_claude_agent(run, toolkit, task, api_key, model)
            )
        elif agent_type == "codex":
            run._task = asyncio.create_task(
                self._run_openai_agent(run, toolkit, task, api_key, model)
            )
        elif agent_type in ("hermes", "antigravity", "custom"):
            run._task = asyncio.create_task(
                self._run_generic_agent(run, toolkit, task, api_key, model, agent_type)
            )
        else:
            run.status = AgentStatus.FAILED
            run.error = f"Unknown agent type: {agent_type}"
            return run

        run.status = AgentStatus.RUNNING
        return run

    async def kill_agent(self, run_id: str) -> bool:
        run = self._runs.get(run_id)
        if run is None:
            return False
        run._cancel_event.set()
        if run._task and not run._task.done():
            run._task.cancel()
        if run._sandbox is not None:
            await run._sandbox.destroy()
        run.status = AgentStatus.KILLED
        run.ended_at = time.time()
        self._session_manager.kill_session(run.session.session_id, "agent_killed")
        await self._emit_event("agent_killed", run)
        return True

    async def _cleanup_run(self, run: AgentRun) -> None:
        """Destroy the container (if any) when a run ends."""
        if run._sandbox is not None:
            await run._sandbox.destroy()
            run._sandbox = None

    # ------------------------------------------------------------------
    # Claude Agent (Anthropic SDK)
    # ------------------------------------------------------------------

    async def _run_claude_agent(
        self,
        run: AgentRun,
        toolkit: SandboxedToolkit,
        task: str,
        api_key: str | None,
        model: str | None,
    ) -> None:
        try:
            import anthropic
        except ImportError:
            run.status = AgentStatus.FAILED
            run.error = "anthropic package not installed. Run: pip install anthropic"
            await self._emit_event("agent_error", run, {"error": run.error})
            return

        resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not resolved_key:
            run.status = AgentStatus.FAILED
            run.error = "No Anthropic API key provided"
            await self._emit_event("agent_error", run, {"error": run.error})
            return

        resolved_model = model or "claude-sonnet-4-20250514"
        client = anthropic.AsyncAnthropic(api_key=resolved_key)
        tools = toolkit.get_anthropic_tool_definitions()
        messages: list[dict[str, Any]] = [{"role": "user", "content": task}]
        run.messages.append({"role": "user", "content": task})

        await self._emit_event("agent_started", run, {"model": resolved_model})

        max_turns = 50
        for turn in range(max_turns):
            if run._cancel_event.is_set():
                break

            try:
                response = await client.messages.create(
                    model=resolved_model,
                    max_tokens=4096,
                    system="You are an AI agent operating inside a security sandbox. Every tool call you make is mediated through an 8-step security pipeline. Follow instructions precisely. Work within the allowed workspace.",
                    tools=tools,
                    messages=messages,
                )
            except Exception as e:
                run.status = AgentStatus.FAILED
                run.error = f"Anthropic API error: {e}"
                await self._emit_event("agent_error", run, {"error": str(e)})
                return

            assistant_msg: dict[str, Any] = {"role": "assistant", "content": []}
            tool_use_blocks = []

            for block in response.content:
                if block.type == "text":
                    assistant_msg["content"].append({"type": "text", "text": block.text})
                    run.messages.append({"role": "assistant", "content": block.text, "turn": turn})
                    await self._emit_event("agent_message", run, {
                        "turn": turn,
                        "text": block.text[:500],
                    })
                elif block.type == "tool_use":
                    assistant_msg["content"].append({
                        "type": "tool_use",
                        "id": block.id,
                        "name": block.name,
                        "input": block.input,
                    })
                    tool_use_blocks.append(block)

            messages.append(assistant_msg)

            if response.stop_reason == "end_turn" and not tool_use_blocks:
                break

            if tool_use_blocks:
                tool_results: list[dict[str, Any]] = []
                for tool_block in tool_use_blocks:
                    await self._emit_event("agent_tool_call", run, {
                        "turn": turn,
                        "tool": tool_block.name,
                        "input": _truncate_dict(tool_block.input),
                    })

                    result = await toolkit.execute_tool(
                        tool_block.name,
                        tool_block.input,
                    )

                    run.tool_calls.append({
                        "turn": turn,
                        "tool": tool_block.name,
                        "input": tool_block.input,
                        "result": _truncate_str(str(result.get("output", result.get("error", ""))), 1000),
                        "status": result.get("status", "unknown"),
                        "pipeline_decision": result.get("pipeline_decision"),
                    })

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_block.id,
                        "content": str(result.get("output", result.get("error", "Tool execution failed"))),
                    })

                    await self._emit_event("agent_tool_result", run, {
                        "turn": turn,
                        "tool": tool_block.name,
                        "status": result.get("status"),
                        "pipeline_decision": result.get("pipeline_decision"),
                    })

                messages.append({"role": "user", "content": tool_results})

            if response.stop_reason == "end_turn":
                break

        await self._cleanup_run(run)
        run.status = AgentStatus.COMPLETED
        run.ended_at = time.time()
        await self._emit_event("agent_completed", run, {
            "turns": turn + 1,
            "tool_calls": len(run.tool_calls),
        })

    # ------------------------------------------------------------------
    # OpenAI Agent (Codex-compatible)
    # ------------------------------------------------------------------

    async def _run_openai_agent(
        self,
        run: AgentRun,
        toolkit: SandboxedToolkit,
        task: str,
        api_key: str | None,
        model: str | None,
    ) -> None:
        try:
            import openai
        except ImportError:
            run.status = AgentStatus.FAILED
            run.error = "openai package not installed. Run: pip install openai"
            await self._emit_event("agent_error", run, {"error": run.error})
            return

        resolved_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not resolved_key:
            run.status = AgentStatus.FAILED
            run.error = "No OpenAI API key provided"
            await self._emit_event("agent_error", run, {"error": run.error})
            return

        resolved_model = model or "gpt-4o"
        client = openai.AsyncOpenAI(api_key=resolved_key)
        tools = toolkit.get_openai_tool_definitions()
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": "You are an AI agent operating inside a security sandbox. Every tool call is mediated through an 8-step security pipeline. Work within the allowed workspace."},
            {"role": "user", "content": task},
        ]
        run.messages.append({"role": "user", "content": task})

        await self._emit_event("agent_started", run, {"model": resolved_model})

        max_turns = 50
        for turn in range(max_turns):
            if run._cancel_event.is_set():
                break

            try:
                response = await client.chat.completions.create(
                    model=resolved_model,
                    messages=messages,
                    tools=tools,
                    max_tokens=4096,
                )
            except Exception as e:
                run.status = AgentStatus.FAILED
                run.error = f"OpenAI API error: {e}"
                await self._emit_event("agent_error", run, {"error": str(e)})
                return

            choice = response.choices[0]
            assistant_msg = choice.message

            if assistant_msg.content:
                run.messages.append({"role": "assistant", "content": assistant_msg.content, "turn": turn})
                await self._emit_event("agent_message", run, {
                    "turn": turn,
                    "text": assistant_msg.content[:500],
                })

            messages.append(assistant_msg.model_dump())

            if not assistant_msg.tool_calls:
                break

            for tool_call in assistant_msg.tool_calls:
                import json
                tool_input = json.loads(tool_call.function.arguments)

                await self._emit_event("agent_tool_call", run, {
                    "turn": turn,
                    "tool": tool_call.function.name,
                    "input": _truncate_dict(tool_input),
                })

                result = await toolkit.execute_tool(
                    tool_call.function.name,
                    tool_input,
                )

                run.tool_calls.append({
                    "turn": turn,
                    "tool": tool_call.function.name,
                    "input": tool_input,
                    "result": _truncate_str(str(result.get("output", result.get("error", ""))), 1000),
                    "status": result.get("status"),
                    "pipeline_decision": result.get("pipeline_decision"),
                })

                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": str(result.get("output", result.get("error", "Tool execution failed"))),
                })

                await self._emit_event("agent_tool_result", run, {
                    "turn": turn,
                    "tool": tool_call.function.name,
                    "status": result.get("status"),
                    "pipeline_decision": result.get("pipeline_decision"),
                })

            if choice.finish_reason == "stop":
                break

        await self._cleanup_run(run)
        run.status = AgentStatus.COMPLETED
        run.ended_at = time.time()
        await self._emit_event("agent_completed", run, {
            "turns": turn + 1,
            "tool_calls": len(run.tool_calls),
        })

    # ------------------------------------------------------------------
    # Generic agent (HTTP tool-calling loop for Hermes/Antigravity/custom)
    # ------------------------------------------------------------------

    async def _run_generic_agent(
        self,
        run: AgentRun,
        toolkit: SandboxedToolkit,
        task: str,
        api_key: str | None,
        model: str | None,
        agent_type: str,
    ) -> None:
        """Generic agent using Anthropic SDK as backbone.

        Hermes, Antigravity, and custom agents all use Claude as
        the underlying model but with different system prompts
        and capability profiles.
        """
        try:
            import anthropic
        except ImportError:
            run.status = AgentStatus.FAILED
            run.error = "anthropic package not installed"
            await self._emit_event("agent_error", run, {"error": run.error})
            return

        resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not resolved_key:
            run.status = AgentStatus.FAILED
            run.error = "No API key provided"
            await self._emit_event("agent_error", run, {"error": run.error})
            return

        system_prompts = {
            "hermes": "You are Hermes, a lightweight task agent focused on file reading and data processing. You operate with minimal privileges. Only use READ operations unless explicitly required.",
            "antigravity": "You are Antigravity, an autonomous development agent with full-stack capabilities. You can read, write, execute commands, and make network requests. Plan carefully before executing.",
            "custom": "You are a custom AI agent operating in a sandboxed environment. Follow the task instructions precisely.",
        }

        resolved_model = model or "claude-sonnet-4-20250514"
        client = anthropic.AsyncAnthropic(api_key=resolved_key)
        tools = toolkit.get_anthropic_tool_definitions()

        await self._emit_event("agent_started", run, {"model": resolved_model, "persona": agent_type})

        # Reuse the Claude agent loop with a different system prompt
        messages: list[dict[str, Any]] = [{"role": "user", "content": task}]
        run.messages.append({"role": "user", "content": task})

        max_turns = 50
        for turn in range(max_turns):
            if run._cancel_event.is_set():
                break

            try:
                response = await client.messages.create(
                    model=resolved_model,
                    max_tokens=4096,
                    system=system_prompts.get(agent_type, system_prompts["custom"]),
                    tools=tools,
                    messages=messages,
                )
            except Exception as e:
                run.status = AgentStatus.FAILED
                run.error = f"API error: {e}"
                await self._emit_event("agent_error", run, {"error": str(e)})
                return

            assistant_msg: dict[str, Any] = {"role": "assistant", "content": []}
            tool_use_blocks = []

            for block in response.content:
                if block.type == "text":
                    assistant_msg["content"].append({"type": "text", "text": block.text})
                    run.messages.append({"role": "assistant", "content": block.text, "turn": turn})
                    await self._emit_event("agent_message", run, {"turn": turn, "text": block.text[:500]})
                elif block.type == "tool_use":
                    assistant_msg["content"].append({
                        "type": "tool_use", "id": block.id,
                        "name": block.name, "input": block.input,
                    })
                    tool_use_blocks.append(block)

            messages.append(assistant_msg)

            if response.stop_reason == "end_turn" and not tool_use_blocks:
                break

            if tool_use_blocks:
                tool_results: list[dict[str, Any]] = []
                for tb in tool_use_blocks:
                    result = await toolkit.execute_tool(tb.name, tb.input)
                    run.tool_calls.append({
                        "turn": turn, "tool": tb.name, "input": tb.input,
                        "status": result.get("status"), "pipeline_decision": result.get("pipeline_decision"),
                    })
                    tool_results.append({
                        "type": "tool_result", "tool_use_id": tb.id,
                        "content": str(result.get("output", result.get("error", ""))),
                    })
                    await self._emit_event("agent_tool_result", run, {
                        "turn": turn, "tool": tb.name,
                        "status": result.get("status"), "pipeline_decision": result.get("pipeline_decision"),
                    })
                messages.append({"role": "user", "content": tool_results})

            if response.stop_reason == "end_turn":
                break

        run.status = AgentStatus.COMPLETED
        run.ended_at = time.time()
        await self._emit_event("agent_completed", run, {"turns": turn + 1, "tool_calls": len(run.tool_calls)})

    # ------------------------------------------------------------------
    # Event broadcasting
    # ------------------------------------------------------------------

    async def _emit_event(self, event_type: str, run: AgentRun, extra: dict[str, Any] | None = None) -> None:
        if self._broadcaster is None:
            return
        event = {
            "event": event_type,
            "run_id": run.run_id,
            "agent_type": run.agent_type,
            "agent_id": run.agent_id,
            "session_id": run.session.session_id,
            "request_id": run.run_id,
            **(extra or {}),
        }
        try:
            await self._broadcaster.broadcast(event)
        except Exception:
            pass


def _truncate_str(s: str, max_len: int = 500) -> str:
    return s[:max_len] + "..." if len(s) > max_len else s


def _truncate_dict(d: Any, max_len: int = 200) -> Any:
    s = str(d)
    if len(s) > max_len:
        return s[:max_len] + "..."
    return d
