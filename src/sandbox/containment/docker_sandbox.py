"""Docker-based containment sandbox for AI agent execution.

Each agent session gets its own container with:
- Isolated filesystem (workspace bind-mount only)
- Network disabled by default (network_mode=none)
- Resource caps (memory, CPU, PIDs)
- Read-only rootfs with tmpfs /tmp
- Non-root user
- Secret-stripped environment

The DockerSandbox interface (create/exec/files/destroy) is the same contract
a future KubernetesSandbox would implement — containers built here run
unchanged as pod images.
"""
from __future__ import annotations

import io
import os
import tarfile
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import structlog

from sandbox.config import ContainmentSettings, ExecutorSettings
from sandbox.executor.isolation import SubprocessIsolator, IsolationProfile

logger = structlog.get_logger()


class ContainerState(StrEnum):
    CREATING = "creating"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    DESTROYED = "destroyed"


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass
class FileInfo:
    name: str
    type: str  # "file" or "dir"
    size: int = 0


def _check_docker_available() -> bool:
    try:
        import docker
        client = docker.from_env()
        client.ping()
        client.close()
        return True
    except Exception:
        return False


def _sanitized_container_env() -> dict[str, str]:
    isolator = SubprocessIsolator(IsolationProfile())
    return isolator.sanitize_environment()


class DockerSandbox:
    """One container per agent session — real OS-level isolation."""

    def __init__(
        self,
        session_id: str,
        containment_settings: ContainmentSettings,
        executor_settings: ExecutorSettings,
        workspace_host_path: str | None = None,
        capabilities: list[str] | None = None,
    ) -> None:
        self._session_id = session_id
        self._settings = containment_settings
        self._executor = executor_settings
        self._capabilities = set(capabilities or [])
        self._state = ContainerState.CREATING
        self._container: Any = None
        self._container_id: str | None = None
        self._client: Any = None
        self._workspace_container = "/workspace"
        self._created_at: float | None = None

        if workspace_host_path:
            self._workspace_host = os.path.abspath(workspace_host_path)
        else:
            ws_root = os.path.abspath(containment_settings.workspace_mount_root)
            self._workspace_host = os.path.join(ws_root, session_id)

    @property
    def container_id(self) -> str | None:
        return self._container_id

    @property
    def state(self) -> ContainerState:
        return self._state

    @property
    def session_id(self) -> str:
        return self._session_id

    async def create(self) -> str:
        """Create and start the sandboxed container. Returns container ID."""
        import docker

        self._client = docker.from_env()

        os.makedirs(self._workspace_host, exist_ok=True)

        network_mode = "none"
        if "NETWORK" in self._capabilities:
            network_mode = self._settings.default_network
            if network_mode == "none":
                network_mode = "bridge"

        mem_limit = f"{self._executor.max_memory_mb}m"
        nano_cpus = int(self._executor.max_cpu_cores * 1e9)
        pids_limit = self._executor.max_pids

        tmpfs_spec = {"/tmp": f"size={self._settings.tmpfs_size_mb}m,noexec,nosuid"}

        env = _sanitized_container_env()
        env["SANDBOX_SESSION_ID"] = self._session_id
        env["HOME"] = "/workspace"

        container_kwargs: dict[str, Any] = {
            "image": self._settings.base_image,
            "command": "sleep infinity",
            "name": f"sandbox-{self._session_id[:12]}",
            "detach": True,
            "network_mode": network_mode,
            "mem_limit": mem_limit,
            "nano_cpus": nano_cpus,
            "pids_limit": pids_limit,
            "read_only": self._settings.read_only_rootfs,
            "tmpfs": tmpfs_spec,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "user": self._settings.container_user,
            "environment": env,
            "volumes": {
                self._workspace_host: {
                    "bind": self._workspace_container,
                    "mode": "rw",
                },
            },
            "working_dir": self._workspace_container,
            "labels": {
                "sandbox.session_id": self._session_id,
                "sandbox.managed": "true",
            },
        }

        try:
            self._client.images.get(self._settings.base_image)
        except docker.errors.ImageNotFound:
            logger.info("pulling_image", image=self._settings.base_image)
            self._client.images.pull(self._settings.base_image)

        self._container = self._client.containers.run(**container_kwargs)
        self._container_id = self._container.id
        self._state = ContainerState.RUNNING
        self._created_at = time.time()

        logger.info(
            "container_created",
            container_id=self._container_id[:12],
            session_id=self._session_id,
            image=self._settings.base_image,
            network=network_mode,
            mem_limit=mem_limit,
        )

        return self._container_id

    async def exec(
        self,
        command: str,
        timeout: int | None = None,
        workdir: str | None = None,
    ) -> ExecResult:
        """Execute a command inside the container."""
        if self._container is None or self._state != ContainerState.RUNNING:
            return ExecResult(exit_code=-1, stdout="", stderr="Container not running")

        effective_timeout = timeout or self._executor.execute_timeout_seconds
        exec_workdir = workdir or self._workspace_container

        try:
            exit_code, output = self._container.exec_run(
                cmd=["sh", "-c", command],
                workdir=exec_workdir,
                demux=True,
                user=self._settings.container_user,
            )

            stdout = (output[0] or b"").decode("utf-8", errors="replace")
            stderr = (output[1] or b"").decode("utf-8", errors="replace")

            return ExecResult(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
            )
        except Exception as e:
            logger.error("container_exec_error", error=str(e), session_id=self._session_id)
            return ExecResult(exit_code=-1, stdout="", stderr=str(e))

    async def write_file(self, container_path: str, content: bytes) -> bool:
        """Write a file into the container's workspace."""
        if self._container is None or self._state != ContainerState.RUNNING:
            return False

        if not container_path.startswith("/"):
            container_path = f"{self._workspace_container}/{container_path}"

        if not container_path.startswith(self._workspace_container):
            logger.warning("write_outside_workspace", path=container_path)
            return False

        try:
            tar_stream = io.BytesIO()
            filename = os.path.basename(container_path)
            dir_path = os.path.dirname(container_path)

            with tarfile.open(fileobj=tar_stream, mode="w") as tar:
                info = tarfile.TarInfo(name=filename)
                info.size = len(content)
                info.mode = 0o644
                tar.addfile(info, io.BytesIO(content))

            tar_stream.seek(0)
            self._container.put_archive(dir_path, tar_stream)
            return True
        except Exception as e:
            logger.error("container_write_error", error=str(e), path=container_path)
            return False

    async def read_file(self, container_path: str) -> bytes | None:
        """Read a file from the container."""
        if self._container is None or self._state != ContainerState.RUNNING:
            return None

        if not container_path.startswith("/"):
            container_path = f"{self._workspace_container}/{container_path}"

        if not container_path.startswith(self._workspace_container):
            logger.warning("read_outside_workspace", path=container_path)
            return None

        try:
            bits, stat = self._container.get_archive(container_path)
            tar_stream = io.BytesIO()
            for chunk in bits:
                tar_stream.write(chunk)
            tar_stream.seek(0)

            with tarfile.open(fileobj=tar_stream, mode="r") as tar:
                member = tar.getmembers()[0]
                f = tar.extractfile(member)
                if f is None:
                    return None
                return f.read()
        except Exception as e:
            logger.error("container_read_error", error=str(e), path=container_path)
            return None

    async def list_dir(self, container_path: str) -> list[FileInfo]:
        """List directory contents inside the container."""
        if self._container is None or self._state != ContainerState.RUNNING:
            return []

        if not container_path.startswith("/"):
            container_path = f"{self._workspace_container}/{container_path}"

        if not container_path.startswith(self._workspace_container):
            return []

        result = await self.exec(
            f'find {container_path} -maxdepth 1 -mindepth 1 -printf "%y %s %f\\n" 2>/dev/null || '
            f'ls -la {container_path} 2>/dev/null'
        )

        entries: list[FileInfo] = []
        if result.exit_code != 0:
            return entries

        for line in result.stdout.strip().splitlines():
            parts = line.split(None, 2)
            if len(parts) >= 3:
                ftype = "dir" if parts[0] == "d" else "file"
                try:
                    size = int(parts[1])
                except ValueError:
                    size = 0
                entries.append(FileInfo(name=parts[2], type=ftype, size=size))

        return entries

    async def pause(self) -> bool:
        """Pause the container (freeze all processes)."""
        if self._container is None or self._state != ContainerState.RUNNING:
            return False
        try:
            self._container.pause()
            self._state = ContainerState.PAUSED
            return True
        except Exception as e:
            logger.error("container_pause_error", error=str(e))
            return False

    async def resume(self) -> bool:
        """Resume a paused container."""
        if self._container is None or self._state != ContainerState.PAUSED:
            return False
        try:
            self._container.unpause()
            self._state = ContainerState.RUNNING
            return True
        except Exception as e:
            logger.error("container_resume_error", error=str(e))
            return False

    async def destroy(self) -> bool:
        """Stop and remove the container."""
        if self._container is None:
            self._state = ContainerState.DESTROYED
            return True

        try:
            self._container.stop(timeout=self._executor.sigterm_grace_seconds)
        except Exception:
            try:
                self._container.kill()
            except Exception:
                pass

        try:
            self._container.remove(force=True)
        except Exception as e:
            logger.error("container_remove_error", error=str(e))

        self._state = ContainerState.DESTROYED
        self._container = None

        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

        logger.info(
            "container_destroyed",
            container_id=(self._container_id or "")[:12],
            session_id=self._session_id,
        )
        return True

    def status(self) -> dict[str, Any]:
        """Return container status info."""
        info: dict[str, Any] = {
            "session_id": self._session_id,
            "state": self._state.value,
            "container_id": self._container_id,
            "image": self._settings.base_image,
            "created_at": self._created_at,
        }

        if self._container is not None and self._state == ContainerState.RUNNING:
            try:
                self._container.reload()
                info["docker_status"] = self._container.status
            except Exception:
                pass

        return info
