from __future__ import annotations

from typing import Any

from titanx.sandbox import SandboxRouter, SandboxedToolHandler, SandboxedToolRuntime
from titanx.sandbox.types import (
    SandboxBackend,
    SandboxBackendCapabilities,
    SandboxExecutionRequest,
    SandboxExecutionResult,
    SandboxSession,
    SandboxToolPolicy,
)
from titanx.types import ToolDefinition


class _DockerRecorder(SandboxBackend):
    kind = "docker"

    def __init__(self) -> None:
        self.created: list[str] = []
        self.executed: list[tuple[SandboxExecutionRequest, SandboxSession | None]] = []
        self._counter = 0

    def capabilities(self) -> SandboxBackendCapabilities:
        return SandboxBackendCapabilities(
            kind="docker",
            supports_persistence=True,
            supports_snapshots=True,
            supports_browser=False,
            supports_network=True,
            supports_package_install=True,
            supported_capabilities=["command-exec", "filesystem"],
        )

    async def is_available(self) -> bool:
        return True

    async def execute(
        self,
        request: SandboxExecutionRequest,
        session: SandboxSession | None = None,
    ) -> SandboxExecutionResult:
        self.executed.append((request, session))
        stdout = "pid=123\npidfile=/tmp/titanx-bg/run.pid\n" if request.command == "sh" else "ok"
        return SandboxExecutionResult(
            backend="docker",
            exit_code=0,
            stdout=stdout,
            stderr="",
            duration_ms=1.0,
        )

    async def create_session(
        self,
        metadata: dict[str, str] | None = None,
        *,
        allowed_write_paths: list[str] | None = None,
        allowed_read_paths: list[str] | None = None,
        image_digest: str | None = None,
    ) -> SandboxSession:
        self._counter += 1
        session_id = f"docker-{self._counter}"
        self.created.append(session_id)
        return SandboxSession(id=session_id, backend="docker", metadata=metadata or {})

    async def destroy_session(self, session_id: str) -> None:
        return None


def _runtime(backend: _DockerRecorder) -> SandboxedToolRuntime:
    def _request(params: dict[str, Any]) -> SandboxExecutionRequest:
        return SandboxExecutionRequest(
            command=str(params.get("command", "")),
            args=list(params.get("args", [])),
            cwd=str(params["cwd"]) if params.get("cwd") else None,
        )

    handler = SandboxedToolHandler(
        definition=ToolDefinition(
            name="run_command",
            description="Execute a command.",
            parameters={"type": "object"},
            requires_approval=True,
            requires_sanitization=True,
        ),
        request_fn=_request,
        policy=SandboxToolPolicy(risk_level="medium", needs_filesystem=True),
    )
    return SandboxedToolRuntime(SandboxRouter([backend]), [handler])


class TestBackgroundCommandSessions:
    async def test_short_command_runs_without_creating_session(self) -> None:
        backend = _DockerRecorder()
        result = await _runtime(backend).execute(
            "run_command",
            {"command": "echo", "args": ["hi"]},
        )

        assert result.error is None
        assert backend.created == []
        assert len(backend.executed) == 1
        assert backend.executed[0][1] is None

    async def test_dev_command_starts_managed_session(self) -> None:
        backend = _DockerRecorder()
        result = await _runtime(backend).execute(
            "run_command",
            {"command": "npm", "args": ["run", "dev"]},
        )

        assert result.error is None
        assert backend.created == ["docker-1"]
        assert "Command still running" in result.output
        assert "sessionId=docker-1" in result.output
        request, session = backend.executed[-1]
        assert session is not None
        assert session.id == "docker-1"
        assert request.command == "sh"
        assert "npm run dev" in request.args[-1]

    async def test_explicit_background_starts_managed_session(self) -> None:
        backend = _DockerRecorder()
        result = await _runtime(backend).execute(
            "run_command",
            {"command": "python", "args": ["worker.py"], "background": True},
        )

        assert result.error is None
        assert backend.created == ["docker-1"]
        assert "sessionId=docker-1" in result.output

    async def test_session_id_reuses_existing_session(self) -> None:
        backend = _DockerRecorder()
        runtime = _runtime(backend)
        await runtime.execute("run_command", {"command": "npm", "args": ["run", "dev"]})

        result = await runtime.execute(
            "run_command",
            {"sessionId": "docker-1", "command": "cat", "args": ["/tmp/titanx-bg/run.log"]},
        )

        assert result.error is None
        assert backend.created == ["docker-1"]
        request, session = backend.executed[-1]
        assert request.command == "cat"
        assert session is not None
        assert session.id == "docker-1"
