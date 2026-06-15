from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from typing import Any, Callable
from uuid import uuid4

from ..types import ToolDefinition, ToolExecutionResult, ToolRuntime
from .path_guard import is_path_allowed, scan_shell_write_targets
from .router import SandboxRouter
from .session_manager import SandboxSessionManager
from .types import (
    SandboxExecutionRequest,
    SandboxExecutionResult,
    SandboxRouterInput,
    SandboxToolPolicy,
)

_LONG_RUNNING_COMMAND_MARKERS = (
    " --watch",
    " -w",
    " --reload",
    " --host",
    " --follow",
    " -f",
    " watch ",
    " tail -f",
    "docker logs -f",
    "while true",
)

_LONG_RUNNING_EXECUTABLES = {
    "celery",
    "jupyter",
    "postgres",
    "postgresql",
    "redis-server",
}


@dataclass
class SandboxedToolHandler:
    definition: ToolDefinition
    request_fn: Callable[[dict[str, Any]], SandboxExecutionRequest]
    policy: SandboxToolPolicy | None = None

    def request(self, params: dict[str, Any]) -> SandboxExecutionRequest:
        return self.request_fn(params)


class SandboxedToolRuntime(ToolRuntime):
    def __init__(
        self,
        router: SandboxRouter,
        handlers: list[SandboxedToolHandler],
        allowed_write_paths: list[str] | None = None,
        policy_store=None,
    ) -> None:
        self._router = router
        self._handlers: dict[str, SandboxedToolHandler] = {h.definition.name: h for h in handlers}
        self._allowed_write_paths = allowed_write_paths
        self._policy_store = policy_store
        self._sessions = SandboxSessionManager(
            router,
            allowed_write_paths=allowed_write_paths,
            policy_store=policy_store,
        )

    def list_tools(self) -> list[ToolDefinition]:
        return [h.definition for h in self._handlers.values()]

    async def execute(self, name: str, params: dict[str, Any]) -> ToolExecutionResult:
        handler = self._handlers.get(name)
        if not handler:
            return ToolExecutionResult(output=f"Unknown tool: {name}", error="unknown_tool")

        req = handler.request(params)

        live_policy = (
            self._policy_store.get_policy() if self._policy_store else None
        )
        effective_paths = (
            live_policy.allowed_write_paths
            if live_policy is not None
            else self._allowed_write_paths
        )
        if effective_paths:
            denied = self._check_write_paths(req, effective_paths)
            if denied:
                return ToolExecutionResult(output=denied, error="path_not_allowed")

        # Propagate the write-path whitelist into the request so the chosen
        # backend can enforce it at the kernel/sandbox layer (e.g. Docker
        # mounts ``/`` read-only and bind-mounts these paths writable). The
        # PathGuard check above is *defence-in-depth*; this propagation is
        # what actually guarantees write isolation in production.
        if effective_paths and req.allowed_write_paths is None:
            req.allowed_write_paths = list(effective_paths)

        # Propagate read-only mount targets and the image digest pin from
        # the live policy. We only set these when the handler hasn't
        # already populated them, so a tool that wants tighter isolation
        # than the policy can still narrow the request itself.
        if live_policy is not None:
            if req.allowed_read_paths is None and live_policy.allowed_read_paths:
                req.allowed_read_paths = list(live_policy.allowed_read_paths)
            if req.image_digest is None and live_policy.image_digest:
                req.image_digest = live_policy.image_digest

        router_input = self._policy_to_router_input(handler.policy)
        session_id = _string_param(params.get("sessionId"))
        if session_id:
            result = await self._sessions.execute(session_id, req)
            return self._format_result(result.backend, result)

        if self._should_background(name, params, req):
            return await self._start_background_session(req, router_input)

        selection = await self._router.select(router_input)
        result = await selection.backend.execute(req)
        return self._format_result(selection.backend.kind, result)

    async def _start_background_session(
        self,
        req: SandboxExecutionRequest,
        router_input: SandboxRouterInput,
    ) -> ToolExecutionResult:
        # Background commands need a persistent Unix-like execution
        # environment. Refuse WASM fallback instead of starting a
        # "background" workload on a stateless backend that cannot be
        # polled or cleaned up.
        router_input.min_isolation = router_input.min_isolation or "docker"
        session = await self._sessions.create(
            router_input,
            metadata={"purpose": "background-command"},
        )
        run_id = uuid4().hex[:12]
        log_path = f"/tmp/titanx-bg/{run_id}.log"
        status_path = f"/tmp/titanx-bg/{run_id}.status"
        pid_path = f"/tmp/titanx-bg/{run_id}.pid"
        script = _background_script(req, log_path, status_path, pid_path)
        bg_req = SandboxExecutionRequest(
            command="sh",
            args=["-c", script],
            env=req.env,
            timeout_ms=5_000,
            allowed_write_paths=req.allowed_write_paths,
            allowed_read_paths=req.allowed_read_paths,
            image_digest=req.image_digest,
        )
        result = await self._sessions.execute(session.id, bg_req)
        if result.exit_code != 0:
            return self._format_result(result.backend, result)
        return ToolExecutionResult(
            output=(
                f"[sandbox:{result.backend}] Command still running "
                f"(sessionId={session.id}).\n"
                f"{result.stdout.strip()}\n"
                f"log={log_path}\n"
                f"status={status_path}\n"
                "Use run_command with this sessionId to inspect logs, "
                "check status, or kill the recorded pid."
            ),
            error=None,
        )

    def _format_result(self, backend: str, result: SandboxExecutionResult) -> ToolExecutionResult:
        prefix = f"[sandbox:{backend}]"
        content = (
            f"{prefix} {result.stdout}".strip()
            if result.stdout.strip()
            else f"{prefix} exit={result.exit_code}"
        )
        return ToolExecutionResult(
            output=content,
            error=result.stderr or f"exit_code_{result.exit_code}" if result.exit_code != 0 else None,
        )

    def _should_background(
        self,
        tool_name: str,
        params: dict[str, Any],
        req: SandboxExecutionRequest,
    ) -> bool:
        if tool_name != "run_command":
            return False
        if params.get("background") is True:
            return True
        if isinstance(params.get("yieldMs"), int):
            return True
        return _looks_long_running(req)

    def _check_write_paths(self, req: SandboxExecutionRequest, allowed: list[str]) -> str | None:
        if req.cwd:
            if not os.path.isabs(req.cwd):
                return f"Working directory '{req.cwd}' must be an absolute path"
            if not is_path_allowed(req.cwd, allowed):
                return f"Working directory '{req.cwd}' is not permitted by the path whitelist"
        scan = scan_shell_write_targets(req.command, req.args, cwd=req.cwd)
        if scan.refuse_reason:
            # Fail closed: anything we can't statically reason about is dropped
            # at the host before it ever reaches the sandbox backend. The
            # sandbox itself is still the authoritative boundary, but we
            # prefer not to even hand the workload over.
            return f"Refusing command — cannot statically verify write targets: {scan.refuse_reason}"
        for target in scan.targets:
            if not is_path_allowed(target, allowed):
                return f"Write to '{target}' is not permitted by the path whitelist"
        return None

    def _policy_to_router_input(self, policy: SandboxToolPolicy | None) -> SandboxRouterInput:
        if not policy:
            return SandboxRouterInput()
        return SandboxRouterInput(
            preferred_backend=policy.preferred_backend,
            risk_level=policy.risk_level,
            requires_remote_isolation=policy.requires_remote_isolation,
            needs_filesystem=policy.needs_filesystem,
            needs_network=policy.needs_network,
            needs_browser=policy.needs_browser,
            needs_package_install=policy.needs_package_install,
        )


def _string_param(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    trimmed = value.strip()
    return trimmed or None


def _looks_long_running(req: SandboxExecutionRequest) -> bool:
    executable = os.path.basename(req.command.strip())
    if executable in _LONG_RUNNING_EXECUTABLES:
        return True

    tokens = [req.command, *req.args]
    command_line = " ".join(str(t) for t in tokens).strip().lower()
    padded = f" {command_line} "
    if any(marker in padded for marker in _LONG_RUNNING_COMMAND_MARKERS):
        return True

    # Common framework forms where the executable itself is short but
    # the subcommand starts a server or watcher.
    if executable in {"npm", "pnpm", "yarn", "bun"} and any(
        arg in {"dev", "serve", "start"} for arg in req.args
    ):
        return True
    if executable in {"python", "python3"} and req.args[:2] == ["-m", "http.server"]:
        return True
    if executable in {"uvicorn", "gunicorn", "fastapi", "flask", "streamlit"}:
        return True
    if executable in {"pytest", "jest", "vitest"} and any(
        arg in {"--watch", "-w", "--watchAll"} for arg in req.args
    ):
        return True
    return False


def _background_script(
    req: SandboxExecutionRequest,
    log_path: str,
    status_path: str,
    pid_path: str,
) -> str:
    argv = " ".join(shlex.quote(part) for part in [req.command, *req.args])
    body = argv
    if req.cwd:
        body = f"cd {shlex.quote(req.cwd)} && {argv}"
    return "\n".join(
        [
            "set -u",
            "mkdir -p /tmp/titanx-bg",
            f"log={shlex.quote(log_path)}",
            f"status={shlex.quote(status_path)}",
            f"pidfile={shlex.quote(pid_path)}",
            "(",
            "  set +e",
            f"  {body}",
            "  code=$?",
            '  printf "%s\\n" "$code" > "$status"',
            ') > "$log" 2>&1 &',
            "pid=$!",
            'printf "%s\\n" "$pid" > "$pidfile"',
            'printf "pid=%s\\npidfile=%s\\n" "$pid" "$pidfile"',
        ]
    )
