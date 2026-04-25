from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable

from ..types import ToolDefinition, ToolExecutionResult, ToolRuntime
from .path_guard import is_path_allowed, scan_shell_write_targets
from .router import SandboxRouter
from .types import SandboxExecutionRequest, SandboxRouterInput, SandboxToolPolicy


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
        selection = await self._router.select(router_input)
        result = await selection.backend.execute(req)
        prefix = f"[sandbox:{selection.backend.kind}]"
        content = (
            f"{prefix} {result.stdout}".strip()
            if result.stdout.strip()
            else f"{prefix} exit={result.exit_code}"
        )
        return ToolExecutionResult(
            output=content,
            error=result.stderr or f"exit_code_{result.exit_code}" if result.exit_code != 0 else None,
        )

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
