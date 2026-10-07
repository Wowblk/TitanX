from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .runtime import AgentRuntime
from .sandbox import (
    DockerSandboxBackend,
    E2BSandboxBackend,
    SandboxBackend,
    SandboxRouter,
    SandboxedToolHandler,
    SandboxedToolRuntime,
    SandboxToolPolicy,
    WasmCommandRegistration,
    WasmSandboxBackend,
)
from .sandbox.types import SandboxExecutionRequest
from .resilience import ResilientOptions, ResilientSandboxBackend
from .types import ToolDefinition, LlmAdapter, RuntimeHooks, SafetyLayerLike
from .context.types import CompactionOptions, CompactionStrategy
from .policy import PolicyStore
from .tools import create_ironclaw_wasm_handlers


@dataclass
class CreateSandboxedRuntimeOptions:
    llm: LlmAdapter
    safety: SafetyLayerLike
    backends: list[SandboxBackend] | None = None
    tool_handlers: list[SandboxedToolHandler] | None = None
    wasm_commands: dict[str, WasmCommandRegistration] | None = None
    log_dir: str | None = None
    cache_dir: str | None = None
    workspace_dir: str | None = None
    allowed_write_paths: list[str] | None = None
    policy_store: PolicyStore | None = None
    compaction_strategy: CompactionStrategy | None = None
    compaction_options: CompactionOptions | None = None
    resilient_options: ResilientOptions | None = None
    user_id: str = "default"
    channel: str = "repl"
    system_prompt: str = ""
    max_iterations: int = 10
    auto_approve_tools: bool = False
    hooks: RuntimeHooks | None = None
    enable_ironclaw_wasm_tools: bool = False
    ironclaw_wasm_tool_names: list[str] | None = None
    ironclaw_wasm_command_overrides: dict[str, str] | None = None


def _default_handlers() -> list[SandboxedToolHandler]:
    def _run_wasm(params: dict[str, Any]) -> SandboxExecutionRequest:
        return SandboxExecutionRequest(
            command=str(params.get("command", "")),
            args=list(params.get("args", [])),
        )

    def _run_cmd(params: dict[str, Any]) -> SandboxExecutionRequest:
        return SandboxExecutionRequest(
            command=str(params.get("command", "")),
            args=list(params.get("args", [])),
            cwd=str(params["cwd"]) if params.get("cwd") else None,
        )

    def _run_browser(params: dict[str, Any]) -> SandboxExecutionRequest:
        return SandboxExecutionRequest(
            command=str(params.get("command", "")),
            args=list(params.get("args", [])),
        )

    return [
        SandboxedToolHandler(
            definition=ToolDefinition(
                name="run_wasm_command",
                description="Execute a registered low-risk command in the WASI sandbox backend.",
                parameters={"type": "object", "properties": {"command": {"type": "string"}, "args": {"type": "array", "items": {"type": "string"}}}, "required": ["command"]},
                requires_approval=True,
                requires_sanitization=True,
            ),
            request_fn=_run_wasm,
            policy=SandboxToolPolicy(preferred_backend="wasm", risk_level="low"),
        ),
        SandboxedToolHandler(
            definition=ToolDefinition(
                name="run_command",
                description="Execute a command in the selected sandbox backend.",
                parameters={"type": "object", "properties": {"command": {"type": "string"}, "args": {"type": "array", "items": {"type": "string"}}, "cwd": {"type": "string"}}, "required": ["command"]},
                requires_approval=True,
                requires_sanitization=True,
            ),
            request_fn=_run_cmd,
            policy=SandboxToolPolicy(risk_level="medium", needs_filesystem=True),
        ),
        SandboxedToolHandler(
            definition=ToolDefinition(
                name="run_browser_task",
                description="Execute a browser-oriented task in a remote isolated sandbox.",
                parameters={"type": "object", "properties": {"command": {"type": "string"}, "args": {"type": "array", "items": {"type": "string"}}}, "required": ["command"]},
                requires_approval=True,
                requires_sanitization=True,
            ),
            request_fn=_run_browser,
            policy=SandboxToolPolicy(risk_level="high", needs_browser=True, requires_remote_isolation=True),
        ),
    ]


def _default_backends(
    wasm_commands: dict[str, WasmCommandRegistration] | None,
    log_dir: str | None,
    cache_dir: str | None,
    resilient_options: ResilientOptions | None,
) -> list[SandboxBackend]:
    raw: list[SandboxBackend] = [
        WasmSandboxBackend(commands=wasm_commands or {}, log_dir=log_dir, cache_dir=cache_dir),
        DockerSandboxBackend(),
        E2BSandboxBackend(),
    ]
    if not resilient_options:
        return raw
    return [ResilientSandboxBackend(b, resilient_options) for b in raw]


def create_sandboxed_runtime(options: CreateSandboxedRuntimeOptions) -> AgentRuntime:
    backends = options.backends or _default_backends(
        options.wasm_commands, options.log_dir, options.cache_dir, options.resilient_options
    )
    router = SandboxRouter(backends)
    handlers = list(options.tool_handlers or _default_handlers())
    if options.enable_ironclaw_wasm_tools:
        handlers.extend(
            create_ironclaw_wasm_handlers(
                options.ironclaw_wasm_tool_names,
                command_overrides=options.ironclaw_wasm_command_overrides,
            )
        )

    tools = SandboxedToolRuntime(
        router=router,
        handlers=handlers,
        allowed_write_paths=options.allowed_write_paths,
        policy_store=options.policy_store,
    )
    return AgentRuntime(
        llm=options.llm,
        tools=tools,
        safety=options.safety,
        user_id=options.user_id,
        channel=options.channel,
        system_prompt=options.system_prompt,
        max_iterations=options.max_iterations,
        auto_approve_tools=options.auto_approve_tools,
        hooks=options.hooks,
        policy_store=options.policy_store,
        compaction_strategy=options.compaction_strategy,
        compaction_options=options.compaction_options,
    )
