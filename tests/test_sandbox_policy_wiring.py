"""The factory must arm sandbox write-path enforcement from one PolicyStore.

Regression: ``create_sandboxed_runtime`` handed ``options.policy_store`` (usually
``None``) to ``SandboxedToolRuntime`` while ``AgentRuntime`` minted its *own*
store. With neither a store nor an explicit ``allowed_write_paths`` the sandbox
runtime computed ``effective_paths = None`` and skipped the host-side write-path
check entirely — the "authoritative boundary" the docstrings promise was never
armed in the default wiring.

The fix has two halves:
  * the factory resolves exactly one PolicyStore and shares it with both layers;
  * an explicit empty whitelist (``[]``) fails closed instead of reading as
    "unrestricted". ``None`` still means "no whitelist configured" for direct
    SDK construction.
"""

from __future__ import annotations

from typing import Any

from titanx.factory import CreateSandboxedRuntimeOptions, create_sandboxed_runtime
from titanx.safety import SafetyLayer
from titanx.sandbox import (
    SandboxBackend,
    SandboxBackendCapabilities,
    SandboxExecutionRequest,
    SandboxExecutionResult,
    SandboxRouter,
    SandboxedToolHandler,
    SandboxedToolRuntime,
    SandboxToolPolicy,
)
from titanx.types import LlmAdapter, LlmTurnResult, ToolCall, ToolDefinition


class _ScriptedLlm(LlmAdapter):
    def __init__(self, responses: list[LlmTurnResult]) -> None:
        self.responses = list(responses)
        self.cursor = 0

    async def respond(self, config, state) -> LlmTurnResult:
        if self.cursor >= len(self.responses):
            return LlmTurnResult(type="text", text="(done)")
        resp = self.responses[self.cursor]
        self.cursor += 1
        return resp


class _RecordingBackend(SandboxBackend):
    """Runs nothing; records which requests reached the sandbox layer."""

    kind = "wasm"

    def __init__(self) -> None:
        self.requests: list[SandboxExecutionRequest] = []

    def capabilities(self) -> SandboxBackendCapabilities:
        return SandboxBackendCapabilities(
            kind="wasm",
            supports_persistence=False,
            supports_snapshots=False,
            supports_browser=False,
            supports_network=False,
            supports_package_install=False,
            supported_capabilities=[],
        )

    async def is_available(self) -> bool:
        return True

    async def execute(self, request, session=None) -> SandboxExecutionResult:
        self.requests.append(request)
        return SandboxExecutionResult(
            backend="wasm", exit_code=0, stdout="ran", stderr="", duration_ms=1.0
        )


class _NullLlm(LlmAdapter):
    async def respond(self, config, state) -> LlmTurnResult:
        return LlmTurnResult(type="text", text="")


def _copy_handler() -> SandboxedToolHandler:
    """A handler issuing ``cp <src> <dst>`` so the write target is unambiguous."""

    def request(params: dict[str, Any]) -> SandboxExecutionRequest:
        return SandboxExecutionRequest(
            command=str(params["command"]), args=list(params.get("args", []))
        )

    return SandboxedToolHandler(
        definition=ToolDefinition(
            name="run_command", description="", parameters={"type": "object"}
        ),
        request_fn=request,
        policy=SandboxToolPolicy(risk_level="low", min_isolation="wasm"),
    )


def _copy(dst: str) -> dict[str, Any]:
    return {"command": "cp", "args": ["/tmp/source", dst]}


class TestEmptyWhitelistFailsClosed:
    async def test_explicit_empty_whitelist_denies_writes(self) -> None:
        backend = _RecordingBackend()
        runtime = SandboxedToolRuntime(
            router=SandboxRouter([backend]),
            handlers=[_copy_handler()],
            allowed_write_paths=[],
        )

        result = await runtime.execute("run_command", _copy("/etc/evil"))

        assert result.error == "path_not_allowed"
        assert backend.requests == []

    async def test_none_whitelist_stays_unconfigured(self) -> None:
        # Direct SDK construction with no store and no whitelist opts out of
        # host-side path filtering; the factory never produces this state.
        backend = _RecordingBackend()
        runtime = SandboxedToolRuntime(
            router=SandboxRouter([backend]),
            handlers=[_copy_handler()],
        )

        result = await runtime.execute("run_command", _copy("/etc/evil"))

        assert result.error is None
        assert len(backend.requests) == 1


class TestFactoryArmsEnforcement:
    async def test_default_factory_denies_sandbox_writes(self) -> None:
        backend = _RecordingBackend()
        runtime = create_sandboxed_runtime(
            CreateSandboxedRuntimeOptions(
                llm=_NullLlm(),
                safety=SafetyLayer(),
                backends=[backend],
                tool_handlers=[_copy_handler()],
            )
        )

        result = await runtime._tools.execute("run_command", _copy("/etc/evil"))

        assert result.error == "path_not_allowed"
        assert backend.requests == []

    async def test_configured_write_paths_allow_listed_targets_only(self) -> None:
        backend = _RecordingBackend()
        runtime = create_sandboxed_runtime(
            CreateSandboxedRuntimeOptions(
                llm=_NullLlm(),
                safety=SafetyLayer(),
                backends=[backend],
                tool_handlers=[_copy_handler()],
                allowed_write_paths=["/work"],
            )
        )

        allowed = await runtime._tools.execute("run_command", _copy("/work/out"))
        denied = await runtime._tools.execute("run_command", _copy("/etc/evil"))

        assert allowed.error is None
        assert denied.error == "path_not_allowed"
        assert len(backend.requests) == 1
        assert backend.requests[0].allowed_write_paths == ["/work"]


class TestFactoryAuthorizesCustomHandlers:
    """Deny-by-default (#4) is compliable through the factory, not just by hand.

    A host that supplies ``requires_approval=False`` handlers has no approval
    gate to fall back on, so the factory must offer a first-class allowlist —
    otherwise the only escape is hand-building a whole ``PolicyStore``.
    """

    @staticmethod
    def _scripted():
        return _ScriptedLlm([
            LlmTurnResult(type="tool_calls", tool_calls=[
                ToolCall("c1", "run_command", _copy("/work/out")),
            ]),
            LlmTurnResult(type="text", text="done"),
        ])

    async def test_allowlisted_handler_is_dispatched(self) -> None:
        backend = _RecordingBackend()
        runtime = create_sandboxed_runtime(
            CreateSandboxedRuntimeOptions(
                llm=self._scripted(),
                safety=SafetyLayer(),
                backends=[backend],
                tool_handlers=[_copy_handler()],
                allowed_write_paths=["/work"],
                tool_allowlist=["run_command"],
            )
        )

        await runtime.run_prompt("run the copy")

        assert len(backend.requests) == 1

    async def test_unlisted_handler_is_denied_by_policy(self) -> None:
        backend = _RecordingBackend()
        runtime = create_sandboxed_runtime(
            CreateSandboxedRuntimeOptions(
                llm=self._scripted(),
                safety=SafetyLayer(),
                backends=[backend],
                tool_handlers=[_copy_handler()],
                allowed_write_paths=["/work"],
            )
        )

        await runtime.run_prompt("run the copy")

        assert backend.requests == []
