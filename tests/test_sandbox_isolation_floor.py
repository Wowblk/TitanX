"""Tool policies must carry the router's hard isolation floor end to end."""

from __future__ import annotations

from typing import Any

import pytest

from titanx.factory import _default_handlers
from titanx.sandbox import (
    SandboxBackend,
    SandboxBackendCapabilities,
    SandboxExecutionRequest,
    SandboxExecutionResult,
    SandboxRouter,
    SandboxedToolHandler,
    SandboxedToolRuntime,
    SandboxSession,
    SandboxToolPolicy,
)
from titanx.types import ToolDefinition


class _WasmOnlyBackend(SandboxBackend):
    kind = "wasm"

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

    async def execute(
        self,
        request: SandboxExecutionRequest,
        session: SandboxSession | None = None,
    ) -> SandboxExecutionResult:
        raise AssertionError("a below-floor backend must never execute")


def _request(_: dict[str, Any]) -> SandboxExecutionRequest:
    return SandboxExecutionRequest(command="browser-task")


class TestToolPolicyIsolationFloor:
    async def test_floor_reaches_router_and_fails_closed(self) -> None:
        runtime = SandboxedToolRuntime(
            router=SandboxRouter([_WasmOnlyBackend()]),
            handlers=[
                SandboxedToolHandler(
                    definition=ToolDefinition(
                        name="remote_browser",
                        description="",
                        parameters={"type": "object"},
                    ),
                    request_fn=_request,
                    policy=SandboxToolPolicy(
                        risk_level="high",
                        needs_browser=True,
                        min_isolation="e2b",
                    ),
                )
            ],
        )

        with pytest.raises(RuntimeError, match="min_isolation='e2b'"):
            await runtime.execute("remote_browser", {})

    def test_factory_defaults_have_explicit_floors(self) -> None:
        handlers = {handler.definition.name: handler for handler in _default_handlers()}
        assert handlers["run_wasm_command"].policy is not None
        assert handlers["run_wasm_command"].policy.min_isolation == "wasm"
        assert handlers["run_command"].policy is not None
        assert handlers["run_command"].policy.min_isolation == "docker"
        assert handlers["run_browser_task"].policy is not None
        assert handlers["run_browser_task"].policy.min_isolation == "e2b"

    def test_risk_classification_derives_floor_when_author_omits_one(self) -> None:
        runtime = SandboxedToolRuntime(
            router=SandboxRouter([_WasmOnlyBackend()]),
            handlers=[],
        )
        high = runtime._policy_to_router_input(SandboxToolPolicy(risk_level="high"))
        medium = runtime._policy_to_router_input(
            SandboxToolPolicy(needs_filesystem=True)
        )
        low = runtime._policy_to_router_input(SandboxToolPolicy(risk_level="low"))

        assert high.min_isolation == "e2b"
        assert medium.min_isolation == "docker"
        assert low.min_isolation is None

    def test_explicit_floor_cannot_weaken_risk_classification(self) -> None:
        runtime = SandboxedToolRuntime(
            router=SandboxRouter([_WasmOnlyBackend()]),
            handlers=[],
        )

        high = runtime._policy_to_router_input(
            SandboxToolPolicy(risk_level="high", min_isolation="wasm")
        )
        medium = runtime._policy_to_router_input(
            SandboxToolPolicy(risk_level="medium", min_isolation="wasm")
        )

        assert high.min_isolation == "e2b"
        assert medium.min_isolation == "docker"
