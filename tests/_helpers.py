"""Shared test fixtures for the Q13–Q22 hardening tests.

Pulled out of the individual test files so the same scripted-LLM and
no-op tool-runtime stand-ins can be reused; the historical "copy-paste
into every test" pattern made it easy for fixes to drift across files.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from titanx.runtime import AgentRuntime
from titanx.safety.safety_layer import SafetyLayer
from titanx.types import (
    LlmAdapter,
    LlmTurnResult,
    RuntimeHooks,
    ToolDefinition,
    ToolExecutionResult,
    ToolRuntime,
)


class ScriptedLlm(LlmAdapter):
    """Plays back a pre-built list of LlmTurnResults in order.

    Falls back to a generic text response after the script is exhausted
    so a misconfigured test (one too few entries) still terminates the
    runtime loop instead of hanging.
    """

    def __init__(self, responses: list[LlmTurnResult]) -> None:
        self.responses = list(responses)
        self.cursor = 0

    async def respond(self, config, state) -> LlmTurnResult:
        if self.cursor >= len(self.responses):
            return LlmTurnResult(type="text", text="(default text)")
        resp = self.responses[self.cursor]
        self.cursor += 1
        return resp


class NullTools(ToolRuntime):
    def list_tools(self) -> list[ToolDefinition]:
        return []

    async def execute(self, name: str, params: dict[str, Any]) -> ToolExecutionResult:
        return ToolExecutionResult(output="", error=None)


class SingleTool(ToolRuntime):
    """ToolRuntime backed by exactly one user-supplied async handler."""

    def __init__(
        self,
        defn: ToolDefinition,
        handler: Callable[[str, dict[str, Any]], Awaitable[ToolExecutionResult]],
    ) -> None:
        self._defn = defn
        self._handler = handler

    def list_tools(self) -> list[ToolDefinition]:
        return [self._defn]

    async def execute(self, name: str, params: dict[str, Any]) -> ToolExecutionResult:
        return await self._handler(name, params)


def make_runtime(
    llm: LlmAdapter,
    *,
    max_iterations: int = 3,
    tools: ToolRuntime | None = None,
) -> AgentRuntime:
    return AgentRuntime(
        llm=llm,
        tools=tools or NullTools(),
        safety=SafetyLayer(),
        max_iterations=max_iterations,
        hooks=RuntimeHooks(),
    )
