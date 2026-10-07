from __future__ import annotations

import asyncio

from titanx.runtime import AgentRuntime
from titanx.safety import SafetyLayer
from titanx.types import AgentConfig, AgentState, LlmAdapter, LlmTurnResult, RuntimeHooks, ToolExecutionResult, ToolRuntime


class CountingLlm(LlmAdapter):
    def __init__(self) -> None:
        self.calls = 0

    async def respond(self, config: AgentConfig, state: AgentState) -> LlmTurnResult:
        self.calls += 1
        return LlmTurnResult(type="text", text=f"ok {self.calls}")


class NoopTools(ToolRuntime):
    def list_tools(self):
        return []

    async def execute(self, name: str, params: dict) -> ToolExecutionResult:
        return ToolExecutionResult(output="")


def test_iteration_budget_resets_for_each_prompt_in_same_session() -> None:
    llm = CountingLlm()
    runtime = AgentRuntime(
        llm=llm,
        tools=NoopTools(),
        safety=SafetyLayer(),
        max_iterations=1,
    )

    first = asyncio.run(runtime.run_prompt("first")).last_text_response
    second = asyncio.run(runtime.run_prompt("second")).last_text_response

    assert first == "ok 1"
    assert second == "ok 2"
    assert llm.calls == 2


def test_runtime_hooks_can_be_rebound_between_sse_requests() -> None:
    runtime = AgentRuntime(
        llm=CountingLlm(),
        tools=NoopTools(),
        safety=SafetyLayer(),
    )
    seen: list[str] = []

    async def on_event(event, _config, _state) -> None:
        seen.append(event.type)

    runtime.set_hooks(RuntimeHooks(on_event=on_event))
    asyncio.run(runtime.run_prompt("hello"))

    assert "assistant_text" in seen
