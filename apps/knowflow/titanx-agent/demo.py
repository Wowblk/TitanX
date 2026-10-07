"""Minimal demo: wire up TitanX with a stub LLM and run a prompt."""
from __future__ import annotations

import asyncio

from titanx import (
    AgentConfig, AgentState, AgentRuntime, LlmAdapter, LlmTurnResult,
    SafetyLayer, create_sandboxed_runtime, CreateSandboxedRuntimeOptions,
    RuntimeHooks, RuntimeEvent,
)


class EchoLlm(LlmAdapter):
    """Stub LLM that echoes the last user message as a text response."""

    async def respond(self, config: AgentConfig, state: AgentState) -> LlmTurnResult:
        last = next((m for m in reversed(state.messages) if m.role == "user"), None)
        text = f"Echo: {last.content}" if last else "Hello!"
        return LlmTurnResult(type="text", text=text)


async def main() -> None:
    def on_event(event: RuntimeEvent, config: AgentConfig, state: AgentState) -> None:
        print(f"[event] {event}")

    opts = CreateSandboxedRuntimeOptions(
        llm=EchoLlm(),
        safety=SafetyLayer(),
        hooks=RuntimeHooks(on_event=on_event),
        system_prompt="You are a helpful assistant.",
    )
    runtime = create_sandboxed_runtime(opts)
    state = await runtime.run_prompt("Hello, TitanX!")
    print(f"\nFinal response: {state.last_text_response}")


if __name__ == "__main__":
    asyncio.run(main())
