"""Start the TitanX gateway with a stub EchoLlm."""
from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from titanx.types import AgentConfig, AgentState, LlmAdapter, LlmTurnResult
from titanx.safety import SafetyLayer
from titanx.factory import create_sandboxed_runtime, CreateSandboxedRuntimeOptions
from titanx.gateway import GatewayOptions, create_gateway
from titanx.types import RuntimeHooks
import uvicorn


class EchoLlm(LlmAdapter):
    async def respond(self, config: AgentConfig, state: AgentState) -> LlmTurnResult:
        last = next((m for m in reversed(state.messages) if m.role == "user"), None)
        text = f"Echo: {last.content}" if last else "Hello from TitanX!"
        return LlmTurnResult(type="text", text=text)


def make_runtime(session_id: str, hooks: RuntimeHooks):
    return create_sandboxed_runtime(CreateSandboxedRuntimeOptions(
        llm=EchoLlm(),
        safety=SafetyLayer(),
        hooks=hooks,
    ))


options = GatewayOptions(
    port=3000,
    create_runtime=make_runtime,
)

app = create_gateway(options)

if __name__ == "__main__":
    print("TitanX Gateway → http://localhost:3000")
    uvicorn.run(app, host="0.0.0.0", port=3000)
