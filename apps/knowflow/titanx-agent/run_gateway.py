"""Start the TitanX gateway for the local KnowFlow agent assistant."""
from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from titanx.types import AgentConfig, AgentState, LlmAdapter, LlmTurnResult
from titanx.safety import SafetyLayer
from titanx.runtime import AgentRuntime
from titanx.gateway import GatewayOptions, create_gateway
from titanx.types import RuntimeHooks
from titanx.llm import KimiLlm
from titanx.tools import KnowFlowToolClient, KnowFlowToolRuntime
import uvicorn


class EchoLlm(LlmAdapter):
    async def respond(self, config: AgentConfig, state: AgentState) -> LlmTurnResult:
        last = next((m for m in reversed(state.messages) if m.role == "user"), None)
        text = f"Echo: {last.content}" if last else "Hello from TitanX!"
        return LlmTurnResult(type="text", text=text)


SYSTEM_PROMPT = """你是KnowFlow的个人 AI 助手，不再只是围绕单篇正文做 RAG 问答。
你可以帮助用户检索公开知文、查看知文详情、整理自己的已发布内容，并在用户明确要求时创建草稿。

行为边界：
- 回答要简洁、直接，用中文。
- 需要平台数据时优先调用工具，不要编造帖子、作者、数量或链接。
- 只有用户明确说“创建草稿 / 保存为草稿 / 帮我写一篇并存起来”时，才调用 knowflow_create_draft。
- 不要发布、删除或修改已有知文；当前工具只允许创建私有草稿。
"""


def make_runtime(session_id: str, hooks: RuntimeHooks, body: dict | None = None):
    body = body or {}
    api_key = os.getenv("KIMI_API_KEY")
    llm: LlmAdapter
    if api_key:
        llm = KimiLlm(
            api_key=api_key,
            base_url=os.getenv("KIMI_BASE_URL", "https://api.moonshot.cn"),
            model=os.getenv("KIMI_CHAT_MODEL", "moonshot-v1-8k"),
        )
    else:
        llm = EchoLlm()

    token = str(body.get("toolBearerToken") or "").removeprefix("Bearer ").strip()
    client = KnowFlowToolClient(
        base_url=os.getenv("KNOWFLOW_API_BASE_URL", "http://127.0.0.1:8080"),
        bearer_token=token,
    )
    return AgentRuntime(
        llm=llm,
        tools=KnowFlowToolRuntime(client),
        safety=SafetyLayer(),
        user_id=str(body.get("userId") or "knowflow-user"),
        channel="knowflow-web",
        system_prompt=SYSTEM_PROMPT,
        max_iterations=int(os.getenv("TITANX_MAX_ITERATIONS", "8")),
        auto_approve_tools=True,
        hooks=hooks,
    )


options = GatewayOptions(
    port=3000,
    create_runtime=make_runtime,
)

app = create_gateway(options)

if __name__ == "__main__":
    print("TitanX Gateway → http://localhost:3000")
    uvicorn.run(app, host="0.0.0.0", port=3000)
