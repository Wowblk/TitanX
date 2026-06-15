"""Start the TitanX gateway.

By default this demo uses EchoLlm so the gateway works without credentials.
Set OPENAI_API_KEY or KIMI_API_KEY to route chat turns to an
OpenAI-compatible model.
Optional environment variables:

    OPENAI_MODEL=gpt-4o-mini
    OPENAI_BASE_URL=https://api.openai.com/v1
    KIMI_MODEL=kimi-k2.6
    KIMI_BASE_URL=https://api.moonshot.cn/v1
    LLM_TEMPERATURE=1
    TITANX_LLM_PROVIDER=openai|kimi|echo
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import urllib.error
import urllib.request
sys.path.insert(0, os.path.dirname(__file__))

from titanx.types import AgentConfig, AgentState, LlmAdapter, LlmTurnResult, LlmUsage
from titanx.safety import SafetyLayer
from titanx.factory import create_sandboxed_runtime, CreateSandboxedRuntimeOptions
from titanx.gateway import GatewayOptions, create_gateway
from titanx.types import RuntimeHooks
from titanx.policy import AgentPolicy, AuditLog, PolicyStore
import uvicorn


class EchoLlm(LlmAdapter):
    async def respond(self, config: AgentConfig, state: AgentState) -> LlmTurnResult:
        last = next((m for m in reversed(state.messages) if m.role == "user"), None)
        text = f"Echo: {last.content}" if last else "Hello from TitanX!"
        return LlmTurnResult(type="text", text=text)


class OpenAIChatLlm(LlmAdapter):
    def __init__(
        self,
        *,
        api_key: str,
        model: str = "gpt-4o-mini",
        base_url: str = "https://api.openai.com/v1",
        temperature: float = 1.0,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._temperature = temperature

    async def respond(self, config: AgentConfig, state: AgentState) -> LlmTurnResult:
        messages: list[dict[str, str]] = []
        if config.system_prompt:
            messages.append({"role": "system", "content": config.system_prompt})
        else:
            messages.append({
                "role": "system",
                "content": (
                    "You are TitanX, a helpful agent running inside a sandboxed "
                    "runtime. Be concise and explain tool limitations clearly."
                ),
            })

        for message in state.messages:
            if message.role in ("system", "user", "assistant"):
                content = message.content or ""
                if content:
                    messages.append({"role": message.role, "content": content})
            elif message.role == "tool":
                messages.append({
                    "role": "user",
                    "content": (
                        f"[Tool result from {message.tool_name}; "
                        f"error={message.is_error}]\n{message.content}"
                    ),
                })

        payload = {
            "model": self._model,
            "messages": messages,
            "temperature": self._temperature,
        }
        data = await asyncio.to_thread(self._post_json, payload)
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        usage = data.get("usage") or {}
        return LlmTurnResult(
            type="text",
            text=msg.get("content") or "",
            usage=LlmUsage(
                input_tokens=int(usage.get("prompt_tokens") or 0),
                output_tokens=int(usage.get("completion_tokens") or 0),
            ),
        )

    def _post_json(self, payload: dict) -> dict:
        req = urllib.request.Request(
            f"{self._base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"OpenAI API error {exc.code}: {detail}") from exc


def make_llm() -> LlmAdapter:
    provider = os.getenv("TITANX_LLM_PROVIDER", "openai").lower()
    temperature = float(os.getenv("LLM_TEMPERATURE", "1"))
    if provider in ("kimi", "moonshot"):
        api_key = os.getenv("KIMI_API_KEY") or os.getenv("MOONSHOT_API_KEY")
        if not api_key:
            print("[titanx.gateway] KIMI_API_KEY is not set; using EchoLlm fallback.")
            return EchoLlm()
        return OpenAIChatLlm(
            api_key=api_key,
            model=os.getenv("KIMI_MODEL", "kimi-k2.6"),
            base_url=os.getenv("KIMI_BASE_URL", "https://api.moonshot.cn/v1"),
            temperature=temperature,
        )

    api_key = os.getenv("OPENAI_API_KEY")
    if provider == "echo" or not api_key:
        if provider != "echo":
            print(
                "[titanx.gateway] OPENAI_API_KEY is not set; using EchoLlm fallback. "
                "Set TITANX_LLM_PROVIDER=kimi to use KIMI_API_KEY."
            )
        return EchoLlm()
    return OpenAIChatLlm(
        api_key=api_key,
        model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        temperature=temperature,
    )


def _csv_env(name: str, default: list[str]) -> list[str]:
    raw = os.getenv(name)
    if raw is None:
        return default
    return [item.strip() for item in raw.split(",") if item.strip()]


def make_production_policy() -> AgentPolicy:
    """Default gateway policy: conservative, explicit, and overrideable by env."""
    image_digest = os.getenv("TITANX_SANDBOX_IMAGE_DIGEST") or None
    return AgentPolicy(
        allowed_write_paths=_csv_env(
            "TITANX_ALLOWED_WRITE_PATHS",
            [os.getenv("TITANX_WORKSPACE_DIR", "/var/lib/titanx/work")],
        ),
        allowed_read_paths=_csv_env("TITANX_ALLOWED_READ_PATHS", []),
        auto_approve_tools=os.getenv("TITANX_AUTO_APPROVE_TOOLS", "").lower()
        in {"1", "true", "yes", "on"},
        max_iterations=int(os.getenv("TITANX_MAX_ITERATIONS", "8")),
        tool_denylist=_csv_env("TITANX_TOOL_DENYLIST", ["run_browser_task"]),
        image_digest=image_digest,
    )


def make_runtime(session_id: str, hooks: RuntimeHooks):
    policy_store = PolicyStore(make_production_policy(), AuditLog())
    return create_sandboxed_runtime(CreateSandboxedRuntimeOptions(
        llm=make_llm(),
        safety=SafetyLayer(),
        hooks=hooks,
        policy_store=policy_store,
    ))


options = GatewayOptions(
    port=3000,
    create_runtime=make_runtime,
)

app = create_gateway(options)

if __name__ == "__main__":
    print("TitanX Gateway → http://localhost:3000")
    uvicorn.run(app, host="0.0.0.0", port=3000)
