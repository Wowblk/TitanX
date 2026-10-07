from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.request import Request, urlopen

from titanx.types import (
    AgentConfig,
    AgentState,
    AssistantMessage,
    LlmAdapter,
    LlmTurnResult,
    LlmUsage,
    Message,
    ToolCall,
    ToolDefinition,
    ToolMessage,
)


class KimiLlm(LlmAdapter):
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.moonshot.cn",
        model: str = "moonshot-v1-8k",
        timeout: float = 60.0,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.timeout = timeout

    async def respond(self, config: AgentConfig, state: AgentState) -> LlmTurnResult:
        payload = self._build_payload(config, state)
        response = await asyncio.to_thread(self._post_chat_completion, payload)

        message = response.get("choices", [{}])[0].get("message", {})
        tool_calls = self._parse_tool_calls(message.get("tool_calls") or [])
        usage = self._parse_usage(response.get("usage") or {})
        text = message.get("content") or ""

        if tool_calls:
            return LlmTurnResult(
                type="tool_calls",
                text=text,
                tool_calls=tool_calls,
                usage=usage,
            )
        return LlmTurnResult(type="text", text=text, usage=usage)

    def _build_payload(self, config: AgentConfig, state: AgentState) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": self._build_messages(config, state),
        }
        if config.available_tools:
            payload["tools"] = [
                self._serialize_tool(tool) for tool in config.available_tools
            ]
            payload["tool_choice"] = "auto"
        return payload

    def _post_chat_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        request = Request(
            f"{self.base_url.rstrip('/')}/v1/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def _build_messages(
        self,
        config: AgentConfig,
        state: AgentState,
    ) -> list[dict[str, Any]]:
        messages: list[dict[str, Any]] = []
        if config.system_prompt:
            messages.append({"role": "system", "content": config.system_prompt})
        messages.extend(self._serialize_message(message) for message in state.messages)
        return messages

    def _serialize_message(self, message: Message) -> dict[str, Any]:
        if isinstance(message, AssistantMessage):
            serialized: dict[str, Any] = {
                "role": "assistant",
                "content": message.content,
            }
            if message.tool_calls:
                serialized["tool_calls"] = [
                    {
                        "id": tool_call.id,
                        "type": "function",
                        "function": {
                            "name": tool_call.name,
                            "arguments": json.dumps(tool_call.args),
                        },
                    }
                    for tool_call in message.tool_calls
                ]
            return serialized
        if isinstance(message, ToolMessage):
            return {
                "role": "tool",
                "tool_call_id": message.tool_call_id,
                "content": message.content,
            }
        return {"role": message.role, "content": message.content}

    def _serialize_tool(self, tool: ToolDefinition) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters,
            },
        }

    def _parse_tool_calls(self, tool_calls: list[dict[str, Any]]) -> list[ToolCall]:
        parsed: list[ToolCall] = []
        for tool_call in tool_calls:
            function = tool_call.get("function") or {}
            parsed.append(
                ToolCall(
                    id=tool_call["id"],
                    name=function["name"],
                    args=self._parse_tool_args(function.get("arguments")),
                )
            )
        return parsed

    def _parse_tool_args(self, arguments: Any) -> dict[str, Any]:
        if arguments is None or arguments == "":
            return {}
        if isinstance(arguments, dict):
            return arguments
        parsed = json.loads(arguments)
        if not isinstance(parsed, dict):
            raise ValueError("Tool call arguments must decode to a JSON object")
        return parsed

    def _parse_usage(self, usage: dict[str, Any]) -> LlmUsage:
        return LlmUsage(
            input_tokens=int(usage.get("prompt_tokens") or 0),
            output_tokens=int(usage.get("completion_tokens") or 0),
        )
