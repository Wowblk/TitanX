from __future__ import annotations

import asyncio
import json
import sys
import types
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
_TITANX_ROOT = _REPO_ROOT / "titanx"
_titanx_package = types.ModuleType("titanx")
_titanx_package.__path__ = [str(_TITANX_ROOT)]
sys.modules.setdefault("titanx", _titanx_package)
sys.path.insert(0, str(_REPO_ROOT))

from titanx.llm import KimiLlm
from titanx.state import create_config, create_initial_state
from titanx.types import AssistantMessage, ToolCall, ToolDefinition, ToolMessage, UserMessage


class _FakeResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


class _UrlopenRecorder:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.requests: list[Any] = []

    def __call__(self, request: Any, timeout: float) -> _FakeResponse:
        self.requests.append((request, timeout))
        return _FakeResponse(self.payload)


def test_text_response_parsing(monkeypatch: Any) -> None:
    recorder = _UrlopenRecorder({
        "choices": [{"message": {"role": "assistant", "content": "Hello from Kimi"}}],
        "usage": {"prompt_tokens": 12, "completion_tokens": 5},
    })
    monkeypatch.setattr("titanx.llm.kimi.urlopen", recorder)

    llm = KimiLlm(api_key="test-key")
    result = asyncio.run(
        llm.respond(
            create_config(system_prompt="You are helpful."),
            create_initial_state([UserMessage(role="user", content="Hi")]),
        )
    )

    assert result.type == "text"
    assert result.text == "Hello from Kimi"
    assert result.tool_calls is None
    assert result.usage is not None
    assert result.usage.input_tokens == 12
    assert result.usage.output_tokens == 5


def test_tool_call_response_parsing(monkeypatch: Any) -> None:
    recorder = _UrlopenRecorder({
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "id": "call_123",
                    "type": "function",
                    "function": {
                        "name": "search_memory",
                        "arguments": "{\"query\": \"kimi\", \"limit\": 3}",
                    },
                }],
            },
        }],
        "usage": {"prompt_tokens": 9, "completion_tokens": 4},
    })
    monkeypatch.setattr("titanx.llm.kimi.urlopen", recorder)

    result = asyncio.run(
        KimiLlm(api_key="test-key").respond(
            create_config(),
            create_initial_state([UserMessage(role="user", content="Find Kimi notes")]),
        )
    )

    assert result.type == "tool_calls"
    assert result.text == ""
    assert result.tool_calls == [
        ToolCall(id="call_123", name="search_memory", args={"query": "kimi", "limit": 3})
    ]
    assert result.usage is not None
    assert result.usage.input_tokens == 9
    assert result.usage.output_tokens == 4


def test_request_url_uses_moonshot_v1_chat_completions(monkeypatch: Any) -> None:
    recorder = _UrlopenRecorder({
        "choices": [{"message": {"role": "assistant", "content": "ok"}}],
        "usage": {},
    })
    monkeypatch.setattr("titanx.llm.kimi.urlopen", recorder)

    asyncio.run(
        KimiLlm(api_key="test-key", base_url="https://api.moonshot.cn").respond(
            create_config(),
            create_initial_state([UserMessage(role="user", content="Hi")]),
        )
    )

    request, timeout = recorder.requests[0]
    assert request.full_url == "https://api.moonshot.cn/v1/chat/completions"
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == "Bearer test-key"
    assert request.get_header("Content-type") == "application/json"
    assert timeout == 60.0


def test_tools_are_serialized_from_agent_config(monkeypatch: Any) -> None:
    recorder = _UrlopenRecorder({
        "choices": [{"message": {"role": "assistant", "content": "ok"}}],
        "usage": {},
    })
    monkeypatch.setattr("titanx.llm.kimi.urlopen", recorder)
    tool = ToolDefinition(
        name="search_memory",
        description="Search personal memory.",
        parameters={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
        requires_approval=True,
        metadata={"internal": True},
    )
    config = create_config(system_prompt="Use tools carefully.", available_tools=[tool])
    state = create_initial_state([
        UserMessage(role="user", content="Search for Kimi"),
        AssistantMessage(
            role="assistant",
            content="",
            tool_calls=[ToolCall(id="call_1", name="search_memory", args={"query": "Kimi"})],
        ),
        ToolMessage(
            role="tool",
            tool_name="search_memory",
            tool_call_id="call_1",
            content="Kimi result",
        ),
    ])

    asyncio.run(KimiLlm(api_key="test-key").respond(config, state))

    request, _ = recorder.requests[0]
    body = json.loads(request.data.decode("utf-8"))
    assert body["model"] == "moonshot-v1-8k"
    assert body["tool_choice"] == "auto"
    assert body["tools"] == [{
        "type": "function",
        "function": {
            "name": "search_memory",
            "description": "Search personal memory.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    }]
    assert body["messages"] == [
        {"role": "system", "content": "Use tools carefully."},
        {"role": "user", "content": "Search for Kimi"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": "call_1",
                "type": "function",
                "function": {
                    "name": "search_memory",
                    "arguments": "{\"query\": \"Kimi\"}",
                },
            }],
        },
        {"role": "tool", "tool_call_id": "call_1", "content": "Kimi result"},
    ]
