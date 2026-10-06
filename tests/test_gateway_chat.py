"""Gateway chat streaming and human-in-the-loop regressions."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
from fastapi.testclient import TestClient

from titanx.gateway import GatewayOptions, create_gateway
from titanx.runtime import AgentRuntime
from titanx.safety.safety_layer import SafetyLayer
from titanx.types import (
    LlmAdapter,
    LlmTurnResult,
    RuntimeHooks,
    ToolCall,
    ToolDefinition,
    ToolExecutionResult,
    ToolMessage,
    ToolRuntime,
)

from ._helpers import NullTools


def _sse_events(body: str) -> list[dict[str, Any]]:
    return [
        json.loads(line.removeprefix("data:").strip())
        for line in body.splitlines()
        if line.startswith("data:")
    ]


class _CountingTextLlm(LlmAdapter):
    def __init__(self) -> None:
        self.calls = 0

    async def respond(self, config, state) -> LlmTurnResult:
        self.calls += 1
        return LlmTurnResult(type="text", text=f"reply-{self.calls}")


def test_same_session_two_sse_requests_each_receive_runtime_events() -> None:
    runtimes: dict[str, AgentRuntime] = {}

    def create_runtime(session_id: str, hooks: RuntimeHooks) -> AgentRuntime:
        runtime = AgentRuntime(
            llm=_CountingTextLlm(),
            tools=NullTools(),
            safety=SafetyLayer(),
            hooks=hooks,
        )
        runtimes[session_id] = runtime
        return runtime

    app = create_gateway(GatewayOptions(create_runtime=create_runtime))
    with TestClient(app) as client:
        first = client.post("/api/chat", json={"sessionId": "long", "message": "one"})
        second = client.post("/api/chat", json={"sessionId": "long", "message": "two"})

    assert first.status_code == 200
    assert second.status_code == 200
    first_events = _sse_events(first.text)
    second_events = _sse_events(second.text)
    assert [e["text"] for e in first_events if e["type"] == "assistant_text"] == [
        "reply-1"
    ]
    assert [e["text"] for e in second_events if e["type"] == "assistant_text"] == [
        "reply-2"
    ]
    assert first_events[0]["type"] == "loop_start"
    assert second_events[0]["type"] == "loop_start"
    assert first_events[-1] == {"type": "stream_end"}
    assert second_events[-1] == {"type": "stream_end"}
    assert list(runtimes) == ["long"]


class _ApprovalLlm(LlmAdapter):
    def __init__(self, tool_call_id: str) -> None:
        self.tool_call_id = tool_call_id
        self.calls = 0

    async def respond(self, config, state) -> LlmTurnResult:
        self.calls += 1
        if self.calls == 1:
            return LlmTurnResult(
                type="tool_calls",
                text="",
                tool_calls=[
                    ToolCall(
                        id=self.tool_call_id,
                        name="dangerous",
                        args={"target": "production"},
                    )
                ],
            )
        return LlmTurnResult(type="text", text="decision recorded")


class _ApprovalTools(ToolRuntime):
    def __init__(self) -> None:
        self.calls: list[str] = []

    def list_tools(self) -> list[ToolDefinition]:
        return [
            ToolDefinition(
                name="dangerous",
                description="",
                parameters={},
                requires_approval=True,
            )
        ]

    async def execute(self, name: str, params: dict[str, Any]) -> ToolExecutionResult:
        self.calls.append(name)
        return ToolExecutionResult(output="should not execute", error=None)


def _approval_gateway(*, max_sessions: int = 1000):
    runtimes: dict[str, AgentRuntime] = {}
    tools_by_session: dict[str, _ApprovalTools] = {}

    def create_runtime(session_id: str, hooks: RuntimeHooks) -> AgentRuntime:
        tools = _ApprovalTools()
        runtime = AgentRuntime(
            llm=_ApprovalLlm(f"tc-{session_id}"),
            tools=tools,
            safety=SafetyLayer(),
            hooks=hooks,
        )
        runtimes[session_id] = runtime
        tools_by_session[session_id] = tools
        return runtime

    return (
        create_gateway(GatewayOptions(
            create_runtime=create_runtime,
            max_sessions=max_sessions,
        )),
        runtimes,
        tools_by_session,
    )


async def _wait_for_pending(runtime: AgentRuntime) -> str:
    for _ in range(100):
        pending = runtime.state.pending_approval
        if pending is not None:
            return pending.tool_call_id
        await asyncio.sleep(0.01)
    raise AssertionError("runtime never entered pending approval")


async def test_http_reject_requires_matching_tool_call_id_and_preserves_reason() -> None:
    app, runtimes, tools_by_session = _approval_gateway()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        chat_task = asyncio.create_task(client.post(
            "/api/chat",
            json={"sessionId": "http", "message": "do it"},
        ))

        for _ in range(100):
            if "http" in runtimes:
                break
            await asyncio.sleep(0.01)
        runtime = runtimes["http"]
        tool_call_id = await _wait_for_pending(runtime)

        wrong = await client.post(
            "/api/chat/reject",
            json={
                "sessionId": "http",
                "toolCallId": "tc-stale",
                "reason": "late decision",
            },
        )
        assert wrong.status_code == 409
        assert runtime.state.pending_approval is not None
        assert not chat_task.done()

        rejected = await client.post(
            "/api/chat/reject",
            json={
                "sessionId": "http",
                "toolCallId": tool_call_id,
                "reason": "operator denied production access",
                "executionId": runtime.state.pending_approval.execution_id,
            },
        )
        assert rejected.status_code == 200
        response = await asyncio.wait_for(chat_task, timeout=2.0)

    events = _sse_events(response.text)
    assert any(e["type"] == "pending_approval" for e in events)
    assert any(
        e["type"] == "loop_end" and e["reason"] == "completed"
        for e in events
    )
    assert tools_by_session["http"].calls == []
    rejected_message = next(
        m
        for m in runtime.state.messages
        if isinstance(m, ToolMessage) and m.tool_call_id == tool_call_id
    )
    assert rejected_message.is_error is True
    assert "operator denied production access" in rejected_message.content


async def test_http_approve_action_remains_supported_for_matching_call() -> None:
    app, runtimes, tools_by_session = _approval_gateway()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        chat_task = asyncio.create_task(client.post(
            "/api/chat",
            json={"sessionId": "approve", "message": "do it"},
        ))

        for _ in range(100):
            if "approve" in runtimes:
                break
            await asyncio.sleep(0.01)
        runtime = runtimes["approve"]
        tool_call_id = await _wait_for_pending(runtime)

        for execution_id in (None, "stale-operation"):
            refused = await client.post(
                "/api/chat/approve",
                json={"sessionId": "approve", "toolCallId": tool_call_id,
                      "executionId": execution_id},
            )
            assert refused.status_code == 409
            assert "executionId" in refused.json()["error"]
            assert tools_by_session["approve"].calls == []
            assert not chat_task.done()

        approved = await client.post(
            "/api/chat/approve",
            json={"sessionId": "approve", "toolCallId": tool_call_id,
                  "executionId": runtime.state.pending_approval.execution_id},
        )
        assert approved.status_code == 200
        response = await asyncio.wait_for(chat_task, timeout=2.0)

    assert response.status_code == 200
    assert tools_by_session["approve"].calls == ["dangerous"]
    tool_message = next(
        m
        for m in runtime.state.messages
        if isinstance(m, ToolMessage) and m.tool_call_id == tool_call_id
    )
    assert tool_message.is_error is False


async def test_http_capacity_refuses_new_session_without_stranding_approval() -> None:
    app, runtimes, tools_by_session = _approval_gateway(max_sessions=1)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        active_chat = asyncio.create_task(client.post(
            "/api/chat",
            json={"sessionId": "active", "message": "do it"},
        ))
        for _ in range(100):
            if "active" in runtimes:
                break
            await asyncio.sleep(0.01)
        runtime = runtimes["active"]
        tool_call_id = await _wait_for_pending(runtime)

        refused = await client.post(
            "/api/chat",
            json={"sessionId": "new", "message": "must not evict"},
        )
        assert refused.status_code == 503
        assert "all sessions are active" in refused.json()["error"]
        assert runtime.state.pending_approval is not None

        rejected = await client.post(
            "/api/chat/reject",
            json={
                "sessionId": "active",
                "toolCallId": tool_call_id,
                "reason": "capacity test cleanup",
                "executionId": runtime.state.pending_approval.execution_id,
            },
        )
        assert rejected.status_code == 200
        completed = await asyncio.wait_for(active_chat, timeout=2.0)

    assert completed.status_code == 200
    assert tools_by_session["active"].calls == []


def test_websocket_reject_resumes_active_stream_with_reason() -> None:
    app, runtimes, tools_by_session = _approval_gateway()

    with TestClient(app) as client:
        with client.websocket_connect("/api/chat/ws/ws") as websocket:
            websocket.send_json({"type": "message", "message": "do it"})
            events: list[dict[str, Any]] = []
            pending_id = ""
            while not pending_id:
                event = websocket.receive_json()
                events.append(event)
                if event.get("type") == "pending_approval":
                    pending_id = event["approval"]["tool_call_id"]
                    execution_id = event["approval"]["execution_id"]

            websocket.send_json({
                "type": "reject",
                "toolCallId": "tc-old",
                "reason": "stale",
            })
            while not any(e.get("type") == "error" for e in events):
                events.append(websocket.receive_json())
            assert "does not match" in next(
                e["message"] for e in events if e.get("type") == "error"
            )

            websocket.send_json({
                "type": "reject",
                "toolCallId": pending_id,
                "reason": "websocket operator rejected",
                "executionId": execution_id,
            })
            while not any(e.get("type") == "stream_end" for e in events):
                events.append(websocket.receive_json())

    runtime = runtimes["ws"]
    assert tools_by_session["ws"].calls == []
    rejected_message = next(
        m
        for m in runtime.state.messages
        if isinstance(m, ToolMessage) and m.tool_call_id == pending_id
    )
    assert rejected_message.is_error is True
    assert "websocket operator rejected" in rejected_message.content
    assert any(e.get("type") == "assistant_text" for e in events)
