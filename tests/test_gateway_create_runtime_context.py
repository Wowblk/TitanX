"""Per-request context reaches the runtime factory (SDK feature).

A host that must build the runtime from *per-request* data — a caller's
bearer token, an end-user id, a tenant — has no other seam: the gateway
keys sessions on ``sessionId`` alone, and the request body is otherwise
dropped before ``create_runtime`` runs. These tests pin the contract that
a factory declaring a third parameter receives the decoded request body,
while a legacy two-parameter factory keeps working untouched.

The factory runs only on a session miss (the first request for a
``sessionId``), which is exactly when the host needs the caller's
credentials to construct the runtime.
"""
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from titanx.gateway import GatewayOptions, create_gateway
from titanx.gateway.session_registry import SessionRegistry
from titanx.runtime import AgentRuntime
from titanx.safety.safety_layer import SafetyLayer
from titanx.types import LlmAdapter, LlmTurnResult, RuntimeHooks

from ._helpers import NullTools


class _TextLlm(LlmAdapter):
    async def respond(self, config, state) -> LlmTurnResult:
        return LlmTurnResult(type="text", text="ok")


def _make_runtime(hooks: RuntimeHooks) -> AgentRuntime:
    return AgentRuntime(
        llm=_TextLlm(),
        tools=NullTools(),
        safety=SafetyLayer(),
        hooks=hooks,
    )


def test_sse_request_body_reaches_three_arg_runtime_factory() -> None:
    seen: list[tuple[str, RuntimeHooks, Any]] = []

    def create_runtime(session_id, hooks, request_context):
        seen.append((session_id, hooks, request_context))
        return _make_runtime(hooks)

    app = create_gateway(GatewayOptions(create_runtime=create_runtime))
    payload = {
        "sessionId": "ctx",
        "message": "hi",
        "userId": "u-42",
        "toolBearerToken": "secret-jwt",
    }
    with TestClient(app) as client:
        response = client.post("/api/chat", json=payload)

    assert response.status_code == 200
    # The factory is invoked once, for the session miss, with the host's
    # credentials intact — not a stripped-body or an empty dict.
    assert len(seen) == 1
    session_id, _, request_context = seen[0]
    assert session_id == "ctx"
    assert request_context == payload


def test_two_arg_runtime_factory_still_works_without_context() -> None:
    seen: list[str] = []

    def create_runtime(session_id, hooks):
        seen.append(session_id)
        return _make_runtime(hooks)

    app = create_gateway(GatewayOptions(create_runtime=create_runtime))
    with TestClient(app) as client:
        response = client.post("/api/chat", json={"sessionId": "two", "message": "hi"})

    # A legacy two-parameter factory must not be handed an unexpected third
    # positional argument.
    assert response.status_code == 200
    assert seen == ["two"]


async def test_registry_forwards_request_context_to_three_arg_factory() -> None:
    registry = SessionRegistry(max_sessions=4, idle_ttl_seconds=0)
    seen: list[dict[str, Any] | None] = []

    def create(session_id, hooks, request_context):
        seen.append(request_context)
        return _make_runtime(hooks)

    entry = await registry.get_or_create(
        "s", create, RuntimeHooks(), {"userId": "u-7"}
    )

    assert seen == [{"userId": "u-7"}]
    assert entry.runtime is not None


async def test_registry_does_not_pass_context_to_two_arg_factory() -> None:
    registry = SessionRegistry(max_sessions=4, idle_ttl_seconds=0)
    calls: list[tuple[str, int]] = []

    def create(session_id, hooks):
        calls.append((session_id, 2))
        return _make_runtime(hooks)

    await registry.get_or_create("s", create, RuntimeHooks(), {"userId": "u-7"})

    # Context is available but the factory never asked for it.
    assert calls == [("s", 2)]
