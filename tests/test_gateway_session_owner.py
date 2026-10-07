"""Session keys are namespaced by caller identity (SDK feature).

The gateway keys sessions on the client-supplied ``sessionId`` alone. When a
host derives the caller's identity from an authenticated request (a user id
from a JWT, a tenant), two different callers that happen to present the same
``sessionId`` must NOT share a session: a session's runtime is built once, from
the *creating* request's context, so it holds that caller's bound credentials
(a bearer token, an end-user id). Handing that runtime to a second caller would
let the second act as the first.

``GatewayOptions.session_owner`` is the seam that closes this: a host-supplied
extractor turns the decoded request body into a stable caller identity, and the
gateway scopes every session lookup by it. With no extractor configured the
historical single-namespace behaviour is preserved untouched.
"""
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from titanx.gateway import GatewayOptions, create_gateway
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


def _make_runtime_arg(session_id, hooks, request_context=None) -> AgentRuntime:
    return _make_runtime(hooks)


def _owner(body: dict[str, Any]) -> str | None:
    value = body.get("userId")
    return str(value) if value else None


def test_same_session_id_from_different_owners_is_isolated() -> None:
    built: list[Any] = []

    def create_runtime(session_id, hooks, request_context):
        built.append((request_context or {}).get("userId"))
        return _make_runtime(hooks)

    app = create_gateway(
        GatewayOptions(create_runtime=create_runtime, session_owner=_owner)
    )
    with TestClient(app) as client:
        first = client.post(
            "/api/chat",
            json={"sessionId": "shared", "message": "one", "userId": "u1"},
        )
        second = client.post(
            "/api/chat",
            json={"sessionId": "shared", "message": "two", "userId": "u2"},
        )

    assert first.status_code == 200
    assert second.status_code == 200
    # Two callers, same client-supplied id: the second must not reuse the
    # first's runtime — and therefore must not inherit the first's bound
    # credentials. A fresh runtime is built from the second request's context.
    assert built == ["u1", "u2"]


def test_same_owner_reusing_its_session_id_shares_one_runtime() -> None:
    built: list[Any] = []

    def create_runtime(session_id, hooks, request_context):
        built.append((request_context or {}).get("userId"))
        return _make_runtime(hooks)

    app = create_gateway(
        GatewayOptions(create_runtime=create_runtime, session_owner=_owner)
    )
    with TestClient(app) as client:
        client.post(
            "/api/chat",
            json={"sessionId": "mine", "message": "one", "userId": "u1"},
        )
        client.post(
            "/api/chat",
            json={"sessionId": "mine", "message": "two", "userId": "u1"},
        )

    # A caller reusing its own id keeps one conversation.
    assert built == ["u1"]


def test_without_session_owner_legacy_sharing_is_preserved() -> None:
    built: list[Any] = []

    def create_runtime(session_id, hooks):
        built.append(session_id)
        return _make_runtime(hooks)

    app = create_gateway(GatewayOptions(create_runtime=create_runtime))
    with TestClient(app) as client:
        client.post(
            "/api/chat",
            json={"sessionId": "legacy", "message": "one", "userId": "u1"},
        )
        client.post(
            "/api/chat",
            json={"sessionId": "legacy", "message": "two", "userId": "u2"},
        )

    # No extractor configured: the id alone still keys the session, exactly as
    # before the feature existed.
    assert built == ["legacy"]


def test_websocket_sessions_are_scoped_by_owner_too() -> None:
    built: list[Any] = []

    def create_runtime(session_id, hooks, request_context):
        built.append((request_context or {}).get("userId"))
        return _make_runtime(hooks)

    app = create_gateway(
        GatewayOptions(create_runtime=create_runtime, session_owner=_owner)
    )
    with TestClient(app) as client:
        for user_id in ("u1", "u2"):
            with client.websocket_connect("/api/chat/ws/shared") as websocket:
                websocket.send_json(
                    {"type": "message", "message": "hi", "userId": user_id}
                )
                while True:
                    if websocket.receive_json().get("type") == "stream_end":
                        break

    assert built == ["u1", "u2"]


def _create_owned_session(client: TestClient, session_id: str, user_id: str) -> None:
    response = client.post(
        "/api/chat",
        json={"sessionId": session_id, "message": "hi", "userId": user_id},
    )
    assert response.status_code == 200


def test_forged_scoped_key_cannot_reach_another_owners_session_over_http() -> None:
    # The scoped key for u1's session "X" is "u1\x00X". A second caller who
    # guesses that exact string (a JSON body may carry \u0000) must NOT resolve
    # u1's session: the request is re-scoped under the attacker's own id.
    app = create_gateway(
        GatewayOptions(create_runtime=_make_runtime_arg, session_owner=_owner)
    )
    with TestClient(app) as client:
        _create_owned_session(client, "X", "u1")

        approve = client.post(
            "/api/chat/approve",
            json={"sessionId": "u1\u0000X", "userId": "u2", "toolCallId": "tc-1"},
        )
        reject = client.post(
            "/api/chat/reject",
            json={"sessionId": "u1\u0000X", "userId": "u2", "toolCallId": "tc-1"},
        )

    assert approve.status_code == 404
    assert reject.status_code == 404


def test_ws_forged_scoped_path_cannot_reach_another_owners_session() -> None:
    # A path param decodes %00, so "/ws/u1%00X" arrives as the victim's scoped
    # key. The WS route must not seed an entry from that raw path (it has no
    # identity yet) — the per-frame lookup re-scopes it under the frame's owner.
    app = create_gateway(
        GatewayOptions(create_runtime=_make_runtime_arg, session_owner=_owner)
    )
    with TestClient(app) as client:
        _create_owned_session(client, "X", "u1")

        with client.websocket_connect("/api/chat/ws/u1%00X") as websocket:
            websocket.send_json(
                {"type": "approve", "toolCallId": "tc-1", "userId": "u2"}
            )
            event = websocket.receive_json()

    assert event == {"type": "error", "message": "session not found"}


def test_empty_owner_is_treated_as_no_identity() -> None:
    # A falsy owner means "no identity": the request lands in the unscoped
    # namespace rather than in a namespace keyed by "". Both callers therefore
    # share the legacy namespace, which is the documented fallback.
    built: list[Any] = []

    def create_runtime(session_id, hooks):
        built.append(session_id)
        return _make_runtime(hooks)

    app = create_gateway(
        GatewayOptions(create_runtime=create_runtime, session_owner=lambda _b: "")
    )
    with TestClient(app) as client:
        for user in ("u1", "u2"):
            client.post(
                "/api/chat",
                json={"sessionId": "e", "message": "hi", "userId": user},
            )

    assert built == ["e"]
