"""Chat endpoints: SSE POST + WebSocket.

All session lookups go through ``SessionRegistry`` (Q19/Q14 fix) so the
in-memory map is bounded by ``max_sessions`` and idle entries are
evicted by ``session_idle_ttl_seconds``.

WebSocket authentication is performed inline before
``websocket.accept()``: Starlette's HTTP middleware does NOT run on
WS handshakes, so the ``api_key`` check in ``server.py`` covers HTTP
only. Without this inline check the WS endpoint was wide open.

Per-session ``run_prompt`` calls are serialised via
``SessionEntry.lock``. Two concurrent POSTs for the same session_id
used to interleave their state mutations — both would race on
``state.messages`` and ``state.pending_tool_calls``, breaking the
OpenAI/Anthropic tool-call protocol.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from fastapi.responses import JSONResponse, StreamingResponse

from ..server import _check_api_key
from ..session_registry import SessionCapacityError, SessionRegistry
from ..types import GatewayOptions, SessionEntry
from ...types import AgentConfig, AgentState, RuntimeEvent, RuntimeHooks


_MAX_REJECTION_REASON_LENGTH = 2_000


def _event_to_dict(event: RuntimeEvent) -> dict[str, Any]:
    return dataclasses.asdict(event) if dataclasses.is_dataclass(event) else {"type": str(event)}


def _approval_fields(
    body: dict[str, Any],
    *,
    decision: str,
) -> tuple[str | None, str | None, str | None]:
    """Return ``(tool_call_id, reason, error)`` for an approval message."""
    tool_call_id = body.get("toolCallId", body.get("tool_call_id"))
    if not isinstance(tool_call_id, str) or not tool_call_id:
        return None, None, "toolCallId is required"

    if decision == "approve":
        return tool_call_id, None, None

    reason = body.get("reason", "Rejected by host")
    if reason is None or reason == "":
        reason = "Rejected by host"
    if not isinstance(reason, str):
        return None, None, "reason must be a string"
    if len(reason) > _MAX_REJECTION_REASON_LENGTH:
        return None, None, (
            f"reason exceeds maximum length ({_MAX_REJECTION_REASON_LENGTH})"
        )
    return tool_call_id, reason, None


async def _apply_approval_resolution(entry: SessionEntry) -> None:
    """Wait for and apply the decision for the exact pending tool call."""
    pending = entry.runtime.state.pending_approval
    if pending is None:
        return
    expected_tool_call_id = pending.tool_call_id
    expected_execution_id = pending.execution_id

    while True:
        await entry.approve_event.wait()
        resolution = entry.consume_approval_resolution(expected_tool_call_id, expected_execution_id)
        if resolution is not None:
            break
        # Defensive compatibility with hosts that still set approve_event
        # directly: never treat an unbound Event as approval. Clear it and
        # continue waiting for a tool-call-bound decision.
        entry.approve_event.clear()

    if resolution.decision == "approve":
        entry.runtime.approve_pending_tool(execution_id=expected_execution_id)
    else:
        entry.runtime.reject_pending_tool(resolution.reason or "Rejected by host")
    await entry.runtime.resume()


def chat_router(sessions: SessionRegistry, options: GatewayOptions) -> APIRouter:
    router = APIRouter()

    # ── SSE endpoint ──────────────────────────────────────────────────────────

    @router.post("")
    async def chat_sse(body: dict[str, Any]) -> StreamingResponse:
        session_id: str = body.get("sessionId", "")
        message: str = body.get("message", "")
        if not session_id or not message:
            return JSONResponse({"error": "sessionId and message are required"}, status_code=400)

        queue: asyncio.Queue[dict | None] = asyncio.Queue()

        entry: SessionEntry | None = None

        async def on_event(event: RuntimeEvent, config: AgentConfig, state: AgentState) -> None:
            event_dict = _event_to_dict(event)
            await queue.put(event_dict)
            if event_dict.get("type") == "loop_end" and event_dict.get("reason") == "pending_approval":
                if entry is not None:
                    await _apply_approval_resolution(entry)

        hooks = RuntimeHooks(on_event=on_event)
        try:
            entry = await sessions.get_or_create(
                session_id,
                options.create_runtime,
                hooks,
                # The decoded request body is the only place a host can get
                # per-request credentials (bearer token, end-user id) at the
                # moment the runtime is built. Consumed only by factories
                # that declare a third parameter.
                request_context=body,
            )
        except SessionCapacityError as exc:
            return JSONResponse({"error": str(exc)}, status_code=503)

        async def stream():
            # ``SessionEntry.lock`` serialises run_prompt calls for this
            # session_id. Without it, concurrent POSTs for the same
            # session would race on AgentState — see SessionEntry
            # docstring.
            task = asyncio.create_task(_run_and_close(entry, message, queue, hooks))
            try:
                while True:
                    item = await queue.get()
                    if item is None:
                        break
                    yield f"data: {json.dumps(item)}\n\n"
                yield f"data: {json.dumps({'type': 'stream_end'})}\n\n"
            finally:
                # Cancel any in-flight run if the client disconnected
                # mid-stream. AgentRuntime's CancelledError handler
                # (Q22) closes the tool-call protocol cleanly.
                if not task.done():
                    task.cancel()
                    try:
                        await task
                    except (asyncio.CancelledError, Exception):
                        pass

        return StreamingResponse(stream(), media_type="text/event-stream")

    async def _run_and_close(
        entry: SessionEntry,
        message: str,
        queue: asyncio.Queue,
        hooks: RuntimeHooks,
    ) -> None:
        try:
            async with entry.lock:
                entry.touch()
                # Bind only after acquiring the session lock. A later request
                # may already be waiting on the lock with a different queue;
                # task-local hooks ensure it cannot redirect this run's events.
                await entry.runtime.run_prompt(message, hooks=hooks)
        except asyncio.CancelledError:
            # Don't re-emit anything — the stream() finally will drain.
            raise
        except Exception as exc:
            await queue.put({"type": "error", "message": str(exc)})
        finally:
            await queue.put(None)

    # ── Approval ──────────────────────────────────────────────────────────────

    @router.post("/approve")
    async def approve(body: dict[str, Any]):
        session_id = body.get("sessionId", "")
        if not isinstance(session_id, str) or not session_id:
            return JSONResponse({"error": "sessionId is required"}, status_code=400)
        entry = sessions.get(session_id)
        if not entry:
            return JSONResponse({"error": "session not found"}, status_code=404)
        tool_call_id, _, error = _approval_fields(body, decision="approve")
        if error:
            return JSONResponse({"error": error}, status_code=400)
        assert tool_call_id is not None
        error = entry.resolve_approval(
            decision="approve",
            tool_call_id=tool_call_id,
            execution_id=body.get("executionId", body.get("execution_id")),
        )
        if error:
            return JSONResponse({"error": error}, status_code=409)
        return {"ok": True, "toolCallId": tool_call_id}

    @router.post("/reject")
    async def reject(body: dict[str, Any]):
        session_id = body.get("sessionId", "")
        if not isinstance(session_id, str) or not session_id:
            return JSONResponse({"error": "sessionId is required"}, status_code=400)
        entry = sessions.get(session_id)
        if not entry:
            return JSONResponse({"error": "session not found"}, status_code=404)
        tool_call_id, reason, error = _approval_fields(body, decision="reject")
        if error:
            return JSONResponse({"error": error}, status_code=400)
        assert tool_call_id is not None
        error = entry.resolve_approval(
            decision="reject",
            tool_call_id=tool_call_id,
            reason=reason,
            execution_id=body.get("executionId", body.get("execution_id")),
        )
        if error:
            return JSONResponse({"error": error}, status_code=409)
        return {"ok": True, "toolCallId": tool_call_id}

    # ── WebSocket endpoint ────────────────────────────────────────────────────

    @router.websocket("/ws/{session_id}")
    async def chat_ws(websocket: WebSocket, session_id: str) -> None:
        # Inline auth: Starlette HTTP middleware DOES NOT run on WS
        # handshakes. The historical bug left this endpoint open even
        # when ``options.api_key`` was set.
        if options.api_key:
            provided = websocket.headers.get("x-api-key")
            if not _check_api_key(provided, options.api_key):
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return
        await websocket.accept()
        entry: SessionEntry | None = sessions.get(session_id)
        active_exchange: asyncio.Task[None] | None = None

        try:
            while True:
                data = await websocket.receive_json()
                # The exchange can finish while receive_json() is blocked.
                # Reap it *after* the receive so the next message is not
                # falsely rejected as concurrent merely because the task was
                # still running before we started waiting for input.
                if active_exchange is not None and active_exchange.done():
                    await active_exchange
                    active_exchange = None
                msg_type = data.get("type")

                if msg_type == "message":
                    if active_exchange is not None:
                        await websocket.send_json({
                            "type": "error",
                            "message": "a message is already running for this connection",
                        })
                        continue

                    queue: asyncio.Queue[dict | None] = asyncio.Queue()
                    entry_for_run: SessionEntry | None = None

                    async def on_event(
                        event: RuntimeEvent,
                        config: AgentConfig,
                        state: AgentState,
                    ) -> None:
                        event_dict = _event_to_dict(event)
                        await queue.put(event_dict)
                        if (
                            event_dict.get("type") == "loop_end"
                            and event_dict.get("reason") == "pending_approval"
                            and entry_for_run is not None
                        ):
                            await _apply_approval_resolution(entry_for_run)

                    hooks = RuntimeHooks(on_event=on_event)
                    try:
                        entry_for_run = await sessions.get_or_create(
                            session_id,
                            options.create_runtime,
                            hooks,
                        )
                    except SessionCapacityError as exc:
                        await websocket.send_json({
                            "type": "error",
                            "message": str(exc),
                        })
                        continue
                    entry = entry_for_run
                    active_exchange = asyncio.create_task(
                        _run_ws_exchange(
                            websocket,
                            entry_for_run,
                            data.get("message", ""),
                            queue,
                            hooks,
                        )
                    )

                elif msg_type in ("approve", "reject"):
                    if entry is None:
                        entry = sessions.get(session_id)
                    if entry is None:
                        await websocket.send_json({
                            "type": "error",
                            "message": "session not found",
                        })
                        continue
                    tool_call_id, reason, error = _approval_fields(
                        data,
                        decision=msg_type,
                    )
                    if error is None:
                        assert tool_call_id is not None
                        error = entry.resolve_approval(
                            decision=msg_type,
                            tool_call_id=tool_call_id,
                            reason=reason,
                            execution_id=data.get("executionId", data.get("execution_id")),
                        )
                    if error:
                        await websocket.send_json({
                            "type": "error",
                            "message": error,
                        })

                else:
                    await websocket.send_json({
                        "type": "error",
                        "message": f"unknown message type: {msg_type}",
                    })

        except WebSocketDisconnect:
            pass
        finally:
            if active_exchange is not None:
                if not active_exchange.done():
                    active_exchange.cancel()
                try:
                    await active_exchange
                except (asyncio.CancelledError, Exception):
                    pass

    async def _run_ws_exchange(
        websocket: WebSocket,
        entry: SessionEntry,
        message: str,
        queue: asyncio.Queue,
        hooks: RuntimeHooks,
    ) -> None:
        async def pump_events() -> None:
            while True:
                item = await queue.get()
                if item is None:
                    await websocket.send_json({"type": "stream_end"})
                    break
                await websocket.send_json(item)

        # Structured concurrency matters here: if the socket send side fails,
        # cancel the runtime side too (and vice versa). asyncio.gather would
        # propagate the first exception while leaving its sibling running,
        # which can strand a task forever in an approval wait after disconnect.
        async with asyncio.TaskGroup() as tasks:
            tasks.create_task(pump_events())
            tasks.create_task(_run_and_close_ws(entry, message, queue, hooks))

    async def _run_and_close_ws(
        entry: SessionEntry,
        message: str,
        queue: asyncio.Queue,
        hooks: RuntimeHooks,
    ) -> None:
        try:
            async with entry.lock:
                entry.touch()
                await entry.runtime.run_prompt(message, hooks=hooks)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await queue.put({"type": "error", "message": str(exc)})
        finally:
            await queue.put(None)

    return router
