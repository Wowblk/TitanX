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
import hmac
import json
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from fastapi.responses import JSONResponse, StreamingResponse

from ..session_registry import SessionRegistry
from ..types import GatewayOptions, SessionEntry
from ...types import AgentConfig, AgentState, RuntimeEvent, RuntimeHooks


def _event_to_dict(event: RuntimeEvent) -> dict[str, Any]:
    return dataclasses.asdict(event) if dataclasses.is_dataclass(event) else {"type": str(event)}


def _check_api_key(provided: str | None, expected: str | None) -> bool:
    if not expected:
        return True
    if not provided:
        return False
    return hmac.compare_digest(provided, expected)


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

        async def on_event(event: RuntimeEvent, config: AgentConfig, state: AgentState) -> None:
            await queue.put(_event_to_dict(event))

            event_dict = _event_to_dict(event)
            if event_dict.get("type") == "loop_end" and event_dict.get("reason") == "pending_approval":
                entry = sessions.get(session_id)
                if entry:
                    await entry.approve_event.wait()  # type: ignore[union-attr]
                    entry.approve_event.clear()  # type: ignore[union-attr]
                    entry.runtime.approve_pending_tool()
                    await entry.runtime.resume()

        hooks = RuntimeHooks(on_event=on_event)
        entry = await sessions.get_or_create(session_id, options.create_runtime, hooks)

        async def stream():
            # ``SessionEntry.lock`` serialises run_prompt calls for this
            # session_id. Without it, concurrent POSTs for the same
            # session would race on AgentState — see SessionEntry
            # docstring.
            task = asyncio.create_task(_run_and_close(entry, message, queue))
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

    async def _run_and_close(entry: SessionEntry, message: str, queue: asyncio.Queue) -> None:
        try:
            async with entry.lock:
                entry.touch()
                await entry.runtime.run_prompt(message)
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
        session_id: str = body.get("sessionId", "")
        entry = sessions.get(session_id)
        if not entry:
            return JSONResponse({"error": "session not found"}, status_code=404)
        entry.approve_event.set()  # type: ignore[union-attr]
        return {"ok": True}

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
        queue: asyncio.Queue[dict | None] = asyncio.Queue()

        async def on_event(event: RuntimeEvent, config: AgentConfig, state: AgentState) -> None:
            await queue.put(_event_to_dict(event))

            event_dict = _event_to_dict(event)
            if event_dict.get("type") == "loop_end" and event_dict.get("reason") == "pending_approval":
                entry = sessions.get(session_id)
                if entry:
                    await entry.approve_event.wait()  # type: ignore[union-attr]
                    entry.approve_event.clear()  # type: ignore[union-attr]
                    entry.runtime.approve_pending_tool()
                    await entry.runtime.resume()

        hooks = RuntimeHooks(on_event=on_event)
        entry = await sessions.get_or_create(session_id, options.create_runtime, hooks)

        async def pump_events() -> None:
            while True:
                item = await queue.get()
                if item is None:
                    await websocket.send_json({"type": "stream_end"})
                    break
                await websocket.send_json(item)

        try:
            while True:
                data = await websocket.receive_json()
                msg_type = data.get("type")

                if msg_type == "message":
                    pump_task = asyncio.create_task(pump_events())
                    run_task = asyncio.create_task(
                        _run_and_close_ws(entry, data.get("message", ""), queue)
                    )
                    await asyncio.gather(pump_task, run_task)

                elif msg_type == "approve":
                    entry.approve_event.set()  # type: ignore[union-attr]

        except WebSocketDisconnect:
            pass

    async def _run_and_close_ws(entry: SessionEntry, message: str, queue: asyncio.Queue) -> None:
        try:
            async with entry.lock:
                entry.touch()
                await entry.runtime.run_prompt(message)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await queue.put({"type": "error", "message": str(exc)})
        finally:
            await queue.put(None)

    return router
