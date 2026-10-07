from __future__ import annotations

import asyncio
import dataclasses
import inspect
import json
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse

from ..types import GatewayOptions, SessionEntry
from ...types import AgentConfig, AgentState, RuntimeEvent, RuntimeHooks


def _event_to_dict(event: RuntimeEvent) -> dict[str, Any]:
    return dataclasses.asdict(event) if dataclasses.is_dataclass(event) else {"type": str(event)}


async def _create_runtime(options: GatewayOptions, session_id: str, hooks: RuntimeHooks, body: dict[str, Any]):
    create_runtime = options.create_runtime
    if len(inspect.signature(create_runtime).parameters) >= 3:
        runtime_or_coro = create_runtime(session_id, hooks, body)
    else:
        runtime_or_coro = create_runtime(session_id, hooks)
    if inspect.isawaitable(runtime_or_coro):
        return await runtime_or_coro
    return runtime_or_coro


def chat_router(sessions: dict[str, SessionEntry], options: GatewayOptions) -> APIRouter:
    router = APIRouter()

    # ── SSE endpoint ──────────────────────────────────────────────────────────

    @router.post("")
    async def chat_sse(body: dict[str, Any]) -> StreamingResponse:
        session_id: str = body.get("sessionId", "")
        message: str = body.get("message", "")
        if not session_id or not message:
            from fastapi.responses import JSONResponse
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

        entry = sessions.get(session_id)
        if not entry:
            runtime = await _create_runtime(options, session_id, hooks, body)
            approve_event = asyncio.Event()
            entry = SessionEntry(runtime=runtime, approve_event=approve_event)
            sessions[session_id] = entry
        else:
            entry.runtime.set_hooks(hooks)

        async def stream():
            task = asyncio.create_task(_run_and_close(entry.runtime, message, queue))
            try:
                while True:
                    item = await queue.get()
                    if item is None:
                        break
                    yield f"data: {json.dumps(item)}\n\n"
                yield f"data: {json.dumps({'type': 'stream_end'})}\n\n"
            finally:
                task.cancel()

        return StreamingResponse(stream(), media_type="text/event-stream")

    async def _run_and_close(runtime, message: str, queue: asyncio.Queue) -> None:
        try:
            await runtime.run_prompt(message)
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
            from fastapi.responses import JSONResponse
            return JSONResponse({"error": "session not found"}, status_code=404)
        entry.approve_event.set()  # type: ignore[union-attr]
        return {"ok": True}

    # ── WebSocket endpoint ────────────────────────────────────────────────────

    @router.websocket("/ws/{session_id}")
    async def chat_ws(websocket: WebSocket, session_id: str) -> None:
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

        entry = sessions.get(session_id)
        if not entry:
            runtime = await _create_runtime(options, session_id, hooks, {})
            approve_event = asyncio.Event()
            entry = SessionEntry(runtime=runtime, approve_event=approve_event)
            sessions[session_id] = entry
        else:
            entry.runtime.set_hooks(hooks)

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
                        _run_and_close_ws(entry.runtime, data.get("message", ""), queue)
                    )
                    await asyncio.gather(pump_task, run_task)

                elif msg_type == "approve":
                    entry.approve_event.set()  # type: ignore[union-attr]

        except WebSocketDisconnect:
            pass

    async def _run_and_close_ws(runtime, message: str, queue: asyncio.Queue) -> None:
        try:
            await runtime.run_prompt(message)
        except Exception as exc:
            await queue.put({"type": "error", "message": str(exc)})
        finally:
            await queue.put(None)

    return router
