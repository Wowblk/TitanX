from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ..types import GatewayOptions
from ...retrieval.types import HybridRetrievalOptions


def memory_router(options: GatewayOptions) -> APIRouter:
    router = APIRouter()

    @router.get("")
    async def list_or_search(sessionId: str | None = None, q: str | None = None, limit: int = 20):
        if not options.storage:
            return JSONResponse({"error": "storage not configured"}, status_code=501)
        if q:
            if options.retriever:
                results = await options.retriever.search(q, HybridRetrievalOptions(session_id=sessionId, limit=limit))
                return results
            results = await options.storage.search_by_fts(q, sessionId, limit)
            return results
        if not sessionId:
            return JSONResponse({"error": "sessionId required for listing"}, status_code=400)
        return await options.storage.list_memories(sessionId, limit)

    @router.post("")
    async def save_memory(body: dict[str, Any]):
        if not options.storage:
            return JSONResponse({"error": "storage not configured"}, status_code=501)
        session_id = body.get("sessionId")
        content = body.get("content")
        if not session_id or not content:
            return JSONResponse({"error": "sessionId and content are required"}, status_code=400)
        entry = await options.storage.save_memory(
            session_id=session_id,
            content=content,
            role=body.get("role", "user"),
        )
        return JSONResponse(content={"id": entry.id, "sessionId": entry.session_id,
                                     "content": entry.content, "role": entry.role,
                                     "createdAt": entry.created_at.isoformat()}, status_code=201)

    return router
