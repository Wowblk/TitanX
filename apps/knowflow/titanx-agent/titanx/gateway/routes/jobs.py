from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ..types import GatewayOptions


def jobs_router(options: GatewayOptions) -> APIRouter:
    router = APIRouter()

    @router.get("")
    async def list_jobs(sessionId: str | None = None):
        if not options.storage:
            return JSONResponse({"error": "storage not configured"}, status_code=501)
        return await options.storage.list_jobs(sessionId)

    @router.post("")
    async def create_job(body: dict[str, Any]):
        if not options.storage:
            return JSONResponse({"error": "storage not configured"}, status_code=501)
        session_id = body.get("sessionId")
        type_ = body.get("type")
        if not session_id or not type_:
            return JSONResponse({"error": "sessionId and type are required"}, status_code=400)
        job = await options.storage.save_job(session_id=session_id, type=type_, payload=body.get("payload"))
        return JSONResponse({"id": job.id, "sessionId": job.session_id, "status": job.status,
                             "type": job.type, "createdAt": job.created_at.isoformat()}, status_code=201)

    @router.patch("/{job_id}")
    async def update_job(job_id: str, body: dict[str, Any]):
        if not options.storage:
            return JSONResponse({"error": "storage not configured"}, status_code=501)
        await options.storage.update_job(
            id=job_id,
            status=body.get("status"),
            result=body.get("result"),
            error=body.get("error"),
        )
        return {"ok": True}

    return router
