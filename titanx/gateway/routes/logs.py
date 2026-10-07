from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ..types import GatewayOptions


def logs_router(options: GatewayOptions) -> APIRouter:
    router = APIRouter()

    @router.get("")
    async def list_logs(sessionId: str | None = None, limit: int = 100):
        # Reads the legacy ``StorageBackend`` audit table populated by the
        # deprecated ``save_log`` write path. The canonical audit trail is
        # ``titanx.policy.audit_log.AuditLog`` (JSONL); this route is kept for
        # backward compatibility and is not the source of truth.
        if not options.storage:
            return JSONResponse({"error": "storage not configured"}, status_code=501)
        return await options.storage.list_logs(sessionId, limit)

    return router
