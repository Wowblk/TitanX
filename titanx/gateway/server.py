from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from .types import GatewayOptions, SessionEntry
from .routes import chat_router, jobs_router, logs_router, memory_router


def create_gateway(options: GatewayOptions) -> FastAPI:
    app = FastAPI(title="TitanX Gateway", docs_url=None, redoc_url=None)
    sessions: dict[str, SessionEntry] = {}

    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

    if options.api_key:
        @app.middleware("http")
        async def auth_middleware(request: Request, call_next):
            if request.url.path.startswith("/api/"):
                key = request.headers.get("x-api-key")
                if key != options.api_key:
                    return JSONResponse({"error": "unauthorized"}, status_code=401)
            return await call_next(request)

    app.include_router(chat_router(sessions, options), prefix="/api/chat")
    app.include_router(memory_router(options), prefix="/api/memory")
    app.include_router(jobs_router(options), prefix="/api/jobs")
    app.include_router(logs_router(options), prefix="/api/logs")

    @app.get("/", response_class=HTMLResponse)
    async def serve_ui():
        ui_path = os.path.join(os.path.dirname(__file__), "../../ui/index.html")
        if os.path.exists(ui_path):
            with open(ui_path) as f:
                return f.read()
        return "TitanX Gateway running. UI not found at ui/index.html."

    return app


def run_gateway(options: GatewayOptions) -> None:
    import uvicorn
    app = create_gateway(options)
    uvicorn.run(app, host="0.0.0.0", port=options.port)
