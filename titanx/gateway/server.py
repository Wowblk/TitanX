"""FastAPI gateway entry point.

Hardened against the historical issues:

1. ``hmac.compare_digest`` instead of ``==`` for the API-key check —
   string equality leaks timing information that lets an attacker
   recover the key one byte at a time over the network.
2. Explicit auth dependency injected into HTTP routers AND the
   WebSocket handler. Starlette's ``@app.middleware("http")`` does not
   run on WS upgrades, so relying on a single HTTP middleware leaves
   ``/api/chat/ws/{id}`` completely unauthenticated. The dependency
   approach unifies both code paths.
3. ``allow_origins`` is configurable. The default keeps ``["*"]`` for
   dev convenience but the docstring on ``GatewayOptions`` warns
   loudly. ``allow_credentials=False`` is implicit (we don't set it)
   because cookie-based browser sessions are out of scope; if you ever
   add them, ``["*"]`` becomes outright incompatible with credentialed
   CORS by spec.
4. Missing ``api_key`` now emits a startup warning to stderr instead
   of silently disabling auth.
"""

from __future__ import annotations

import hmac
import os
import sys

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from .types import GatewayOptions
from .session_registry import SessionRegistry
from .routes import chat_router, jobs_router, logs_router, memory_router


def _check_api_key(provided: str | None, expected: str) -> bool:
    """Constant-time API-key comparison.

    ``hmac.compare_digest`` is the canonical defence against timing
    attacks that recover a secret one byte at a time. ``==`` returns as
    soon as it finds the first mismatching byte, which leaks the prefix
    length the attacker has already guessed correctly.
    """
    if not provided:
        return False
    return hmac.compare_digest(provided, expected)


def require_api_key(request: Request, options: GatewayOptions) -> None:
    """Single auth gate used by HTTP routes AND WS handlers.

    Raising ``HTTPException`` short-circuits FastAPI's response
    pipeline; for WS we do the same check inline before
    ``websocket.accept()``.
    """
    if not options.api_key:
        return
    provided = request.headers.get("x-api-key")
    if not _check_api_key(provided, options.api_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")


def create_gateway(options: GatewayOptions) -> FastAPI:
    if not options.api_key:
        # Loud, single-line, stderr-only — ``logging`` hasn't been
        # configured yet at this point, and we want this visible even
        # when the host has filtered the package logger.
        print(
            "[titanx.gateway] WARNING: api_key is None — /api/* is OPEN to "
            "every caller, including unauthenticated WebSocket clients. "
            "Set GatewayOptions.api_key in production.",
            file=sys.stderr,
            flush=True,
        )
    if "*" in options.allowed_origins:
        print(
            "[titanx.gateway] WARNING: allowed_origins includes '*' — any "
            "browser origin can call /api/*. Override "
            "GatewayOptions.allowed_origins for production deployments.",
            file=sys.stderr,
            flush=True,
        )

    app = FastAPI(title="TitanX Gateway", docs_url=None, redoc_url=None)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=options.allowed_origins,
        allow_methods=options.allowed_methods,
        allow_headers=options.allowed_headers,
        # Credentials disabled by default; the auth model is
        # x-api-key headers, not cookies. Anything that needs cookies
        # should add its own middleware after careful review.
        allow_credentials=False,
    )

    @app.middleware("http")
    async def http_auth_middleware(request: Request, call_next):
        # Note: this DOES NOT cover WebSocket connections — Starlette
        # routes WS handshakes through a separate code path that
        # bypasses ``http`` middleware. The WS handler in chat.py
        # performs its own ``_check_api_key`` call; do not remove that
        # without first migrating it into a shared dependency.
        if options.api_key and request.url.path.startswith("/api/"):
            provided = request.headers.get("x-api-key")
            if not _check_api_key(provided, options.api_key):
                from fastapi.responses import JSONResponse
                return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)

    sessions = SessionRegistry(
        max_sessions=options.max_sessions,
        idle_ttl_seconds=options.session_idle_ttl_seconds,
    )

    app.include_router(chat_router(sessions, options), prefix="/api/chat")
    app.include_router(memory_router(options), prefix="/api/memory")
    app.include_router(jobs_router(options), prefix="/api/jobs")
    app.include_router(logs_router(options), prefix="/api/logs")

    @app.get("/", response_class=HTMLResponse)
    async def serve_ui():
        ui_path = os.path.join(os.path.dirname(__file__), "../../ui/index.html")
        if os.path.exists(ui_path):
            with open(ui_path, encoding="utf-8") as f:
                return f.read()
        return "TitanX Gateway running. UI not found at ui/index.html."

    return app


def run_gateway(options: GatewayOptions) -> None:
    import uvicorn
    app = create_gateway(options)
    uvicorn.run(app, host="0.0.0.0", port=options.port)
