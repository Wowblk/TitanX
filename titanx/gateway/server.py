"""FastAPI gateway entry point.

Hardened against the historical issues:

1. ``hmac.compare_digest`` instead of ``==`` for the API-key check —
   string equality leaks timing information that lets an attacker
   recover the key one byte at a time over the network.
2. HTTP auth runs as ``@app.middleware("http")``; the WebSocket handler
   in ``routes/chat.py`` calls the same ``_check_api_key`` inline.
   Starlette's ``@app.middleware("http")`` does not run on WS upgrades,
   so relying on the middleware alone would leave
   ``/api/chat/ws/{id}`` completely unauthenticated.
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

from contextlib import asynccontextmanager
import hmac
import os
import sys

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from .types import GatewayOptions
from .session_registry import SessionRegistry


# Single default bind address for every entry point. 127.0.0.1 keeps the
# gateway off the network by default; override per call / via --host.
DEFAULT_HOST = "127.0.0.1"


def _check_api_key(provided: str | None, expected: str | None) -> bool:
    """The single, canonical API-key check for HTTP **and** WS.

    Semantics (documented here once so the file, the middleware and the
    WS handler cannot drift apart again):

    - ``expected`` is falsy (``None`` or ``""``) -> no key is configured
      -> the gateway is open -> allow (``True``). Every call site gates
      on ``if options.api_key:``, so an empty key must mean "open" here
      too or the helper would disagree with the gateway it protects.
    - a key *is* configured -> require a non-empty ``provided`` that
      matches ``expected``.

    ``hmac.compare_digest`` is the canonical defence against timing
    attacks that recover a secret one byte at a time. ``==`` returns as
    soon as it finds the first mismatching byte, which leaks the prefix
    length the attacker has already guessed correctly.
    """
    if not expected:
        return True
    if not provided:
        return False
    return hmac.compare_digest(provided, expected)


def create_gateway(options: GatewayOptions) -> FastAPI:
    # Imported here rather than at module scope: ``routes.chat`` imports
    # this module's ``_check_api_key``, so a top-level import would form a
    # cycle the moment ``titanx.gateway.routes.chat`` is imported first.
    from .routes import chat_router, jobs_router, logs_router, memory_router

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

    sessions = SessionRegistry(
        max_sessions=options.max_sessions,
        idle_ttl_seconds=options.session_idle_ttl_seconds,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Bounded sessions are meaningless if eviction only drops dict rows:
        # shutting the gateway down must destroy sandbox sessions and release
        # per-session store rows, or containers/disk grow without limit.
        try:
            yield
        finally:
            await sessions.aclose()

    app = FastAPI(title="TitanX Gateway", docs_url=None, redoc_url=None, lifespan=lifespan)

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
        # bypasses ``http`` middleware. The WS handler in chat.py calls
        # the same ``_check_api_key`` inline; both paths share that one
        # helper so they cannot drift apart.
        if options.api_key and request.url.path.startswith("/api/"):
            provided = request.headers.get("x-api-key")
            if not _check_api_key(provided, options.api_key):
                from fastapi.responses import JSONResponse
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
            with open(ui_path, encoding="utf-8") as f:
                return f.read()
        return "TitanX Gateway running. UI not found at ui/index.html."

    return app


def run_gateway(options: GatewayOptions, host: str = DEFAULT_HOST) -> None:
    import uvicorn
    app = create_gateway(options)
    uvicorn.run(app, host=host, port=options.port)
