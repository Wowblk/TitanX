from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from ..runtime import AgentRuntime
from ..types import RuntimeHooks
from ..storage.types import StorageBackend
from ..retrieval.hybrid import HybridRetriever


@dataclass
class GatewayOptions:
    """Configuration for the FastAPI gateway.

    Security-relevant knobs:

    - ``api_key`` — when set, every ``/api/`` request (HTTP **and** WS)
      must present a matching ``x-api-key`` header. Comparison uses
      ``hmac.compare_digest`` to defeat string-equality timing leaks.
      When ``None`` the gateway logs a single warning at startup so
      "I forgot to configure auth" becomes visible instead of silent.

    - ``allowed_origins`` — list of origins permitted by CORS. Default
      ``["*"]`` is convenient for development but is **incompatible with
      credentialed requests**: combined with custom-header auth it lets
      any third-party site probe the gateway from a victim's browser.
      Set this to the actual host list in production.

    - ``max_sessions`` / ``session_idle_ttl_seconds`` — bound the
      in-memory session map so an unauthenticated WS client (or a
      misbehaving frontend) cannot grow the dict without limit. Idle
      sessions past TTL are evicted on the next access; the limit is
      a hard LRU cap.
    """

    port: int = 3000
    api_key: str | None = None
    storage: StorageBackend | None = None
    retriever: HybridRetriever | None = None
    create_runtime: Callable[[str, RuntimeHooks], AgentRuntime | Awaitable[AgentRuntime]] = None  # type: ignore[assignment]
    # Tighten these defaults at deploy time. ``["*"]`` is dev-only.
    allowed_origins: list[str] = field(default_factory=lambda: ["*"])
    allowed_methods: list[str] = field(default_factory=lambda: ["GET", "POST"])
    allowed_headers: list[str] = field(default_factory=lambda: ["x-api-key", "content-type"])
    max_sessions: int = 1000
    session_idle_ttl_seconds: float = 3600.0


@dataclass
class SessionEntry:
    runtime: AgentRuntime
    approve_event: object  # asyncio.Event — typed as object to avoid import cycle
    # Per-session serialisation lock so concurrent ``run_prompt`` calls
    # against the same session never interleave their state mutations.
    # Without this, two parallel POSTs would fight over
    # ``state.messages`` and ``state.pending_tool_calls`` and the
    # OpenAI/Anthropic tool-call protocol invariant breaks immediately.
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    last_used: float = field(default_factory=time.monotonic)

    def touch(self) -> None:
        self.last_used = time.monotonic()
