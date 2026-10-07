from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Literal

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

    - ``create_runtime`` — builds a session's runtime on a session miss.
      A factory that needs per-request data (a bearer token, an end-user
      id) opts in by naming a parameter ``request_context``; it receives
      the decoded request body — the ``POST /api/chat`` payload, or the
      first WS frame. Factories without that parameter are called with
      the historical ``(session_id, hooks)`` signature. Note the body is
      consulted only when the session is *created*; a later request
      reusing the same ``session_id`` reaches the existing runtime.
    """

    port: int = 3000
    api_key: str | None = None
    storage: StorageBackend | None = None
    retriever: HybridRetriever | None = None
    create_runtime: Callable[
        ...,
        AgentRuntime | Awaitable[AgentRuntime],
    ] = None  # type: ignore[assignment]
    # Tighten these defaults at deploy time. ``["*"]`` is dev-only.
    allowed_origins: list[str] = field(default_factory=lambda: ["*"])
    allowed_methods: list[str] = field(default_factory=lambda: ["GET", "POST"])
    allowed_headers: list[str] = field(default_factory=lambda: ["x-api-key", "content-type"])
    max_sessions: int = 1000
    session_idle_ttl_seconds: float = 3600.0


@dataclass
class ApprovalResolution:
    """One host decision, bound to the exact pending tool call."""

    decision: Literal["approve", "reject"]
    tool_call_id: str
    reason: str | None = None
    execution_id: str | None = None


@dataclass
class SessionEntry:
    runtime: AgentRuntime
    approve_event: asyncio.Event
    approval_resolution: ApprovalResolution | None = None
    # Per-session serialisation lock so concurrent ``run_prompt`` calls
    # against the same session never interleave their state mutations.
    # Without this, two parallel POSTs would fight over
    # ``state.messages`` and ``state.pending_tool_calls`` and the
    # OpenAI/Anthropic tool-call protocol invariant breaks immediately.
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    last_used: float = field(default_factory=time.monotonic)

    def touch(self) -> None:
        self.last_used = time.monotonic()

    def resolve_approval(
        self,
        *,
        decision: Literal["approve", "reject"],
        tool_call_id: str,
        reason: str | None = None,
        execution_id: str | None = None,
    ) -> str | None:
        """Atomically resolve the current approval, or return an error.

        ``tool_call_id`` is mandatory: accepting a generic/late approval while
        another tool is pending can accidentally authorise the wrong side
        effect. Since this method contains no awaits, the check-and-set is
        atomic within the gateway event loop; the first valid decision wins.
        """
        pending = self.runtime.state.pending_approval
        if pending is None:
            return "no pending approval"
        if pending.tool_call_id != tool_call_id:
            return "toolCallId does not match the pending approval"
        if pending.execution_id is not None and execution_id != pending.execution_id:
            return "executionId does not match the pending approval"
        if self.approval_resolution is not None or self.approve_event.is_set():
            return "approval already resolved"

        self.approval_resolution = ApprovalResolution(
            decision=decision,
            tool_call_id=tool_call_id,
            reason=reason,
            execution_id=execution_id,
        )
        self.approve_event.set()
        return None

    def consume_approval_resolution(
        self,
        expected_tool_call_id: str,
        expected_execution_id: str | None = None,
    ) -> ApprovalResolution | None:
        """Consume a decision only when it belongs to the current call."""
        resolution = self.approval_resolution
        if (resolution is None or resolution.tool_call_id != expected_tool_call_id
                or resolution.execution_id != expected_execution_id):
            return None
        self.approval_resolution = None
        self.approve_event.clear()
        return resolution
