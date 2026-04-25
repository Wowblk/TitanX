"""Bounded session map with LRU + idle-TTL eviction.

The historical implementation was a plain ``dict[str, SessionEntry]``
that never shrunk:

- ``destroy_session`` was nowhere
- nothing ever evicted on idle
- nothing capped the total
- nothing kept the keys behaving as identifiers (a malicious
  unauthenticated WS client could open thousands of distinct
  ``session_id`` values and exhaust the gateway's memory)

This module gives the gateway a single chokepoint: every read or write
goes through the registry, every ``get_or_create`` enforces both the
per-session idle TTL and the global max-sessions cap, and the eviction
order is LRU by ``last_used``.

Concurrency model
=================

The registry is intended to be called from inside a request handler;
its ``asyncio.Lock`` serialises eviction against creation so two
concurrent ``POST /api/chat`` requests for new sessions can't both
push us over the cap. Per-session locks live on ``SessionEntry`` and
are NOT held by the registry — those are about ``run_prompt``
serialisation, not registry serialisation.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from typing import Awaitable, Callable

from .types import GatewayOptions, SessionEntry
from ..runtime import AgentRuntime
from ..types import RuntimeHooks


CreateRuntime = Callable[[str, RuntimeHooks], "AgentRuntime | Awaitable[AgentRuntime]"]


class SessionRegistry:
    def __init__(self, *, max_sessions: int, idle_ttl_seconds: float) -> None:
        if max_sessions <= 0:
            raise ValueError("max_sessions must be positive")
        if idle_ttl_seconds < 0:
            raise ValueError("idle_ttl_seconds must be non-negative")
        self._max = max_sessions
        self._ttl = idle_ttl_seconds
        self._sessions: dict[str, SessionEntry] = {}
        self._lock = asyncio.Lock()

    def get(self, session_id: str) -> SessionEntry | None:
        entry = self._sessions.get(session_id)
        if entry is None:
            return None
        if self._is_idle_expired(entry):
            # Don't pop here — popping under read access would race
            # with concurrent get_or_create. We just report "no entry"
            # and let the eviction sweep in get_or_create reap it.
            return None
        entry.touch()
        return entry

    async def get_or_create(
        self,
        session_id: str,
        create: CreateRuntime,
        hooks: RuntimeHooks,
    ) -> SessionEntry:
        # Fast path: hit and not idle-expired.
        existing = self.get(session_id)
        if existing is not None:
            return existing

        async with self._lock:
            # Double-check under the lock — a concurrent caller for the
            # same id may have just created it.
            existing = self._sessions.get(session_id)
            if existing is not None and not self._is_idle_expired(existing):
                existing.touch()
                return existing

            # Sweep idle entries before applying the cap so we don't
            # evict an active session just because we're full of stale
            # ones we already could've reaped.
            self._sweep_idle_locked()
            if len(self._sessions) >= self._max:
                self._evict_lru_locked()

            runtime_or_coro = create(session_id, hooks)
            if inspect.isawaitable(runtime_or_coro):
                runtime = await runtime_or_coro
            else:
                runtime = runtime_or_coro
            entry = SessionEntry(
                runtime=runtime,
                approve_event=asyncio.Event(),
            )
            self._sessions[session_id] = entry
            return entry

    def remove(self, session_id: str) -> SessionEntry | None:
        return self._sessions.pop(session_id, None)

    def __len__(self) -> int:
        return len(self._sessions)

    def __contains__(self, session_id: object) -> bool:
        return session_id in self._sessions

    # ── internal ────────────────────────────────────────────────────────

    def _is_idle_expired(self, entry: SessionEntry) -> bool:
        if self._ttl <= 0:
            return False
        return (time.monotonic() - entry.last_used) > self._ttl

    def _sweep_idle_locked(self) -> None:
        if self._ttl <= 0:
            return
        cutoff = time.monotonic() - self._ttl
        # Materialise the iteration so we can mutate the dict.
        stale = [k for k, v in self._sessions.items() if v.last_used < cutoff]
        for k in stale:
            self._sessions.pop(k, None)

    def _evict_lru_locked(self) -> None:
        if not self._sessions:
            return
        victim = min(self._sessions.items(), key=lambda kv: kv[1].last_used)[0]
        self._sessions.pop(victim, None)
