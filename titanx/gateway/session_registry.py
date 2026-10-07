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


class SessionCapacityError(RuntimeError):
    """Raised when every bounded-registry slot is actively in use."""


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
        # Teardown tasks scheduled by the synchronous ``remove`` path. Held so
        # the event loop cannot garbage-collect them mid-flight.
        self._pending_teardowns: set[asyncio.Task] = set()

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

        victims: list[SessionEntry] = []
        try:
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
                victims.extend(self._sweep_idle_locked())
                if len(self._sessions) >= self._max:
                    victim = self._evict_lru_locked()
                    if victim is None:
                        raise SessionCapacityError(
                            "session capacity reached and all sessions are active"
                        )
                    victims.append(victim)

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
        except BaseException:
            # Sweep/eviction may already have detached victims from the map
            # before creation failed; tear them down here or their sandbox
            # sessions and store rows leak. The ``async with`` released the
            # lock on the way out, so this runs outside it like the happy path.
            for victim in victims:
                await self._teardown_entry(victim)
            raise
        # Tear victims down *after* releasing the registry lock: teardown is
        # arbitrary host code (sandbox destroy, store deletes) and must never
        # run while the registry is serialised against creation.
        for victim in victims:
            await self._teardown_entry(victim)
        return entry

    def remove(self, session_id: str) -> SessionEntry | None:
        entry = self._sessions.pop(session_id, None)
        if entry is not None:
            self._schedule_teardown(entry)
        return entry

    async def aclose(self) -> None:
        """Tear down every live session. Safe to call multiple times."""
        async with self._lock:
            entries = list(self._sessions.values())
            self._sessions.clear()
        for entry in entries:
            await self._teardown_entry(entry)
        if self._pending_teardowns:
            await asyncio.gather(*list(self._pending_teardowns), return_exceptions=True)

    def __len__(self) -> int:
        return len(self._sessions)

    def __contains__(self, session_id: object) -> bool:
        return session_id in self._sessions

    # ── internal ────────────────────────────────────────────────────────

    async def _teardown_entry(self, entry: SessionEntry) -> None:
        """Run the runtime's async teardown if it exposes one.

        ``getattr`` keeps arbitrary host runtimes (including fakes and
        non-sandbox ToolRuntimes) compatible.
        """
        closer = getattr(entry.runtime, "aclose", None)
        if closer is None:
            return
        try:
            result = closer()
            if inspect.isawaitable(result):
                await result
        except Exception:
            # Teardown is best-effort: a failing session must not break
            # eviction or shutdown for its siblings.
            pass

    def _schedule_teardown(self, entry: SessionEntry) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running loop (e.g. a host calling ``remove`` synchronously
            # outside async context): nothing we can await here.
            return
        task = loop.create_task(self._teardown_entry(entry))
        self._pending_teardowns.add(task)
        task.add_done_callback(self._pending_teardowns.discard)

    def _is_idle_expired(self, entry: SessionEntry) -> bool:
        if self._is_protected(entry):
            return False
        if self._ttl <= 0:
            return False
        return (time.monotonic() - entry.last_used) > self._ttl

    @staticmethod
    def _is_protected(entry: SessionEntry) -> bool:
        """Return whether eviction could strand an active safety decision."""
        state = getattr(entry.runtime, "state", None)
        return (
            entry.lock.locked()
            or getattr(state, "pending_approval", None) is not None
            or entry.approval_resolution is not None
            or entry.approve_event.is_set()
        )

    def _sweep_idle_locked(self) -> list[SessionEntry]:
        if self._ttl <= 0:
            return []
        # Materialise the iteration so we can mutate the dict.
        stale = [
            (key, entry)
            for key, entry in self._sessions.items()
            if self._is_idle_expired(entry)
        ]
        for key, _ in stale:
            self._sessions.pop(key, None)
        return [entry for _, entry in stale]

    def _evict_lru_locked(self) -> SessionEntry | None:
        candidates = [
            item
            for item in self._sessions.items()
            if not self._is_protected(item[1])
        ]
        if not candidates:
            return None
        victim_key, victim = min(candidates, key=lambda item: item[1].last_used)
        self._sessions.pop(victim_key, None)
        return victim
