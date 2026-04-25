from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Literal, TypeVar

T = TypeVar("T")

CircuitState = Literal["closed", "open", "half-open"]

# A state-change observer gets ``(circuit_name, previous_state, new_state)`` and
# is invoked synchronously while the breaker's internal lock is held.
# IMPORTANT: callbacks MUST NOT block, await, or perform IO. To ship events
# to async sinks (audit log, metrics) push to an ``asyncio.Queue`` or schedule
# via ``asyncio.create_task``; do not call ``await`` from inside the callback.
StateChangeCallback = Callable[[str, CircuitState, CircuitState], None]


@dataclass
class CircuitBreakerOptions:
    failure_threshold: int = 5
    success_threshold: int = 2
    cooldown_ms: int = 60_000
    window_ms: int = 60_000
    on_state_change: StateChangeCallback | None = None


class CircuitOpenError(Exception):
    def __init__(self, circuit_name: str) -> None:
        super().__init__(f"Circuit breaker '{circuit_name}' is open — service unavailable")
        self.circuit_name = circuit_name


class CircuitBreaker:
    """Single-probe asynchronous circuit breaker.

    Three-state machine: ``closed`` (normal), ``open`` (fail-fast), and
    ``half-open`` (one trial probe in flight). The crucial design property
    is that **half-open admits exactly one in-flight call** — the historical
    bug fixed in Q9 was that the lock was released between the state check
    and ``await fn()``, so 100 concurrent callers all saw "state has just
    flipped to half-open" and stampeded N concurrent probes against the
    very service we'd just declared broken.

    The fix: under the lock we perform two operations atomically — read
    the state and (if entering half-open or already half-open) **claim**
    the single probe slot via ``_half_open_probe_in_flight``. Any caller
    that finds the slot already taken raises ``CircuitOpenError`` straight
    away. The slot is released (also under lock) after the call returns,
    success or failure, so the next eligible caller can take the next
    probe in the success-counting sequence.

    Threading: this class assumes a single asyncio event loop. The
    ``asyncio.Lock`` serialises critical sections within the loop; it is
    NOT safe for use across multiple OS threads.
    """

    def __init__(self, name: str, options: CircuitBreakerOptions | None = None) -> None:
        self.name = name
        self._opts = options or CircuitBreakerOptions()
        self._state: CircuitState = "closed"
        self._failure_timestamps: list[float] = []
        self._half_open_successes = 0
        # Single-slot probe gate: True iff exactly one probe is currently
        # mid-flight in the half-open state. This is the keystone of the
        # thundering-herd fix — see class docstring.
        self._half_open_probe_in_flight = False
        self._opened_at: float | None = None
        self._lock = asyncio.Lock()
        self._on_state_change = self._opts.on_state_change

    def get_state(self) -> CircuitState:
        return self._state

    async def call(self, fn: Callable[[], Awaitable[T]]) -> T:
        is_probe = await self._acquire_slot()

        try:
            result = await fn()
        except Exception:
            async with self._lock:
                self._record_failure(was_probe=is_probe)
            raise
        else:
            async with self._lock:
                self._record_success(was_probe=is_probe)
            return result

    async def _acquire_slot(self) -> bool:
        """Atomically decide whether the call may proceed.

        Returns ``True`` if the call is the half-open probe (it must
        release the probe slot after ``fn()`` resolves). Returns ``False``
        if the call is just a normal closed-state pass-through. Raises
        ``CircuitOpenError`` if the breaker is open or if half-open's
        single probe slot is already taken.
        """
        async with self._lock:
            state = self._state
            if state == "open":
                if not self._should_attempt_reset():
                    raise CircuitOpenError(self.name)
                # Cooldown elapsed — promote to half-open and immediately
                # claim the probe slot. Doing this under the lock is what
                # prevents the herd: any call that arrives after this point
                # sees half-open + slot=taken and is rejected below.
                self._transition_to("half-open")
                self._half_open_probe_in_flight = True
                return True

            if state == "half-open":
                if self._half_open_probe_in_flight:
                    # A probe is already running. Concurrent callers must
                    # NOT execute fn() — that would defeat the entire point
                    # of half-open as a single-probe state. Fail fast; the
                    # caller's retry layer can re-attempt later, and if the
                    # probe succeeds the breaker will close before that.
                    raise CircuitOpenError(self.name)
                # Slot free → take it. This handles the case where a previous
                # probe completed successfully but didn't yet meet
                # success_threshold; the next eligible call becomes the
                # next probe in the success-counting sequence.
                self._half_open_probe_in_flight = True
                return True

            # state == "closed" — fully concurrent, no probe semantics.
            return False

    # ── Outcome handlers (always invoked under self._lock) ──────────────────

    def _record_success(self, *, was_probe: bool) -> None:
        if was_probe:
            self._half_open_probe_in_flight = False
            # Only count the success toward the threshold if we are still
            # in half-open. If a *concurrent* probe failed and slammed us
            # back to open in between, this success is stale and must NOT
            # silently accumulate against the new lifecycle.
            if self._state == "half-open":
                self._half_open_successes += 1
                if self._half_open_successes >= self._opts.success_threshold:
                    self._transition_to("closed")
        # In closed state we don't track anything special on success.
        # Failure timestamps inside the rolling window will age out on
        # the next failure or get cleared if/when we transition to closed.

    def _record_failure(self, *, was_probe: bool) -> None:
        now_ms = time.monotonic() * 1000
        self._failure_timestamps.append(now_ms)
        cutoff = now_ms - self._opts.window_ms
        self._failure_timestamps = [t for t in self._failure_timestamps if t >= cutoff]

        if was_probe:
            self._half_open_probe_in_flight = False

        if self._state == "half-open":
            # Any failure during the half-open probe re-opens immediately.
            # Probe semantics: one strike re-trips. The success-counter is
            # cleared in ``_transition_to("open")``.
            self._transition_to("open")
        elif self._state == "closed" and len(self._failure_timestamps) >= self._opts.failure_threshold:
            self._transition_to("open")

    def _should_attempt_reset(self) -> bool:
        # Caller invariant: only meaningful in the open state. We don't
        # assert because the caller's logic already guards on state, but
        # defensively guard against ``_opened_at`` being None.
        if self._opened_at is None:
            return False
        elapsed_ms = (time.monotonic() - self._opened_at) * 1000
        return elapsed_ms >= self._opts.cooldown_ms

    def _transition_to(self, next_state: CircuitState) -> None:
        if next_state == self._state:
            return
        previous = self._state
        self._state = next_state

        if next_state == "open":
            self._opened_at = time.monotonic()
            self._half_open_successes = 0
            # Clearing the in-flight flag on transition to open is
            # important when this transition happens from half-open
            # because of a probe failure — the probe slot is being
            # released anyway, but if we don't clear it here a future
            # cooldown→half-open transition might still see it set
            # from a stale state.
            self._half_open_probe_in_flight = False
        elif next_state == "closed":
            self._failure_timestamps.clear()
            self._half_open_successes = 0
            self._opened_at = None
            self._half_open_probe_in_flight = False
        elif next_state == "half-open":
            self._half_open_successes = 0
            # Probe slot is set by ``_acquire_slot`` immediately after
            # this transition — keeping it conceptually paired with the
            # entry instead of pre-clearing it here.

        if self._on_state_change is not None:
            # Synchronous callback under the lock. Documented contract:
            # callback must not block. See ``StateChangeCallback``.
            try:
                self._on_state_change(self.name, previous, next_state)
            except Exception:
                # Swallow to keep breaker invariants intact; observability
                # bugs must never break the breaker itself.
                pass
