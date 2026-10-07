from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Literal, TypeVar

T = TypeVar("T")

CircuitState = Literal["closed", "open", "half-open"]


@dataclass
class CircuitBreakerOptions:
    failure_threshold: int = 5
    success_threshold: int = 2
    cooldown_ms: int = 60_000
    window_ms: int = 60_000


class CircuitOpenError(Exception):
    def __init__(self, circuit_name: str) -> None:
        super().__init__(f"Circuit breaker '{circuit_name}' is open — service unavailable")
        self.circuit_name = circuit_name


class CircuitBreaker:
    def __init__(self, name: str, options: CircuitBreakerOptions | None = None) -> None:
        self.name = name
        self._opts = options or CircuitBreakerOptions()
        self._state: CircuitState = "closed"
        self._failure_timestamps: list[float] = []
        self._half_open_successes = 0
        self._opened_at: float | None = None
        self._lock = asyncio.Lock()

    def get_state(self) -> CircuitState:
        return self._state

    async def call(self, fn: Callable[[], Awaitable[T]]) -> T:
        async with self._lock:
            if self._state == "open":
                if not self._should_attempt_reset():
                    raise CircuitOpenError(self.name)
                self._transition_to("half-open")

        try:
            result = await fn()
            async with self._lock:
                self._on_success()
            return result
        except Exception:
            async with self._lock:
                self._on_failure()
            raise

    def _on_success(self) -> None:
        if self._state == "half-open":
            self._half_open_successes += 1
            if self._half_open_successes >= self._opts.success_threshold:
                self._transition_to("closed")

    def _on_failure(self) -> None:
        now = time.monotonic() * 1000
        self._failure_timestamps.append(now)
        cutoff = now - self._opts.window_ms
        self._failure_timestamps = [t for t in self._failure_timestamps if t >= cutoff]

        if self._state == "half-open":
            self._transition_to("open")
        elif self._state == "closed" and len(self._failure_timestamps) >= self._opts.failure_threshold:
            self._transition_to("open")

    def _should_attempt_reset(self) -> bool:
        if self._opened_at is None:
            return False
        elapsed_ms = (time.monotonic() - self._opened_at) * 1000
        return elapsed_ms >= self._opts.cooldown_ms

    def _transition_to(self, next_state: CircuitState) -> None:
        self._state = next_state
        if next_state == "open":
            self._opened_at = time.monotonic()
            self._half_open_successes = 0
        elif next_state == "closed":
            self._failure_timestamps.clear()
            self._half_open_successes = 0
            self._opened_at = None
        elif next_state == "half-open":
            self._half_open_successes = 0
