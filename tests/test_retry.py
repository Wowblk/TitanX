"""Retry helper invariants (Q16).

- ``asyncio.CancelledError`` is never retried.
- ``KeyboardInterrupt`` is never retried.
- ``max_total_time_ms`` caps total wall-clock across attempts AND sleeps.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from titanx.resilience.retry import RetryOptions, with_retry


class TestNonRetryable:
    async def test_cancelled_error_not_retried(self) -> None:
        calls = 0

        async def fn() -> None:
            nonlocal calls
            calls += 1
            raise asyncio.CancelledError()

        with pytest.raises(asyncio.CancelledError):
            await with_retry(fn, RetryOptions(max_attempts=5))
        # Exactly one attempt: cancellation must propagate immediately
        # so callers (Ctrl+C, gateway-disconnect) get the contract
        # they expect.
        assert calls == 1

    async def test_keyboard_interrupt_not_retried(self) -> None:
        calls = 0

        async def fn() -> None:
            nonlocal calls
            calls += 1
            raise KeyboardInterrupt()

        with pytest.raises(KeyboardInterrupt):
            await with_retry(fn, RetryOptions(max_attempts=5))
        assert calls == 1


class TestTotalDeadline:
    async def test_max_total_time_ms_caps_wall_clock(self) -> None:
        # Without the deadline these settings would spin for >1s on
        # base*2^attempt sleep. The 300ms cap forces the helper to
        # bail out early with the latest error.
        calls = 0

        async def always_fails() -> None:
            nonlocal calls
            calls += 1
            raise RuntimeError("nope")

        started = time.monotonic()
        with pytest.raises(RuntimeError):
            await with_retry(
                always_fails,
                RetryOptions(
                    max_attempts=20,
                    base_delay_ms=50,
                    max_delay_ms=200,
                    max_total_time_ms=300,
                ),
            )
        elapsed = time.monotonic() - started
        # Generous upper bound to keep the test stable under load —
        # the assertion is "we did NOT spin indefinitely", not "we
        # finished by exactly 300ms".
        assert elapsed < 1.0
        # And the helper must have actually attempted at least once
        # before bailing out.
        assert calls >= 1


class TestRetryIfPredicate:
    async def test_retry_if_returning_false_short_circuits(self) -> None:
        calls = 0

        class _Fatal(Exception):
            pass

        async def fn() -> None:
            nonlocal calls
            calls += 1
            raise _Fatal("non-retryable")

        with pytest.raises(_Fatal):
            await with_retry(
                fn,
                RetryOptions(max_attempts=5, retry_if=lambda exc: not isinstance(exc, _Fatal)),
            )
        assert calls == 1
