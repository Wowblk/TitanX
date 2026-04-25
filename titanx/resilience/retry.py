"""Async retry helper with capped exponential Full Jitter backoff.

Backoff schedule
================

For attempt index ``k`` (0-indexed), the maximum delay is
``min(base_delay_ms * 2**k, max_delay_ms)``. With ``jitter=True`` (the
recommended default) the actual delay is sampled uniformly from
``[0, max_delay]`` — this is the AWS Architecture Blog "Full Jitter"
formula. Without jitter, the delay is the exact ``max_delay`` ceiling.

The previous implementation used ``random.random() * capped`` which is
mathematically equivalent to ``random.uniform(0, capped)`` for the
half-open interval; we switch to ``uniform`` for clarity. The
correctness-relevant fix below is the **total-time deadline** and the
**non-retryable exception list**.

Total-time deadline
===================

``max_total_time_ms`` is a budget across ALL attempts including their
sleeps. Without it, a misconfigured ``retry_if`` could keep us looping
for hours past the host's intended timeout — particularly nasty inside
a request handler where the upstream client has already given up. When
the deadline elapses we abort with the latest exception rather than
silently sleeping past it.

Non-retryable exceptions
========================

``asyncio.CancelledError`` and ``KeyboardInterrupt`` are NEVER retried.
Both signal "the host wants this task gone NOW", and treating them as
generic failures defeats the cancellation contract — exactly the kind
of bug that makes ``Ctrl+C`` feel "broken" or makes a gateway client
disconnect leak background work.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, TypeVar

T = TypeVar("T")


@dataclass
class RetryOptions:
    max_attempts: int = 3
    base_delay_ms: int = 100
    max_delay_ms: int = 10_000
    jitter: bool = True
    # Total wall-clock budget across all attempts AND their inter-attempt
    # sleeps. ``None`` keeps the historical "retry until max_attempts no
    # matter how long it takes" behaviour. Recommended in production:
    # set this to a value tighter than the upstream caller's timeout.
    max_total_time_ms: int | None = None
    retry_if: Callable[[Exception], bool] | None = None


def _compute_delay(attempt: int, options: RetryOptions) -> float:
    exponential = options.base_delay_ms * (2 ** attempt)
    capped = min(exponential, options.max_delay_ms)
    if options.jitter:
        delay_ms = random.uniform(0.0, capped)
    else:
        delay_ms = capped
    return delay_ms / 1000.0


async def with_retry(
    fn: Callable[[], Awaitable[T]],
    options: RetryOptions | None = None,
) -> T:
    opts = options or RetryOptions()
    last_error: Exception | None = None
    deadline: float | None = None
    if opts.max_total_time_ms is not None:
        deadline = time.monotonic() + opts.max_total_time_ms / 1000.0

    for attempt in range(opts.max_attempts):
        try:
            return await fn()
        except (asyncio.CancelledError, KeyboardInterrupt):
            # Cooperative cancellation must propagate immediately.
            # Retrying turns ``Ctrl+C`` and gateway-disconnect into
            # silent background work; both break the cancellation
            # contract callers rely on.
            raise
        except Exception as exc:
            last_error = exc
            if opts.retry_if and not opts.retry_if(exc):
                raise
            if attempt >= opts.max_attempts - 1:
                # No more attempts queued.
                break

            delay_s = _compute_delay(attempt, opts)
            # Clamp the sleep so it cannot push us past the deadline.
            # An attempt that ran for 4 s with a 5 s remaining budget
            # should sleep at most ~1 s, not the configured 8 s.
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if delay_s > remaining:
                    delay_s = remaining
            try:
                await asyncio.sleep(delay_s)
            except asyncio.CancelledError:
                raise

    assert last_error is not None  # narrows the Optional for type checkers
    raise last_error
