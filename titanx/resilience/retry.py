from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field
from typing import Awaitable, Callable, TypeVar

T = TypeVar("T")


@dataclass
class RetryOptions:
    max_attempts: int = 3
    base_delay_ms: int = 100
    max_delay_ms: int = 10_000
    jitter: bool = True
    retry_if: Callable[[Exception], bool] | None = None


def _compute_delay(attempt: int, options: RetryOptions) -> float:
    exponential = options.base_delay_ms * (2 ** attempt)
    capped = min(exponential, options.max_delay_ms)
    delay_ms = random.random() * capped if options.jitter else capped
    return delay_ms / 1000.0


async def with_retry(
    fn: Callable[[], Awaitable[T]],
    options: RetryOptions | None = None,
) -> T:
    opts = options or RetryOptions()
    last_error: Exception | None = None

    for attempt in range(opts.max_attempts):
        try:
            return await fn()
        except Exception as exc:
            last_error = exc
            if opts.retry_if and not opts.retry_if(exc):
                raise
            if attempt < opts.max_attempts - 1:
                await asyncio.sleep(_compute_delay(attempt, opts))

    raise last_error  # type: ignore[misc]
