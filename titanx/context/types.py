from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..types import Message


class CompactionStrategy:
    async def summarize(self, messages: list[Message]) -> str:
        raise NotImplementedError


@dataclass
class CompactionOptions:
    """Tunables for the auto-compaction subsystem.

    ``token_budget`` is the high-water mark — when the most recent LLM turn's
    reported ``input_tokens`` exceeds this number (or when
    ``AgentState.needs_compaction`` is set explicitly), the runtime runs a
    pre-flight compaction *before* the next LLM call so the budget-busting
    payload never leaves the host.

    ``min_recent_messages`` is the floor of "always-keep" tail messages that
    PTL trimming refuses to drop. The most recent assistant + tool-result
    pair is what gives the agent any hope of continuing reasoning, so we
    pin it. The historical mistake was for PTL to chop the *oldest* messages
    and leave the recent giant tool output (the actual culprit) untouched.

    ``max_summary_chars`` is a defensive cap: a buggy ``CompactionStrategy``
    that returns a 100KB "summary" must not be allowed to silently re-
    blow the budget right after we just compacted. When exceeded the
    compaction is treated as a failure and PTL retries.
    """
    token_budget: int
    max_ptl_retries: int = 3
    max_consecutive_failures: int = 3
    min_recent_messages: int = 6
    max_summary_chars: int = 16_000


@dataclass
class CompactionTracking:
    consecutive_failures: int = 0


@dataclass
class CompactionResult:
    summary: str
    messages_retained: int
    ptl_attempts: int
