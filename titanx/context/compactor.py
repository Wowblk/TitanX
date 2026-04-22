from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from ..types import AgentState, Message, UserMessage
from .types import CompactionOptions, CompactionResult, CompactionStrategy, CompactionTracking

PTL_TRIM_RATIO = 0.2


def _non_system(messages: list[Message]) -> list[Message]:
    return [m for m in messages if m.role != "system"]


def _trim_oldest(messages: list[Message]) -> list[Message] | None:
    trim_count = max(1, int(len(messages) * PTL_TRIM_RATIO))
    if len(messages) <= trim_count:
        return None
    return messages[trim_count:]


def _summary_message(summary: str) -> UserMessage:
    return UserMessage(role="user", content=f"[Conversation summary]\n{summary}", id=str(uuid4()))


@dataclass
class CompactionOutcome:
    was_compacted: bool
    tracking: CompactionTracking
    result: CompactionResult | None = None


async def auto_compact_if_needed(
    state: AgentState,
    strategy: CompactionStrategy,
    options: CompactionOptions,
    tracking: CompactionTracking,
) -> CompactionOutcome:
    if tracking.consecutive_failures >= options.max_consecutive_failures:
        return CompactionOutcome(was_compacted=False, tracking=tracking)

    if not state.needs_compaction and state.total_input_tokens < options.token_budget:
        return CompactionOutcome(was_compacted=False, tracking=tracking)

    candidates = _non_system(state.messages)
    summary: str | None = None
    ptl_attempts = 0

    while summary is None:
        try:
            summary = await strategy.summarize(candidates)
        except Exception:
            if ptl_attempts >= options.max_ptl_retries:
                return CompactionOutcome(
                    was_compacted=False,
                    tracking=CompactionTracking(consecutive_failures=tracking.consecutive_failures + 1),
                )
            trimmed = _trim_oldest(candidates)
            if trimmed is None:
                return CompactionOutcome(
                    was_compacted=False,
                    tracking=CompactionTracking(consecutive_failures=tracking.consecutive_failures + 1),
                )
            candidates = trimmed
            ptl_attempts += 1

    system_messages = [m for m in state.messages if m.role == "system"]
    state.messages = [*system_messages, _summary_message(summary)]
    state.total_input_tokens = 0
    state.needs_compaction = False

    return CompactionOutcome(
        was_compacted=True,
        tracking=CompactionTracking(consecutive_failures=0),
        result=CompactionResult(
            summary=summary,
            messages_retained=len(state.messages),
            ptl_attempts=ptl_attempts,
        ),
    )
