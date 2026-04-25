from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from ..types import AgentState, AssistantMessage, Message, SystemMessage, ToolMessage
from .types import CompactionOptions, CompactionResult, CompactionStrategy, CompactionTracking

# Fraction of *eligible* (= non-system, non-pinned-tail) messages dropped per
# PTL retry when the "drop largest middle message" heuristic doesn't free
# enough budget. 0.2 keeps the trimmer gentle enough that on a 50-message
# conversation we step ~10/8/6/5 messages, not a guillotine.
PTL_TRIM_RATIO = 0.2


def _system_messages(messages: list[Message]) -> list[Message]:
    return [m for m in messages if m.role == "system"]


def _split_pinned_tail(
    messages: list[Message],
    *,
    min_recent: int,
) -> tuple[list[Message], list[Message]]:
    """Partition non-system messages into (eligible_to_trim, must_keep_tail).

    The tail is the floor of "most recent N" messages PTL must never touch.
    We also expand the tail upwards to cover any in-flight tool-call group:
    if the K-th-from-end message is a ``ToolMessage``, walk back until we hit
    its parent ``AssistantMessage`` (the one with ``tool_calls``). Splitting
    a tool_calls→tool_result pair across the trim boundary would leave an
    orphan tool_result that no LLM provider will accept (HTTP 400 on the
    next turn). This is the same invariant the Q2 fix protects in the
    approval flow.
    """
    body = [m for m in messages if m.role != "system"]
    if len(body) <= min_recent:
        return [], body

    cut = len(body) - min_recent
    while cut > 0 and isinstance(body[cut], ToolMessage):
        cut -= 1
    if cut > 0 and isinstance(body[cut - 1], AssistantMessage):
        ahead = body[cut - 1]
        if ahead.tool_calls:
            cut -= 1
    return body[:cut], body[cut:]


def _drop_largest(eligible: list[Message]) -> list[Message] | None:
    """Drop the single largest eligible message by content length.

    Real-world context blowouts almost always come from one bloated tool
    output — a 60KB JSON dump, an entire scraped HTML page, etc. Removing
    that one message is *far* more effective than the historical PTL
    behaviour of chopping the conversation's head, which threw away the
    user's original goal and system framing while leaving the bloated
    middle untouched.
    """
    if not eligible:
        return None
    biggest_idx = max(
        range(len(eligible)),
        key=lambda i: len(getattr(eligible[i], "content", "") or ""),
    )
    return [m for i, m in enumerate(eligible) if i != biggest_idx]


def _trim_oldest(eligible: list[Message]) -> list[Message] | None:
    """Fallback when no single message dominates: chop the oldest 20%.

    Only invoked after ``_drop_largest`` has already pulled the obvious
    culprit. Operates strictly on the eligible (non-pinned) span so user
    framing in messages 0..1 still survives via _split_pinned_tail's tail
    slot if min_recent_messages is large enough — this is a knob the host
    can tune.
    """
    trim_count = max(1, int(len(eligible) * PTL_TRIM_RATIO))
    if len(eligible) <= trim_count:
        return None
    return eligible[trim_count:]


def _summary_message(summary: str) -> SystemMessage:
    """Inject the post-compaction summary as a SystemMessage.

    Earlier code wrapped the summary in a UserMessage, which made the model
    treat the body as a fresh user instruction (with all the hijack risk
    that implies). The summary is *background context* the agent should
    remember; SystemMessage is the role that semantically conveys "this is
    framing, not a directive". The framing prefix is also explicit so a
    well-trained model and a human reading the log can distinguish a
    compaction artefact from the real system prompt.
    """
    return SystemMessage(
        role="system",
        content=f"[Conversation summary so far]\n{summary}",
        id=str(uuid4()),
    )


@dataclass
class CompactionOutcome:
    was_compacted: bool
    tracking: CompactionTracking
    result: CompactionResult | None = None
    # Set when ``tracking.consecutive_failures`` has reached
    # ``options.max_consecutive_failures``. Runtime treats this as a terminal
    # condition and aborts the loop with an explicit event — see Q8 fix in
    # ``runtime.py``.
    exhausted: bool = False


def _should_compact(state: AgentState, options: CompactionOptions) -> bool:
    """Trigger gate.

    Compaction fires when *either* the host has explicitly requested it
    (``state.needs_compaction``) or the most recent LLM turn's prompt size
    crossed the budget. ``last_input_tokens`` is the **canonical** signal
    here — see ``AgentState.last_input_tokens`` for why we deliberately
    stopped using ``total_input_tokens``: the latter accumulates across
    turns and double-counts the prior history that's already inside each
    turn's reported ``input_tokens``.
    """
    if state.needs_compaction:
        return True
    return state.last_input_tokens >= options.token_budget


async def auto_compact_if_needed(
    state: AgentState,
    strategy: CompactionStrategy,
    options: CompactionOptions,
    tracking: CompactionTracking,
) -> CompactionOutcome:
    if tracking.consecutive_failures >= options.max_consecutive_failures:
        # Already in a permanently-degraded state. The runtime is expected
        # to read ``exhausted`` and stop the loop; we never auto-recover
        # because retrying a strategy that has failed N times in a row is
        # almost always going to keep failing — the right move is to break
        # the loop and let the host operator decide.
        return CompactionOutcome(was_compacted=False, tracking=tracking, exhausted=True)

    if not _should_compact(state, options):
        return CompactionOutcome(was_compacted=False, tracking=tracking)

    eligible, pinned_tail = _split_pinned_tail(
        state.messages, min_recent=options.min_recent_messages,
    )

    if not eligible:
        # Nothing the trimmer can legally remove — every message is either
        # a system message or part of the pinned tail. Treat as failure so
        # the consecutive-failure ceiling can eventually break us out.
        return CompactionOutcome(
            was_compacted=False,
            tracking=CompactionTracking(consecutive_failures=tracking.consecutive_failures + 1),
        )

    summary: str | None = None
    ptl_attempts = 0
    candidates = list(eligible)

    while summary is None:
        try:
            produced = await strategy.summarize(candidates)
        except Exception:
            produced = None
        if produced and len(produced) <= options.max_summary_chars:
            summary = produced
            break

        # Either summarisation raised, or it returned a string so large that
        # ingesting it would re-blow the budget we're trying to enforce.
        # Both cases retry via PTL trimming.
        if ptl_attempts >= options.max_ptl_retries:
            return CompactionOutcome(
                was_compacted=False,
                tracking=CompactionTracking(
                    consecutive_failures=tracking.consecutive_failures + 1,
                ),
            )

        # First retry: drop the single largest message — usually the bloated
        # tool output that triggered the budget breach. Subsequent retries
        # fall back to the oldest-20% chop. This is the inverse of the
        # historical behaviour, which cut the head and left the bomb in.
        next_candidates = (
            _drop_largest(candidates) if ptl_attempts == 0
            else _trim_oldest(candidates)
        )
        if next_candidates is None or not next_candidates:
            return CompactionOutcome(
                was_compacted=False,
                tracking=CompactionTracking(
                    consecutive_failures=tracking.consecutive_failures + 1,
                ),
            )
        candidates = next_candidates
        ptl_attempts += 1

    # Successful compaction: rebuild messages as
    # [original system prompts] + [summary] + [pinned recent tail]. Pinning
    # the tail preserves the in-flight reasoning the agent needs to make
    # forward progress on the user's current task — historically this was
    # nuked along with everything else, which often broke mid-tool-call
    # message chains.
    state.messages = [
        *_system_messages(state.messages),
        _summary_message(summary),
        *pinned_tail,
    ]

    # Reset the trigger metric — the next LLM turn will repopulate it with
    # the provider's authoritative count for the *new* (post-compaction)
    # prompt. Crucially we do NOT touch ``total_input_tokens`` /
    # ``total_output_tokens``: those are cumulative cost-tracking counters
    # that must keep growing across the whole session.
    state.last_input_tokens = 0
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
