from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from math import ceil
from typing import Literal
from uuid import uuid4

from ..types import AgentState, AssistantMessage, Message, SystemMessage, ToolMessage
from .types import (
    CompactionInput,
    CompactionOptions,
    CompactionOutput,
    CompactionResult,
    CompactionStrategy,
    CompactionTracking,
    RuntimeStateSnapshot,
)

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


def _estimate_tokens(text: str, options: CompactionOptions) -> int:
    return ceil(len(text) / max(options.avg_chars_per_token, 1.0))


def estimate_message_tokens(message: Message, options: CompactionOptions) -> int:
    content = getattr(message, "content", "") or ""
    extra = ""
    if isinstance(message, AssistantMessage) and message.tool_calls:
        extra = json.dumps([tc.__dict__ for tc in message.tool_calls], sort_keys=True)
    return _estimate_tokens(content + extra, options)


def estimate_context_tokens(messages: list[Message], options: CompactionOptions) -> int:
    return sum(estimate_message_tokens(m, options) for m in messages)


def effective_compaction_budget(options: CompactionOptions) -> int:
    budget = options.token_budget
    if options.model_context_window is not None:
        reserved_output = min(
            options.model_max_output_tokens or options.reserved_output_tokens,
            options.reserved_output_tokens,
        )
        derived = max(1, options.model_context_window - reserved_output - options.safety_buffer)
        budget = min(budget, derived)
    return max(1, budget)


def expected_turn_growth(options: CompactionOptions) -> int:
    reserved_output = min(
        options.model_max_output_tokens or options.reserved_output_tokens,
        options.reserved_output_tokens,
    )
    return reserved_output + options.tool_growth_estimate


@dataclass
class MicroCompactionResult:
    messages: list[Message]
    messages_compacted: int
    tokens_saved: int


def _micro_placeholder(message: ToolMessage, tokens: int) -> str:
    status = "error" if message.is_error else "ok"
    return (
        "[Tool result cleared by micro-compaction: "
        f"{message.tool_name}, approx {tokens} tokens, status={status}.]"
    )


def micro_compact_messages(
    messages: list[Message],
    options: CompactionOptions,
) -> MicroCompactionResult:
    if not options.enable_micro_compaction:
        return MicroCompactionResult(list(messages), 0, 0)

    tool_messages = [m for m in messages if isinstance(m, ToolMessage)]
    keep_count = max(options.micro_keep_recent_tool_results, 0)
    keep_ids = {m.id for m in tool_messages[-keep_count:]} if keep_count else set()
    compacted = 0
    saved = 0
    result: list[Message] = []

    for message in messages:
        if (
            isinstance(message, ToolMessage)
            and message.id not in keep_ids
            and len(message.content or "") >= options.micro_min_content_chars
        ):
            old_tokens = estimate_message_tokens(message, options)
            placeholder = _micro_placeholder(message, old_tokens)
            replacement = ToolMessage(
                role="tool",
                tool_name=message.tool_name,
                tool_call_id=message.tool_call_id,
                content=placeholder,
                id=message.id,
                is_error=message.is_error,
            )
            new_tokens = estimate_message_tokens(replacement, options)
            compacted += 1
            saved += max(0, old_tokens - new_tokens)
            result.append(replacement)
        else:
            result.append(message)

    return MicroCompactionResult(result, compacted, saved)


def _format_runtime_snapshot(snapshot: RuntimeStateSnapshot | None) -> str:
    if snapshot is None:
        return ""
    data = {k: v for k, v in asdict(snapshot).items() if v not in (None, [], {})}
    if not data:
        return ""
    return "[Runtime state snapshot]\n" + json.dumps(data, sort_keys=True)


def _summary_message(
    summary: str,
    runtime_state: RuntimeStateSnapshot | None = None,
    *,
    reason: str = "auto",
) -> SystemMessage:
    """Inject the post-compaction summary as a SystemMessage.

    Earlier code wrapped the summary in a UserMessage, which made the model
    treat the body as a fresh user instruction (with all the hijack risk
    that implies). The summary is *background context* the agent should
    remember; SystemMessage is the role that semantically conveys "this is
    framing, not a directive". The framing prefix is also explicit so a
    well-trained model and a human reading the log can distinguish a
    compaction artefact from the real system prompt.
    """
    snapshot = _format_runtime_snapshot(runtime_state)
    parts = [
        "[Conversation summary so far]",
        f"Compaction reason: {reason}",
    ]
    if snapshot:
        parts.append(snapshot)
    parts.append(summary)
    return SystemMessage(
        role="system",
        content="\n".join(parts),
        id=str(uuid4()),
    )


@dataclass
class CompactionOutcome:
    was_compacted: bool
    tracking: CompactionTracking
    result: CompactionResult | None = None
    failure_reason: str | None = None
    # Set when ``tracking.consecutive_failures`` has reached
    # ``options.max_consecutive_failures``. Runtime treats this as a terminal
    # condition and aborts the loop with an explicit event — see Q8 fix in
    # ``runtime.py``.
    exhausted: bool = False


@dataclass
class CompactionDecision:
    should_compact: bool
    trigger_reason: str
    pre_tokens: int
    projected_tokens: int
    budget: int


def _compaction_decision(
    state: AgentState,
    options: CompactionOptions,
    *,
    reason: Literal["auto", "manual", "reactive", "ptl_fallback"] = "auto",
) -> CompactionDecision:
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
        pre_tokens = estimate_context_tokens(state.messages, options)
        budget = effective_compaction_budget(options)
        return CompactionDecision(True, reason, pre_tokens, pre_tokens, budget)
    pre_tokens = estimate_context_tokens(state.messages, options)
    measured_tokens = max(pre_tokens, state.last_input_tokens)
    projected_tokens = measured_tokens + expected_turn_growth(options)
    budget = effective_compaction_budget(options)
    if projected_tokens > budget:
        return CompactionDecision(
            True,
            "projected_context_exceeds_budget",
            pre_tokens,
            projected_tokens,
            budget,
        )
    return CompactionDecision(False, "", pre_tokens, projected_tokens, budget)


def _should_compact(state: AgentState, options: CompactionOptions) -> bool:
    return _compaction_decision(state, options).should_compact


async def _run_strategy(
    strategy: CompactionStrategy,
    messages: list[Message],
    runtime_state: RuntimeStateSnapshot | None,
    budget: int,
    reason: Literal["auto", "manual", "reactive", "ptl_fallback"],
    custom_instructions: str | None,
    options: CompactionOptions,
) -> str | None:
    compact = getattr(strategy, "compact", None)
    if callable(compact):
        output = await compact(CompactionInput(
            messages=messages,
            runtime_state=runtime_state or RuntimeStateSnapshot(),
            token_budget=budget,
            custom_instructions=custom_instructions,
            reason=reason,
        ))
        if isinstance(output, CompactionOutput):
            return output.summary
        return getattr(output, "summary", None)
    return await strategy.summarize(messages)


async def auto_compact_if_needed(
    state: AgentState,
    strategy: CompactionStrategy | None,
    options: CompactionOptions,
    tracking: CompactionTracking,
    *,
    reason: Literal["auto", "manual", "reactive", "ptl_fallback"] = "auto",
    runtime_state: RuntimeStateSnapshot | None = None,
    custom_instructions: str | None = None,
) -> CompactionOutcome:
    started = time.perf_counter()
    if tracking.consecutive_failures >= options.max_consecutive_failures:
        # Already in a permanently-degraded state. The runtime is expected
        # to read ``exhausted`` and stop the loop; we never auto-recover
        # because retrying a strategy that has failed N times in a row is
        # almost always going to keep failing — the right move is to break
        # the loop and let the host operator decide.
        return CompactionOutcome(was_compacted=False, tracking=tracking, exhausted=True)

    decision = _compaction_decision(state, options, reason=reason)
    if not decision.should_compact:
        return CompactionOutcome(was_compacted=False, tracking=tracking)

    micro = micro_compact_messages(state.messages, options)
    if micro.messages_compacted:
        state.messages = micro.messages
    post_micro_tokens = estimate_context_tokens(state.messages, options)
    post_micro_projected = post_micro_tokens + expected_turn_growth(options)

    if micro.messages_compacted and post_micro_projected <= decision.budget:
        state.last_input_tokens = 0
        state.needs_compaction = False
        duration_ms = (time.perf_counter() - started) * 1000
        return CompactionOutcome(
            was_compacted=True,
            tracking=CompactionTracking(consecutive_failures=0),
            result=CompactionResult(
                summary=(
                    f"Micro-compaction cleared {micro.messages_compacted} "
                    f"old tool result(s), saving ~{micro.tokens_saved} tokens."
                ),
                messages_retained=len(state.messages),
                ptl_attempts=0,
                reason=reason,
                phase="micro",
                trigger_reason=decision.trigger_reason,
                pre_compact_tokens=decision.pre_tokens,
                post_compact_tokens=post_micro_tokens,
                projected_tokens=post_micro_projected,
                budget=decision.budget,
                messages_compacted=micro.messages_compacted,
                messages_kept=len(state.messages),
                summary_tokens=0,
                strategy_name="micro",
                duration_ms=duration_ms,
            ),
        )

    if strategy is None:
        failure = "micro_compaction_insufficient_and_no_summary_strategy"
        return CompactionOutcome(
            was_compacted=False,
            tracking=CompactionTracking(consecutive_failures=tracking.consecutive_failures + 1),
            failure_reason=failure,
        )

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
            failure_reason="no_eligible_messages",
        )

    summary: str | None = None
    ptl_attempts = 0
    candidates = list(eligible)
    current_max_summary_chars = options.max_summary_chars

    while summary is None:
        try:
            produced = await _run_strategy(
                strategy,
                candidates,
                runtime_state,
                decision.budget,
                reason if ptl_attempts == 0 else "ptl_fallback",
                custom_instructions,
                options,
            )
        except Exception:
            produced = None
        if produced and len(produced) <= current_max_summary_chars:
            tentative = [
                *_system_messages(state.messages),
                _summary_message(produced, runtime_state, reason=reason),
                *pinned_tail,
            ]
            tentative_tokens = estimate_context_tokens(tentative, options)
            if tentative_tokens + expected_turn_growth(options) <= decision.budget:
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
                failure_reason="ptl_retries_exhausted",
            )

        # First retry: drop the single largest message — usually the bloated
        # tool output that triggered the budget breach. Subsequent retries
        # fall back to the oldest-20% chop. This is the inverse of the
        # historical behaviour, which cut the head and left the bomb in.
        if ptl_attempts == 0:
            next_candidates = _drop_largest(candidates)
        elif ptl_attempts == 1:
            next_candidates = _trim_oldest(candidates)
        elif len(pinned_tail) > 1:
            pinned_tail = pinned_tail[1:]
            next_candidates = candidates
        else:
            current_max_summary_chars = max(1_000, int(current_max_summary_chars * 0.5))
            next_candidates = _trim_oldest(candidates)
        if next_candidates is None or not next_candidates:
            return CompactionOutcome(
                was_compacted=False,
                tracking=CompactionTracking(
                    consecutive_failures=tracking.consecutive_failures + 1,
                ),
                failure_reason="no_messages_after_ptl_trim",
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
        _summary_message(summary, runtime_state, reason=reason),
        *pinned_tail,
    ]

    # Reset the trigger metric — the next LLM turn will repopulate it with
    # the provider's authoritative count for the *new* (post-compaction)
    # prompt. Crucially we do NOT touch ``total_input_tokens`` /
    # ``total_output_tokens``: those are cumulative cost-tracking counters
    # that must keep growing across the whole session.
    state.last_input_tokens = 0
    state.needs_compaction = False

    post_tokens = estimate_context_tokens(state.messages, options)
    duration_ms = (time.perf_counter() - started) * 1000
    strategy_name = getattr(strategy, "name", strategy.__class__.__name__)
    return CompactionOutcome(
        was_compacted=True,
        tracking=CompactionTracking(consecutive_failures=0),
        result=CompactionResult(
            summary=summary,
            messages_retained=len(state.messages),
            ptl_attempts=ptl_attempts,
            reason=reason,
            phase="summary",
            trigger_reason=decision.trigger_reason,
            pre_compact_tokens=decision.pre_tokens,
            post_compact_tokens=post_tokens,
            projected_tokens=post_tokens + expected_turn_growth(options),
            budget=decision.budget,
            messages_compacted=len(eligible) + micro.messages_compacted,
            messages_kept=len(state.messages),
            summary_tokens=_estimate_tokens(summary, options),
            strategy_name=str(strategy_name),
            duration_ms=duration_ms,
        ),
    )
