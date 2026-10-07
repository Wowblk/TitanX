from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
import asyncio
from time import monotonic
from typing import Literal

from ..types import AgentConfig, AgentState, AssistantMessage, Message, SystemMessage, ToolMessage
from .tokens import estimate_input_tokens
from .tasks import model_messages
from .store import ContextStore
from .summary import StructuredSummary, SummaryValidationError
from .transcript import SUMMARY_PREFIX, Transcript, is_summary as _is_summary
from .types import CompactionOptions, CompactionResult, CompactionStrategy, CompactionTracking

PTL_TRIM_RATIO = 0.2
BlockedReason = Literal["context_budget_exceeded", "token_estimation_failed", "context_storage_failed"]


def _message_groups(messages: list[Message]) -> list[list[Message]]:
    """Keep an assistant tool declaration and its consecutive results atomic."""
    groups: list[list[Message]] = []
    for message in messages:
        if (
            isinstance(message, ToolMessage) and groups
            and isinstance(groups[-1][0], AssistantMessage)
            and groups[-1][0].tool_calls
        ):
            groups[-1].append(message)
        else:
            groups.append([message])
    return groups


def _flatten(groups: list[list[Message]]) -> list[Message]:
    return [message for group in groups for message in group]


def _split_pinned_tail(messages: list[Message], *, min_recent: int) -> tuple[list[Message], list[Message]]:
    groups = _message_groups([m for m in messages if m.role != "system"])
    cut, retained = len(groups), 0
    while cut > 0 and retained < min_recent:
        cut -= 1
        retained += len(groups[cut])
    return _flatten(groups[:cut]), _flatten(groups[cut:])


def _drop_largest(eligible: list[Message]) -> list[Message]:
    groups = _message_groups(eligible)
    if not groups:
        return []
    # Include call arguments, not only content. Never orphan a tool result.
    biggest = max(range(len(groups)), key=lambda i: estimate_input_tokens(None, groups[i]))
    return _flatten([group for i, group in enumerate(groups) if i != biggest])


def _trim_oldest(eligible: list[Message]) -> list[Message]:
    groups = _message_groups(eligible)
    trim_count = max(1, int(len(groups) * PTL_TRIM_RATIO))
    return _flatten(groups[trim_count:])


@dataclass
class CompactionOutcome:
    was_compacted: bool
    tracking: CompactionTracking
    result: CompactionResult | None = None
    exhausted: bool = False
    estimated_input_tokens: int | None = None
    blocked_reason: BlockedReason | None = None
    failure_reason: str | None = None
    duration_ms: float = 0.0
    summary_input_tokens: int = 0
    summary_output_tokens: int = 0


def _estimate(config: AgentConfig | None, messages: list[Message], options: CompactionOptions) -> int:
    # Host callbacks receive a detached request view, like the summarizer.
    count = options.token_estimator(deepcopy(config), deepcopy(messages))
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ValueError("token_estimator must return a nonnegative integer")
    return count


async def auto_compact_if_needed(
    state: AgentState,
    strategy: CompactionStrategy,
    options: CompactionOptions,
    tracking: CompactionTracking,
    *,
    config: AgentConfig | None = None,
    store: ContextStore | None = None,
    store_timeout_seconds: float = 10.0,
    transcript: Transcript | None = None,
) -> CompactionOutcome:
    """Commit one replacement summary only after the rebuilt input fits.

    Summary failures and budget/estimation blocks leave the transcript intact.
    PTL retries may discard eligible history, but retain prior summaries in
    every attempt and keep assistant/tool groups whole. The pinned recent tail
    and original system instructions never enter PTL trimming.
    """
    started = monotonic()
    if tracking.consecutive_failures >= options.max_consecutive_failures:
        return CompactionOutcome(False, tracking, exhausted=True)

    estimated: int | None = None
    failure_reason: str | None = None
    summary_input_tokens = 0
    summary_output_tokens = 0

    def estimate(messages):
        return _estimate(config, model_messages(state, messages), options)

    def failure(reason: BlockedReason | None = None) -> CompactionOutcome:
        detail = reason or failure_reason
        if reason is None and estimated is not None and estimated >= options.input_budget:
            reason = "context_budget_exceeded"
        failures = CompactionTracking(tracking.consecutive_failures + 1)
        return CompactionOutcome(
            False, failures,
            exhausted=failures.consecutive_failures >= options.max_consecutive_failures,
            estimated_input_tokens=estimated, blocked_reason=reason,
            failure_reason=detail or reason, duration_ms=(monotonic() - started) * 1000,
            summary_input_tokens=summary_input_tokens, summary_output_tokens=summary_output_tokens,
        )

    try:
        estimated = estimate(state.messages)
    except Exception:
        return failure("token_estimation_failed")
    if not state.needs_compaction and estimated < options.input_budget:
        return CompactionOutcome(False, tracking, estimated_input_tokens=estimated)

    systems = [m for m in state.messages if m.role == "system" and not _is_summary(m)]
    summaries = [m for m in state.messages if _is_summary(m)]
    eligible, pinned_tail = _split_pinned_tail(state.messages, min_recent=options.min_recent_messages)
    if not eligible and not summaries:
        failure_reason = "no_eligible_history"
        return failure()

    # If the immutable portion alone is too large, summarizing older history
    # cannot help. Preserve the full transcript for the host to resolve.
    try:
        if estimate([*systems, *pinned_tail]) >= options.input_budget:
            failure_reason = "pinned_context_too_large"
            return failure()
    except Exception:
        return failure("token_estimation_failed")

    candidates = eligible
    for ptl_attempts in range(options.max_ptl_retries + 1):
        try:
            inputs = [*summaries, *candidates]
            contextual = getattr(strategy, "summarize_context", None)
            request = (contextual(deepcopy(inputs), task=deepcopy(state.task), target_tokens=options.target_tokens)
                       if contextual else strategy.summarize(deepcopy(inputs)))
            produced = await asyncio.wait_for(request, timeout=options.summary_timeout_seconds)
            if isinstance(produced, StructuredSummary):
                summary_input_tokens += produced.usage.input_tokens
                summary_output_tokens += produced.usage.output_tokens
                produced.validate(inputs, state.task)
                produced = produced.render()
            elif options.require_structured_summary:
                raise ValueError("structured summary required")
        except TimeoutError:
            failure_reason = "summary_timeout"
            produced = None
        except SummaryValidationError as exc:
            summary_input_tokens += exc.usage.input_tokens
            summary_output_tokens += exc.usage.output_tokens
            failure_reason = "summary_failed_or_invalid"
            produced = None
        except Exception:
            failure_reason = "summary_failed_or_invalid"
            produced = None

        if isinstance(produced, str) and produced.strip() and len(produced) <= options.max_summary_chars:
            # Preserve the existing adapter-facing role, but mark SDK summaries
            # explicitly so future passes merge them instead of pinning them.
            rebuilt = [
                *systems,
                SystemMessage(role="system", content=f"{SUMMARY_PREFIX}{produced}", is_summary=True,
                              source_message_ids=tuple(m.id for m in inputs)),
                *pinned_tail,
            ]
            try:
                rebuilt_estimate = estimate(rebuilt)
            except Exception:
                return failure("token_estimation_failed")
            if rebuilt_estimate <= options.target_tokens:
                included_ids = {m.id for m in inputs}
                result = CompactionResult(
                    summary=produced, messages_retained=len(rebuilt), ptl_attempts=ptl_attempts,
                    source_message_ids=tuple(m.id for m in inputs), input_tokens_before=estimated,
                    input_tokens_after=rebuilt_estimate, duration_ms=(monotonic() - started) * 1000,
                    summary_input_tokens=summary_input_tokens, summary_output_tokens=summary_output_tokens,
                    omitted_message_ids=tuple(m.id for m in eligible if m.id not in included_ids),
                )
                if store is not None:
                    try:
                        if config is None:
                            raise ValueError("archival requires a configured session")
                        summary_message = next(m for m in rebuilt if _is_summary(m))
                        await asyncio.wait_for(store.commit_compaction(
                            config.session_id, state.messages, rebuilt,
                            {"id": summary_message.id, **asdict(result),
                             "task_id": state.task.id if state.task else None,
                             "task_revision": state.task.revision if state.task else None},
                        ), timeout=store_timeout_seconds)
                    except Exception:
                        return failure("context_storage_failed")
                (transcript or Transcript(config)).replace(state, rebuilt, reason="compaction")
                state.needs_compaction = False
                # Usage fields remain the actual past provider counts.
                return CompactionOutcome(
                    True, CompactionTracking(),
                    result=result,
                    estimated_input_tokens=rebuilt_estimate,
                )
            failure_reason = "summary_target_not_reached"
        elif produced is not None:
            failure_reason = "summary_failed_or_invalid"

        if ptl_attempts == options.max_ptl_retries or not candidates:
            break
        candidates = _drop_largest(candidates) if ptl_attempts == 0 else _trim_oldest(candidates)
        if not candidates and not summaries:
            break
    return failure()
