from __future__ import annotations

from dataclasses import dataclass
import math
from typing import TYPE_CHECKING

from .tokens import TokenEstimator, estimate_input_tokens

if TYPE_CHECKING:
    from ..types import Message, TaskState
    from .summary import StructuredSummary


class CompactionStrategy:
    async def summarize(self, messages: list[Message]) -> str:
        raise NotImplementedError

    async def summarize_context(
        self, messages: list[Message], *, task: TaskState | None = None, target_tokens: int | None = None,
    ) -> str | StructuredSummary:
        """Legacy strategies remain valid; new strategies can use task metadata."""
        return await self.summarize(messages)


@dataclass
class CompactionOptions:
    """Tunables for the auto-compaction subsystem.

    ``token_budget`` is the INPUT trigger. When ``model_context_window`` is
    set, the usable input budget is also capped by window minus output reserve
    and safety margin. ``target_token_budget`` is a strictly lower post-
    compaction target; omission preserves the legacy trigger-minus-one target.
    Before every model call, ``token_estimator`` sizes the
    current system prompt, tool definitions and messages, including new user
    input and tool results. At or above the budget, compaction must bring the
    estimate below the budget or the runtime stops before calling the model.
    ``AgentState.needs_compaction`` can also force a pass below the budget.

    The default estimator uses serialized UTF-8 bytes as a conservative token
    estimate. For model-specific accuracy, supply a synchronous callable
    ``(config, messages) -> nonnegative int`` using the adapter's serialization
    and tokenizer. ``config`` is None for standalone compactor calls that omit
    it. Estimation failures stop the runtime instead of bypassing the check.

    ``min_recent_messages`` is the floor of "always-keep" tail messages that
    PTL trimming refuses to drop. The most recent assistant + tool-result
    pair is what gives the agent any hope of continuing reasoning, so we
    pin it. Tool-call groups are kept whole. An oversized pinned tail stops
    the loop; it is never silently truncated to make the request fit.

    ``max_summary_chars`` is a defensive cap: a buggy ``CompactionStrategy``
    that returns a 100KB "summary" must not be allowed to silently re-
    blow the budget right after we just compacted. When exceeded the
    compaction is treated as a failure and PTL retries.

    ``summary_timeout_seconds`` bounds each cooperative async summary attempt;
    at most ``max_ptl_retries + 1`` attempts run per pass. The opt-in
    ``require_structured_summary`` rejects legacy free-text summaries.
    """
    token_budget: int
    max_ptl_retries: int = 3
    max_consecutive_failures: int = 3
    min_recent_messages: int = 6
    max_summary_chars: int = 16_000
    token_estimator: TokenEstimator = estimate_input_tokens
    target_token_budget: int | None = None
    summary_timeout_seconds: float = 30.0
    model_context_window: int | None = None
    reserved_output_tokens: int = 0
    safety_margin_tokens: int = 0
    require_structured_summary: bool = False

    @property
    def input_budget(self) -> int:
        if self.model_context_window is None:
            return self.token_budget
        return min(self.token_budget, self.model_context_window - self.reserved_output_tokens - self.safety_margin_tokens)

    @property
    def target_tokens(self) -> int:
        return self.target_token_budget if self.target_token_budget is not None else self.input_budget - 1

    def __post_init__(self) -> None:
        for name in ("token_budget", "max_consecutive_failures", "max_summary_chars"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        for name in ("max_ptl_retries", "min_recent_messages"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")
        if not callable(self.token_estimator):
            raise ValueError("token_estimator must be callable")
        for name in ("reserved_output_tokens", "safety_margin_tokens"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 0:
                raise ValueError(f"{name} must be a nonnegative integer")
        if self.model_context_window is not None and (type(self.model_context_window) is not int or self.model_context_window <= 0):
            raise ValueError("model_context_window must be a positive integer")
        if self.input_budget <= 0:
            raise ValueError("output reserve and safety margin leave no input budget")
        if self.target_token_budget is not None and (type(self.target_token_budget) is not int or not 0 < self.target_token_budget < self.input_budget):
            raise ValueError("target_token_budget must be positive and below the usable input budget")
        if not math.isfinite(self.summary_timeout_seconds) or self.summary_timeout_seconds <= 0:
            raise ValueError("summary_timeout_seconds must be positive and finite")


@dataclass
class CompactionTracking:
    consecutive_failures: int = 0


@dataclass
class CompactionResult:
    summary: str
    messages_retained: int
    ptl_attempts: int
    source_message_ids: tuple[str, ...] = ()
    input_tokens_before: int | None = None
    input_tokens_after: int | None = None
    duration_ms: float = 0.0
    summary_input_tokens: int = 0
    summary_output_tokens: int = 0
    omitted_message_ids: tuple[str, ...] = ()
