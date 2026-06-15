from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from ..types import Message


class CompactionStrategy:
    name: str = "summary"

    async def summarize(self, messages: list[Message]) -> str:
        raise NotImplementedError


@dataclass
class RuntimeStateSnapshot:
    cwd: str | None = None
    workspace_dir: str | None = None
    model: str | None = None
    permission_mode: str | None = None
    active_plan: str | None = None
    current_goal: str | None = None
    recent_files_read: list[str] = field(default_factory=list)
    recent_files_modified: list[str] = field(default_factory=list)
    available_tools: list[str] = field(default_factory=list)
    compaction_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CompactionInput:
    messages: list[Message]
    runtime_state: RuntimeStateSnapshot
    token_budget: int
    custom_instructions: str | None = None
    reason: Literal["auto", "manual", "reactive", "ptl_fallback"] = "auto"


@dataclass
class CompactionOutput:
    summary: str
    tokens_estimate: int
    metadata: dict[str, Any] = field(default_factory=dict)


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
    model_context_window: int | None = None
    model_max_output_tokens: int | None = None
    reserved_output_tokens: int = 20_000
    safety_buffer: int = 13_000
    tool_growth_estimate: int = 10_000
    avg_chars_per_token: float = 4.0
    enable_micro_compaction: bool = True
    micro_min_content_chars: int = 2_048
    micro_keep_recent_tool_results: int = 2
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
    reason: Literal["auto", "manual", "reactive", "ptl_fallback"] = "auto"
    phase: Literal["micro", "summary"] = "summary"
    trigger_reason: str = ""
    pre_compact_tokens: int = 0
    post_compact_tokens: int = 0
    projected_tokens: int = 0
    budget: int = 0
    messages_compacted: int = 0
    messages_kept: int = 0
    summary_tokens: int = 0
    strategy_name: str = ""
    duration_ms: float = 0.0
    failure_reason: str | None = None
