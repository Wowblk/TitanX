from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable, Literal, Union
from uuid import uuid4

Role = Literal["system", "user", "assistant", "tool"]
LoopSignal = Literal["continue", "stop", "interrupt"]
LastResponseType = Literal["text", "tool_calls", "none", "need_approval"]


@dataclass
class ToolDefinition:
    name: str
    description: str
    parameters: dict[str, Any]
    requires_approval: bool = False
    requires_sanitization: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict[str, Any]


@dataclass
class PendingApproval:
    tool_name: str
    tool_call_id: str
    parameters: dict[str, Any]
    requires_always: bool


@dataclass
class SystemMessage:
    role: Literal["system"]
    content: str
    id: str = field(default_factory=lambda: str(uuid4()))


@dataclass
class UserMessage:
    role: Literal["user"]
    content: str
    id: str = field(default_factory=lambda: str(uuid4()))


@dataclass
class AssistantMessage:
    role: Literal["assistant"]
    content: str
    id: str = field(default_factory=lambda: str(uuid4()))
    tool_calls: list[ToolCall] = field(default_factory=list)


@dataclass
class ToolMessage:
    role: Literal["tool"]
    tool_name: str
    tool_call_id: str
    content: str
    id: str = field(default_factory=lambda: str(uuid4()))
    is_error: bool = False


Message = Union[SystemMessage, UserMessage, AssistantMessage, ToolMessage]


@dataclass(frozen=True)
class AgentConfig:
    thread_id: str
    session_id: str
    user_id: str
    channel: str
    system_prompt: str
    available_tools: tuple[ToolDefinition, ...]
    max_iterations: int
    auto_approve_tools: bool


@dataclass
class AgentState:
    signal: LoopSignal = "continue"
    iteration: int = 0
    consecutive_tool_intent_nudges: int = 0
    force_text: bool = False
    messages: list[Message] = field(default_factory=list)
    pending_approval: PendingApproval | None = None
    last_response_type: LastResponseType = "none"
    last_text_response: str = ""
    needs_compaction: bool = False
    total_input_tokens: int = 0
    total_output_tokens: int = 0


@dataclass
class LlmUsage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class LlmTurnResult:
    type: Literal["text", "tool_calls"]
    text: str | None = None
    tool_calls: list[ToolCall] | None = None
    usage: LlmUsage | None = None


@dataclass
class ToolExecutionResult:
    output: str
    error: str | None = None


@dataclass
class ValidationIssue:
    field: str
    message: str
    code: str
    severity: Literal["warning", "error"]


@dataclass
class ValidationResult:
    is_valid: bool
    errors: list[ValidationIssue]
    warnings: list[ValidationIssue]


@dataclass
class SafetyViolation:
    pattern: str
    action: Literal["warn", "sanitize", "block", "review"]


@dataclass
class SafetyResult:
    safe: bool
    sanitized_content: str
    violations: list[SafetyViolation]


# ── Runtime events ────────────────────────────────────────────────────────────

@dataclass
class LoopStartEvent:
    type: Literal["loop_start"] = "loop_start"


@dataclass
class IterationStartEvent:
    iteration: int
    type: Literal["iteration_start"] = "iteration_start"


@dataclass
class AssistantTextEvent:
    text: str
    type: Literal["assistant_text"] = "assistant_text"


@dataclass
class AssistantToolCallsEvent:
    tool_calls: list[ToolCall]
    type: Literal["assistant_tool_calls"] = "assistant_tool_calls"


@dataclass
class ToolResultEvent:
    tool_name: str
    tool_call_id: str
    is_error: bool
    type: Literal["tool_result"] = "tool_result"


@dataclass
class PendingApprovalEvent:
    approval: PendingApproval
    type: Literal["pending_approval"] = "pending_approval"


@dataclass
class LoopEndEvent:
    reason: str
    type: Literal["loop_end"] = "loop_end"


@dataclass
class CompactionTriggeredEvent:
    summary: str
    ptl_attempts: int
    type: Literal["compaction_triggered"] = "compaction_triggered"


@dataclass
class CompactionFailedEvent:
    consecutive_failures: int
    type: Literal["compaction_failed"] = "compaction_failed"


RuntimeEvent = Union[
    LoopStartEvent,
    IterationStartEvent,
    AssistantTextEvent,
    AssistantToolCallsEvent,
    ToolResultEvent,
    PendingApprovalEvent,
    LoopEndEvent,
    CompactionTriggeredEvent,
    CompactionFailedEvent,
]

# ── Protocol interfaces ───────────────────────────────────────────────────────

class ValidatorLike:
    def validate_input(self, content: str, field: str = "input") -> ValidationResult:
        raise NotImplementedError

    def validate_tool_params(self, params: dict[str, Any]) -> ValidationResult:
        raise NotImplementedError


class SafetyLayerLike:
    @property
    def validator(self) -> ValidatorLike:
        raise NotImplementedError

    def check_input(self, content: str) -> SafetyResult:
        raise NotImplementedError

    def sanitize_tool_output(self, tool_name: str, output: str) -> dict[str, str]:
        raise NotImplementedError


class LlmAdapter:
    async def respond(self, config: AgentConfig, state: AgentState) -> LlmTurnResult:
        raise NotImplementedError


class ToolRuntime:
    def list_tools(self) -> list[ToolDefinition]:
        raise NotImplementedError

    async def execute(self, name: str, params: dict[str, Any]) -> ToolExecutionResult:
        raise NotImplementedError


OnEventCallback = Callable[[RuntimeEvent, AgentConfig, AgentState], Awaitable[None] | None]


@dataclass
class RuntimeHooks:
    on_event: OnEventCallback | None = None
