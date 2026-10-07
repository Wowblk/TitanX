from __future__ import annotations

from uuid import uuid4

from .types import (
    AgentConfig,
    AgentState,
    Message,
    PendingApproval,
    ToolDefinition,
)


def _new_id() -> str:
    return str(uuid4())


def create_config(
    *,
    user_id: str = "default",
    channel: str = "repl",
    system_prompt: str = "",
    available_tools: list[ToolDefinition] | None = None,
    wrap_tool_output: bool = False,
    max_output_tokens: int | None = None,
) -> AgentConfig:
    if max_output_tokens is not None and (type(max_output_tokens) is not int or max_output_tokens < 0):
        raise ValueError("max_output_tokens must be a nonnegative integer or None")
    return AgentConfig(
        thread_id=_new_id(),
        session_id=_new_id(),
        user_id=user_id,
        channel=channel,
        system_prompt=system_prompt,
        available_tools=tuple(available_tools or []),
        wrap_tool_output=wrap_tool_output,
        max_output_tokens=max_output_tokens,
    )


def create_initial_state(messages: list[Message] | None = None) -> AgentState:
    return AgentState(messages=list(messages or []))


def append_message(state: AgentState, message: Message) -> None:
    state.messages.append(message)


def set_pending_approval(state: AgentState, approval: PendingApproval | None) -> None:
    state.pending_approval = approval
