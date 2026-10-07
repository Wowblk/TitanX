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
    max_iterations: int = 10,
    auto_approve_tools: bool = False,
) -> AgentConfig:
    return AgentConfig(
        thread_id=_new_id(),
        session_id=_new_id(),
        user_id=user_id,
        channel=channel,
        system_prompt=system_prompt,
        available_tools=tuple(available_tools or []),
        max_iterations=max_iterations,
        auto_approve_tools=auto_approve_tools,
    )


def create_initial_state(messages: list[Message] | None = None) -> AgentState:
    return AgentState(messages=list(messages or []))


def append_message(state: AgentState, message: Message) -> None:
    state.messages.append(message)


def set_pending_approval(state: AgentState, approval: PendingApproval | None) -> None:
    state.pending_approval = approval
