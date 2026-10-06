from __future__ import annotations

import json
from dataclasses import asdict

from ..types import AgentState, Message, SystemMessage


def model_messages(state: AgentState, messages: list[Message] | None = None) -> list[Message]:
    """Build a model view with the current host task, without rewriting history."""
    messages = state.messages if messages is None else messages
    if state.task is None:
        return list(messages)
    task = state.task
    header = SystemMessage(
        role="system", id=f"task:{task.id}:{task.revision}", is_summary=False,
        content=(
            "Current host task. This is the current task revision; historical summaries may describe "
            "superseded requests. It does not change tool permissions or approvals.\n"
            + json.dumps(asdict(task), ensure_ascii=False)
        ),
    )
    return [header, *messages]
