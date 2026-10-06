"""Model-independent input sizing; adapters can supply an exact tokenizer."""

from __future__ import annotations

import json
from collections.abc import Callable

from ..types import AgentConfig, AssistantMessage, Message, ToolMessage

TokenEstimator = Callable[[AgentConfig | None, list[Message]], int]


def estimate_input_tokens(config: AgentConfig | None, messages: list[Message]) -> int:
    """Use the UTF-8 byte length of a model-facing JSON envelope as an estimate.

    This deliberately errs towards early compaction compared with chars / 4,
    including for CJK text. It is NOT an exact count or a universal upper bound:
    adapters may use different framing/tokenizers or add provider-only fields.
    Set ``CompactionOptions.token_estimator`` for the adapter's actual format,
    and leave room in ``token_budget`` for output tokens and framing overhead.
    Runtime-only metadata (message UUIDs, approvals, billing) is not input.
    """
    payload: dict = {"messages": []}
    if config is not None:
        payload["system"] = config.system_prompt
        payload["tools"] = [
            {"name": tool.name, "description": tool.description, "parameters": tool.parameters}
            for tool in config.available_tools
        ]
    for message in messages:
        item: dict = {"role": message.role, "content": message.content}
        if isinstance(message, AssistantMessage) and message.tool_calls:
            item["tool_calls"] = [
                {"id": call.id, "name": call.name, "arguments": call.args}
                for call in message.tool_calls
            ]
        elif isinstance(message, ToolMessage):
            item.update(name=message.tool_name, tool_call_id=message.tool_call_id)
        payload["messages"].append(item)
    return len(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
