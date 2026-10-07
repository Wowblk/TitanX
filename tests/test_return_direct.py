"""``return_direct`` tool short-circuit (SDK feature).

When the tool-call pipeline commits a *successful* result for a tool marked
``return_direct``, the runtime must end the turn using that output as the
final assistant message — exactly like a plain text turn — instead of asking
the LLM for a second turn to summarise the tool result.

These tests live at the ``run_prompt`` seam: they observe the public
behaviour (how many LLM turns ran, what the final message is, which events
fired) without reaching into pipeline internals.
"""
from __future__ import annotations

from titanx.types import (
    AssistantMessage,
    AssistantTextEvent,
    LlmTurnResult,
    LoopEndEvent,
    RuntimeHooks,
    ToolCall,
    ToolDefinition,
    ToolExecutionResult,
    ToolMessage,
    ToolRuntime,
)
from tests._helpers import ScriptedLlm, SingleTool, make_runtime


class _MultiTools(ToolRuntime):
    """ToolRuntime exposing several definitions, all dispatched to one handler."""

    def __init__(self, defs: list[ToolDefinition], handler) -> None:
        self._defs = defs
        self._handler = handler

    def list_tools(self) -> list[ToolDefinition]:
        return list(self._defs)

    async def execute(self, name, params):
        return await self._handler(name, params)


def _tool_call(name: str = "echo_direct") -> LlmTurnResult:
    return LlmTurnResult(
        type="tool_calls",
        text="",
        tool_calls=[ToolCall(id="tc-1", name=name, args={})],
    )


async def test_return_direct_tool_ends_turn_without_second_llm_turn():
    events: list[object] = []

    async def handler(name, params):
        return ToolExecutionResult(output="FINAL:hello", error=None)

    tools = SingleTool(
        ToolDefinition(name="echo_direct", description="", parameters={}, return_direct=True),
        handler,
    )
    llm = ScriptedLlm([
        _tool_call(),
        LlmTurnResult(type="text", text="SHOULD-NOT-RUN"),
    ])
    hooks = RuntimeHooks(on_event=lambda event, config, state: events.append(event))
    rt = make_runtime(llm, tools=tools, hooks=hooks)

    await rt.run_prompt("go")

    # Exactly one LLM turn: the tool short-circuited the loop.
    assert llm.cursor == 1

    # The final assistant message is the tool output, not a second LLM reply.
    last = rt.state.messages[-1]
    assert isinstance(last, AssistantMessage)
    assert last.content == "FINAL:hello"
    assert rt.state.last_response_type == "text"
    assert rt.state.last_text_response == "FINAL:hello"

    # The tool-call protocol is still closed with a matching ToolMessage.
    assert any(
        isinstance(message, ToolMessage) and message.tool_call_id == "tc-1"
        for message in rt.state.messages
    )

    # The turn ended as a normal completion, with the output surfaced.
    assert any(isinstance(e, LoopEndEvent) and e.reason == "completed" for e in events)
    assert any(isinstance(e, AssistantTextEvent) and e.text == "FINAL:hello" for e in events)


async def test_non_return_direct_tool_still_needs_second_llm_turn():
    async def handler(name, params):
        return ToolExecutionResult(output="raw-data", error=None)

    tools = SingleTool(
        ToolDefinition(name="plain", description="", parameters={}),
        handler,
    )
    llm = ScriptedLlm([
        _tool_call(name="plain"),
        LlmTurnResult(type="text", text="summarised"),
    ])
    rt = make_runtime(llm, tools=tools)

    await rt.run_prompt("go")

    # No short-circuit: the LLM gets a second turn to interpret the result.
    assert llm.cursor == 2
    assert rt.state.messages[-1].content == "summarised"


async def test_return_direct_error_does_not_short_circuit():
    async def handler(name, params):
        return ToolExecutionResult(output="", error="boom")

    tools = SingleTool(
        ToolDefinition(name="echo_direct", description="", parameters={}, return_direct=True),
        handler,
    )
    llm = ScriptedLlm([
        _tool_call(),
        LlmTurnResult(type="text", text="handled-error"),
    ])
    rt = make_runtime(llm, tools=tools)

    await rt.run_prompt("go")

    # An errored return_direct tool must NOT be treated as the final answer.
    assert llm.cursor == 2
    assert rt.state.messages[-1].content == "handled-error"


def _tool_calls(*names: str) -> LlmTurnResult:
    return LlmTurnResult(
        type="tool_calls",
        text="",
        tool_calls=[
            ToolCall(id=f"tc-{i + 1}", name=name, args={})
            for i, name in enumerate(names)
        ],
    )


async def test_return_direct_last_in_batch_short_circuits_and_clears_queue():
    async def handler(name, params):
        return ToolExecutionResult(output=f"OUT:{name}", error=None)

    tools = _MultiTools(
        [
            ToolDefinition(name="plain", description="", parameters={}),
            ToolDefinition(name="echo_direct", description="", parameters={}, return_direct=True),
        ],
        handler,
    )
    llm = ScriptedLlm([
        _tool_calls("plain", "echo_direct"),
        LlmTurnResult(type="text", text="SHOULD-NOT-RUN"),
    ])
    rt = make_runtime(llm, tools=tools)

    await rt.run_prompt("go")

    # The batch ran to completion (both calls), then short-circuited.
    assert llm.cursor == 1

    # The in-flight batch bookkeeping is fully drained, so the *next*
    # run_prompt starts clean instead of resuming a stale cursor.
    assert rt.state.pending_tool_calls == []
    assert rt.state.pending_tool_call_index == 0

    last = rt.state.messages[-1]
    assert isinstance(last, AssistantMessage)
    assert last.content == "OUT:echo_direct"

    # Every call in the batch is still closed with a matching ToolMessage.
    ids = {m.tool_call_id for m in rt.state.messages if isinstance(m, ToolMessage)}
    assert ids == {"tc-1", "tc-2"}


async def test_return_direct_not_last_in_batch_does_not_short_circuit():
    async def handler(name, params):
        return ToolExecutionResult(output=f"OUT:{name}", error=None)

    tools = _MultiTools(
        [
            ToolDefinition(name="plain", description="", parameters={}),
            ToolDefinition(name="echo_direct", description="", parameters={}, return_direct=True),
        ],
        handler,
    )
    llm = ScriptedLlm([
        _tool_calls("echo_direct", "plain"),
        LlmTurnResult(type="text", text="summarised"),
    ])
    rt = make_runtime(llm, tools=tools)

    await rt.run_prompt("go")

    # A return_direct call that is not the last of its batch must not end the
    # turn early: the remaining sibling still has to run, and the loop still
    # asks the LLM to interpret the combined results.
    assert llm.cursor == 2
    assert rt.state.messages[-1].content == "summarised"
