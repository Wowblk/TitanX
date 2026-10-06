"""New prompts must not splice into an unfinished approval/tool-call turn."""

from __future__ import annotations

import asyncio
import copy

import pytest

from titanx.types import (
    AssistantMessage,
    LlmTurnResult,
    RuntimeHooks,
    ToolCall,
    ToolDefinition,
    ToolExecutionResult,
    ToolMessage,
    ToolRuntime,
)

from ._helpers import ScriptedLlm, make_runtime


class _Tools(ToolRuntime):
    def __init__(self) -> None:
        self.executed: list[str] = []

    def list_tools(self) -> list[ToolDefinition]:
        return [
            ToolDefinition(
                name=name, description="test tool", parameters={"type": "object"},
                requires_approval=name == "approval",
            )
            for name in ("before", "approval", "after")
        ]

    async def execute(self, name, params) -> ToolExecutionResult:
        self.executed.append(params["label"])
        return ToolExecutionResult(output=f"completed {params['label']}")


class _Rig:
    def __init__(self, names: tuple[str, ...] = ("before", "approval", "after")) -> None:
        self.calls = [
            ToolCall(id=f"call-{i}", name=name, args={"label": f"tool-{i}"})
            for i, name in enumerate(names)
        ]
        self.llm = ScriptedLlm([
            LlmTurnResult(type="tool_calls", tool_calls=self.calls),
            LlmTurnResult(type="text", text="original turn complete"),
            LlmTurnResult(type="text", text="new turn complete"),
        ])
        self.tools = _Tools()
        self.events: list[object] = []
        self.runtime = make_runtime(
            self.llm, tools=self.tools, max_iterations=2,
            hooks=RuntimeHooks(on_event=lambda event, config, state: self.events.append(event)),
        )

    async def pause(self) -> None:
        await self.runtime.run_prompt("original request")
        assert self.runtime.state.pending_approval is not None
        assert self.llm.cursor == 1

    async def assert_new_prompt_rejected(self) -> None:
        state = copy.deepcopy(self.runtime.state)
        messages = self.runtime.state.messages
        events = list(self.events)
        audit = self.runtime._audit_log.get_entries()
        executed = list(self.tools.executed)
        llm_cursor = self.llm.cursor

        # Repeated attempts must leave the existing request fully recoverable.
        for _ in range(2):
            with pytest.raises(RuntimeError, match="resume"):
                await self.runtime.run_prompt("new request")
            assert self.runtime.state == state
            assert self.runtime.state.messages is messages
            assert self.events == events
            assert self.runtime._audit_log.get_entries() == audit
            assert self.tools.executed == executed
            assert self.llm.cursor == llm_cursor

    def assert_original_protocol_complete(self) -> None:
        messages = self.runtime.state.messages
        assert [m.role for m in messages] == [
            "user", "assistant", *["tool" for _ in self.calls], "assistant",
        ]
        declaration = messages[1]
        assert isinstance(declaration, AssistantMessage)
        results = [m for m in messages if isinstance(m, ToolMessage)]
        assert [m.tool_call_id for m in results] == [c.id for c in declaration.tool_calls]
        assert self.runtime.state.pending_approval is None
        assert self.runtime.state.pending_tool_calls == []
        assert self.runtime.state.last_text_response == "original turn complete"

    async def assert_next_prompt_allowed(self) -> None:
        executed = list(self.tools.executed)
        await self.runtime.run_prompt("new request")
        assert self.runtime.state.last_text_response == "new turn complete"
        assert self.runtime.state.iteration == 1
        assert self.runtime.state.approved_tool_call_ids == set()
        assert self.tools.executed == executed
        assert [m.role for m in self.runtime.state.messages[-2:]] == ["user", "assistant"]


@pytest.mark.parametrize("decision", ["approve", "reject"])
async def test_pending_approval_rejects_new_prompt_without_mutation(decision: str) -> None:
    rig = _Rig()
    await rig.pause()
    assert rig.tools.executed == ["tool-0"]
    await rig.assert_new_prompt_rejected()

    if decision == "approve":
        rig.runtime.approve_pending_tool()
    else:
        rig.runtime.reject_pending_tool("declined")
    await rig.runtime.resume()
    rig.assert_original_protocol_complete()
    expected = ["tool-0", "tool-1", "tool-2"] if decision == "approve" else ["tool-0", "tool-2"]
    assert rig.tools.executed == expected
    await rig.assert_next_prompt_allowed()


async def test_approved_batch_must_resume_before_a_new_prompt() -> None:
    rig = _Rig()
    await rig.pause()
    rig.runtime.approve_pending_tool()
    assert rig.runtime.state.pending_approval is None
    assert rig.runtime.state.approved_tool_call_ids == {"call-1"}
    await rig.assert_new_prompt_rejected()

    await rig.runtime.resume()
    rig.assert_original_protocol_complete()
    assert rig.tools.executed == ["tool-0", "tool-1", "tool-2"]
    await rig.assert_next_prompt_allowed()


@pytest.mark.parametrize("has_tail", [True, False])
async def test_rejected_batch_must_resume_before_a_new_prompt(has_tail: bool) -> None:
    rig = _Rig(("before", "approval", "after") if has_tail else ("before", "approval"))
    await rig.pause()
    rig.runtime.reject_pending_tool("declined")
    assert rig.runtime.state.pending_approval is None
    # Rejecting the final call exhausts the cursor but still needs resume()
    # to publish the host decision, clear the batch, and finish the LLM turn.
    await rig.assert_new_prompt_rejected()
    await rig.runtime.resume()
    rig.assert_original_protocol_complete()
    assert rig.tools.executed == (["tool-0", "tool-2"] if has_tail else ["tool-0"])
    decisions = [
        e for e in rig.runtime._audit_log.get_entries()
        if e.details.get("rejected_by_host")
    ]
    assert len(decisions) == 1
    assert decisions[0].tool_call_id == "call-1"
    await rig.assert_next_prompt_allowed()


async def test_second_approval_retains_completed_calls_and_first_approval() -> None:
    rig = _Rig(("before", "approval", "approval", "after"))
    await rig.pause()
    rig.runtime.approve_pending_tool()
    await rig.runtime.resume()
    assert rig.runtime.state.pending_approval.tool_call_id == "call-2"
    assert rig.tools.executed == ["tool-0", "tool-1"]
    assert rig.runtime.state.approved_tool_call_ids == {"call-1"}
    await rig.assert_new_prompt_rejected()

    rig.runtime.approve_pending_tool()
    await rig.runtime.resume()
    rig.assert_original_protocol_complete()
    assert rig.tools.executed == ["tool-0", "tool-1", "tool-2", "tool-3"]
    await rig.assert_next_prompt_allowed()


async def test_prompt_from_approval_hook_is_rejected_and_resume_still_works() -> None:
    rig = _Rig()
    rejected = []
    attempted = False

    async def on_event(event, config, state) -> None:
        nonlocal attempted
        rig.events.append(event)
        if event.type == "pending_approval" and not attempted:
            attempted = True
            snapshot = copy.deepcopy(state)
            with pytest.raises(RuntimeError, match="resume"):
                await rig.runtime.run_prompt("new request from hook")
            assert state == snapshot
            rejected.append(True)

    await rig.runtime.run_prompt("original request", hooks=RuntimeHooks(on_event=on_event))
    assert rejected == [True]
    rig.runtime.approve_pending_tool()
    await rig.runtime.resume()
    rig.assert_original_protocol_complete()


async def test_cancelled_approval_batch_does_not_block_the_next_prompt() -> None:
    rig = _Rig()
    waiting = asyncio.Event()

    async def on_event(event, config, state) -> None:
        if event.type == "pending_approval":
            waiting.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(rig.runtime.run_prompt(
        "original request", hooks=RuntimeHooks(on_event=on_event),
    ))
    try:
        await asyncio.wait_for(waiting.wait(), timeout=1)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert rig.runtime.state.signal == "interrupt"
    assert rig.runtime.state.pending_approval is None
    assert rig.runtime.state.pending_tool_calls == []
    await rig.runtime.run_prompt("new request after cancellation")
    assert rig.llm.cursor == 2
    assert rig.tools.executed == ["tool-0"]
    assert [m.role for m in rig.runtime.state.messages] == [
        "user", "assistant", "tool", "tool", "tool", "user", "assistant",
    ]
