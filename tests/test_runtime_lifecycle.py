"""Runtime per-prompt invariants and cancellation protocol.

Covers:

- Q13: ``state.iteration`` resets on every ``run_prompt`` so
  ``max_iterations`` caps work per-turn, not per-session.
- Q21: trust-boundary input checks (empty / oversized) live on
  ``run_prompt`` itself; the redundant second injection scan is gone.
- Q22: cancellation mid-tool-execution synthesises a ``ToolMessage``
  for the in-flight call, sets ``signal=interrupt``, and re-raises so
  the OpenAI/Anthropic tool-call protocol stays consistent across a
  resume.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from titanx.types import (
    LlmTurnResult,
    ToolCall,
    ToolDefinition,
    ToolExecutionResult,
)

from ._helpers import ScriptedLlm, SingleTool, make_runtime


class TestQ13IterationReset:
    async def test_iteration_resets_between_prompts(self) -> None:
        llm = ScriptedLlm([LlmTurnResult(type="text", text="ok-1")])
        runtime = make_runtime(llm, max_iterations=2)

        await runtime.run_prompt("hello")
        assert runtime.state.iteration == 1

        # Simulate a long-lived session whose iteration counter is far
        # past the per-prompt cap from previous turns. Without the
        # reset (Q13) the next run_prompt would hit max_iterations on
        # the very first iteration and exit without ever calling the
        # LLM.
        runtime.state.iteration = 999
        llm.cursor = 0
        llm.responses = [LlmTurnResult(type="text", text="ok-2")]

        await runtime.run_prompt("hello again")
        assert runtime.state.iteration == 1

    async def test_approval_set_resets_per_prompt(self) -> None:
        llm = ScriptedLlm([LlmTurnResult(type="text", text="done")])
        runtime = make_runtime(llm)

        # Pretend a previous prompt left a stale approval in the set.
        # A new run_prompt must clear it; otherwise an approval
        # granted for an old tool_call_id could silently auto-approve
        # a re-issued call.
        runtime.state.approved_tool_call_ids.add("stale-id")
        await runtime.run_prompt("hi")
        assert runtime.state.approved_tool_call_ids == set()


class TestQ21TrustBoundaryInputChecks:
    async def test_empty_prompt_rejected(self) -> None:
        runtime = make_runtime(ScriptedLlm([]))
        with pytest.raises(ValueError, match="empty"):
            await runtime.run_prompt("")

    async def test_oversized_prompt_rejected(self) -> None:
        runtime = make_runtime(ScriptedLlm([]))
        with pytest.raises(ValueError, match="maximum length"):
            await runtime.run_prompt("x" * 200_000)


class TestQ22CancellationProtocol:
    async def test_cancellation_synthesizes_tool_message(self) -> None:
        # The handler blocks indefinitely so the parent task can cancel
        # while we're inside ``_tools.execute``. A flag confirms the
        # tool actually started — otherwise the cancel could fire
        # before the body runs and the test would be vacuous.
        started = asyncio.Event()

        async def slow_handler(name: str, params: dict[str, Any]) -> ToolExecutionResult:
            started.set()
            await asyncio.sleep(60)
            return ToolExecutionResult(output="never", error=None)  # pragma: no cover

        tools = SingleTool(
            ToolDefinition(name="slow", description="", parameters={}),
            slow_handler,
        )
        llm = ScriptedLlm([LlmTurnResult(
            type="tool_calls",
            text="",
            tool_calls=[ToolCall(id="tc-1", name="slow", args={})],
        )])
        runtime = make_runtime(llm, tools=tools)

        task = asyncio.create_task(runtime.run_prompt("trigger"))
        await asyncio.wait_for(started.wait(), timeout=1.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        # Q22 invariants: signal flips to "interrupt" and the last
        # message is the synthesised ToolMessage closing the protocol.
        assert runtime.state.signal == "interrupt"
        last = runtime.state.messages[-1]
        assert getattr(last, "role", None) == "tool"
        # The cursor must advance past the cancelled call so a follow-
        # up resume() would pick the next pending tool, not retry the
        # same one (which would be the wrong semantics for a tool
        # that has user-visible side effects).
        assert runtime.state.pending_tool_call_index >= 1
