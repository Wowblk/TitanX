from __future__ import annotations

from titanx.context import (
    CompactionOptions,
    CompactionStrategy,
    RuntimeStateSnapshot,
    auto_compact_if_needed,
)
from titanx.context.compactor import CompactionTracking
from titanx.runtime import AgentRuntime
from titanx.safety.safety_layer import SafetyLayer
from titanx.types import (
    AgentState,
    LlmAdapter,
    LlmTurnResult,
    RuntimeHooks,
    SystemMessage,
    ToolMessage,
    UserMessage,
)

from ._helpers import NullTools


class SummaryStrategy(CompactionStrategy):
    name = "test-summary"

    async def summarize(self, messages):
        return (
            "Primary Request and Intent: keep working.\n"
            "Current Task State: compacted.\n"
            "Key Decisions: preserve recent tail.\n"
            "Pending Tasks: continue.\n"
            "Next Step: call the model."
        )


class ExplodingLlm(LlmAdapter):
    async def respond(self, config, state) -> LlmTurnResult:  # pragma: no cover
        raise AssertionError("manual compaction should not call the LLM")


def _tool(content: str, *, id_: str = "tool-1") -> ToolMessage:
    return ToolMessage(
        role="tool",
        tool_name="shell",
        tool_call_id=id_,
        content=content,
        id=id_,
    )


async def test_micro_compaction_can_satisfy_projected_budget_without_llm() -> None:
    state = AgentState(messages=[
        UserMessage(role="user", content="inspect logs"),
        _tool("x" * 1_200),
        UserMessage(role="user", content="continue"),
    ])
    options = CompactionOptions(
        token_budget=250,
        reserved_output_tokens=1,
        tool_growth_estimate=0,
        micro_keep_recent_tool_results=0,
        micro_min_content_chars=100,
        min_recent_messages=1,
    )

    outcome = await auto_compact_if_needed(
        state,
        strategy=None,
        options=options,
        tracking=CompactionTracking(),
    )

    assert outcome.was_compacted
    assert outcome.result is not None
    assert outcome.result.phase == "micro"
    assert outcome.result.messages_compacted == 1
    assert "cleared by micro-compaction" in state.messages[1].content
    assert state.last_input_tokens == 0


async def test_summary_compaction_rebuilds_with_snapshot_and_recent_tail() -> None:
    state = AgentState(messages=[
        SystemMessage(role="system", content="canonical system"),
        UserMessage(role="user", content="original goal " + "a" * 400),
        UserMessage(role="user", content="recent tail"),
    ])
    options = CompactionOptions(
        token_budget=90,
        reserved_output_tokens=1,
        tool_growth_estimate=0,
        enable_micro_compaction=False,
        min_recent_messages=1,
    )

    outcome = await auto_compact_if_needed(
        state,
        strategy=SummaryStrategy(),
        options=options,
        tracking=CompactionTracking(),
        runtime_state=RuntimeStateSnapshot(cwd="/tmp/project", available_tools=["run_command"]),
    )

    assert outcome.was_compacted
    assert outcome.result is not None
    assert outcome.result.phase == "summary"
    assert [m.role for m in state.messages] == ["system", "system", "user"]
    assert state.messages[0].content == "canonical system"
    assert "Runtime state snapshot" in state.messages[1].content
    assert '"available_tools": ["run_command"]' in state.messages[1].content
    assert state.messages[-1].content == "recent tail"


async def test_manual_compact_uses_pipeline_without_model_call() -> None:
    events = []

    async def on_event(event, config, state):
        events.append(event)

    runtime = AgentRuntime(
        llm=ExplodingLlm(),
        tools=NullTools(),
        safety=SafetyLayer(),
        hooks=RuntimeHooks(on_event=on_event),
        compaction_options=CompactionOptions(
            token_budget=340,
            reserved_output_tokens=1,
            tool_growth_estimate=0,
            micro_keep_recent_tool_results=0,
            micro_min_content_chars=100,
            min_recent_messages=1,
        ),
    )
    runtime.state.messages = [
        UserMessage(role="user", content="previous goal"),
        _tool("y" * 1_200),
        UserMessage(role="user", content="still here"),
    ]

    await runtime.run_prompt("/compact keep task state")

    compaction_events = [e for e in events if getattr(e, "type", "") == "compaction_triggered"]
    assert compaction_events
    assert compaction_events[0].reason == "manual"
    assert compaction_events[0].phase == "micro"
    assert events[-1].reason == "manual_compacted"


async def test_summary_failure_reports_diagnostic_reason() -> None:
    class FailingStrategy(CompactionStrategy):
        async def summarize(self, messages):
            raise RuntimeError("nope")

    state = AgentState(messages=[
        UserMessage(role="user", content="old " + "z" * 300),
        UserMessage(role="user", content="recent"),
    ])
    options = CompactionOptions(
        token_budget=40,
        reserved_output_tokens=1,
        tool_growth_estimate=0,
        enable_micro_compaction=False,
        min_recent_messages=1,
        max_ptl_retries=0,
    )

    outcome = await auto_compact_if_needed(
        state,
        strategy=FailingStrategy(),
        options=options,
        tracking=CompactionTracking(),
    )

    assert not outcome.was_compacted
    assert outcome.failure_reason == "ptl_retries_exhausted"
    assert outcome.tracking.consecutive_failures == 1
