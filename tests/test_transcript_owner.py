"""Single-owner transcript replacement (design review 2.1 #5).

The transcript used to be rewritten wholesale by two independent components
(``ContextManager.prepare`` and ``auto_compact_if_needed``) with only call
ordering as coordination. These tests pin the new contract: one owner both
writers go through, and that owner enforces the invariants that were
otherwise silently violable.
"""
from __future__ import annotations

from titanx.context import CompactionOptions, ContextOptions, SQLiteContextStore
from titanx.context.transcript import (
    SUMMARY_PREFIX,
    Transcript,
    TranscriptInvariantError,
)
from titanx.runtime import AgentRuntime
from titanx.safety import SafetyLayer
from titanx.types import (
    AgentState,
    AssistantMessage,
    LlmTurnResult,
    SystemMessage,
    ToolCall,
    ToolDefinition,
    ToolExecutionResult,
    ToolMessage,
    UserMessage,
)

from ._helpers import NullTools, ScriptedLlm, SingleTool


def _tool_groups_intact(messages) -> bool:
    declared = [call.id for m in messages if isinstance(m, AssistantMessage) for call in m.tool_calls]
    results = [m.tool_call_id for m in messages if isinstance(m, ToolMessage)]
    return declared == results


class _SummaryStrategy:
    async def summarize(self, messages):
        return "merged history"


class TestTranscriptOwnerInvariants:
    async def test_host_pinned_system_is_preserved_and_summaries_collapsed(self):
        pinned = SystemMessage(role="system", content="Keep the host instructions.", is_summary=False)
        state = AgentState(messages=[pinned])
        owner = Transcript()

        proposed = [
            SystemMessage(role="system", content=f"{SUMMARY_PREFIX}older", is_summary=True),
            UserMessage(role="user", content="round"),
            SystemMessage(role="system", content=f"{SUMMARY_PREFIX}newer", is_summary=True),
        ]
        owner.replace(state, proposed, reason="compaction")

        assert state.messages[0] is pinned
        summaries = [m for m in state.messages if isinstance(m, SystemMessage) and m.is_summary is True]
        assert len(summaries) == 1
        assert summaries[0].content.endswith("newer")
        assert owner.commit_count == 1
        assert owner.commits[0].reason == "compaction"

    async def test_owner_rejects_separated_tool_declaration_without_committing(self):
        owner = Transcript()
        state = AgentState(messages=[])
        broken = [
            AssistantMessage(role="assistant", content="", tool_calls=[ToolCall(id="c1", name="t", args={})]),
            UserMessage(role="user", content="interrupting turn"),
            ToolMessage(role="tool", tool_name="t", tool_call_id="c1", content="result"),
        ]

        try:
            owner.replace(state, broken, reason="x")
        except TranscriptInvariantError:
            pass
        else:  # pragma: no cover - explicit failure message
            raise AssertionError("owner committed a transcript with an orphaned tool declaration")

        assert state.messages == []
        assert owner.commit_count == 0


class TestRuntimeRoutesThroughOwner:
    async def test_offload_and_compaction_commit_through_one_owner(self, tmp_path):
        store = SQLiteContextStore(tmp_path / "context.sqlite")
        executions = []

        async def execute(name, params):
            executions.append(name)
            return ToolExecutionResult(output="log row\n" * 500 + "TAIL=9182")

        tool = SingleTool(ToolDefinition("logs", "Read logs", {}), execute)
        llm = ScriptedLlm([
            LlmTurnResult(type="tool_calls", tool_calls=[ToolCall("read-1", "logs", {})]),
            LlmTurnResult(type="text", text="first answer"),
            LlmTurnResult(type="text", text="second answer"),
        ])
        runtime = AgentRuntime(
            llm, tool, SafetyLayer(),
            context_options=ContextOptions(store, offload_threshold_chars=500, preview_chars=50),
            compaction_options=CompactionOptions(100000, min_recent_messages=1),
            compaction_strategy=_SummaryStrategy(),
        )
        try:
            await runtime.run_prompt("read the logs")
            runtime.state.needs_compaction = True
            await runtime.run_prompt("continue")
        finally:
            await store.close()

        reasons = [commit.reason for commit in runtime.transcript.commits]
        assert "offload" in reasons, reasons
        assert "compaction" in reasons, reasons
        # Invariants hold on the transcript produced through the owner.
        summaries = [m for m in runtime.state.messages if isinstance(m, SystemMessage) and m.is_summary is True]
        assert len(summaries) == 1
        assert _tool_groups_intact(runtime.state.messages)

    async def test_owner_survives_no_context_configuration(self):
        # A runtime without context management still exposes a single owner
        # (so teardown has a stable handle) and never commits.
        runtime = AgentRuntime(ScriptedLlm([LlmTurnResult(type="text", text="hi")]), NullTools(), SafetyLayer())
        assert runtime.transcript.commit_count == 0
