"""Regression tests for behaviours mutation testing found undetected (§3.1).

After the ``ToolCallPipeline`` extraction, mutation testing on the moved
code left a set of *surviving* mutants: deliberate faults the suite did not
notice. They cluster in three host-visible behaviours, all previously
unasserted:

- PII redaction is gated by ``ToolDefinition.requires_sanitization`` — a
  mutant forcing ``redact_pii`` off survived, so nothing proved that a
  tool declaring the flag actually gets its output redacted.
- The at-most-once cursor commit on the *success* path of a multi-call
  batch — mutating ``i + 1`` survived, so nothing proved each tool in a
  clean batch runs exactly once.
- The ``tool_invocation`` audit record's identity fields — removing
  ``tool_name`` / ``tool_call_id`` / ``is_error`` / ``decision`` survived
  because they all default to ``None`` and no test read them back.

Every test drives the public ``run_prompt`` seam and asserts on host-visible
artefacts (tool messages, audit entries), never on pipeline internals.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from titanx.state import now_iso
from titanx.types import (
    LlmTurnResult,
    ToolCall,
    ToolDefinition,
    ToolExecutionResult,
    ToolMessage,
    ToolRuntime,
)

from ._helpers import ScriptedLlm, SingleTool, make_runtime


class TestRequiresSanitizationRedaction:
    """``requires_sanitization`` decides whether tool output is PII-redacted."""

    async def test_pii_is_redacted_when_tool_requires_sanitization(self) -> None:
        async def handler(name: str, params: dict[str, Any]) -> ToolExecutionResult:
            return ToolExecutionResult(output="contact alice@example.com now", error=None)

        tools = SingleTool(
            ToolDefinition(
                name="fetch",
                description="",
                parameters={},
                requires_sanitization=True,
            ),
            handler,
        )
        llm = ScriptedLlm([
            LlmTurnResult(
                type="tool_calls",
                text="",
                tool_calls=[ToolCall(id="tc-pii", name="fetch", args={})],
            ),
            LlmTurnResult(type="text", text="done"),
        ])
        runtime = make_runtime(llm, tools=tools)

        await runtime.run_prompt("fetch it")

        message = next(m for m in runtime.state.messages if isinstance(m, ToolMessage))
        assert "[REDACTED:EMAIL]" in message.content
        assert "alice@example.com" not in message.content

    async def test_pii_is_preserved_when_tool_does_not_require_sanitization(self) -> None:
        # The flag is inclusive, not global: a tool that leaves
        # ``requires_sanitization`` at its default must keep structured
        # output intact (rewriting it can break downstream parsing).
        async def handler(name: str, params: dict[str, Any]) -> ToolExecutionResult:
            return ToolExecutionResult(output="contact alice@example.com now", error=None)

        tools = SingleTool(
            ToolDefinition(name="fetch", description="", parameters={}),
            handler,
        )
        llm = ScriptedLlm([
            LlmTurnResult(
                type="tool_calls",
                text="",
                tool_calls=[ToolCall(id="tc-raw", name="fetch", args={})],
            ),
            LlmTurnResult(type="text", text="done"),
        ])
        runtime = make_runtime(llm, tools=tools)

        await runtime.run_prompt("fetch it")

        message = next(m for m in runtime.state.messages if isinstance(m, ToolMessage))
        assert "alice@example.com" in message.content
        assert "[REDACTED:EMAIL]" not in message.content


class _RecordingBatchTools(ToolRuntime):
    """Three tools that all succeed, each recording its invocation."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def list_tools(self) -> list[ToolDefinition]:
        return [
            ToolDefinition(name=name, description="", parameters={})
            for name in ("t0", "t1", "t2")
        ]

    async def execute(self, name: str, params: dict[str, Any]) -> ToolExecutionResult:
        self.calls.append(name)
        return ToolExecutionResult(output=f"ok:{name}", error=None)


class TestSuccessfulBatchRunsEachToolExactlyOnce:
    """The success-path cursor commit is at-most-once and forward-only."""

    async def test_each_tool_in_a_clean_batch_runs_exactly_once(self) -> None:
        tools = _RecordingBatchTools()
        llm = ScriptedLlm([
            LlmTurnResult(
                type="tool_calls",
                text="",
                tool_calls=[
                    ToolCall(id="tc-0", name="t0", args={}),
                    ToolCall(id="tc-1", name="t1", args={}),
                    ToolCall(id="tc-2", name="t2", args={}),
                ],
            ),
            LlmTurnResult(type="text", text="done"),
        ])
        runtime = make_runtime(llm, tools=tools)

        await runtime.run_prompt("run all three")

        # Exactly once each, in declaration order. A cursor that rewinds
        # replays a tool (duplicates / IndexError); one that skips ahead
        # drops a tool. Both must fail this assertion.
        assert tools.calls == ["t0", "t1", "t2"]
        tool_messages = [m for m in runtime.state.messages if isinstance(m, ToolMessage)]
        assert [m.tool_call_id for m in tool_messages] == ["tc-0", "tc-1", "tc-2"]


class TestToolInvocationAuditContent:
    """The ``tool_invocation`` record carries the call's identity."""

    async def test_successful_call_audit_records_identity_and_args(self) -> None:
        async def handler(name: str, params: dict[str, Any]) -> ToolExecutionResult:
            return ToolExecutionResult(output="body", error=None)

        tools = SingleTool(
            ToolDefinition(name="search", description="", parameters={}),
            handler,
        )
        llm = ScriptedLlm([
            LlmTurnResult(
                type="tool_calls",
                text="",
                tool_calls=[ToolCall(id="tc-audit", name="search", args={"q": "x"})],
            ),
            LlmTurnResult(type="text", text="done"),
        ])
        runtime = make_runtime(llm, tools=tools)

        await runtime.run_prompt("search")

        invocations = [
            e for e in runtime._audit_log.get_entries() if e.event == "tool_invocation"
        ]
        assert len(invocations) == 1
        entry = invocations[0]
        assert entry.actor == "agent"
        assert entry.tool_name == "search"
        assert entry.tool_call_id == "tc-audit"
        assert entry.decision == "allow"
        assert entry.is_error is False
        assert entry.details["args_keys"] == ["q"]
        assert entry.details["tool_reported_error"] is False


class TestNowIsoIsUtc:
    def test_now_iso_stamps_utc(self) -> None:
        # Audit timestamps must be UTC so records from different hosts line
        # up; dropping the tzinfo still yields a parseable string, so only an
        # explicit offset assertion catches it.
        parsed = datetime.fromisoformat(now_iso())
        assert parsed.utcoffset() == timedelta(0)
