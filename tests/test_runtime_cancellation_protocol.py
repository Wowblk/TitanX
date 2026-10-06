"""Cancellation and host-rejection tool protocol invariants."""

from __future__ import annotations

import asyncio
import copy
from collections import Counter
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from titanx.types import (
    AssistantMessage,
    AssistantToolCallsEvent,
    LoopEndEvent,
    LlmTurnResult,
    PendingApprovalEvent,
    RuntimeHooks,
    ToolCall,
    ToolDefinition,
    ToolExecutionResult,
    ToolMessage,
    ToolResultEvent,
    ToolRuntime,
)
from titanx.safety.safety_layer import SafetyLayer

from ._helpers import ScriptedLlm, make_runtime


ToolHandler = Callable[[str, dict[str, Any]], Awaitable[ToolExecutionResult]]


class _Tools(ToolRuntime):
    def __init__(
        self,
        definitions: list[ToolDefinition],
        handler: ToolHandler,
    ) -> None:
        self._definitions = definitions
        self._handler = handler
        self.calls: list[str] = []

    def list_tools(self) -> list[ToolDefinition]:
        return self._definitions

    async def execute(self, name: str, params: dict[str, Any]) -> ToolExecutionResult:
        self.calls.append(name)
        return await self._handler(name, params)


def _calls(*names: str) -> list[ToolCall]:
    return [
        ToolCall(id=f"tc-{index}", name=name, args={"token": "super-secret"})
        for index, name in enumerate(names, start=1)
    ]


def _assert_closed_once(
    runtime,
    expected_ids: list[str],
    *,
    completed_ids: set[str] | None = None,
) -> list[ToolMessage]:
    messages = [
        message
        for message in runtime.state.messages
        if isinstance(message, ToolMessage)
        and message.tool_call_id in expected_ids
    ]
    assert Counter(message.tool_call_id for message in messages) == Counter(expected_ids)
    completed_ids = completed_ids or set()
    assert all(
        message.is_error
        for message in messages
        if message.tool_call_id not in completed_ids
    )
    assert all("super-secret" not in message.content for message in messages)
    assert runtime.state.pending_approval is None
    assert runtime.state.approved_tool_call_ids == set()
    assert runtime.state.pending_tool_calls == []
    assert runtime.state.pending_tool_call_index == 0
    assert runtime.state.signal == "interrupt"
    return messages


async def _successful_handler(
    name: str,
    params: dict[str, Any],
) -> ToolExecutionResult:
    return ToolExecutionResult(output=f"completed {name}", error=None)


class TestCancellationBatchClosure:
    async def test_cancelling_first_execution_closes_every_call_once(self) -> None:
        started = asyncio.Event()
        never = asyncio.Event()

        async def handler(
            name: str,
            params: dict[str, Any],
        ) -> ToolExecutionResult:
            if name == "first":
                started.set()
                await never.wait()
            return ToolExecutionResult(output="not reached", error=None)

        definitions = [
            ToolDefinition(name=name, description="", parameters={})
            for name in ("first", "second", "third")
        ]
        tools = _Tools(definitions, handler)
        calls = _calls("first", "second", "third")
        runtime = make_runtime(
            ScriptedLlm([LlmTurnResult(type="tool_calls", tool_calls=calls)]),
            tools=tools,
        )

        task = asyncio.create_task(runtime.run_prompt("run batch"))
        await asyncio.wait_for(started.wait(), timeout=1.0)
        runtime.state.approved_tool_call_ids.add("must-be-cleared")
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        _assert_closed_once(runtime, [call.id for call in calls])
        assert tools.calls == ["first"]

        # A fresh user turn is now safe: every result was committed before the
        # new UserMessage, and no cancelled side effect is replayed.
        await runtime.run_prompt("after cancellation")
        new_user_index = max(
            index
            for index, message in enumerate(runtime.state.messages)
            if getattr(message, "role", None) == "user"
        )
        result_indices = [
            index
            for index, message in enumerate(runtime.state.messages)
            if isinstance(message, ToolMessage)
            and message.tool_call_id in {call.id for call in calls}
        ]
        assert result_indices
        assert max(result_indices) < new_user_index
        assert tools.calls == ["first"]

    async def test_assistant_tool_hook_sees_stashed_batch_and_cancel_closes_it(self) -> None:
        calls = _calls("first", "second")
        tools = _Tools(
            [
                ToolDefinition(name=name, description="", parameters={})
                for name in ("first", "second")
            ],
            _successful_handler,
        )

        async def on_event(event, config, state) -> None:
            if isinstance(event, AssistantToolCallsEvent):
                assert state.pending_tool_calls == calls
                assert state.pending_tool_call_index == 0
                raise asyncio.CancelledError()

        runtime = make_runtime(
            ScriptedLlm([LlmTurnResult(type="tool_calls", tool_calls=calls)]),
            tools=tools,
            hooks=RuntimeHooks(on_event=on_event),
        )

        with pytest.raises(asyncio.CancelledError):
            await runtime.run_prompt("declare batch")

        _assert_closed_once(runtime, [call.id for call in calls])
        assert tools.calls == []

    async def test_pending_approval_hook_wait_cancellation_closes_batch(self) -> None:
        entered = asyncio.Event()
        never = asyncio.Event()
        calls = _calls("approval", "later")
        tools = _Tools(
            [
                ToolDefinition(
                    name="approval",
                    description="",
                    parameters={},
                    requires_approval=True,
                ),
                ToolDefinition(name="later", description="", parameters={}),
            ],
            _successful_handler,
        )

        async def on_event(event, config, state) -> None:
            if isinstance(event, PendingApprovalEvent):
                entered.set()
                await never.wait()

        runtime = make_runtime(
            ScriptedLlm([LlmTurnResult(type="tool_calls", tool_calls=calls)]),
            tools=tools,
            hooks=RuntimeHooks(on_event=on_event),
        )
        task = asyncio.create_task(runtime.run_prompt("needs approval"))
        await asyncio.wait_for(entered.wait(), timeout=1.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        _assert_closed_once(runtime, [call.id for call in calls])
        assert tools.calls == []

    async def test_pending_loop_end_hook_wait_cancellation_closes_batch(self) -> None:
        entered = asyncio.Event()
        never = asyncio.Event()
        calls = _calls("approval", "later")
        tools = _Tools(
            [
                ToolDefinition(
                    name="approval",
                    description="",
                    parameters={},
                    requires_approval=True,
                ),
                ToolDefinition(name="later", description="", parameters={}),
            ],
            _successful_handler,
        )

        async def on_event(event, config, state) -> None:
            if isinstance(event, LoopEndEvent) and event.reason == "pending_approval":
                entered.set()
                await never.wait()

        runtime = make_runtime(
            ScriptedLlm([LlmTurnResult(type="tool_calls", tool_calls=calls)]),
            tools=tools,
            hooks=RuntimeHooks(on_event=on_event),
        )
        task = asyncio.create_task(runtime.run_prompt("needs approval"))
        await asyncio.wait_for(entered.wait(), timeout=1.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        _assert_closed_once(runtime, [call.id for call in calls])
        assert tools.calls == []


class TestToolResultHookCancellation:
    async def test_success_event_cancellation_does_not_duplicate_result(self) -> None:
        entered = asyncio.Event()
        never = asyncio.Event()
        calls = _calls("first", "second")
        tools = _Tools(
            [
                ToolDefinition(name=name, description="", parameters={})
                for name in ("first", "second")
            ],
            _successful_handler,
        )

        async def on_event(event, config, state) -> None:
            if isinstance(event, ToolResultEvent) and event.tool_call_id == "tc-1":
                assert state.pending_tool_call_index == 1
                entered.set()
                await never.wait()

        runtime = make_runtime(
            ScriptedLlm([LlmTurnResult(type="tool_calls", tool_calls=calls)]),
            tools=tools,
            hooks=RuntimeHooks(on_event=on_event),
        )
        task = asyncio.create_task(runtime.run_prompt("run tools"))
        await asyncio.wait_for(entered.wait(), timeout=1.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        messages = _assert_closed_once(
            runtime,
            [call.id for call in calls],
            completed_ids={"tc-1"},
        )
        first = next(message for message in messages if message.tool_call_id == "tc-1")
        assert first.content == "completed first"
        assert tools.calls == ["first"]

    async def test_deny_event_cancellation_does_not_duplicate_result(self) -> None:
        entered = asyncio.Event()
        never = asyncio.Event()
        calls = _calls("unknown", "safe")
        tools = _Tools(
            [ToolDefinition(name="safe", description="", parameters={})],
            _successful_handler,
        )

        async def on_event(event, config, state) -> None:
            if isinstance(event, ToolResultEvent) and event.tool_call_id == "tc-1":
                assert state.pending_tool_call_index == 1
                entered.set()
                await never.wait()

        runtime = make_runtime(
            ScriptedLlm([LlmTurnResult(type="tool_calls", tool_calls=calls)]),
            tools=tools,
            hooks=RuntimeHooks(on_event=on_event),
        )
        task = asyncio.create_task(runtime.run_prompt("try denied tool"))
        await asyncio.wait_for(entered.wait(), timeout=1.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        messages = _assert_closed_once(runtime, [call.id for call in calls])
        denied = next(message for message in messages if message.tool_call_id == "tc-1")
        assert "denied by policy" in denied.content
        assert tools.calls == []


class TestHostRejectionPublication:
    async def test_resume_audits_and_emits_synchronous_rejection(self) -> None:
        events: list[object] = []
        calls = [ToolCall(id="tc-reject", name="approval", args={})]
        tools = _Tools(
            [
                ToolDefinition(
                    name="approval",
                    description="",
                    parameters={},
                    requires_approval=True,
                )
            ],
            _successful_handler,
        )

        async def on_event(event, config, state) -> None:
            events.append(event)

        llm = ScriptedLlm([
            LlmTurnResult(type="tool_calls", tool_calls=calls),
            LlmTurnResult(type="text", text="understood"),
        ])
        runtime = make_runtime(
            llm,
            tools=tools,
            hooks=RuntimeHooks(on_event=on_event),
        )

        await runtime.run_prompt("request risky operation")
        assert runtime.state.pending_approval is not None

        reason = "operator denied risky transfer"
        assert runtime.reject_pending_tool(reason) is None
        rejected = [
            message
            for message in runtime.state.messages
            if isinstance(message, ToolMessage)
            and message.tool_call_id == "tc-reject"
        ]
        assert len(rejected) == 1
        assert rejected[0].is_error is True
        assert not any(
            entry.event == "tool_decision"
            and entry.tool_call_id == "tc-reject"
            and entry.decision == "deny"
            for entry in runtime._audit_log.get_entries()
        )

        await runtime.resume()

        final_decisions = [
            entry
            for entry in runtime._audit_log.get_entries()
            if entry.event == "tool_decision"
            and entry.tool_call_id == "tc-reject"
            and entry.decision == "deny"
        ]
        assert len(final_decisions) == 1
        assert final_decisions[0].actor == "host"
        assert final_decisions[0].reason == reason
        result_events = [
            event
            for event in events
            if isinstance(event, ToolResultEvent)
            and event.tool_call_id == "tc-reject"
        ]
        assert len(result_events) == 1
        assert result_events[0].is_error is True
        assert runtime.state.pending_tool_calls == []
        assert runtime.state.pending_tool_call_index == 0
        assert tools.calls == []


class _ExplodingInspectionSafety(SafetyLayer):
    def inspect_tool_output(self, tool_name, output, *, redact_pii=False):
        raise RuntimeError("backend-secret-from-inspection")


class TestPostExecutionCommitPoint:
    async def test_invalid_output_type_is_closed_without_reexecution(self) -> None:
        calls = [ToolCall(id="tc-invalid", name="side_effect", args={})]
        execution_count = 0

        async def handler(name, params):
            nonlocal execution_count
            execution_count += 1
            return ToolExecutionResult(output=object(), error=None)  # type: ignore[arg-type]

        tools = _Tools(
            [ToolDefinition(name="side_effect", description="", parameters={})],
            handler,
        )
        runtime = make_runtime(
            ScriptedLlm([
                LlmTurnResult(type="tool_calls", tool_calls=calls),
                LlmTurnResult(type="text", text="done"),
            ]),
            tools=tools,
        )

        await runtime.run_prompt("perform once")
        await runtime.resume()
        await runtime.run_prompt("next user turn")

        assert execution_count == 1
        results = [
            message
            for message in runtime.state.messages
            if isinstance(message, ToolMessage)
            and message.tool_call_id == "tc-invalid"
        ]
        assert len(results) == 1
        assert results[0].is_error is True
        assert results[0].content == "Tool result processing failed safely."
        assert "object" not in results[0].content

    async def test_tool_reported_error_text_is_not_written_to_audit(self) -> None:
        secret = "stderr-contained-secret-token"
        calls = [ToolCall(id="tc-error-audit", name="side_effect", args={})]

        async def handler(name, params):
            return ToolExecutionResult(output="safe public failure", error=secret)

        tools = _Tools(
            [ToolDefinition(name="side_effect", description="", parameters={})],
            handler,
        )
        runtime = make_runtime(
            ScriptedLlm([
                LlmTurnResult(type="tool_calls", tool_calls=calls),
                LlmTurnResult(type="text", text="done"),
            ]),
            tools=tools,
        )

        await runtime.run_prompt("perform once")

        invocation = next(
            entry
            for entry in runtime._audit_log.get_entries()
            if entry.event == "tool_invocation"
            and entry.tool_call_id == "tc-error-audit"
        )
        assert invocation.is_error is True
        assert invocation.details["tool_reported_error"] is True
        assert secret not in repr(invocation)

    async def test_safety_inspection_failure_is_closed_without_reexecution(self) -> None:
        calls = [ToolCall(id="tc-inspect", name="side_effect", args={})]
        execution_count = 0

        async def handler(name, params):
            nonlocal execution_count
            execution_count += 1
            return ToolExecutionResult(output="untrusted output", error=None)

        tools = _Tools(
            [ToolDefinition(name="side_effect", description="", parameters={})],
            handler,
        )
        runtime = make_runtime(
            ScriptedLlm([
                LlmTurnResult(type="tool_calls", tool_calls=calls),
                LlmTurnResult(type="text", text="done"),
            ]),
            tools=tools,
        )
        runtime._safety = _ExplodingInspectionSafety()

        await runtime.run_prompt("perform once")
        await runtime.resume()

        assert execution_count == 1
        result = next(
            message
            for message in runtime.state.messages
            if isinstance(message, ToolMessage)
            and message.tool_call_id == "tc-inspect"
        )
        assert result.is_error is True
        assert result.content == "Tool result processing failed safely."
        assert "backend-secret" not in result.content
        assert "untrusted output" not in result.content

    async def test_audit_failure_after_return_does_not_replay_tool(self) -> None:
        calls = [ToolCall(id="tc-audit", name="side_effect", args={})]
        execution_count = 0
        runtime = None

        async def handler(name, params):
            nonlocal execution_count
            execution_count += 1
            assert runtime is not None
            # The pre-execution decision audit has already completed. Simulate
            # a sink becoming unavailable exactly after the side effect.
            runtime._audit_log._closed = True
            return ToolExecutionResult(output="completed", error=None)

        tools = _Tools(
            [ToolDefinition(name="side_effect", description="", parameters={})],
            handler,
        )
        runtime = make_runtime(
            ScriptedLlm([
                LlmTurnResult(type="tool_calls", tool_calls=calls),
                LlmTurnResult(type="text", text="done"),
            ]),
            tools=tools,
        )

        await runtime.run_prompt("perform once")
        await runtime.resume()

        assert execution_count == 1
        result = next(
            message
            for message in runtime.state.messages
            if isinstance(message, ToolMessage)
            and message.tool_call_id == "tc-audit"
        )
        assert result.is_error is True
        assert result.content == "Tool result processing failed safely."

    async def test_observer_failure_after_return_does_not_replay_tool(self) -> None:
        calls = [ToolCall(id="tc-hook", name="side_effect", args={})]
        execution_count = 0
        result_event_count = 0

        async def handler(name, params):
            nonlocal execution_count
            execution_count += 1
            return ToolExecutionResult(output="completed", error=None)

        async def on_event(event, config, state) -> None:
            nonlocal result_event_count
            if isinstance(event, ToolResultEvent) and event.tool_call_id == "tc-hook":
                result_event_count += 1
                raise RuntimeError("observer-secret")

        tools = _Tools(
            [ToolDefinition(name="side_effect", description="", parameters={})],
            handler,
        )
        runtime = make_runtime(
            ScriptedLlm([
                LlmTurnResult(type="tool_calls", tool_calls=calls),
                LlmTurnResult(type="text", text="done"),
            ]),
            tools=tools,
            hooks=RuntimeHooks(on_event=on_event),
        )

        await runtime.run_prompt("perform once")
        await runtime.resume()

        assert execution_count == 1
        assert result_event_count >= 1
        results = [
            message
            for message in runtime.state.messages
            if isinstance(message, ToolMessage)
            and message.tool_call_id == "tc-hook"
        ]
        assert len(results) == 1
        assert results[0].is_error is True
        assert results[0].content == "Tool result processing failed safely."
        assert "observer-secret" not in results[0].content


class _CopyBomb:
    copies = 0

    def __deepcopy__(self, memo):
        type(self).copies += 1
        if type(self).copies >= 4:
            raise RuntimeError("copy-secret")
        return type(self)()


class TestToolArgumentIsolation:
    async def test_approval_event_cannot_mutate_pending_dispatch_params(self) -> None:
        source_call = ToolCall(
            id="tc-approval-copy",
            name="dangerous",
            args={"nested": {"items": ["original"]}},
        )

        async def on_event(event, config, state) -> None:
            if isinstance(event, PendingApprovalEvent):
                event.approval.parameters["nested"]["items"].append(
                    "observer-mutation"
                )

        tools = _Tools(
            [ToolDefinition(
                name="dangerous",
                description="",
                parameters={},
                requires_approval=True,
            )],
            _successful_handler,
        )
        runtime = make_runtime(
            ScriptedLlm([
                LlmTurnResult(type="tool_calls", tool_calls=[source_call]),
            ]),
            tools=tools,
            hooks=RuntimeHooks(on_event=on_event),
        )

        await runtime.run_prompt("request approval")

        expected = {"nested": {"items": ["original"]}}
        assert runtime.state.pending_approval is not None
        assert runtime.state.pending_approval.parameters == expected
        assert runtime.state.pending_tool_calls[0].args == expected
        assert source_call.args == expected

    async def test_tool_mutation_cannot_rewrite_history_or_adapter_result(self) -> None:
        source_args = {"nested": {"items": ["original"]}}
        source_call = ToolCall(id="tc-mutate", name="mutator", args=source_args)
        dispatched_snapshot: dict[str, Any] = {}
        history_during_dispatch: dict[str, Any] = {}
        pending_during_dispatch: dict[str, Any] = {}
        runtime = None

        async def handler(name, params):
            assert runtime is not None
            dispatched_snapshot.update(copy.deepcopy(params))
            params["nested"]["items"].append("tool-mutation")
            params["new"] = "tool-only"
            assistant = next(
                message
                for message in reversed(runtime.state.messages)
                if isinstance(message, AssistantMessage) and message.tool_calls
            )
            history_during_dispatch.update(copy.deepcopy(assistant.tool_calls[0].args))
            pending_during_dispatch.update(
                copy.deepcopy(runtime.state.pending_tool_calls[0].args)
            )
            return ToolExecutionResult(output="ok", error=None)

        async def on_event(event, config, state) -> None:
            if isinstance(event, AssistantToolCallsEvent):
                event.tool_calls[0].args["nested"]["items"].append("observer-mutation")

        tools = _Tools(
            [ToolDefinition(name="mutator", description="", parameters={})],
            handler,
        )
        runtime = make_runtime(
            ScriptedLlm([
                LlmTurnResult(type="tool_calls", tool_calls=[source_call]),
                LlmTurnResult(type="text", text="done"),
            ]),
            tools=tools,
            hooks=RuntimeHooks(on_event=on_event),
        )

        await runtime.run_prompt("mutate copy")

        assistant = next(
            message
            for message in runtime.state.messages
            if isinstance(message, AssistantMessage) and message.tool_calls
        )
        expected = {"nested": {"items": ["original"]}}
        assert source_call.args == expected
        assert assistant.tool_calls[0].args == expected
        assert history_during_dispatch == expected
        assert pending_during_dispatch == expected
        assert dispatched_snapshot == expected

    async def test_dispatch_copy_failure_denies_without_executing(self) -> None:
        _CopyBomb.copies = 0
        execution_count = 0

        async def handler(name, params):
            nonlocal execution_count
            execution_count += 1
            return ToolExecutionResult(output="must not run", error=None)

        call = ToolCall(
            id="tc-copy-fail",
            name="dangerous",
            args={"nested": _CopyBomb()},
        )
        tools = _Tools(
            [ToolDefinition(name="dangerous", description="", parameters={})],
            handler,
        )
        runtime = make_runtime(
            ScriptedLlm([
                LlmTurnResult(type="tool_calls", tool_calls=[call]),
                LlmTurnResult(type="text", text="done"),
            ]),
            tools=tools,
        )

        await runtime.run_prompt("do not alias params")

        assert execution_count == 0
        result = next(
            message
            for message in runtime.state.messages
            if isinstance(message, ToolMessage)
            and message.tool_call_id == "tc-copy-fail"
        )
        assert result.is_error is True
        # Non-JSON objects now fail before dispatch-copying is attempted.
        assert result.content == "Tool call denied by policy: invalid_json_value."
        assert "copy-secret" not in result.content
