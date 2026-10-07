"""Archive, recall, task contracts, structured summaries and model budgeting."""
from __future__ import annotations

import asyncio
import json
import sqlite3
from copy import deepcopy
from dataclasses import replace

import pytest
import pytest_asyncio

from titanx import (
    AgentRuntime, CompactionOptions, CompactionStrategy, ContextOptions,
    LlmCompactionStrategy, SQLiteContextStore, TaskState,
)
from titanx.context import CompactionTracking, auto_compact_if_needed
from titanx.context.manager import ContextManager
from titanx.context.store import ContextStore, ContextStoreClosedError
from titanx.safety import SafetyLayer
from titanx.state import create_config
from titanx.types import (
    AgentState, AssistantMessage, LlmAdapter, LlmTurnResult, LlmUsage,
    RuntimeHooks, ToolCall, ToolDefinition, ToolExecutionResult,
    ToolMessage, UserMessage,
)
from ._helpers import NullTools, SingleTool, authorizing_policy_store
from .test_context_compaction import RecordingLlm, RecordingStrategy, assert_complete_tool_groups


@pytest_asyncio.fixture
async def store(tmp_path):
    value = SQLiteContextStore(tmp_path / "context.sqlite")
    yield value
    await value.close()


def runtime_with_store(store, llm, *, tools=None, strategy=None, options=None, context=None, **kwargs):
    events = []
    runtime_tools = tools or NullTools()
    kwargs.setdefault("policy_store", authorizing_policy_store(runtime_tools, include_context=True))
    runtime = AgentRuntime(
        llm, runtime_tools, SafetyLayer(),
        context_options=context or ContextOptions(store, offload_threshold_chars=1500, preview_chars=150),
        compaction_options=options or CompactionOptions(12000, target_token_budget=7000),
        compaction_strategy=strategy or RecordingStrategy(),
        hooks=RuntimeHooks(on_event=lambda event, config, state: events.append(event)),
        **kwargs,
    )
    return runtime, events


async def test_originals_and_task_survive_reopening_sqlite(tmp_path):
    path = tmp_path / "context.sqlite"
    store = SQLiteContextStore(path)
    message = UserMessage(role="user", content="原文：精确值 9182")
    task = TaskState("preserve exact values", constraints=("read only",))
    await store.archive("session", [message])
    await store.archive("session", [replace(message, content="replacement view")])
    await store.save_task("session", task)
    artifact = await store.put_artifact("session", "中\x00文\nTAIL=9182")
    await store.close()
    reopened = SQLiteContextStore(path)
    try:
        result = await reopened.read("session", "message", message.id)
        assert json.loads(result.content)["content"] == message.content
        assert await reopened.load_task("session") == task
        chunks, offset = [], 0
        while True:
            page = await reopened.read("session", "artifact", artifact, offset, 2)
            chunks.append(page.content)
            if page.next_offset is None:
                break
            offset = page.next_offset
        assert "".join(chunks) == "中\x00文\nTAIL=9182"
    finally:
        await reopened.close()


async def test_search_is_literal_paged_and_session_scoped(store):
    messages = [UserMessage(role="user", content=f"value %_ item {i}") for i in range(3)]
    await store.archive("a", messages)
    await store.archive("b", [UserMessage(role="user", content="value %_ private")])
    first = await store.search("a", "%_", limit=2)
    second = await store.search("a", "%_", after=first[-1]["cursor"], limit=2)
    assert [r["message_id"] for r in first + second] == [m.id for m in messages]
    assert await store.search("a", "' OR 1=1 --") == []
    with pytest.raises(LookupError):
        await store.read("b", "message", messages[0].id)
    artifact = await store.put_artifact("a", "content")
    with pytest.raises(LookupError):
        await store.read("b", "artifact", artifact)
    await store.delete_session("a")
    assert await store.search("a", "%_") == []
    assert len(await store.search("b", "%_")) == 1


async def test_operation_after_close_raises_context_store_closed_error(tmp_path):
    """A closed store fails fast with a typed, catchable error."""
    store = SQLiteContextStore(tmp_path / "context.sqlite")
    message = UserMessage(role="user", content="after close")
    await store.archive("session", [message])

    await store.close()
    await store.close()  # close is idempotent

    with pytest.raises(ContextStoreClosedError):
        await store.archive("session", [message])
    with pytest.raises(ContextStoreClosedError):
        await store.search("session", "after")


async def test_closed_error_is_exported_and_legacy_catchable(tmp_path):
    """The typed error is reachable from the package and keeps the old contract.

    Hosts were told to catch ``ContextStoreClosedError``; that is only
    actionable if it is importable, and it must remain a ``sqlite3.
    ProgrammingError`` so existing handlers keyed on the driver error keep
    matching.
    """
    from titanx import ContextStoreClosedError as Exported

    assert Exported is ContextStoreClosedError
    assert issubclass(ContextStoreClosedError, sqlite3.ProgrammingError)

    store = SQLiteContextStore(tmp_path / "context.sqlite")
    await store.close()
    with pytest.raises(sqlite3.ProgrammingError):
        await store.archive("session", [UserMessage(role="user", content="x")])


def test_context_store_base_declares_the_full_interface():
    # §5.4: list_compactions/delete_session/close lived only on the concrete
    # store, so the base interface could not be implemented or duck-typed
    # against. The base must declare the whole contract the runtime and
    # gateway teardown rely on.
    required = {
        "archive", "put_artifact", "read", "search", "commit_compaction",
        "list_compactions", "save_task", "load_task", "delete_session", "close",
    }
    assert required <= set(dir(ContextStore))
    assert required <= set(dir(SQLiteContextStore))


async def test_cancelled_operation_does_not_wedge_store(tmp_path):
    """A cancelled/timed-out caller must leave the store usable and closeable."""
    store = SQLiteContextStore(tmp_path / "context.sqlite")
    message = UserMessage(role="user", content="survives cancellation")

    # Start the operation, let it reach the worker thread, then cancel the
    # awaiting coroutine (the shape of a ContextManager._wait timeout).
    task = asyncio.create_task(store.archive("session", [message]))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # The store must not be wedged: later work still commits and is readable.
    await store.archive("session", [message])
    page = await store.read("session", "message", message.id)
    assert json.loads(page.content)["content"] == message.content
    await store.close()


async def test_offload_and_model_recall_do_not_rerun_original_tool(store):
    executions = []
    output = "log row\n" * 2000 + "TAIL_VALUE=9182"

    async def execute(name, params):
        executions.append(name)
        return ToolExecutionResult(output=output)

    class RecallLlm(LlmAdapter):
        def __init__(self):
            self.inputs = []

        async def respond(self, config, state):
            self.inputs.append(deepcopy(state))
            if len(self.inputs) == 1:
                return LlmTurnResult(type="tool_calls", tool_calls=[ToolCall("read-1", "logs", {})])
            if len(self.inputs) == 2:
                tool_message = next(m for m in state.messages if isinstance(m, ToolMessage))
                assert len(tool_message.content) < 1500
                return LlmTurnResult(type="tool_calls", tool_calls=[ToolCall("recall-1", "context_read", {
                    "kind": "artifact", "id": tool_message.artifact_id,
                    "offset": len(output) - 100, "limit": 100,
                })])
            result = next(m for m in reversed(state.messages) if isinstance(m, ToolMessage))
            assert "TAIL_VALUE=9182" in result.content
            return LlmTurnResult(type="text", text="9182")

    llm = RecallLlm()
    tool = SingleTool(ToolDefinition("logs", "Read logs", {}), execute)
    runtime, events = runtime_with_store(store, llm, tools=tool)
    await runtime.run_prompt("Find the exact value at the end of the logs")

    assert runtime.state.last_text_response == "9182"
    assert executions == ["logs"]
    assert len(llm.inputs) == 3
    assert sum(e.type == "context_offloaded" for e in events) == 1
    assert_complete_tool_groups(runtime.state.messages)
    tool_message = next(m for m in runtime.state.messages if isinstance(m, ToolMessage))
    archived = await store.read(runtime.config.session_id, "message", tool_message.id, 0, 16000)
    assert "archived_tool_output" not in archived.content
    assert "log row" in archived.content


async def test_compaction_archives_originals_and_lineage_before_replacement(store):
    state = AgentState(messages=[UserMessage(role="user", content="old exact value=4567"),
                                 UserMessage(role="user", content="latest")], needs_compaction=True)
    original = deepcopy(state.messages)
    config = create_config()
    result = await auto_compact_if_needed(state, RecordingStrategy(), CompactionOptions(3000, min_recent_messages=1),
                                         CompactionTracking(), config=config, store=store)
    assert result.was_compacted
    assert original[0].id not in [m.id for m in state.messages]
    page = await store.read(config.session_id, "message", original[0].id)
    assert "4567" in page.content
    records = await store.list_compactions(config.session_id)
    assert records[0]["source_message_ids"] == [original[0].id]
    assert records[0]["id"] == state.messages[0].id


async def test_failed_compaction_archive_keeps_original_state(store):
    async def fail(*args):
        raise OSError("disk unavailable")
    store.commit_compaction = fail
    state = AgentState(messages=[UserMessage(role="user", content="old " * 1000),
                                 UserMessage(role="user", content="latest")])
    before = deepcopy(state)
    result = await auto_compact_if_needed(state, RecordingStrategy(), CompactionOptions(3000, min_recent_messages=1),
                                         CompactionTracking(), config=create_config(), store=store)
    assert result.blocked_reason == "context_storage_failed"
    assert state == before


async def test_storage_error_supersedes_earlier_summary_retry_error(store):
    class RetryOnce(RecordingStrategy):
        async def summarize(self, messages):
            if not self.inputs:
                self.inputs.append([])
                raise ValueError("first summary failed")
            return await super().summarize(messages)
    async def fail(*args):
        raise OSError("disk unavailable")
    store.commit_compaction = fail
    state = AgentState(messages=[UserMessage(role="user", content="large " * 1000),
                                 UserMessage(role="user", content="small"),
                                 UserMessage(role="user", content="latest")])
    result = await auto_compact_if_needed(state, RetryOnce(), CompactionOptions(3000, min_recent_messages=1),
                                         CompactionTracking(), config=create_config(), store=store)
    assert result.blocked_reason == result.failure_reason == "context_storage_failed"


def test_task_constraints_iterable_is_not_consumed_during_validation():
    task = TaskState("objective", constraints=(value for value in ("first", "second")))
    assert task.constraints == ("first", "second")
    with pytest.raises(ValueError):
        TaskState("objective", constraints="not a sequence of constraints")


async def test_storage_failure_then_explicit_recovery_does_not_replay_tool(store):
    executions = []
    original_put = store.put_artifact

    async def fail(*args):
        raise OSError("disk unavailable")

    async def execute(name, params):
        executions.append(name)
        return ToolExecutionResult(output="large " * 2000)

    store.put_artifact = fail
    llm = RecordingLlm([
        LlmTurnResult(type="tool_calls", tool_calls=[ToolCall("a", "logs", {})]),
        LlmTurnResult(type="text", text="recovered"),
    ])
    runtime, events = runtime_with_store(store, llm, tools=SingleTool(ToolDefinition("logs", "", {}), execute))
    await runtime.run_prompt("Read logs")
    assert len(llm.inputs) == 1
    assert events[-1].reason == "context_storage_failed"
    assert len(runtime.state.messages[-1].content) == 12000
    assert runtime.state.messages[-1].artifact_id is None
    store.put_artifact = original_put
    await runtime.retry_context()
    assert executions == ["logs"]
    assert len(llm.inputs) == 2
    assert runtime.state.last_text_response == "recovered"


async def test_storage_timeout_stops_before_model_and_cancels_io(store):
    cancelled = asyncio.Event()
    async def hang(*args):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()
    store.archive = hang
    llm = RecordingLlm([LlmTurnResult(type="text", text="unexpected")])
    runtime, events = runtime_with_store(store, llm, context=ContextOptions(store, storage_timeout_seconds=0.01))
    await runtime.run_prompt("hello")
    assert not llm.inputs
    assert cancelled.is_set()
    assert events[-1].reason == "context_storage_failed"
    assert runtime.state.messages[0].content == "hello"


async def test_final_archive_recovery_does_not_call_model_again(store):
    archive = store.archive
    async def fail_final(session, messages):
        if messages[-1].role == "assistant":
            raise OSError("final write failed")
        await archive(session, messages)
    store.archive = fail_final
    llm = RecordingLlm([LlmTurnResult(type="text", text="finished answer")])
    runtime, events = runtime_with_store(store, llm)
    await runtime.run_prompt("hello")
    assert runtime.state.last_text_response == "finished answer"
    assert events[-1].reason == "context_storage_failed"
    assert not any(e.type == "loop_end" and e.reason == "completed" for e in events)
    # A second failed save must remain recoverable too.
    await runtime.retry_context()
    assert events[-1].reason == "context_storage_failed"
    store.archive = archive
    await runtime.retry_context()
    assert len(llm.inputs) == 1
    assert runtime.state.signal == "stop"
    assert events[-1].reason == "completed"
    saved = await store.read(runtime.config.session_id, "message", runtime.state.messages[-1].id)
    assert "finished answer" in saved.content


async def test_cancellation_during_offload_preserves_original_tool_result(store):
    started = asyncio.Event()
    async def hang(*args):
        started.set()
        await asyncio.Event().wait()
    put = store.put_artifact
    store.put_artifact = hang
    state = AgentState(messages=[ToolMessage(role="tool", content="large " * 2000,
                                           tool_call_id="one", tool_name="logs")])
    before = deepcopy(state)
    manager = ContextManager(ContextOptions(store), create_config())
    # Threshold comparison is strict, so use a lower limit for this fixture.
    manager.options.offload_threshold_chars = 2000
    running = asyncio.create_task(manager.prepare(state))
    await asyncio.wait_for(started.wait(), 1)
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running
    assert state == before
    store.put_artifact = put


async def test_current_task_survives_uninformative_summary_and_explicit_revision(store):
    llm = RecordingLlm([LlmTurnResult(type="text", text="one"), LlmTurnResult(type="text", text="two")])
    runtime, _ = runtime_with_store(store, llm)
    first = runtime.set_task("Review the code", constraints=("Do not edit files",), acceptance_criteria=("Cite file names",))
    runtime.state.messages = [UserMessage(role="user", content="initial request"),
                              *[AssistantMessage(role="assistant", content=f"observation {i}") for i in range(8)]]
    runtime.state.needs_compaction = True
    await runtime.run_prompt("continue")
    assert llm.inputs[0][0].id == f"task:{first.id}:1"
    assert "Do not edit files" in llm.inputs[0][0].content
    assert runtime.state.task == first
    assert all(not m.id.startswith("task:") for m in runtime.state.messages)
    runtime.set_task("Implement the approved change", constraints=("Keep public signatures",))
    await runtime.run_prompt("updated goal")
    assert "Do not edit files" not in llm.inputs[1][0].content
    assert "Keep public signatures" in llm.inputs[1][0].content
    assert runtime.state.task.revision == 2
    assert runtime.state.task.id == first.id


async def test_task_change_cannot_skip_waiting_approval(store):
    async def execute(name, params):
        return ToolExecutionResult(output="done")
    tool = SingleTool(ToolDefinition("approval", "", {}, requires_approval=True), execute)
    llm = RecordingLlm([LlmTurnResult(type="tool_calls", tool_calls=[ToolCall("a", "approval", {})])])
    runtime, _ = runtime_with_store(store, llm, tools=tool)
    await runtime.run_prompt("original goal")
    before = deepcopy(runtime.state)
    with pytest.raises(RuntimeError):
        runtime.set_task("changed goal")
    assert runtime.state == before


class JsonSummaryLlm(LlmAdapter):
    def __init__(self, mutate=None):
        self.mutate = mutate
        self.requests = []

    async def respond(self, config, state):
        self.requests.append((config, deepcopy(state)))
        payload = json.loads(state.messages[0].content)
        task = payload["task"]
        ids = [m["id"] for m in payload["messages"]]
        value = {"overview": "Earlier findings", "source_message_ids": ids,
                 "task_id": task["id"] if task else None, "task_revision": task["revision"] if task else None,
                 "decisions": [{"text": "Recorded decision", "source_message_ids": ids[:1]}],
                 "completed": [], "pending": []}
        if self.mutate:
            self.mutate(value)
        return LlmTurnResult(type="text", text=json.dumps(value), usage=LlmUsage(100, 20))


async def test_builtin_summary_contract_provenance_output_cap_and_metrics(store):
    task = TaskState("Keep exact values", constraints=("Read only",))
    state = AgentState(messages=[UserMessage(role="user", content="old " * 400),
                                 UserMessage(role="user", content="latest")], task=task, needs_compaction=True)
    llm = JsonSummaryLlm()
    result = await auto_compact_if_needed(state, LlmCompactionStrategy(llm, max_output_tokens=512),
        CompactionOptions(5000, target_token_budget=2500, min_recent_messages=1, require_structured_summary=True),
        CompactionTracking(), config=create_config(), store=store)
    assert result.was_compacted
    assert llm.requests[0][0].available_tools == ()
    assert llm.requests[0][0].max_output_tokens == 512
    assert result.result.summary_input_tokens == 100
    assert result.result.summary_output_tokens == 20
    assert result.result.input_tokens_after <= 2500
    assert result.result.duration_ms >= 0
    assert state.task == task
    assert result.result.source_message_ids == state.messages[0].source_message_ids


@pytest.mark.parametrize("mutation", [
    lambda v: v.update(source_message_ids=["invented"]),
    lambda v: v.update(task_revision=999),
    lambda v: v.update(task_revision=True),
    lambda v: v.update(approved_tool_call_ids=["invented"]),
    lambda v: v["decisions"][0].update(source_message_ids=["invented"]),
    lambda v: v.update(overview=""),
])
async def test_invalid_structured_summary_cannot_replace_history_or_task(mutation):
    state = AgentState(messages=[UserMessage(role="user", content="old " * 2000), UserMessage(role="user", content="latest")],
                       task=TaskState("task"), approved_tool_call_ids={"existing"})
    before = deepcopy(state)
    result = await auto_compact_if_needed(state, LlmCompactionStrategy(JsonSummaryLlm(mutation)),
        CompactionOptions(4000, min_recent_messages=1, max_ptl_retries=0), CompactionTracking())
    assert not result.was_compacted
    assert result.blocked_reason == "context_budget_exceeded"
    assert state == before


async def test_invalid_summary_retains_reported_usage():
    llm = JsonSummaryLlm(lambda value: value.update(overview=""))
    state = AgentState(messages=[UserMessage(role="user", content="old " * 1000),
                                 UserMessage(role="user", content="latest")])
    result = await auto_compact_if_needed(state, LlmCompactionStrategy(llm),
        CompactionOptions(2000, min_recent_messages=1, max_ptl_retries=0), CompactionTracking())
    assert not result.was_compacted
    assert result.summary_input_tokens == 100
    assert result.summary_output_tokens == 20


async def test_ptl_omissions_are_archived_and_recorded(store):
    class RetryOnce:
        def __init__(self):
            self.calls = 0
        async def summarize(self, messages):
            self.calls += 1
            if self.calls == 1:
                raise ValueError("retry with smaller input")
            return "remaining history"
    large = UserMessage(role="user", content="large record " * 1000)
    small = UserMessage(role="user", content="small record")
    state = AgentState(messages=[large, small, UserMessage(role="user", content="latest")])
    config = create_config()
    result = await auto_compact_if_needed(state, RetryOnce(), CompactionOptions(3000, min_recent_messages=1),
                                         CompactionTracking(), config=config, store=store)
    assert result.was_compacted
    assert result.result.omitted_message_ids == (large.id,)
    assert result.result.source_message_ids == (small.id,)
    record = (await store.list_compactions(config.session_id))[0]
    assert record["omitted_message_ids"] == [large.id]
    assert "large record" in (await store.read(config.session_id, "message", large.id)).content


async def test_three_compactions_keep_task_and_recall_exact_original_evidence(store):
    original = UserMessage(role="user", content="authoritative result: ANSWER=9182")
    state = AgentState(messages=[original], task=TaskState("Report exact result", constraints=("read only",)))
    config = create_config()
    previous_summary_id = None
    for i in range(3):
        state.messages.extend([AssistantMessage(role="assistant", content="observations " * 100),
                               UserMessage(role="user", content=f"continue {i}")])
        state.needs_compaction = True
        result = await auto_compact_if_needed(state, LlmCompactionStrategy(JsonSummaryLlm()),
            CompactionOptions(6000, target_token_budget=2500, min_recent_messages=1),
            CompactionTracking(), config=config, store=store)
        assert result.was_compacted
        summaries = [m for m in state.messages if getattr(m, "is_summary", False)]
        assert len(summaries) == 1
        if previous_summary_id:
            assert previous_summary_id in summaries[0].source_message_ids
        previous_summary_id = summaries[0].id
        assert state.task.constraints == ("read only",)
    # The deliberately generic summary loses the exact value; archive recall
    # must still recover it after three generations, without guessing.
    matches = await store.search(config.session_id, "ANSWER=9182")
    assert matches[0]["message_id"] == original.id
    page = await store.read(config.session_id, "message", matches[0]["message_id"])
    assert "ANSWER=9182" in page.content
    assert len(await store.list_compactions(config.session_id)) == 3


async def test_context_read_still_obeys_policy_denial(store):
    from titanx.policy import AgentPolicy, PolicyStore
    async def unexpected_read(*args):
        pytest.fail("denied context tool reached storage")
    store.read = unexpected_read
    llm = RecordingLlm([
        LlmTurnResult(type="tool_calls", tool_calls=[ToolCall("read", "context_read", {"kind": "message", "id": "example"})]),
        LlmTurnResult(type="text", text="denied"),
    ])
    runtime, _ = runtime_with_store(store, llm, policy_store=PolicyStore(AgentPolicy(tool_denylist=["context_read"])))
    await runtime.run_prompt("read history")
    result = next(m for m in runtime.state.messages if isinstance(m, ToolMessage))
    assert result.is_error
    assert "denied by policy" in result.content


async def test_factory_wires_builtin_summary_and_explicit_counter(store):
    from titanx import CreateSandboxedRuntimeOptions, create_sandboxed_runtime
    class CombinedLlm(JsonSummaryLlm):
        def count_input_tokens(self, config, messages):
            pytest.fail("explicit estimator must take precedence")
        async def respond(self, config, state):
            if not config.available_tools:
                return await super().respond(config, state)
            return LlmTurnResult(type="text", text="factory done")
    llm = CombinedLlm()
    runtime = create_sandboxed_runtime(CreateSandboxedRuntimeOptions(
        llm=llm, safety=SafetyLayer(),
        context_options=ContextOptions(store, session_id="host-session"),
        compaction_options=CompactionOptions(1000, token_estimator=lambda config, messages: 100, min_recent_messages=1),
    ))
    runtime.state.messages = [UserMessage(role="user", content="old history")]
    runtime.state.needs_compaction = True
    await runtime.run_prompt("continue")
    assert runtime.config.session_id == "host-session"
    assert len(llm.requests) == 1
    assert runtime.state.last_text_response == "factory done"


async def test_summary_timeout_is_bounded_and_preserves_state():
    cancelled = asyncio.Event()
    class SlowSummary(CompactionStrategy):
        async def summarize(self, messages):
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()
    state = AgentState(messages=[UserMessage(role="user", content="old " * 500), UserMessage(role="user", content="latest")])
    before = deepcopy(state)
    result = await auto_compact_if_needed(state, SlowSummary(),
        CompactionOptions(1000, min_recent_messages=1, max_ptl_retries=0, summary_timeout_seconds=0.01), CompactionTracking())
    assert cancelled.is_set()
    assert result.failure_reason == "summary_timeout"
    assert result.blocked_reason == "context_budget_exceeded"
    assert state == before


async def test_compression_target_is_lower_than_trigger():
    class MediumSummary(CompactionStrategy):
        async def summarize(self, messages):
            return "x" * 600
    state = AgentState(messages=[UserMessage(role="user", content="old " * 500), UserMessage(role="user", content="latest")])
    result = await auto_compact_if_needed(state, MediumSummary(),
        CompactionOptions(1000, target_token_budget=400, min_recent_messages=1, max_ptl_retries=0), CompactionTracking())
    assert not result.was_compacted
    assert result.failure_reason == "summary_target_not_reached"


async def test_runtime_prefers_adapter_counter_and_keeps_output_reserve_in_budget():
    class CountingLlm(RecordingLlm):
        def __init__(self):
            super().__init__([LlmTurnResult(type="text", text="done")])
            self.counted = []
        def count_input_tokens(self, config, messages):
            self.counted.append((config, deepcopy(messages)))
            return 10
    llm = CountingLlm()
    options = CompactionOptions(1000, model_context_window=100, reserved_output_tokens=20, safety_margin_tokens=10)
    runtime = AgentRuntime(llm, NullTools(), SafetyLayer(), compaction_strategy=RecordingStrategy(), compaction_options=options)
    runtime.set_task("current task")
    await runtime.run_prompt("new user input")
    assert options.input_budget == 70
    # reserved_output_tokens is a compaction input-budget reservation only; it
    # must never be smuggled into the provider generation cap on AgentConfig.
    assert llm.counted[0][0].max_output_tokens is None
    assert llm.counted[0][1] == llm.inputs[0]
    assert any("current task" in m.content for m in llm.counted[0][1])


async def test_runtime_forwards_host_max_output_tokens_to_adapter():
    class CountingLlm(RecordingLlm):
        def __init__(self):
            super().__init__([LlmTurnResult(type="text", text="done")])
            self.counted = []
        def count_input_tokens(self, config, messages):
            self.counted.append((config, deepcopy(messages)))
            return 10
    llm = CountingLlm()
    options = CompactionOptions(1000, model_context_window=100, reserved_output_tokens=20, safety_margin_tokens=10)
    runtime = AgentRuntime(
        llm, NullTools(), SafetyLayer(),
        compaction_strategy=RecordingStrategy(), compaction_options=options,
        max_output_tokens=42,
    )
    runtime.set_task("current task")
    await runtime.run_prompt("new user input")
    assert options.input_budget == 70
    assert llm.counted[0][0].max_output_tokens == 42


def test_create_config_rejects_invalid_max_output_tokens():
    assert create_config().max_output_tokens is None
    assert create_config(max_output_tokens=0).max_output_tokens == 0
    assert create_config(max_output_tokens=128).max_output_tokens == 128
    with pytest.raises(ValueError):
        create_config(max_output_tokens=-1)
    with pytest.raises(ValueError):
        create_config(max_output_tokens=True)


async def test_context_tool_cannot_select_session_or_request_unbounded_page(store):
    config = create_config()
    manager = ContextManager(ContextOptions(store, read_max_chars=100), config)
    artifact = await store.put_artifact(config.session_id, "value" * 1000)
    with pytest.raises(ValueError):
        await manager.execute("context_read", {"kind": "artifact", "id": artifact, "session_id": "other"})
    result = await manager.execute("context_read", {"kind": "artifact", "id": artifact, "limit": 100000})
    page = json.loads(result.output)
    assert len(page["content"]) == 100
    assert page["next_offset"] == 100


def test_context_read_schema_max_matches_configured_read_max_chars(store):
    # §5.4: the schema advertised ``maximum: 16000`` while execute silently
    # clamped to ``read_max_chars`` (default 4000), so the advertised contract
    # disagreed with the effective cap. The schema must reflect the real bound.
    runtime, _ = runtime_with_store(
        store, RecordingLlm([]),
        context=ContextOptions(store, read_max_chars=1234),
    )
    definition = next(
        tool for tool in runtime.config.available_tools if tool.name == "context_read"
    )
    assert definition.parameters["properties"]["limit"]["maximum"] == 1234


async def test_runtime_context_read_uses_configured_cap_end_to_end(store):
    # The runtime derives the context tool catalog twice — at construction and
    # again when re-checking the contract before dispatch. If the second path
    # used a different cap, every context_read would fail with
    # tool_contract_changed. Drive a real call through the runtime to pin it.
    output = "log row\n" * 2000 + "TAIL_VALUE=9182"

    async def execute(name, params):
        return ToolExecutionResult(output=output)

    class RecallLlm(LlmAdapter):
        def __init__(self):
            self.calls = 0

        async def respond(self, config, state):
            self.calls += 1
            if self.calls == 1:
                return LlmTurnResult(type="tool_calls", tool_calls=[ToolCall("read-1", "logs", {})])
            if self.calls == 2:
                tm = next(m for m in state.messages if isinstance(m, ToolMessage))
                return LlmTurnResult(type="tool_calls", tool_calls=[ToolCall("recall-1", "context_read", {
                    "kind": "artifact", "id": tm.artifact_id, "limit": 1234,
                })])
            return LlmTurnResult(type="text", text="done")

    tool = SingleTool(ToolDefinition("logs", "Read logs", {}), execute)
    runtime, _ = runtime_with_store(
        store, RecallLlm(), tools=tool,
        context=ContextOptions(
            store, offload_threshold_chars=1500, preview_chars=150, read_max_chars=1234,
        ),
    )
    await runtime.run_prompt("recall the tail")

    recall = next(
        m for m in runtime.state.messages
        if isinstance(m, ToolMessage) and m.tool_name == "context_read"
    )
    page = json.loads(recall.content)
    assert page["next_offset"] == 1234  # the configured cap applies, not 16000


async def test_offload_preserves_wrapper_and_only_archives_inspected_output(store):
    async def execute(name, params):
        return ToolExecutionResult(output="raw output")
    class InspectingSafety(SafetyLayer):
        def inspect_tool_output(self, tool_name, output, *, redact_pii=False):
            from titanx.types import ToolOutputSafetyResult
            return ToolOutputSafetyResult("safe content " * 400, [], False)
    llm = RecordingLlm([LlmTurnResult(type="tool_calls", tool_calls=[ToolCall("a", "logs", {})]),
                        LlmTurnResult(type="text", text="done")])
    tools = SingleTool(ToolDefinition("logs", "", {}), execute)
    runtime = AgentRuntime(llm, tools, InspectingSafety(),
                           context_options=ContextOptions(store, offload_threshold_chars=2000, preview_chars=50),
                           wrap_tool_output=True,
                           policy_store=authorizing_policy_store(tools, include_context=True))
    await runtime.run_prompt("read")
    message = next(m for m in runtime.state.messages if isinstance(m, ToolMessage))
    assert message.content.startswith('<tool_output tool="logs" trust="untrusted">')
    assert message.content.endswith("</tool_output>")
    page = await store.read(runtime.config.session_id, "artifact", message.artifact_id, limit=16000)
    assert "raw output" not in page.content
    assert "safe content" in page.content


@pytest.mark.parametrize("kwargs", [
    {"target_token_budget": 1000}, {"target_token_budget": 0},
    {"summary_timeout_seconds": 0}, {"summary_timeout_seconds": float("inf")},
    {"model_context_window": 100, "reserved_output_tokens": 100}, {"safety_margin_tokens": -1},
])
def test_invalid_budget_and_timeout_configuration(kwargs):
    with pytest.raises(ValueError):
        CompactionOptions(token_budget=1000, **kwargs)
