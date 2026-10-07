"""Compaction must merge old summaries and check the next model request."""

from copy import deepcopy

import asyncio
import pytest

from titanx.context import (
    CompactionOptions,
    CompactionStrategy,
    CompactionTracking,
    auto_compact_if_needed,
    estimate_input_tokens,
)
from titanx.state import create_config
from titanx.runtime import AgentRuntime
from titanx.safety.safety_layer import SafetyLayer
from titanx.types import (
    AgentState,
    AssistantMessage,
    LlmTurnResult,
    LlmUsage,
    RuntimeHooks,
    SystemMessage,
    ToolCall,
    ToolDefinition,
    ToolExecutionResult,
    ToolMessage,
    UserMessage,
)

from ._helpers import NullTools, ScriptedLlm, SingleTool, authorizing_policy_store


class RecordingStrategy(CompactionStrategy):
    def __init__(self):
        self.inputs = []

    async def summarize(self, messages):
        self.inputs.append(deepcopy(messages))
        return f"merged history {len(self.inputs)}"


class RecordingLlm(ScriptedLlm):
    def __init__(self, responses):
        super().__init__(responses)
        self.inputs = []

    async def respond(self, config, state):
        self.inputs.append(deepcopy(state.messages))
        return await super().respond(config, state)


def make_compacting_runtime(
    llm, strategy, *, budget=2500, tools=None, options=None, auto_approve_tools=True, **kwargs,
):
    events = []
    runtime_tools = tools or NullTools()
    kwargs.setdefault(
        "policy_store",
        authorizing_policy_store(runtime_tools, auto_approve_tools=auto_approve_tools),
    )
    runtime = AgentRuntime(
        llm=llm, tools=runtime_tools, safety=SafetyLayer(),
        compaction_strategy=strategy,
        compaction_options=options or CompactionOptions(token_budget=budget, min_recent_messages=2),
        hooks=RuntimeHooks(on_event=lambda event, config, state: events.append(event)),
        auto_approve_tools=auto_approve_tools, **kwargs,
    )
    return runtime, events


async def test_repeated_compaction_merges_previous_summary_without_accumulating():
    original_system = SystemMessage(role="system", content="Keep the original instructions.")
    state = AgentState(messages=[original_system])
    strategy = RecordingStrategy()
    options = CompactionOptions(token_budget=10000, min_recent_messages=2)
    tracking = CompactionTracking()

    for round_number in range(1, 4):
        state.messages.extend(UserMessage(role="user", content=f"round {round_number}: {i}") for i in range(4))
        tail = state.messages[-2:]
        state.needs_compaction = True
        outcome = await auto_compact_if_needed(state, strategy, options, tracking)
        tracking = outcome.tracking

        assert outcome.was_compacted
        summaries = [m for m in state.messages if m.content.startswith("[Conversation summary so far]\n")]
        assert len(summaries) == 1
        assert state.messages[0] is original_system
        assert state.messages[-2:] == tail
        if round_number > 1:
            assert any(f"merged history {round_number - 1}" in m.content for m in strategy.inputs[-1])


async def test_first_oversized_user_prompt_stops_before_model_call():
    llm = RecordingLlm([LlmTurnResult(type="text", text="must not be called")])
    runtime, events = make_compacting_runtime(llm, RecordingStrategy(), budget=1000)

    await runtime.run_prompt("request " * 300)

    assert llm.inputs == []
    assert runtime.state.signal == "stop"
    assert events[-1].reason == "context_budget_exceeded"
    assert runtime.state.messages[-1].content == "request " * 300


async def test_new_tool_output_is_compacted_before_next_model_call():
    async def execute(name, params):
        return ToolExecutionResult(output="data " * 200)

    tool = SingleTool(ToolDefinition(name="read_data", description="Read data", parameters={}), execute)
    llm = RecordingLlm([
        LlmTurnResult(type="tool_calls", tool_calls=[ToolCall(id="read-1", name="read_data", args={})],
                      usage=LlmUsage(input_tokens=10, output_tokens=1)),
        LlmTurnResult(type="text", text="done"),
    ])
    strategy = RecordingStrategy()
    runtime, _ = make_compacting_runtime(llm, strategy, tools=tool)
    runtime.state.messages = [UserMessage(role="user", content="history " * 150),
                              AssistantMessage(role="assistant", content="previous answer")]

    await runtime.run_prompt("read the data")

    assert len(llm.inputs) == 2
    assert len(strategy.inputs) == 1
    assert all(estimate_input_tokens(runtime.config, messages) < 2500 for messages in llm.inputs)
    assert not any("history " * 150 == m.content for m in llm.inputs[1])
    assert any(isinstance(m, ToolMessage) and m.content == "data " * 200 for m in llm.inputs[1])


async def test_missing_usage_still_checks_new_tool_output_and_preserves_protocol():
    async def execute(name, params):
        return ToolExecutionResult(output="data " * 1000)

    tool = SingleTool(ToolDefinition(name="read_data", description="Read data", parameters={}), execute)
    llm = RecordingLlm([
        LlmTurnResult(type="tool_calls", tool_calls=[ToolCall(id="read-1", name="read_data", args={})]),
        LlmTurnResult(type="text", text="must not be called"),
    ])
    runtime, events = make_compacting_runtime(llm, RecordingStrategy(), tools=tool)

    await runtime.run_prompt("read the data")

    assert len(llm.inputs) == 1
    assert events[-1].reason == "context_budget_exceeded"
    declarations = [m for m in runtime.state.messages if isinstance(m, AssistantMessage) and m.tool_calls]
    results = [m for m in runtime.state.messages if isinstance(m, ToolMessage)]
    assert [m.tool_call_id for m in results] == [c.id for m in declarations for c in m.tool_calls]
    assert results[0].content == "data " * 1000


async def test_legacy_summaries_merge_even_without_eligible_body_messages():
    prefix = "[Conversation summary so far]\n"
    original = SystemMessage(role="system", content=f"{prefix}host instructions", is_summary=False)
    legacy = [SystemMessage(role="system", content=f"{prefix}legacy {i}") for i in range(2)]
    state = AgentState(messages=[original, *legacy, UserMessage(role="user", content="latest")],
                       needs_compaction=True)
    strategy = RecordingStrategy()

    outcome = await auto_compact_if_needed(state, strategy, CompactionOptions(1000), CompactionTracking())

    assert outcome.was_compacted
    assert strategy.inputs == [legacy]
    assert state.messages[0] is original
    assert len(state.messages) == 3
    assert state.messages[1].is_summary is True


@pytest.mark.parametrize("failure_kind", ["exception", "empty", "whitespace", "too_long", "wrong_type"])
async def test_failed_summary_does_not_mutate_history_or_usage(failure_kind):
    class FailingStrategy(CompactionStrategy):
        async def summarize(self, messages):
            messages[0].content = "mutated by adapter"
            if failure_kind == "exception":
                raise RuntimeError("summarizer failed")
            return {"empty": "", "whitespace": "  ", "too_long": "x" * 300, "wrong_type": 42}[failure_kind]

    state = AgentState(
        messages=[SystemMessage(role="system", content="prior summary", is_summary=True),
                  UserMessage(role="user", content="old " * 400),
                  UserMessage(role="user", content="latest")],
        needs_compaction=True, last_input_tokens=9, total_input_tokens=123, total_output_tokens=45,
    )
    before, messages = deepcopy(state), state.messages
    options = CompactionOptions(500, min_recent_messages=1, max_summary_chars=256, max_ptl_retries=1)

    outcome = await auto_compact_if_needed(state, FailingStrategy(), options, CompactionTracking())

    assert outcome.blocked_reason == "context_budget_exceeded"
    assert outcome.tracking.consecutive_failures == 1
    assert state == before
    assert state.messages is messages


async def test_summary_within_char_cap_still_must_fit_token_budget():
    class OversizedStrategy(CompactionStrategy):
        async def summarize(self, messages):
            return "中" * 200  # 200 chars fits the cap, but over 600 UTF-8 bytes.

    state = AgentState(messages=[UserMessage(role="user", content="old " * 400),
                                 UserMessage(role="user", content="latest")])
    before = deepcopy(state)
    options = CompactionOptions(500, min_recent_messages=1, max_summary_chars=300, max_ptl_retries=0)

    outcome = await auto_compact_if_needed(state, OversizedStrategy(), options, CompactionTracking())

    assert not outcome.was_compacted
    assert outcome.blocked_reason == "context_budget_exceeded"
    assert state == before


async def test_successful_compaction_preserves_all_provider_usage_counters():
    state = AgentState(messages=[UserMessage(role="user", content="old " * 400),
                                 UserMessage(role="user", content="latest")],
                       last_input_tokens=9, total_input_tokens=123, total_output_tokens=45)
    outcome = await auto_compact_if_needed(
        state, RecordingStrategy(), CompactionOptions(500, min_recent_messages=1), CompactionTracking(2),
    )
    assert outcome.was_compacted
    assert outcome.tracking.consecutive_failures == 0
    assert (state.last_input_tokens, state.total_input_tokens, state.total_output_tokens) == (9, 123, 45)


def assert_complete_tool_groups(messages):
    calls = [call.id for m in messages if isinstance(m, AssistantMessage) for call in m.tool_calls]
    results = [m.tool_call_id for m in messages if isinstance(m, ToolMessage)]
    assert calls == results


async def test_ptl_keeps_previous_summary_and_complete_tool_groups_on_every_retry():
    class RetryStrategy(RecordingStrategy):
        async def summarize(self, messages):
            self.inputs.append(deepcopy(messages))
            if len(self.inputs) < 3:
                raise RuntimeError("retry with less old history")
            return "combined history"

    previous = SystemMessage(role="system", content="prior decisions", is_summary=True)
    calls = [ToolCall(id=f"old-{i}", name="read", args={"large": "x" * 300}) for i in range(2)]
    current = [ToolCall(id=f"new-{i}", name="read", args={}) for i in range(2)]
    pinned = [AssistantMessage(role="assistant", content="", tool_calls=current),
              *[ToolMessage(role="tool", tool_name="read", tool_call_id=c.id, content="recent result") for c in current]]
    state = AgentState(messages=[
        previous, UserMessage(role="user", content="old user"),
        AssistantMessage(role="assistant", content="old answer"),
        AssistantMessage(role="assistant", content="", tool_calls=calls),
        *[ToolMessage(role="tool", tool_name="read", tool_call_id=c.id, content="old result") for c in calls],
        *pinned,
    ], needs_compaction=True)
    strategy = RetryStrategy()

    outcome = await auto_compact_if_needed(
        state, strategy, CompactionOptions(10000, min_recent_messages=1), CompactionTracking(),
    )

    assert outcome.was_compacted
    assert outcome.result.ptl_attempts == 2
    assert len(strategy.inputs) == 3
    for attempt in strategy.inputs:
        assert attempt[0] == previous
        assert_complete_tool_groups(attempt)
    assert not any(isinstance(m, ToolMessage) for m in strategy.inputs[1])
    assert state.messages[-3:] == pinned
    assert_complete_tool_groups(state.messages)


async def test_ptl_victim_selection_uses_configured_token_estimator():
    """The PTL "largest group" must follow ``token_estimator``, not raw bytes.

    A custom tokenizer can rank a small-byte group as the most expensive one.
    The estimator below counts ``X`` markers, so the byte-small group is the
    victim even though the byte estimator would drop the byte-large group.
    """
    class FlakyStrategy(CompactionStrategy):
        def __init__(self):
            self.inputs = []

        async def summarize(self, messages):
            self.inputs.append([m.content for m in messages])
            if len(self.inputs) == 1:
                raise RuntimeError("force PTL")
            return "combined history"

    def estimator(config, messages):
        return sum(message.content.count("X") for message in messages)

    byte_large = UserMessage(role="user", content="A" * 400)          # big bytes, 0 tokens
    token_large = UserMessage(role="user", content="B" + "X" * 60)    # small bytes, 60 tokens
    pinned = UserMessage(role="user", content="pinned tail")
    # Independent confirmation that byte size ranks the opposite group largest.
    assert estimate_input_tokens(None, [byte_large]) > estimate_input_tokens(None, [token_large])

    state = AgentState(messages=[byte_large, token_large, pinned], needs_compaction=True)
    strategy = FlakyStrategy()
    options = CompactionOptions(1000, min_recent_messages=1, max_ptl_retries=1, token_estimator=estimator)

    outcome = await auto_compact_if_needed(state, strategy, options, CompactionTracking())

    assert outcome.was_compacted
    assert outcome.result.ptl_attempts == 1
    # The retained candidate set is the byte-large / token-cheap group.
    assert strategy.inputs[1] == ["A" * 400]
    assert token_large.id in outcome.result.omitted_message_ids
    assert byte_large.id not in outcome.result.omitted_message_ids


@pytest.mark.parametrize("large_field", ["system_prompt", "tool_description", "tool_parameters", "tool_arguments"])
async def test_preflight_includes_system_prompt_tools_and_call_arguments(large_field):
    large = "context " * 500
    config_kwargs = {}
    tool = ToolDefinition(name="read", description="Read", parameters={})
    if large_field == "system_prompt":
        config_kwargs["system_prompt"] = large
    elif large_field == "tool_description":
        tool.description = large
    elif large_field == "tool_parameters":
        tool.parameters = {"description": large}

    async def execute(name, params):
        return ToolExecutionResult(output="result")

    llm = RecordingLlm([LlmTurnResult(type="text", text="must not be called")])
    runtime, events = make_compacting_runtime(
        llm, RecordingStrategy(), tools=SingleTool(tool, execute), **config_kwargs,
    )
    if large_field == "tool_arguments":
        # Keep the old complete tool group in the pinned span alongside the new input.
        runtime.state.messages = [
            AssistantMessage(role="assistant", content="", tool_calls=[ToolCall(id="old", name="read", args={"text": large})]),
            ToolMessage(role="tool", tool_name="read", tool_call_id="old", content="result"),
        ]

    await runtime.run_prompt("hello")

    assert not llm.inputs
    assert events[-1].reason == "context_budget_exceeded"
    blocked = next(event for event in events if event.type == "compaction_blocked")
    assert blocked.estimated_input_tokens >= blocked.token_budget


async def test_custom_estimator_receives_current_config_and_rebuilt_messages():
    seen = []

    def estimator(config, messages):
        seen.append((config, deepcopy(messages)))
        return sum(len(message.content.split()) for message in messages)

    options = CompactionOptions(20, min_recent_messages=1, token_estimator=estimator)
    llm = RecordingLlm([LlmTurnResult(type="text", text="done")])
    runtime, _ = make_compacting_runtime(llm, RecordingStrategy(), options=options, system_prompt="system")
    runtime.state.messages = [UserMessage(role="user", content="old " * 30)]

    await runtime.run_prompt("latest question")

    assert len(llm.inputs) == 1
    assert len(seen) == 3  # current request, pinned floor, rebuilt request
    assert all(config == runtime.config for config, _ in seen)
    assert seen[0][1][-1].content == "latest question"
    assert seen[-1][1] == llm.inputs[0]


@pytest.mark.parametrize("invalid", [-1, True, 1.5, None, "raises"])
async def test_invalid_estimate_stops_before_model_call(invalid):
    def estimator(config, messages):
        messages[0].content = "mutated by estimator"
        if invalid == "raises":
            raise RuntimeError("counting failed")
        return invalid

    llm = RecordingLlm([LlmTurnResult(type="text", text="must not be called")])
    options = CompactionOptions(1000, token_estimator=estimator)
    runtime, events = make_compacting_runtime(llm, RecordingStrategy(), options=options)
    await runtime.run_prompt("hello")
    assert not llm.inputs
    assert events[-1].reason == "token_estimation_failed"
    assert runtime.state.messages[0].content == "hello"


async def test_historical_usage_does_not_trigger_small_current_request():
    state = AgentState(messages=[UserMessage(role="user", content="small")],
                       last_input_tokens=100000, total_input_tokens=1000000)
    strategy = RecordingStrategy()
    outcome = await auto_compact_if_needed(state, strategy, CompactionOptions(1000), CompactionTracking())
    assert not outcome.was_compacted
    assert not outcome.blocked_reason
    assert not strategy.inputs


async def test_manual_failure_below_budget_can_continue_until_failure_ceiling():
    class FailingStrategy(CompactionStrategy):
        async def summarize(self, messages):
            raise RuntimeError("unavailable")

    llm = RecordingLlm([LlmTurnResult(type="text", text="first answer")])
    options = CompactionOptions(10000, max_ptl_retries=0, max_consecutive_failures=2, min_recent_messages=1)
    runtime, events = make_compacting_runtime(llm, FailingStrategy(), options=options)
    runtime.state.messages = [UserMessage(role="user", content="older message")]
    runtime.state.needs_compaction = True

    await runtime.run_prompt("first")
    assert len(llm.inputs) == 1
    assert runtime.state.needs_compaction
    await runtime.run_prompt("second")
    assert len(llm.inputs) == 1
    assert events[-1].reason == "compaction_exhausted"


async def test_cancellation_leaves_history_and_usage_intact():
    class CancelledStrategy(CompactionStrategy):
        async def summarize(self, messages):
            messages[0].content = "changed"
            raise asyncio.CancelledError

    state = AgentState(messages=[UserMessage(role="user", content="old " * 400),
                                 UserMessage(role="user", content="latest")], last_input_tokens=10)
    before = deepcopy(state)
    with pytest.raises(asyncio.CancelledError):
        await auto_compact_if_needed(state, CancelledStrategy(), CompactionOptions(500, min_recent_messages=1), CompactionTracking())
    assert state == before


async def test_zero_recent_messages_can_compact_without_index_error():
    state = AgentState(messages=[UserMessage(role="user", content="history")], needs_compaction=True)
    outcome = await auto_compact_if_needed(state, RecordingStrategy(), CompactionOptions(500, min_recent_messages=0), CompactionTracking())
    assert outcome.was_compacted
    assert len(state.messages) == 1


@pytest.mark.parametrize("kwargs", [{"token_budget": 0}, {"min_recent_messages": -1},
                                   {"max_ptl_retries": -1}, {"max_consecutive_failures": 0},
                                   {"max_summary_chars": 0}, {"token_estimator": None}])
def test_invalid_compaction_options_rejected(kwargs):
    with pytest.raises(ValueError):
        CompactionOptions(**{"token_budget": 1000, **kwargs})


def test_default_estimator_counts_utf8_and_ignores_runtime_only_metadata():
    config = create_config()
    message = SystemMessage(role="system", content="a", is_summary=False)
    ascii_size = estimate_input_tokens(config, [message])
    message.content = "中"
    assert estimate_input_tokens(config, [message]) == ascii_size + 2
    message.id = "uuid is not sent to model"
    message.is_summary = True
    assert estimate_input_tokens(config, [message]) == ascii_size + 2


@pytest.mark.parametrize("failure_kind", ["summary_exception", "summary_still_too_large", "recount_error"])
async def test_failed_preflight_never_forwards_oversized_context(failure_kind):
    class Strategy(CompactionStrategy):
        async def summarize(self, messages):
            if failure_kind == "summary_exception":
                raise RuntimeError("summary unavailable")
            return "large " * 100 if failure_kind == "summary_still_too_large" else "short"

    def estimator(config, messages):
        if failure_kind == "recount_error" and any(getattr(m, "is_summary", False) for m in messages):
            raise RuntimeError("cannot count new summary")
        return estimate_input_tokens(config, messages)

    llm = RecordingLlm([LlmTurnResult(type="text", text="must not be called")])
    options = CompactionOptions(500, max_ptl_retries=0, min_recent_messages=1, token_estimator=estimator)
    runtime, events = make_compacting_runtime(llm, Strategy(), options=options)
    old = UserMessage(role="user", content="history " * 400)
    runtime.state.messages = [old]
    await runtime.run_prompt("new request")

    assert not llm.inputs
    assert runtime.state.messages[0] is old
    assert len(runtime.state.messages) == 2
    assert not any(event.type == "compaction_triggered" for event in events)
    expected = "token_estimation_failed" if failure_kind == "recount_error" else "context_budget_exceeded"
    assert events[-1].reason == expected


async def test_approval_resume_drains_batch_then_checks_new_tool_output():
    executions = []

    async def execute(name, params):
        executions.append(name)
        return ToolExecutionResult(output="large " * 1000)

    tool = SingleTool(ToolDefinition(name="read", description="Read", parameters={}, requires_approval=True), execute)
    llm = RecordingLlm([
        LlmTurnResult(type="tool_calls", tool_calls=[ToolCall(id="read-1", name="read", args={})],
                      usage=LlmUsage(input_tokens=10)),
        LlmTurnResult(type="text", text="must not be called"),
    ])
    runtime, events = make_compacting_runtime(llm, RecordingStrategy(), tools=tool, auto_approve_tools=False)
    await runtime.run_prompt("read")
    assert runtime.state.pending_approval is not None
    assert not executions
    runtime.approve_pending_tool()
    await runtime.resume()

    assert executions == ["read"]
    assert len(llm.inputs) == 1
    assert runtime.state.pending_tool_calls == []
    assert_complete_tool_groups(runtime.state.messages)
    assert events[-1].reason == "context_budget_exceeded"
