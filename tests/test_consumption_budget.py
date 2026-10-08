"""Session consumption budget + halt kill-switch (OWASP LLM06:2026).

Unbounded consumption / denial-of-wallet is the risk that rose the most in
the 2026 OWASP LLM Top 10 (LLM10 -> LLM06). An agentic workflow turns one
prompt into repeated model calls, so ``max_iterations`` alone does not bound
spend. These tests pin two runtime-owned controls that do:

- ``AgentPolicy.max_total_tokens`` — a *session-cumulative* (input+output)
  ceiling. Enforced at the top of the runtime loop so the next LLM call is
  withheld once the budget is crossed.
- ``AgentPolicy.halt`` — a kill switch. Also checked at the loop top.

Both are expressed through ``AgentPolicy`` (validated, snapshotted, audited)
so a change to either leaves the same trail as any other policy change.
"""

from __future__ import annotations

import pytest

from titanx.policy import AgentPolicy, PolicyStore, PolicyValidationError, validate_policy
from titanx.runtime import AgentRuntime
from titanx.safety.safety_layer import SafetyLayer
from titanx.types import (
    BudgetExhaustedEvent,
    LlmTurnResult,
    LlmUsage,
    LoopEndEvent,
    RuntimeHaltedEvent,
    RuntimeHooks,
    ToolCall,
    ToolDefinition,
    ToolExecutionResult,
)

from ._helpers import ScriptedLlm, SingleTool


def _runtime_with_tool(
    llm,
    *,
    policy: AgentPolicy | None = None,
    store: PolicyStore | None = None,
    hooks: RuntimeHooks | None = None,
    requires_approval: bool = False,
) -> AgentRuntime:
    defn = ToolDefinition(
        name="ping",
        description="ping",
        parameters={"type": "object", "properties": {}},
        requires_approval=requires_approval,
    )

    async def handler(_name: str, _params: dict) -> ToolExecutionResult:
        return ToolExecutionResult(output="pong")

    return AgentRuntime(
        llm=llm,
        tools=SingleTool(defn, handler),
        safety=SafetyLayer(),
        hooks=hooks or RuntimeHooks(),
        policy_store=store if store is not None else PolicyStore(policy),
    )


def _tool_turn(*, input_tokens: int = 0, output_tokens: int = 0, call_id: str = "c1") -> LlmTurnResult:
    return LlmTurnResult(
        type="tool_calls",
        tool_calls=[ToolCall(id=call_id, name="ping", args={})],
        usage=LlmUsage(input_tokens=input_tokens, output_tokens=output_tokens),
    )


def _loop_end_reasons(events: list) -> list[str]:
    return [e.reason for e in events if isinstance(e, LoopEndEvent)]


async def test_session_token_budget_stops_before_next_llm_call():
    events: list = []
    hooks = RuntimeHooks(on_event=lambda e, _c, _s: events.append(e))
    # Budget 100; the first turn alone reports 60 + 60 = 120 tokens, so the
    # budget is already crossed when the loop comes back to the top.
    llm = ScriptedLlm([
        _tool_turn(input_tokens=60, output_tokens=60),
        LlmTurnResult(type="text", text="second turn must never run"),
    ])
    runtime = _runtime_with_tool(
        llm,
        hooks=hooks,
        policy=AgentPolicy(tool_allowlist=["ping"], max_total_tokens=100),
    )

    state = await runtime.run_prompt("hi")

    assert llm.cursor == 1, "no LLM call may happen after the budget is exhausted"
    assert state.signal == "stop"
    assert _loop_end_reasons(events) == ["budget_exhausted"]


async def test_budget_under_limit_does_not_stop_the_loop():
    events: list = []
    hooks = RuntimeHooks(on_event=lambda e, _c, _s: events.append(e))
    llm = ScriptedLlm([
        _tool_turn(input_tokens=10, output_tokens=10),
        LlmTurnResult(
            type="text", text="done", usage=LlmUsage(input_tokens=5, output_tokens=5)
        ),
    ])
    runtime = _runtime_with_tool(
        llm,
        hooks=hooks,
        policy=AgentPolicy(tool_allowlist=["ping"], max_total_tokens=1000),
    )

    state = await runtime.run_prompt("hi")

    assert llm.cursor == 2, "a run well under budget must complete normally"
    assert state.signal == "stop"
    assert _loop_end_reasons(events) == ["completed"]


async def test_budget_accumulates_across_prompts_not_reset_per_prompt():
    events: list = []
    hooks = RuntimeHooks(on_event=lambda e, _c, _s: events.append(e))
    # Each prompt reports 60 + 60 = 120 tokens; the budget is 100. The budget
    # must be session-cumulative: the second prompt is refused before its first
    # model call, proving run_prompt does NOT reset the consumption counters the
    # way it resets max_iterations.
    llm = ScriptedLlm([
        LlmTurnResult(
            type="text", text="first", usage=LlmUsage(input_tokens=60, output_tokens=60)
        ),
        LlmTurnResult(type="text", text="second must not run"),
    ])
    runtime = _runtime_with_tool(
        llm,
        hooks=hooks,
        policy=AgentPolicy(tool_allowlist=["ping"], max_total_tokens=100),
    )

    await runtime.run_prompt("one")
    assert llm.cursor == 1

    state = await runtime.run_prompt("two")

    assert llm.cursor == 1, "second prompt must be refused before any model call"
    assert state.signal == "stop"
    assert _loop_end_reasons(events) == ["completed", "budget_exhausted"]


async def test_budget_does_not_discard_an_answer_from_the_same_turn():
    # The budget is a *pre-turn* gate. A turn that already produced the final
    # answer is committed even if its usage crosses the budget — withholding
    # the answer after paying for it would waste the tokens it was meant to
    # bound.
    events: list = []
    hooks = RuntimeHooks(on_event=lambda e, _c, _s: events.append(e))
    llm = ScriptedLlm([
        LlmTurnResult(
            type="text",
            text="here is your answer",
            usage=LlmUsage(input_tokens=500, output_tokens=500),
        )
    ])
    runtime = _runtime_with_tool(
        llm,
        hooks=hooks,
        policy=AgentPolicy(tool_allowlist=["ping"], max_total_tokens=100),
    )

    state = await runtime.run_prompt("hi")

    assert state.messages[-1].content == "here is your answer"
    assert _loop_end_reasons(events) == ["completed"]


async def test_halt_stops_before_the_first_llm_call():
    events: list = []
    hooks = RuntimeHooks(on_event=lambda e, _c, _s: events.append(e))
    llm = ScriptedLlm([LlmTurnResult(type="text", text="must not run")])
    runtime = _runtime_with_tool(
        llm,
        hooks=hooks,
        policy=AgentPolicy(tool_allowlist=["ping"], halt=True),
    )

    state = await runtime.run_prompt("hi")

    assert llm.cursor == 0, "a halted runtime must not spend a single model call"
    assert state.signal == "stop"
    assert _loop_end_reasons(events) == ["halted"]


async def test_halt_can_be_raised_mid_session():
    events: list = []
    hooks = RuntimeHooks(on_event=lambda e, _c, _s: events.append(e))
    store = PolicyStore(AgentPolicy(tool_allowlist=["ping"]))
    llm = ScriptedLlm([
        LlmTurnResult(type="text", text="first"),
        LlmTurnResult(type="text", text="second must not run"),
    ])
    runtime = _runtime_with_tool(llm, store=store, hooks=hooks)

    await runtime.run_prompt("one")
    assert llm.cursor == 1

    # Operator raises the kill switch through the audited policy path.
    policy = store.get_policy()
    policy.halt = True
    await store.set(policy, "operator kill switch")

    state = await runtime.run_prompt("two")

    assert llm.cursor == 1
    assert state.signal == "stop"
    assert _loop_end_reasons(events) == ["completed", "halted"]


async def test_budget_stop_emits_structured_event_with_usage():
    events: list = []
    hooks = RuntimeHooks(on_event=lambda e, _c, _s: events.append(e))
    llm = ScriptedLlm([
        _tool_turn(input_tokens=60, output_tokens=60),
        LlmTurnResult(type="text", text="second turn must never run"),
    ])
    runtime = _runtime_with_tool(
        llm,
        hooks=hooks,
        policy=AgentPolicy(tool_allowlist=["ping"], max_total_tokens=100),
    )

    await runtime.run_prompt("hi")

    budget_events = [e for e in events if isinstance(e, BudgetExhaustedEvent)]
    assert len(budget_events) == 1, "the stop must be observable to the host"
    assert budget_events[0].tokens_used == 120
    assert budget_events[0].budget == 100


async def test_halt_stop_emits_structured_event():
    events: list = []
    hooks = RuntimeHooks(on_event=lambda e, _c, _s: events.append(e))
    llm = ScriptedLlm([LlmTurnResult(type="text", text="must not run")])
    runtime = _runtime_with_tool(
        llm,
        hooks=hooks,
        policy=AgentPolicy(tool_allowlist=["ping"], halt=True),
    )

    await runtime.run_prompt("hi")

    assert len([e for e in events if isinstance(e, RuntimeHaltedEvent)]) == 1


async def test_budget_stop_is_audited():
    store = PolicyStore(AgentPolicy(tool_allowlist=["ping"], max_total_tokens=100))
    llm = ScriptedLlm([
        _tool_turn(input_tokens=60, output_tokens=60),
        LlmTurnResult(type="text", text="second turn must never run"),
    ])
    runtime = _runtime_with_tool(llm, store=store)

    await runtime.run_prompt("hi")

    entries = [e for e in store.get_audit_log().get_entries() if e.event == "budget_exhausted"]
    assert len(entries) == 1
    assert entries[0].actor == "system"
    assert entries[0].details.get("tokens_used") == 120
    assert entries[0].details.get("budget") == 100


async def test_halt_stop_is_audited():
    store = PolicyStore(AgentPolicy(tool_allowlist=["ping"], halt=True))
    llm = ScriptedLlm([LlmTurnResult(type="text", text="must not run")])
    runtime = _runtime_with_tool(llm, store=store)

    await runtime.run_prompt("hi")

    entries = [e for e in store.get_audit_log().get_entries() if e.event == "halted"]
    assert len(entries) == 1
    assert entries[0].actor == "system"


# ── Policy validation (the install-time boundary) ───────────────────────────


@pytest.mark.parametrize("value", [0, -1, True, "100", 3.5])
def test_validate_policy_rejects_bad_max_total_tokens(value):
    with pytest.raises(PolicyValidationError):
        validate_policy(AgentPolicy(max_total_tokens=value))


def test_validate_policy_accepts_none_or_positive_max_total_tokens():
    validate_policy(AgentPolicy(max_total_tokens=None))
    validate_policy(AgentPolicy(max_total_tokens=1))
    validate_policy(AgentPolicy(max_total_tokens=1_000_000))


@pytest.mark.parametrize("value", [1, 0, "yes", None])
def test_validate_policy_rejects_non_bool_halt(value):
    with pytest.raises(PolicyValidationError):
        validate_policy(AgentPolicy(halt=value))


# ── Integrity of the counter the budget is enforced against ─────────────────


async def test_exact_boundary_used_equals_budget_stops():
    events: list = []
    hooks = RuntimeHooks(on_event=lambda e, _c, _s: events.append(e))
    # 50 + 50 == 100 exactly at the ceiling; the next turn must be withheld.
    llm = ScriptedLlm([
        _tool_turn(input_tokens=50, output_tokens=50),
        LlmTurnResult(type="text", text="must not run"),
    ])
    runtime = _runtime_with_tool(
        llm,
        hooks=hooks,
        policy=AgentPolicy(tool_allowlist=["ping"], max_total_tokens=100),
    )

    await runtime.run_prompt("hi")

    assert llm.cursor == 1
    assert _loop_end_reasons(events) == ["budget_exhausted"]


async def test_negative_usage_cannot_understate_the_budget():
    events: list = []
    hooks = RuntimeHooks(on_event=lambda e, _c, _s: events.append(e))
    # A misreporting adapter must not be able to walk the running total
    # backwards: each turn's contribution is clamped at zero, so (500, -400)
    # counts as 500, not 100. Without the clamp this run would keep spending.
    llm = ScriptedLlm([
        _tool_turn(input_tokens=500, output_tokens=-400, call_id="a"),
        _tool_turn(input_tokens=500, output_tokens=-400, call_id="b"),
        _tool_turn(input_tokens=500, output_tokens=-400, call_id="c"),
        LlmTurnResult(type="text", text="must not run"),
    ])
    runtime = _runtime_with_tool(
        llm,
        hooks=hooks,
        policy=AgentPolicy(tool_allowlist=["ping"], max_total_tokens=1000),
    )

    await runtime.run_prompt("hi")

    assert llm.cursor == 2, "clamped sum reaches 1000 after two turns"
    assert _loop_end_reasons(events) == ["budget_exhausted"]


async def test_unreported_usage_with_a_budget_is_audited_once():
    store = PolicyStore(AgentPolicy(tool_allowlist=["ping"], max_total_tokens=100))
    # No usage at all: the budget is unenforceable. That must not be silent.
    llm = ScriptedLlm([
        LlmTurnResult(type="tool_calls", tool_calls=[ToolCall(id="a", name="ping", args={})]),
        LlmTurnResult(type="tool_calls", tool_calls=[ToolCall(id="b", name="ping", args={})]),
        LlmTurnResult(type="text", text="done"),
    ])
    runtime = _runtime_with_tool(llm, store=store)

    await runtime.run_prompt("hi")

    entries = [
        e for e in store.get_audit_log().get_entries() if e.event == "budget_unenforceable"
    ]
    assert len(entries) == 1, "warned exactly once, not once per turn"
    assert entries[0].actor == "system"


async def test_refused_prompt_does_not_grow_the_transcript():
    events: list = []
    hooks = RuntimeHooks(on_event=lambda e, _c, _s: events.append(e))
    llm = ScriptedLlm([
        LlmTurnResult(
            type="text", text="answer", usage=LlmUsage(input_tokens=60, output_tokens=60)
        ),
        LlmTurnResult(type="text", text="must not run"),
    ])
    runtime = _runtime_with_tool(
        llm,
        hooks=hooks,
        policy=AgentPolicy(tool_allowlist=["ping"], max_total_tokens=100),
    )

    state = await runtime.run_prompt("one")
    assert llm.cursor == 1
    after_first = len(state.messages)

    # A client that keeps hammering an exhausted session must not be able to
    # grow the transcript without bound.
    for _ in range(5):
        await runtime.run_prompt("spam")

    assert llm.cursor == 1
    assert len(runtime.state.messages) == after_first


async def test_approval_pause_drains_batch_then_stops_on_exhausted_budget():
    events: list = []
    hooks = RuntimeHooks(on_event=lambda e, _c, _s: events.append(e))
    llm = ScriptedLlm([
        _tool_turn(input_tokens=60, output_tokens=60),
        LlmTurnResult(type="text", text="must not run"),
    ])
    runtime = _runtime_with_tool(
        llm,
        hooks=hooks,
        policy=AgentPolicy(tool_allowlist=["ping"], max_total_tokens=100),
        requires_approval=True,
    )

    # First pass pauses for approval; the budget is already crossed.
    await runtime.run_prompt("hi")
    assert runtime.state.pending_approval is not None
    assert _loop_end_reasons(events) == ["pending_approval"]

    runtime.approve_pending_tool()
    await runtime.resume()

    # The paused batch must still drain (protocol integrity), then the loop
    # stops on the budget before any further model call.
    assert llm.cursor == 1
    assert _loop_end_reasons(events) == ["pending_approval", "budget_exhausted"]
