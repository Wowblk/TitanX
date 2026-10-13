"""Completion honesty: "completed" is a loop-termination reason, not a verdict.

``LoopEndEvent(reason="completed")`` means the runtime loop ended by producing a
final text answer. It does **not** mean the task's result was verified — the
runtime never checks whether tests passed, whether a file was actually written,
or whether a cited reference exists, and it never evaluates
``TaskState.acceptance_criteria``.

That is a legitimate contract for a generic SDK (it cannot know what "done"
means for a host), but it must not be *silent*: a task that declares acceptance
criteria the runtime cannot check is the "looks enforced, isn't" case these
tests pin. When such a task completes, the runtime writes a one-shot
``completion_unverified`` audit entry so the failure to verify is attributable
and never invisible.
"""

from __future__ import annotations

from titanx.policy import AgentPolicy, PolicyStore
from titanx.runtime import AgentRuntime
from titanx.safety.safety_layer import SafetyLayer
from titanx.types import LlmTurnResult, RuntimeHooks

from ._helpers import NullTools, ScriptedLlm


def _store(**policy_kwargs) -> PolicyStore:
    return PolicyStore(AgentPolicy(**policy_kwargs))


def _runtime(store: PolicyStore, turns: list) -> AgentRuntime:
    return AgentRuntime(
        llm=ScriptedLlm(turns),
        tools=NullTools(),
        safety=SafetyLayer(),
        hooks=RuntimeHooks(),
        policy_store=store,
    )


def _unverified(store: PolicyStore):
    return [
        e for e in store.get_audit_log().get_entries()
        if e.event == "completion_unverified"
    ]


def _answer() -> LlmTurnResult:
    return LlmTurnResult(type="text", text="done")


async def test_completing_a_task_with_acceptance_criteria_is_flagged():
    store = _store()
    runtime = _runtime(store, [_answer()])
    runtime.set_task("ship the fix", acceptance_criteria=("tests pass", "no regressions"))

    await runtime.run_prompt("go")

    entries = _unverified(store)
    assert len(entries) == 1, "an unverifiable completion must leave a trail"
    assert entries[0].actor == "system"
    assert entries[0].details.get("criteria_count") == 2
    assert entries[0].details.get("task_revision") == 1


async def test_completion_without_acceptance_criteria_is_not_flagged():
    store = _store()
    runtime = _runtime(store, [_answer()])
    runtime.set_task("just chat")  # no acceptance criteria to leave unchecked

    await runtime.run_prompt("go")

    assert _unverified(store) == []


async def test_completion_without_any_task_is_not_flagged():
    store = _store()

    await _runtime(store, [_answer()]).run_prompt("go")

    assert _unverified(store) == []


async def test_flag_is_one_shot_across_prompts():
    store = _store()
    runtime = _runtime(store, [_answer(), _answer()])
    runtime.set_task("ship the fix", acceptance_criteria=("tests pass",))

    await runtime.run_prompt("one")
    await runtime.run_prompt("two")

    assert len(_unverified(store)) == 1, "warned once per session, not once per completion"


async def test_criteria_added_after_an_earlier_completion_are_still_flagged():
    store = _store()
    runtime = _runtime(store, [_answer(), _answer()])

    await runtime.run_prompt("one")  # no task -> nothing to verify, no warning
    assert _unverified(store) == []

    runtime.set_task("now with criteria", acceptance_criteria=("must cite evidence",))
    await runtime.run_prompt("two")

    assert len(_unverified(store)) == 1


async def test_a_non_completion_termination_is_not_flagged():
    # Only a *completion* is a claim that a task finished; a halt / budget stop
    # is not, so it must not emit the completion-honesty record.
    store = _store(halt=True)
    runtime = _runtime(store, [_answer()])
    runtime.set_task("ship the fix", acceptance_criteria=("tests pass",))

    await runtime.run_prompt("go")

    assert _unverified(store) == []
