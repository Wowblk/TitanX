"""Defensive admission contracts; all tools are in-memory test doubles."""
from __future__ import annotations

import asyncio
import copy
import re
from dataclasses import FrozenInstanceError, replace

import pytest

from titanx import (
    AgentPolicy, AgentRuntime, AuditLog, ExecutionAuthorizationError,
    ExecutionGuard, ExecutionGuardOptions, PolicyStore, SafetyLayer,
)
from titanx.state import create_config
from titanx.types import (
    LlmTurnResult, RuntimeHooks, ToolCall, ToolDefinition, ToolExecutionResult,
    ToolMessage, ToolRuntime,
)
from ._helpers import ScriptedLlm, authorizing_policy_store


SCHEMA = {
    "type": "object",
    "properties": {
        "note": {"type": "object", "properties": {
            "text": {"type": "string", "maxLength": 80},
        }, "required": ["text"], "additionalProperties": False},
    },
    "required": ["note"], "additionalProperties": False,
}
ARGS = {"note": {"text": "reviewed note"}}


class NoteTools(ToolRuntime):
    def __init__(self, *, requires_approval=True, schema=None):
        self.definition = ToolDefinition(
            "write_note", "Update one test note", copy.deepcopy(SCHEMA if schema is None else schema),
            requires_approval=requires_approval,
        )
        self.calls = []
        self.entered = asyncio.Event()
        self.release = None

    def list_tools(self):
        return [self.definition]

    async def execute(self, name, params):
        self.calls.append((name, copy.deepcopy(params)))
        self.entered.set()
        if self.release is not None:
            await self.release.wait()
        params["handler_only"] = True
        return ToolExecutionResult(output="note updated")


def rig(*, tools=None, calls=None, turns=None, store=None, hooks=None, options=None):
    tools = tools or NoteTools()
    if store is None:
        # Deny-by-default: a host that hands an in-process tool to the runtime
        # must authorise it. Tests whose subject is not the allowlist seed it.
        store = authorizing_policy_store(tools)
    calls = calls if calls is not None else [ToolCall("call-note", "write_note", copy.deepcopy(ARGS))]
    llm = ScriptedLlm(turns or [
        LlmTurnResult(type="tool_calls", tool_calls=calls),
        LlmTurnResult(type="text", text="done"),
    ])
    runtime = AgentRuntime(
        llm, tools, SafetyLayer(), policy_store=store, hooks=hooks,
        execution_guard_options=options,
    )
    return runtime, tools, llm


def results(runtime):
    return [m for m in runtime.state.messages if isinstance(m, ToolMessage)]


async def test_exact_approval_dispatches_snapshot_once_and_audits_operation():
    runtime, tools, llm = rig()
    await runtime.run_prompt("update the note")
    pending = runtime.state.pending_approval
    assert pending is not None and pending.execution_id
    runtime.approve_pending_tool(execution_id=pending.execution_id)
    runtime.approve_pending_tool()  # legacy duplicate is a no-op
    await runtime.resume()
    assert tools.calls == [("write_note", ARGS)]
    assert len(results(runtime)) == 1
    assert llm.cursor == 2
    invocation = next(e for e in runtime._audit_log.get_entries() if e.event == "tool_invocation")
    assert invocation.details["execution_id"] == pending.execution_id
    assert invocation.details["approval_status"] == "consumed"
    assert "reviewed note" not in repr(invocation.details)
    assert pending.parameters == ARGS  # handler mutation stayed in its copy


async def test_tool_audit_carries_identity_and_contract_digest():
    runtime, _, _ = rig(tools=NoteTools(requires_approval=False))
    await runtime.run_prompt("update the note")
    entries = [
        e for e in runtime._audit_log.get_entries()
        if e.event in {"tool_decision", "tool_invocation"}
    ]
    assert {e.event for e in entries} == {"tool_decision", "tool_invocation"}
    for entry in entries:
        details = entry.details
        assert details["thread_id"] == runtime.config.thread_id
        assert details["session_id"] == runtime.config.session_id
        assert details["user_id"] == runtime.config.user_id
        assert details["channel"] == runtime.config.channel
        assert re.fullmatch(r"[0-9a-f]{64}", details["contract_digest"])


def test_tool_audit_contract_digest_identifies_the_contract():
    call = ToolCall("unit-note", "write_note", copy.deepcopy(ARGS))

    def digest_for(runtime_tools):
        definitions = runtime_tools.list_tools()
        config = create_config(available_tools=definitions)
        guard = ExecutionGuard(PolicyStore(AgentPolicy()), definitions)
        guard.start_run(config)
        guard.prepare(copy.deepcopy(call), 0, config, definitions)
        return guard.audit_details(0)["contract_digest"]

    baseline = digest_for(NoteTools(requires_approval=False))
    assert digest_for(NoteTools(requires_approval=False)) == baseline
    altered = NoteTools(requires_approval=False)
    altered.definition.description = "Different contract text"
    assert digest_for(altered) != baseline


async def test_public_approval_observation_is_not_an_authority_source():
    runtime, tools, _ = rig()
    await runtime.run_prompt("update the note")
    runtime.state.approved_tool_call_ids.add("call-note")
    runtime.state.signal = "continue"
    await runtime.resume()
    assert tools.calls == []
    assert runtime.state.pending_approval is not None


@pytest.mark.parametrize("change", ["arguments", "call_id", "session", "user", "contract", "config_contract"])
async def test_changed_operation_cannot_use_existing_approval(change):
    runtime, tools, _ = rig()
    await runtime.run_prompt("update the note")
    runtime.approve_pending_tool()
    if change == "arguments":
        runtime.state.pending_tool_calls[0].args["note"]["text"] = "different note"
    elif change == "call_id":
        runtime.state.pending_tool_calls[0].id = "different-call"
    elif change == "session":
        runtime.config = replace(runtime.config, session_id="other-session")
    elif change == "user":
        runtime.config = replace(runtime.config, user_id="other-user")
    elif change == "contract":
        tools.definition.requires_approval = False
    else:
        runtime.config.available_tools[0].description = "different contract"
    await runtime.resume()
    assert tools.calls == []
    assert results(runtime)[0].is_error
    assert results(runtime)[0].tool_call_id == "call-note"


@pytest.mark.parametrize("change", ["parameters", "execution_id"])
async def test_changed_approval_view_is_rejected_by_host_api(change):
    runtime, tools, _ = rig()
    await runtime.run_prompt("update the note")
    if change == "parameters":
        runtime.state.pending_approval.parameters["note"]["text"] = "unreviewed"
    else:
        runtime.state.pending_approval.execution_id = "different-operation"
    with pytest.raises(ExecutionAuthorizationError, match="approval_request_changed"):
        runtime.approve_pending_tool()
    assert tools.calls == []


async def test_reused_model_call_id_in_next_batch_requires_new_approval():
    call = ToolCall("same-call-id", "write_note", copy.deepcopy(ARGS))
    runtime, tools, _ = rig(turns=[
        LlmTurnResult(type="tool_calls", tool_calls=[call]),
        LlmTurnResult(type="tool_calls", tool_calls=[copy.deepcopy(call)]),
        LlmTurnResult(type="text", text="done"),
    ])
    await runtime.run_prompt("two separately reviewed notes")
    first_id = runtime.state.pending_approval.execution_id
    runtime.approve_pending_tool(execution_id=first_id)
    await runtime.resume()
    assert len(tools.calls) == 1
    assert runtime.state.pending_approval.execution_id != first_id
    with pytest.raises(ExecutionAuthorizationError):
        runtime.approve_pending_tool(execution_id=first_id)
    runtime.reject_pending_tool()
    await runtime.resume()
    assert len(tools.calls) == 1 and len(results(runtime)) == 2


@pytest.mark.parametrize("invalidation", ["expiry", "policy_change", "rollback", "revocation"])
async def test_stale_grant_requires_fresh_review(invalidation):
    clock = [10.0]
    store = PolicyStore(AgentPolicy())
    runtime, tools, _ = rig(store=store, options=ExecutionGuardOptions(approval_ttl_seconds=5))
    runtime._execution_guard._clock = lambda: clock[0]
    await runtime.run_prompt("update the note")
    old_id = runtime.state.pending_approval.execution_id
    runtime.approve_pending_tool(execution_id=old_id)
    if invalidation == "expiry":
        clock[0] = 15.0
    elif invalidation == "revocation":
        runtime.revoke_tool_approval(old_id)
    else:
        snapshot = await store.set(AgentPolicy(max_iterations=8), "change test policy")
        if invalidation == "rollback":
            await store.rollback(snapshot.id)
            assert store.epoch == 2
    await runtime.resume()
    assert tools.calls == []
    assert runtime.state.pending_approval.execution_id != old_id
    runtime.approve_pending_tool(execution_id=runtime.state.pending_approval.execution_id)
    await runtime.resume()
    assert len(tools.calls) == 1


async def test_final_admission_rechecks_policy_after_awaited_audit():
    changed = False
    store = None

    async def observer(entry):
        nonlocal changed
        if entry.event == "tool_decision" and entry.decision == "allow" and not changed:
            changed = True
            await store.set(AgentPolicy(tool_denylist=["write_note"]), "revoke test operation")

    store = PolicyStore(AgentPolicy(tool_allowlist=["write_note"]), AuditLog(secondary_sink=observer))
    runtime, tools, _ = rig(tools=NoteTools(requires_approval=False), store=store)
    await runtime.run_prompt("test final authorization")
    assert changed and tools.calls == []
    assert "authorization_stale" in results(runtime)[0].content


async def test_final_admission_rechecks_arguments_after_observer():
    runtime = None

    async def observer(entry):
        if entry.event == "tool_decision" and entry.decision == "allow":
            runtime.state.pending_tool_calls[0].args["note"]["text"] = "changed before dispatch"

    store = PolicyStore(AgentPolicy(tool_allowlist=["write_note"]), AuditLog(secondary_sink=observer))
    runtime, tools, _ = rig(tools=NoteTools(requires_approval=False), store=store)
    await runtime.run_prompt("test operation binding")
    assert tools.calls == []
    assert "operation_changed" in results(runtime)[0].content


@pytest.mark.parametrize("args", [
    {}, {"note": {"text": 123}}, {"note": {"text": "ok", "extra": 1}},
    {"note": {"text": "x" * 81}}, {"note": {"text": "ok"}, "extra": True},
    {"note": {"text": float("nan")}}, {"note": {"text": object()}},
])
async def test_invalid_parameters_are_denied_before_approval(args):
    runtime, tools, _ = rig(calls=[ToolCall("invalid-note", "write_note", args)])
    await runtime.run_prompt("validate note parameters")
    assert tools.calls == [] and runtime.state.pending_approval is None
    assert results(runtime)[0].is_error


async def test_local_schema_reference_is_resolved():
    schema = {"$defs": {"note": SCHEMA}, "$ref": "#/$defs/note"}
    runtime, tools, _ = rig(tools=NoteTools(requires_approval=False, schema=schema))
    await runtime.run_prompt("validate local schema")
    assert len(tools.calls) == 1


async def test_external_schema_reference_is_denied_without_retrieval(monkeypatch):
    from urllib import request
    retrieved = []

    def unexpected_retrieval(*args, **kwargs):
        retrieved.append(True)
        raise AssertionError("schema checks must not perform network I/O")

    monkeypatch.setattr(request, "urlopen", unexpected_retrieval)
    runtime, tools, _ = rig(tools=NoteTools(schema={"$ref": "https://schema.example.invalid/note"}))
    await runtime.run_prompt("validate unavailable schema")
    assert tools.calls == [] and retrieved == []
    assert results(runtime)[0].is_error


@pytest.mark.parametrize("kind", ["size", "depth", "nodes"])
async def test_argument_structure_has_bounds(kind):
    if kind == "size":
        args = {"text": "x" * 1025}
    elif kind == "depth":
        args = {}
        for _ in range(35):
            args = {"child": args}
    else:
        args = {"items": [0] * 10_001}
    runtime, tools, _ = rig(
        tools=NoteTools(schema={}), calls=[ToolCall("bounded", "write_note", args)],
        options=ExecutionGuardOptions(max_argument_bytes=1024),
    )
    await runtime.run_prompt("check bounded arguments")
    assert tools.calls == [] and results(runtime)[0].is_error


async def test_overlapping_resume_and_new_prompt_do_not_start_another_runner():
    runtime, tools, _ = rig()
    tools.release = asyncio.Event()
    await runtime.run_prompt("update once")
    runtime.approve_pending_tool()
    active = asyncio.create_task(runtime.resume())
    await asyncio.wait_for(tools.entered.wait(), 1)
    try:
        with pytest.raises(RuntimeError, match="already executing"):
            await runtime.resume()
        with pytest.raises(RuntimeError, match="already executing"):
            await runtime.run_prompt("overlapping request")
    finally:
        tools.release.set()
        await active
    assert len(tools.calls) == 1


def test_intent_is_immutable_and_admission_is_one_use():
    tools = NoteTools(requires_approval=False)
    config = create_config(available_tools=tools.list_tools())
    guard = ExecutionGuard(PolicyStore(AgentPolicy(tool_allowlist=["write_note"])), tools.list_tools())
    guard.start_run(config)
    call = ToolCall("unit-note", "write_note", copy.deepcopy(ARGS))
    intent = guard.prepare(call, 0, config, tools.list_tools())
    with pytest.raises(FrozenInstanceError):
        intent.tool_name = "other"
    guard.admit(intent, call, 0, config, tools.list_tools())
    with pytest.raises(ExecutionAuthorizationError, match="already_admitted"):
        guard.admit(intent, call, 0, config, tools.list_tools())


async def test_rejected_policy_update_does_not_change_epoch():
    store = PolicyStore(AgentPolicy())
    with pytest.raises(ValueError):
        await store.set(AgentPolicy(max_iterations=0), "invalid budget")
    assert store.epoch == 0


async def test_duplicate_message_ids_are_rejected_before_committing_a_batch():
    call = ToolCall("duplicate", "write_note", copy.deepcopy(ARGS))
    runtime, tools, _ = rig(calls=[call, copy.deepcopy(call)])
    with pytest.raises(ValueError, match="unique call IDs"):
        await runtime.run_prompt("check message protocol")
    assert tools.calls == []
    assert [m.role for m in runtime.state.messages] == ["user"]


async def test_adapter_config_observation_cannot_change_registered_contract():
    runtime, tools, _ = rig()

    class Adapter(ScriptedLlm):
        async def respond(self, config, state):
            config.available_tools[0].requires_approval = False
            state.approved_tool_call_ids.add("call-note")
            return await super().respond(config, state)

    runtime._llm = Adapter([LlmTurnResult(type="tool_calls", tool_calls=[
        ToolCall("call-note", "write_note", copy.deepcopy(ARGS)),
    ])])
    await runtime.run_prompt("review model observation")
    assert tools.calls == []
    assert runtime.state.pending_approval is not None
    assert runtime.state.approved_tool_call_ids == set()
