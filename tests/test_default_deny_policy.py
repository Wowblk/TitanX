"""Deny-by-default policy admission (TXS-02).

A registered tool is not automatically authorised. Tools that do not require
human approval must still appear on the explicit ``tool_allowlist`` before
``PolicyStore.check_tool_call`` will allow dispatch.
"""

from __future__ import annotations

import pytest

from titanx.policy import AgentPolicy, PolicyStore
from titanx.policy.validation import PolicyValidationError
from titanx.types import ToolCall, ToolDefinition


def _definition(name: str, *, requires_approval: bool = False, mandatory: bool = False) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        description="",
        parameters={"type": "object"},
        requires_approval=requires_approval,
        mandatory_approval=mandatory,
    )


def _call(name: str) -> ToolCall:
    return ToolCall(id="call-1", name=name, args={})


def test_registered_non_approval_tool_without_allowlist_is_denied() -> None:
    store = PolicyStore(AgentPolicy())
    result = store.check_tool_call(_call("custom_handler"), _definition("custom_handler"))
    assert result.decision == "deny"


def test_registered_non_approval_tool_on_allowlist_is_allowed() -> None:
    store = PolicyStore(AgentPolicy(tool_allowlist=["custom_handler"]))
    result = store.check_tool_call(_call("custom_handler"), _definition("custom_handler"))
    assert result.decision == "allow"


def test_auto_approve_does_not_grant_unlisted_non_approval_tools() -> None:
    # ``auto_approve_tools`` only relaxes the approval gate, never the
    # explicit-allowlist requirement for non-approval tools.
    store = PolicyStore(AgentPolicy(auto_approve_tools=True))
    result = store.check_tool_call(_call("custom_handler"), _definition("custom_handler"))
    assert result.decision == "deny"


def test_denylist_beats_allowlist() -> None:
    store = PolicyStore(AgentPolicy(tool_allowlist=["x"], tool_denylist=["x"]))
    assert store.check_tool_call(_call("x"), _definition("x")).decision == "deny"


def test_unregistered_tool_is_denied_even_if_allowlisted() -> None:
    store = PolicyStore(AgentPolicy(tool_allowlist=["ghost"]))
    assert store.check_tool_call(_call("ghost"), None).decision == "deny"


def test_approval_tool_still_needs_approval_unless_auto_approved() -> None:
    store = PolicyStore(AgentPolicy())
    definition = _definition("danger", requires_approval=True)
    assert store.check_tool_call(_call("danger"), definition).decision == "needs_approval"
    auto = PolicyStore(AgentPolicy(auto_approve_tools=True))
    assert auto.check_tool_call(_call("danger"), definition).decision == "allow"


def test_mandatory_approval_ignores_auto_approve() -> None:
    store = PolicyStore(AgentPolicy(auto_approve_tools=True))
    definition = _definition("mcp__srv__tool", requires_approval=True, mandatory=True)
    assert store.check_tool_call(_call("mcp__srv__tool"), definition).decision == "needs_approval"


def test_mandatory_approval_forces_prompt_without_requires_approval() -> None:
    # ``mandatory_approval`` is an independent field (see titanx/types.py): a
    # tool that mandates review must pause even if the host forgot to also set
    # ``requires_approval``. Otherwise a "mandatory review" tool that is merely
    # allowlisted (with auto_approve_tools on) is dispatched with no prompt —
    # the exact silent-approval failure the flag exists to prevent.
    store = PolicyStore(
        AgentPolicy(auto_approve_tools=True, tool_allowlist=["review_gate"])
    )
    definition = _definition("review_gate", requires_approval=False, mandatory=True)
    assert store.check_tool_call(_call("review_gate"), definition).decision == "needs_approval"


@pytest.mark.parametrize("bad", [[123], [""], "not-a-list", [None]])
def test_tool_allowlist_validation_rejects_bad_entries(bad) -> None:
    with pytest.raises(PolicyValidationError):
        PolicyStore(AgentPolicy(tool_allowlist=bad))


def test_policy_allowlist_is_deep_copied() -> None:
    leaked = ["safe"]
    store = PolicyStore(AgentPolicy(tool_allowlist=leaked))
    leaked.append("injected")
    assert store.get_policy().tool_allowlist == ["safe"]
