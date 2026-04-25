from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

ToolDecision = Literal["allow", "needs_approval", "deny"]

AuditEvent = Literal[
    "policy_change",
    # Emitted when ``PolicyStore.set`` (or ``rollback``) refuses a policy
    # because validation failed. Critical for forensic analysis: an
    # attacker fuzzing privileged-path payloads would otherwise leave no
    # trail of failed attempts. See ``policy.validation.validate_policy``.
    "policy_change_rejected",
    "break_glass_activated",
    "break_glass_expired",
    "rollback",
    "tool_decision",
    "tool_invocation",
]

AuditActor = Literal["host", "system", "agent"]


@dataclass
class AgentPolicy:
    allowed_write_paths: list[str] = field(default_factory=list)
    auto_approve_tools: bool = False
    max_iterations: int = 10
    # Tools listed here are unconditionally denied even when auto_approve_tools=True.
    tool_denylist: list[str] = field(default_factory=list)


@dataclass
class PolicySnapshot:
    id: str
    created_at: str
    policy: AgentPolicy
    reason: str


@dataclass
class PolicyCheckResult:
    decision: ToolDecision
    reason: str


@dataclass
class AuditEntry:
    """Append-only audit record.

    The schema is intentionally unioned: ``policy_change`` / ``rollback`` /
    ``break_glass_*`` events use ``before`` + ``after``; ``tool_decision`` /
    ``tool_invocation`` events use ``tool_name`` / ``tool_call_id`` / ``decision``
    / ``is_error`` / ``details`` and leave the policy fields unset.
    """

    timestamp: str
    event: AuditEvent
    actor: AuditActor
    reason: str
    before: AgentPolicy | None = None
    after: AgentPolicy | None = None
    snapshot_id: str | None = None
    tool_name: str | None = None
    tool_call_id: str | None = None
    decision: ToolDecision | None = None
    is_error: bool | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class BreakGlassSession:
    activated_at: str
    expires_at: str
    original_snapshot_id: str


class ReadonlyPolicyView:
    def get_policy(self) -> AgentPolicy:
        raise NotImplementedError
