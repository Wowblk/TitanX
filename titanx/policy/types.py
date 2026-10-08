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
    "compaction",
    # Consumption stops (OWASP LLM06:2026). The runtime withholds the next
    # model call when the session token budget is reached or the halt kill
    # switch is raised; both leave the same audited trail as a policy change,
    # so a denial-of-wallet attempt is attributable after the fact.
    "budget_exhausted",
    "halted",
]

AuditActor = Literal["host", "system", "agent"]


@dataclass
class AgentPolicy:
    allowed_write_paths: list[str] = field(default_factory=list)
    auto_approve_tools: bool = False
    max_iterations: int = 10
    # Tools listed here are unconditionally denied even when auto_approve_tools=True.
    tool_denylist: list[str] = field(default_factory=list)
    # Deny-by-default (TXS-02): a registered tool that does not itself require
    # approval is only dispatched when its name appears here. Registration is
    # not authorisation. ``tool_denylist`` still wins over this list.
    tool_allowlist: list[str] = field(default_factory=list)
    # Paths the sandbox may *read* but never write. Validated by the same
    # ``validate_write_path`` rules (no privileged subtrees, normalised,
    # absolute) — host /etc, /proc, /sys etc. stay forbidden because
    # mounting them into the container is a host-side leak even when
    # mounted read-only. Empty list means "no host-side reads beyond the
    # container image" which is the most restrictive setting and the
    # default. Backends that don't model read-only mounts (e.g. wasm)
    # are free to ignore this list. NemoClaw's filesystem_policy splits
    # read_only and read_write — this field is the TitanX equivalent.
    allowed_read_paths: list[str] = field(default_factory=list)
    # OCI image digest pin (``sha256:...``) for sandbox backends that
    # launch a container image. When set, the Docker backend refuses to
    # start unless the resolved image digest matches. Without this, a
    # registry compromise or a ``:latest`` force-push silently swaps the
    # image under the agent. NemoClaw's blueprint pins the sandbox image
    # the same way; this brings the SDK to parity. ``None`` (default)
    # disables the check; the audit CLI flags policies without a pin.
    image_digest: str | None = None
    # Session-cumulative token ceiling (input + output) for defence against
    # unbounded consumption / denial-of-wallet (OWASP LLM06:2026). The runtime
    # counts provider-reported usage across the *whole* session — resetting
    # ``max_iterations`` per prompt does not reset this — and withholds the
    # next LLM call once the sum reaches the budget. ``None`` (default) means
    # no ceiling. Cost (USD) is deliberately not modelled here: the SDK has no
    # pricing knowledge; hosts map tokens to money off the audit trail.
    # NOTE: the counter is *provider-reported* usage. An adapter that returns
    # ``usage=None`` (or omits it) contributes nothing, so the ceiling is only
    # as enforceable as the adapter's accounting — document/verify usage
    # reporting when this control is load-bearing.
    max_total_tokens: int | None = None
    # Kill switch. When true the runtime withholds the next LLM turn and ends
    # the loop with reason ``"halted"``. Raising it through ``PolicyStore.set``
    # (rather than mutating the live policy in place) makes the stop audited and
    # reversible via ``rollback`` — the same trail as any other policy change.
    halt: bool = False


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
