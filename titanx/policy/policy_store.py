from __future__ import annotations

import copy
from datetime import datetime, timezone
from uuid import uuid4

from .audit_log import AuditLog
from .types import AgentPolicy, PolicyCheckResult, PolicySnapshot, ReadonlyPolicyView
from .validation import PolicyValidationError, validate_policy
from ..types import ToolCall, ToolDefinition


class PolicyStore(ReadonlyPolicyView):
    """Custodian of the live ``AgentPolicy``.

    Every mutation path runs ``validate_policy`` so the kernel-impactful
    invariants (no system bind-mounts, sane iteration bounds, type
    correctness) are enforced at exactly one boundary. Bypass attempts
    via the constructor or via ``rollback`` of a maliciously-crafted
    snapshot are caught by the same validator.

    Stored policies are deep-copied so that callers cannot retroactively
    mutate the live policy by holding onto references to lists they
    handed in. The historical ``copy.copy`` was a shallow copy and
    silently shared list fields with the caller.
    """

    def __init__(self, initial: AgentPolicy, audit_log: AuditLog | None = None) -> None:
        # Validate the initial policy at construction so the invariant
        # "the live policy is always validated" holds from t=0. Without
        # this, a host could pass an invalid policy through the
        # constructor and never get caught until something tried to
        # mount /proc.
        validate_policy(initial)
        self._current = copy.deepcopy(initial)
        self._snapshots: list[PolicySnapshot] = []
        self._audit_log = audit_log or AuditLog()

    def get_policy(self) -> AgentPolicy:
        return self._current

    def get_snapshots(self) -> list[PolicySnapshot]:
        return list(self._snapshots)

    def get_audit_log(self) -> AuditLog:
        return self._audit_log

    def check_tool_call(
        self,
        tool_call: ToolCall,
        tool_definition: ToolDefinition | None,
    ) -> PolicyCheckResult:
        """Return the policy decision for a single tool call.

        Decision precedence (most restrictive wins):
          1. Tool is on the denylist                         -> deny
          2. Tool is unknown to the runtime                  -> deny
          3. Tool definition has ``requires_approval=True``  -> needs_approval
             (unless ``auto_approve_tools`` is enabled, in which case allow)
          4. Otherwise                                       -> allow
        """
        policy = self._current

        if tool_call.name in policy.tool_denylist:
            return PolicyCheckResult(
                decision="deny",
                reason=f"tool '{tool_call.name}' is on the policy denylist",
            )

        if tool_definition is None:
            return PolicyCheckResult(
                decision="deny",
                reason=f"tool '{tool_call.name}' is not registered with the runtime",
            )

        if tool_definition.requires_approval and not policy.auto_approve_tools:
            return PolicyCheckResult(
                decision="needs_approval",
                reason=f"tool '{tool_call.name}' requires explicit human approval",
            )

        if tool_definition.requires_approval and policy.auto_approve_tools:
            return PolicyCheckResult(
                decision="allow",
                reason=f"auto_approve_tools enabled; '{tool_call.name}' allowed without prompt",
            )

        return PolicyCheckResult(
            decision="allow",
            reason=f"tool '{tool_call.name}' has no approval requirement",
        )

    async def set(
        self,
        policy: AgentPolicy,
        reason: str,
        actor: str = "host",
    ) -> PolicySnapshot:
        """Validate, snapshot, swap, and audit. Atomic on failure.

        On validation failure we **audit the rejected attempt before
        re-raising** — without that record an attacker probing for
        privileged-path payloads leaves no trail. The store's live
        ``_current`` and snapshot list are untouched on rejection.
        """
        try:
            validate_policy(policy)
        except PolicyValidationError as exc:
            await self._audit_rejection(
                attempted=policy,
                reason=reason,
                actor=actor,
                error=str(exc),
            )
            raise

        before = copy.deepcopy(self._current)
        snapshot = self._save_snapshot(reason)
        self._current = copy.deepcopy(policy)
        from .types import AuditEntry
        await self._audit_log.append(AuditEntry(
            timestamp=_now(),
            event="policy_change",
            actor=actor,
            before=before,
            after=copy.deepcopy(self._current),
            reason=reason,
            snapshot_id=snapshot.id,
        ))
        return snapshot

    async def rollback(self, snapshot_id: str, actor: str = "host") -> None:
        """Restore a previously-stored snapshot.

        Snapshots are re-validated before they're installed: a snapshot
        written by an older version of this code (pre-Q11) might contain
        an unsafe policy, and we'd rather refuse the rollback than
        silently regress the security posture. The audit trail records
        the rejection so operators can see *why* the rollback failed.
        """
        snapshot = next((s for s in self._snapshots if s.id == snapshot_id), None)
        if not snapshot:
            raise ValueError(f"Unknown policy snapshot: {snapshot_id}")

        try:
            validate_policy(snapshot.policy)
        except PolicyValidationError as exc:
            await self._audit_rejection(
                attempted=snapshot.policy,
                reason=f"rollback to {snapshot_id}",
                actor=actor,
                error=str(exc),
                snapshot_id=snapshot_id,
            )
            raise

        before = copy.deepcopy(self._current)
        self._current = copy.deepcopy(snapshot.policy)
        from .types import AuditEntry
        await self._audit_log.append(AuditEntry(
            timestamp=_now(),
            event="rollback",
            actor=actor,
            before=before,
            after=copy.deepcopy(self._current),
            reason=f"Rollback to snapshot {snapshot_id}: {snapshot.reason}",
            snapshot_id=snapshot_id,
        ))

    def _save_snapshot(self, reason: str) -> PolicySnapshot:
        snapshot = PolicySnapshot(
            id=str(uuid4()),
            created_at=_now(),
            # Deep-copy here too: a snapshot must capture the policy at
            # this exact moment, immune to later mutation of the live
            # ``_current`` reference.
            policy=copy.deepcopy(self._current),
            reason=reason,
        )
        self._snapshots.append(snapshot)
        return snapshot

    async def _audit_rejection(
        self,
        *,
        attempted: AgentPolicy,
        reason: str,
        actor: str,
        error: str,
        snapshot_id: str | None = None,
    ) -> None:
        """Record a rejected mutation. Best-effort: never raises.

        The audit append itself is wrapped in a try/except so an audit
        backend failure can't mask the original validation error. The
        validation error is the signal the caller actually needs.
        """
        from .types import AuditEntry
        try:
            # Best-effort deepcopy of the rejected payload — if the
            # rejected object has a non-copy-safe field we still want the
            # rejection audited, so fall back to a string repr.
            try:
                attempted_copy = copy.deepcopy(attempted)
            except Exception:
                attempted_copy = None
            await self._audit_log.append(AuditEntry(
                timestamp=_now(),
                event="policy_change_rejected",
                actor=actor,  # type: ignore[arg-type]
                before=copy.deepcopy(self._current),
                after=attempted_copy,
                reason=reason,
                snapshot_id=snapshot_id,
                details={"error": error},
            ))
        except Exception:
            # Never let audit failure mask the validation error path.
            pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
