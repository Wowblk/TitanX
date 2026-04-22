from __future__ import annotations

import copy
from datetime import datetime, timezone
from uuid import uuid4

from .audit_log import AuditLog
from .types import AgentPolicy, PolicySnapshot, ReadonlyPolicyView


class PolicyStore(ReadonlyPolicyView):
    def __init__(self, initial: AgentPolicy, audit_log: AuditLog | None = None) -> None:
        self._current = copy.copy(initial)
        self._snapshots: list[PolicySnapshot] = []
        self._audit_log = audit_log or AuditLog()

    def get_policy(self) -> AgentPolicy:
        return self._current

    def get_snapshots(self) -> list[PolicySnapshot]:
        return list(self._snapshots)

    def get_audit_log(self) -> AuditLog:
        return self._audit_log

    async def set(
        self,
        policy: AgentPolicy,
        reason: str,
        actor: str = "host",
    ) -> PolicySnapshot:
        before = copy.copy(self._current)
        snapshot = self._save_snapshot(reason)
        self._current = copy.copy(policy)
        from .types import AuditEntry
        await self._audit_log.append(AuditEntry(
            timestamp=_now(),
            event="policy_change",
            actor=actor,
            before=before,
            after=copy.copy(self._current),
            reason=reason,
            snapshot_id=snapshot.id,
        ))
        return snapshot

    async def rollback(self, snapshot_id: str, actor: str = "host") -> None:
        snapshot = next((s for s in self._snapshots if s.id == snapshot_id), None)
        if not snapshot:
            raise ValueError(f"Unknown policy snapshot: {snapshot_id}")
        before = copy.copy(self._current)
        self._current = copy.copy(snapshot.policy)
        from .types import AuditEntry
        await self._audit_log.append(AuditEntry(
            timestamp=_now(),
            event="rollback",
            actor=actor,
            before=before,
            after=copy.copy(self._current),
            reason=f"Rollback to snapshot {snapshot_id}: {snapshot.reason}",
            snapshot_id=snapshot_id,
        ))

    def _save_snapshot(self, reason: str) -> PolicySnapshot:
        snapshot = PolicySnapshot(
            id=str(uuid4()),
            created_at=_now(),
            policy=copy.copy(self._current),
            reason=reason,
        )
        self._snapshots.append(snapshot)
        return snapshot


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
