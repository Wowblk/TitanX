from __future__ import annotations

import asyncio
import copy
from datetime import datetime, timedelta, timezone

from .policy_store import PolicyStore, _now
from .types import AgentPolicy, AuditEntry, BreakGlassSession


class BreakGlassController:
    def __init__(self, store: PolicyStore) -> None:
        self._store = store
        self._session: BreakGlassSession | None = None
        self._task: asyncio.Task | None = None

    def is_active(self) -> bool:
        return self._session is not None

    def get_session(self) -> BreakGlassSession | None:
        return self._session

    async def activate(
        self,
        reason: str,
        ttl_ms: int,
        relaxed_policy: AgentPolicy,
    ) -> BreakGlassSession:
        if self._session:
            raise RuntimeError("A break-glass session is already active")

        before = copy.copy(self._store.get_policy())
        snapshot = await self._store.set(relaxed_policy, f"break_glass: {reason}", "host")

        now = datetime.now(timezone.utc)
        session = BreakGlassSession(
            activated_at=now.isoformat(),
            expires_at=(now + timedelta(milliseconds=ttl_ms)).isoformat(),
            original_snapshot_id=snapshot.id,
        )
        self._session = session

        await self._store.get_audit_log().append(AuditEntry(
            timestamp=_now(),
            event="break_glass_activated",
            actor="host",
            before=before,
            after=relaxed_policy,
            reason=reason,
            snapshot_id=snapshot.id,
        ))

        self._task = asyncio.get_event_loop().create_task(self._expire_after(ttl_ms / 1000.0))
        return session

    def dispose(self) -> None:
        if self._task:
            self._task.cancel()
            self._task = None

    async def _expire_after(self, delay_s: float) -> None:
        await asyncio.sleep(delay_s)
        await self._expire()

    async def _expire(self) -> None:
        if not self._session:
            return
        session = self._session
        self._session = None
        self._task = None

        before = copy.copy(self._store.get_policy())
        await self._store.rollback(session.original_snapshot_id, "system")

        await self._store.get_audit_log().append(AuditEntry(
            timestamp=_now(),
            event="break_glass_expired",
            actor="system",
            before=before,
            after=copy.copy(self._store.get_policy()),
            reason="TTL expired — policy auto-restored",
            snapshot_id=session.original_snapshot_id,
        ))
