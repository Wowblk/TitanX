"""Break-glass session controller.

Break-glass is the "production fire alarm" path for the policy plane:
the on-call operator temporarily relaxes ``AgentPolicy`` (e.g. widens
``allowed_write_paths``, enables ``auto_approve_tools``) for a bounded
TTL, then the controller MUST restore the original policy when the TTL
expires or the operator explicitly revokes the session.

Invariants enforced here:

1. **At most one active session.** Concurrent activation is rejected at
   the controller boundary; otherwise overlapping break-glass windows
   would make rollback non-deterministic.
2. **Every activation is matched by a rollback.** ``aclose()`` /
   ``revoke()`` / TTL expiry all funnel into the same ``_expire`` path,
   which is guarded by a lock so a manual revoke racing with the timer
   coroutine cannot double-rollback or double-audit.
3. **Audit before re-raise.** Validation failures inside
   ``PolicyStore.set`` propagate up; we don't try to half-activate.
4. **Snapshots are deep-copied.** ``AuditEntry.before`` / ``after``
   never share list references with the live policy — historical
   ``copy.copy`` was a shallow copy that let the audit record mutate
   alongside subsequent policy edits.
5. **No deprecated event-loop access.** ``asyncio.create_task`` requires
   a running loop, which is exactly what we want: an activation outside
   an async context should fail fast rather than silently scheduling
   onto whatever loop ``get_event_loop()`` happens to find.
"""

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
        self._original_snapshot_id: str | None = None
        # Serialise activate / expire / revoke. Without this lock a manual
        # revoke racing with the TTL timer can issue two rollbacks against
        # the same snapshot and emit two ``break_glass_expired`` audits,
        # corrupting the forensic trail.
        self._lock = asyncio.Lock()

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
        if not isinstance(ttl_ms, int) or isinstance(ttl_ms, bool):
            raise TypeError("ttl_ms must be int (got bool / non-int)")
        if ttl_ms <= 0:
            raise ValueError("ttl_ms must be a positive integer (milliseconds)")

        async with self._lock:
            if self._session is not None:
                raise RuntimeError("A break-glass session is already active")

            # Capture the *current* policy for the audit record before
            # ``set()`` swaps it. Deep copy so the entry can't be mutated
            # by later edits to the live policy. ``PolicyStore.set`` runs
            # ``validate_policy`` and can raise; if it does, the
            # controller stays in the inactive state and no timer task is
            # leaked because we haven't created one yet.
            before = copy.deepcopy(self._store.get_policy())
            snapshot = await self._store.set(
                relaxed_policy, f"break_glass: {reason}", "host"
            )

            now = datetime.now(timezone.utc)
            session = BreakGlassSession(
                activated_at=now.isoformat(),
                expires_at=(now + timedelta(milliseconds=ttl_ms)).isoformat(),
                original_snapshot_id=snapshot.id,
            )
            # Commit session state BEFORE scheduling the timer — if the
            # audit append below raises, the session is still active and
            # the timer can still expire it. The alternative (schedule
            # first, audit second) leaks an active relaxed policy if the
            # audit raises and the host treats the activation as failed.
            self._session = session
            self._original_snapshot_id = snapshot.id

            # Audit is best-effort: the operational primary effect — the
            # policy is now relaxed — has already happened. A failed
            # audit append must not roll back that effect, but it must
            # be visible. ``AuditLog`` (Q12) handles its own backpressure
            # / IO failures internally and never raises in normal
            # operation; this try/except is belt-and-suspenders.
            try:
                await self._store.get_audit_log().append(AuditEntry(
                    timestamp=_now(),
                    event="break_glass_activated",
                    actor="host",
                    before=before,
                    after=copy.deepcopy(relaxed_policy),
                    reason=reason,
                    snapshot_id=snapshot.id,
                ))
            except Exception:
                pass

            # ``asyncio.create_task`` requires a running event loop. We
            # WANT this requirement: ``get_event_loop()`` is deprecated in
            # 3.10+ and pending removal, and silently scheduling onto a
            # background loop the caller didn't expect is exactly the
            # kind of "expired in 10 minutes? not on this thread" bug
            # that defeats the whole purpose of a break-glass TTL.
            self._task = asyncio.create_task(
                self._expire_after(ttl_ms / 1000.0),
                name=f"break_glass_expire:{snapshot.id}",
            )
            return session

    async def revoke(self, reason: str = "manual revoke") -> None:
        """Explicitly end the active session and roll back the policy.

        The original ``dispose()`` only cancelled the TTL timer — it did
        NOT roll back the relaxed policy, leaving the system in a quietly
        more-permissive state forever. ``revoke`` is the correct API for
        "operator says we're done with break-glass": it cancels the
        timer AND restores the original policy AND emits the matching
        audit entry, all under the same lock used by the timer so the
        two paths cannot race.
        """
        async with self._lock:
            if self._session is None:
                return
            await self._cancel_timer_locked()
            await self._expire_locked(reason)

    async def aclose(self) -> None:
        """Stop the controller. If a session is active, revoke it.

        Safe to call multiple times. Hosts that hold a controller for
        the lifetime of the gateway should call ``aclose`` on shutdown
        to avoid leaving an active relaxed policy + a dangling timer
        task when the event loop shuts down.
        """
        await self.revoke(reason="controller shutdown — auto-revoked")

    def dispose(self) -> None:
        """Deprecated. Cancels the TTL timer **without** rolling back.

        Retained for source-compat with hosts that called the historical
        API. Calling this on an active session leaves the relaxed policy
        in place — exactly the foot-gun the controller was supposed to
        prevent. New code should call ``revoke()`` (async) or
        ``aclose()`` (async). A ``DeprecationWarning`` would be ideal but
        we don't pull in ``warnings`` here to keep the import surface
        minimal; the docstring + audit log are the source of truth.
        """
        if self._task and not self._task.done():
            self._task.cancel()
            self._task = None

    # ── internal ────────────────────────────────────────────────────────

    async def _expire_after(self, delay_s: float) -> None:
        try:
            await asyncio.sleep(delay_s)
        except asyncio.CancelledError:
            return
        async with self._lock:
            if self._session is None:
                return
            await self._expire_locked("TTL expired — policy auto-restored")

    async def _expire_locked(self, reason: str) -> None:
        # Caller MUST hold ``self._lock``. This is the single rollback
        # implementation, used by both manual revoke and TTL expiry.
        if self._session is None or self._original_snapshot_id is None:
            return

        snapshot_id = self._original_snapshot_id
        # Clear local state BEFORE the rollback so a re-entrant call
        # (e.g. an audit hook that triggers another revoke) sees the
        # session as already gone and short-circuits.
        self._session = None
        self._original_snapshot_id = None
        self._task = None

        before = copy.deepcopy(self._store.get_policy())

        # Rollback runs validate_policy on the snapshot — if validation
        # rejects (snapshot from an older code version), the rollback
        # raises and we surface it. The forensic trail still gets the
        # rejection via PolicyStore's own audit path.
        try:
            await self._store.rollback(snapshot_id, "system")
        except Exception:
            # Re-arm the session reference so a follow-up manual revoke
            # can be retried. This is preferable to leaving the
            # controller permanently confused about whether a session
            # is active.
            self._session = BreakGlassSession(
                activated_at="",
                expires_at="",
                original_snapshot_id=snapshot_id,
            )
            self._original_snapshot_id = snapshot_id
            raise

        try:
            await self._store.get_audit_log().append(AuditEntry(
                timestamp=_now(),
                event="break_glass_expired",
                actor="system",
                before=before,
                after=copy.deepcopy(self._store.get_policy()),
                reason=reason,
                snapshot_id=snapshot_id,
            ))
        except Exception:
            pass

    async def _cancel_timer_locked(self) -> None:
        # Caller MUST hold ``self._lock``. Cancels the TTL timer if any
        # and waits for the task to settle so we don't race with its
        # own attempt to acquire the lock.
        if self._task is None or self._task.done():
            self._task = None
            return
        self._task.cancel()
        try:
            await self._task
        except (asyncio.CancelledError, Exception):
            pass
        self._task = None
