"""Adapters that translate ``AuditEntry`` into other audit destinations.

The canonical pipeline is ``AuditLog`` (JSONL on disk + bounded ring
buffer in memory). Other destinations — relational stores, structured
logging, an SIEM — should hang off ``AuditLog.secondary_sink`` rather
than be written to directly. Two parallel pipelines that don't
reconcile are exactly the Q20 anti-pattern.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Awaitable, Callable

from .types import AuditEntry


# Subset of ``StorageBackend`` we need for the adapter — kept narrow so
# tests can pass a mock without implementing the full interface.
class _LogSink:
    async def save_log(
        self,
        timestamp: datetime,
        event: str,
        actor: str,
        session_id: str | None = None,
        data: object | None = None,
    ) -> None:  # pragma: no cover - protocol stub
        raise NotImplementedError


def storage_secondary_sink(
    storage: _LogSink,
    *,
    session_id: str | None = None,
) -> Callable[[AuditEntry], Awaitable[None]]:
    """Adapter that routes ``AuditLog`` entries to a ``StorageBackend.save_log``.

    Use it like::

        audit = AuditLog(
            "audit.jsonl",
            secondary_sink=storage_secondary_sink(my_storage, session_id=sid),
        )

    The caller is responsible for the ``session_id`` correlation; the
    audit entry itself doesn't carry one (it's a separate identifier in
    ``StorageBackend``'s schema). When ``session_id`` is None the
    adapter writes ``None``, matching the legacy save_log signature.
    """

    async def _sink(entry: AuditEntry) -> None:
        # Parse the ISO-8601 timestamp the audit pipeline emits. The
        # sink interface wants a real datetime so the storage layer
        # can index it. Fall back to "now" if the entry's timestamp is
        # somehow non-parseable — failure-here cascades into "no audit
        # row" which is worse than "audit row with slightly wrong ts".
        try:
            ts = datetime.fromisoformat(entry.timestamp)
        except Exception:
            ts = datetime.now(timezone.utc)
        # Bundle the audit-specific fields into ``data`` so the
        # downstream schema doesn't need to grow a column per audit
        # variant. Storage backends already store this as JSON/TEXT.
        data = {
            "reason": entry.reason,
            "snapshot_id": entry.snapshot_id,
            "tool_name": entry.tool_name,
            "tool_call_id": entry.tool_call_id,
            "decision": entry.decision,
            "is_error": entry.is_error,
            "details": entry.details,
        }
        await storage.save_log(
            timestamp=ts,
            event=entry.event,
            actor=entry.actor,
            session_id=session_id,
            data=data,
        )

    return _sink
