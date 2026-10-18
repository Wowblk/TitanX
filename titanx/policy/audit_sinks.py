"""Adapters that translate ``AuditEntry`` into other audit destinations.

The canonical pipeline is ``AuditLog`` (JSONL on disk + bounded ring
buffer in memory). Other destinations — relational stores, structured
logging, an SIEM — should hang off ``AuditLog.secondary_sink`` rather
than be written to directly. Two parallel pipelines that don't
reconcile are exactly the Q20 anti-pattern.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Awaitable, Callable

from .audit_log import AUDIT_SCHEMA_VERSION
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


class _StorageSecondarySink:
    """Callable adapter that mirrors entries into ``StorageBackend.save_log``.

    ``AuditLog`` binds the configured schema version through
    ``bind_schema_version`` when the sink is attached, so a mirrored row
    never claims a different record shape from the JSONL line it mirrors.
    Without an owner (direct use in tests or custom wiring) the module
    constant remains the default.
    """

    def __init__(self, storage: _LogSink, session_id: str | None) -> None:
        self._storage = storage
        self._session_id = session_id
        self._schema_version = AUDIT_SCHEMA_VERSION

    def bind_schema_version(self, version: int) -> None:
        self._schema_version = version

    async def __call__(self, entry: AuditEntry) -> None:
        # Parse the ISO-8601 timestamp the audit pipeline emits. The
        # sink interface wants a real datetime so the storage layer
        # can index it. Fall back to "now" if the entry's timestamp is
        # somehow non-parseable — failure-here cascades into "no audit
        # row" which is worse than "audit row with slightly wrong ts".
        try:
            ts = datetime.fromisoformat(entry.timestamp)
        except Exception:
            ts = datetime.now(timezone.utc)
        # Mirror the canonical JSONL record exactly, then promote the
        # per-event fields out of ``details`` so nothing is dropped and
        # the execution fields stay indexable. Canonical top-level
        # fields win on any key collision with ``details``; the nested
        # ``details`` mapping is retained unchanged for compatibility.
        record = {"schema": self._schema_version, **asdict(entry)}
        data = {**entry.details, **record}
        await self._storage.save_log(
            timestamp=ts,
            event=entry.event,
            actor=entry.actor,
            session_id=self._session_id,
            data=data,
        )


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

    The stored ``data`` payload is a **superset** of the canonical audit
    record: it carries the same ``{"schema": ..., **asdict(entry)}`` fields
    the JSONL writer emits, *plus* the execution/authorisation fields from
    ``details`` (``execution_id``, ``run_id``, ``batch_id``, ``ordinal``,
    ``policy_epoch``, ...) promoted to the top level so the secondary store
    is queryable on them rather than a lossy subset (Q20). Because those
    fields are promoted, the mirrored row has extra top-level keys versus
    the JSONL record — additive, and the nested ``details`` mapping is still
    present unchanged; code diffing the two streams should expect the
    superset.

    ``AuditLog`` binds its own ``schema_version`` to the returned sink, so
    the mirrored ``data["schema"]`` always equals the JSONL record's. Used
    standalone, the sink stamps ``AUDIT_SCHEMA_VERSION``.
    """
    return _StorageSecondarySink(storage, session_id)
