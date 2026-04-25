"""AuditLog secondary sink fan-out (Q20).

JSONL on disk remains the canonical audit pipeline; the secondary sink
is a convenience for indexing audit data into a relational store. The
key invariants:

- The sink fires once per ``append`` entry, in append order.
- A failing sink is permanently disabled but the JSONL pipeline is
  unaffected (i.e. audit failures cannot cascade into policy failures).
- ``storage_secondary_sink`` packs audit-specific fields into ``data``
  so the storage schema doesn't grow a column per event variant.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest

from titanx.policy import (
    AgentPolicy,
    AuditEntry,
    AuditLog,
    PolicyStore,
    storage_secondary_sink,
)


class _CapturingStorage:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.fail_next = False

    async def save_log(
        self,
        *,
        timestamp: datetime,
        event: str,
        actor: str,
        session_id: str | None = None,
        data: object | None = None,
    ) -> None:
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("storage went away")
        self.calls.append({
            "timestamp": timestamp,
            "event": event,
            "actor": actor,
            "session_id": session_id,
            "data": data,
        })


class TestSecondarySinkFanout:
    async def test_policy_change_routed_to_storage(self) -> None:
        storage = _CapturingStorage()
        audit = AuditLog(
            secondary_sink=storage_secondary_sink(storage, session_id="sid-1"),
        )
        store = PolicyStore(AgentPolicy(), audit)

        await store.set(
            AgentPolicy(allowed_write_paths=["/work"]),
            reason="test",
            actor="host",
        )

        assert len(storage.calls) == 1
        call = storage.calls[0]
        assert call["event"] == "policy_change"
        assert call["actor"] == "host"
        assert call["session_id"] == "sid-1"
        assert call["data"]["reason"] == "test"

    async def test_sink_failure_disables_sink_but_keeps_log(self) -> None:
        storage = _CapturingStorage()
        storage.fail_next = True

        audit = AuditLog(
            secondary_sink=storage_secondary_sink(storage, session_id="sid"),
        )
        store = PolicyStore(AgentPolicy(), audit)

        # First call: sink raises. We must NOT propagate that failure
        # into the caller — Q12 / Q20 contract is "audit failures
        # never mask policy operations".
        await store.set(
            AgentPolicy(allowed_write_paths=["/a"]),
            reason="first",
            actor="host",
        )

        # Second call: sink would normally succeed, but it's been
        # permanently disabled by the first failure to avoid pinning
        # the writer in retry loops. Confirms one-shot disable.
        await store.set(
            AgentPolicy(allowed_write_paths=["/b"]),
            reason="second",
            actor="host",
        )

        assert storage.calls == []  # sink disabled before any successful call
        # In-memory ring still got both entries.
        events = [e.event for e in audit.get_entries()]
        assert events.count("policy_change") == 2

    async def test_sync_sink_function_works(self) -> None:
        # The sink hook accepts plain callables too — useful for tests
        # and for hosts that just want a stderr fan-out.
        captured: list[AuditEntry] = []

        def sync_sink(entry: AuditEntry) -> None:
            captured.append(entry)

        audit = AuditLog(secondary_sink=sync_sink)
        store = PolicyStore(AgentPolicy(), audit)
        await store.set(
            AgentPolicy(allowed_write_paths=["/x"]),
            reason="sync-sink",
            actor="host",
        )
        assert len(captured) == 1
        assert captured[0].event == "policy_change"
