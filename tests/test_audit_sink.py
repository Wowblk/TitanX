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

import json
from datetime import datetime, timezone
from typing import Any

import pytest

from titanx.policy import (
    AgentPolicy,
    AuditEntry,
    AuditLog,
    PolicyStore,
    storage_secondary_sink,
)
from titanx.storage.types import StorageBackend


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

    async def test_secondary_payload_retains_the_full_execution_record(self) -> None:
        # The canonical JSONL record carries every AuditEntry field. The
        # secondary store must not be a lossy copy: promoting the
        # execution/authorisation fields out of ``details`` keeps them
        # queryable instead of buried inside a JSON blob (Q20).
        storage = _CapturingStorage()
        sink = storage_secondary_sink(storage, session_id="sid")

        await sink(AuditEntry(
            timestamp="2026-10-07T12:00:00+00:00",
            event="tool_decision",
            actor="host",
            reason="approval required",
            before=AgentPolicy(allowed_write_paths=["/a"]),
            after=AgentPolicy(allowed_write_paths=["/b"]),
            snapshot_id="snap-1",
            tool_name="mcp__github__search",
            tool_call_id="call-1",
            decision="allow",
            is_error=False,
            details={
                "execution_id": "exec-1",
                "run_id": "run-1",
                "batch_id": "batch-1",
                "ordinal": 3,
                "policy_epoch": 7,
            },
        ))

        [call] = storage.calls
        data = call["data"]
        # The five execution fields are present at the top level, not
        # only buried inside ``data["details"]``.
        assert data["execution_id"] == "exec-1"
        assert data["run_id"] == "run-1"
        assert data["batch_id"] == "batch-1"
        assert data["ordinal"] == 3
        assert data["policy_epoch"] == 7
        # Every other canonical field survives too.
        assert data["reason"] == "approval required"
        assert data["snapshot_id"] == "snap-1"
        assert data["tool_name"] == "mcp__github__search"
        assert data["tool_call_id"] == "call-1"
        assert data["decision"] == "allow"
        assert data["is_error"] is False
        assert data["before"]["allowed_write_paths"] == ["/a"]
        assert data["after"]["allowed_write_paths"] == ["/b"]
        assert data["details"]["execution_id"] == "exec-1"


class TestStorageBackendSaveLogDeprecation:
    def test_save_log_survives_but_is_marked_deprecated(self) -> None:
        # ``save_log`` is kept for backward compatibility but is no longer
        # a supported write path — the canonical pipeline is ``AuditLog``
        # plus a secondary sink. Its docstring must say so.
        assert hasattr(StorageBackend, "save_log")
        doc = StorageBackend.save_log.__doc__ or ""
        assert "deprecat" in doc.lower()

    async def test_default_save_log_still_raises_not_implemented(self) -> None:
        backend = StorageBackend()
        with pytest.raises(NotImplementedError):
            await backend.save_log(
                datetime.now(timezone.utc), "policy_change", "host"
            )


class TestAuditRecordImmutability:
    async def test_append_and_get_entries_never_leak_mutable_records(self) -> None:
        audit = AuditLog()
        submitted = AuditEntry(
            timestamp="2026-08-27T00:00:00+00:00",
            event="tool_decision",
            actor="host",
            reason="original",
            details={"nested": {"value": "original"}},
        )

        await audit.append(submitted)
        submitted.reason = "tampered caller"
        submitted.details["nested"]["value"] = "tampered caller"

        [leaked] = audit.get_entries()
        leaked.reason = "tampered reader"
        leaked.details["nested"]["value"] = "tampered reader"

        [fresh] = audit.get_entries()
        assert fresh.reason == "original"
        assert fresh.details == {"nested": {"value": "original"}}

    async def test_sink_mutation_cannot_rewrite_ring_or_jsonl(self, tmp_path) -> None:
        log_path = tmp_path / "audit.jsonl"

        def mutating_sink(entry: AuditEntry) -> None:
            entry.reason = "tampered sink"
            entry.details["nested"]["value"] = "tampered sink"

        audit = AuditLog(
            str(log_path),
            fsync_policy="every",
            secondary_sink=mutating_sink,
        )
        submitted = AuditEntry(
            timestamp="2026-08-27T00:00:00+00:00",
            event="tool_decision",
            actor="host",
            reason="original",
            details={"nested": {"value": "original"}},
        )

        await audit.append(submitted)
        submitted.reason = "tampered caller"
        submitted.details["nested"]["value"] = "tampered caller"
        await audit.aclose()

        [memory_entry] = audit.get_entries()
        disk_entry = json.loads(log_path.read_text())
        assert memory_entry.reason == "original"
        assert memory_entry.details == {"nested": {"value": "original"}}
        assert disk_entry["reason"] == "original"
        assert disk_entry["details"] == {"nested": {"value": "original"}}
