"""Gateway security and bookkeeping (Q14).

- ``hmac.compare_digest`` for API-key comparison (constant-time).
- Bounded session map: LRU eviction when ``max_sessions`` is reached.
- Idle TTL: stale entries are reaped on next access.
"""

from __future__ import annotations

import asyncio

import pytest

from titanx.gateway.server import _check_api_key
from titanx.gateway.session_registry import SessionCapacityError, SessionRegistry
from titanx.types import RuntimeHooks


class TestApiKeyComparison:
    def test_exact_match(self) -> None:
        assert _check_api_key("secret", "secret") is True

    def test_off_by_one_rejected(self) -> None:
        assert _check_api_key("secret", "secrex") is False

    def test_none_provided_rejected(self) -> None:
        assert _check_api_key(None, "secret") is False

    def test_empty_provided_rejected(self) -> None:
        assert _check_api_key("", "secret") is False


class _FakeRuntime:
    def __init__(self, sid: str) -> None:
        self.sid = sid
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


async def _create_runtime(sid: str, hooks: RuntimeHooks) -> _FakeRuntime:
    return _FakeRuntime(sid)


class TestSessionRegistryBounds:
    async def test_lru_eviction_when_full(self) -> None:
        registry = SessionRegistry(max_sessions=2, idle_ttl_seconds=60.0)

        await registry.get_or_create("a", _create_runtime, RuntimeHooks())  # type: ignore[arg-type]
        await registry.get_or_create("b", _create_runtime, RuntimeHooks())  # type: ignore[arg-type]
        # Touching 'a' so 'b' becomes the LRU.
        registry.get("a")

        await registry.get_or_create("c", _create_runtime, RuntimeHooks())  # type: ignore[arg-type]

        assert len(registry) == 2
        # 'b' was the LRU at the moment 'c' arrived; it should be gone.
        assert "a" in registry
        assert "c" in registry
        assert "b" not in registry

    async def test_idle_ttl_evicts_on_access(self) -> None:
        # Tiny TTL so the test doesn't actually sleep. We can't drive
        # ``time.monotonic`` directly, but we can manually mark the
        # entry's last-used timestamp far in the past.
        registry = SessionRegistry(max_sessions=10, idle_ttl_seconds=0.01)
        entry = await registry.get_or_create(
            "a", _create_runtime, RuntimeHooks()  # type: ignore[arg-type]
        )
        entry.last_used = 0.0  # ancient

        # The fast path GET reports None for an idle-expired entry.
        assert registry.get("a") is None

        # And the next get_or_create observes the registry as
        # effectively empty for this id, so a fresh entry is created.
        new_entry = await registry.get_or_create(
            "a", _create_runtime, RuntimeHooks()  # type: ignore[arg-type]
        )
        assert new_entry is not entry

    async def test_invalid_max_sessions_rejected(self) -> None:
        with pytest.raises(ValueError):
            SessionRegistry(max_sessions=0, idle_ttl_seconds=10.0)

    async def test_concurrent_get_or_create_returns_same_entry(self) -> None:
        # Two concurrent requests for the same session_id must end up
        # with the SAME entry — otherwise the per-session lock that
        # serialises run_prompt is meaningless (each caller would hold
        # a different lock).
        registry = SessionRegistry(max_sessions=10, idle_ttl_seconds=60.0)

        async def request() -> object:
            return await registry.get_or_create(
                "shared", _create_runtime, RuntimeHooks()  # type: ignore[arg-type]
            )

        a, b = await asyncio.gather(request(), request())
        assert a is b

    async def test_active_session_is_never_ttl_or_lru_evicted(self) -> None:
        registry = SessionRegistry(max_sessions=1, idle_ttl_seconds=0.01)
        active = await registry.get_or_create(
            "active", _create_runtime, RuntimeHooks()  # type: ignore[arg-type]
        )
        active.last_used = 0.0
        await active.lock.acquire()
        try:
            assert registry.get("active") is active
            with pytest.raises(SessionCapacityError, match="all sessions are active"):
                await registry.get_or_create(
                    "new", _create_runtime, RuntimeHooks()  # type: ignore[arg-type]
                )
            assert registry.get("active") is active
        finally:
            active.lock.release()

        replacement = await registry.get_or_create(
            "new", _create_runtime, RuntimeHooks()  # type: ignore[arg-type]
        )
        assert replacement is not active
        assert "active" not in registry
        assert "new" in registry

    async def test_pending_approval_is_protected_even_without_locked_run(self) -> None:
        registry = SessionRegistry(max_sessions=1, idle_ttl_seconds=0.01)
        active = await registry.get_or_create(
            "approval", _create_runtime, RuntimeHooks()  # type: ignore[arg-type]
        )
        active.runtime.state = type(
            "State",
            (),
            {"pending_approval": object()},
        )()
        active.last_used = 0.0

        assert registry.get("approval") is active
        with pytest.raises(SessionCapacityError):
            await registry.get_or_create(
                "new", _create_runtime, RuntimeHooks()  # type: ignore[arg-type]
            )


class TestSessionRegistryTeardown:
    """Eviction must tear down the evicted runtime, not just drop the dict row."""

    async def test_lru_eviction_tears_down_evicted_runtime(self) -> None:
        registry = SessionRegistry(max_sessions=1, idle_ttl_seconds=60.0)
        first = await registry.get_or_create("a", _create_runtime, RuntimeHooks())  # type: ignore[arg-type]
        await registry.get_or_create("b", _create_runtime, RuntimeHooks())  # type: ignore[arg-type]
        assert first.runtime.closed is True

    async def test_idle_sweep_tears_down_evicted_runtime(self) -> None:
        registry = SessionRegistry(max_sessions=10, idle_ttl_seconds=0.01)
        entry = await registry.get_or_create("a", _create_runtime, RuntimeHooks())  # type: ignore[arg-type]
        entry.last_used = 0.0
        await registry.get_or_create("b", _create_runtime, RuntimeHooks())  # type: ignore[arg-type]
        assert entry.runtime.closed is True

    async def test_remove_tears_down_runtime(self) -> None:
        registry = SessionRegistry(max_sessions=10, idle_ttl_seconds=60.0)
        entry = await registry.get_or_create("a", _create_runtime, RuntimeHooks())  # type: ignore[arg-type]
        registry.remove("a")
        await asyncio.sleep(0.01)
        assert entry.runtime.closed is True

    async def test_aclose_tears_down_every_session(self) -> None:
        registry = SessionRegistry(max_sessions=10, idle_ttl_seconds=60.0)
        entries = [
            await registry.get_or_create(sid, _create_runtime, RuntimeHooks())  # type: ignore[arg-type]
            for sid in ("a", "b", "c")
        ]
        await registry.aclose()
        assert len(registry) == 0
        assert all(entry.runtime.closed for entry in entries)

    async def test_create_failure_still_tears_down_swept_idle_victims(self) -> None:
        # A request first sweeps an idle-expired victim out of the map (it is
        # now unreachable), then creation fails. The detached victim must still
        # be torn down or its sandbox session and store rows leak.
        registry = SessionRegistry(max_sessions=10, idle_ttl_seconds=0.01)
        idle = await registry.get_or_create("idle", _create_runtime, RuntimeHooks())  # type: ignore[arg-type]
        idle.last_used = 0.0

        async def failing_create(sid: str, hooks: RuntimeHooks) -> _FakeRuntime:
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            await registry.get_or_create("new", failing_create, RuntimeHooks())  # type: ignore[arg-type]

        assert idle.runtime.closed is True
