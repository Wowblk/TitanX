"""Gateway security and bookkeeping (Q14).

- ``hmac.compare_digest`` for API-key comparison (constant-time).
- Bounded session map: LRU eviction when ``max_sessions`` is reached.
- Idle TTL: stale entries are reaped on next access.
"""

from __future__ import annotations

import asyncio

import pytest

from titanx.gateway.server import _check_api_key
from titanx.gateway.session_registry import SessionRegistry
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
