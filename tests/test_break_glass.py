"""BreakGlassController lifecycle (Q15).

The original controller's ``dispose()`` cancelled the TTL timer but
did NOT roll back the relaxed policy — leaving the system in a quietly
more-permissive state forever. The new contract:

- ``revoke()`` rolls back AND cancels the timer (single locked path).
- ``dispose()`` is retained for source-compat but does not roll back.
- ``ttl_ms <= 0`` and non-int values are rejected at the boundary.
- Snapshots are deep-copied so audit entries cannot be mutated by
  later edits to the live policy.
"""

from __future__ import annotations

import pytest

from titanx.policy import (
    AgentPolicy,
    AuditLog,
    BreakGlassController,
    PolicyStore,
)


@pytest.fixture
def store() -> PolicyStore:
    return PolicyStore(
        AgentPolicy(allowed_write_paths=["/work"], max_iterations=5),
        AuditLog(),
    )


@pytest.fixture
def relaxed() -> AgentPolicy:
    return AgentPolicy(
        allowed_write_paths=["/work", "/tmp"],
        auto_approve_tools=True,
        max_iterations=5,
    )


class TestRevokeRollsBack:
    async def test_revoke_restores_original_policy(
        self, store: PolicyStore, relaxed: AgentPolicy
    ) -> None:
        bg = BreakGlassController(store)
        await bg.activate("incident-fix", 60_000, relaxed)
        assert "/tmp" in store.get_policy().allowed_write_paths
        assert store.get_policy().auto_approve_tools is True

        await bg.revoke("operator complete")

        # Both fields must come back, not just one.
        assert "/tmp" not in store.get_policy().allowed_write_paths
        assert store.get_policy().auto_approve_tools is False
        assert bg.is_active() is False

    async def test_aclose_revokes_active_session(
        self, store: PolicyStore, relaxed: AgentPolicy
    ) -> None:
        bg = BreakGlassController(store)
        await bg.activate("incident-fix", 60_000, relaxed)

        # aclose is the gateway-shutdown path; it must roll back the
        # policy too, not just stop the timer.
        await bg.aclose()
        assert "/tmp" not in store.get_policy().allowed_write_paths
        assert bg.is_active() is False


class TestTtlValidation:
    @pytest.mark.parametrize("bad_ttl", [0, -1, -10_000])
    async def test_non_positive_ttl_rejected(
        self, store: PolicyStore, relaxed: AgentPolicy, bad_ttl: int
    ) -> None:
        bg = BreakGlassController(store)
        with pytest.raises(ValueError):
            await bg.activate("bad", bad_ttl, relaxed)

    async def test_bool_ttl_rejected(
        self, store: PolicyStore, relaxed: AgentPolicy
    ) -> None:
        # ``bool`` is a subclass of ``int`` in Python; the historical
        # validation accepted ``True`` (== 1ms TTL) silently. Hard to
        # debug operationally; reject explicitly.
        bg = BreakGlassController(store)
        with pytest.raises(TypeError):
            await bg.activate("bad", True, relaxed)  # type: ignore[arg-type]


class TestConcurrentSessionsRefused:
    async def test_double_activate_rejected(
        self, store: PolicyStore, relaxed: AgentPolicy
    ) -> None:
        bg = BreakGlassController(store)
        await bg.activate("first", 60_000, relaxed)
        with pytest.raises(RuntimeError):
            await bg.activate("second", 60_000, relaxed)
        await bg.aclose()
