"""PolicyStore must not leak mutable references across its trust boundary."""

from __future__ import annotations

from titanx.policy import AgentPolicy, AuditLog, PolicyStore


class TestDetachedPolicyViews:
    def test_get_policy_cannot_mutate_live_policy(self) -> None:
        audit = AuditLog()
        store = PolicyStore(
            AgentPolicy(
                allowed_write_paths=["/srv/titanx/work"],
                tool_denylist=["dangerous"],
            ),
            audit,
        )

        leaked = store.get_policy()
        leaked.auto_approve_tools = True
        leaked.allowed_write_paths.append("/tmp/escaped")
        leaked.tool_denylist.clear()

        live = store.get_policy()
        assert live.auto_approve_tools is False
        assert live.allowed_write_paths == ["/srv/titanx/work"]
        assert live.tool_denylist == ["dangerous"]
        # A bypass attempt must neither change state nor fabricate a normal
        # policy-change record.
        assert store.get_snapshots() == []
        assert audit.get_entries() == []

    async def test_get_snapshots_cannot_poison_rollback_target(self) -> None:
        store = PolicyStore(AgentPolicy(max_iterations=3))
        snapshot = await store.set(
            AgentPolicy(max_iterations=7),
            reason="raise bounded iteration budget",
        )

        leaked = store.get_snapshots()
        assert len(leaked) == 1
        leaked[0].policy.max_iterations = 999
        leaked[0].policy.auto_approve_tools = True

        await store.rollback(snapshot.id)
        restored = store.get_policy()
        assert restored.max_iterations == 3
        assert restored.auto_approve_tools is False

    async def test_set_return_value_cannot_poison_rollback_target(self) -> None:
        store = PolicyStore(AgentPolicy(max_iterations=3))
        returned = await store.set(
            AgentPolicy(max_iterations=7),
            reason="raise bounded iteration budget",
        )

        returned.policy.max_iterations = 999
        returned.policy.auto_approve_tools = True

        await store.rollback(returned.id)
        restored = store.get_policy()
        assert restored.max_iterations == 3
        assert restored.auto_approve_tools is False
