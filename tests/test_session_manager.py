"""SandboxSessionManager lifecycle (Q19).

- ``max_sessions`` enforces an LRU cap.
- ``aclose`` destroys all live sessions.
- Constructor-time ``allowed_write_paths`` is overridden by the live
  ``policy_store`` when one is provided, so a break-glass relaxation
  reaches new and existing sessions without restart.
"""

from __future__ import annotations

from typing import Any

import pytest

from titanx.policy import AgentPolicy, AuditLog, PolicyStore
from titanx.sandbox import (
    SandboxRouter,
    SandboxSessionManager,
)
from titanx.sandbox.types import (
    SandboxBackend,
    SandboxBackendCapabilities,
    SandboxExecutionResult,
    SandboxFileEntry,
    SandboxKind,
    SandboxSession,
)


class _RecorderBackend(SandboxBackend):
    """Backend that records every create_session / write_files call.

    Sessions get monotonically-increasing ids so multiple ``create``
    calls produce distinct entries (the historical bug had the stub
    return the same id and silently clobber the session map).
    """

    def __init__(self, kind: SandboxKind) -> None:
        self.kind = kind
        self.create_calls: list[list[str] | None] = []
        self.destroyed: list[str] = []
        self.writes: list[tuple[str, str]] = []
        self._counter = 0

    def capabilities(self) -> SandboxBackendCapabilities:
        return SandboxBackendCapabilities(
            kind=self.kind,
            supports_persistence=True, supports_snapshots=False,
            supports_browser=False, supports_network=False,
            supports_package_install=False, supported_capabilities=[],
        )

    async def is_available(self) -> bool:
        return True

    async def execute(self, request, session=None) -> SandboxExecutionResult:
        return SandboxExecutionResult(
            backend=self.kind, exit_code=0, stdout="", stderr="", duration_ms=1.0,
        )

    async def create_session(self, metadata=None, *, allowed_write_paths=None) -> SandboxSession:
        self.create_calls.append(list(allowed_write_paths) if allowed_write_paths else None)
        self._counter += 1
        return SandboxSession(id=f"{self.kind}-{self._counter}", backend=self.kind)

    async def destroy_session(self, session_id: str) -> None:
        self.destroyed.append(session_id)

    async def write_files(self, files: list[SandboxFileEntry], session=None) -> None:
        for f in files:
            self.writes.append((f.path, f.content))


@pytest.fixture
def backend() -> _RecorderBackend:
    return _RecorderBackend("wasm")


@pytest.fixture
def router(backend: _RecorderBackend) -> SandboxRouter:
    return SandboxRouter([backend], default_backend="wasm")


class TestLruEviction:
    async def test_creating_past_max_evicts_oldest(
        self, router: SandboxRouter, backend: _RecorderBackend
    ) -> None:
        mgr = SandboxSessionManager(router, max_sessions=2)
        a = await mgr.create()
        b = await mgr.create()
        c = await mgr.create()  # evicts 'a'

        live_ids = {s.id for s in mgr.list_sessions()}
        assert live_ids == {b.id, c.id}
        # The backend's ``destroy_session`` must have been called for
        # the evicted entry — otherwise we leak container/process
        # resources at the backend layer.
        assert a.id in backend.destroyed


class TestAclose:
    async def test_aclose_drains_all_sessions(
        self, router: SandboxRouter, backend: _RecorderBackend
    ) -> None:
        mgr = SandboxSessionManager(router, max_sessions=10)
        for _ in range(3):
            await mgr.create()
        assert len(mgr.list_sessions()) == 3

        await mgr.aclose()
        assert mgr.list_sessions() == []
        # All three backend sessions should have been destroyed.
        assert len(backend.destroyed) == 3


class TestDynamicPolicyPaths:
    async def test_policy_store_paths_override_constructor_list(
        self, router: SandboxRouter, backend: _RecorderBackend
    ) -> None:
        # Constructor list is "old"; live policy is "current". Q19 says
        # the live policy wins so a break-glass relaxation reaches the
        # backend without rebuilding the manager.
        store = PolicyStore(
            AgentPolicy(allowed_write_paths=["/work/live"]),
            AuditLog(),
        )
        mgr = SandboxSessionManager(
            router,
            allowed_write_paths=["/work/static"],
            policy_store=store,
        )
        await mgr.create()
        assert backend.create_calls[-1] == ["/work/live"]

    async def test_falls_back_to_constructor_list_when_policy_empty(
        self, router: SandboxRouter, backend: _RecorderBackend
    ) -> None:
        store = PolicyStore(AgentPolicy(allowed_write_paths=[]), AuditLog())
        mgr = SandboxSessionManager(
            router,
            allowed_write_paths=["/work/static"],
            policy_store=store,
        )
        await mgr.create()
        assert backend.create_calls[-1] == ["/work/static"]
