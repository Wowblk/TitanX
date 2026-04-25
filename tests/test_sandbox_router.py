"""SandboxRouter min_isolation enforcement (Q18).

The historical router silently fell back to a weaker backend (e.g. WASM
when Docker / E2B were unavailable). For workloads classified as
``risk_level="high"`` this was a dangerous quiet downgrade. The new
contract requires the caller to opt into a hard floor; below that floor
the router refuses rather than degrading.
"""

from __future__ import annotations

import pytest

from titanx.sandbox import SandboxRouter, SandboxRouterInput
from titanx.sandbox.types import (
    SandboxBackend,
    SandboxBackendCapabilities,
    SandboxExecutionResult,
    SandboxKind,
    SandboxSession,
)


class _StubBackend(SandboxBackend):
    """Minimal SandboxBackend with controllable availability."""

    def __init__(self, kind: SandboxKind, available: bool = True) -> None:
        self.kind = kind
        self._available = available
        self._counter = 0

    def capabilities(self) -> SandboxBackendCapabilities:
        return SandboxBackendCapabilities(
            kind=self.kind,
            supports_persistence=True, supports_snapshots=False,
            supports_browser=False, supports_network=False,
            supports_package_install=False, supported_capabilities=[],
        )

    async def is_available(self) -> bool:
        return self._available

    async def execute(self, request, session=None) -> SandboxExecutionResult:
        return SandboxExecutionResult(
            backend=self.kind, exit_code=0, stdout="", stderr="", duration_ms=1.0,
        )

    async def create_session(self, metadata=None, *, allowed_write_paths=None) -> SandboxSession:
        self._counter += 1
        return SandboxSession(id=f"{self.kind}-{self._counter}", backend=self.kind)

    async def destroy_session(self, session_id: str) -> None:
        return None


class TestMinIsolationFloor:
    async def test_default_picks_wasm_when_only_wasm_present(self) -> None:
        router = SandboxRouter([_StubBackend("wasm")])
        sel = await router.select(SandboxRouterInput())
        assert sel.backend.kind == "wasm"

    async def test_min_isolation_docker_with_only_wasm_raises(self) -> None:
        router = SandboxRouter([_StubBackend("wasm")])
        with pytest.raises(RuntimeError, match="min_isolation"):
            await router.select(SandboxRouterInput(min_isolation="docker"))

    async def test_min_isolation_docker_picks_docker_when_available(self) -> None:
        router = SandboxRouter([_StubBackend("wasm"), _StubBackend("docker")])
        sel = await router.select(SandboxRouterInput(min_isolation="docker"))
        assert sel.backend.kind == "docker"

    async def test_unavailable_backend_skipped_with_trail(self) -> None:
        # Docker is registered but reports "not available". The router
        # must include this fact in the rejection trail so operators
        # can debug daemon configuration.
        router = SandboxRouter([
            _StubBackend("wasm", available=False),
            _StubBackend("docker", available=False),
        ])
        with pytest.raises(RuntimeError) as exc_info:
            await router.select(SandboxRouterInput())
        msg = str(exc_info.value)
        assert "wasm" in msg
        assert "docker" in msg


class TestSelectionCallback:
    async def test_on_selection_called_with_request(self) -> None:
        captured: list[tuple[str, str | None]] = []

        async def on_sel(selection, request) -> None:
            captured.append((selection.backend.kind, request.min_isolation))

        router = SandboxRouter(
            [_StubBackend("wasm")],
            on_selection=on_sel,
        )
        await router.select(SandboxRouterInput())
        assert captured == [("wasm", None)]

    async def test_on_selection_failure_does_not_break_select(self) -> None:
        # The observer is best-effort; a bug in the callback must not
        # cascade into a sandbox-execution failure.
        async def boom(selection, request) -> None:
            raise RuntimeError("observer crashed")

        router = SandboxRouter([_StubBackend("wasm")], on_selection=boom)
        sel = await router.select(SandboxRouterInput())
        assert sel.backend.kind == "wasm"
