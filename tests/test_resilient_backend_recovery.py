"""Recovery must remain reachable through the normal sandbox routing path.

Only the backend and monotonic clock are simulated. Routing, tool dispatch,
retry, and circuit-breaker state transitions use the production classes.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from titanx.resilience import circuit_breaker
from titanx.resilience import CircuitOpenError, ResilientOptions, ResilientSandboxBackend
from titanx.sandbox import (
    SandboxBackend,
    SandboxBackendCapabilities,
    SandboxExecutionRequest,
    SandboxExecutionResult,
    SandboxRouter,
    SandboxRouterInput,
    SandboxedToolHandler,
    SandboxedToolRuntime,
    SandboxToolPolicy,
)
from titanx.types import ToolDefinition


class _Clock:
    now = 100.0

    def monotonic(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    clock = _Clock()
    # Replace only this module's clock reference; asyncio keeps real time.
    monkeypatch.setattr(
        circuit_breaker, "time", SimpleNamespace(monotonic=clock.monotonic),
    )
    return clock


class _Backend(SandboxBackend):
    kind = "docker"

    def __init__(self) -> None:
        self.available = True
        self.fail = False
        self.executions = 0
        self.availability_checks = 0
        self.started = asyncio.Event()
        self.release: asyncio.Event | None = None
        self.check_started = asyncio.Event()
        self.check_release: asyncio.Event | None = None

    def capabilities(self) -> SandboxBackendCapabilities:
        return SandboxBackendCapabilities(
            kind="docker", supports_persistence=False, supports_snapshots=False,
            supports_browser=False, supports_network=False,
            supports_package_install=False, supported_capabilities=["filesystem"],
        )

    async def is_available(self) -> bool:
        self.availability_checks += 1
        self.check_started.set()
        if self.check_release is not None:
            await self.check_release.wait()
        return self.available

    async def execute(self, request, session=None) -> SandboxExecutionResult:
        self.executions += 1
        self.started.set()
        if self.release is not None:
            await self.release.wait()
        if self.fail:
            raise RuntimeError("simulated backend outage")
        return SandboxExecutionResult(
            backend="docker", exit_code=0, stdout="recovered", stderr="", duration_ms=0,
        )


class _Rig:
    def __init__(self, *, success_threshold: int = 2) -> None:
        self.raw = _Backend()
        self.transitions: list[tuple[str, str]] = []
        self.backend = ResilientSandboxBackend(
            self.raw,
            ResilientOptions(
                failure_threshold=1, success_threshold=success_threshold,
                cooldown_ms=60_000, max_attempts=1,
                on_state_change=lambda name, previous, current:
                    self.transitions.append((previous, current)),
            ),
        )
        self.router = SandboxRouter([self.backend])
        self.profile = SandboxRouterInput(needs_filesystem=True, min_isolation="docker")
        self.request = SandboxExecutionRequest(command="simulated-command")
        self.tools = SandboxedToolRuntime(
            router=self.router,
            handlers=[SandboxedToolHandler(
                definition=ToolDefinition(name="demo", description="test", parameters={}),
                request_fn=lambda params: self.request,
                policy=SandboxToolPolicy(needs_filesystem=True, min_isolation="docker"),
            )],
        )

    async def trip(self) -> None:
        self.raw.fail = True
        with pytest.raises(RuntimeError, match="simulated backend outage"):
            await self.tools.execute("demo", {})
        self.raw.fail = False
        self.raw.started.clear()
        assert self.backend.get_circuit_state() == "open"


async def test_tool_dispatch_recovers_after_cooldown(clock: _Clock) -> None:
    """Regression: even healthy backends used to be skipped forever."""
    rig = _Rig()
    await rig.trip()
    clock.advance(60)

    first = await rig.tools.execute("demo", {})
    assert first.output == "[sandbox:docker] recovered"
    assert first.error is None
    assert rig.backend.get_circuit_state() == "half-open"

    second = await rig.tools.execute("demo", {})
    assert second.error is None
    assert rig.backend.get_circuit_state() == "closed"
    assert rig.raw.executions == 3  # original failure + two recovery probes
    assert rig.transitions == [
        ("closed", "open"), ("open", "half-open"), ("half-open", "closed"),
    ]


async def test_no_probe_before_cooldown_expires(clock: _Clock) -> None:
    rig = _Rig()
    await rig.trip()
    checks = rig.raw.availability_checks
    clock.advance(59)

    with pytest.raises(RuntimeError, match="is_available=False"):
        await rig.router.select(rig.profile)
    with pytest.raises(CircuitOpenError):
        await rig.backend.execute(rig.request)
    assert rig.raw.availability_checks == checks
    assert rig.raw.executions == 1
    assert rig.backend.get_circuit_state() == "open"


async def test_selection_does_not_claim_probe_or_emit_transitions(clock: _Clock) -> None:
    rig = _Rig()
    await rig.trip()
    clock.advance(60)

    # A caller may select a backend and then abandon the request. Readiness
    # checks must neither consume the probe nor announce a state transition.
    for _ in range(3):
        assert await rig.backend.is_available()
        selection = await rig.router.select(rig.profile)
        assert selection.backend is rig.backend
    assert rig.backend.get_circuit_state() == "open"
    assert rig.transitions == [("closed", "open")]
    assert rig.raw.executions == 1
    await rig.tools.execute("demo", {})
    assert rig.backend.get_circuit_state() == "half-open"


async def test_underlying_availability_is_still_required(clock: _Clock) -> None:
    rig = _Rig()
    await rig.trip()
    clock.advance(60)
    checks = rig.raw.availability_checks
    rig.raw.available = False
    with pytest.raises(RuntimeError, match="is_available=False"):
        await rig.router.select(rig.profile)
    assert rig.raw.availability_checks == checks + 1
    assert rig.raw.executions == 1
    assert rig.backend.get_circuit_state() == "open"

    rig.raw.available = True
    await rig.tools.execute("demo", {})
    assert rig.backend.get_circuit_state() == "half-open"


async def test_failed_recovery_probe_restarts_cooldown(clock: _Clock) -> None:
    rig = _Rig(success_threshold=1)
    await rig.trip()
    clock.advance(60)
    rig.raw.fail = True
    with pytest.raises(RuntimeError, match="simulated backend outage"):
        await rig.tools.execute("demo", {})
    assert rig.backend.get_circuit_state() == "open"
    rig.raw.fail = False
    clock.advance(59)
    with pytest.raises(RuntimeError, match="is_available=False"):
        await rig.router.select(rig.profile)
    assert rig.raw.executions == 2

    clock.advance(1)
    await rig.tools.execute("demo", {})
    assert rig.backend.get_circuit_state() == "closed"


async def test_preselected_concurrent_callers_share_one_probe(clock: _Clock) -> None:
    rig = _Rig()
    await rig.trip()
    clock.advance(60)
    # Force the check/execute race: all callers see readiness before any of
    # them executes. The authoritative gate still admits exactly one call.
    selections = await asyncio.gather(*(
        rig.router.select(rig.profile) for _ in range(10)
    ))
    rig.raw.release = asyncio.Event()
    probe = asyncio.create_task(selections[0].backend.execute(rig.request))
    try:
        await asyncio.wait_for(rig.raw.started.wait(), timeout=1)
        competitors = await asyncio.gather(*(
            selected.backend.execute(rig.request) for selected in selections[1:]
        ), return_exceptions=True)
        assert all(isinstance(result, CircuitOpenError) for result in competitors)
        assert not await rig.backend.is_available()
        with pytest.raises(RuntimeError, match="is_available=False"):
            await rig.router.select(rig.profile)
        assert rig.raw.executions == 2
    finally:
        rig.raw.release.set()
        await probe
    assert rig.backend.get_circuit_state() == "half-open"
    await rig.tools.execute("demo", {})
    assert rig.backend.get_circuit_state() == "closed"


@pytest.mark.parametrize("prior_successes", [0, 1])
async def test_cancelled_probe_releases_slot_without_counting_success(
    clock: _Clock, prior_successes: int,
) -> None:
    rig = _Rig()
    await rig.trip()
    clock.advance(60)
    for _ in range(prior_successes):
        await rig.tools.execute("demo", {})
    rig.raw.started.clear()
    rig.raw.release = asyncio.Event()
    probe = asyncio.create_task(rig.tools.execute("demo", {}))
    try:
        await asyncio.wait_for(rig.raw.started.wait(), timeout=1)
    finally:
        probe.cancel()
        with pytest.raises(asyncio.CancelledError):
            await probe

    assert rig.backend.get_circuit_state() == "half-open"
    assert rig.transitions == [("closed", "open"), ("open", "half-open")]
    rig.raw.release = None
    for successes in range(prior_successes + 1, 3):
        await rig.tools.execute("demo", {})
        expected = "closed" if successes == 2 else "half-open"
        assert rig.backend.get_circuit_state() == expected
    assert rig.raw.executions == 4  # failure, cancelled probe, two successes


async def test_recheck_admission_after_awaiting_backend_health(clock: _Clock) -> None:
    rig = _Rig()
    rig.raw.check_release = asyncio.Event()
    checking = asyncio.create_task(rig.backend.is_available())
    try:
        await asyncio.wait_for(rig.raw.check_started.wait(), timeout=1)
        rig.raw.fail = True
        with pytest.raises(RuntimeError, match="simulated backend outage"):
            await rig.backend.execute(rig.request)
        rig.raw.fail = False
    finally:
        rig.raw.check_release.set()
    assert not await checking
    assert rig.backend.get_circuit_state() == "open"
